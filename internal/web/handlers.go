package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kontsevoye/boxctl/internal/eventlog"
)

func (s *Server) handleAdminSetup(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	if s.services.AdminSetup == nil {
		writeUnsupported(w, r)
		return
	}
	if r.Method == http.MethodGet {
		status, err := s.services.AdminSetup.AdminSetupStatus(r.Context())
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, status)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAPIError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Administrator setup requires application/json")
		return
	}
	if !s.trustedLoginOrigin(r) || !s.trustedSetupHost(r) {
		writeAPIError(w, r, http.StatusForbidden, "origin_rejected", "Cross-site setup requests are not allowed")
		return
	}
	var request struct {
		Password string `json:"password"`
	}
	if !s.decodeJSON(w, r, &request) {
		return
	}
	if err := s.services.AdminSetup.InitializeAdmin(r.Context(), request.Password); err != nil {
		writeServiceError(w, r, err)
		return
	}
	revokeContext, cancelRevoke := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	revokeErr := s.sessions.revokeAll(revokeContext)
	cancelRevoke()
	if revokeErr != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "setup_session_reset_failed", "Administrator was created, but session signing state could not be finalized")
		return
	}
	writeData(w, http.StatusCreated, AdminSetupStatus{Required: false})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAPIError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Login requires application/json")
		return
	}
	if !s.trustedLoginOrigin(r) {
		writeAPIError(w, r, http.StatusForbidden, "origin_rejected", "Cross-site login requests are not allowed")
		return
	}
	key := loginKey(r)
	if allowed, retry := s.loginLimiter.reserve(key); !allowed {
		seconds := int64((retry + time.Second - 1) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		writeAPIError(w, r, http.StatusTooManyRequests, "rate_limited", "Too many login attempts")
		return
	}
	var request struct {
		Password string `json:"password"`
	}
	if !s.decodeJSON(w, r, &request) {
		return
	}
	if request.Password == "" || len(request.Password) > 4_096 {
		writeAPIError(w, r, http.StatusUnauthorized, "invalid_credentials", "Invalid password")
		return
	}

	select {
	case s.loginChecks <- struct{}{}:
		defer func() { <-s.loginChecks }()
	case <-r.Context().Done():
		s.loginLimiter.cancel(key)
		writeAPIError(w, r, http.StatusServiceUnavailable, "request_canceled", "Login request was canceled")
		return
	}
	// Backup import holds the same gate from the state swap through runtime
	// postflight and session-key revocation. Serialize credential lookup and
	// token issuance with that interval so a login can never authenticate a
	// provisional restored password and survive a later rollback.
	if !s.acquireMutation(r.Context()) {
		s.loginLimiter.cancel(key)
		writeAPIError(w, r, http.StatusServiceUnavailable, "request_canceled", "Login request was canceled")
		return
	}
	defer s.releaseMutation()

	credential, err := s.services.Credentials.Credential(r.Context())
	if errors.Is(err, ErrNotFound) {
		_, _ = VerifyPBKDF2Record(s.dummyPasswordRecord, request.Password)
		writeAPIError(w, r, http.StatusUnauthorized, "invalid_credentials", "Invalid password")
		return
	}
	if err != nil {
		s.loginLimiter.cancel(key)
		writeServiceError(w, r, err)
		return
	}
	valid, err := VerifyPBKDF2Record(credential.PasswordRecord, request.Password)
	if err != nil {
		s.loginLimiter.cancel(key)
		writeAPIError(w, r, http.StatusInternalServerError, "authentication_unavailable", "Authentication is unavailable")
		return
	}
	if !valid {
		writeAPIError(w, r, http.StatusUnauthorized, "invalid_credentials", "Invalid password")
		return
	}
	if credential.UserID == "" {
		credential.UserID = "administrator"
	}
	token, claims, err := s.sessions.issue(r.Context(), credential)
	if err != nil {
		s.loginLimiter.cancel(key)
		writeAPIError(w, r, http.StatusInternalServerError, "authentication_unavailable", "Authentication is unavailable")
		return
	}
	s.loginLimiter.success(key)
	s.setSessionCookie(w, token)
	writeData(w, http.StatusOK, sessionResponse(claims))
}

func (s *Server) trustedLoginOrigin(r *http.Request) bool {
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	actual, err := parseCanonicalOrigin(origin)
	if err != nil {
		return false
	}
	expected, ok := s.expectedRequestOrigin(r)
	return ok && actual.scheme == expected.scheme && actual.host == expected.host
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	s.clearSessionCookie(w)
	writeData(w, http.StatusOK, struct {
		Authenticated bool `json:"authenticated"`
	}{Authenticated: false})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	claims, ok := claimsFromContext(r.Context())
	if !ok {
		writeAPIError(w, r, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	writeData(w, http.StatusOK, sessionResponse(claims))
}

func sessionResponse(claims sessionClaims) any {
	return struct {
		Authenticated bool      `json:"authenticated"`
		User          identity  `json:"user"`
		CSRFToken     string    `json:"csrfToken"`
		ExpiresAt     time.Time `json:"expiresAt"`
	}{
		Authenticated: true,
		User:          claims.identity(),
		CSRFToken:     claims.CSRF,
		ExpiresAt:     time.Unix(claims.ExpiresAt, 0).UTC(),
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	if s.services.Status == nil {
		writeUnsupported(w, r)
		return
	}
	status, err := s.services.Status.Status(r.Context())
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	sanitizeStatus(&status)
	writeData(w, http.StatusOK, status)
}

func (s *Server) handleEngines(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	if s.services.Engines == nil {
		writeUnsupported(w, r)
		return
	}
	engines, err := s.services.Engines.Engines(r.Context())
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	if engines == nil {
		engines = []EngineInfo{}
	}
	writeData(w, http.StatusOK, engines)
}

func (s *Server) handleEngineRoute(w http.ResponseWriter, r *http.Request) {
	segments, ok := routeSegments(r.URL.Path, "/api/v1/engines/")
	if !ok || len(segments) != 2 || segments[1] != "update" || !validProfileEngine(segments[0]) {
		writeAPIError(w, r, http.StatusNotFound, "not_found", "Engine endpoint not found")
		return
	}
	updates, ok := s.services.CoreUpdates.(EngineUpdateService)
	if !ok {
		writeUnsupported(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		status, err := updates.EngineUpdateStatus(r.Context(), segments[0])
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, status)
	case http.MethodPost:
		result, err := updates.InstallEngineUpdate(r.Context(), segments[0])
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, result)
	default:
		requireMethod(w, r, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if s.services.Settings == nil {
		writeUnsupported(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		settings, err := s.services.Settings.Settings(r.Context())
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, settings)
	case http.MethodPut, http.MethodPatch:
		var patch SettingsPatch
		if !s.decodeJSON(w, r, &patch) {
			return
		}
		settings, err := s.services.Settings.UpdateSettings(r.Context(), patch)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, settings)
	default:
		requireMethod(w, r, http.MethodGet, http.MethodPut, http.MethodPatch)
	}
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if s.services.Config == nil {
		writeUnsupported(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		document, err := s.services.Config.RawConfig(r.Context())
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, document)
	case http.MethodPut:
		var update RawConfigUpdate
		if !s.decodeJSON(w, r, &update) {
			return
		}
		result, err := s.services.Config.SaveRawConfig(r.Context(), update)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, result)
	default:
		requireMethod(w, r, http.MethodGet, http.MethodPut)
	}
}

func (s *Server) handleConfigValidation(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if s.services.Config == nil {
		writeUnsupported(w, r)
		return
	}
	var update RawConfigUpdate
	if !s.decodeJSON(w, r, &update) {
		return
	}
	validation, err := s.services.Config.ValidateRawConfig(r.Context(), update)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	for i := range validation.Diagnostics {
		validation.Diagnostics[i].Message = redactText(validation.Diagnostics[i].Message)
	}
	writeData(w, http.StatusOK, validation)
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	if s.services.Profiles == nil {
		writeUnsupported(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		profiles, err := s.services.Profiles.Profiles(r.Context())
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		sanitizeProfiles(profiles)
		writeData(w, http.StatusOK, profiles)
	case http.MethodPost:
		var draft ProfileDraft
		if !s.decodeJSON(w, r, &draft) {
			return
		}
		if draft.Engine == "" {
			draft.Engine = "mihomo"
		}
		if !validProfileEngine(draft.Engine) {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_engine", "Profile engine must be mihomo or sing-box")
			return
		}
		profile, err := s.services.Profiles.CreateProfile(r.Context(), draft)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		sanitizeProfile(&profile)
		writeData(w, http.StatusCreated, profile)
	default:
		requireMethod(w, r, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	if s.services.Profiles == nil {
		writeUnsupported(w, r)
		return
	}
	segments, ok := routeSegments(r.URL.Path, "/api/v1/profiles/")
	if !ok || len(segments) == 0 {
		writeAPIError(w, r, http.StatusNotFound, "not_found", "Profile not found")
		return
	}
	id := segments[0]
	if len(segments) == 2 && segments[1] == "activate" {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		request := ProfileActivationRequest{}
		if !s.decodeOptionalJSON(w, r, &request) {
			return
		}
		var profile Profile
		var err error
		if confirmed, ok := s.services.Profiles.(ConfirmedProfileService); ok {
			profile, err = confirmed.ActivateProfileWithRequest(r.Context(), id, request)
		} else {
			profile, err = s.services.Profiles.ActivateProfile(r.Context(), id)
		}
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		sanitizeProfile(&profile)
		writeData(w, http.StatusOK, profile)
		return
	}
	if len(segments) == 2 && segments[1] == "config" {
		configs, ok := s.services.Config.(ProfileConfigService)
		if !ok {
			writeUnsupported(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			document, err := configs.ProfileConfig(r.Context(), id)
			if err != nil {
				writeServiceError(w, r, err)
				return
			}
			writeData(w, http.StatusOK, document)
		case http.MethodPut:
			var update RawConfigUpdate
			if !s.decodeJSON(w, r, &update) {
				return
			}
			result, err := configs.SaveProfileConfig(r.Context(), id, update)
			if err != nil {
				writeServiceError(w, r, err)
				return
			}
			writeData(w, http.StatusOK, result)
		default:
			requireMethod(w, r, http.MethodGet, http.MethodPut)
		}
		return
	}
	if len(segments) == 3 && segments[1] == "config" && segments[2] == "validate" {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		configs, ok := s.services.Config.(ProfileConfigService)
		if !ok {
			writeUnsupported(w, r)
			return
		}
		var update RawConfigUpdate
		if !s.decodeJSON(w, r, &update) {
			return
		}
		validation, err := configs.ValidateProfileConfig(r.Context(), id, update)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		for i := range validation.Diagnostics {
			validation.Diagnostics[i].Message = redactText(validation.Diagnostics[i].Message)
		}
		writeData(w, http.StatusOK, validation)
		return
	}
	if len(segments) == 2 && segments[1] == "refresh" {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		profile, err := s.services.Profiles.RefreshProfile(r.Context(), id)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		sanitizeProfile(&profile)
		writeData(w, http.StatusOK, profile)
		return
	}
	if len(segments) == 3 && segments[1] == "source" && segments[2] == "detach" {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		profile, err := s.services.Profiles.DetachProfileSource(r.Context(), id)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		sanitizeProfile(&profile)
		writeData(w, http.StatusOK, profile)
		return
	}
	if len(segments) != 1 {
		writeAPIError(w, r, http.StatusNotFound, "not_found", "Profile not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		profile, err := s.services.Profiles.Profile(r.Context(), id)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		sanitizeProfile(&profile)
		writeData(w, http.StatusOK, profile)
	case http.MethodPut, http.MethodPatch:
		var patch ProfilePatch
		if !s.decodeJSON(w, r, &patch) {
			return
		}
		if patch.Engine != nil && !validProfileEngine(*patch.Engine) {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_engine", "Profile engine must be mihomo or sing-box")
			return
		}
		profile, err := s.services.Profiles.UpdateProfile(r.Context(), id, patch)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		sanitizeProfile(&profile)
		writeData(w, http.StatusOK, profile)
	case http.MethodDelete:
		if err := s.services.Profiles.DeleteProfile(r.Context(), id); err != nil {
			writeServiceError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		requireMethod(w, r, http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete)
	}
}

func (s *Server) handleProxySubscriptions(w http.ResponseWriter, r *http.Request) {
	if s.services.ProxySubscriptions == nil {
		writeUnsupported(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := s.services.ProxySubscriptions.ProxySubscriptions(r.Context())
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, items)
	case http.MethodPost:
		var draft ProxySubscriptionDraft
		if !s.decodeJSON(w, r, &draft) {
			return
		}
		item, err := s.services.ProxySubscriptions.CreateProxySubscription(r.Context(), draft)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusCreated, item)
	default:
		requireMethod(w, r, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) handleProxySubscription(w http.ResponseWriter, r *http.Request) {
	if s.services.ProxySubscriptions == nil {
		writeUnsupported(w, r)
		return
	}
	segments, ok := routeSegments(r.URL.Path, "/api/v1/proxy-subscriptions/")
	if !ok || len(segments) == 0 {
		writeAPIError(w, r, http.StatusNotFound, "not_found", "Proxy subscription not found")
		return
	}
	id := segments[0]
	if len(segments) == 2 && segments[1] == "refresh" {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		item, err := s.services.ProxySubscriptions.RefreshProxySubscription(r.Context(), id)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, item)
		return
	}
	if len(segments) != 1 {
		writeAPIError(w, r, http.StatusNotFound, "not_found", "Proxy subscription not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		item, err := s.services.ProxySubscriptions.ProxySubscription(r.Context(), id)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, item)
	case http.MethodPatch, http.MethodPut:
		var patch ProxySubscriptionPatch
		if !s.decodeJSON(w, r, &patch) {
			return
		}
		item, err := s.services.ProxySubscriptions.UpdateProxySubscription(r.Context(), id, patch)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, item)
	case http.MethodDelete:
		if err := s.services.ProxySubscriptions.DeleteProxySubscription(r.Context(), id); err != nil {
			writeServiceError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		requireMethod(w, r, http.MethodGet, http.MethodPatch, http.MethodPut, http.MethodDelete)
	}
}

func (s *Server) handleRuleLists(w http.ResponseWriter, r *http.Request) {
	if s.services.RuleLists == nil {
		writeUnsupported(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		lists, err := s.services.RuleLists.RuleLists(r.Context())
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, lists)
	case http.MethodPost:
		var draft RuleListDraft
		if !s.decodeJSON(w, r, &draft) {
			return
		}
		if !validRuleListNameAndFormat(draft.Name, draft.Format) {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_rule_list", "Rule list name and format are required")
			return
		}
		document, err := s.services.RuleLists.CreateRuleList(r.Context(), draft)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		setRevisionETag(w, document.Revision)
		writeData(w, http.StatusCreated, document)
	default:
		requireMethod(w, r, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) handleRuleList(w http.ResponseWriter, r *http.Request) {
	if s.services.RuleLists == nil {
		writeUnsupported(w, r)
		return
	}
	segments, ok := routeSegments(r.URL.Path, "/api/v1/rule-lists/")
	if !ok || len(segments) < 1 || len(segments) > 2 {
		writeAPIError(w, r, http.StatusNotFound, "not_found", "Rule list not found")
		return
	}
	id := segments[0]
	if len(segments) == 2 {
		if segments[1] != "config" {
			writeAPIError(w, r, http.StatusNotFound, "not_found", "Rule list action not found")
			return
		}
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		document, err := s.services.RuleLists.AddRuleListToConfig(r.Context(), id)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		setRevisionETag(w, document.Revision)
		writeData(w, http.StatusOK, document)
		return
	}
	switch r.Method {
	case http.MethodGet:
		document, err := s.services.RuleLists.RuleList(r.Context(), id)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		setRevisionETag(w, document.Revision)
		writeData(w, http.StatusOK, document)
	case http.MethodPut, http.MethodPatch:
		var update RuleListUpdate
		if !s.decodeJSON(w, r, &update) {
			return
		}
		headerRevision := parseRevisionHeader(r.Header.Get("If-Match"))
		if update.Revision == "" {
			update.Revision = headerRevision
		} else if headerRevision != "" && headerRevision != update.Revision {
			writeAPIError(w, r, http.StatusBadRequest, "revision_mismatch", "Body revision and If-Match do not match")
			return
		}
		if update.Revision == "" {
			writeAPIError(w, r, http.StatusPreconditionRequired, "revision_required", "Rule list revision is required")
			return
		}
		if update.Name != nil && (strings.TrimSpace(*update.Name) == "" || len(*update.Name) > 128) {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_rule_list", "Rule list name is invalid")
			return
		}
		if update.Format != nil && (strings.TrimSpace(*update.Format) == "" || len(*update.Format) > 32) {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_rule_list", "Rule list format is invalid")
			return
		}
		document, err := s.services.RuleLists.UpdateRuleList(r.Context(), id, update)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		setRevisionETag(w, document.Revision)
		writeData(w, http.StatusOK, document)
	case http.MethodDelete:
		revision := parseRevisionHeader(r.Header.Get("If-Match"))
		if revision == "" {
			revision = r.URL.Query().Get("revision")
		}
		if revision == "" {
			writeAPIError(w, r, http.StatusPreconditionRequired, "revision_required", "Rule list revision is required")
			return
		}
		if err := s.services.RuleLists.DeleteRuleList(r.Context(), id, revision); err != nil {
			writeServiceError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		requireMethod(w, r, http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete)
	}
}

func validRuleListNameAndFormat(name, format string) bool {
	name = strings.TrimSpace(name)
	format = strings.TrimSpace(format)
	return name != "" && len(name) <= 128 && format != "" && len(format) <= 32
}

func setRevisionETag(w http.ResponseWriter, revision string) {
	if revision != "" {
		w.Header().Set("ETag", strconv.Quote(revision))
	}
}

func parseRevisionHeader(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "W/") {
		value = strings.TrimSpace(strings.TrimPrefix(value, "W/"))
	}
	if unquoted, err := strconv.Unquote(value); err == nil {
		return unquoted
	}
	return strings.Trim(value, `"`)
}

func (s *Server) handleFakeIPWhitelist(w http.ResponseWriter, r *http.Request) {
	if s.services.FakeIPWhitelist == nil {
		writeUnsupported(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		document, err := s.services.FakeIPWhitelist.FakeIPWhitelist(r.Context())
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		sanitizeFakeIPWhitelistDocument(&document)
		setRevisionETag(w, document.Revision)
		writeData(w, http.StatusOK, document)
	case http.MethodPut:
		var update FakeIPWhitelistUpdate
		if !s.decodeJSON(w, r, &update) {
			return
		}
		update.Revision = parseRevisionHeader(r.Header.Get("If-Match"))
		if update.Revision == "" {
			writeAPIError(w, r, http.StatusPreconditionRequired, "revision_required", "Fake-IP whitelist revision is required")
			return
		}
		document, err := s.services.FakeIPWhitelist.UpdateFakeIPWhitelist(r.Context(), update)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		sanitizeFakeIPWhitelistDocument(&document)
		setRevisionETag(w, document.Revision)
		writeData(w, http.StatusOK, document)
	default:
		requireMethod(w, r, http.MethodGet, http.MethodPut)
	}
}

func (s *Server) handleFakeIPWhitelistRegenerate(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if s.services.FakeIPWhitelist == nil {
		writeUnsupported(w, r)
		return
	}
	revision := parseRevisionHeader(r.Header.Get("If-Match"))
	if revision == "" {
		writeAPIError(w, r, http.StatusPreconditionRequired, "revision_required", "Fake-IP whitelist revision is required")
		return
	}
	document, err := s.services.FakeIPWhitelist.RegenerateFakeIPWhitelist(r.Context(), revision)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	sanitizeFakeIPWhitelistDocument(&document)
	setRevisionETag(w, document.Revision)
	writeData(w, http.StatusOK, document)
}

func sanitizeFakeIPWhitelistDocument(document *FakeIPWhitelistDocument) {
	if document.GeneratedCIDRs == nil {
		document.GeneratedCIDRs = []string{}
	}
	if document.FakeIPRanges == nil {
		document.FakeIPRanges = []string{}
	}
	if document.EffectiveCIDRs == nil {
		document.EffectiveCIDRs = []string{}
	}
	if document.Warnings == nil {
		document.Warnings = []string{}
	}
	for index := range document.Warnings {
		document.Warnings[index] = redactText(document.Warnings[index])
	}
}

func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	if s.services.Backups == nil {
		writeUnsupported(w, r)
		return
	}
	if !s.acquireMutation(r.Context()) {
		writeAPIError(w, r, http.StatusServiceUnavailable, "request_canceled", "Request was canceled before it could run")
		return
	}
	defer s.releaseMutation()
	options, optionErr := backupExportOptions(r)
	if optionErr != nil {
		writeServiceError(w, r, optionErr)
		return
	}
	archive, err := s.services.Backups.ExportBackup(r.Context(), options)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	if int64(len(archive.Data)) > s.config.MaxBackupBytes {
		writeAPIError(w, r, http.StatusRequestEntityTooLarge, "backup_too_large", "Backup exceeds the configured size limit")
		return
	}
	filename := safeBackupFilename(archive.Filename)
	disposition := mime.FormatMediaType("attachment", map[string]string{"filename": filename})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", disposition)
	w.Header().Set("Content-Length", strconv.Itoa(len(archive.Data)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(archive.Data)
}

func backupExportOptions(r *http.Request) (BackupExportOptions, error) {
	parse := func(name string) (bool, error) {
		value := strings.TrimSpace(r.URL.Query().Get(name))
		if value == "" {
			return false, nil
		}
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return false, &PublicError{Status: http.StatusBadRequest, Code: "invalid_export_options", Message: "Backup export options must be true or false"}
		}
		return parsed, nil
	}
	adminPassword, err := parse("includeAdminPassword")
	if err != nil {
		return BackupExportOptions{}, err
	}
	providerCaches, err := parse("includeProviderCaches")
	if err != nil {
		return BackupExportOptions{}, err
	}
	dashboardUI, err := parse("includeDashboardUI")
	if err != nil {
		return BackupExportOptions{}, err
	}
	return BackupExportOptions{
		IncludeAdminPassword:  adminPassword,
		IncludeProviderCaches: providerCaches,
		IncludeDashboardUI:    dashboardUI,
	}, nil
}

func (s *Server) handleBackupImport(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if s.services.Backups == nil {
		writeUnsupported(w, r)
		return
	}
	backup, requestError := s.readBackup(w, r)
	if requestError != nil {
		writeServiceError(w, r, requestError)
		return
	}
	defer clear(backup.Data)
	if !s.acquireMutation(r.Context()) {
		writeAPIError(w, r, http.StatusServiceUnavailable, "request_canceled", "Request was canceled before it could run")
		return
	}
	defer s.releaseMutation()
	result, err := s.services.Backups.ImportBackup(r.Context(), backup)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	revokeContext, cancelRevoke := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	revokeErr := s.sessions.revokeAll(revokeContext)
	cancelRevoke()
	if revokeErr != nil {
		s.clearSessionCookie(w)
		writeAPIError(w, r, http.StatusInternalServerError, "session_revocation_failed", "Backup was restored, but browser sessions could not be revoked safely")
		return
	}
	result.SessionsRevoked = true
	s.clearSessionCookie(w)
	for i := range result.Warnings {
		result.Warnings[i] = redactText(result.Warnings[i])
	}
	writeData(w, http.StatusOK, result)
}

func (s *Server) readBackup(w http.ResponseWriter, r *http.Request) (BackupImport, error) {
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return BackupImport{}, &PublicError{Status: http.StatusUnsupportedMediaType, Code: "unsupported_media_type", Message: "Backup must be application/octet-stream or multipart/form-data"}
	}
	switch mediaType {
	case "application/octet-stream":
		if r.ContentLength > s.config.MaxBackupBytes {
			return BackupImport{}, backupTooLargeError()
		}
		r.Body = http.MaxBytesReader(w, r.Body, s.config.MaxBackupBytes+1)
		data, err := io.ReadAll(r.Body)
		if err != nil || int64(len(data)) > s.config.MaxBackupBytes {
			return BackupImport{}, backupTooLargeError()
		}
		if len(data) == 0 {
			return BackupImport{}, &PublicError{Status: http.StatusBadRequest, Code: "empty_backup", Message: "Backup is empty"}
		}
		filename := r.Header.Get("X-Backup-Filename")
		if disposition := r.Header.Get("Content-Disposition"); disposition != "" {
			if _, values, parseErr := mime.ParseMediaType(disposition); parseErr == nil && values["filename"] != "" {
				filename = values["filename"]
			}
		}
		return BackupImport{Filename: safeBackupFilename(filename), Data: data}, nil
	case "multipart/form-data":
		boundary := params["boundary"]
		if boundary == "" {
			return BackupImport{}, &PublicError{Status: http.StatusBadRequest, Code: "invalid_multipart", Message: "Multipart boundary is missing"}
		}
		overheadLimit := s.config.MaxBackupBytes + 1<<20
		r.Body = http.MaxBytesReader(w, r.Body, overheadLimit)
		reader := multipart.NewReader(r.Body, boundary)
		for partCount := 0; partCount < 32; partCount++ {
			part, nextErr := reader.NextPart()
			if errors.Is(nextErr, io.EOF) {
				break
			}
			if nextErr != nil {
				return BackupImport{}, &PublicError{Status: http.StatusBadRequest, Code: "invalid_multipart", Message: "Multipart backup is invalid"}
			}
			if part.FormName() != "backup" {
				_ = part.Close()
				continue
			}
			data, readErr := io.ReadAll(io.LimitReader(part, s.config.MaxBackupBytes+1))
			_ = part.Close()
			if readErr != nil || int64(len(data)) > s.config.MaxBackupBytes {
				return BackupImport{}, backupTooLargeError()
			}
			if len(data) == 0 {
				return BackupImport{}, &PublicError{Status: http.StatusBadRequest, Code: "empty_backup", Message: "Backup is empty"}
			}
			return BackupImport{Filename: safeBackupFilename(part.FileName()), Data: data}, nil
		}
		return BackupImport{}, &PublicError{Status: http.StatusBadRequest, Code: "backup_part_missing", Message: "Multipart field backup is required"}
	default:
		return BackupImport{}, &PublicError{Status: http.StatusUnsupportedMediaType, Code: "unsupported_media_type", Message: "Backup must be application/octet-stream or multipart/form-data"}
	}
}

func backupTooLargeError() error {
	return &PublicError{Status: http.StatusRequestEntityTooLarge, Code: "backup_too_large", Message: "Backup exceeds the configured size limit"}
}

func safeBackupFilename(filename string) string {
	filename = strings.ReplaceAll(filename, `\`, "/")
	filename = path.Base(strings.TrimSpace(filename))
	filename = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '"' || r == '/' || r == '\\' {
			return -1
		}
		return r
	}, filename)
	runes := []rune(filename)
	if len(runes) > 128 {
		filename = string(runes[:128])
	}
	if filename == "" || filename == "." || filename == ".." {
		return "boxctl-backup.bin"
	}
	return filename
}

func (s *Server) handleCore(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	if s.services.Core == nil {
		writeUnsupported(w, r)
		return
	}
	health, err := s.services.Core.Health(r.Context())
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	health.LastError = redactText(health.LastError)
	writeData(w, http.StatusOK, health)
}

func (s *Server) handleCoreRoute(w http.ResponseWriter, r *http.Request) {
	if s.services.Core == nil {
		writeUnsupported(w, r)
		return
	}
	segments, ok := routeSegments(r.URL.Path, "/api/v1/core/")
	if !ok || len(segments) == 0 {
		writeAPIError(w, r, http.StatusNotFound, "not_found", "Core endpoint not found")
		return
	}
	switch segments[0] {
	case "capabilities":
		if len(segments) != 1 {
			writeAPIError(w, r, http.StatusNotFound, "not_found", "Core endpoint not found")
			return
		}
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		capabilities, err := s.services.Core.Capabilities(r.Context())
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		if capabilities.Pages == nil {
			capabilities.Pages = map[string]bool{}
		}
		if capabilities.Actions == nil {
			capabilities.Actions = map[string]bool{}
		}
		writeData(w, http.StatusOK, capabilities)
	case "reload":
		if len(segments) != 1 {
			writeAPIError(w, r, http.StatusNotFound, "not_found", "Core endpoint not found")
			return
		}
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		if err := s.services.Core.Reload(r.Context()); err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusAccepted, struct {
			Accepted bool `json:"accepted"`
		}{Accepted: true})
	case "update":
		if len(segments) != 1 {
			writeAPIError(w, r, http.StatusNotFound, "not_found", "Core endpoint not found")
			return
		}
		if s.services.CoreUpdates == nil {
			writeUnsupported(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			status, err := s.services.CoreUpdates.CoreUpdateStatus(r.Context())
			if err != nil {
				writeServiceError(w, r, err)
				return
			}
			writeData(w, http.StatusOK, status)
		case http.MethodPost:
			result, err := s.services.CoreUpdates.InstallCoreUpdate(r.Context())
			if err != nil {
				writeServiceError(w, r, err)
				return
			}
			writeData(w, http.StatusOK, result)
		default:
			requireMethod(w, r, http.MethodGet, http.MethodPost)
		}
	case "proxies":
		s.handleCoreProxies(w, r, segments[1:])
	case "dashboard":
		s.handleCoreDashboard(w, r, segments[1:])
	case "providers":
		s.handleCoreProviders(w, r, segments[1:])
	case "connections":
		s.handleCoreConnections(w, r, segments[1:])
	case "rules":
		if len(segments) != 1 {
			writeAPIError(w, r, http.StatusNotFound, "not_found", "Core endpoint not found")
			return
		}
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		rules, err := s.services.Core.Rules(r.Context())
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, rules)
	case "logs":
		s.handleCoreLogs(w, r, segments[1:])
	default:
		writeAPIError(w, r, http.StatusNotFound, "not_found", "Core endpoint not found")
	}
}

func (s *Server) handleExternalDashboard(w http.ResponseWriter, r *http.Request) {
	if s.services.ExternalDashboard == nil {
		writeUnsupported(w, r)
		return
	}
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	checkUpdates := false
	if raw := strings.TrimSpace(r.URL.Query().Get("checkUpdates")); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_query", "checkUpdates must be true or false")
			return
		}
		checkUpdates = parsed
	}
	status, err := s.services.ExternalDashboard.ExternalDashboardStatus(r.Context(), checkUpdates)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeData(w, http.StatusOK, status)
}

func (s *Server) handleExternalDashboardRoute(w http.ResponseWriter, r *http.Request) {
	if s.services.ExternalDashboard == nil {
		writeUnsupported(w, r)
		return
	}
	segment := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/external-dashboard/"), "/")
	switch segment {
	case "install":
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		result, err := s.services.ExternalDashboard.InstallExternalDashboard(r.Context())
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, result)
	case "update":
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		result, err := s.services.ExternalDashboard.UpdateExternalDashboard(r.Context())
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, result)
	case "open":
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		result, err := s.services.ExternalDashboard.OpenExternalDashboard(r.Context())
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, result)
	default:
		writeAPIError(w, r, http.StatusNotFound, "not_found", "External dashboard endpoint not found")
	}
}

func (s *Server) handleCoreDashboard(w http.ResponseWriter, r *http.Request, segments []string) {
	if len(segments) == 0 {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		dashboard, err := s.services.Core.Dashboard(r.Context())
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, dashboard)
		return
	}
	if len(segments) == 1 && segments[0] == "stream" {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		stream, err := s.services.Core.StreamDashboard(r.Context())
		serveDashboardStream(w, r, stream, err)
		return
	}
	if len(segments) == 1 && segments[0] == "mode" {
		if !requireMethod(w, r, http.MethodPut) {
			return
		}
		var request struct {
			Mode string `json:"mode"`
		}
		if !s.decodeJSON(w, r, &request) {
			return
		}
		if err := s.services.Core.SetRoutingMode(r.Context(), request.Mode); err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, struct {
			Mode string `json:"mode"`
		}{Mode: strings.ToLower(strings.TrimSpace(request.Mode))})
		return
	}
	writeAPIError(w, r, http.StatusNotFound, "not_found", "Dashboard endpoint not found")
}

func serveDashboardStream(w http.ResponseWriter, r *http.Request, stream <-chan CoreDashboard, err error) {
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	if stream == nil {
		writeAPIError(w, r, http.StatusInternalServerError, "stream_unavailable", "Dashboard stream is unavailable")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeAPIError(w, r, http.StatusInternalServerError, "stream_unsupported", "Streaming is not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "retry: 3000\n\n")
	flusher.Flush()

	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if _, writeErr := fmt.Fprint(w, ": keepalive\n\n"); writeErr != nil {
				return
			}
			flusher.Flush()
		case dashboard, ok := <-stream:
			if !ok {
				return
			}
			payload, marshalErr := json.Marshal(dashboard)
			if marshalErr != nil {
				return
			}
			if _, writeErr := fmt.Fprintf(w, "event: dashboard\ndata: %s\n\n", payload); writeErr != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleCoreProxies(w http.ResponseWriter, r *http.Request, segments []string) {
	if len(segments) == 1 && segments[0] == "delay" {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		var request struct {
			Proxy     string `json:"proxy"`
			URL       string `json:"url"`
			TimeoutMS int64  `json:"timeoutMs"`
		}
		if !s.decodeJSON(w, r, &request) {
			return
		}
		request.URL = strings.TrimSpace(request.URL)
		if !validCoreIdentifier(request.Proxy) {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_proxy", "Proxy name is required and must be valid")
			return
		}
		if !validDelayTestURL(request.URL) {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_test_url", "Test URL must be an absolute HTTP or HTTPS URL without credentials")
			return
		}
		if request.TimeoutMS <= 0 || request.TimeoutMS > 60_000 {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_timeout", "Timeout must be between 1 and 60000 milliseconds")
			return
		}
		result, err := s.services.Core.TestProxyDelay(r.Context(), request.Proxy, request.URL, time.Duration(request.TimeoutMS)*time.Millisecond)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, result)
		return
	}
	if len(segments) == 0 && r.Method == http.MethodGet {
		groups, err := s.services.Core.ProxyGroups(r.Context())
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, groups)
		return
	}
	if r.Method == http.MethodPut && len(segments) <= 1 {
		var request struct {
			Group string `json:"group"`
			Proxy string `json:"proxy"`
		}
		if !s.decodeJSON(w, r, &request) {
			return
		}
		if len(segments) == 1 && request.Group == "" {
			request.Group = segments[0]
		}
		if request.Group == "" || request.Proxy == "" || len(request.Group) > 512 || len(request.Proxy) > 512 {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "Proxy group and proxy are required")
			return
		}
		if err := s.services.Core.SelectProxy(r.Context(), request.Group, request.Proxy); err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, struct {
			Group string `json:"group"`
			Proxy string `json:"proxy"`
		}{Group: request.Group, Proxy: request.Proxy})
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		requireMethod(w, r, http.MethodGet, http.MethodPut)
		return
	}
	writeAPIError(w, r, http.StatusNotFound, "not_found", "Proxy endpoint not found")
}

func (s *Server) handleCoreProviders(w http.ResponseWriter, r *http.Request, segments []string) {
	if len(segments) < 1 || len(segments) > 2 {
		writeAPIError(w, r, http.StatusNotFound, "not_found", "Provider endpoint not found")
		return
	}
	kind, ok := parseProviderKind(segments[0])
	if !ok {
		writeAPIError(w, r, http.StatusBadRequest, "invalid_provider_kind", "Provider kind must be proxy or rule")
		return
	}
	if len(segments) == 1 {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		providers, err := s.services.Core.Providers(r.Context(), kind)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeData(w, http.StatusOK, providers)
		return
	}
	if !requireMethod(w, r, http.MethodPut) {
		return
	}
	name := segments[1]
	if !validCoreIdentifier(name) {
		writeAPIError(w, r, http.StatusBadRequest, "invalid_provider_name", "Provider name is required and must be valid")
		return
	}
	if err := s.services.Core.UpdateProvider(r.Context(), kind, name); err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeData(w, http.StatusOK, struct {
		Kind    ProviderKind `json:"kind"`
		Name    string       `json:"name"`
		Updated bool         `json:"updated"`
	}{Kind: kind, Name: name, Updated: true})
}

func parseProviderKind(value string) (ProviderKind, bool) {
	switch ProviderKind(value) {
	case ProviderProxy:
		return ProviderProxy, true
	case ProviderRule:
		return ProviderRule, true
	default:
		return "", false
	}
}

func validCoreIdentifier(value string) bool {
	if value == "" || strings.TrimSpace(value) == "" || len(value) > 512 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validDelayTestURL(value string) bool {
	if value == "" || len(value) > 4_096 || !utf8.ValidString(value) {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
}

func (s *Server) handleCoreConnections(w http.ResponseWriter, r *http.Request, segments []string) {
	if len(segments) == 1 && segments[0] == "stream" {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		stream, err := s.services.Core.StreamConnections(r.Context())
		serveConnectionsStream(w, r, stream, err)
		return
	}
	if len(segments) == 0 {
		switch r.Method {
		case http.MethodGet:
			connections, err := s.services.Core.Connections(r.Context())
			if err != nil {
				writeServiceError(w, r, err)
				return
			}
			writeData(w, http.StatusOK, connections)
		case http.MethodDelete:
			if err := s.services.Core.CloseAllConnections(r.Context()); err != nil {
				writeServiceError(w, r, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			requireMethod(w, r, http.MethodGet, http.MethodDelete)
		}
		return
	}
	if len(segments) == 1 && r.Method == http.MethodDelete {
		if err := s.services.Core.CloseConnection(r.Context(), segments[0]); err != nil {
			writeServiceError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodDelete {
		requireMethod(w, r, http.MethodGet, http.MethodDelete)
		return
	}
	writeAPIError(w, r, http.StatusNotFound, "not_found", "Connection endpoint not found")
}

func serveConnectionsStream(w http.ResponseWriter, r *http.Request, stream <-chan ConnectionStreamSnapshot, err error) {
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	if stream == nil {
		writeAPIError(w, r, http.StatusInternalServerError, "stream_unavailable", "Connection stream is unavailable")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeAPIError(w, r, http.StatusInternalServerError, "stream_unsupported", "Streaming is not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "retry: 3000\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case snapshot, ok := <-stream:
			if !ok {
				return
			}
			payload, marshalErr := json.Marshal(snapshot)
			if marshalErr != nil {
				return
			}
			if _, writeErr := fmt.Fprintf(w, "event: connections\ndata: %s\n\n", payload); writeErr != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleCoreLogs(w http.ResponseWriter, r *http.Request, segments []string) {
	if len(segments) == 0 {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		entries, err := s.services.Core.CoreLogs(r.Context(), parseLogQuery(r))
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		sanitizeLogs(entries)
		writeData(w, http.StatusOK, entries)
		return
	}
	if len(segments) == 1 && segments[0] == "stream" {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		stream, err := s.services.Core.StreamCoreLogs(r.Context(), parseLogQuery(r))
		serveLogStream(w, r, stream, err)
		return
	}
	writeAPIError(w, r, http.StatusNotFound, "not_found", "Core log endpoint not found")
}

func (s *Server) handleSystemLogs(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	if s.services.SystemLogs == nil {
		writeUnsupported(w, r)
		return
	}
	entries, err := s.services.SystemLogs.SystemLogs(r.Context(), parseLogQuery(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	sanitizeLogs(entries)
	writeData(w, http.StatusOK, entries)
}

func (s *Server) handleLifecycle(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if s.services.Lifecycle == nil {
		writeUnsupported(w, r)
		return
	}
	segments, ok := routeSegments(r.URL.Path, "/api/v1/service/")
	if !ok || len(segments) != 1 {
		writeAPIError(w, r, http.StatusNotFound, "not_found", "Service action not found")
		return
	}
	var err error
	switch segments[0] {
	case "start":
		err = s.services.Lifecycle.Start(r.Context())
	case "stop":
		err = s.services.Lifecycle.Stop(r.Context())
	case "restart":
		err = s.services.Lifecycle.Restart(r.Context())
	default:
		writeAPIError(w, r, http.StatusNotFound, "not_found", "Service action not found")
		return
	}
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeData(w, http.StatusAccepted, struct {
		Action   string `json:"action"`
		Accepted bool   `json:"accepted"`
	}{Action: segments[0], Accepted: true})
}

func (s *Server) handleSystemLogStream(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	if s.services.SystemLogs == nil {
		writeUnsupported(w, r)
		return
	}
	stream, err := s.services.SystemLogs.StreamSystemLogs(r.Context(), parseLogQuery(r))
	serveLogStream(w, r, stream, err)
}

func serveLogStream(w http.ResponseWriter, r *http.Request, stream <-chan LogEntry, err error) {
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	if stream == nil {
		writeAPIError(w, r, http.StatusInternalServerError, "stream_unavailable", "Log stream is unavailable")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeAPIError(w, r, http.StatusInternalServerError, "stream_unsupported", "Streaming is not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "retry: 3000\n\n")
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case entry, ok := <-stream:
			if !ok {
				return
			}
			sanitizeLog(&entry)
			payload, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "event: log\ndata: %s\n\n", payload)
			flusher.Flush()
		}
	}
}

func routeSegments(requestPath, prefix string) ([]string, bool) {
	if !strings.HasPrefix(requestPath, prefix) {
		return nil, false
	}
	rest := strings.Trim(strings.TrimPrefix(requestPath, prefix), "/")
	if rest == "" {
		return nil, true
	}
	raw := strings.Split(rest, "/")
	segments := make([]string, 0, len(raw))
	for _, value := range raw {
		decoded, err := url.PathUnescape(value)
		if err != nil || decoded == "" || decoded == "." || decoded == ".." || len(decoded) > 1_024 {
			return nil, false
		}
		segments = append(segments, decoded)
	}
	return segments, true
}

func sanitizeStatus(status *StatusSnapshot) {
	status.Core.LastError = redactText(status.Core.LastError)
	for i := range status.Warnings {
		status.Warnings[i].Message = redactText(status.Warnings[i].Message)
	}
}

func sanitizeProfiles(profiles []Profile) {
	for i := range profiles {
		sanitizeProfile(&profiles[i])
	}
}

func sanitizeProfile(profile *Profile) {
	if profile.Engine == "" {
		profile.Engine = "mihomo"
	}
	profile.LastError = redactText(profile.LastError)
}

func validProfileEngine(engine string) bool {
	return engine == "mihomo" || engine == "sing-box"
}

func sanitizeLogs(entries []LogEntry) {
	for i := range entries {
		sanitizeLog(&entries[i])
	}
}

func sanitizeLog(entry *LogEntry) {
	entry.Message = redactText(entry.Message)
	entry.Fields = sanitizeFields(entry.Fields)
}

func sanitizeFields(fields map[string]any) map[string]any {
	if len(fields) == 0 {
		return fields
	}
	result := make(map[string]any, len(fields))
	for key, value := range fields {
		if sensitiveField(key) {
			result[key] = "[redacted]"
			continue
		}
		result[key] = sanitizeValue(value)
	}
	return result
}

func sanitizeValue(value any) any {
	switch typed := value.(type) {
	case string:
		return redactText(typed)
	case map[string]any:
		return sanitizeFields(typed)
	case []any:
		result := make([]any, len(typed))
		for i := range typed {
			result[i] = sanitizeValue(typed[i])
		}
		return result
	case []string:
		result := make([]string, len(typed))
		for i := range typed {
			result[i] = redactText(typed[i])
		}
		return result
	case map[string]string:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			if sensitiveField(key) {
				result[key] = "[redacted]"
			} else {
				result[key] = redactText(item)
			}
		}
		return result
	case error:
		return redactText(typed.Error())
	default:
		return value
	}
}

func sensitiveField(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(key))
	for _, part := range []string{
		"password", "passwd", "secret", "token", "authorization", "cookie", "credential", "private",
		"apikey", "url", "uri", "path", "controller", "subscription",
	} {
		if strings.Contains(normalized, part) {
			return true
		}
	}
	return false
}

func redactText(value string) string {
	value = eventlog.RedactText(value)
	value = strings.ReplaceAll(value, "[REDACTED_PATH]", "[redacted_path]")
	return strings.ReplaceAll(value, "[REDACTED]", "[redacted]")
}
