package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const passkeyLifetime = 5 * time.Minute
const maxPasskeys = 32
const maxPasskeyCeremonies = 256

// PasskeyState is private credential state, never the settings API response.
// Only public keys are stored; the authenticator retains the private keys.
type PasskeyState struct {
	UserHandle []byte          `json:"userHandle"`
	Passkeys   []StoredPasskey `json:"passkeys"`
}

type StoredPasskey struct {
	Credential webauthn.Credential `json:"credential"`
	RPID       string              `json:"rpId"`
	Name       string              `json:"name"`
	CreatedAt  time.Time           `json:"createdAt"`
	LastUsedAt *time.Time          `json:"lastUsedAt,omitempty"`
}

// UpdatePasskeys must read fresh state and the current password under a lock,
// run update, then persist atomically. A failed callback must not save anything.
type PasskeyStore interface {
	LoadPasskeys(context.Context) (PasskeyState, error)
	UpdatePasskeys(context.Context, func(*PasskeyState, Credential) error) error
}

type passkeySummary struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	RPID       string     `json:"rpId"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
}

type passkeyUser struct {
	state PasskeyState
	rpID  string
}

func (u passkeyUser) WebAuthnID() []byte          { return u.state.UserHandle }
func (u passkeyUser) WebAuthnName() string        { return "Administrator" }
func (u passkeyUser) WebAuthnDisplayName() string { return "boxctl Administrator" }
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential {
	result := make([]webauthn.Credential, 0, len(u.state.Passkeys))
	for _, key := range u.state.Passkeys {
		if key.RPID == u.rpID {
			result = append(result, key.Credential)
		}
	}
	return result
}

type passkeyCeremony struct {
	Session      webauthn.SessionData
	Origin       string
	SessionID    string
	PasswordHash [32]byte
	UserHandle   []byte
	Name         string
	ExpiresAt    time.Time
}

type passkeyCeremonies struct {
	mu      sync.Mutex
	pending map[string]passkeyCeremony
}

func (s *Server) rememberPasskey(c passkeyCeremony) (string, error) {
	id, err := randomToken(rand.Reader, 32)
	if err != nil {
		return "", err
	}
	s.passkeyCeremonies.mu.Lock()
	defer s.passkeyCeremonies.mu.Unlock()
	if s.passkeyCeremonies.pending == nil {
		s.passkeyCeremonies.pending = make(map[string]passkeyCeremony)
	}
	for key, pending := range s.passkeyCeremonies.pending {
		if !s.config.now().Before(pending.ExpiresAt) {
			delete(s.passkeyCeremonies.pending, key)
		}
	}
	if len(s.passkeyCeremonies.pending) >= maxPasskeyCeremonies {
		return "", &PublicError{Status: http.StatusTooManyRequests, Code: "rate_limited", Message: "Too many pending passkey requests"}
	}
	c.ExpiresAt = s.config.now().Add(passkeyLifetime)
	s.passkeyCeremonies.pending[id] = c
	return id, nil
}

func (s *Server) consumePasskey(id, origin, sessionID string) (passkeyCeremony, bool) {
	s.passkeyCeremonies.mu.Lock()
	defer s.passkeyCeremonies.mu.Unlock()
	c, ok := s.passkeyCeremonies.pending[id]
	delete(s.passkeyCeremonies.pending, id)
	return c, ok && s.config.now().Before(c.ExpiresAt) && c.Origin == origin && c.SessionID == sessionID
}

// Derive the exact RP from the effective server origin, never from an Origin or
// forwarded header supplied by a client. PublicOrigin already covers TLS proxies.
func (s *Server) passkeyRP(r *http.Request) (*webauthn.WebAuthn, string, error) {
	origin, ok := s.expectedRequestOrigin(r)
	if !ok || net.ParseIP(origin.hostname) != nil || (origin.scheme != "https" && origin.hostname != "localhost") {
		return nil, "", &PublicError{Status: http.StatusBadRequest, Code: "passkey_origin_unavailable", Message: "Passkeys require an HTTPS domain name or localhost"}
	}
	value := origin.scheme + "://" + origin.host
	rp, err := webauthn.New(&webauthn.Config{
		RPID: origin.hostname, RPDisplayName: "boxctl", RPOrigins: []string{value},
		AttestationPreference:  protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: protocol.ResidentKeyRequired(), UserVerification: protocol.VerificationRequired},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: passkeyLifetime},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: passkeyLifetime},
		},
	})
	return rp, value, err
}

func (s *Server) passkeyRequest(w http.ResponseWriter, r *http.Request) bool {
	if s.services.Passkeys == nil {
		writeUnsupported(w, r)
		return false
	}
	if !s.trustedLoginOrigin(r) {
		writeAPIError(w, r, http.StatusForbidden, "origin_rejected", "Cross-site passkey requests are not allowed")
		return false
	}
	return true
}

func (s *Server) reservePasskeyAttempt(w http.ResponseWriter, r *http.Request, key string) bool {
	if allowed, retry := s.loginLimiter.reserve(key); !allowed {
		w.Header().Set("Retry-After", strconv.FormatInt(max(1, int64((retry+time.Second-1)/time.Second)), 10))
		writeAPIError(w, r, http.StatusTooManyRequests, "rate_limited", "Too many authentication attempts")
		return false
	}
	return true
}

func verifyPasskeyPassword(credential Credential, password string) error {
	if password != "" && len(password) <= 4096 {
		valid, err := VerifyPBKDF2Record(credential.PasswordRecord, password)
		if err != nil {
			return err
		}
		if valid {
			return nil
		}
	}
	// A wrong confirmation password is not an expired browser session.
	return &PublicError{Status: http.StatusForbidden, Code: "invalid_password", Message: "Invalid administrator password"}
}

func passkeyFailure() error {
	return &PublicError{Status: http.StatusBadRequest, Code: "passkey_verification_failed", Message: "Passkey verification failed. Please try again"}
}

func passkeySummaries(state PasskeyState) []passkeySummary {
	result := make([]passkeySummary, 0, len(state.Passkeys))
	for _, key := range state.Passkeys {
		result = append(result, passkeySummary{ID: base64.RawURLEncoding.EncodeToString(key.Credential.ID), Name: key.Name, RPID: key.RPID, CreatedAt: key.CreatedAt, LastUsedAt: key.LastUsedAt})
	}
	return result
}

func (s *Server) handlePasskeys(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodDelete) || !s.passkeyRequest(w, r) {
		return
	}
	if r.Method == http.MethodGet {
		current, err := s.services.Passkeys.LoadPasskeys(r.Context())
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		rp, _, rpErr := s.passkeyRP(r)
		rpID := ""
		if rpErr == nil {
			rpID = rp.Config.RPID
		}
		writeData(w, http.StatusOK, struct {
			Passkeys              []passkeySummary `json:"passkeys"`
			RegistrationAvailable bool             `json:"registrationAvailable"`
			RPID                  string           `json:"rpId"`
			Limit                 int              `json:"limit"`
		}{passkeySummaries(current), rpErr == nil, rpID, maxPasskeys})
		return
	}
	var input struct {
		ID       string `json:"id"`
		Password string `json:"password"`
	}
	if !s.decodeJSON(w, r, &input) {
		return
	}
	key := "passkey-manage:" + loginKey(r)
	if !s.reservePasskeyAttempt(w, r, key) {
		return
	}
	err := s.services.Passkeys.UpdatePasskeys(r.Context(), func(current *PasskeyState, credential Credential) error {
		if err := verifyPasskeyPassword(credential, input.Password); err != nil {
			return err
		}
		for i, stored := range current.Passkeys {
			if base64.RawURLEncoding.EncodeToString(stored.Credential.ID) == input.ID {
				current.Passkeys = append(current.Passkeys[:i], current.Passkeys[i+1:]...)
				return nil
			}
		}
		return ErrNotFound
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	s.loginLimiter.success(key)
	w.WriteHeader(http.StatusNoContent)
}

func validPasskeyName(name string) bool {
	return utf8.ValidString(name) && utf8.RuneCountInString(name) >= 1 && utf8.RuneCountInString(name) <= 64 && strings.IndexFunc(name, unicode.IsControl) == -1
}

func (s *Server) handlePasskeyRegistrationBegin(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !s.passkeyRequest(w, r) {
		return
	}
	var input struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if !s.decodeJSON(w, r, &input) {
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if !validPasskeyName(input.Name) {
		writeAPIError(w, r, http.StatusBadRequest, "invalid_passkey_name", "Passkey name must contain 1 to 64 characters without control characters")
		return
	}
	rp, origin, err := s.passkeyRP(r)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	key := "passkey-manage:" + loginKey(r)
	if !s.reservePasskeyAttempt(w, r, key) {
		return
	}
	var current PasskeyState
	var admin Credential
	err = s.services.Passkeys.UpdatePasskeys(r.Context(), func(state *PasskeyState, credential Credential) error {
		if err := verifyPasskeyPassword(credential, input.Password); err != nil {
			return err
		}
		if len(state.Passkeys) >= maxPasskeys {
			return &PublicError{Status: http.StatusConflict, Code: "passkey_limit", Message: "Passkey limit reached"}
		}
		if len(state.UserHandle) == 0 {
			state.UserHandle = make([]byte, 32)
			if _, err := rand.Read(state.UserHandle); err != nil {
				return err
			}
		}
		current, admin = *state, credential
		return nil
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	user := passkeyUser{current, rp.Config.RPID}
	exclude := make([]protocol.CredentialDescriptor, 0)
	for _, credential := range user.WebAuthnCredentials() {
		exclude = append(exclude, credential.Descriptor())
	}
	options, session, err := rp.BeginRegistration(user, webauthn.WithExclusions(exclude), webauthn.WithExtensions(webauthn.WithExtensionCredProps()))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	claims, _ := claimsFromContext(r.Context())
	id, err := s.rememberPasskey(passkeyCeremony{Session: *session, Origin: origin, SessionID: claims.SessionID, PasswordHash: sha256.Sum256([]byte(admin.PasswordRecord)), UserHandle: current.UserHandle, Name: input.Name})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	s.loginLimiter.success(key)
	writeData(w, http.StatusOK, struct {
		CeremonyID string                       `json:"ceremonyId"`
		Options    *protocol.CredentialCreation `json:"options"`
	}{id, options})
}

type passkeyFinishRequest struct {
	CeremonyID string          `json:"ceremonyId"`
	Credential json.RawMessage `json:"credential"`
}

func (s *Server) handlePasskeyRegistrationFinish(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !s.passkeyRequest(w, r) {
		return
	}
	var input passkeyFinishRequest
	if !s.decodeJSON(w, r, &input) {
		return
	}
	rp, origin, err := s.passkeyRP(r)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	claims, _ := claimsFromContext(r.Context())
	ceremony, ok := s.consumePasskey(input.CeremonyID, origin, claims.SessionID)
	if !ok {
		writeServiceError(w, r, passkeyFailure())
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(input.Credential)
	if err != nil {
		writeServiceError(w, r, passkeyFailure())
		return
	}
	var result []passkeySummary
	err = s.services.Passkeys.UpdatePasskeys(r.Context(), func(current *PasskeyState, credential Credential) error {
		if sha256.Sum256([]byte(credential.PasswordRecord)) != ceremony.PasswordHash || !bytes.Equal(current.UserHandle, ceremony.UserHandle) {
			return passkeyFailure()
		}
		if len(current.Passkeys) >= maxPasskeys {
			return &PublicError{Status: http.StatusConflict, Code: "passkey_limit", Message: "Passkey limit reached"}
		}
		registered, err := rp.CreateCredential(passkeyUser{*current, rp.Config.RPID}, ceremony.Session, parsed)
		if err != nil {
			return passkeyFailure()
		}
		if registered.Extensions.RK != nil && !*registered.Extensions.RK {
			return passkeyFailure()
		}
		for _, stored := range current.Passkeys {
			if bytes.Equal(stored.Credential.ID, registered.ID) {
				return &PublicError{Status: http.StatusConflict, Code: "passkey_exists", Message: "This passkey is already registered"}
			}
		}
		current.Passkeys = append(current.Passkeys, StoredPasskey{Credential: *registered, RPID: rp.Config.RPID, Name: ceremony.Name, CreatedAt: s.config.now().UTC()})
		result = passkeySummaries(*current)
		return nil
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeData(w, http.StatusCreated, result)
}

// Public ceremony handlers bound/read the body before acquiring the mutation
// gate, so slow unauthenticated uploads cannot block the rest of the panel.
func (s *Server) beginPublicPasskeyRequest(w http.ResponseWriter, r *http.Request, input any) bool {
	if !requireMethod(w, r, http.MethodPost) || !s.passkeyRequest(w, r) {
		return false
	}
	if !s.reservePasskeyAttempt(w, r, "passkey-login:"+loginKey(r)) {
		return false
	}
	if !s.decodeJSON(w, r, input) {
		return false
	}
	if !s.acquireMutation(r.Context()) {
		writeAPIError(w, r, http.StatusServiceUnavailable, "request_canceled", "Request canceled")
		return false
	}
	return true
}

func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if !s.beginPublicPasskeyRequest(w, r, &input) {
		return
	}
	defer s.releaseMutation()
	rp, origin, err := s.passkeyRP(r)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	// Do not reveal credential IDs or whether the administrator has passkeys.
	options, session, err := rp.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	id, err := s.rememberPasskey(passkeyCeremony{Session: *session, Origin: origin})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeData(w, http.StatusOK, struct {
		CeremonyID string                        `json:"ceremonyId"`
		Options    *protocol.CredentialAssertion `json:"options"`
	}{id, options})
}

func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	var input passkeyFinishRequest
	if !s.beginPublicPasskeyRequest(w, r, &input) {
		return
	}
	defer s.releaseMutation()
	rp, origin, err := s.passkeyRP(r)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	ceremony, ok := s.consumePasskey(input.CeremonyID, origin, "")
	if !ok {
		writeServiceError(w, r, passkeyFailure())
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(input.Credential)
	if err != nil {
		writeServiceError(w, r, passkeyFailure())
		return
	}
	var admin Credential
	err = s.services.Passkeys.UpdatePasskeys(r.Context(), func(current *PasskeyState, credential Credential) error {
		verified, err := rp.ValidateDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
			if len(current.UserHandle) == 0 || !bytes.Equal(current.UserHandle, userHandle) {
				return nil, passkeyFailure()
			}
			return passkeyUser{*current, rp.Config.RPID}, nil
		}, ceremony.Session, parsed)
		if err != nil || verified.Authenticator.CloneWarning {
			return passkeyFailure()
		}
		for i := range current.Passkeys {
			if current.Passkeys[i].RPID == rp.Config.RPID && bytes.Equal(current.Passkeys[i].Credential.ID, verified.ID) {
				now := s.config.now().UTC()
				current.Passkeys[i].Credential = *verified
				current.Passkeys[i].LastUsedAt = &now
				admin = credential
				return nil
			}
		}
		return passkeyFailure()
	})
	if errors.Is(err, ErrNotFound) {
		err = passkeyFailure()
	}
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	if admin.UserID == "" {
		admin.UserID = "administrator"
	}
	token, claims, err := s.sessions.issue(r.Context(), admin)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	s.loginLimiter.success("passkey-login:" + loginKey(r))
	s.setSessionCookie(w, token)
	writeData(w, http.StatusOK, sessionResponse(claims))
}
