package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	defaultCookieName      = "boxctl_session"
	defaultSessionTTL      = 12 * time.Hour
	defaultSecretRotation  = 30 * 24 * time.Hour
	defaultLoginLimit      = 5
	defaultLoginWindow     = 5 * time.Minute
	defaultMaxRequestBytes = 1 << 20
	defaultMaxBackupBytes  = 32 << 20
	styleNoncePlaceholder  = "__BOXCTL_STYLE_NONCE__"
)

// Keep these paths explicit: a direct Go build from a clean checkout must fail
// clearly when the generated frontend was not built first. The Makefile builds
// it before every Go compile/test target.
//
//go:embed static/index.html static/assets static/favicon.svg
var embeddedStatic embed.FS

// Config controls HTTP-only concerns. CookieSecure should be enabled whenever
// the management UI is served over HTTPS.
type Config struct {
	CookieName   string
	CookieSecure bool
	// PublicOrigin is the externally visible http(s) origin when TLS terminates
	// at a reverse proxy. The proxy must preserve the original Host header.
	PublicOrigin string
	// AllowedHosts contains host names that may perform the unauthenticated
	// first-run administrator setup. IP literals and localhost are always
	// accepted. Populate this when the UI is intentionally exposed through a
	// stable DNS name or reverse proxy.
	AllowedHosts          []string
	SessionTTL            time.Duration
	SessionSecretRotation time.Duration
	LoginAttemptLimit     int
	LoginAttemptWindow    time.Duration
	MaxRequestBytes       int64
	MaxBackupBytes        int64
	Logger                *slog.Logger

	// Test hooks are intentionally package-private.
	now    func() time.Time
	random io.Reader
}

// Server is an http.Handler containing the API and embedded single-page UI.
type Server struct {
	config              Config
	services            Services
	mux                 *http.ServeMux
	static              http.Handler
	sessions            *sessionManager
	loginLimiter        *loginLimiter
	dummyPasswordRecord string
	allowedHosts        map[string]struct{}
	publicOrigin        canonicalOrigin
	mutationGate        chan struct{}
	loginChecks         chan struct{}
}

type contextKey uint8

const (
	contextSession contextKey = iota
	contextRequestID
	contextStyleNonce
	contextLogger
)

// NewHandler initializes signing keys and returns the complete web handler.
func NewHandler(config Config, services Services) (http.Handler, error) {
	return NewHandlerContext(context.Background(), config, services)
}

// NewHandlerContext is NewHandler with a caller-controlled initialization context.
func NewHandlerContext(ctx context.Context, config Config, services Services) (http.Handler, error) {
	if services.Credentials == nil {
		return nil, errors.New("web: credential service is required")
	}
	config = config.withDefaults()
	sessions, err := newSessionManager(
		ctx,
		services.SessionSecrets,
		config.SessionTTL,
		config.SessionSecretRotation,
		config.now,
		config.random,
	)
	if err != nil {
		return nil, err
	}
	if services.AdminSetup != nil {
		setupStatus, statusErr := services.AdminSetup.AdminSetupStatus(ctx)
		if statusErr != nil {
			return nil, fmt.Errorf("web: inspect administrator setup: %w", statusErr)
		}
		if setupStatus.Required {
			// A missing canonical password must never revive a cookie signed by
			// session state left from an older installation or partial restore.
			if err := sessions.revokeAll(ctx); err != nil {
				return nil, fmt.Errorf("web: revoke pre-setup sessions: %w", err)
			}
		}
	}
	staticFS, err := fs.Sub(embeddedStatic, "static")
	if err != nil {
		return nil, fmt.Errorf("web: initialize embedded UI: %w", err)
	}

	dummySalt := []byte("boxctl-login-dummy-salt")
	dummyHash := pbkdf2SHA256([]byte("invalid-password"), dummySalt, 100_000, sha256Size)
	allowedHosts, err := normalizeAllowedHosts(config.AllowedHosts)
	if err != nil {
		return nil, fmt.Errorf("web: allowed hosts: %w", err)
	}
	publicOrigin, err := parseConfiguredPublicOrigin(config.PublicOrigin)
	if err != nil {
		return nil, fmt.Errorf("web: public origin: %w", err)
	}
	if publicOrigin.hostname != "" {
		allowedHosts[publicOrigin.hostname] = struct{}{}
	}
	if publicOrigin.scheme == "https" {
		config.CookieSecure = true
	}
	s := &Server{
		config:              config,
		services:            services,
		mux:                 http.NewServeMux(),
		static:              http.FileServer(http.FS(staticFS)),
		sessions:            sessions,
		loginLimiter:        newLoginLimiter(config.LoginAttemptLimit, config.LoginAttemptWindow, config.now),
		dummyPasswordRecord: "pbkdf2$100000$" + hex.EncodeToString(dummySalt) + "$" + hex.EncodeToString(dummyHash),
		allowedHosts:        allowedHosts,
		publicOrigin:        publicOrigin,
		mutationGate:        make(chan struct{}, 1),
		loginChecks:         make(chan struct{}, 2),
	}
	s.routes()
	return s, nil
}

type canonicalOrigin struct {
	scheme   string
	host     string
	hostname string
}

func parseConfiguredPublicOrigin(value string) (canonicalOrigin, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return canonicalOrigin{}, nil
	}
	origin, err := parseCanonicalOrigin(value)
	if err != nil {
		return canonicalOrigin{}, err
	}
	parsed, _ := url.Parse(value)
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return canonicalOrigin{}, errors.New("must contain only scheme and host")
	}
	return origin, nil
}

func parseCanonicalOrigin(value string) (canonicalOrigin, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.User != nil || parsed.Host == "" {
		return canonicalOrigin{}, errors.New("must be an absolute HTTP(S) origin")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return canonicalOrigin{}, errors.New("must use http or https")
	}
	hostname, ok := normalizeRequestHost(parsed.Hostname())
	if !ok {
		return canonicalOrigin{}, errors.New("contains an invalid host")
	}
	port := parsed.Port()
	if port != "" {
		parsedPort, portErr := strconv.ParseUint(port, 10, 16)
		if portErr != nil || parsedPort == 0 {
			return canonicalOrigin{}, errors.New("contains an invalid port")
		}
		if (scheme == "http" && parsedPort == 80) || (scheme == "https" && parsedPort == 443) {
			port = ""
		}
	}
	host := hostname
	if port != "" {
		host = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	return canonicalOrigin{scheme: scheme, host: host, hostname: hostname}, nil
}

func normalizeAllowedHosts(values []string) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		host, ok := normalizeRequestHost(value)
		if !ok {
			return nil, fmt.Errorf("invalid host %q", value)
		}
		result[host] = struct{}{}
	}
	return result, nil
}

func normalizeRequestHost(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\r\n/\\@?#") {
		return "", false
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	} else if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	} else if strings.Contains(value, ":") {
		// A colon outside a bracketed literal must be either a malformed port or
		// an unbracketed IPv6 address. Accept only the latter.
		if parsed := net.ParseIP(value); parsed == nil {
			return "", false
		}
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if value == "" || strings.ContainsAny(value, " \t") {
		return "", false
	}
	return value, true
}

func (s *Server) trustedSetupHost(r *http.Request) bool {
	host, ok := normalizeRequestHost(r.Host)
	if !ok {
		return false
	}
	if parsed := net.ParseIP(host); parsed != nil || host == "localhost" {
		return true
	}
	_, ok = s.allowedHosts[host]
	return ok
}

const sha256Size = 32

func (c Config) withDefaults() Config {
	if c.CookieName == "" {
		c.CookieName = defaultCookieName
	}
	if c.SessionTTL <= 0 {
		c.SessionTTL = defaultSessionTTL
	}
	if c.SessionSecretRotation <= 0 {
		c.SessionSecretRotation = defaultSecretRotation
	}
	if c.LoginAttemptLimit <= 0 {
		c.LoginAttemptLimit = defaultLoginLimit
	}
	if c.LoginAttemptWindow <= 0 {
		c.LoginAttemptWindow = defaultLoginWindow
	}
	if c.MaxRequestBytes <= 0 {
		c.MaxRequestBytes = defaultMaxRequestBytes
	}
	if c.MaxBackupBytes <= 0 {
		c.MaxBackupBytes = defaultMaxBackupBytes
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.random == nil {
		c.random = rand.Reader
	}
	return c
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/v1/setup", s.handleAdminSetup)
	s.mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	s.mux.HandleFunc("/api/v1/auth/logout", s.handleLogout)
	s.mux.HandleFunc("/api/v1/auth/session", s.handleSession)
	s.mux.HandleFunc("/api/v1/status", s.handleStatus)
	s.mux.HandleFunc("/api/v1/engines", s.handleEngines)
	s.mux.HandleFunc("/api/v1/engines/", s.handleEngineRoute)
	s.mux.HandleFunc("/api/v1/settings", s.handleSettings)
	s.mux.HandleFunc("/api/v1/config", s.handleConfig)
	s.mux.HandleFunc("/api/v1/config/validate", s.handleConfigValidation)
	s.mux.HandleFunc("/api/v1/profiles", s.handleProfiles)
	s.mux.HandleFunc("/api/v1/profiles/", s.handleProfile)
	s.mux.HandleFunc("/api/v1/proxy-subscriptions", s.handleProxySubscriptions)
	s.mux.HandleFunc("/api/v1/proxy-subscriptions/", s.handleProxySubscription)
	s.mux.HandleFunc("/api/v1/rule-lists", s.handleRuleLists)
	s.mux.HandleFunc("/api/v1/rule-lists/", s.handleRuleList)
	s.mux.HandleFunc("/api/v1/fake-ip-whitelist", s.handleFakeIPWhitelist)
	s.mux.HandleFunc("/api/v1/fake-ip-whitelist/regenerate", s.handleFakeIPWhitelistRegenerate)
	s.mux.HandleFunc("/api/v1/backups/export", s.handleBackupExport)
	s.mux.HandleFunc("/api/v1/backups/import", s.handleBackupImport)
	s.mux.HandleFunc("/api/v1/core", s.handleCore)
	s.mux.HandleFunc("/api/v1/core/", s.handleCoreRoute)
	s.mux.HandleFunc("/api/v1/external-dashboard", s.handleExternalDashboard)
	s.mux.HandleFunc("/api/v1/manager/update", s.handleManagerUpdate)
	s.mux.HandleFunc("/api/v1/external-dashboard/", s.handleExternalDashboardRoute)
	s.mux.HandleFunc("/api/v1/service/", s.handleLifecycle)
	s.mux.HandleFunc("/api/v1/firewall/cleanup", s.handleFirewallCleanup)
	s.mux.HandleFunc("/api/v1/logs/system", s.handleSystemLogs)
	s.mux.HandleFunc("/api/v1/logs/system/stream", s.handleSystemLogStream)
	s.mux.HandleFunc("/api/v1", func(w http.ResponseWriter, r *http.Request) {
		writeAPIError(w, r, http.StatusNotFound, "not_found", "API endpoint not found")
	})
	s.mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		writeAPIError(w, r, http.StatusNotFound, "not_found", "API endpoint not found")
	})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.setSecurityHeaders(w)
	requestID, err := randomToken(s.config.random, 18)
	styleNonce := requestID
	if err != nil {
		requestID = strconv.FormatInt(s.config.now().UnixNano(), 36)
		styleNonce = ""
	}
	w.Header().Set("X-Request-ID", requestID)
	r = r.WithContext(context.WithValue(r.Context(), contextRequestID, requestID))
	r = r.WithContext(context.WithValue(r.Context(), contextStyleNonce, styleNonce))
	r = r.WithContext(context.WithValue(r.Context(), contextLogger, s.config.Logger))

	if r.URL.Path == "/api/v1" || strings.HasPrefix(r.URL.Path, "/api/v1/") {
		w.Header().Set("Cache-Control", "no-store")
		if !isPublicAPIPath(r.URL.Path) {
			claims, ok := s.authenticate(w, r)
			if !ok {
				return
			}
			var cancelSession context.CancelFunc
			r, cancelSession = s.withSessionExpiry(r, claims)
			defer cancelSession()
			if isUnsafeMethod(r.Method) && !validCSRF(r.Header.Get("X-CSRF-Token"), claims.CSRF) {
				writeAPIError(w, r, http.StatusForbidden, "csrf_failed", "CSRF token is missing or invalid")
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), contextSession, claims))
		}
		if serializeUnsafeRequest(r) {
			if !s.acquireMutation(r.Context()) {
				writeAPIError(w, r, http.StatusServiceUnavailable, "request_canceled", "Request was canceled before it could run")
				return
			}
			defer s.releaseMutation()
		}
		s.mux.ServeHTTP(w, r)
		return
	}
	if r.URL.Path == "/external-ui" || strings.HasPrefix(r.URL.Path, "/external-ui/") {
		claims, ok := s.authenticate(w, r)
		if !ok {
			return
		}
		var cancelSession context.CancelFunc
		r, cancelSession = s.withSessionExpiry(r, claims)
		defer cancelSession()
		r = r.WithContext(context.WithValue(r.Context(), contextSession, claims))
		if s.services.ExternalDashboardHTTP == nil {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/external-ui" {
			http.Redirect(w, r, "/external-ui/", http.StatusPermanentRedirect)
			return
		}
		if (isUnsafeMethod(r.Method) || isWebSocketUpgrade(r)) && !s.trustedDashboardOrigin(r) {
			writeAPIError(w, r, http.StatusForbidden, "origin_rejected", "Cross-site dashboard controller requests are not allowed")
			return
		}
		s.services.ExternalDashboardHTTP.ServeHTTP(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/" {
		if _, ok := s.sessionFromRequest(r); !ok {
			if _, err := r.Cookie(s.config.CookieName); err == nil {
				s.clearSessionCookie(w)
			}
			location := "/login"
			if s.services.AdminSetup != nil {
				if status, statusErr := s.services.AdminSetup.AdminSetupStatus(r.Context()); statusErr == nil && status.Required {
					location = "/setup"
				}
			}
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, location, http.StatusSeeOther)
			return
		}
	}
	s.serveStatic(w, r)
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") &&
		headerContainsToken(r.Header.Values("Connection"), "upgrade")
}

func headerContainsToken(values []string, want string) bool {
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), want) {
				return true
			}
		}
	}
	return false
}

func (s *Server) trustedDashboardOrigin(r *http.Request) bool {
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
		return false
	}
	expected, ok := s.expectedRequestOrigin(r)
	if !ok {
		return false
	}
	for _, candidate := range []string{r.Header.Get("Origin"), r.Header.Get("Referer")} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		actual, err := parseCanonicalOrigin(candidate)
		if err != nil {
			return false
		}
		return actual.scheme == expected.scheme && actual.host == expected.host
	}
	return false
}

func (s *Server) expectedRequestOrigin(r *http.Request) (canonicalOrigin, bool) {
	if s.publicOrigin.scheme != "" {
		// PublicOrigin is a complete origin, so keep the port in the Host check.
		// Comparing only hostnames would let a request sent directly to another
		// port borrow the configured proxy origin for its Origin check.
		requestOrigin, err := parseCanonicalOrigin(s.publicOrigin.scheme + "://" + r.Host)
		return s.publicOrigin, err == nil && requestOrigin.host == s.publicOrigin.host
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	origin, err := parseCanonicalOrigin(scheme + "://" + r.Host)
	return origin, err == nil
}

func isPublicAPIPath(path string) bool {
	return path == "/api/v1/auth/login" || path == "/api/v1/setup"
}

func (s *Server) withSessionExpiry(r *http.Request, claims sessionClaims) (*http.Request, context.CancelFunc) {
	remaining := time.Unix(claims.ExpiresAt, 0).Sub(s.config.now())
	ctx, cancel := context.WithTimeout(r.Context(), remaining)
	return r.WithContext(ctx), cancel
}

func serializeUnsafeRequest(r *http.Request) bool {
	if !isUnsafeMethod(r.Method) {
		return false
	}
	// Login and backup read and bound their request bodies before taking the
	// gate inside their handlers. This keeps slow unauthenticated uploads from
	// blocking mutations while still serializing credential verification with
	// a provisional backup state.
	return r.URL.Path != "/api/v1/auth/login" && r.URL.Path != "/api/v1/backups/import"
}

func (s *Server) acquireMutation(ctx context.Context) bool {
	select {
	case s.mutationGate <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *Server) releaseMutation() {
	<-s.mutationGate
}

func (s *Server) setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy(""))
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
}

func contentSecurityPolicy(styleNonce string) string {
	styleSource := "style-src 'self'"
	if styleNonce != "" {
		styleSource += " 'nonce-" + styleNonce + "'"
	}
	return "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data: https:; object-src 'none'; script-src 'self'; " + styleSource
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (sessionClaims, bool) {
	claims, ok := s.sessionFromRequest(r)
	if !ok {
		if _, err := r.Cookie(s.config.CookieName); err == nil {
			s.clearSessionCookie(w)
		}
		writeAPIError(w, r, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return sessionClaims{}, false
	}
	return claims, true
}

func (s *Server) sessionFromRequest(r *http.Request) (sessionClaims, bool) {
	// Rotation is lazy but applies to normal authenticated traffic, not just logins.
	// Persistence failures leave the previous key active and are retried later.
	_ = s.sessions.rotateIfDue(r.Context())
	cookie, err := r.Cookie(s.config.CookieName)
	if err != nil || cookie.Value == "" {
		return sessionClaims{}, false
	}
	claims, err := s.sessions.verify(cookie.Value)
	if err != nil {
		return sessionClaims{}, false
	}
	return claims, true
}

func validCSRF(got, want string) bool {
	return got != "" && len(got) == len(want) && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func isUnsafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func (s *Server) setSessionCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.config.CookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(s.config.SessionTTL.Seconds()),
		Expires:  s.config.now().Add(s.config.SessionTTL).UTC(),
		HttpOnly: true,
		Secure:   s.config.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.config.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(1, 0).UTC(),
		HttpOnly: true,
		Secure:   s.config.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	clean := path.Clean("/" + r.URL.Path)
	name := strings.TrimPrefix(clean, "/")
	if name == "" {
		name = "index.html"
	}
	// Precompressed representations are implementation details selected through
	// content negotiation; never expose them as separate public assets.
	if strings.HasSuffix(name, ".gz") {
		http.NotFound(w, r)
		return
	}
	staticFS, _ := fs.Sub(embeddedStatic, "static")
	if info, err := fs.Stat(staticFS, name); err == nil && !info.IsDir() {
		if name == "index.html" {
			s.serveIndex(w, r, staticFS)
			return
		}
		if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			if s.servePrecompressed(w, r, staticFS, name) {
				return
			}
		}
		r.URL.Path = "/" + name
		s.static.ServeHTTP(w, r)
		return
	}
	if path.Ext(name) != "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	s.serveIndex(w, r, staticFS)
}

func (s *Server) servePrecompressed(w http.ResponseWriter, r *http.Request, staticFS fs.FS, name string) bool {
	if strings.HasSuffix(name, ".gz") {
		return false
	}
	compressedName := name + ".gz"
	info, err := fs.Stat(staticFS, compressedName)
	if err != nil || info.IsDir() {
		return false
	}
	appendVary(w.Header(), "Accept-Encoding")
	if !acceptsEncoding(r.Header.Get("Accept-Encoding"), "gzip") {
		return false
	}
	content, err := fs.ReadFile(staticFS, compressedName)
	if err != nil {
		return false
	}
	if contentType := mime.TypeByExtension(path.Ext(name)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.Header().Set("Content-Encoding", "gzip")
	http.ServeContent(w, r, path.Base(name), info.ModTime(), bytes.NewReader(content))
	return true
}

func appendVary(header http.Header, value string) {
	for _, current := range header.Values("Vary") {
		for _, item := range strings.Split(current, ",") {
			if strings.EqualFold(strings.TrimSpace(item), value) {
				return
			}
		}
	}
	header.Add("Vary", value)
}

func acceptsEncoding(header, wanted string) bool {
	explicit := false
	explicitAccepted := false
	wildcardAccepted := false
	for _, item := range strings.Split(header, ",") {
		parts := strings.Split(item, ";")
		encoding := strings.ToLower(strings.TrimSpace(parts[0]))
		quality := 1.0
		for _, parameter := range parts[1:] {
			key, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "q") {
				continue
			}
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil || parsed < 0 || parsed > 1 {
				quality = 0
			} else {
				quality = parsed
			}
		}
		switch {
		case strings.EqualFold(encoding, wanted):
			explicit = true
			explicitAccepted = quality > 0
		case encoding == "*":
			wildcardAccepted = quality > 0
		}
	}
	if explicit {
		return explicitAccepted
	}
	return wildcardAccepted
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request, staticFS fs.FS) {
	content, err := fs.ReadFile(staticFS, "index.html")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	styleNonce, _ := r.Context().Value(contextStyleNonce).(string)
	if styleNonce == "" || !bytes.Contains(content, []byte(styleNoncePlaceholder)) {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	content = bytes.Replace(content, []byte(styleNoncePlaceholder), []byte(styleNonce), 1)
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy(styleNonce))
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(content))
}

func loginKey(r *http.Request) string {
	host := r.RemoteAddr
	if parsed, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = parsed
	}
	return host
}

func claimsFromContext(ctx context.Context) (sessionClaims, bool) {
	claims, ok := ctx.Value(contextSession).(sessionClaims)
	return claims, ok
}

func writeData(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Data any `json:"data"`
	}{Data: data})
}

func writeAPIError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	requestID, _ := r.Context().Value(contextRequestID).(string)
	_ = json.NewEncoder(w).Encode(struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"requestId,omitempty"`
		} `json:"error"`
	}{Error: struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"requestId,omitempty"`
	}{Code: code, Message: redactText(message), RequestID: requestID}})
}

func writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	var public *PublicError
	switch {
	case errors.As(err, &public):
		status := public.Status
		if status < 400 || status > 599 {
			status = http.StatusInternalServerError
		}
		writeAPIError(w, r, status, public.Code, public.Message)
	case errors.Is(err, ErrNotFound):
		writeAPIError(w, r, http.StatusNotFound, "not_found", "Resource not found")
	case errors.Is(err, ErrConflict):
		writeAPIError(w, r, http.StatusConflict, "conflict", "Requested state conflicts with current state")
	case errors.Is(err, ErrUnavailable):
		writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "Service temporarily unavailable")
	default:
		logger, _ := r.Context().Value(contextLogger).(*slog.Logger)
		if logger != nil {
			requestID, _ := r.Context().Value(contextRequestID).(string)
			logger.ErrorContext(r.Context(), fmt.Sprintf("HTTP request %s failed: %v", requestID, err),
				"request_id", requestID,
				"method", r.Method,
				"path", r.URL.Path,
				"error", err,
			)
		}
		writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error")
	}
}

func writeUnsupported(w http.ResponseWriter, r *http.Request) {
	writeAPIError(w, r, http.StatusNotImplemented, "unsupported", "Feature is not supported by this installation")
}

func requireMethod(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, method := range methods {
		if r.Method == method {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeAPIError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	return false
}

func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, s.config.MaxRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "invalid_json", "Request body must contain valid JSON")
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeAPIError(w, r, http.StatusBadRequest, "invalid_json", "Request body must contain one JSON value")
		return false
	}
	return true
}

// decodeOptionalJSON preserves the historical empty-body behavior of action
// endpoints while allowing newer clients to send explicit confirmation data.
func (s *Server) decodeOptionalJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil || r.ContentLength == 0 {
		return true
	}
	return s.decodeJSON(w, r, dst)
}

func parseLogQuery(r *http.Request) LogQuery {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 200
	}
	if limit > 1_000 {
		limit = 1_000
	}
	level := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("level")))
	if len(level) > 16 {
		level = ""
	}
	return LogQuery{Limit: limit, Level: level}
}
