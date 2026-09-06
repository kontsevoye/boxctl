package web

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/eventlog"
)

func TestFirstRunAdminSetupIsPublicSameOriginAndOneTime(t *testing.T) {
	setup := &fakeAdminSetup{required: true}
	handler := newTestHandler(t, Services{
		Credentials:    fakeCredentials{},
		AdminSetup:     setup,
		SessionSecrets: &memorySecretStore{},
	})

	status := perform(handler, http.MethodGet, "/api/v1/setup", "", nil, "")
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"required":true`) || strings.Contains(status.Body.String(), `"username"`) {
		t.Fatalf("initial setup status = %d %s", status.Code, status.Body.String())
	}
	crossSite := performWithHeaders(handler, http.MethodPost, "/api/v1/setup", "application/json", []byte(`{"password":"first secure password"}`), nil, "", map[string]string{
		"Origin": "https://attacker.example",
	})
	if crossSite.Code != http.StatusForbidden || setup.calls != 0 {
		t.Fatalf("cross-site setup = %d calls=%d", crossSite.Code, setup.calls)
	}
	rebinding := performWithHeaders(handler, http.MethodPost, "/api/v1/setup", "application/json", []byte(`{"password":"first secure password"}`), nil, "", map[string]string{
		"Host":           "attacker.example",
		"Origin":         "http://attacker.example",
		"Sec-Fetch-Site": "same-origin",
	})
	if rebinding.Code != http.StatusForbidden || setup.calls != 0 {
		t.Fatalf("rebinding setup = %d calls=%d", rebinding.Code, setup.calls)
	}
	created := perform(handler, http.MethodPost, "/api/v1/setup", `{"password":"first secure password"}`, nil, "")
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"required":false`) || setup.calls != 1 {
		t.Fatalf("created setup = %d calls=%d body=%s", created.Code, setup.calls, created.Body.String())
	}
	repeated := perform(handler, http.MethodPost, "/api/v1/setup", `{"password":"replacement password"}`, nil, "")
	if repeated.Code != http.StatusConflict || !strings.Contains(repeated.Body.String(), `"code":"setup_complete"`) || setup.calls != 2 {
		t.Fatalf("repeated setup = %d calls=%d body=%s", repeated.Code, setup.calls, repeated.Body.String())
	}
}

func TestFirstRunSetupAcceptsConfiguredHostnameAndRejectsInvalidHostConfig(t *testing.T) {
	setup := &fakeAdminSetup{required: true}
	handler, err := NewHandler(Config{AllowedHosts: []string{"router.example"}}, Services{
		Credentials: fakeCredentials{}, AdminSetup: setup, SessionSecrets: &memorySecretStore{},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := performWithHeaders(handler, http.MethodPost, "/api/v1/setup", "application/json", []byte(`{"password":"first secure password"}`), nil, "", map[string]string{
		"Host": "router.example:9091", "Origin": "http://router.example:9091", "Sec-Fetch-Site": "same-origin",
	})
	if response.Code != http.StatusCreated || setup.calls != 1 {
		t.Fatalf("configured-host setup = %d calls=%d body=%s", response.Code, setup.calls, response.Body.String())
	}
	if _, err := NewHandler(Config{AllowedHosts: []string{"https://router.example"}}, Services{
		Credentials: fakeCredentials{}, SessionSecrets: &memorySecretStore{},
	}); err == nil {
		t.Fatal("URL was accepted as an allowed host")
	}
}

func TestPublicOriginValidation(t *testing.T) {
	t.Parallel()
	services := Services{Credentials: fakeCredentials{}, SessionSecrets: &memorySecretStore{}}
	for _, value := range []string{"ftp://router.example", "https://router.example/path", "https://router.example?query=1", "https://user@router.example", "https://router.example:0"} {
		if _, err := NewHandler(Config{PublicOrigin: value}, services); err == nil {
			t.Errorf("PublicOrigin %q was accepted", value)
		}
	}
}

func TestRootRedirectsToFirstRunSetup(t *testing.T) {
	handler := newTestHandler(t, Services{
		Credentials:    fakeCredentials{},
		AdminSetup:     &fakeAdminSetup{required: true},
		SessionSecrets: &memorySecretStore{},
	})
	response := perform(handler, http.MethodGet, "/", "", nil, "")
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/setup" {
		t.Fatalf("root redirect = %d location=%q", response.Code, response.Header().Get("Location"))
	}
}

func TestFirstRunStartupRevokesPersistedPreSetupSessions(t *testing.T) {
	store := &memorySecretStore{}
	oldSessions, err := newSessionManager(context.Background(), store, time.Hour, 24*time.Hour, time.Now, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := oldSessions.issue(context.Background(), Credential{UserID: "1"})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Config{}, Services{
		Credentials:    fakeCredentials{},
		AdminSetup:     &fakeAdminSetup{required: true},
		SessionSecrets: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := perform(handler, http.MethodGet, "/api/v1/auth/session", "", &http.Cookie{Name: defaultCookieName, Value: token}, "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("pre-setup session remained valid: %d %s", response.Code, response.Body.String())
	}
}

func TestAuthenticationCSRFAndStructuredErrors(t *testing.T) {
	settings := &fakeSettingsService{settings: Settings{Language: "ru", Theme: "system"}}
	handler := newTestHandler(t, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
		Settings:       settings,
	})

	unauthorized := perform(handler, http.MethodGet, "/api/v1/settings", "", nil, "")
	if unauthorized.Code != http.StatusUnauthorized || !strings.Contains(unauthorized.Body.String(), `"code":"unauthorized"`) {
		t.Fatalf("unauthorized response = %d %s", unauthorized.Code, unauthorized.Body.String())
	}

	cookie, csrf := login(t, handler)
	withoutCSRF := perform(handler, http.MethodPut, "/api/v1/settings", `{"language":"en"}`, cookie, "")
	if withoutCSRF.Code != http.StatusForbidden || !strings.Contains(withoutCSRF.Body.String(), `"code":"csrf_failed"`) {
		t.Fatalf("CSRF response = %d %s", withoutCSRF.Code, withoutCSRF.Body.String())
	}
	withCSRF := perform(handler, http.MethodPut, "/api/v1/settings", `{"language":"en"}`, cookie, csrf)
	if withCSRF.Code != http.StatusOK || settings.updates != 1 {
		t.Fatalf("authorized update = %d %s, updates=%d", withCSRF.Code, withCSRF.Body.String(), settings.updates)
	}

	loginResponse := perform(handler, http.MethodPost, "/api/v1/auth/login", `{"password":"correct horse"}`, nil, "")
	setCookie := loginResponse.Result().Cookies()[0]
	if !setCookie.HttpOnly || setCookie.SameSite != http.SameSiteStrictMode || setCookie.Path != "/" {
		t.Fatalf("insecure session cookie: %+v", setCookie)
	}
}

func TestMutationGateRespectsCancellationAndCanBeReused(t *testing.T) {
	server := &Server{mutationGate: make(chan struct{}, 1)}
	if !server.acquireMutation(context.Background()) {
		t.Fatal("first mutation did not acquire the gate")
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if server.acquireMutation(canceled) {
		t.Fatal("canceled mutation acquired an occupied gate")
	}

	server.releaseMutation()
	if !server.acquireMutation(context.Background()) {
		t.Fatal("released mutation gate could not be reused")
	}
	server.releaseMutation()
}

func TestLoginRateLimiting(t *testing.T) {
	handler, err := NewHandler(Config{LoginAttemptLimit: 2}, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		response := perform(handler, http.MethodPost, "/api/v1/auth/login", `{"password":"wrong"}`, nil, "")
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", attempt, response.Code)
		}
	}
	blocked := perform(handler, http.MethodPost, "/api/v1/auth/login", `{"password":"wrong"}`, nil, "")
	if blocked.Code != http.StatusTooManyRequests || blocked.Header().Get("Retry-After") == "" {
		t.Fatalf("blocked response = %d headers=%v", blocked.Code, blocked.Header())
	}
}

func TestLoginRequiresJSONTrustedOriginAndLimitsByClientIP(t *testing.T) {
	handler, err := NewHandler(Config{LoginAttemptLimit: 2}, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
	})
	if err != nil {
		t.Fatal(err)
	}
	plain := performWithHeaders(handler, http.MethodPost, "/api/v1/auth/login", "text/plain", []byte(`{"password":"correct horse"}`), nil, "", nil)
	if plain.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text login = %d, want 415", plain.Code)
	}
	crossSite := performWithHeaders(handler, http.MethodPost, "/api/v1/auth/login", "application/json", []byte(`{"password":"correct horse"}`), nil, "", map[string]string{
		"Origin":         "http://attacker.invalid",
		"Sec-Fetch-Site": "cross-site",
	})
	if crossSite.Code != http.StatusForbidden {
		t.Fatalf("cross-site login = %d, want 403", crossSite.Code)
	}
	for attempt := 0; attempt < 2; attempt++ {
		response := perform(handler, http.MethodPost, "/api/v1/auth/login", `{"password":"wrong"}`, nil, "")
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("wrong login %d = %d, want 401", attempt, response.Code)
		}
	}
	blocked := perform(handler, http.MethodPost, "/api/v1/auth/login", `{"password":"wrong"}`, nil, "")
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited login = %d, want 429", blocked.Code)
	}
}

func TestMalformedLoginConsumesClientIPBudget(t *testing.T) {
	handler, err := NewHandler(Config{LoginAttemptLimit: 1}, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
	})
	if err != nil {
		t.Fatal(err)
	}
	malformed := perform(handler, http.MethodPost, "/api/v1/auth/login", `{`, nil, "")
	if malformed.Code != http.StatusBadRequest {
		t.Fatalf("malformed login = %d, want 400", malformed.Code)
	}
	blocked := perform(handler, http.MethodPost, "/api/v1/auth/login", `{"password":"correct horse"}`, nil, "")
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("login after malformed attempt = %d, want 429", blocked.Code)
	}
}

func TestProfileAndLogResponsesRedactSecrets(t *testing.T) {
	logs := make(chan LogEntry, 1)
	logs <- LogEntry{
		Time:  time.Now(),
		Level: "info",
		Message: "request token=topsecret https://user:pass@example.test/subscriptions/path-secret?opaque=query-secret " +
			"using /tmp/boxctl/runtime/mihomo-private.yaml",
		Fields: map[string]any{
			"api_token":        "topsecret",
			"subscription_url": "https://example.test/path-secret?opaque=query-secret",
			"runtime_path":     "/tmp/boxctl/runtime/mihomo-private.yaml",
			"targets":          []string{"vmess://payload-secret", "https://example.test/path-secret?opaque=query-secret"},
			"safe":             "ok",
		},
	}
	close(logs)
	handler := newTestHandler(t, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
		Profiles: fakeProfilesService{profiles: []Profile{{
			ID:        "p1",
			Name:      "Home",
			LastError: "download token=topsecret",
		}}},
		SystemLogs: fakeLogService{stream: logs},
	})
	cookie, _ := login(t, handler)

	profiles := perform(handler, http.MethodGet, "/api/v1/profiles", "", cookie, "")
	if profiles.Code != http.StatusOK || containsSecret(profiles.Body.String()) || !strings.Contains(profiles.Body.String(), "[redacted]") {
		t.Fatalf("profile response was not redacted: %s", profiles.Body.String())
	}
	stream := perform(handler, http.MethodGet, "/api/v1/logs/system/stream", "", cookie, "")
	if stream.Code != http.StatusOK || containsSecret(stream.Body.String()) || !strings.Contains(stream.Body.String(), "event: log") {
		t.Fatalf("SSE response was not redacted: %d %s", stream.Code, stream.Body.String())
	}
	for _, secret := range []string{"path-secret", "query-secret", "mihomo-private.yaml", "payload-secret"} {
		if strings.Contains(stream.Body.String(), secret) {
			t.Fatalf("SSE response leaked %q: %s", secret, stream.Body.String())
		}
	}
}

func TestAPIErrorMessageRedactsPrivateLocations(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/core", nil)
	response := httptest.NewRecorder()
	writeServiceError(response, request, &PublicError{
		Status: http.StatusBadGateway,
		Code:   "upstream_failed",
		Message: "failed https://admin:user-secret@example.test/subscriptions/path-secret?opaque=query-secret " +
			"with /tmp/boxctl/runtime/mihomo-private.yaml",
	})
	if response.Code != http.StatusBadGateway {
		t.Fatalf("response status = %d", response.Code)
	}
	for _, secret := range []string{"user-secret", "path-secret", "query-secret", "mihomo-private.yaml"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatalf("API error leaked %q: %s", secret, response.Body.String())
		}
	}
}

func TestEmbeddedSPAAndSecurityHeaders(t *testing.T) {
	handler := newTestHandler(t, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
	})
	response := perform(handler, http.MethodGet, "/settings", "", nil, "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "<!doctype html>") {
		t.Fatalf("SPA response = %d %s", response.Code, response.Body.String())
	}
	csp := response.Header().Get("Content-Security-Policy")
	if csp == "" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("security headers missing: %v", response.Header())
	}
	if !strings.Contains(csp, "img-src 'self' data: https:") {
		t.Fatalf("remote proxy icons are not permitted by CSP: %q", csp)
	}
	const noncePrefix = "style-src 'self' 'nonce-"
	nonceStart := strings.Index(csp, noncePrefix)
	if nonceStart < 0 {
		t.Fatalf("style nonce missing from CSP: %q", csp)
	}
	nonceStart += len(noncePrefix)
	nonceEnd := strings.Index(csp[nonceStart:], "'")
	if nonceEnd <= 0 {
		t.Fatalf("invalid style nonce in CSP: %q", csp)
	}
	nonce := csp[nonceStart : nonceStart+nonceEnd]
	body := response.Body.String()
	if !strings.Contains(body, `name="boxctl-style-nonce" content="`+nonce+`"`) {
		t.Fatalf("HTML nonce does not match CSP: %q", body)
	}
	if strings.Contains(csp, "'unsafe-inline'") || strings.Contains(body, styleNoncePlaceholder) {
		t.Fatalf("unsafe or unresolved CSP configuration: CSP=%q body=%q", csp, body)
	}
	missingAsset := perform(handler, http.MethodGet, "/assets/missing.js", "", nil, "")
	if missingAsset.Code != http.StatusNotFound {
		t.Fatalf("missing asset = %d, want 404", missingAsset.Code)
	}
}

func TestEmbeddedAssetsUsePrecompressedRepresentation(t *testing.T) {
	entries, err := embeddedStatic.ReadDir("static/assets")
	if err != nil {
		t.Fatal(err)
	}
	asset := ""
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".js") {
			asset = entry.Name()
			break
		}
	}
	if asset == "" {
		t.Fatal("embedded JavaScript asset is missing")
	}
	want, err := embeddedStatic.ReadFile("static/assets/" + asset)
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestHandler(t, Services{Credentials: fakeCredentials{}, SessionSecrets: &memorySecretStore{}})
	requestPath := "/assets/" + asset

	compressed := performWithHeaders(handler, http.MethodGet, requestPath, "", nil, nil, "", map[string]string{
		"Accept-Encoding": "br, gzip",
	})
	if compressed.Code != http.StatusOK || compressed.Header().Get("Content-Encoding") != "gzip" ||
		!strings.Contains(compressed.Header().Get("Vary"), "Accept-Encoding") ||
		compressed.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" ||
		!strings.Contains(compressed.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("compressed asset = %d headers=%v", compressed.Code, compressed.Header())
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	if !bytes.Equal(got, want) {
		t.Fatal("precompressed asset does not decode to the original")
	}

	plain := performWithHeaders(handler, http.MethodGet, requestPath, "", nil, nil, "", map[string]string{
		"Accept-Encoding": "gzip;q=0, *;q=1",
	})
	if plain.Code != http.StatusOK || plain.Header().Get("Content-Encoding") != "" || !bytes.Equal(plain.Body.Bytes(), want) ||
		!strings.Contains(plain.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatalf("plain asset = %d headers=%v", plain.Code, plain.Header())
	}

	direct := perform(handler, http.MethodGet, requestPath+".gz", "", nil, "")
	if direct.Code != http.StatusNotFound {
		t.Fatalf("direct precompressed asset = %d, want 404", direct.Code)
	}
}

func TestAcceptsEncoding(t *testing.T) {
	t.Parallel()
	tests := []struct {
		header string
		want   bool
	}{
		{"gzip", true},
		{"br, GZip; q=0.5", true},
		{"*;q=1", true},
		{"gzip;q=0, *;q=1", false},
		{"br", false},
		{"gzip;q=2", false},
	}
	for _, test := range tests {
		if got := acceptsEncoding(test.header, "gzip"); got != test.want {
			t.Errorf("acceptsEncoding(%q) = %t, want %t", test.header, got, test.want)
		}
	}
}

func TestRootRedirectsToLoginWithoutSession(t *testing.T) {
	handler := newTestHandler(t, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
	})
	response := perform(handler, http.MethodGet, "/", "", nil, "")
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
		t.Fatalf("anonymous root = %d Location=%q", response.Code, response.Header().Get("Location"))
	}
	loginPage := perform(handler, http.MethodGet, "/login", "", nil, "")
	if loginPage.Code != http.StatusOK || !strings.Contains(loginPage.Body.String(), "<!doctype html>") {
		t.Fatalf("login SPA = %d %s", loginPage.Code, loginPage.Body.String())
	}
	cookie, _ := login(t, handler)
	authenticated := perform(handler, http.MethodGet, "/", "", cookie, "")
	if authenticated.Code != http.StatusOK || !strings.Contains(authenticated.Body.String(), "<!doctype html>") {
		t.Fatalf("authenticated root = %d %s", authenticated.Code, authenticated.Body.String())
	}
}

func TestCapabilityEndpointUsesNeutralCoreService(t *testing.T) {
	core := &fakeCoreService{capabilities: Capabilities{
		CoreName: "test-core",
		Pages:    map[string]bool{"proxies": true, "rules": false},
		Actions:  map[string]bool{"selectProxy": true},
	}}
	handler := newTestHandler(t, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
		Core:           core,
	})
	cookie, _ := login(t, handler)
	response := perform(handler, http.MethodGet, "/api/v1/core/capabilities", "", cookie, "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"coreName":"test-core"`) {
		t.Fatalf("capabilities response = %d %s", response.Code, response.Body.String())
	}
}

func TestDashboardStreamAndRoutingModeAreAuthenticatedAndEventDriven(t *testing.T) {
	dashboardStream := make(chan CoreDashboard, 1)
	dashboardStream <- CoreDashboard{
		Mode: "rule", Groups: []ProxyGroup{{Name: "PROXY", Type: "Selector", Selected: "node-a"}},
		ProxyProviders: []Provider{{Name: "subscription", ProxyCount: 12}},
		Traffic:        &CoreTraffic{UploadRateBytes: 12, DownloadRateBytes: 34}, CapturedAt: time.Now(),
	}
	close(dashboardStream)
	core := &fakeCoreService{dashboardStream: dashboardStream}
	handler := newTestHandler(t, Services{Credentials: fakeCredentials{}, SessionSecrets: &memorySecretStore{}, Core: core})

	anonymous := perform(handler, http.MethodGet, "/api/v1/core/dashboard/stream", "", nil, "")
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous dashboard stream = %d", anonymous.Code)
	}
	cookie, csrf := login(t, handler)
	stream := perform(handler, http.MethodGet, "/api/v1/core/dashboard/stream", "", cookie, "")
	if stream.Code != http.StatusOK || !strings.Contains(stream.Body.String(), "event: dashboard") || !strings.Contains(stream.Body.String(), `"downloadRateBytes":34`) || !strings.Contains(stream.Body.String(), `"proxyCount":12`) {
		t.Fatalf("dashboard stream = %d %s", stream.Code, stream.Body.String())
	}
	withoutCSRF := perform(handler, http.MethodPut, "/api/v1/core/dashboard/mode", `{"mode":"direct"}`, cookie, "")
	if withoutCSRF.Code != http.StatusForbidden || len(core.routingModes) != 0 {
		t.Fatalf("routing mode without CSRF = %d calls=%v", withoutCSRF.Code, core.routingModes)
	}
	updated := perform(handler, http.MethodPut, "/api/v1/core/dashboard/mode", `{"mode":"direct"}`, cookie, csrf)
	if updated.Code != http.StatusOK || len(core.routingModes) != 1 || core.routingModes[0] != "direct" {
		t.Fatalf("routing mode update = %d calls=%v body=%s", updated.Code, core.routingModes, updated.Body.String())
	}
}

func TestCoreDelayAndProviderEndpointsAreValidatedAndSecretFree(t *testing.T) {
	core := &fakeCoreService{
		delayResult: ProxyDelayResult{Proxy: "node-a", DelayMS: 123},
		providers: map[ProviderKind][]Provider{
			ProviderProxy: {{Name: "subscription", Type: "Proxy", VehicleType: "HTTP", UpdatedAt: "2026-08-26T12:00:00Z"}},
			ProviderRule:  {{Name: "rules", Type: "Rule", VehicleType: "File"}},
		},
	}
	handler := newTestHandler(t, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
		Core:           core,
	})
	cookie, csrf := login(t, handler)

	const secretURL = "https://example.test/generate_204?token=do-not-echo"
	withoutCSRF := perform(handler, http.MethodPost, "/api/v1/core/proxies/delay", `{"proxy":"node-a","url":"`+secretURL+`","timeoutMs":5000}`, cookie, "")
	if withoutCSRF.Code != http.StatusForbidden || len(core.delayCalls) != 0 {
		t.Fatalf("delay without CSRF = %d calls=%d", withoutCSRF.Code, len(core.delayCalls))
	}
	delay := perform(handler, http.MethodPost, "/api/v1/core/proxies/delay", `{"proxy":"node-a","url":"`+secretURL+`","timeoutMs":5000}`, cookie, csrf)
	if delay.Code != http.StatusOK || !strings.Contains(delay.Body.String(), `"delayMs":123`) || strings.Contains(delay.Body.String(), "do-not-echo") {
		t.Fatalf("delay response = %d %s", delay.Code, delay.Body.String())
	}
	if len(core.delayCalls) != 1 || core.delayCalls[0].proxy != "node-a" || core.delayCalls[0].testURL != secretURL || core.delayCalls[0].timeout != 5*time.Second {
		t.Fatalf("delay calls = %#v", core.delayCalls)
	}

	for _, body := range []string{
		`{"proxy":"node-a","url":"ftp://example.test/file","timeoutMs":5000}`,
		`{"proxy":"node-a","url":"https://user:password@example.test/test","timeoutMs":5000}`,
		`{"proxy":"node-a","url":"https://example.test/test","timeoutMs":0}`,
		`{"proxy":"node-a","url":"https://example.test/test","timeoutMs":60001}`,
		`{"proxy":"node\na","url":"https://example.test/test","timeoutMs":5000}`,
	} {
		response := perform(handler, http.MethodPost, "/api/v1/core/proxies/delay", body, cookie, csrf)
		if response.Code != http.StatusBadRequest {
			t.Errorf("invalid delay request %s = %d %s", body, response.Code, response.Body.String())
		}
	}
	oversizedDelayBody, err := json.Marshal(map[string]any{
		"proxy": "node-a", "url": "https://example.test/" + strings.Repeat("a", 4_096), "timeoutMs": 5_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	oversizedDelay := perform(handler, http.MethodPost, "/api/v1/core/proxies/delay", string(oversizedDelayBody), cookie, csrf)
	if oversizedDelay.Code != http.StatusBadRequest || len(core.delayCalls) != 1 {
		t.Fatalf("oversized delay URL = %d calls=%d", oversizedDelay.Code, len(core.delayCalls))
	}

	providers := perform(handler, http.MethodGet, "/api/v1/core/providers/proxy", "", cookie, "")
	if providers.Code != http.StatusOK || !strings.Contains(providers.Body.String(), `"name":"subscription"`) || strings.Contains(strings.ToLower(providers.Body.String()), `"path"`) {
		t.Fatalf("providers response = %d %s", providers.Code, providers.Body.String())
	}
	updateWithoutCSRF := perform(handler, http.MethodPut, "/api/v1/core/providers/rule/my%20rules", `{}`, cookie, "")
	if updateWithoutCSRF.Code != http.StatusForbidden || len(core.providerUpdates) != 0 {
		t.Fatalf("provider update without CSRF = %d updates=%d", updateWithoutCSRF.Code, len(core.providerUpdates))
	}
	updated := perform(handler, http.MethodPut, "/api/v1/core/providers/rule/my%20rules", `{}`, cookie, csrf)
	if updated.Code != http.StatusOK || len(core.providerUpdates) != 1 || core.providerUpdates[0] != (fakeProviderUpdate{kind: ProviderRule, name: "my rules"}) {
		t.Fatalf("provider update = %d updates=%#v body=%s", updated.Code, core.providerUpdates, updated.Body.String())
	}
	invalidKind := perform(handler, http.MethodGet, "/api/v1/core/providers/native", "", cookie, "")
	if invalidKind.Code != http.StatusBadRequest || !strings.Contains(invalidKind.Body.String(), `"code":"invalid_provider_kind"`) {
		t.Fatalf("invalid provider kind = %d %s", invalidKind.Code, invalidKind.Body.String())
	}
	oversizedName := perform(handler, http.MethodPut, "/api/v1/core/providers/rule/"+strings.Repeat("n", 513), `{}`, cookie, csrf)
	if oversizedName.Code != http.StatusBadRequest || len(core.providerUpdates) != 1 {
		t.Fatalf("oversized provider name = %d updates=%d", oversizedName.Code, len(core.providerUpdates))
	}
}

func TestUnexpectedProviderUpdateErrorIsLoggedWithRequestID(t *testing.T) {
	ring := eventlog.New(10)
	core := &fakeCoreService{providerUpdateErr: errors.New("controller rejected provider state")}
	handler, err := NewHandler(Config{Logger: slog.New(ring.Handler(slog.LevelInfo)).WithGroup("http")}, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
		Core:           core,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	cookie, csrf := login(t, handler)

	response := perform(handler, http.MethodPut, "/api/v1/core/providers/proxy/remote", `{}`, cookie, csrf)
	requestID := response.Header().Get("X-Request-ID")
	if response.Code != http.StatusInternalServerError || requestID == "" || !strings.Contains(response.Body.String(), `"requestId":"`+requestID+`"`) {
		t.Fatalf("provider update error = %d request-id=%q body=%s", response.Code, requestID, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "controller rejected") {
		t.Fatalf("internal cause leaked in response: %s", response.Body.String())
	}
	entries := ring.Snapshot(0, 0)
	if len(entries) != 1 {
		t.Fatalf("logged entries = %d, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Level != "ERROR" || entry.Component != "http" || entry.Message != "HTTP request "+requestID+" failed: controller rejected provider state" || entry.Fields["request_id"] != requestID || entry.Fields["method"] != http.MethodPut || entry.Fields["path"] != "[REDACTED]" || entry.Fields["error"] != "controller rejected provider state" {
		t.Fatalf("logged entry = %#v", entry)
	}
}

func TestConnectionStreamAndCloseEndpointsAreAuthenticatedAndCapabilityNeutral(t *testing.T) {
	connectionStream := make(chan ConnectionStreamSnapshot, 1)
	connectionStream <- ConnectionStreamSnapshot{Active: []Connection{{
		ID: "connection-1", Host: "example.test", Destination: "198.51.100.2:443",
		Source: "192.0.2.10:54321", Network: "tcp", Type: "TProxy",
		Rule: "RuleSet", RulePayload: "local-example", Chains: []string{"node-a", "PROXY"},
		DownloadRateBytes: 250, UploadRateBytes: 100, DownloadBytes: 700, UploadBytes: 300,
	}}, DownloadTotalBytes: 700, UploadTotalBytes: 300, MemoryBytes: 4096}
	close(connectionStream)
	core := &fakeCoreService{connectionStream: connectionStream}
	handler := newTestHandler(t, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
		Core:           core,
	})

	anonymous := perform(handler, http.MethodGet, "/api/v1/core/connections/stream", "", nil, "")
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous connection stream = %d, want 401", anonymous.Code)
	}
	cookie, csrf := login(t, handler)
	stream := perform(handler, http.MethodGet, "/api/v1/core/connections/stream", "", cookie, "")
	if stream.Code != http.StatusOK || !strings.HasPrefix(stream.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatalf("connection stream = %d headers=%v body=%s", stream.Code, stream.Header(), stream.Body.String())
	}
	for _, expected := range []string{
		"event: connections", `"host":"example.test"`, `"type":"TProxy"`,
		`"rulePayload":"local-example"`, `"chains":["node-a","PROXY"]`,
		`"downloadRateBytes":250`, `"uploadRateBytes":100`, `"downloadTotalBytes":700`, `"memoryBytes":4096`,
	} {
		if !strings.Contains(stream.Body.String(), expected) {
			t.Errorf("connection stream missing %q: %s", expected, stream.Body.String())
		}
	}

	withoutCSRF := perform(handler, http.MethodDelete, "/api/v1/core/connections", "", cookie, "")
	if withoutCSRF.Code != http.StatusForbidden || core.closedAll != 0 {
		t.Fatalf("close all without CSRF = %d calls=%d", withoutCSRF.Code, core.closedAll)
	}
	closeAll := perform(handler, http.MethodDelete, "/api/v1/core/connections", "", cookie, csrf)
	if closeAll.Code != http.StatusNoContent || core.closedAll != 1 {
		t.Fatalf("close all = %d calls=%d body=%s", closeAll.Code, core.closedAll, closeAll.Body.String())
	}
	closeOne := perform(handler, http.MethodDelete, "/api/v1/core/connections/connection-1", "", cookie, csrf)
	if closeOne.Code != http.StatusNoContent || len(core.closedIDs) != 1 || core.closedIDs[0] != "connection-1" {
		t.Fatalf("close one = %d ids=%#v", closeOne.Code, core.closedIDs)
	}
}

func TestAuthenticatedStreamClosesAtSessionExpiry(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	stream := make(chan LogEntry)
	handler, err := NewHandler(Config{
		SessionTTL: time.Second,
		now:        func() time.Time { return now },
	}, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
		SystemLogs:     fakeLogService{stream: stream},
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := login(t, handler)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/logs/system/stream", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	started := time.Now()
	go func() {
		handler.ServeHTTP(response, request)
		close(done)
	}()
	select {
	case <-done:
		if elapsed := time.Since(started); elapsed < 750*time.Millisecond {
			t.Fatalf("stream closed before session expiry after %s", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream remained open after session expiry")
	}
}

func TestCoreUpdateEndpointIsAuthenticatedCSRFProtectedAndNeutral(t *testing.T) {
	updates := &fakeCoreUpdateService{status: CoreUpdateStatus{
		CurrentVersion: "v1.19.29", LatestVersion: "v1.19.30", Channel: "stable", UpdateAvailable: true,
	}}
	handler := newTestHandler(t, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
		Core:           &fakeCoreService{},
		CoreUpdates:    updates,
	})
	cookie, csrf := login(t, handler)
	status := perform(handler, http.MethodGet, "/api/v1/core/update", "", cookie, "")
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"latestVersion":"v1.19.30"`) {
		t.Fatalf("update status = %d %s", status.Code, status.Body.String())
	}
	withoutCSRF := perform(handler, http.MethodPost, "/api/v1/core/update", `{}`, cookie, "")
	if withoutCSRF.Code != http.StatusForbidden || updates.installs != 0 {
		t.Fatalf("update without CSRF = %d installs=%d", withoutCSRF.Code, updates.installs)
	}
	installed := perform(handler, http.MethodPost, "/api/v1/core/update", `{}`, cookie, csrf)
	if installed.Code != http.StatusOK || updates.installs != 1 || !strings.Contains(installed.Body.String(), `"currentVersion":"v1.19.30"`) {
		t.Fatalf("update install = %d installs=%d body=%s", installed.Code, updates.installs, installed.Body.String())
	}
}

func TestEngineCatalogIsAuthenticatedAndReturnsNativeMetadata(t *testing.T) {
	engines := &fakeEngineService{engines: []EngineInfo{
		{ID: "mihomo", DisplayName: "Mihomo", ConfigFormat: "yaml", Extensions: []string{".yaml", ".yml"}, Installed: true, Compatible: true, Selected: true, Running: true, SupportedCaptureModes: []string{"tproxy"}, Management: EngineManagementCapabilities{Updates: true, ExternalDashboard: true}},
		{ID: "sing-box", DisplayName: "sing-box", ConfigFormat: "json", Extensions: []string{".json"}, Installed: false, Compatible: false, Management: EngineManagementCapabilities{RemoteProfiles: true, Updates: true}},
	}}
	handler := newTestHandler(t, Services{
		Credentials: fakeCredentials{}, SessionSecrets: &memorySecretStore{}, Engines: engines,
	})
	if anonymous := perform(handler, http.MethodGet, "/api/v1/engines", "", nil, ""); anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous engine catalog = %d, want 401", anonymous.Code)
	}
	cookie, _ := login(t, handler)
	response := perform(handler, http.MethodGet, "/api/v1/engines", "", cookie, "")
	if response.Code != http.StatusOK || engines.calls != 1 {
		t.Fatalf("engine catalog = %d calls=%d body=%s", response.Code, engines.calls, response.Body.String())
	}
	for _, expected := range []string{`"id":"mihomo"`, `"configFormat":"yaml"`, `"id":"sing-box"`, `"configFormat":"json"`, `"externalDashboard":true`} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Errorf("engine catalog missing %s: %s", expected, response.Body.String())
		}
	}
}

func TestProfileConfigEndpointsAreScopedAndCSRFProtected(t *testing.T) {
	configs := &fakeConfigService{document: RawConfigDocument{
		Format: "json", Content: `{"log":{"level":"info"}}`, Revision: "r1",
		Profile: &ProfileRef{ID: "sing profile", Name: "Sing", Engine: "sing-box"}, Engine: "sing-box",
	}}
	handler := newTestHandler(t, Services{
		Credentials: fakeCredentials{}, SessionSecrets: &memorySecretStore{},
		Profiles: fakeProfilesService{profiles: []Profile{{ID: "sing profile", Name: "Sing", Engine: "sing-box"}}}, Config: configs,
	})
	path := "/api/v1/profiles/sing%20profile/config"
	if anonymous := perform(handler, http.MethodGet, path, "", nil, ""); anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous profile config = %d, want 401", anonymous.Code)
	}
	cookie, csrf := login(t, handler)
	loaded := perform(handler, http.MethodGet, path, "", cookie, "")
	if loaded.Code != http.StatusOK || configs.profileID != "sing profile" || loaded.Header().Get("Cache-Control") != "no-store" || !strings.Contains(loaded.Body.String(), `"engine":"sing-box"`) {
		t.Fatalf("profile config = %d id=%q headers=%v body=%s", loaded.Code, configs.profileID, loaded.Header(), loaded.Body.String())
	}
	withoutCSRF := perform(handler, http.MethodPost, path+"/validate", `{"content":"{}","revision":"r1"}`, cookie, "")
	if withoutCSRF.Code != http.StatusForbidden || configs.validatedProfileID != "" {
		t.Fatalf("validation without CSRF = %d id=%q", withoutCSRF.Code, configs.validatedProfileID)
	}
	validated := perform(handler, http.MethodPost, path+"/validate", `{"content":"{}","revision":"r1"}`, cookie, csrf)
	if validated.Code != http.StatusOK || configs.validatedProfileID != "sing profile" || configs.validatedUpdate.Content != "{}" || !strings.Contains(validated.Body.String(), `"valid":true`) {
		t.Fatalf("profile validation = %d id=%q update=%+v body=%s", validated.Code, configs.validatedProfileID, configs.validatedUpdate, validated.Body.String())
	}
	saved := perform(handler, http.MethodPut, path, `{"content":"{}","revision":"r1","apply":"save"}`, cookie, csrf)
	if saved.Code != http.StatusOK || configs.savedProfileID != "sing profile" || configs.savedUpdate.Apply != "save" || strings.Contains(saved.Body.String(), `"content"`) {
		t.Fatalf("profile save = %d id=%q update=%+v body=%s", saved.Code, configs.savedProfileID, configs.savedUpdate, saved.Body.String())
	}
}

func TestProfileActivationAcceptsOptionalRestartConfirmation(t *testing.T) {
	profiles := &recordingProfilesService{}
	handler := newTestHandler(t, Services{
		Credentials: fakeCredentials{}, SessionSecrets: &memorySecretStore{}, Profiles: profiles,
	})
	cookie, csrf := login(t, handler)
	legacy := perform(handler, http.MethodPost, "/api/v1/profiles/p1/activate", "", cookie, csrf)
	confirmed := perform(handler, http.MethodPost, "/api/v1/profiles/p1/activate", `{"confirmRestart":true}`, cookie, csrf)
	if legacy.Code != http.StatusOK || confirmed.Code != http.StatusOK || len(profiles.activations) != 2 {
		t.Fatalf("profile activations = legacy:%d confirmed:%d calls=%+v", legacy.Code, confirmed.Code, profiles.activations)
	}
	if profiles.activations[0].ConfirmRestart || !profiles.activations[1].ConfirmRestart {
		t.Fatalf("activation confirmations = %+v", profiles.activations)
	}
	malformed := perform(handler, http.MethodPost, "/api/v1/profiles/p1/activate", `{"confirmRestart":`, cookie, csrf)
	if malformed.Code != http.StatusBadRequest || len(profiles.activations) != 2 {
		t.Fatalf("malformed activation = %d calls=%+v body=%s", malformed.Code, profiles.activations, malformed.Body.String())
	}
}

func TestPerEngineUpdateRouteIsAuthenticatedValidatedAndCSRFProtected(t *testing.T) {
	updates := &fakeCoreUpdateService{engineStatuses: map[string]CoreUpdateStatus{
		"mihomo":   {Engine: "mihomo", CurrentVersion: "v1.19.29", LatestVersion: "v1.19.30", Channel: "stable", UpdateAvailable: true},
		"sing-box": {Engine: "sing-box", LatestVersion: "v1.14.0", Channel: "stable", UpdateAvailable: true},
	}}
	handler := newTestHandler(t, Services{
		Credentials: fakeCredentials{}, SessionSecrets: &memorySecretStore{}, CoreUpdates: updates,
	})
	if anonymous := perform(handler, http.MethodGet, "/api/v1/engines/sing-box/update", "", nil, ""); anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous engine update = %d, want 401", anonymous.Code)
	}
	cookie, csrf := login(t, handler)
	status := perform(handler, http.MethodGet, "/api/v1/engines/sing-box/update", "", cookie, "")
	if status.Code != http.StatusOK || updates.engineStatusCalls != 1 || !strings.Contains(status.Body.String(), `"engine":"sing-box"`) {
		t.Fatalf("engine update status = %d calls=%d body=%s", status.Code, updates.engineStatusCalls, status.Body.String())
	}
	withoutCSRF := perform(handler, http.MethodPost, "/api/v1/engines/sing-box/update", `{}`, cookie, "")
	if withoutCSRF.Code != http.StatusForbidden || len(updates.engineInstalls) != 0 {
		t.Fatalf("engine update without CSRF = %d installs=%v", withoutCSRF.Code, updates.engineInstalls)
	}
	installed := perform(handler, http.MethodPost, "/api/v1/engines/sing-box/update", `{}`, cookie, csrf)
	if installed.Code != http.StatusOK || !reflect.DeepEqual(updates.engineInstalls, []string{"sing-box"}) || !strings.Contains(installed.Body.String(), `"currentVersion":"v1.14.0"`) {
		t.Fatalf("engine install = %d installs=%v body=%s", installed.Code, updates.engineInstalls, installed.Body.String())
	}
	invalid := perform(handler, http.MethodGet, "/api/v1/engines/unknown/update", "", cookie, "")
	if invalid.Code != http.StatusNotFound || updates.engineStatusCalls != 1 {
		t.Fatalf("invalid engine update = %d calls=%d body=%s", invalid.Code, updates.engineStatusCalls, invalid.Body.String())
	}
}

func TestExternalDashboardAPIAndFilesAreAuthenticatedAndScoped(t *testing.T) {
	dashboard := &fakeExternalDashboardService{status: ExternalDashboardStatus{
		Name: "Zashboard", Installed: true, CurrentVersion: "v3.22.0", LatestVersion: "v3.23.0", UpdateAvailable: true,
	}}
	assets := &recordingDashboardHandler{}
	handler := newTestHandler(t, Services{
		Credentials:           fakeCredentials{},
		SessionSecrets:        &memorySecretStore{},
		ExternalDashboard:     dashboard,
		ExternalDashboardHTTP: assets,
	})

	if response := perform(handler, http.MethodGet, "/external-ui/", "", nil, ""); response.Code != http.StatusUnauthorized || assets.calls != 0 {
		t.Fatalf("anonymous dashboard asset = %d calls=%d body=%s", response.Code, assets.calls, response.Body.String())
	}
	cookie, csrf := login(t, handler)
	status := perform(handler, http.MethodGet, "/api/v1/external-dashboard?checkUpdates=true", "", cookie, "")
	if status.Code != http.StatusOK || !dashboard.checked || !strings.Contains(status.Body.String(), `"currentVersion":"v3.22.0"`) || strings.Contains(status.Body.String(), "controller-secret") {
		t.Fatalf("dashboard status = %d checked=%t body=%s", status.Code, dashboard.checked, status.Body.String())
	}
	asset := perform(handler, http.MethodGet, "/external-ui/assets/app.js", "", cookie, "")
	if asset.Code != http.StatusOK || assets.calls != 1 {
		t.Fatalf("authorized dashboard asset = %d calls=%d", asset.Code, assets.calls)
	}

	withoutOrigin := perform(handler, http.MethodPut, "/external-ui/controller/configs", `{}`, cookie, "")
	if withoutOrigin.Code != http.StatusForbidden || assets.calls != 1 {
		t.Fatalf("origin-less dashboard mutation = %d calls=%d", withoutOrigin.Code, assets.calls)
	}
	crossSite := performWithHeaders(handler, http.MethodPut, "/external-ui/controller/configs", "application/json", []byte(`{}`), cookie, "", map[string]string{"Origin": "http://attacker.example"})
	if crossSite.Code != http.StatusForbidden || assets.calls != 1 {
		t.Fatalf("cross-site dashboard mutation = %d calls=%d", crossSite.Code, assets.calls)
	}
	sameOrigin := performWithHeaders(handler, http.MethodPut, "/external-ui/controller/configs", "application/json", []byte(`{}`), cookie, "", map[string]string{"Origin": "http://example.com"})
	if sameOrigin.Code != http.StatusOK || assets.calls != 2 {
		t.Fatalf("same-origin dashboard mutation = %d calls=%d", sameOrigin.Code, assets.calls)
	}

	websocketWithoutOrigin := performWithHeaders(handler, http.MethodGet, "/external-ui/controller/traffic", "", nil, cookie, "", map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"})
	if websocketWithoutOrigin.Code != http.StatusForbidden {
		t.Fatalf("origin-less dashboard websocket = %d", websocketWithoutOrigin.Code)
	}
	websocketSameOrigin := performWithHeaders(handler, http.MethodGet, "/external-ui/controller/traffic", "", nil, cookie, "", map[string]string{"Connection": "Upgrade", "Upgrade": "websocket", "Origin": "http://example.com"})
	if websocketSameOrigin.Code != http.StatusOK || assets.calls != 3 {
		t.Fatalf("same-origin dashboard websocket = %d calls=%d", websocketSameOrigin.Code, assets.calls)
	}

	withoutCSRF := perform(handler, http.MethodPost, "/api/v1/external-dashboard/update", `{}`, cookie, "")
	if withoutCSRF.Code != http.StatusForbidden || dashboard.updates != 0 {
		t.Fatalf("dashboard update without CSRF = %d updates=%d", withoutCSRF.Code, dashboard.updates)
	}
	updated := perform(handler, http.MethodPost, "/api/v1/external-dashboard/update", `{}`, cookie, csrf)
	if updated.Code != http.StatusOK || dashboard.updates != 1 {
		t.Fatalf("dashboard update = %d updates=%d body=%s", updated.Code, dashboard.updates, updated.Body.String())
	}
	opened := perform(handler, http.MethodGet, "/api/v1/external-dashboard/open", "", cookie, "")
	if opened.Code != http.StatusOK || !strings.Contains(opened.Body.String(), `"path":"/external-ui/"`) || strings.Contains(opened.Body.String(), "controller-secret") {
		t.Fatalf("dashboard open = %d body=%s", opened.Code, opened.Body.String())
	}
}

func TestExternalDashboardAcceptsExplicitHTTPSOriginBehindHTTPProxy(t *testing.T) {
	assets := &recordingDashboardHandler{}
	handler, err := NewHandler(Config{PublicOrigin: "https://router.example"}, Services{
		Credentials: fakeCredentials{}, SessionSecrets: &memorySecretStore{}, ExternalDashboardHTTP: assets,
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := login(t, handler)
	if !cookie.Secure {
		t.Fatal("HTTPS public origin did not enable the Secure session cookie")
	}
	accepted := performWithHeaders(handler, http.MethodPut, "/external-ui/controller/configs", "application/json", []byte(`{}`), cookie, "", map[string]string{
		"Host": "router.example", "Origin": "https://router.example",
	})
	if accepted.Code != http.StatusOK || assets.calls != 1 {
		t.Fatalf("proxied HTTPS mutation = %d calls=%d body=%s", accepted.Code, assets.calls, accepted.Body.String())
	}
	rejected := performWithHeaders(handler, http.MethodPut, "/external-ui/controller/configs", "application/json", []byte(`{}`), cookie, "", map[string]string{
		"Host": "router.example", "Origin": "http://router.example",
	})
	if rejected.Code != http.StatusForbidden || assets.calls != 1 {
		t.Fatalf("wrong-scheme mutation = %d calls=%d", rejected.Code, assets.calls)
	}
	wrongPort := performWithHeaders(handler, http.MethodPut, "/external-ui/controller/configs", "application/json", []byte(`{}`), cookie, "", map[string]string{
		"Host": "router.example:9443", "Origin": "https://router.example",
	})
	if wrongPort.Code != http.StatusForbidden || assets.calls != 1 {
		t.Fatalf("wrong-host-port mutation = %d calls=%d", wrongPort.Code, assets.calls)
	}
}

func TestExternalDashboardAcceptsConfiguredNonDefaultOriginPort(t *testing.T) {
	assets := &recordingDashboardHandler{}
	handler, err := NewHandler(Config{PublicOrigin: "https://router.example:8443"}, Services{
		Credentials: fakeCredentials{}, SessionSecrets: &memorySecretStore{}, ExternalDashboardHTTP: assets,
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := login(t, handler)
	accepted := performWithHeaders(handler, http.MethodPut, "/external-ui/controller/configs", "application/json", []byte(`{}`), cookie, "", map[string]string{
		"Host": "router.example:8443", "Origin": "https://router.example:8443",
	})
	if accepted.Code != http.StatusOK || assets.calls != 1 {
		t.Fatalf("proxied non-default-port mutation = %d calls=%d body=%s", accepted.Code, assets.calls, accepted.Body.String())
	}
}

func TestExternalDashboardWebSocketContextClosesAtSessionExpiry(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	assets := &expiringDashboardHandler{started: make(chan struct{}), canceled: make(chan struct{})}
	handler, err := NewHandler(Config{
		SessionTTL: time.Second,
		now:        func() time.Time { return now },
	}, Services{
		Credentials:           fakeCredentials{},
		SessionSecrets:        &memorySecretStore{},
		ExternalDashboardHTTP: assets,
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := login(t, handler)
	request := httptest.NewRequest(http.MethodGet, "/external-ui/controller/traffic", nil)
	request.AddCookie(cookie)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Origin", "http://example.com")
	response := httptest.NewRecorder()
	done := make(chan struct{})
	started := time.Now()
	go func() {
		handler.ServeHTTP(response, request)
		close(done)
	}()
	select {
	case <-assets.started:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("dashboard WebSocket handler did not start")
	}
	select {
	case <-assets.canceled:
		if elapsed := time.Since(started); elapsed < 750*time.Millisecond {
			t.Fatalf("dashboard WebSocket context closed before session expiry after %s", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dashboard WebSocket context remained open after session expiry")
	}
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("dashboard WebSocket handler did not return after context cancellation")
	}
}

func TestRawConfigAndLifecycleAreAuthenticatedAndCSRFProtected(t *testing.T) {
	configService := &fakeConfigService{document: RawConfigDocument{
		Format:   "yaml",
		Content:  "password: very-secret\n",
		Revision: "r1",
	}}
	lifecycle := &fakeLifecycleService{}
	handler := newTestHandler(t, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
		Config:         configService,
		Lifecycle:      lifecycle,
	})
	anonymous := perform(handler, http.MethodGet, "/api/v1/config", "", nil, "")
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous config = %d, want 401", anonymous.Code)
	}
	cookie, csrf := login(t, handler)
	get := perform(handler, http.MethodGet, "/api/v1/config", "", cookie, "")
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), "very-secret") || get.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("authenticated config = %d headers=%v body=%s", get.Code, get.Header(), get.Body.String())
	}
	withoutCSRF := perform(handler, http.MethodPost, "/api/v1/service/restart", "", cookie, "")
	if withoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("lifecycle without CSRF = %d, want 403", withoutCSRF.Code)
	}
	restart := perform(handler, http.MethodPost, "/api/v1/service/restart", "", cookie, csrf)
	if restart.Code != http.StatusAccepted || lifecycle.restarts != 1 {
		t.Fatalf("lifecycle restart = %d restarts=%d", restart.Code, lifecycle.restarts)
	}
	save := perform(handler, http.MethodPut, "/api/v1/config", `{"content":"password: very-secret\n","revision":"r1"}`, cookie, csrf)
	if save.Code != http.StatusOK || strings.Contains(save.Body.String(), "very-secret") {
		t.Fatalf("save response leaked raw config: %d %s", save.Code, save.Body.String())
	}
}

func TestProfileEngineDefaultsToMihomoAndRejectsUnknownEngine(t *testing.T) {
	profiles := &recordingProfilesService{}
	handler := newTestHandler(t, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
		Profiles:       profiles,
	})
	cookie, csrf := login(t, handler)
	created := perform(handler, http.MethodPost, "/api/v1/profiles", `{"name":"Legacy","sourceUrl":"https://example.test/sub"}`, cookie, csrf)
	if created.Code != http.StatusCreated || profiles.draft.Engine != "mihomo" || !strings.Contains(created.Body.String(), `"engine":"mihomo"`) {
		t.Fatalf("default engine create = %d draft=%+v body=%s", created.Code, profiles.draft, created.Body.String())
	}
	unknown := perform(handler, http.MethodPost, "/api/v1/profiles", `{"name":"Bad","engine":"unknown"}`, cookie, csrf)
	if unknown.Code != http.StatusBadRequest || !strings.Contains(unknown.Body.String(), `"code":"invalid_engine"`) {
		t.Fatalf("unknown engine = %d %s", unknown.Code, unknown.Body.String())
	}
}

func TestProxySubscriptionCRUDIsCSRFProtectedAndWriteOnly(t *testing.T) {
	service := &recordingProxySubscriptionService{}
	handler := newTestHandler(t, Services{
		Credentials: fakeCredentials{}, SessionSecrets: &memorySecretStore{}, ProxySubscriptions: service,
	})
	cookie, csrf := login(t, handler)
	secretURL := "https://example.test/private-token"
	created := perform(handler, http.MethodPost, "/api/v1/proxy-subscriptions", `{"engine":"mihomo","name":"Remote","sourceUrl":"`+secretURL+`","headers":{"X-HWID":"private-hwid"}}`, cookie, csrf)
	if created.Code != http.StatusCreated || service.draft.Engine != "mihomo" || service.draft.SourceURL != secretURL || !strings.Contains(created.Body.String(), `"engine":"mihomo"`) || strings.Contains(created.Body.String(), "private-token") || strings.Contains(created.Body.String(), "private-hwid") {
		t.Fatalf("create = %d draft=%+v body=%s", created.Code, service.draft, created.Body.String())
	}
	read := perform(handler, http.MethodGet, "/api/v1/proxy-subscriptions/sub-1", "", cookie, "")
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"providerName":"boxctl-sub-1"`) {
		t.Fatalf("read = %d body=%s", read.Code, read.Body.String())
	}
	withoutCSRF := perform(handler, http.MethodPost, "/api/v1/proxy-subscriptions/sub-1/refresh", `{}`, cookie, "")
	if withoutCSRF.Code != http.StatusForbidden || service.refreshes != 0 {
		t.Fatalf("refresh without CSRF = %d refreshes=%d", withoutCSRF.Code, service.refreshes)
	}
	refreshed := perform(handler, http.MethodPost, "/api/v1/proxy-subscriptions/sub-1/refresh", `{}`, cookie, csrf)
	if refreshed.Code != http.StatusOK || service.refreshes != 1 {
		t.Fatalf("refresh = %d refreshes=%d", refreshed.Code, service.refreshes)
	}
}

func TestAdvancedSettingsPatchPreservesTypedFields(t *testing.T) {
	settings := &fakeSettingsService{settings: Settings{
		Language:                             "ru",
		Theme:                                "system",
		DNSMode:                              "redirect",
		InterfaceMode:                        "explicit",
		AutoDetectWAN:                        true,
		AutoDetectLAN:                        false,
		InterceptRouterOutput:                true,
		IncludedInterfaces:                   []string{"br-lan", "tailscale0"},
		ExcludedInterfaces:                   []string{"wan"},
		TUNStack:                             "mixed",
		RejectQUIC:                           true,
		ReservedNetworks:                     []string{"192.0.2.0/24"},
		BypassSources:                        []string{"192.0.2.5"},
		BypassTCPPorts:                       []uint16{22, 80},
		BypassUDPPorts:                       []uint16{53},
		ProxyOnlyTCPPorts:                    []uint16{443},
		ProxyOnlyUDPPorts:                    []uint16{443},
		AutoFakeIPWhitelist:                  true,
		AutoFakeIPIncludeExternalIPProviders: true,
		UseTmpfsRules:                        true,
		EnableHWID:                           true,
	}}
	handler := newTestHandler(t, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
		Settings:       settings,
	})
	cookie, csrf := login(t, handler)

	response := perform(handler, http.MethodPut, "/api/v1/settings", `{
		"dnsMode":"disabled",
		"interfaceMode":"exclude",
		"autoDetectWAN":false,
		"autoDetectLAN":true,
		"interceptRouterOutput":false,
		"includedInterfaces":[],
		"excludedInterfaces":["pppoe-wan","wg0"],
		"tunStack":"gvisor",
		"rejectQUIC":false,
		"reservedNetworks":["198.51.100.0/24"],
		"bypassSources":["198.51.100.8"],
		"bypassTCPPorts":[22,8080],
		"bypassUDPPorts":[53,123],
		"proxyOnlyTCPPorts":[80,443],
		"proxyOnlyUDPPorts":[443],
		"autoFakeIPWhitelist":false,
		"autoFakeIPIncludeExternalIPProviders":false,
		"useTmpfsRules":false,
		"enableHWID":false
	}`, cookie, csrf)
	if response.Code != http.StatusOK {
		t.Fatalf("settings update = %d %s", response.Code, response.Body.String())
	}
	for _, field := range []string{`"autoDetectWAN":true`, `"autoDetectLAN":false`, `"interceptRouterOutput":true`, `"autoFakeIPIncludeExternalIPProviders":true`} {
		if !strings.Contains(response.Body.String(), field) {
			t.Fatalf("settings response is missing %s: %s", field, response.Body.String())
		}
	}
	patch := settings.patch
	assertStringPointer(t, "dnsMode", patch.DNSMode, "disabled")
	assertStringPointer(t, "interfaceMode", patch.InterfaceMode, "exclude")
	assertBoolPointer(t, "autoDetectWAN", patch.AutoDetectWAN, false)
	assertBoolPointer(t, "autoDetectLAN", patch.AutoDetectLAN, true)
	assertBoolPointer(t, "interceptRouterOutput", patch.InterceptRouterOutput, false)
	assertStringPointer(t, "tunStack", patch.TUNStack, "gvisor")
	assertBoolPointer(t, "rejectQUIC", patch.RejectQUIC, false)
	assertBoolPointer(t, "autoFakeIPWhitelist", patch.AutoFakeIPWhitelist, false)
	assertBoolPointer(t, "autoFakeIPIncludeExternalIPProviders", patch.AutoFakeIPIncludeExternalIPProviders, false)
	assertBoolPointer(t, "useTmpfsRules", patch.UseTmpfsRules, false)
	assertBoolPointer(t, "enableHWID", patch.EnableHWID, false)
	if patch.IncludedInterfaces == nil || !reflect.DeepEqual(*patch.IncludedInterfaces, []string{}) {
		t.Fatalf("includedInterfaces = %#v, want present empty list", patch.IncludedInterfaces)
	}
	if patch.ExcludedInterfaces == nil || !reflect.DeepEqual(*patch.ExcludedInterfaces, []string{"pppoe-wan", "wg0"}) {
		t.Fatalf("excludedInterfaces = %#v", patch.ExcludedInterfaces)
	}
	if patch.BypassTCPPorts == nil || !reflect.DeepEqual(*patch.BypassTCPPorts, []uint16{22, 8080}) {
		t.Fatalf("bypassTCPPorts = %#v", patch.BypassTCPPorts)
	}
	if patch.ProxyOnlyUDPPorts == nil || !reflect.DeepEqual(*patch.ProxyOnlyUDPPorts, []uint16{443}) {
		t.Fatalf("proxyOnlyUDPPorts = %#v", patch.ProxyOnlyUDPPorts)
	}
}

func TestRuleListCRUDUsesOptimisticRevisions(t *testing.T) {
	ruleLists := &fakeRuleListService{document: RuleListDocument{
		RuleList: RuleList{ID: "local", Engine: "mihomo", Name: "Local bypass", Format: "text", Enabled: true, RuleCount: 1, Revision: "r1"},
		Content:  "example.test\n",
	}}
	handler := newTestHandler(t, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
		RuleLists:      ruleLists,
	})

	anonymous := perform(handler, http.MethodGet, "/api/v1/rule-lists", "", nil, "")
	if anonymous.Code != http.StatusUnauthorized || anonymous.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("anonymous list = %d headers=%v", anonymous.Code, anonymous.Header())
	}
	cookie, csrf := login(t, handler)
	withoutCSRF := perform(handler, http.MethodPost, "/api/v1/rule-lists", `{"name":"New","format":"text","content":"test"}`, cookie, "")
	if withoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("create without CSRF = %d, want 403", withoutCSRF.Code)
	}
	created := perform(handler, http.MethodPost, "/api/v1/rule-lists", `{"engine":"mihomo","name":"New","format":"text","enabled":true,"content":"test"}`, cookie, csrf)
	if created.Code != http.StatusCreated || ruleLists.lastDraft.Engine != "mihomo" || !strings.Contains(created.Body.String(), `"engine":"mihomo"`) || created.Header().Get("ETag") != `"c1"` || created.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create = %d headers=%v body=%s", created.Code, created.Header(), created.Body.String())
	}
	loaded := perform(handler, http.MethodGet, "/api/v1/rule-lists/local", "", cookie, "")
	if loaded.Code != http.StatusOK || loaded.Header().Get("ETag") != `"r1"` || !strings.Contains(loaded.Body.String(), "example.test") {
		t.Fatalf("load = %d headers=%v body=%s", loaded.Code, loaded.Header(), loaded.Body.String())
	}
	missingRevision := perform(handler, http.MethodPut, "/api/v1/rule-lists/local", `{"content":"next"}`, cookie, csrf)
	if missingRevision.Code != http.StatusPreconditionRequired || !strings.Contains(missingRevision.Body.String(), `"code":"revision_required"`) {
		t.Fatalf("missing revision = %d %s", missingRevision.Code, missingRevision.Body.String())
	}
	stale := performWithHeaders(handler, http.MethodPut, "/api/v1/rule-lists/local", "application/json", []byte(`{"content":"next"}`), cookie, csrf, map[string]string{"If-Match": `"stale"`})
	if stale.Code != http.StatusConflict || !strings.Contains(stale.Body.String(), `"code":"conflict"`) {
		t.Fatalf("stale update = %d %s", stale.Code, stale.Body.String())
	}
	mismatched := performWithHeaders(handler, http.MethodPut, "/api/v1/rule-lists/local", "application/json", []byte(`{"content":"next","revision":"r1"}`), cookie, csrf, map[string]string{"If-Match": `"other"`})
	if mismatched.Code != http.StatusBadRequest || !strings.Contains(mismatched.Body.String(), `"code":"revision_mismatch"`) {
		t.Fatalf("mismatched revision = %d %s", mismatched.Code, mismatched.Body.String())
	}
	updated := performWithHeaders(handler, http.MethodPut, "/api/v1/rule-lists/local", "application/json", []byte(`{"content":"next"}`), cookie, csrf, map[string]string{"If-Match": `"r1"`})
	if updated.Code != http.StatusOK || updated.Header().Get("ETag") != `"r2"` || ruleLists.lastUpdate.Revision != "r1" {
		t.Fatalf("update = %d headers=%v update=%+v body=%s", updated.Code, updated.Header(), ruleLists.lastUpdate, updated.Body.String())
	}
	attachWithoutCSRF := perform(handler, http.MethodPost, "/api/v1/rule-lists/local/config", `{}`, cookie, "")
	if attachWithoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("attach without CSRF = %d, want 403", attachWithoutCSRF.Code)
	}
	attached := perform(handler, http.MethodPost, "/api/v1/rule-lists/local/config", `{}`, cookie, csrf)
	if attached.Code != http.StatusOK || ruleLists.addedToConfig != "local" || !strings.Contains(attached.Body.String(), `"inConfig":true`) {
		t.Fatalf("attach = %d id=%q body=%s", attached.Code, ruleLists.addedToConfig, attached.Body.String())
	}
	deleteWithoutRevision := perform(handler, http.MethodDelete, "/api/v1/rule-lists/local", "", cookie, csrf)
	if deleteWithoutRevision.Code != http.StatusPreconditionRequired {
		t.Fatalf("delete without revision = %d, want 428", deleteWithoutRevision.Code)
	}
	staleDelete := performWithHeaders(handler, http.MethodDelete, "/api/v1/rule-lists/local", "", nil, cookie, csrf, map[string]string{"If-Match": `"r1"`})
	if staleDelete.Code != http.StatusConflict {
		t.Fatalf("stale delete = %d, want 409", staleDelete.Code)
	}
	deleted := performWithHeaders(handler, http.MethodDelete, "/api/v1/rule-lists/local", "", nil, cookie, csrf, map[string]string{"If-Match": `"r2"`})
	if deleted.Code != http.StatusNoContent || ruleLists.deletedRevision != "r2" {
		t.Fatalf("delete = %d revision=%q", deleted.Code, ruleLists.deletedRevision)
	}
}

func TestFakeIPWhitelistEndpointsUseOptimisticRevisions(t *testing.T) {
	generatedAt := time.Date(2026, time.August, 25, 20, 15, 0, 0, time.UTC)
	whitelist := &fakeFakeIPWhitelistService{
		document: FakeIPWhitelistDocument{
			ManualContent:   "203.0.113.0/24\n",
			GeneratedCIDRs:  []string{"149.154.160.0/20"},
			FakeIPRanges:    []string{"198.18.0.0/15"},
			EffectiveCIDRs:  []string{"149.154.160.0/20", "198.18.0.0/15", "203.0.113.0/24"},
			ManualCount:     1,
			GeneratedCount:  1,
			EffectiveCount:  3,
			Revision:        "r1",
			GeneratedAt:     &generatedAt,
			Applicable:      true,
			Selective:       true,
			Applied:         true,
			RestartRequired: false,
		},
		privateConfig: "password: very-secret",
	}
	handler := newTestHandler(t, Services{
		Credentials:     fakeCredentials{},
		SessionSecrets:  &memorySecretStore{},
		FakeIPWhitelist: whitelist,
	})

	anonymous := perform(handler, http.MethodGet, "/api/v1/fake-ip-whitelist", "", nil, "")
	if anonymous.Code != http.StatusUnauthorized || anonymous.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("anonymous whitelist = %d headers=%v", anonymous.Code, anonymous.Header())
	}
	cookie, csrf := login(t, handler)
	loaded := perform(handler, http.MethodGet, "/api/v1/fake-ip-whitelist", "", cookie, "")
	if loaded.Code != http.StatusOK || loaded.Header().Get("ETag") != `"r1"` || loaded.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("load whitelist = %d headers=%v body=%s", loaded.Code, loaded.Header(), loaded.Body.String())
	}
	for _, expected := range []string{`"manualContent":"203.0.113.0/24\n"`, `"generatedCIDRs":["149.154.160.0/20"]`, `"warnings":[]`} {
		if !strings.Contains(loaded.Body.String(), expected) {
			t.Fatalf("load whitelist omitted %s: %s", expected, loaded.Body.String())
		}
	}
	if strings.Contains(loaded.Body.String(), whitelist.privateConfig) || containsSecret(loaded.Body.String()) {
		t.Fatalf("load whitelist leaked private configuration: %s", loaded.Body.String())
	}

	withoutCSRF := performWithHeaders(handler, http.MethodPut, "/api/v1/fake-ip-whitelist", "application/json", []byte(`{"manualContent":"next"}`), cookie, "", map[string]string{"If-Match": `"r1"`})
	if withoutCSRF.Code != http.StatusForbidden || whitelist.updates != 0 {
		t.Fatalf("update without CSRF = %d updates=%d", withoutCSRF.Code, whitelist.updates)
	}
	missingRevision := perform(handler, http.MethodPut, "/api/v1/fake-ip-whitelist", `{"manualContent":"next"}`, cookie, csrf)
	if missingRevision.Code != http.StatusPreconditionRequired || !strings.Contains(missingRevision.Body.String(), `"code":"revision_required"`) {
		t.Fatalf("update without revision = %d %s", missingRevision.Code, missingRevision.Body.String())
	}
	stale := performWithHeaders(handler, http.MethodPut, "/api/v1/fake-ip-whitelist", "application/json", []byte(`{"manualContent":"next"}`), cookie, csrf, map[string]string{"If-Match": `"stale"`})
	if stale.Code != http.StatusConflict || !strings.Contains(stale.Body.String(), `"code":"conflict"`) {
		t.Fatalf("stale whitelist update = %d %s", stale.Code, stale.Body.String())
	}

	whitelist.updateErr = &PublicError{
		Status:  http.StatusUnprocessableEntity,
		Code:    "invalid_cidr",
		Message: "invalid value from /tmp/boxctl/mihomo-private.yaml at https://user:pass@example.test/path-secret?token=query-secret",
	}
	invalid := performWithHeaders(handler, http.MethodPut, "/api/v1/fake-ip-whitelist", "application/json", []byte(`{"manualContent":"bad"}`), cookie, csrf, map[string]string{"If-Match": `"r1"`})
	if invalid.Code != http.StatusUnprocessableEntity || !strings.Contains(invalid.Body.String(), `"code":"invalid_cidr"`) || containsSecret(invalid.Body.String()) {
		t.Fatalf("public whitelist error = %d %s", invalid.Code, invalid.Body.String())
	}
	whitelist.updateErr = nil

	updated := performWithHeaders(handler, http.MethodPut, "/api/v1/fake-ip-whitelist", "application/json", []byte(`{"manualContent":"203.0.113.0/25\n203.0.113.128/25\n"}`), cookie, csrf, map[string]string{"If-Match": "r1"})
	if updated.Code != http.StatusOK || updated.Header().Get("ETag") != `"r2"` || whitelist.lastUpdate.Revision != "r1" || whitelist.lastUpdate.ManualContent != "203.0.113.0/25\n203.0.113.128/25\n" {
		t.Fatalf("update whitelist = %d headers=%v update=%+v body=%s", updated.Code, updated.Header(), whitelist.lastUpdate, updated.Body.String())
	}

	regenerateWithoutCSRF := performWithHeaders(handler, http.MethodPost, "/api/v1/fake-ip-whitelist/regenerate", "application/json", []byte(`{}`), cookie, "", map[string]string{"If-Match": `"r2"`})
	if regenerateWithoutCSRF.Code != http.StatusForbidden || whitelist.regenerations != 0 {
		t.Fatalf("regenerate without CSRF = %d regenerations=%d", regenerateWithoutCSRF.Code, whitelist.regenerations)
	}
	regenerateWithoutRevision := perform(handler, http.MethodPost, "/api/v1/fake-ip-whitelist/regenerate", `{}`, cookie, csrf)
	if regenerateWithoutRevision.Code != http.StatusPreconditionRequired {
		t.Fatalf("regenerate without revision = %d %s", regenerateWithoutRevision.Code, regenerateWithoutRevision.Body.String())
	}
	staleRegenerate := performWithHeaders(handler, http.MethodPost, "/api/v1/fake-ip-whitelist/regenerate", "application/json", []byte(`{}`), cookie, csrf, map[string]string{"If-Match": `"r1"`})
	if staleRegenerate.Code != http.StatusConflict {
		t.Fatalf("stale regenerate = %d %s", staleRegenerate.Code, staleRegenerate.Body.String())
	}
	regenerated := performWithHeaders(handler, http.MethodPost, "/api/v1/fake-ip-whitelist/regenerate", "application/json", []byte(`{}`), cookie, csrf, map[string]string{"If-Match": `"r2"`})
	if regenerated.Code != http.StatusOK || regenerated.Header().Get("ETag") != `"r3"` || whitelist.lastRegenerateRevision != "r2" || whitelist.regenerations != 1 || !strings.Contains(regenerated.Body.String(), `"applied":true`) {
		t.Fatalf("regenerate whitelist = %d headers=%v revision=%q regenerations=%d body=%s", regenerated.Code, regenerated.Header(), whitelist.lastRegenerateRevision, whitelist.regenerations, regenerated.Body.String())
	}
}

func TestBackupExportImportAuthCSRFLimitsAndHeaders(t *testing.T) {
	backups := &fakeBackupService{archive: BackupArchive{
		Filename: `../router backup "daily".bin`,
		Data:     []byte("backup-data"),
	}}
	handler, err := NewHandler(Config{MaxBackupBytes: 64}, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
		Backups:        backups,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	anonymous := perform(handler, http.MethodGet, "/api/v1/backups/export", "", nil, "")
	if anonymous.Code != http.StatusUnauthorized || anonymous.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("anonymous export = %d headers=%v", anonymous.Code, anonymous.Header())
	}
	cookie, csrf := login(t, handler)
	exported := perform(handler, http.MethodGet, "/api/v1/backups/export?includeAdminPassword=true&includeProviderCaches=true&includeDashboardUI=true", "", cookie, "")
	if exported.Code != http.StatusOK || exported.Body.String() != "backup-data" || exported.Header().Get("Content-Type") != "application/octet-stream" || exported.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("export = %d headers=%v body=%q", exported.Code, exported.Header(), exported.Body.String())
	}
	if len(backups.exports) != 1 || backups.exports[0] != (BackupExportOptions{IncludeAdminPassword: true, IncludeProviderCaches: true, IncludeDashboardUI: true}) {
		t.Fatalf("export options = %+v", backups.exports)
	}
	invalidOptions := perform(handler, http.MethodGet, "/api/v1/backups/export?includeAdminPassword=maybe", "", cookie, "")
	if invalidOptions.Code != http.StatusBadRequest || !strings.Contains(invalidOptions.Body.String(), `"code":"invalid_export_options"`) {
		t.Fatalf("invalid export options = %d %s", invalidOptions.Code, invalidOptions.Body.String())
	}
	dispositionType, dispositionParams, err := mime.ParseMediaType(exported.Header().Get("Content-Disposition"))
	if err != nil || dispositionType != "attachment" || dispositionParams["filename"] != "router backup daily.bin" {
		t.Fatalf("Content-Disposition = %q parsed=%q %#v err=%v", exported.Header().Get("Content-Disposition"), dispositionType, dispositionParams, err)
	}

	withoutCSRF := performWithHeaders(handler, http.MethodPost, "/api/v1/backups/import", "application/octet-stream", []byte("raw"), cookie, "", map[string]string{"X-Backup-Filename": "raw.bin"})
	if withoutCSRF.Code != http.StatusForbidden || len(backups.imports) != 0 {
		t.Fatalf("import without CSRF = %d imports=%d", withoutCSRF.Code, len(backups.imports))
	}
	raw := performWithHeaders(handler, http.MethodPost, "/api/v1/backups/import", "application/octet-stream", []byte("raw"), cookie, csrf, map[string]string{"Content-Disposition": `attachment; filename*=UTF-8''daily%20router.bin`})
	if raw.Code != http.StatusOK || raw.Header().Get("Cache-Control") != "no-store" || len(backups.imports) != 1 || backups.imports[0].Filename != "daily router.bin" || string(backups.imports[0].Data) != "raw" || !strings.Contains(raw.Body.String(), `"sessionsRevoked":true`) {
		t.Fatalf("raw import = %d headers=%v imports=%+v body=%s", raw.Code, raw.Header(), backups.imports, raw.Body.String())
	}
	clearedCookies := raw.Result().Cookies()
	if len(clearedCookies) != 1 || clearedCookies[0].MaxAge >= 0 {
		t.Fatalf("restore did not clear browser cookie: %+v", clearedCookies)
	}
	oldSession := perform(handler, http.MethodGet, "/api/v1/auth/session", "", cookie, "")
	if oldSession.Code != http.StatusUnauthorized {
		t.Fatalf("pre-restore session remained valid: %d %s", oldSession.Code, oldSession.Body.String())
	}
	cookie, csrf = login(t, handler)

	var multipartBody bytes.Buffer
	multipartWriter := multipart.NewWriter(&multipartBody)
	part, err := multipartWriter.CreateFormFile("backup", "router.tgz")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	_, _ = part.Write([]byte("multipart"))
	if err := multipartWriter.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	multipartResponse := performWithHeaders(handler, http.MethodPost, "/api/v1/backups/import", multipartWriter.FormDataContentType(), multipartBody.Bytes(), cookie, csrf, nil)
	if multipartResponse.Code != http.StatusOK || len(backups.imports) != 2 || backups.imports[1].Filename != "router.tgz" || string(backups.imports[1].Data) != "multipart" {
		t.Fatalf("multipart import = %d imports=%+v body=%s", multipartResponse.Code, backups.imports, multipartResponse.Body.String())
	}

	smallBackups := &fakeBackupService{archive: BackupArchive{Filename: "too-big.bin", Data: []byte("four")}}
	smallHandler, err := NewHandler(Config{MaxBackupBytes: 3}, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
		Backups:        smallBackups,
	})
	if err != nil {
		t.Fatalf("NewHandler small: %v", err)
	}
	smallCookie, smallCSRF := login(t, smallHandler)
	oversizedExport := perform(smallHandler, http.MethodGet, "/api/v1/backups/export", "", smallCookie, "")
	if oversizedExport.Code != http.StatusRequestEntityTooLarge || strings.Contains(oversizedExport.Body.String(), "four") {
		t.Fatalf("oversized export = %d body=%s", oversizedExport.Code, oversizedExport.Body.String())
	}
	oversized := performWithHeaders(smallHandler, http.MethodPost, "/api/v1/backups/import", "application/octet-stream", []byte("four"), smallCookie, smallCSRF, nil)
	if oversized.Code != http.StatusRequestEntityTooLarge || len(smallBackups.imports) != 0 || !strings.Contains(oversized.Body.String(), `"code":"backup_too_large"`) {
		t.Fatalf("oversized import = %d imports=%d body=%s", oversized.Code, len(smallBackups.imports), oversized.Body.String())
	}
}

func TestBackupImportBlocksLoginThroughSessionRevocation(t *testing.T) {
	backups := &blockingBackupService{started: make(chan struct{}), release: make(chan struct{})}
	handler, err := NewHandler(Config{MaxBackupBytes: 64}, Services{
		Credentials:    fakeCredentials{},
		SessionSecrets: &memorySecretStore{},
		Backups:        backups,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	cookie, csrf := login(t, handler)

	importDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		importDone <- performWithHeaders(handler, http.MethodPost, "/api/v1/backups/import", "application/octet-stream", []byte("backup"), cookie, csrf, nil)
	}()
	select {
	case <-backups.started:
	case <-time.After(time.Second):
		t.Fatal("backup import did not enter postflight")
	}

	loginDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		loginDone <- perform(handler, http.MethodPost, "/api/v1/auth/login", `{"password":"correct horse"}`, nil, "")
	}()
	select {
	case response := <-loginDone:
		t.Fatalf("login escaped backup mutation gate: %d %s", response.Code, response.Body.String())
	case <-time.After(50 * time.Millisecond):
	}
	close(backups.release)
	select {
	case response := <-importDone:
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"sessionsRevoked":true`) {
			t.Fatalf("backup import = %d %s", response.Code, response.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("backup import did not finish")
	}
	select {
	case response := <-loginDone:
		if response.Code != http.StatusOK {
			t.Fatalf("login after restore = %d %s", response.Code, response.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("login remained blocked after backup finalization")
	}
}

func newTestHandler(t *testing.T, services Services) http.Handler {
	t.Helper()
	handler, err := NewHandler(Config{AllowedHosts: []string{"example.com"}}, services)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return handler
}

func login(t *testing.T, handler http.Handler) (*http.Cookie, string) {
	t.Helper()
	response := perform(handler, http.MethodPost, "/api/v1/auth/login", `{"password":"correct horse"}`, nil, "")
	if response.Code != http.StatusOK {
		t.Fatalf("login = %d %s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies = %d, want 1", len(cookies))
	}
	var envelope struct {
		Data struct {
			CSRF string `json:"csrfToken"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	if envelope.Data.CSRF == "" {
		t.Fatal("login did not return CSRF token")
	}
	return cookies[0], envelope.Data.CSRF
}

func perform(handler http.Handler, method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request.RemoteAddr = "192.0.2.15:12345"
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func performWithHeaders(handler http.Handler, method, requestPath, contentType string, body []byte, cookie *http.Cookie, csrf string, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, requestPath, bytes.NewReader(body))
	request.RemoteAddr = "192.0.2.15:12345"
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	for name, value := range headers {
		if strings.EqualFold(name, "Host") {
			request.Host = value
		} else {
			request.Header.Set(name, value)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertStringPointer(t *testing.T, name string, got *string, want string) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("%s = %#v, want %q", name, got, want)
	}
}

func assertBoolPointer(t *testing.T, name string, got *bool, want bool) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("%s = %#v, want %t", name, got, want)
	}
}

type fakeCredentials struct{}

func (fakeCredentials) Credential(context.Context) (Credential, error) {
	return Credential{UserID: "1", DisplayName: "Administrator", PasswordRecord: passwordRecord("correct horse")}, nil
}

type fakeAdminSetup struct {
	mu       sync.Mutex
	required bool
	calls    int
}

func (s *fakeAdminSetup) AdminSetupStatus(context.Context) (AdminSetupStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return AdminSetupStatus{Required: s.required}, nil
}

func (s *fakeAdminSetup) InitializeAdmin(_ context.Context, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if !s.required {
		return &PublicError{Status: http.StatusConflict, Code: "setup_complete", Message: "Administrator setup is already complete"}
	}
	s.required = false
	return nil
}

type fakeSettingsService struct {
	settings Settings
	updates  int
	patch    SettingsPatch
}

func (s *fakeSettingsService) Settings(context.Context) (Settings, error) { return s.settings, nil }

func (s *fakeSettingsService) UpdateSettings(_ context.Context, patch SettingsPatch) (Settings, error) {
	s.updates++
	s.patch = patch
	if patch.Language != nil {
		s.settings.Language = *patch.Language
	}
	return s.settings, nil
}

type fakeProfilesService struct{ profiles []Profile }

func (s fakeProfilesService) Profiles(context.Context) ([]Profile, error) { return s.profiles, nil }
func (s fakeProfilesService) Profile(context.Context, string) (Profile, error) {
	return s.profiles[0], nil
}
func (s fakeProfilesService) CreateProfile(context.Context, ProfileDraft) (Profile, error) {
	return s.profiles[0], nil
}
func (s fakeProfilesService) UpdateProfile(context.Context, string, ProfilePatch) (Profile, error) {
	return s.profiles[0], nil
}
func (s fakeProfilesService) DeleteProfile(context.Context, string) error { return nil }
func (s fakeProfilesService) ActivateProfile(context.Context, string) (Profile, error) {
	return s.profiles[0], nil
}
func (s fakeProfilesService) RefreshProfile(context.Context, string) (Profile, error) {
	return s.profiles[0], nil
}
func (s fakeProfilesService) DetachProfileSource(context.Context, string) (Profile, error) {
	return s.profiles[0], nil
}

type fakeEngineService struct {
	engines []EngineInfo
	calls   int
}

func (s *fakeEngineService) Engines(context.Context) ([]EngineInfo, error) {
	s.calls++
	return append([]EngineInfo(nil), s.engines...), nil
}

type fakeLogService struct{ stream <-chan LogEntry }

func (s fakeLogService) SystemLogs(context.Context, LogQuery) ([]LogEntry, error) { return nil, nil }
func (s fakeLogService) StreamSystemLogs(context.Context, LogQuery) (<-chan LogEntry, error) {
	return s.stream, nil
}

type fakeDelayCall struct {
	proxy   string
	testURL string
	timeout time.Duration
}

type fakeProviderUpdate struct {
	kind ProviderKind
	name string
}

type fakeCoreService struct {
	capabilities        Capabilities
	delayResult         ProxyDelayResult
	delayErr            error
	delayCalls          []fakeDelayCall
	providers           map[ProviderKind][]Provider
	providersErr        error
	providerUpdates     []fakeProviderUpdate
	providerUpdateErr   error
	dashboard           CoreDashboard
	dashboardStream     <-chan CoreDashboard
	dashboardStreamErr  error
	routingModes        []string
	connections         []Connection
	connectionStream    <-chan ConnectionStreamSnapshot
	connectionStreamErr error
	closedIDs           []string
	closedAll           int
}

func (s *fakeCoreService) Capabilities(context.Context) (Capabilities, error) {
	return s.capabilities, nil
}
func (s *fakeCoreService) Health(context.Context) (CoreHealth, error) { return CoreHealth{}, nil }
func (s *fakeCoreService) Reload(context.Context) error               { return nil }
func (s *fakeCoreService) Dashboard(context.Context) (CoreDashboard, error) {
	return s.dashboard, nil
}
func (s *fakeCoreService) StreamDashboard(context.Context) (<-chan CoreDashboard, error) {
	return s.dashboardStream, s.dashboardStreamErr
}
func (s *fakeCoreService) SetRoutingMode(_ context.Context, mode string) error {
	s.routingModes = append(s.routingModes, mode)
	return nil
}
func (s *fakeCoreService) ProxyGroups(context.Context) ([]ProxyGroup, error) {
	return nil, nil
}
func (s *fakeCoreService) SelectProxy(context.Context, string, string) error { return nil }
func (s *fakeCoreService) TestProxyDelay(_ context.Context, proxy, testURL string, timeout time.Duration) (ProxyDelayResult, error) {
	s.delayCalls = append(s.delayCalls, fakeDelayCall{proxy: proxy, testURL: testURL, timeout: timeout})
	return s.delayResult, s.delayErr
}
func (s *fakeCoreService) Providers(_ context.Context, kind ProviderKind) ([]Provider, error) {
	return append([]Provider(nil), s.providers[kind]...), s.providersErr
}
func (s *fakeCoreService) UpdateProvider(_ context.Context, kind ProviderKind, name string) error {
	s.providerUpdates = append(s.providerUpdates, fakeProviderUpdate{kind: kind, name: name})
	return s.providerUpdateErr
}
func (s *fakeCoreService) Connections(context.Context) ([]Connection, error) {
	return append([]Connection(nil), s.connections...), nil
}
func (s *fakeCoreService) StreamConnections(context.Context) (<-chan ConnectionStreamSnapshot, error) {
	return s.connectionStream, s.connectionStreamErr
}
func (s *fakeCoreService) CloseConnection(_ context.Context, id string) error {
	s.closedIDs = append(s.closedIDs, id)
	return nil
}
func (s *fakeCoreService) CloseAllConnections(context.Context) error {
	s.closedAll++
	return nil
}
func (s *fakeCoreService) Rules(context.Context) ([]Rule, error) { return nil, nil }
func (s *fakeCoreService) CoreLogs(context.Context, LogQuery) ([]LogEntry, error) {
	return nil, nil
}
func (s *fakeCoreService) StreamCoreLogs(context.Context, LogQuery) (<-chan LogEntry, error) {
	return nil, io.EOF
}

type fakeCoreUpdateService struct {
	status            CoreUpdateStatus
	installs          int
	engineStatuses    map[string]CoreUpdateStatus
	engineStatusCalls int
	engineInstalls    []string
}

func (s *fakeCoreUpdateService) CoreUpdateStatus(context.Context) (CoreUpdateStatus, error) {
	return s.status, nil
}

func (s *fakeCoreUpdateService) InstallCoreUpdate(context.Context) (CoreUpdateResult, error) {
	s.installs++
	return CoreUpdateResult{PreviousVersion: s.status.CurrentVersion, CurrentVersion: s.status.LatestVersion, Restarted: true}, nil
}

func (s *fakeCoreUpdateService) EngineUpdateStatus(_ context.Context, engine string) (CoreUpdateStatus, error) {
	s.engineStatusCalls++
	status, ok := s.engineStatuses[engine]
	if !ok {
		return CoreUpdateStatus{}, ErrNotFound
	}
	return status, nil
}

func (s *fakeCoreUpdateService) InstallEngineUpdate(_ context.Context, engine string) (CoreUpdateResult, error) {
	status, ok := s.engineStatuses[engine]
	if !ok {
		return CoreUpdateResult{}, ErrNotFound
	}
	s.engineInstalls = append(s.engineInstalls, engine)
	return CoreUpdateResult{Engine: engine, PreviousVersion: status.CurrentVersion, CurrentVersion: status.LatestVersion, Restarted: true}, nil
}

type fakeExternalDashboardService struct {
	status   ExternalDashboardStatus
	checked  bool
	installs int
	updates  int
}

func (service *fakeExternalDashboardService) ExternalDashboardStatus(_ context.Context, checkUpdates bool) (ExternalDashboardStatus, error) {
	service.checked = checkUpdates
	return service.status, nil
}

func (service *fakeExternalDashboardService) InstallExternalDashboard(context.Context) (ExternalDashboardResult, error) {
	service.installs++
	return ExternalDashboardResult{ExternalDashboardStatus: service.status, Changed: true}, nil
}

func (service *fakeExternalDashboardService) UpdateExternalDashboard(context.Context) (ExternalDashboardResult, error) {
	service.updates++
	service.status.CurrentVersion = service.status.LatestVersion
	service.status.UpdateAvailable = false
	return ExternalDashboardResult{ExternalDashboardStatus: service.status, Changed: true}, nil
}

func (*fakeExternalDashboardService) OpenExternalDashboard(context.Context) (ExternalDashboardOpen, error) {
	return ExternalDashboardOpen{Path: "/external-ui/", ControllerPath: "/external-ui/controller"}, nil
}

type recordingDashboardHandler struct{ calls int }

func (handler *recordingDashboardHandler) ServeHTTP(response http.ResponseWriter, _ *http.Request) {
	handler.calls++
	response.WriteHeader(http.StatusOK)
}

type expiringDashboardHandler struct {
	started  chan struct{}
	canceled chan struct{}
}

func (handler *expiringDashboardHandler) ServeHTTP(_ http.ResponseWriter, request *http.Request) {
	close(handler.started)
	<-request.Context().Done()
	close(handler.canceled)
}

type fakeConfigService struct {
	document           RawConfigDocument
	profileID          string
	validatedProfileID string
	validatedUpdate    RawConfigUpdate
	savedProfileID     string
	savedUpdate        RawConfigUpdate
}

func (s *fakeConfigService) RawConfig(context.Context) (RawConfigDocument, error) {
	return s.document, nil
}
func (s *fakeConfigService) ValidateRawConfig(context.Context, RawConfigUpdate) (ConfigValidation, error) {
	return ConfigValidation{Valid: true}, nil
}
func (s *fakeConfigService) SaveRawConfig(_ context.Context, update RawConfigUpdate) (ConfigSaveResult, error) {
	s.document.Content = update.Content
	s.document.Revision = "r2"
	return ConfigSaveResult{Revision: "r2", ReloadRequired: true}, nil
}

func (s *fakeConfigService) ProfileConfig(_ context.Context, id string) (RawConfigDocument, error) {
	s.profileID = id
	return s.document, nil
}

func (s *fakeConfigService) ValidateProfileConfig(_ context.Context, id string, update RawConfigUpdate) (ConfigValidation, error) {
	s.validatedProfileID = id
	s.validatedUpdate = update
	return ConfigValidation{Valid: true}, nil
}

func (s *fakeConfigService) SaveProfileConfig(_ context.Context, id string, update RawConfigUpdate) (ConfigSaveResult, error) {
	s.savedProfileID = id
	s.savedUpdate = update
	return ConfigSaveResult{Revision: "r2", ReloadRequired: true, Apply: update.Apply}, nil
}

type fakeLifecycleService struct {
	starts   int
	stops    int
	restarts int
}

func (s *fakeLifecycleService) Start(context.Context) error   { s.starts++; return nil }
func (s *fakeLifecycleService) Stop(context.Context) error    { s.stops++; return nil }
func (s *fakeLifecycleService) Restart(context.Context) error { s.restarts++; return nil }

type recordingProfilesService struct {
	draft       ProfileDraft
	activations []ProfileActivationRequest
}

func (s *recordingProfilesService) Profiles(context.Context) ([]Profile, error) { return nil, nil }
func (s *recordingProfilesService) Profile(context.Context, string) (Profile, error) {
	return Profile{}, ErrNotFound
}

type recordingProxySubscriptionService struct {
	draft     ProxySubscriptionDraft
	refreshes int
}

func (service *recordingProxySubscriptionService) item() ProxySubscription {
	return ProxySubscription{ID: "sub-1", Engine: "mihomo", Name: "Remote", ProviderName: "boxctl-sub-1", SourceKind: "remote", Enabled: true, HeaderNames: []string{"X-Hwid"}, UpdateIntervalHours: 24}
}
func (service *recordingProxySubscriptionService) ProxySubscriptions(context.Context) ([]ProxySubscription, error) {
	return []ProxySubscription{service.item()}, nil
}
func (service *recordingProxySubscriptionService) ProxySubscription(context.Context, string) (ProxySubscription, error) {
	return service.item(), nil
}
func (service *recordingProxySubscriptionService) CreateProxySubscription(_ context.Context, draft ProxySubscriptionDraft) (ProxySubscription, error) {
	service.draft = draft
	return service.item(), nil
}
func (service *recordingProxySubscriptionService) UpdateProxySubscription(context.Context, string, ProxySubscriptionPatch) (ProxySubscription, error) {
	return service.item(), nil
}
func (service *recordingProxySubscriptionService) DeleteProxySubscription(context.Context, string) error {
	return nil
}
func (service *recordingProxySubscriptionService) RefreshProxySubscription(context.Context, string) (ProxySubscription, error) {
	service.refreshes++
	return service.item(), nil
}
func (s *recordingProfilesService) CreateProfile(_ context.Context, draft ProfileDraft) (Profile, error) {
	s.draft = draft
	return Profile{ID: "p1", Name: draft.Name, Engine: draft.Engine}, nil
}
func (s *recordingProfilesService) UpdateProfile(context.Context, string, ProfilePatch) (Profile, error) {
	return Profile{}, ErrNotFound
}
func (s *recordingProfilesService) DeleteProfile(context.Context, string) error { return nil }
func (s *recordingProfilesService) ActivateProfile(context.Context, string) (Profile, error) {
	return Profile{}, ErrNotFound
}
func (s *recordingProfilesService) ActivateProfileWithRequest(_ context.Context, id string, request ProfileActivationRequest) (Profile, error) {
	s.activations = append(s.activations, request)
	return Profile{ID: id, Name: "Activated", Engine: "mihomo", Active: true}, nil
}
func (s *recordingProfilesService) RefreshProfile(context.Context, string) (Profile, error) {
	return Profile{}, ErrNotFound
}
func (s *recordingProfilesService) DetachProfileSource(context.Context, string) (Profile, error) {
	return Profile{}, ErrNotFound
}

type fakeRuleListService struct {
	document        RuleListDocument
	lastDraft       RuleListDraft
	lastUpdate      RuleListUpdate
	deletedRevision string
	addedToConfig   string
}

func (s *fakeRuleListService) RuleLists(context.Context) ([]RuleList, error) {
	return []RuleList{s.document.RuleList}, nil
}

func (s *fakeRuleListService) RuleList(_ context.Context, id string) (RuleListDocument, error) {
	if id != s.document.ID {
		return RuleListDocument{}, ErrNotFound
	}
	return s.document, nil
}

func (s *fakeRuleListService) CreateRuleList(_ context.Context, draft RuleListDraft) (RuleListDocument, error) {
	s.lastDraft = draft
	return RuleListDocument{
		RuleList: RuleList{ID: "created", Engine: draft.Engine, Name: draft.Name, Format: draft.Format, Enabled: draft.Enabled, Revision: "c1"},
		Content:  draft.Content,
	}, nil
}

func (s *fakeRuleListService) UpdateRuleList(_ context.Context, id string, update RuleListUpdate) (RuleListDocument, error) {
	s.lastUpdate = update
	if id != s.document.ID {
		return RuleListDocument{}, ErrNotFound
	}
	if update.Revision != s.document.Revision {
		return RuleListDocument{}, ErrConflict
	}
	if update.Name != nil {
		s.document.Name = *update.Name
	}
	if update.Format != nil {
		s.document.Format = *update.Format
	}
	if update.Enabled != nil {
		s.document.Enabled = *update.Enabled
	}
	if update.Content != nil {
		s.document.Content = *update.Content
	}
	s.document.Revision = "r2"
	return s.document, nil
}

func (s *fakeRuleListService) DeleteRuleList(_ context.Context, id, revision string) error {
	if id != s.document.ID {
		return ErrNotFound
	}
	if revision != s.document.Revision {
		return ErrConflict
	}
	s.deletedRevision = revision
	return nil
}

func (s *fakeRuleListService) AddRuleListToConfig(_ context.Context, id string) (RuleListDocument, error) {
	if id != s.document.ID {
		return RuleListDocument{}, ErrNotFound
	}
	s.addedToConfig = id
	s.document.InConfig = true
	return s.document, nil
}

type fakeFakeIPWhitelistService struct {
	document               FakeIPWhitelistDocument
	privateConfig          string
	lastUpdate             FakeIPWhitelistUpdate
	lastRegenerateRevision string
	updates                int
	regenerations          int
	updateErr              error
}

func (s *fakeFakeIPWhitelistService) FakeIPWhitelist(context.Context) (FakeIPWhitelistDocument, error) {
	return s.document, nil
}

func (s *fakeFakeIPWhitelistService) UpdateFakeIPWhitelist(_ context.Context, update FakeIPWhitelistUpdate) (FakeIPWhitelistDocument, error) {
	if s.updateErr != nil {
		return FakeIPWhitelistDocument{}, s.updateErr
	}
	if update.Revision != s.document.Revision {
		return FakeIPWhitelistDocument{}, ErrConflict
	}
	s.updates++
	s.lastUpdate = update
	s.document.ManualContent = update.ManualContent
	s.document.ManualCount = 2
	s.document.EffectiveCount = s.document.GeneratedCount + s.document.ManualCount + len(s.document.FakeIPRanges)
	s.document.Revision = "r2"
	s.document.Applied = false
	s.document.RestartRequired = true
	return s.document, nil
}

func (s *fakeFakeIPWhitelistService) RegenerateFakeIPWhitelist(_ context.Context, revision string) (FakeIPWhitelistDocument, error) {
	if revision != s.document.Revision {
		return FakeIPWhitelistDocument{}, ErrConflict
	}
	s.regenerations++
	s.lastRegenerateRevision = revision
	s.document.GeneratedCIDRs = []string{"91.108.4.0/22", "149.154.160.0/20"}
	s.document.GeneratedCount = len(s.document.GeneratedCIDRs)
	s.document.Revision = "r3"
	s.document.Applied = true
	s.document.RestartRequired = false
	return s.document, nil
}

type fakeBackupService struct {
	archive BackupArchive
	imports []BackupImport
	exports []BackupExportOptions
}

type blockingBackupService struct {
	started chan struct{}
	release chan struct{}
}

func (service *blockingBackupService) ExportBackup(context.Context, BackupExportOptions) (BackupArchive, error) {
	return BackupArchive{}, nil
}

func (service *blockingBackupService) ImportBackup(ctx context.Context, _ BackupImport) (BackupImportResult, error) {
	close(service.started)
	select {
	case <-service.release:
		return BackupImportResult{Imported: true}, nil
	case <-ctx.Done():
		return BackupImportResult{}, ctx.Err()
	}
}

func (s *fakeBackupService) ExportBackup(_ context.Context, options BackupExportOptions) (BackupArchive, error) {
	s.exports = append(s.exports, options)
	return s.archive, nil
}

func (s *fakeBackupService) ImportBackup(_ context.Context, backup BackupImport) (BackupImportResult, error) {
	copyOfData := append([]byte(nil), backup.Data...)
	s.imports = append(s.imports, BackupImport{Filename: backup.Filename, Data: copyOfData})
	return BackupImportResult{Imported: true, RestartRequired: true}, nil
}
