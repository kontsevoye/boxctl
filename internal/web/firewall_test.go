package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

type fakeFirewallService struct {
	calls int
	err   error
}

func (service *fakeFirewallService) CleanupFirewall(context.Context) error {
	service.calls++
	return service.err
}

func TestFirewallCleanupRequiresAuthenticationCSRFAndExplicitSupport(t *testing.T) {
	for _, supported := range []bool{false, true} {
		firewall := &fakeFirewallService{}
		services := Services{Credentials: fakeCredentials{}, SessionSecrets: &memorySecretStore{}, Core: &fakeCoreService{}}
		if supported {
			services.Firewall = firewall
		}
		handler := newTestHandler(t, services)
		cookie, csrf := login(t, handler)
		capabilities := perform(handler, http.MethodGet, "/api/v1/core/capabilities", "", cookie, "")
		if strings.Contains(capabilities.Body.String(), `"cleanupFirewall":true`) != supported {
			t.Fatalf("capabilities = %s", capabilities.Body.String())
		}
		for _, check := range []struct {
			method string
			cookie *http.Cookie
			csrf   string
			want   int
		}{
			{http.MethodPost, nil, "", http.StatusUnauthorized},
			{http.MethodPost, cookie, "", http.StatusForbidden},
			{http.MethodGet, cookie, "", http.StatusMethodNotAllowed},
		} {
			response := perform(handler, check.method, "/api/v1/firewall/cleanup", "", check.cookie, check.csrf)
			if response.Code != check.want || firewall.calls != 0 {
				t.Fatalf("unaccepted cleanup = %d, calls=%d", response.Code, firewall.calls)
			}
		}
		response := perform(handler, http.MethodPost, "/api/v1/firewall/cleanup", "{}", cookie, csrf)
		if !supported {
			if response.Code != http.StatusNotImplemented {
				t.Fatalf("unsupported cleanup = %d", response.Code)
			}
			continue
		}
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"cleaned":true`) || firewall.calls != 1 {
			t.Fatalf("cleanup = %d %s calls=%d", response.Code, response.Body.String(), firewall.calls)
		}
		firewall.err = &PublicError{Status: http.StatusConflict, Code: "lifecycle_busy", Message: "Operation in progress"}
		response = perform(handler, http.MethodPost, "/api/v1/firewall/cleanup", "{}", cookie, csrf)
		if response.Code != http.StatusConflict {
			t.Fatalf("busy cleanup = %d", response.Code)
		}
	}
}
