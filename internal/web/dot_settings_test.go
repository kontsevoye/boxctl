package web

import (
	"net/http"
	"strings"
	"testing"
)

func TestDoTSettingsAPIAuthAndTypedPatch(t *testing.T) {
	service := &fakeSettingsService{settings: Settings{BlockDoT: true}}
	handler := newTestHandler(t, Services{Credentials: fakeCredentials{}, SessionSecrets: &memorySecretStore{}, Settings: service})
	if response := perform(handler, http.MethodPut, "/api/v1/settings", `{"blockDoT":true}`, nil, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated save=%d", response.Code)
	}
	cookie, csrf := login(t, handler)
	if response := perform(handler, http.MethodGet, "/api/v1/settings", "", cookie, ""); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"blockDoT":true`) {
		t.Fatalf("authenticated read=%d %s", response.Code, response.Body.String())
	}
	if response := perform(handler, http.MethodPut, "/api/v1/settings", `{"blockDoT":true}`, cookie, ""); response.Code != http.StatusForbidden {
		t.Fatalf("save without CSRF=%d", response.Code)
	}
	if response := perform(handler, http.MethodPut, "/api/v1/settings", `{"blockDoT":"true"}`, cookie, csrf); response.Code != http.StatusBadRequest {
		t.Fatalf("string bool save=%d", response.Code)
	}
	for _, enabled := range []bool{true, false} {
		body := `{"blockDoT":false}`
		if enabled {
			body = `{"blockDoT":true}`
		}
		response := perform(handler, http.MethodPut, "/api/v1/settings", body, cookie, csrf)
		if response.Code != http.StatusOK || service.patch.BlockDoT == nil || *service.patch.BlockDoT != enabled {
			t.Fatalf("typed patch lost bool: code=%d patch=%+v", response.Code, service.patch)
		}
		if !strings.Contains(response.Body.String(), `"blockDoT":true`) {
			t.Fatalf("saved response missing DoT: %s", response.Body.String())
		}
	}
	service.settings.BlockDoT = false
	if response := perform(handler, http.MethodGet, "/api/v1/settings", "", cookie, ""); !strings.Contains(response.Body.String(), `"blockDoT":false`) {
		t.Fatalf("read omitted default-off DoT state: %s", response.Body.String())
	}
}
