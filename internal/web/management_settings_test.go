package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type fakeManagementSettings struct {
	settings ManagementSettings
	updates  []ManagementSettingsUpdate
	applies  []string
}

func (service *fakeManagementSettings) ManagementSettings(context.Context) (ManagementSettings, error) {
	return service.settings, nil
}

func (service *fakeManagementSettings) UpdateManagementSettings(_ context.Context, request ManagementSettingsUpdate) (ManagementSettings, error) {
	service.updates = append(service.updates, request)
	service.settings.ManagementConfig = request.ManagementConfig
	return service.settings, nil
}

func (service *fakeManagementSettings) ApplyManagementSettings(_ context.Context, revision string) error {
	service.applies = append(service.applies, revision)
	return nil
}

func TestManagementSettingsAPIRequiresAuthenticationCSRFAndTypedRequests(t *testing.T) {
	service := &fakeManagementSettings{settings: ManagementSettings{
		ManagementConfig: ManagementConfig{PublicOrigin: "https://boxctl.lan"}, Supported: true, Revision: "original",
	}}
	handler := newTestHandler(t, Services{Credentials: fakeCredentials{}, SessionSecrets: &memorySecretStore{}, ManagementSettings: service})
	for _, endpoint := range []string{"/api/v1/settings/management", "/api/v1/settings/management/apply"} {
		response := perform(handler, http.MethodGet, endpoint, "", nil, "")
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s = %d", endpoint, response.Code)
		}
	}
	cookie, csrf := login(t, handler)
	read := perform(handler, http.MethodGet, "/api/v1/settings/management", "", cookie, "")
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"publicOrigin":"https://boxctl.lan"`) {
		t.Fatalf("read = %d %s", read.Code, read.Body.String())
	}
	for _, request := range []struct{ method, endpoint, body string }{
		{http.MethodPut, "/api/v1/settings/management", `{"publicOrigin":"https://next.lan","revision":"original"}`},
		{http.MethodPost, "/api/v1/settings/management/apply", `{"revision":"original"}`},
	} {
		response := perform(handler, request.method, request.endpoint, request.body, cookie, "")
		if response.Code != http.StatusForbidden || len(service.updates)+len(service.applies) != 0 {
			t.Fatalf("missing CSRF = %d %s", response.Code, response.Body.String())
		}
		invalid := strings.TrimSuffix(request.body, "}") + `,"unexpected":"field"}`
		response = perform(handler, request.method, request.endpoint, invalid, cookie, csrf)
		if response.Code != http.StatusBadRequest || len(service.updates)+len(service.applies) != 0 {
			t.Fatalf("unknown field = %d %s", response.Code, response.Body.String())
		}
	}
	want := ManagementSettingsUpdate{ManagementConfig: ManagementConfig{
		PublicOrigin: "https://next.lan", AllowedHosts: "next.lan", TLSCertificate: "/etc/ssl/cert.pem", TLSKey: "/etc/ssl/key.pem",
	}, Revision: "original"}
	body, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	saved := perform(handler, http.MethodPut, "/api/v1/settings/management", string(body), cookie, csrf)
	if saved.Code != http.StatusOK || len(service.updates) != 1 || service.updates[0] != want {
		t.Fatalf("save = %d %s updates=%+v", saved.Code, saved.Body.String(), service.updates)
	}
	applied := perform(handler, http.MethodPost, "/api/v1/settings/management/apply", `{"revision":"original"}`, cookie, csrf)
	if applied.Code != http.StatusAccepted || len(service.applies) != 1 || service.applies[0] != "original" {
		t.Fatalf("apply = %d %s applies=%v", applied.Code, applied.Body.String(), service.applies)
	}
}

func TestManagementAccessAllowsEmptyDefaultsAndRejectsInvalidOriginsAndHosts(t *testing.T) {
	for _, config := range []ManagementConfig{{}, {PublicOrigin: "https://boxctl.lan"}, {AllowedHosts: "router.lan, , router.home"}} {
		if err := ValidateManagementAccess(config); err != nil {
			t.Fatalf("valid config %+v: %v", config, err)
		}
	}
	for _, config := range []ManagementConfig{{PublicOrigin: "https://boxctl.lan/path"}, {PublicOrigin: "https://boxctl.lan:0"}, {AllowedHosts: "https://boxctl.lan"}, {AllowedHosts: "bad host"}} {
		if err := ValidateManagementAccess(config); err == nil {
			t.Fatalf("accepted invalid config %+v", config)
		}
	}
}
