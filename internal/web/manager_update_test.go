package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

type fakeManagerUpdates struct {
	starts, checks int
	approved       bool
}

func (updates *fakeManagerUpdates) UpdateStatus(_ context.Context, check bool) (ManagerUpdateView, error) {
	if check {
		updates.checks++
	}
	return ManagerUpdateView{ManagerUpdateStatus: ManagerUpdateStatus{CurrentVersion: "2026.09.5", LatestVersion: "2026.09.6", UpdateAvailable: true}}, nil
}

func (updates *fakeManagerUpdates) StartUpdate(_ context.Context, approved bool) (ManagerUpdateJob, error) {
	updates.starts++
	updates.approved = approved
	return ManagerUpdateJob{ID: "job-1", State: "queued"}, nil
}

func TestManagerUpdateRequiresAuthenticationCSRFAndStrictParameters(t *testing.T) {
	updates := &fakeManagerUpdates{}
	handler := newTestHandler(t, Services{Credentials: fakeCredentials{}, SessionSecrets: &memorySecretStore{}, ManagerUpdates: updates})
	cookie, csrf := login(t, handler)
	for _, test := range []struct {
		method, path, body string
		cookie             *http.Cookie
		csrf               string
		want               int
	}{
		{http.MethodGet, "/api/v1/manager/update", "", nil, "", http.StatusUnauthorized},
		{http.MethodPost, "/api/v1/manager/update", "{}", nil, "", http.StatusUnauthorized},
		{http.MethodPost, "/api/v1/manager/update", "{}", cookie, "", http.StatusForbidden},
		{http.MethodGet, "/api/v1/manager/update?checkUpdates=invalid", "", cookie, "", http.StatusBadRequest},
		{http.MethodDelete, "/api/v1/manager/update", "{}", cookie, csrf, http.StatusMethodNotAllowed},
		{http.MethodPost, "/api/v1/manager/update", `{"file":"/tmp/custom"}`, cookie, csrf, http.StatusBadRequest},
		{http.MethodPost, "/api/v1/manager/update", `{"repo":"attacker/custom"}`, cookie, csrf, http.StatusBadRequest},
		{http.MethodPost, "/api/v1/manager/update", `{"allowFullRestart":"yes"}`, cookie, csrf, http.StatusBadRequest},
	} {
		response := perform(handler, test.method, test.path, test.body, test.cookie, test.csrf)
		if response.Code != test.want || updates.starts != 0 {
			t.Fatalf("%s %s = %d, starts=%d", test.method, test.path, response.Code, updates.starts)
		}
	}
	response := perform(handler, http.MethodGet, "/api/v1/manager/update?checkUpdates=true", "", cookie, "")
	if response.Code != http.StatusOK || updates.checks != 1 || !strings.Contains(response.Body.String(), `"currentVersion":"2026.09.5"`) {
		t.Fatalf("check = %d %s", response.Code, response.Body.String())
	}
	for _, approved := range []bool{false, true} {
		body := `{}`
		if approved {
			body = `{"allowFullRestart":true}`
		}
		response = perform(handler, http.MethodPost, "/api/v1/manager/update", body, cookie, csrf)
		if response.Code != http.StatusAccepted || updates.approved != approved || !strings.Contains(response.Body.String(), `"state":"queued"`) {
			t.Fatalf("start = %d %s", response.Code, response.Body.String())
		}
	}
}

func TestManagerUpdateUnsupportedInstallation(t *testing.T) {
	handler := newTestHandler(t, Services{Credentials: fakeCredentials{}, SessionSecrets: &memorySecretStore{}})
	cookie, _ := login(t, handler)
	response := perform(handler, http.MethodGet, "/api/v1/manager/update", "", cookie, "")
	if response.Code != http.StatusNotImplemented {
		t.Fatalf("unsupported update = %d", response.Code)
	}
}
