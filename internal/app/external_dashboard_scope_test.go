package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

func TestExternalDashboardSupportsBothClashCompatibleEngines(t *testing.T) {
	for _, engineName := range []string{state.EngineMihomo, state.EngineSingBox} {
		scope := clashExternalDashboard{
			manager:  &ExternalDashboardManager{},
			selected: func() string { return engineName },
		}
		if err := scope.available(); err != nil {
			t.Fatalf("engine %q availability = %v", engineName, err)
		}
	}
}

func TestExternalDashboardIsUnavailableOutsideClashCompatibleEngines(t *testing.T) {
	scope := clashExternalDashboard{
		manager:  &ExternalDashboardManager{},
		selected: func() string { return "unknown" },
	}
	_, err := scope.ExternalDashboardStatus(context.Background(), false)
	var public *web.PublicError
	if !errors.As(err, &public) || public.Code != "dashboard_engine_unsupported" {
		t.Fatalf("status error = %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, externalDashboardPublicPath, nil)
	response := httptest.NewRecorder()
	scope.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("dashboard HTTP status = %d, want 404", response.Code)
	}
}

type controllerBackendFake struct {
	*coreBackendFake
	endpoint engine.ControllerEndpoint
}

func (fake *controllerBackendFake) ActiveControllerEndpoint() (engine.ControllerEndpoint, error) {
	return fake.endpoint, nil
}

func TestEngineHostExternalDashboardFollowsRunningController(t *testing.T) {
	mihomo := &controllerBackendFake{coreBackendFake: newCoreBackendFake(), endpoint: engine.ControllerEndpoint{BaseURL: "http://127.0.0.1:9090", Secret: "mihomo"}}
	singBox := &controllerBackendFake{coreBackendFake: newCoreBackendFake(), endpoint: engine.ControllerEndpoint{BaseURL: "http://127.0.0.1:9091", Secret: "sing-box"}}
	host, err := NewEngineHost(map[string]CoreBackend{state.EngineMihomo: mihomo, state.EngineSingBox: singBox}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	if _, err := host.ActiveControllerEndpoint(); !errors.Is(err, engine.ErrNotRunning) {
		t.Fatalf("stopped controller error = %v", err)
	}
	if err := host.SetAdopted(state.EngineSingBox); err != nil {
		t.Fatal(err)
	}
	endpoint, err := host.ActiveControllerEndpoint()
	if err != nil || endpoint.Secret != "sing-box" || endpoint.BaseURL != "http://127.0.0.1:9091" {
		t.Fatalf("active controller = %#v, %v", endpoint, err)
	}
}
