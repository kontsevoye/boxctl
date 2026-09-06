package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/update"
	"github.com/kontsevoye/boxctl/internal/web"
)

func dashboardSettingsFixture(t *testing.T) (*clashExternalDashboard, *SettingsService) {
	t.Helper()
	manager := dashboardTestManager(t, &dashboardSourceStub{}, http.DefaultClient)
	settings, err := NewSettingsService(manager.Layout.Root)
	if err != nil {
		t.Fatal(err)
	}
	scope := &clashExternalDashboard{manager: manager, settings: settings.State, selected: func() string { return state.EngineMihomo }}
	settings.ExternalDashboardChanged = scope.cancelRequests
	settings.OnChanged = func(_ context.Context, restart bool) error {
		if restart {
			t.Error("dashboard setting requested a core restart")
		}
		return nil
	}
	return scope, settings
}

func TestExternalDashboardSettingsControlFilesAndControllerWithoutRestart(t *testing.T) {
	scope, settings := dashboardSettingsFixture(t)
	if err := os.MkdirAll(scope.manager.Layout.DashboardDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scope.manager.Layout.DashboardDir, "index.html"), []byte("dashboard"), 0o600); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("controller"))
	}))
	defer upstream.Close()
	scope.manager.ControllerTarget = func() (engine.ControllerEndpoint, error) {
		return engine.ControllerEndpoint{BaseURL: upstream.URL}, nil
	}

	for _, enabled := range []bool{false, true, false, true} {
		result, err := settings.UpdateSettings(context.Background(), web.SettingsPatch{ExternalDashboardEnabled: &enabled})
		if err != nil || result.ExternalDashboardEnabled != enabled {
			t.Fatalf("toggle %t: %+v, %v", enabled, result, err)
		}
		// A new service reads the persisted choice without a startup flag.
		reloaded, err := NewSettingsService(scope.manager.Layout.Root)
		if err != nil {
			t.Fatal(err)
		}
		persisted, err := reloaded.Settings(context.Background())
		if err != nil || persisted.ExternalDashboardEnabled != enabled {
			t.Fatalf("persisted setting: %+v, %v", persisted, err)
		}
		status, err := scope.ExternalDashboardStatus(context.Background(), false)
		if err != nil || status.Enabled != enabled || !status.Installed {
			t.Fatalf("dashboard status: %+v, %v", status, err)
		}
		_, err = scope.OpenExternalDashboard(context.Background())
		if enabled && err != nil {
			t.Fatal(err)
		}
		if !enabled {
			var public *web.PublicError
			if !errors.As(err, &public) || public.Code != "dashboard_disabled" {
				t.Fatalf("disabled launch: %v", err)
			}
		}
		for _, path := range []string{externalDashboardPublicPath, externalDashboardControllerPath + "/version"} {
			response := httptest.NewRecorder()
			scope.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			want := http.StatusNotFound
			if enabled {
				want = http.StatusOK
			}
			if response.Code != want {
				t.Fatalf("enabled=%t, path=%s: %d %s", enabled, path, response.Code, response.Body.String())
			}
		}
	}
}

func TestExternalDashboardCanInstallAndUpdateWhileDisabled(t *testing.T) {
	scope, _ := dashboardSettingsFixture(t)
	archive := dashboardArchive(t, map[string]string{"dist/index.html": "zashboard ./assets/"})
	source := &dashboardSourceStub{}
	scope.manager.Source = source
	scope.manager.Client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return dashboardResponse(request, archive), nil
	})}
	for index, version := range []string{"v3.24.0", "v3.25.0"} {
		source.release = update.Release{Tag: version, Assets: []update.Asset{{
			Name: externalDashboardAsset, Size: int64(len(archive)), Digest: dashboardDigest(archive),
			URL: "https://github.com/Zephyruso/zashboard/releases/download/" + version + "/dist-no-fonts.zip",
		}}}
		status, err := scope.ExternalDashboardStatus(context.Background(), true)
		if err != nil || status.Enabled || status.LatestVersion != version || !status.UpdateAvailable {
			t.Fatalf("disabled discovery: %+v, %v", status, err)
		}
		install := scope.InstallExternalDashboard
		if index > 0 {
			install = scope.UpdateExternalDashboard
		}
		result, err := install(context.Background())
		if err != nil || result.Enabled || !result.Changed || result.CurrentVersion != version {
			t.Fatalf("disabled installation: %+v, %v", result, err)
		}
	}
}

func TestExternalDashboardRecoveryFailureLeavesSettingsUsable(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{".boxctl-dashboard-previous-one", ".boxctl-dashboard-previous-two"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	manager, err := NewExternalDashboardManager(root, nil, nil)
	if err != nil {
		t.Fatalf("optional dashboard recovery blocked manager construction: %v", err)
	}
	if _, err := manager.ExternalDashboardStatus(context.Background(), false); err == nil {
		t.Fatal("dashboard recovery error was hidden")
	}
	settings, err := NewSettingsService(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{true, false} {
		if _, err := settings.UpdateSettings(context.Background(), web.SettingsPatch{ExternalDashboardEnabled: &enabled}); err != nil {
			t.Fatalf("dashboard files prevented changing its setting: %v", err)
		}
	}
}

func TestExternalDashboardDisablingClosesExistingWebSocket(t *testing.T) {
	scope, settings := dashboardSettingsFixture(t)
	enabled := true
	if _, err := settings.UpdateSettings(context.Background(), web.SettingsPatch{ExternalDashboardEnabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer func() { _ = connection.CloseNow() }()
		_, _, _ = connection.Read(r.Context())
	}))
	defer upstream.Close()
	scope.manager.ControllerTarget = func() (engine.ControllerEndpoint, error) {
		return engine.ControllerEndpoint{BaseURL: upstream.URL}, nil
	}
	proxy := httptest.NewServer(scope)
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(proxy.URL, "http")+externalDashboardControllerPath+"/traffic", nil) //nolint:bodyclose // websocket owns the handshake response.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.CloseNow() }()
	enabled = false
	if _, err := settings.UpdateSettings(ctx, web.SettingsPatch{ExternalDashboardEnabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := connection.Read(ctx); err == nil || ctx.Err() != nil {
		t.Fatalf("dashboard stream was not revoked immediately: %v (context %v)", err, ctx.Err())
	}
}

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
