package app

import (
	"context"
	"net/http"
	"sync"

	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

// clashExternalDashboard keeps Zashboard and its controller proxy strictly
// scoped to engines with an explicitly supported Clash API. The manager target
// itself follows the live engine, so credentials can never be taken from a
// merely selected but stopped profile.
type clashExternalDashboard struct {
	manager  *ExternalDashboardManager
	selected func() string
	settings state.Store
	mu       sync.Mutex
	requests map[*http.Request]context.CancelFunc
}

func (scope *clashExternalDashboard) available() error {
	if scope.manager == nil {
		return web.ErrUnavailable
	}
	if scope.selected != nil && !supportsClashExternalDashboard(scope.selected()) {
		return &web.PublicError{
			Status: http.StatusConflict, Code: "dashboard_engine_unsupported",
			Message: "Zashboard is unavailable for the selected engine",
		}
	}
	return nil
}

func supportsClashExternalDashboard(engineName string) bool {
	return engineName == state.EngineMihomo || engineName == state.EngineSingBox
}

func (scope *clashExternalDashboard) ExternalDashboardStatus(ctx context.Context, check bool) (web.ExternalDashboardStatus, error) {
	if err := scope.available(); err != nil {
		return web.ExternalDashboardStatus{}, err
	}
	enabled, err := scope.enabled()
	if err != nil {
		return web.ExternalDashboardStatus{}, err
	}
	status, err := scope.manager.ExternalDashboardStatus(ctx, check)
	status.Enabled = enabled
	return status, err
}

func (scope *clashExternalDashboard) InstallExternalDashboard(ctx context.Context) (web.ExternalDashboardResult, error) {
	if err := scope.available(); err != nil {
		return web.ExternalDashboardResult{}, err
	}
	result, err := scope.manager.InstallExternalDashboard(ctx)
	return scope.installResult(result, err)
}

func (scope *clashExternalDashboard) UpdateExternalDashboard(ctx context.Context) (web.ExternalDashboardResult, error) {
	if err := scope.available(); err != nil {
		return web.ExternalDashboardResult{}, err
	}
	result, err := scope.manager.UpdateExternalDashboard(ctx)
	return scope.installResult(result, err)
}

func (scope *clashExternalDashboard) installResult(result web.ExternalDashboardResult, err error) (web.ExternalDashboardResult, error) {
	if err != nil {
		return result, err
	}
	result.Enabled, err = scope.enabled()
	return result, err
}

func (scope *clashExternalDashboard) enabled() (bool, error) {
	settings, err := LoadRuntimeSettings(scope.settings)
	return settings.ExternalDashboardEnabled, err
}

func (scope *clashExternalDashboard) requireEnabled() error {
	enabled, err := scope.enabled()
	if err != nil {
		return err
	}
	if !enabled {
		return &web.PublicError{Status: http.StatusConflict, Code: "dashboard_disabled", Message: "Enable the external dashboard in Settings first"}
	}
	return nil
}

func (scope *clashExternalDashboard) OpenExternalDashboard(ctx context.Context) (web.ExternalDashboardOpen, error) {
	if err := scope.available(); err != nil {
		return web.ExternalDashboardOpen{}, err
	}
	if err := scope.requireEnabled(); err != nil {
		return web.ExternalDashboardOpen{}, err
	}
	return scope.manager.OpenExternalDashboard(ctx)
}

// Settings changes also revoke already-open controller streams and WebSockets.
func (scope *clashExternalDashboard) cancelRequests() {
	scope.mu.Lock()
	defer scope.mu.Unlock()
	for _, cancel := range scope.requests {
		cancel()
	}
}

func (scope *clashExternalDashboard) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if scope.available() != nil {
		http.NotFound(response, request)
		return
	}
	scope.mu.Lock()
	if scope.requireEnabled() != nil {
		scope.mu.Unlock()
		http.NotFound(response, request)
		return
	}
	ctx, cancel := context.WithCancel(request.Context())
	if scope.requests == nil {
		scope.requests = make(map[*http.Request]context.CancelFunc)
	}
	scope.requests[request] = cancel
	scope.mu.Unlock()
	defer func() {
		cancel()
		scope.mu.Lock()
		delete(scope.requests, request)
		scope.mu.Unlock()
	}()
	scope.manager.ServeHTTP(response, request.WithContext(ctx))
}

var _ web.ExternalDashboardService = (*clashExternalDashboard)(nil)
var _ http.Handler = (*clashExternalDashboard)(nil)
