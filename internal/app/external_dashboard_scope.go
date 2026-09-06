package app

import (
	"context"
	"net/http"

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
}

func (scope clashExternalDashboard) available() error {
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

func (scope clashExternalDashboard) ExternalDashboardStatus(ctx context.Context, check bool) (web.ExternalDashboardStatus, error) {
	if err := scope.available(); err != nil {
		return web.ExternalDashboardStatus{}, err
	}
	return scope.manager.ExternalDashboardStatus(ctx, check)
}

func (scope clashExternalDashboard) InstallExternalDashboard(ctx context.Context) (web.ExternalDashboardResult, error) {
	if err := scope.available(); err != nil {
		return web.ExternalDashboardResult{}, err
	}
	return scope.manager.InstallExternalDashboard(ctx)
}

func (scope clashExternalDashboard) UpdateExternalDashboard(ctx context.Context) (web.ExternalDashboardResult, error) {
	if err := scope.available(); err != nil {
		return web.ExternalDashboardResult{}, err
	}
	return scope.manager.UpdateExternalDashboard(ctx)
}

func (scope clashExternalDashboard) OpenExternalDashboard(ctx context.Context) (web.ExternalDashboardOpen, error) {
	if err := scope.available(); err != nil {
		return web.ExternalDashboardOpen{}, err
	}
	return scope.manager.OpenExternalDashboard(ctx)
}

func (scope clashExternalDashboard) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if scope.available() != nil {
		http.NotFound(response, request)
		return
	}
	scope.manager.ServeHTTP(response, request)
}

var _ web.ExternalDashboardService = clashExternalDashboard{}
var _ http.Handler = clashExternalDashboard{}
