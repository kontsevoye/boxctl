package app

import (
	"context"
	"net/http"

	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

// mihomoExternalDashboard keeps Zashboard and its controller proxy strictly
// scoped to the engine it understands, even when an authenticated caller uses
// the API directly while sing-box is selected.
type mihomoExternalDashboard struct {
	manager  *ExternalDashboardManager
	selected func() string
}

func (scope mihomoExternalDashboard) available() error {
	if scope.manager == nil {
		return web.ErrUnavailable
	}
	if scope.selected != nil && scope.selected() != state.EngineMihomo {
		return &web.PublicError{
			Status: http.StatusConflict, Code: "dashboard_engine_unsupported",
			Message: "Zashboard is available only when Mihomo is selected",
		}
	}
	return nil
}

func (scope mihomoExternalDashboard) ExternalDashboardStatus(ctx context.Context, check bool) (web.ExternalDashboardStatus, error) {
	if err := scope.available(); err != nil {
		return web.ExternalDashboardStatus{}, err
	}
	return scope.manager.ExternalDashboardStatus(ctx, check)
}

func (scope mihomoExternalDashboard) InstallExternalDashboard(ctx context.Context) (web.ExternalDashboardResult, error) {
	if err := scope.available(); err != nil {
		return web.ExternalDashboardResult{}, err
	}
	return scope.manager.InstallExternalDashboard(ctx)
}

func (scope mihomoExternalDashboard) UpdateExternalDashboard(ctx context.Context) (web.ExternalDashboardResult, error) {
	if err := scope.available(); err != nil {
		return web.ExternalDashboardResult{}, err
	}
	return scope.manager.UpdateExternalDashboard(ctx)
}

func (scope mihomoExternalDashboard) OpenExternalDashboard(ctx context.Context) (web.ExternalDashboardOpen, error) {
	if err := scope.available(); err != nil {
		return web.ExternalDashboardOpen{}, err
	}
	return scope.manager.OpenExternalDashboard(ctx)
}

func (scope mihomoExternalDashboard) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if scope.available() != nil {
		http.NotFound(response, request)
		return
	}
	scope.manager.ServeHTTP(response, request)
}

var _ web.ExternalDashboardService = mihomoExternalDashboard{}
var _ http.Handler = mihomoExternalDashboard{}
