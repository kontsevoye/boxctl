package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

func TestExternalDashboardIsUnavailableOutsideMihomo(t *testing.T) {
	scope := mihomoExternalDashboard{
		manager:  &ExternalDashboardManager{},
		selected: func() string { return state.EngineSingBox },
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
