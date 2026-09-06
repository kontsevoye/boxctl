package app

import (
	"context"
	"errors"
	"net/http"

	"github.com/kontsevoye/boxctl/internal/web"
)

// FirewallService reconciles owned dataplane state even when the lifecycle
// already says stopped. A normal Stop can skip this work after a clean stop.
type FirewallService struct{ Lifecycle *Lifecycle }

func (service FirewallService) CleanupFirewall(ctx context.Context) error {
	lifecycle := service.Lifecycle
	if !lifecycle.opMu.TryLock() {
		return &web.PublicError{Status: http.StatusConflict, Code: "lifecycle_busy", Message: "Wait for the current core operation to finish before cleaning the firewall"}
	}
	defer lifecycle.opMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	lifecycle.defaults()
	// Once accepted, recovery must finish even if the browser disconnects.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*lifecycle.CleanupTimeout)
	defer cancel()
	err := lifecycle.stopWithCleanupLocked(cleanup, true)
	if lifecycle.RestartGuard != nil {
		guardContext, cancelGuard := lifecycle.cleanupContext(context.Background())
		defer cancelGuard()
		err = errors.Join(err, lifecycle.RestartGuard.Remove(guardContext))
	}
	if err != nil {
		lifecycle.Logger.Error("firewall recovery could not complete", "error", err)
		return errors.Join(err, &web.PublicError{Status: http.StatusInternalServerError, Code: "firewall_cleanup_failed", Message: "Firewall cleanup could not be completed; check system logs and retry"})
	}
	lifecycle.Logger.Info("firewall recovery completed; core stopped and owned routing state removed")
	return nil
}

var _ web.FirewallService = FirewallService{}
