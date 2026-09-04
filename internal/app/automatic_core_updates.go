package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

const automaticCoreUpdateInterval = 6 * time.Hour

type coreUpdateInstaller interface {
	InstallCoreUpdate(context.Context) (web.CoreUpdateResult, error)
}

type selectedEngineUpdateInstaller interface {
	InstallSelectedEngineUpdate(context.Context) (web.CoreUpdateResult, error)
}

// AutomaticCoreUpdates implements AUTO_UPDATE entirely in the backend. A
// successful update is visible in the system-log stream; the browser never
// runs a status polling timer.
type AutomaticCoreUpdates struct {
	State    state.Store
	Updates  coreUpdateInstaller
	Logger   *slog.Logger
	Interval time.Duration
	wake     chan struct{}
}

func NewAutomaticCoreUpdates(store state.Store, updates coreUpdateInstaller, logger *slog.Logger) *AutomaticCoreUpdates {
	return &AutomaticCoreUpdates{
		State: store, Updates: updates, Logger: logger,
		Interval: automaticCoreUpdateInterval, wake: make(chan struct{}, 1),
	}
}

func (service *AutomaticCoreUpdates) Reload() {
	if service == nil {
		return
	}
	select {
	case service.wake <- struct{}{}:
	default:
	}
}

func (service *AutomaticCoreUpdates) Run(ctx context.Context) {
	if service == nil || service.Updates == nil {
		return
	}
	for {
		if err := service.runOnce(ctx); err != nil && ctx.Err() == nil && service.Logger != nil {
			service.Logger.Warn("automatic core update failed", "error", err)
		}
		interval := service.Interval
		if interval <= 0 {
			interval = automaticCoreUpdateInterval
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			stopAutomaticUpdateTimer(timer)
			return
		case <-service.wake:
			stopAutomaticUpdateTimer(timer)
		case <-timer.C:
		}
	}
}

// Since Go 1.23 timer channels are synchronous. A false Stop result no longer
// guarantees that a value is available to drain, so an unconditional receive
// can deadlock a settings wake or daemon shutdown racing the timer deadline.
func stopAutomaticUpdateTimer(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func (service *AutomaticCoreUpdates) runOnce(ctx context.Context) error {
	settings, err := LoadRuntimeSettings(service.State)
	if err != nil {
		return err
	}
	if !settingBoolUnchecked(settings.Raw, "AUTO_UPDATE", false) {
		return nil
	}
	var result web.CoreUpdateResult
	var updateErr error
	if selected, ok := service.Updates.(selectedEngineUpdateInstaller); ok {
		result, updateErr = selected.InstallSelectedEngineUpdate(ctx)
	} else {
		result, updateErr = service.Updates.InstallCoreUpdate(ctx)
	}
	if updateErr != nil {
		var public *web.PublicError
		if errors.As(updateErr, &public) && public.Code == "custom_engine_update_disabled" {
			return nil
		}
		return updateErr
	}
	if service.Logger != nil && result.CurrentVersion != "" && result.CurrentVersion != result.PreviousVersion {
		service.Logger.Info("core updated automatically", "engine", result.Engine, "previous", result.PreviousVersion, "current", result.CurrentVersion)
	}
	return nil
}
