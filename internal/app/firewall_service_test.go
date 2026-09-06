package app

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/web"
)

func TestFirewallRecoveryForcesOwnedCleanupInEveryState(t *testing.T) {
	for _, state := range []LifecycleState{"", LifecycleStopped, LifecycleFailed, LifecycleRunning, LifecycleCleanupFailed} {
		t.Run(string(state), func(t *testing.T) {
			core := &lifecycleFake{health: engine.HealthStatus{Running: state == LifecycleRunning}}
			guard := &restartGuardFake{core: core} // No in-memory record of the stale table.
			lifecycle := &Lifecycle{Preparer: core, Core: core, Activation: core, RestartGuard: guard, snap: LifecycleSnapshot{State: state}}
			service := FirewallService{Lifecycle: lifecycle}
			for range 2 {
				core.events = nil
				if err := service.CleanupFirewall(context.Background()); err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(core.events, []string{"gateway-deactivate", "core-stop", "guard-remove"}) {
					t.Fatalf("cleanup order = %v", core.events)
				}
				if lifecycle.Snapshot().State != LifecycleStopped {
					t.Fatalf("cleanup state = %s", lifecycle.Snapshot().State)
				}
			}
		})
	}
}

func TestFirewallRecoveryKeepsCoreAliveWhenCaptureCleanupFails(t *testing.T) {
	lifecycle, core, guard := guardedLifecycle(t)
	core.deactivateErr = errors.New("owned capture is busy")
	guard.status.Active = true
	service := FirewallService{Lifecycle: lifecycle}
	if err := service.CleanupFirewall(context.Background()); err == nil {
		t.Fatal("failed cleanup succeeded")
	}
	if !slices.Equal(core.events, []string{"gateway-deactivate", "guard-remove"}) || !core.health.Running || guard.status.Active || lifecycle.Snapshot().State != LifecycleCleanupFailed {
		t.Fatalf("unsafe failed recovery: events=%v snapshot=%+v", core.events, lifecycle.Snapshot())
	}
	core.deactivateErr = nil
	if err := service.CleanupFirewall(context.Background()); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

func TestFirewallRecoveryRefusesConcurrentOperationAndCanceledRequest(t *testing.T) {
	lifecycle, core, _ := guardedLifecycle(t)
	lifecycle.opMu.Lock()
	err := (FirewallService{Lifecycle: lifecycle}).CleanupFirewall(context.Background())
	lifecycle.opMu.Unlock()
	var public *web.PublicError
	if !errors.As(err, &public) || public.Status != http.StatusConflict || len(core.events) != 0 {
		t.Fatalf("concurrent cleanup = %v, events=%v", err, core.events)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (FirewallService{Lifecycle: lifecycle}).CleanupFirewall(ctx); !errors.Is(err, context.Canceled) || len(core.events) != 0 {
		t.Fatalf("canceled cleanup = %v, events=%v", err, core.events)
	}
}

func TestFirewallRecoveryReportsGuardFailureAndAllowsRetry(t *testing.T) {
	lifecycle, _, guard := guardedLifecycle(t)
	guard.removeErr = errors.New("nft cleanup failed")
	service := FirewallService{Lifecycle: lifecycle}
	if err := service.CleanupFirewall(context.Background()); err == nil || lifecycle.Snapshot().State != LifecycleStopped || guard.status.LastError == "" {
		t.Fatalf("cleanup error=%v state=%s guard=%+v", err, lifecycle.Snapshot().State, guard.status)
	}
	guard.removeErr = nil
	if err := service.CleanupFirewall(context.Background()); err != nil || guard.status.LastError != "" {
		t.Fatalf("retry error=%v guard=%+v", err, guard.status)
	}
}
