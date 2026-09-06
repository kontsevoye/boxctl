package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/platform/openwrt"
	"github.com/kontsevoye/boxctl/internal/web"
)

type panelRestartKey struct{}

func removeOneShotRestartGuard(ctx context.Context, candidate any, runner openwrt.Runner) error {
	activation, ok := candidate.(*OpenWrtActivation)
	if !ok {
		return nil
	}
	return activation.withTransaction(ctx, false, func() error { return openwrt.RemoveRestartGuard(ctx, runner) })
}

func panelRestart(ctx context.Context, reason string) context.Context {
	return context.WithValue(ctx, panelRestartKey{}, reason)
}

// RestartTrafficGuard belongs to a user-requested restart transaction, never
// to generic core availability or capture activation/deactivation.
type RestartTrafficGuard interface {
	Enabled() (bool, error)
	Begin(context.Context, engine.PreparedCore, string) (bool, error)
	Verify(context.Context, engine.PreparedCore) error
	Remove(context.Context) error
	Status() web.RestartGuardStatus
}

func (guard *openWrtRestartGuard) Enabled() (bool, error) {
	settings, err := LoadRuntimeSettings(guard.activation.State)
	return settings.CoreRestartGuard, err
}

type openWrtRestartGuard struct {
	activation *OpenWrtActivation
	runner     openwrt.Runner
	mu         sync.Mutex
	status     web.RestartGuardStatus
}

func (guard *openWrtRestartGuard) Status() web.RestartGuardStatus {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	status := guard.status
	status.ProtectedInterfaces = append([]string(nil), status.ProtectedInterfaces...)
	status.TrustedInterfaces = append([]string(nil), status.TrustedInterfaces...)
	if status.ExpiresAt != nil && !time.Now().Before(*status.ExpiresAt) {
		status.Active = false
	}
	return status
}

func (guard *openWrtRestartGuard) plan(ctx context.Context, settings RuntimeSettings, previous ...string) (openwrt.RestartGuardPlan, error) {
	discovered, err := guard.activation.gateway.Detect(ctx)
	if err != nil {
		return openwrt.RestartGuardPlan{}, err
	}
	protected := append([]string(nil), discovered.LANInterfaces...)
	if settings.InterfaceMode == "explicit" && len(settings.Included) > 0 {
		protected = append([]string(nil), settings.Included...)
	}
	protected = slices.DeleteFunc(protected, func(name string) bool { return slices.Contains(settings.Excluded, name) })
	protected = append(protected, previous...)
	for _, name := range protected {
		if slices.Contains(discovered.WANInterfaces, name) {
			return openwrt.RestartGuardPlan{}, errors.New("restart guard cannot protect a WAN interface as LAN")
		}
	}
	trusted := normalizeStringList(append(append([]string(nil), discovered.LANInterfaces...), protected...))
	plan := openwrt.RestartGuardPlan{Protected: normalizeStringList(protected), Trusted: trusted}
	_, err = openwrt.RenderRestartGuard(plan, openwrt.RestartGuardMaxLease)
	return plan, err
}

func (guard *openWrtRestartGuard) validate(ctx context.Context, settings RuntimeSettings) error {
	if settings.OperatingMode != "gateway" {
		return errors.New("restart guard requires gateway mode")
	}
	if err := openwrt.CheckRestartGuardSupport(ctx, guard.runner); err != nil {
		return err
	}
	_, err := guard.plan(ctx, settings)
	return err
}

// Configure validates a saved policy without installing a blocking rule.
// The caller holds the lifecycle gate until the setting is persisted.
func (guard *openWrtRestartGuard) Configure(ctx context.Context, settings RuntimeSettings) error {
	if settings.CoreRestartGuard {
		if err := guard.validate(ctx, settings); err != nil {
			return errors.Join(err, &web.PublicError{Status: http.StatusConflict, Code: "restart_guard_unavailable", Message: "Restart protection requires gateway mode, identifiable LAN interfaces, and disabled software and hardware flow offloading"})
		}
		return nil
	}
	return guard.Remove(ctx)
}

func (guard *openWrtRestartGuard) Begin(ctx context.Context, _ engine.PreparedCore, reason string) (bool, error) {
	settings, err := LoadRuntimeSettings(guard.activation.State)
	if err != nil || !settings.CoreRestartGuard {
		return false, err
	}
	if err := guard.validate(ctx, settings); err != nil {
		return false, err
	}
	var plan openwrt.RestartGuardPlan
	err = guard.activation.withTransaction(ctx, false, func() error {
		active, err := guard.activation.loadActiveGatewayState()
		if err != nil {
			return err
		}
		check, err := guard.activation.gateway.Check(ctx, active.Plan)
		if err != nil {
			return err
		}
		if !check.Exists || !check.Owned || !check.PlanMatches || !check.PolicyMatches || !check.FirewallMatches {
			return errors.New("cannot protect restart: active gateway ownership is not healthy")
		}
		// Include the old explicit ingress if settings now select another LAN,
		// but never promote an excluded or WAN device to a trusted local egress.
		previous := slices.DeleteFunc(append([]string(nil), active.Plan.IncludeInterfaces...), func(name string) bool { return slices.Contains(active.Plan.ExcludeInterfaces, name) })
		plan, err = guard.plan(ctx, settings, previous...)
		if err != nil {
			return err
		}
		if err := openwrt.RemoveRestartGuard(ctx, guard.runner); err != nil {
			return err
		}
		return openwrt.ApplyRestartGuard(ctx, guard.runner, plan, openwrt.RestartGuardMaxLease)
	})
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), openWrtRollbackTimeout)
		defer cancel()
		return false, errors.Join(err, guard.Remove(cleanup))
	}
	expires := time.Now().UTC().Add(openwrt.RestartGuardMaxLease)
	guard.mu.Lock()
	guard.status = web.RestartGuardStatus{Active: true, Reason: reason, ExpiresAt: &expires, ProtectedInterfaces: plan.Protected, TrustedInterfaces: plan.Trusted}
	guard.mu.Unlock()
	return true, nil
}

func (guard *openWrtRestartGuard) Verify(ctx context.Context, _ engine.PreparedCore) error {
	return guard.activation.withTransaction(ctx, false, func() error {
		active, err := guard.activation.loadActiveGatewayState()
		if err != nil {
			return err
		}
		check, err := guard.activation.gateway.Check(ctx, active.Plan)
		if err != nil {
			return err
		}
		if !check.Exists || !check.Owned || !check.PlanMatches || !check.PolicyMatches || !check.FirewallMatches {
			return errors.New("replacement gateway state did not pass verification")
		}
		backup, err := guard.activation.loadDNSBackup()
		if err != nil {
			return err
		}
		return openwrt.NewDNSManager(guard.runner).Check(ctx, active.Plan, backup)
	})
}

func (guard *openWrtRestartGuard) Remove(ctx context.Context) error {
	err := guard.activation.withTransaction(ctx, false, func() error { return openwrt.RemoveRestartGuard(ctx, guard.runner) })
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if err == nil {
		guard.status = web.RestartGuardStatus{}
	} else {
		guard.status.LastError = "Restart guard cleanup could not be verified; see system logs"
	}
	return err
}

func (lifecycle *Lifecycle) beginRestartGuard(ctx context.Context, current engine.PreparedCore) (context.Context, func() error, error) {
	reason, _ := ctx.Value(panelRestartKey{}).(string)
	noop := func() error { return nil }
	if reason == "" || lifecycle.RestartGuard == nil {
		return ctx, noop, nil
	}
	active, err := lifecycle.RestartGuard.Begin(ctx, current, reason)
	if err != nil || !active {
		return ctx, noop, err
	}
	lifecycle.guardInProgress = true
	// Finish the transaction even if the browser disconnects. The target gets
	// two minutes; bounded rollback/cleanup still fit within the five-minute
	// kernel lease. Recovery is never allowed to renew the lease.
	operation, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	return operation, func() error {
		defer cancel()
		defer func() { lifecycle.guardInProgress = false }()
		cleanup, cancelCleanup := context.WithTimeout(context.Background(), openWrtRollbackTimeout)
		defer cancelCleanup()
		if err := lifecycle.RestartGuard.Remove(cleanup); err != nil {
			return fmt.Errorf("remove restart guard: %w", err)
		}
		return nil
	}, nil
}

// retryRestartGuardCleanup runs only between lifecycle operations. It cannot
// remove another transaction's guard or interfere with a rollback.
func (lifecycle *Lifecycle) retryRestartGuardCleanup() {
	if lifecycle.RestartGuard == nil || !lifecycle.opMu.TryLock() {
		return
	}
	defer lifecycle.opMu.Unlock()
	if lifecycle.RestartGuard.Status().LastError == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), openWrtRollbackTimeout)
	defer cancel()
	if err := lifecycle.RestartGuard.Remove(ctx); err != nil {
		lifecycle.Logger.Warn("retry restart guard cleanup", "error", err)
	}
}
