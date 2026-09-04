package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
)

const maintenanceOperationTimeout = 90 * time.Second

type dynamicCaptureActivation interface {
	RefreshDynamicCapture(context.Context, engine.DestinationCapture, []netip.Prefix) (engine.CapturePlan, error)
}

// PeriodicMaintenance updates only firewall-owned dynamic sets. It does not
// reload the core, mutate the selected native config, or require browser
// polling. Settings changes wake the scheduler immediately.
type PeriodicMaintenance struct {
	State      state.Store
	Preparer   *ActiveMihomoPreparer
	Lifecycle  *Lifecycle
	Activation dynamicCaptureActivation
	Logger     *slog.Logger

	wake chan struct{}
}

func NewPeriodicMaintenance(store state.Store, preparer *ActiveMihomoPreparer, lifecycle *Lifecycle, activation dynamicCaptureActivation, logger *slog.Logger) *PeriodicMaintenance {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &PeriodicMaintenance{
		State: store, Preparer: preparer, Lifecycle: lifecycle, Activation: activation,
		Logger: logger, wake: make(chan struct{}, 1),
	}
}

func (service *PeriodicMaintenance) Reload() {
	if service == nil {
		return
	}
	select {
	case service.wake <- struct{}{}:
	default:
	}
}

func (service *PeriodicMaintenance) Run(ctx context.Context) {
	if service == nil {
		return
	}
	for {
		settings, err := LoadRuntimeSettings(service.State)
		if err != nil {
			service.Logger.Error("periodic maintenance settings are invalid", "error", err)
			_, ok := service.wait(ctx, 5*time.Minute)
			if !ok {
				return
			}
			continue
		}
		if settings.OperatingMode == "server" || (!settings.AutoRefreshProxyIPs && !settings.AutoRefreshFakeIP) {
			_, ok := service.wait(ctx, 0)
			if !ok {
				return
			}
			continue
		}
		fired, ok := service.wait(ctx, time.Duration(settings.MaintenanceInterval)*time.Minute)
		if !ok {
			return
		}
		if !fired {
			continue
		}
		operationContext, cancel := context.WithTimeout(ctx, maintenanceOperationTimeout)
		err = service.Refresh(operationContext, settings)
		cancel()
		if err != nil && !errors.Is(err, context.Canceled) {
			service.Logger.Warn("periodic firewall maintenance failed", "error", err)
		}
	}
}

// wait returns after the timer, a settings notification, or cancellation. A
// zero duration means wait indefinitely for a settings notification.
func (service *PeriodicMaintenance) wait(ctx context.Context, duration time.Duration) (bool, bool) {
	if duration <= 0 {
		select {
		case <-ctx.Done():
			return false, false
		case <-service.wake:
			return false, true
		}
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false, false
	case <-service.wake:
		return false, true
	case <-timer.C:
		return true, true
	}
}

func (service *PeriodicMaintenance) Refresh(ctx context.Context, settings RuntimeSettings) error {
	if settings.OperatingMode == "server" {
		return nil
	}
	if service == nil || service.Preparer == nil || service.Lifecycle == nil || service.Activation == nil {
		return errors.New("periodic maintenance dependencies are incomplete")
	}
	if err := service.Lifecycle.lockOperation(ctx); err != nil {
		return err
	}
	defer service.Lifecycle.opMu.Unlock()
	snapshot := service.Lifecycle.Snapshot()
	if snapshot.State != LifecycleRunning {
		return nil
	}
	if snapshot.Prepared.Engine != "" && snapshot.Prepared.Engine != state.EngineMihomo {
		// The current dynamic-maintenance inputs are Mihomo YAML/provider
		// semantics. sing-box endpoint sets are computed transactionally during
		// native preparation instead of parsing them through this adapter.
		return nil
	}

	source, err := service.source(snapshot)
	if err != nil {
		return err
	}

	destinations := snapshot.Prepared.Capture.Destinations
	if settings.AutoRefreshFakeIP && settings.AutoFakeIP {
		manager := service.Preparer.FakeIP
		if manager == nil {
			manager = NewFakeIPCaptureManager(service.Preparer.Layout)
		}
		policy, policyErr := manager.PrepareWithOptions(source, true, FakeIPCaptureOptions{
			IncludeExternalIPProviders: settings.AutoFakeIPIncludeExternalIPProviders,
		})
		if policyErr != nil {
			return policyErr
		}
		if policy.Selective {
			destinations = engine.DestinationCapture{Mode: engine.DestinationCaptureAllowlist, CIDRs: append([]netip.Prefix(nil), policy.Effective...)}
		} else {
			destinations = engine.DestinationCapture{Mode: engine.DestinationCaptureAll}
		}
	}

	endpoints := append([]netip.Prefix(nil), snapshot.Prepared.Capture.EndpointBypassCIDRs...)
	if settings.AutoRefreshProxyIPs {
		manager := service.Preparer.Endpoints
		if manager == nil {
			manager = NewEndpointBypassManager(service.Preparer.Layout, service.Preparer.State)
		}
		endpoints, err = manager.Prepare(ctx, source)
		if err != nil {
			return err
		}
	}
	refreshed, err := service.Activation.RefreshDynamicCapture(ctx, destinations, endpoints)
	if err != nil {
		return err
	}
	service.Lifecycle.mu.Lock()
	if service.Lifecycle.snap.State == LifecycleRunning {
		service.Lifecycle.snap.Prepared.Capture = cloneCapturePlan(refreshed)
	}
	service.Lifecycle.mu.Unlock()
	return nil
}

// source prefers the private document currently used by Mihomo. Besides being
// the most accurate description of the running core, it contains subscription
// injection and the manager-owned tmpfs cache paths. A missing runtime file is
// tolerated for restored/legacy lifecycle snapshots; malformed or unsafe files
// fail closed instead of silently regenerating from a different document.
func (service *PeriodicMaintenance) source(snapshot LifecycleSnapshot) ([]byte, error) {
	runtimePath := strings.TrimSpace(snapshot.Prepared.RuntimeConfigPath)
	if runtimePath != "" {
		source, err := readBoundedRegular(runtimePath, 32<<20)
		if err == nil {
			return source, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("read running Mihomo configuration: %w", err)
		}
	}
	active, activeErr := service.Preparer.Profiles.Current()
	if activeErr != nil && !errors.Is(activeErr, fs.ErrNotExist) {
		return nil, activeErr
	}
	sourcePath, err := service.Preparer.sourcePath(active, activeErr)
	if err != nil {
		return nil, err
	}
	return readBoundedRegular(sourcePath, 32<<20)
}
