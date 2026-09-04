package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
)

// ActivePreparer renders and validates the currently selected native profile.
type ActivePreparer interface {
	PrepareActive(context.Context) (engine.PreparedCore, error)
}

// CoreRuntime is the supervised process subset used by Lifecycle.
type CoreRuntime interface {
	Start(context.Context, engine.PreparedCore) error
	Stop(context.Context) error
	Health(context.Context) (engine.HealthStatus, error)
}

// Activation owns platform capture and DNS as one rollback-capable unit.
type Activation interface {
	Activate(context.Context, engine.PreparedCore) error
	Deactivate(context.Context, engine.PreparedCore) error
}

type LifecycleState string

const (
	LifecycleStopped  LifecycleState = "stopped"
	LifecycleStarting LifecycleState = "starting"
	LifecycleRunning  LifecycleState = "running"
	LifecycleStopping LifecycleState = "stopping"
	// LifecycleCleanupFailed keeps the core alive because owned capture or DNS
	// could not be fully removed. Stopping the core in this state could turn a
	// partial cleanup into a persistent traffic blackhole.
	LifecycleCleanupFailed LifecycleState = "cleanup-failed"
	LifecycleFailed        LifecycleState = "failed"
)

type LifecycleSnapshot struct {
	State       LifecycleState
	Prepared    engine.PreparedCore
	Health      engine.HealthStatus
	StartedAt   time.Time
	LastError   string
	LastChecked time.Time
}

// Lifecycle provides the core -> gateway -> DNS transaction and fail-open
// crash monitor. It never holds its mutex while running external commands.
type Lifecycle struct {
	Preparer   ActivePreparer
	Core       CoreRuntime
	Activation Activation
	Logger     *slog.Logger
	// OnStarted persists local host state after the complete core + gateway +
	// DNS transaction succeeds. A persistence failure is logged and leaves the
	// runtime running; for the first-start marker this fails safely by keeping
	// the next daemon launch in management-only mode.
	OnStarted func() error

	PrepareTimeout     time.Duration
	StartTimeout       time.Duration
	ReadyTimeout       time.Duration
	ReadyPollInterval  time.Duration
	MonitorInterval    time.Duration
	ControllerFailures int
	CleanupTimeout     time.Duration

	opMu sync.Mutex
	mu   sync.RWMutex
	snap LifecycleSnapshot
}

const (
	lifecycleOperationPollInterval = 10 * time.Millisecond
	defaultLifecycleCleanupTimeout = 10 * time.Second
)

func (lifecycle *Lifecycle) defaults() {
	if lifecycle.PrepareTimeout <= 0 {
		lifecycle.PrepareTimeout = 30 * time.Second
	}
	if lifecycle.StartTimeout <= 0 {
		lifecycle.StartTimeout = 30 * time.Second
	}
	if lifecycle.ReadyTimeout <= 0 {
		lifecycle.ReadyTimeout = 20 * time.Second
	}
	if lifecycle.ReadyPollInterval <= 0 {
		lifecycle.ReadyPollInterval = 250 * time.Millisecond
	}
	if lifecycle.MonitorInterval <= 0 {
		lifecycle.MonitorInterval = 2 * time.Second
	}
	if lifecycle.ControllerFailures <= 0 {
		lifecycle.ControllerFailures = 3
	}
	if lifecycle.CleanupTimeout <= 0 {
		lifecycle.CleanupTimeout = defaultLifecycleCleanupTimeout
	}
	if lifecycle.Logger == nil {
		lifecycle.Logger = slog.New(slog.DiscardHandler)
	}
}

func (lifecycle *Lifecycle) validate() error {
	if lifecycle.Preparer == nil || lifecycle.Core == nil || lifecycle.Activation == nil {
		return errors.New("lifecycle dependencies are incomplete")
	}
	return nil
}

// Start validates and starts the core before making any gateway or DNS change.
func (lifecycle *Lifecycle) Start(ctx context.Context) error {
	if err := lifecycle.lockOperation(ctx); err != nil {
		return err
	}
	defer lifecycle.opMu.Unlock()
	return lifecycle.startLocked(ctx)
}

func (lifecycle *Lifecycle) startLocked(ctx context.Context) error {
	lifecycle.defaults()
	if err := lifecycle.validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current := lifecycle.Snapshot()
	if current.State == LifecycleRunning {
		lifecycle.recordSuccessfulStart()
		return nil
	}
	if current.State == LifecycleCleanupFailed {
		return errors.New("cannot start while owned activation cleanup is unresolved")
	}
	// An empty state means this manager has just started and cannot know
	// whether its predecessor was SIGKILLed after installing capture. A failed
	// state likewise cannot prove that the previous cleanup completed. Remove
	// only our owned platform state before profile preparation, which may fail
	// or hang, so stale capture can never outlive a dead core.
	if current.State == "" || current.State == LifecycleFailed {
		if err := lifecycle.rollback(ctx, current.Prepared); err != nil {
			return lifecycle.failAfterRollback(fmt.Errorf("recover stale owned activation: %w", err))
		}
	}
	lifecycle.setState(LifecycleStarting, "")
	prepareContext, cancelPrepare := context.WithTimeout(ctx, lifecycle.PrepareTimeout)
	prepared, err := lifecycle.Preparer.PrepareActive(prepareContext)
	cancelPrepare()
	if err != nil {
		return lifecycle.fail(fmt.Errorf("prepare active core: %w", err))
	}
	lifecycle.mu.Lock()
	lifecycle.snap.Prepared = prepared
	lifecycle.mu.Unlock()
	startContext, cancelStart := context.WithTimeout(ctx, lifecycle.StartTimeout)
	startErr := lifecycle.Core.Start(startContext, prepared)
	cancelStart()
	if startErr != nil {
		rollbackErr := lifecycle.rollback(ctx, prepared)
		if lifecycle.Snapshot().State != LifecycleCleanupFailed {
			removeOneShotRuntime(prepared)
		}
		return lifecycle.failAfterRollback(errors.Join(fmt.Errorf("start core: %w", startErr), rollbackErr))
	}
	readyContext, cancelReady := context.WithTimeout(ctx, lifecycle.ReadyTimeout)
	health, err := lifecycle.waitReady(readyContext, prepared)
	cancelReady()
	lifecycle.recordHealth(health, err)
	if err != nil {
		rollbackErr := lifecycle.rollback(ctx, prepared)
		return lifecycle.failAfterRollback(errors.Join(fmt.Errorf("wait for core readiness: %w", err), rollbackErr))
	}
	if err := lifecycle.Activation.Activate(ctx, prepared); err != nil {
		rollbackErr := lifecycle.rollback(ctx, prepared)
		return lifecycle.failAfterRollback(errors.Join(fmt.Errorf("activate gateway: %w", err), rollbackErr))
	}
	lifecycle.mu.Lock()
	lifecycle.snap = LifecycleSnapshot{
		State: LifecycleRunning, Prepared: prepared, Health: health,
		StartedAt: time.Now().UTC(), LastChecked: health.CheckedAt,
	}
	lifecycle.mu.Unlock()
	lifecycle.Logger.Info("selective routing activated", "engine", prepared.Engine, "pid", health.PID)
	lifecycle.recordSuccessfulStart()
	return nil
}

func (lifecycle *Lifecycle) recordSuccessfulStart() {
	if lifecycle.OnStarted == nil {
		return
	}
	if err := lifecycle.OnStarted(); err != nil {
		lifecycle.Logger.Warn("could not persist successful lifecycle start; next daemon launch remains start-stopped", "error", err)
	}
}

// Adopt records a core and dataplane generation that remained live across a
// verified manager handoff. It deliberately does not reapply nftables or DNS.
func (lifecycle *Lifecycle) Adopt(prepared engine.PreparedCore, health engine.HealthStatus) error {
	lifecycle.defaults()
	if err := lifecycle.validate(); err != nil {
		return err
	}
	if !health.Running || health.PID <= 1 {
		return errors.New("cannot adopt a core that is not running")
	}
	lifecycle.mu.Lock()
	lifecycle.snap = LifecycleSnapshot{
		State: LifecycleRunning, Prepared: cloneLifecyclePrepared(prepared), Health: health,
		StartedAt: health.StartedAt, LastChecked: health.CheckedAt,
	}
	lifecycle.mu.Unlock()
	lifecycle.Logger.Info("adopted selective-routing generation without restarting the core", "engine", prepared.Engine, "pid", health.PID)
	return nil
}

func cloneLifecyclePrepared(prepared engine.PreparedCore) engine.PreparedCore {
	prepared.Args = append([]string(nil), prepared.Args...)
	prepared.Env = append([]string(nil), prepared.Env...)
	prepared.Capture.FakeIPRanges = append([]netip.Prefix(nil), prepared.Capture.FakeIPRanges...)
	prepared.Capture.Destinations.CIDRs = append([]netip.Prefix(nil), prepared.Capture.Destinations.CIDRs...)
	prepared.Capture.EndpointBypassCIDRs = append([]netip.Prefix(nil), prepared.Capture.EndpointBypassCIDRs...)
	return prepared
}

// Stop removes capture and restores DNS before stopping the core.
func (lifecycle *Lifecycle) Stop(ctx context.Context) error {
	if err := lifecycle.lockOperation(ctx); err != nil {
		return err
	}
	defer lifecycle.opMu.Unlock()
	return lifecycle.stopLocked(ctx)
}

func (lifecycle *Lifecycle) stopLocked(ctx context.Context) error {
	lifecycle.defaults()
	if err := lifecycle.validate(); err != nil {
		return err
	}
	current := lifecycle.Snapshot()
	if current.State == LifecycleStopped && current.Prepared.BinaryPath == "" {
		return nil
	}
	lifecycle.setState(LifecycleStopping, "")
	cleanupContext, cancel := lifecycle.cleanupContext(ctx)
	deactivateErr := lifecycle.Activation.Deactivate(cleanupContext, current.Prepared)
	if deactivateErr != nil {
		cancel()
		lifecycle.markCleanupFailed(current.Prepared, deactivateErr)
		lifecycle.Logger.Error("owned activation cleanup failed; keeping core alive", "error", deactivateErr)
		return deactivateErr
	}
	stopErr := lifecycle.Core.Stop(cleanupContext)
	cancel()
	lifecycle.mu.Lock()
	lifecycle.snap.LastChecked = time.Now().UTC()
	if stopErr != nil {
		// Capture is gone, so traffic is fail-open, but a failed Stop cannot
		// prove the process or its private runtime are no longer in use.
		lifecycle.snap.State = LifecycleFailed
		lifecycle.snap.LastError = stopErr.Error()
	} else {
		lifecycle.snap.State = LifecycleStopped
		lifecycle.snap.Health = engine.HealthStatus{}
		lifecycle.snap.LastError = ""
		lifecycle.snap.Prepared = engine.PreparedCore{}
	}
	lifecycle.mu.Unlock()
	if stopErr != nil {
		lifecycle.Logger.Error("core stop failed after selective routing cleanup", "error", stopErr)
		return stopErr
	}
	lifecycle.Logger.Info("selective routing stopped; traffic is fail-open")
	return nil
}

func (lifecycle *Lifecycle) Restart(ctx context.Context) error {
	if err := lifecycle.lockOperation(ctx); err != nil {
		return err
	}
	defer lifecycle.opMu.Unlock()
	if err := lifecycle.stopLocked(ctx); err != nil {
		return err
	}
	return lifecycle.startLocked(ctx)
}

// RestartIfRunning atomically checks the live state under the lifecycle
// operation gate. Callers which mutate companion state can therefore refresh a
// running generation without racing the crash monitor (or an explicit Stop)
// and accidentally starting a service which was stopped while they waited.
func (lifecycle *Lifecycle) RestartIfRunning(ctx context.Context) (bool, error) {
	if err := lifecycle.lockOperation(ctx); err != nil {
		return false, err
	}
	defer lifecycle.opMu.Unlock()
	if lifecycle.Snapshot().State != LifecycleRunning {
		return false, nil
	}
	if err := lifecycle.stopLocked(ctx); err != nil {
		return true, err
	}
	return true, lifecycle.startLocked(ctx)
}

// lockOperation makes lifecycle serialization responsive to request and
// shutdown cancellation. sync.Mutex remains the single ownership primitive;
// TryLock only avoids an unbounded wait behind a hung operation.
func (lifecycle *Lifecycle) lockOperation(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if lifecycle.opMu.TryLock() {
		return nil
	}
	ticker := time.NewTicker(lifecycleOperationPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if lifecycle.opMu.TryLock() {
				return nil
			}
		}
	}
}

func (lifecycle *Lifecycle) Snapshot() LifecycleSnapshot {
	lifecycle.mu.RLock()
	defer lifecycle.mu.RUnlock()
	result := lifecycle.snap
	result.Prepared.Args = append([]string(nil), result.Prepared.Args...)
	result.Prepared.Env = append([]string(nil), result.Prepared.Env...)
	result.Prepared.Capture.FakeIPRanges = append([]netip.Prefix(nil), result.Prepared.Capture.FakeIPRanges...)
	result.Prepared.Capture.Destinations.CIDRs = append([]netip.Prefix(nil), result.Prepared.Capture.Destinations.CIDRs...)
	result.Prepared.Capture.EndpointBypassCIDRs = append([]netip.Prefix(nil), result.Prepared.Capture.EndpointBypassCIDRs...)
	return result
}

// Monitor fails open when a running core exits or its controller stays
// unavailable. It does not silently re-enable capture; recovery is explicit or
// handled by the service controller after diagnostics.
func (lifecycle *Lifecycle) Monitor(ctx context.Context) {
	lifecycle.defaults()
	ticker := time.NewTicker(lifecycle.MonitorInterval)
	defer ticker.Stop()
	controllerFailures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		current := lifecycle.Snapshot()
		if current.State == LifecycleCleanupFailed {
			lifecycle.Logger.Warn("retrying unresolved owned activation cleanup")
			if err := lifecycle.Stop(context.Background()); err != nil {
				lifecycle.Logger.Error("owned activation cleanup retry failed; keeping core alive", "error", err)
			}
			controllerFailures = 0
			continue
		}
		if current.State != LifecycleRunning {
			controllerFailures = 0
			continue
		}
		healthContext, cancel := context.WithTimeout(ctx, lifecycle.MonitorInterval)
		health, err := lifecycle.Core.Health(healthContext)
		cancel()
		lifecycle.recordHealth(health, err)
		if !health.Running {
			lifecycle.Logger.Error("core exited; removing capture for fail-open recovery", "error", err)
			_ = lifecycle.Stop(context.Background())
			controllerFailures = 0
			continue
		}
		prepared := lifecycle.Snapshot().Prepared
		if err != nil || !health.ControllerReady || (prepared.Capture.DNS.Enabled && !health.DNSReady) {
			controllerFailures++
			if controllerFailures >= lifecycle.ControllerFailures {
				lifecycle.Logger.Error("core readiness remained unavailable; removing capture", "failures", controllerFailures, "error", err)
				_ = lifecycle.Stop(context.Background())
				controllerFailures = 0
			}
			continue
		}
		controllerFailures = 0
	}
}

func (lifecycle *Lifecycle) waitReady(ctx context.Context, prepared engine.PreparedCore) (engine.HealthStatus, error) {
	ticker := time.NewTicker(lifecycle.ReadyPollInterval)
	defer ticker.Stop()
	var lastErr error
	for {
		health, err := lifecycle.Core.Health(ctx)
		dnsReady := !prepared.Capture.DNS.Enabled || health.DNSReady
		if health.Running && health.ControllerReady && dnsReady && err == nil {
			return health, nil
		}
		if !health.Running && health.LastExitError != "" {
			return health, errors.New(health.LastExitError)
		}
		if err != nil {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return health, errors.Join(ctx.Err(), lastErr)
			}
			return health, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (lifecycle *Lifecycle) rollback(parent context.Context, prepared engine.PreparedCore) error {
	cleanupContext, cancel := lifecycle.cleanupContext(parent)
	defer cancel()
	if err := lifecycle.Activation.Deactivate(cleanupContext, prepared); err != nil {
		lifecycle.markCleanupFailed(prepared, err)
		return err
	}
	if err := lifecycle.Core.Stop(cleanupContext); err != nil {
		return err
	}
	lifecycle.mu.Lock()
	lifecycle.snap.Prepared = engine.PreparedCore{}
	lifecycle.snap.Health = engine.HealthStatus{}
	lifecycle.mu.Unlock()
	return nil
}

func (lifecycle *Lifecycle) cleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	now := time.Now()
	deadline := now.Add(lifecycle.CleanupTimeout)
	// Preserve an already-expired parent deadline too. Giving a timed-out
	// recovery another full cleanup window can keep the lifecycle operation gate
	// beyond the manager's graceful-shutdown budget.
	if parentDeadline, ok := parent.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	return context.WithDeadline(context.Background(), deadline)
}

func (lifecycle *Lifecycle) fail(err error) error {
	lifecycle.setState(LifecycleFailed, err.Error())
	lifecycle.Logger.Error("lifecycle transaction failed", "error", err)
	return err
}

func (lifecycle *Lifecycle) failAfterRollback(err error) error {
	if lifecycle.Snapshot().State != LifecycleCleanupFailed {
		return lifecycle.fail(err)
	}
	lifecycle.mu.Lock()
	lifecycle.snap.LastError = err.Error()
	lifecycle.snap.LastChecked = time.Now().UTC()
	lifecycle.mu.Unlock()
	lifecycle.Logger.Error("lifecycle transaction failed; keeping core alive until owned activation cleanup succeeds", "error", err)
	return err
}

func (lifecycle *Lifecycle) markCleanupFailed(prepared engine.PreparedCore, err error) {
	lifecycle.mu.Lock()
	lifecycle.snap.State = LifecycleCleanupFailed
	lifecycle.snap.Prepared = prepared
	lifecycle.snap.LastError = err.Error()
	lifecycle.snap.LastChecked = time.Now().UTC()
	lifecycle.mu.Unlock()
}

func (lifecycle *Lifecycle) setState(state LifecycleState, lastError string) {
	lifecycle.mu.Lock()
	lifecycle.snap.State = state
	lifecycle.snap.LastError = lastError
	lifecycle.snap.LastChecked = time.Now().UTC()
	lifecycle.mu.Unlock()
}

func (lifecycle *Lifecycle) recordHealth(health engine.HealthStatus, err error) {
	lifecycle.mu.Lock()
	lifecycle.snap.Health = health
	lifecycle.snap.LastChecked = time.Now().UTC()
	if err != nil {
		lifecycle.snap.LastError = err.Error()
	} else if lifecycle.snap.State == LifecycleRunning && health.Running && health.ControllerReady &&
		(!lifecycle.snap.Prepared.Capture.DNS.Enabled || health.DNSReady) {
		// A controller or DNS probe can fail briefly while the core keeps
		// running. Do not leave that transient failure latched after the next
		// complete health snapshot succeeds. Errors for failed lifecycle states
		// remain intact because only a fully ready running state clears them.
		lifecycle.snap.LastError = ""
	}
	lifecycle.mu.Unlock()
}
