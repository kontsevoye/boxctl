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

// CoreRuntime is the supervised process subset used by Lifecycle. A nil Start
// transfers ownership of PreparedCore's private runtime to the implementation;
// Stop releases it only after the process can no longer read it.
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
	Preparer        ActivePreparer
	Core            CoreRuntime
	Activation      Activation
	Logger          *slog.Logger
	RestartGuard    RestartTrafficGuard
	guardInProgress bool // protected by opMu
	// OnStarted persists local host state after the complete core + gateway +
	// DNS transaction succeeds. A persistence failure is logged and leaves the
	// runtime running; for the first-start marker this fails safely by keeping
	// the next daemon launch in management-only mode.
	OnStarted func(engine.PreparedCore) error

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
	if err := lifecycle.startPreparedLocked(ctx, prepared); err != nil {
		return err
	}
	lifecycle.recordSuccessfulStart(prepared)
	return nil
}

// startPreparedLocked starts one already validated native generation. The
// caller must hold opMu. It preserves the core -> readiness -> gateway order.
func (lifecycle *Lifecycle) startPreparedLocked(ctx context.Context, prepared engine.PreparedCore) error {
	return lifecycle.startPreparedLockedWithAcceptance(ctx, prepared, nil)
}

// startPreparedLockedWithAcceptance reports the exact point at which Core.Start
// accepted ownership of the prepared runtime. Rollback callers need this
// distinction: a clone which was never accepted remains caller-owned, while an
// accepted clone must not be removed if later readiness or activation cleanup
// leaves the core running.
func (lifecycle *Lifecycle) startPreparedLockedWithAcceptance(
	ctx context.Context,
	prepared engine.PreparedCore,
	onAccepted func(),
) error {
	lifecycle.setState(LifecycleStarting, "")
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
	if onAccepted != nil {
		onAccepted()
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
	// Activation changes the packet path and, in upstream mode, points dnsmasq
	// at the core. Probe the resulting generation again: a resolver which was
	// healthy against the pre-activation system DNS can otherwise enter a loop
	// only after the gateway transaction commits.
	postActivateContext, cancelPostActivate := context.WithTimeout(ctx, lifecycle.ReadyTimeout)
	postActivateHealth, postActivateErr := lifecycle.waitReady(postActivateContext, prepared)
	cancelPostActivate()
	lifecycle.recordHealth(postActivateHealth, postActivateErr)
	if postActivateErr != nil {
		rollbackErr := lifecycle.rollback(ctx, prepared)
		return lifecycle.failAfterRollback(errors.Join(fmt.Errorf("core readiness failed after gateway activation: %w", postActivateErr), rollbackErr))
	}
	if lifecycle.guardInProgress {
		if err := lifecycle.RestartGuard.Verify(ctx, prepared); err != nil {
			rollbackErr := lifecycle.rollback(ctx, prepared)
			return lifecycle.failAfterRollback(errors.Join(fmt.Errorf("verify guarded gateway: %w", err), rollbackErr))
		}
	}
	health = postActivateHealth
	lifecycle.mu.Lock()
	lifecycle.snap = LifecycleSnapshot{
		State: LifecycleRunning, Prepared: prepared, Health: health,
		StartedAt: time.Now().UTC(), LastChecked: health.CheckedAt,
	}
	lifecycle.mu.Unlock()
	lifecycle.Logger.Info("selective routing activated", "engine", prepared.Engine, "pid", health.PID)
	return nil
}

// SwitchPrepared atomically changes the live engine/profile generation. The
// target must have been prepared before this call while the old selection was
// still authoritative. commit persists the new active profile only after the
// target core and dataplane are ready.
func (lifecycle *Lifecycle) SwitchPrepared(ctx context.Context, target engine.PreparedCore, commit func() error) (changed bool, returnErr error) {
	if commit == nil {
		engine.CleanupPreparedRuntime(target)
		return false, errors.New("profile switch commit is required")
	}
	if err := lifecycle.lockOperation(ctx); err != nil {
		engine.CleanupPreparedRuntime(target)
		return false, err
	}
	defer lifecycle.opMu.Unlock()
	lifecycle.defaults()
	if err := lifecycle.validate(); err != nil {
		engine.CleanupPreparedRuntime(target)
		return false, err
	}
	current := lifecycle.Snapshot()
	if current.State != LifecycleRunning {
		defer engine.CleanupPreparedRuntime(target)
		if current.State == LifecycleCleanupFailed || current.State == LifecycleStarting || current.State == LifecycleStopping {
			return false, errors.New("cannot change the selected profile during an incomplete lifecycle operation")
		}
		return false, commit()
	}

	rollbackPrepared, err := engine.ClonePreparedRuntime(current.Prepared)
	if err != nil {
		engine.CleanupPreparedRuntime(target)
		return true, fmt.Errorf("clone live rollback generation: %w", err)
	}
	rollbackConsumed := false
	defer func() {
		if !rollbackConsumed {
			engine.CleanupPreparedRuntime(rollbackPrepared)
		}
	}()

	ctx, finishGuard, guardErr := lifecycle.beginRestartGuard(ctx, current.Prepared)
	if guardErr != nil {
		engine.CleanupPreparedRuntime(target)
		return true, fmt.Errorf("install restart guard: %w", guardErr)
	}
	defer func() { returnErr = errors.Join(returnErr, finishGuard()) }()
	if err := lifecycle.stopLocked(ctx); err != nil {
		engine.CleanupPreparedRuntime(target)
		return true, fmt.Errorf("stop previous generation: %w", err)
	}
	if err := lifecycle.startPreparedLocked(ctx, target); err != nil {
		recoveryContext, cancelRecovery := lifecycle.recoveryContext()
		rollbackTransferred, restoreErr := lifecycle.restorePreparedAfterFailure(recoveryContext, rollbackPrepared)
		rollbackConsumed = rollbackTransferred
		cancelRecovery()
		return true, errors.Join(fmt.Errorf("start target generation: %w", err), wrapLifecycleRollbackError(restoreErr))
	}
	if err := commit(); err != nil {
		recoveryContext, cancelRecovery := lifecycle.recoveryContext()
		defer cancelRecovery()
		stopErr := lifecycle.stopLocked(recoveryContext)
		var restoreErr error
		if stopErr == nil {
			rollbackConsumed, restoreErr = lifecycle.restorePreparedAfterFailure(recoveryContext, rollbackPrepared)
		}
		return true, errors.Join(fmt.Errorf("commit active profile: %w", err), stopErr, wrapLifecycleRollbackError(restoreErr))
	}
	lifecycle.recordSuccessfulStart(target)
	return true, nil
}

// ReconfigurePrepared replaces the live generation while the selected profile
// stays the same. It clones the actual private runtime before stopping it, so
// a failed restart restores the exact previous generation without discarding
// the newly saved (pending) source document.
func (lifecycle *Lifecycle) ReconfigurePrepared(
	ctx context.Context,
	target engine.PreparedCore,
	commit func() error,
) (bool, error) {
	if err := lifecycle.lockOperation(ctx); err != nil {
		engine.CleanupPreparedRuntime(target)
		return false, err
	}
	defer lifecycle.opMu.Unlock()
	return lifecycle.reconfigurePreparedLocked(ctx, target, commit)
}

func (lifecycle *Lifecycle) reconfigurePreparedLocked(ctx context.Context, target engine.PreparedCore, commit func() error) (changed bool, returnErr error) {
	lifecycle.defaults()
	if err := lifecycle.validate(); err != nil {
		engine.CleanupPreparedRuntime(target)
		return false, err
	}
	current := lifecycle.Snapshot()
	if current.State != LifecycleRunning {
		defer engine.CleanupPreparedRuntime(target)
		if current.State == LifecycleCleanupFailed || current.State == LifecycleStarting || current.State == LifecycleStopping {
			return false, errors.New("cannot reconfigure during an incomplete lifecycle operation")
		}
		if commit != nil {
			return false, commit()
		}
		return false, nil
	}
	rollbackPrepared, err := engine.ClonePreparedRuntime(current.Prepared)
	if err != nil {
		engine.CleanupPreparedRuntime(target)
		return true, fmt.Errorf("clone live rollback generation: %w", err)
	}

	rollbackConsumed := false
	defer func() {
		if !rollbackConsumed {
			engine.CleanupPreparedRuntime(rollbackPrepared)
		}
	}()
	ctx, finishGuard, guardErr := lifecycle.beginRestartGuard(ctx, current.Prepared)
	if guardErr != nil {
		engine.CleanupPreparedRuntime(target)
		return true, fmt.Errorf("install restart guard: %w", guardErr)
	}
	defer func() { returnErr = errors.Join(returnErr, finishGuard()) }()
	if err := lifecycle.stopLocked(ctx); err != nil {
		engine.CleanupPreparedRuntime(target)
		return true, fmt.Errorf("stop previous generation: %w", err)
	}
	if err := lifecycle.startPreparedLocked(ctx, target); err != nil {
		recoveryContext, cancelRecovery := lifecycle.recoveryContext()
		rollbackTransferred, restoreErr := lifecycle.restorePreparedAfterFailure(recoveryContext, rollbackPrepared)
		rollbackConsumed = rollbackTransferred
		cancelRecovery()
		return true, errors.Join(fmt.Errorf("start replacement generation: %w", err), wrapLifecycleRollbackError(restoreErr))
	}
	if commit == nil {
		lifecycle.recordSuccessfulStart(target)
		return true, nil
	}
	if err := commit(); err != nil {
		recoveryContext, cancelRecovery := lifecycle.recoveryContext()
		defer cancelRecovery()
		stopErr := lifecycle.stopLocked(recoveryContext)
		var restoreErr error
		if stopErr == nil {
			rollbackConsumed, restoreErr = lifecycle.restorePreparedAfterFailure(recoveryContext, rollbackPrepared)
		}
		return true, errors.Join(fmt.Errorf("commit replacement generation: %w", err), stopErr, wrapLifecycleRollbackError(restoreErr))
	}
	lifecycle.recordSuccessfulStart(target)
	return true, nil
}

func (lifecycle *Lifecycle) restorePreparedAfterFailure(ctx context.Context, prepared engine.PreparedCore) (bool, error) {
	failed := lifecycle.Snapshot()
	if failed.State == LifecycleCleanupFailed || failed.Health.Running {
		return false, errors.New("rollback start skipped because the failed target generation may still own the core or dataplane")
	}
	accepted := false
	err := lifecycle.startPreparedLockedWithAcceptance(ctx, prepared, func() { accepted = true })
	return accepted, err
}

func wrapLifecycleRollbackError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("restore previous generation: %w", err)
}

func (lifecycle *Lifecycle) recordSuccessfulStart(prepared engine.PreparedCore) {
	if lifecycle.OnStarted == nil {
		return
	}
	if err := lifecycle.OnStarted(cloneLifecyclePrepared(prepared)); err != nil {
		lifecycle.Logger.Warn("could not persist successful lifecycle start; next daemon launch remains start-stopped", "error", err)
	}
}

// Adopt records a core and dataplane generation that remained live across a
// verified manager handoff. It deliberately does not reapply nftables or DNS,
// so callers must never use it for an unrequested manager crash.
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

// RecoverAdopted accepts a process which survived an unrequested manager crash.
// Unlike the verified handoff path, it rebuilds the exact adopted generation's
// packet path and DNS ownership before reporting Running. Any failure follows
// the normal fail-open rollback: activation is removed before the core stops,
// while a failed cleanup keeps the core alive in CleanupFailed for retry.
func (lifecycle *Lifecycle) RecoverAdopted(ctx context.Context, prepared engine.PreparedCore, health engine.HealthStatus) error {
	if err := lifecycle.lockOperation(ctx); err != nil {
		return err
	}
	defer lifecycle.opMu.Unlock()
	lifecycle.defaults()
	if err := lifecycle.validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	lifecycle.mu.Lock()
	lifecycle.snap = LifecycleSnapshot{
		State: LifecycleStarting, Prepared: cloneLifecyclePrepared(prepared), Health: health,
		StartedAt: health.StartedAt, LastChecked: health.CheckedAt,
	}
	lifecycle.mu.Unlock()
	if !health.Running || health.PID <= 1 {
		rollbackErr := lifecycle.rollback(ctx, prepared)
		return lifecycle.failAfterRollback(errors.Join(errors.New("cannot recover a core that is not running"), rollbackErr))
	}

	readyContext, cancelReady := context.WithTimeout(ctx, lifecycle.ReadyTimeout)
	readyHealth, err := lifecycle.waitReady(readyContext, prepared)
	cancelReady()
	lifecycle.recordHealth(readyHealth, err)
	if err != nil {
		rollbackErr := lifecycle.rollback(ctx, prepared)
		return lifecycle.failAfterRollback(errors.Join(fmt.Errorf("wait for adopted core readiness: %w", err), rollbackErr))
	}
	if err := lifecycle.Activation.Activate(ctx, prepared); err != nil {
		rollbackErr := lifecycle.rollback(ctx, prepared)
		return lifecycle.failAfterRollback(errors.Join(fmt.Errorf("activate adopted gateway: %w", err), rollbackErr))
	}
	postActivateContext, cancelPostActivate := context.WithTimeout(ctx, lifecycle.ReadyTimeout)
	postActivateHealth, postActivateErr := lifecycle.waitReady(postActivateContext, prepared)
	cancelPostActivate()
	lifecycle.recordHealth(postActivateHealth, postActivateErr)
	if postActivateErr != nil {
		rollbackErr := lifecycle.rollback(ctx, prepared)
		return lifecycle.failAfterRollback(errors.Join(fmt.Errorf("adopted core readiness failed after gateway activation: %w", postActivateErr), rollbackErr))
	}
	lifecycle.mu.Lock()
	lifecycle.snap = LifecycleSnapshot{
		State: LifecycleRunning, Prepared: cloneLifecyclePrepared(prepared), Health: postActivateHealth,
		StartedAt: health.StartedAt, LastChecked: postActivateHealth.CheckedAt,
	}
	lifecycle.mu.Unlock()
	lifecycle.recordSuccessfulStart(prepared)
	lifecycle.Logger.Info("recovered selective-routing generation after manager crash", "engine", prepared.Engine, "pid", postActivateHealth.PID)
	return nil
}

// DiscardAdopted removes any packet-path ownership for an adopted generation
// which does not match the recovered selection, then stops its exact backend.
func (lifecycle *Lifecycle) DiscardAdopted(ctx context.Context, prepared engine.PreparedCore, health engine.HealthStatus) error {
	if err := lifecycle.lockOperation(ctx); err != nil {
		return err
	}
	defer lifecycle.opMu.Unlock()
	lifecycle.defaults()
	if err := lifecycle.validate(); err != nil {
		return err
	}
	lifecycle.mu.Lock()
	lifecycle.snap = LifecycleSnapshot{
		State: LifecycleRunning, Prepared: cloneLifecyclePrepared(prepared), Health: health,
		StartedAt: health.StartedAt, LastChecked: health.CheckedAt,
	}
	lifecycle.mu.Unlock()
	return lifecycle.stopLocked(ctx)
}

func cloneLifecyclePrepared(prepared engine.PreparedCore) engine.PreparedCore {
	prepared.Args = append([]string(nil), prepared.Args...)
	prepared.Env = append([]string(nil), prepared.Env...)
	prepared.Capture.FakeIPRanges = append([]netip.Prefix(nil), prepared.Capture.FakeIPRanges...)
	prepared.Capture.TUNAddresses = append([]netip.Prefix(nil), prepared.Capture.TUNAddresses...)
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
	err := lifecycle.stopLocked(ctx)
	if lifecycle.RestartGuard != nil {
		status := lifecycle.RestartGuard.Status()
		if status.Active || status.LastError != "" {
			cleanup, cancel := context.WithTimeout(context.Background(), openWrtRollbackTimeout)
			defer cancel()
			err = errors.Join(err, lifecycle.RestartGuard.Remove(cleanup))
		}
	}
	return err
}

func (lifecycle *Lifecycle) stopLocked(ctx context.Context) error {
	return lifecycle.stopWithCleanupLocked(ctx, false)
}

func (lifecycle *Lifecycle) stopWithCleanupLocked(ctx context.Context, forceCleanup bool) error {
	lifecycle.defaults()
	if err := lifecycle.validate(); err != nil {
		return err
	}
	current := lifecycle.Snapshot()
	if !forceCleanup && current.State == LifecycleStopped && current.Prepared.BinaryPath == "" {
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
	if _, panel := ctx.Value(panelRestartKey{}).(string); panel && lifecycle.RestartGuard != nil && lifecycle.Snapshot().State == LifecycleRunning {
		enabled, err := lifecycle.RestartGuard.Enabled()
		if err != nil {
			return err
		}
		if enabled {
			return lifecycle.restartPreparedLocked(ctx)
		}
	}
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
	if _, panel := ctx.Value(panelRestartKey{}).(string); panel && lifecycle.RestartGuard != nil {
		enabled, err := lifecycle.RestartGuard.Enabled()
		if err != nil {
			return false, err
		}
		if enabled {
			return true, lifecycle.restartPreparedLocked(ctx)
		}
	}
	if err := lifecycle.stopLocked(ctx); err != nil {
		return true, err
	}
	return true, lifecycle.startLocked(ctx)
}

// restartPreparedLocked validates before teardown and shares the exact-runtime
// rollback path used by Save & restart. The operation lock is already held.
func (lifecycle *Lifecycle) restartPreparedLocked(ctx context.Context) error {
	lifecycle.defaults()
	if err := lifecycle.validate(); err != nil {
		return err
	}
	prepareContext, cancel := context.WithTimeout(ctx, lifecycle.PrepareTimeout)
	target, err := lifecycle.Preparer.PrepareActive(prepareContext)
	cancel()
	if err != nil {
		return fmt.Errorf("prepare restart target: %w", err)
	}
	_, err = lifecycle.reconfigurePreparedLocked(ctx, target, nil)
	return err
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
	result.Prepared.Capture.TUNAddresses = append([]netip.Prefix(nil), result.Prepared.Capture.TUNAddresses...)
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
		lifecycle.retryRestartGuardCleanup()
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
		if err := lifecycle.lockOperation(healthContext); err != nil {
			cancel()
			continue
		}
		current = lifecycle.Snapshot()
		if current.State != LifecycleRunning {
			lifecycle.opMu.Unlock()
			cancel()
			controllerFailures = 0
			continue
		}
		health, err := lifecycle.Core.Health(healthContext)
		cancel()
		lifecycle.recordHealth(health, err)
		if !health.Running {
			lifecycle.Logger.Error("core exited; removing capture for fail-open recovery", "error", err)
			recoveryContext, cancelRecovery := lifecycle.recoveryContext()
			_ = lifecycle.stopLocked(recoveryContext)
			cancelRecovery()
			lifecycle.opMu.Unlock()
			controllerFailures = 0
			continue
		}
		prepared := lifecycle.Snapshot().Prepared
		if err != nil || !health.ControllerReady || (prepared.Capture.DNS.Enabled && !health.DNSReady) {
			controllerFailures++
			if controllerFailures >= lifecycle.ControllerFailures {
				lifecycle.Logger.Error("core readiness remained unavailable; removing capture", "failures", controllerFailures, "error", err)
				recoveryContext, cancelRecovery := lifecycle.recoveryContext()
				_ = lifecycle.stopLocked(recoveryContext)
				cancelRecovery()
				controllerFailures = 0
			}
			lifecycle.opMu.Unlock()
			continue
		}
		controllerFailures = 0
		lifecycle.opMu.Unlock()
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

func (lifecycle *Lifecycle) recoveryContext() (context.Context, context.CancelFunc) {
	lifecycle.defaults()
	timeout := lifecycle.StartTimeout + lifecycle.ReadyTimeout + lifecycle.CleanupTimeout + 5*time.Second
	return context.WithTimeout(context.Background(), timeout)
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
