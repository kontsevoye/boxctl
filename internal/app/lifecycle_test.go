package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
)

type lifecycleFake struct {
	mu            sync.Mutex
	events        []string
	prepared      engine.PreparedCore
	health        engine.HealthStatus
	prepareErr    error
	prepareWait   bool
	startErr      error
	startWait     bool
	stopErr       error
	activateErr   error
	deactivateErr error
}

func (fake *lifecycleFake) event(value string) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.events = append(fake.events, value)
}

func (fake *lifecycleFake) PrepareActive(ctx context.Context) (engine.PreparedCore, error) {
	fake.event("prepare")
	if fake.prepareWait {
		<-ctx.Done()
		return fake.prepared, ctx.Err()
	}
	return fake.prepared, fake.prepareErr
}

func (fake *lifecycleFake) Start(ctx context.Context, _ engine.PreparedCore) error {
	fake.event("core-start")
	if fake.startWait {
		<-ctx.Done()
		return ctx.Err()
	}
	if fake.startErr == nil {
		fake.mu.Lock()
		fake.health.Running = true
		fake.health.ControllerReady = true
		fake.mu.Unlock()
	}
	return fake.startErr
}

func (fake *lifecycleFake) Stop(context.Context) error {
	fake.event("core-stop")
	if fake.stopErr != nil {
		return fake.stopErr
	}
	fake.mu.Lock()
	fake.health.Running = false
	fake.health.ControllerReady = false
	fake.mu.Unlock()
	return nil
}

func TestLifecycleStopFailureRetainsPreparedOwnership(t *testing.T) {
	t.Parallel()
	prepared := engine.PreparedCore{Engine: "mihomo", BinaryPath: "/fake/core", RuntimeConfigPath: "/tmp/private.yaml"}
	health := engine.HealthStatus{Running: true, ControllerReady: true, PID: 42}
	fake := &lifecycleFake{health: health, stopErr: errors.New("process did not exit")}
	lifecycle := &Lifecycle{
		Preparer: fake, Core: fake, Activation: fake,
		snap: LifecycleSnapshot{State: LifecycleRunning, Prepared: prepared, Health: health},
	}
	if err := lifecycle.Stop(context.Background()); err == nil {
		t.Fatal("core stop failure succeeded")
	}
	snapshot := lifecycle.Snapshot()
	if snapshot.State != LifecycleFailed || snapshot.Prepared.RuntimeConfigPath != prepared.RuntimeConfigPath || !snapshot.Health.Running {
		t.Fatalf("failed core ownership was discarded: %#v", snapshot)
	}
	if lifecycleAllowsBackupImport(snapshot) {
		t.Fatal("backup import was allowed while core ownership remained uncertain")
	}
}

func (fake *lifecycleFake) Health(context.Context) (engine.HealthStatus, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.health, nil
}

func (fake *lifecycleFake) Activate(context.Context, engine.PreparedCore) error {
	fake.event("gateway-activate")
	return fake.activateErr
}

func (fake *lifecycleFake) Deactivate(context.Context, engine.PreparedCore) error {
	fake.event("gateway-deactivate")
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.deactivateErr
}

func TestLifecycleTransactionOrdering(t *testing.T) {
	t.Parallel()
	fake := &lifecycleFake{
		prepared: engine.PreparedCore{Engine: "mihomo", BinaryPath: "/fake/core"},
		health:   engine.HealthStatus{Running: true, ControllerReady: true, PID: 42, CheckedAt: time.Now()},
	}
	lifecycle := &Lifecycle{
		Preparer: fake, Core: fake, Activation: fake,
		ReadyTimeout: time.Second, ReadyPollInterval: time.Millisecond,
		snap: LifecycleSnapshot{State: LifecycleStopped},
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if lifecycle.Snapshot().State != LifecycleRunning {
		t.Fatalf("unexpected state %#v", lifecycle.Snapshot())
	}
	if err := lifecycle.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"prepare", "core-start", "gateway-activate", "gateway-deactivate", "core-stop"}
	if !slices.Equal(fake.events, want) {
		t.Fatalf("events %v, want %v", fake.events, want)
	}
}

func TestLifecycleClearsPendingFirstStartOnlyAfterSuccessfulActivation(t *testing.T) {
	t.Parallel()
	newLifecycle := func(fake *lifecycleFake, onStarted func() error) *Lifecycle {
		return &Lifecycle{
			Preparer: fake, Core: fake, Activation: fake, OnStarted: onStarted,
			ReadyTimeout: time.Second, ReadyPollInterval: time.Millisecond,
			snap: LifecycleSnapshot{State: LifecycleStopped},
		}
	}

	successful := &lifecycleFake{
		prepared: engine.PreparedCore{Engine: "mihomo", BinaryPath: "/fake/core"},
		health:   engine.HealthStatus{Running: true, ControllerReady: true, PID: 42},
	}
	startRecords := 0
	lifecycle := newLifecycle(successful, func() error {
		startRecords++
		return errors.New("read-only filesystem")
	})
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatalf("successful activation was turned into a failure by marker cleanup: %v", err)
	}
	if startRecords != 1 || lifecycle.Snapshot().State != LifecycleRunning {
		t.Fatalf("successful start persistence calls=%d state=%s", startRecords, lifecycle.Snapshot().State)
	}
	// A repeated Start retries failed persistence without restarting the core.
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if startRecords != 2 {
		t.Fatalf("running lifecycle did not retry marker cleanup: %d", startRecords)
	}

	failed := &lifecycleFake{
		prepared:    engine.PreparedCore{Engine: "mihomo", BinaryPath: "/fake/core"},
		health:      engine.HealthStatus{Running: true, ControllerReady: true, PID: 42},
		activateErr: errors.New("nft failed"),
	}
	failedRecords := 0
	if err := newLifecycle(failed, func() error { failedRecords++; return nil }).Start(context.Background()); err == nil {
		t.Fatal("activation failure was accepted")
	}
	if failedRecords != 0 {
		t.Fatalf("failed activation cleared first-start marker %d times", failedRecords)
	}
}

func TestLifecycleRollsBackActivationFailure(t *testing.T) {
	t.Parallel()
	fake := &lifecycleFake{
		prepared:    engine.PreparedCore{Engine: "mihomo", BinaryPath: "/fake/core"},
		health:      engine.HealthStatus{Running: true, ControllerReady: true, PID: 42},
		activateErr: errors.New("nft failed"),
	}
	lifecycle := &Lifecycle{
		Preparer: fake, Core: fake, Activation: fake,
		ReadyTimeout: time.Second, ReadyPollInterval: time.Millisecond,
		snap: LifecycleSnapshot{State: LifecycleStopped},
	}
	if err := lifecycle.Start(context.Background()); err == nil {
		t.Fatal("activation failure was accepted")
	}
	want := []string{"prepare", "core-start", "gateway-activate", "gateway-deactivate", "core-stop"}
	if !slices.Equal(fake.events, want) {
		t.Fatalf("events %v, want %v", fake.events, want)
	}
	if lifecycle.Snapshot().State != LifecycleFailed {
		t.Fatalf("unexpected state %#v", lifecycle.Snapshot())
	}
}

func TestLifecycleRefusesToRemoveRuntimeWithoutEngineOwnershipProof(t *testing.T) {
	temporaryRoot := filepath.Join(os.TempDir(), "boxctl")
	if err := os.MkdirAll(temporaryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	runtimeDir, err := os.MkdirTemp(temporaryRoot, "lifecycle-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDir) })
	runtimePath := filepath.Join(runtimeDir, "mihomo-start-failure.yaml")
	if err := os.WriteFile(runtimePath, []byte("secret: private\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &lifecycleFake{
		prepared: engine.PreparedCore{Engine: "mihomo", RuntimeConfigPath: runtimePath},
		startErr: errors.New("exec failed"),
	}
	lifecycle := &Lifecycle{
		Preparer: fake, Core: fake, Activation: fake,
		snap: LifecycleSnapshot{State: LifecycleStopped},
	}
	if err := lifecycle.Start(context.Background()); err == nil {
		t.Fatal("core start failure succeeded")
	}
	if _, err := os.Stat(runtimePath); err != nil {
		t.Fatalf("unowned runtime was removed after start failure: %v", err)
	}
	if !slices.Equal(fake.events, []string{"prepare", "core-start", "gateway-deactivate", "core-stop"}) {
		t.Fatalf("start failure did not fail open: %v", fake.events)
	}
}

func TestLifecycleCleansStaleOwnedActivationBeforePrepareFailure(t *testing.T) {
	t.Parallel()
	for _, state := range []LifecycleState{"", LifecycleFailed} {
		state := state
		t.Run(string(state), func(t *testing.T) {
			t.Parallel()
			fake := &lifecycleFake{prepareErr: errors.New("broken profile")}
			lifecycle := &Lifecycle{
				Preparer: fake, Core: fake, Activation: fake,
				snap: LifecycleSnapshot{State: state},
			}
			if err := lifecycle.Start(context.Background()); err == nil {
				t.Fatal("prepare failure succeeded")
			}
			want := []string{"gateway-deactivate", "core-stop", "prepare"}
			if !slices.Equal(fake.events, want) {
				t.Fatalf("events %v, want one cleanup before prepare: %v", fake.events, want)
			}
			if lifecycle.Snapshot().State != LifecycleFailed {
				t.Fatalf("unexpected state %#v", lifecycle.Snapshot())
			}
		})
	}
}

func TestLifecycleBoundsPrepareWithoutCleaningKnownStoppedState(t *testing.T) {
	t.Parallel()
	fake := &lifecycleFake{prepareWait: true}
	lifecycle := &Lifecycle{
		Preparer: fake, Core: fake, Activation: fake,
		PrepareTimeout: 10 * time.Millisecond,
		snap:           LifecycleSnapshot{State: LifecycleStopped},
	}
	err := lifecycle.Start(context.Background())
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Start() error = %v, want prepare deadline", err)
	}
	if !slices.Equal(fake.events, []string{"prepare"}) {
		t.Fatalf("known stopped state received unnecessary cleanup: %v", fake.events)
	}
}

func TestLifecycleBoundsCoreStart(t *testing.T) {
	t.Parallel()
	fake := &lifecycleFake{startWait: true}
	lifecycle := &Lifecycle{
		Preparer: fake, Core: fake, Activation: fake,
		StartTimeout: 10 * time.Millisecond,
		snap:         LifecycleSnapshot{State: LifecycleStopped},
	}
	err := lifecycle.Start(context.Background())
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Start() error = %v, want core-start deadline", err)
	}
	want := []string{"prepare", "core-start", "gateway-deactivate", "core-stop"}
	if !slices.Equal(fake.events, want) {
		t.Fatalf("bounded core-start events = %v, want %v", fake.events, want)
	}
}

func TestLifecycleStartCanceledContextDoesNotTouchDependencies(t *testing.T) {
	t.Parallel()
	fake := &lifecycleFake{}
	lifecycle := &Lifecycle{Preparer: fake, Core: fake, Activation: fake}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := lifecycle.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start() error = %v, want context canceled", err)
	}
	if len(fake.events) != 0 {
		t.Fatalf("canceled Start touched dependencies: %v", fake.events)
	}
}

func TestLifecycleOperationLockRespectsContext(t *testing.T) {
	t.Parallel()
	fake := &lifecycleFake{}
	lifecycle := &Lifecycle{Preparer: fake, Core: fake, Activation: fake}
	lifecycle.opMu.Lock()
	defer lifecycle.opMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := lifecycle.Stop(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop() error = %v, want operation-lock deadline", err)
	}
	if len(fake.events) != 0 {
		t.Fatalf("timed-out Stop touched dependencies: %v", fake.events)
	}
}

func TestLifecycleRestartIfRunningChecksStateUnderOperationLock(t *testing.T) {
	t.Parallel()
	fake := &lifecycleFake{
		prepared: engine.PreparedCore{Engine: "mihomo", BinaryPath: "/fake/core"},
		health:   engine.HealthStatus{Running: true, ControllerReady: true, PID: 42},
	}
	lifecycle := &Lifecycle{
		Preparer: fake, Core: fake, Activation: fake,
		ReadyTimeout: time.Second, ReadyPollInterval: time.Millisecond,
		snap: LifecycleSnapshot{
			State:    LifecycleRunning,
			Prepared: engine.PreparedCore{Engine: "mihomo", BinaryPath: "/fake/old-core"},
		},
	}

	lifecycle.opMu.Lock()
	result := make(chan struct {
		restarted bool
		err       error
	}, 1)
	go func() {
		restarted, err := lifecycle.RestartIfRunning(context.Background())
		result <- struct {
			restarted bool
			err       error
		}{restarted: restarted, err: err}
	}()

	// Simulate an explicit Stop or crash-monitor cleanup completing while the
	// refresh request is queued behind the same operation gate.
	lifecycle.mu.Lock()
	lifecycle.snap.State = LifecycleStopped
	lifecycle.snap.Prepared = engine.PreparedCore{}
	lifecycle.mu.Unlock()
	lifecycle.opMu.Unlock()

	got := <-result
	if got.err != nil || got.restarted {
		t.Fatalf("RestartIfRunning() = (%v, %v), want (false, nil)", got.restarted, got.err)
	}
	if len(fake.events) != 0 {
		t.Fatalf("stopped lifecycle was touched: %v", fake.events)
	}
}

func TestLifecycleCleanupContextCapsLongParentDeadline(t *testing.T) {
	t.Parallel()
	lifecycle := &Lifecycle{CleanupTimeout: 40 * time.Millisecond}
	parent, cancelParent := context.WithTimeout(context.Background(), time.Hour)
	defer cancelParent()

	started := time.Now()
	cleanup, cancelCleanup := lifecycle.cleanupContext(parent)
	defer cancelCleanup()
	deadline, ok := cleanup.Deadline()
	if !ok {
		t.Fatal("cleanup context has no deadline")
	}
	remaining := deadline.Sub(started)
	if remaining <= 0 || remaining > 2*lifecycle.CleanupTimeout {
		t.Fatalf("cleanup deadline = %v, want at most %v", remaining, lifecycle.CleanupTimeout)
	}
}

func TestLifecycleCleanupContextKeepsShorterParentDeadlineAndDetachesCancellation(t *testing.T) {
	t.Parallel()
	lifecycle := &Lifecycle{CleanupTimeout: time.Second}
	parent, cancelParent := context.WithTimeout(context.Background(), 100*time.Millisecond)
	parentDeadline, _ := parent.Deadline()
	cleanup, cancelCleanup := lifecycle.cleanupContext(parent)
	defer cancelCleanup()
	cleanupDeadline, ok := cleanup.Deadline()
	if !ok || !cleanupDeadline.Equal(parentDeadline) {
		t.Fatalf("cleanup deadline = %v, want parent deadline %v", cleanupDeadline, parentDeadline)
	}
	cancelParent()
	if err := cleanup.Err(); err != nil {
		t.Fatalf("cleanup inherited parent cancellation: %v", err)
	}
}

func TestLifecycleCleanupContextDoesNotExtendExpiredParentDeadline(t *testing.T) {
	t.Parallel()
	lifecycle := &Lifecycle{CleanupTimeout: time.Second}
	parentDeadline := time.Now().Add(-time.Second)
	parent, cancelParent := context.WithDeadline(context.Background(), parentDeadline)
	defer cancelParent()

	cleanup, cancelCleanup := lifecycle.cleanupContext(parent)
	defer cancelCleanup()
	cleanupDeadline, ok := cleanup.Deadline()
	if !ok || !cleanupDeadline.Equal(parentDeadline) {
		t.Fatalf("cleanup deadline = %v, want expired parent deadline %v", cleanupDeadline, parentDeadline)
	}
	if !errors.Is(cleanup.Err(), context.DeadlineExceeded) {
		t.Fatalf("cleanup error = %v, want deadline exceeded", cleanup.Err())
	}
}

func TestLifecycleStopKeepsCoreAliveWhenActivationCleanupFails(t *testing.T) {
	t.Parallel()
	prepared := engine.PreparedCore{Engine: "mihomo", BinaryPath: "/fake/core"}
	health := engine.HealthStatus{Running: true, ControllerReady: true, PID: 42}
	fake := &lifecycleFake{
		prepared: prepared, health: health,
		deactivateErr: errors.New("dns restore failed"),
	}
	lifecycle := &Lifecycle{
		Preparer: fake, Core: fake, Activation: fake,
		snap: LifecycleSnapshot{State: LifecycleRunning, Prepared: prepared, Health: health},
	}
	if err := lifecycle.Stop(context.Background()); err == nil {
		t.Fatal("activation cleanup failure was accepted")
	}
	if !slices.Equal(fake.events, []string{"gateway-deactivate"}) {
		t.Fatalf("core was touched after activation cleanup failure: %v", fake.events)
	}
	snapshot := lifecycle.Snapshot()
	if snapshot.State != LifecycleCleanupFailed || snapshot.Prepared.BinaryPath != prepared.BinaryPath || !snapshot.Health.Running {
		t.Fatalf("running core state was not preserved: %#v", snapshot)
	}
	if err := lifecycle.Start(context.Background()); err == nil {
		t.Fatal("Start succeeded over unresolved cleanup")
	}
	if !slices.Equal(fake.events, []string{"gateway-deactivate"}) {
		t.Fatalf("Start reactivated over unresolved cleanup: %v", fake.events)
	}
}

func TestLifecycleAdoptDoesNotTouchCoreOrActivation(t *testing.T) {
	t.Parallel()
	fake := &lifecycleFake{}
	prepared := engine.PreparedCore{Engine: "mihomo", BinaryPath: "/fake/core"}
	health := engine.HealthStatus{Running: true, ControllerReady: true, PID: 42, StartedAt: time.Now().Add(-time.Hour), CheckedAt: time.Now()}
	lifecycle := &Lifecycle{Preparer: fake, Core: fake, Activation: fake}
	if err := lifecycle.Adopt(prepared, health); err != nil {
		t.Fatal(err)
	}
	if len(fake.events) != 0 {
		t.Fatalf("adoption mutated runtime: %v", fake.events)
	}
	snapshot := lifecycle.Snapshot()
	if snapshot.State != LifecycleRunning || snapshot.Health.PID != 42 || snapshot.Prepared.BinaryPath != prepared.BinaryPath {
		t.Fatalf("adopted snapshot = %#v", snapshot)
	}
}

func TestLifecycleRollbackKeepsCoreAliveWhenActivationCleanupFails(t *testing.T) {
	t.Parallel()
	prepared := engine.PreparedCore{Engine: "mihomo", BinaryPath: "/fake/core"}
	health := engine.HealthStatus{Running: true, ControllerReady: true, PID: 42}
	fake := &lifecycleFake{
		prepared: prepared, health: health,
		activateErr:   errors.New("dns activation failed"),
		deactivateErr: errors.New("dns rollback failed"),
	}
	lifecycle := &Lifecycle{
		Preparer: fake, Core: fake, Activation: fake,
		ReadyTimeout: time.Second, ReadyPollInterval: time.Millisecond,
		snap: LifecycleSnapshot{State: LifecycleStopped},
	}
	if err := lifecycle.Start(context.Background()); err == nil {
		t.Fatal("activation and rollback failure was accepted")
	}
	want := []string{"prepare", "core-start", "gateway-activate", "gateway-deactivate"}
	if !slices.Equal(fake.events, want) {
		t.Fatalf("core was stopped after activation rollback failure: %v, want %v", fake.events, want)
	}
	snapshot := lifecycle.Snapshot()
	if snapshot.State != LifecycleCleanupFailed || snapshot.Prepared.BinaryPath != prepared.BinaryPath || !snapshot.Health.Running {
		t.Fatalf("running core was not retained for cleanup retry: %#v", snapshot)
	}
}

func TestLifecycleMonitorRetriesActivationCleanupBeforeStoppingCore(t *testing.T) {
	t.Parallel()
	prepared := engine.PreparedCore{Engine: "mihomo", BinaryPath: "/fake/core"}
	health := engine.HealthStatus{Running: true, ControllerReady: true, PID: 42}
	fake := &lifecycleFake{
		prepared: prepared, health: health,
		deactivateErr: errors.New("nft busy"),
	}
	lifecycle := &Lifecycle{
		Preparer: fake, Core: fake, Activation: fake,
		MonitorInterval: 5 * time.Millisecond,
		snap:            LifecycleSnapshot{State: LifecycleRunning, Prepared: prepared, Health: health},
	}
	if err := lifecycle.Stop(context.Background()); err == nil {
		t.Fatal("initial cleanup failure was accepted")
	}
	fake.mu.Lock()
	fake.deactivateErr = nil
	fake.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go lifecycle.Monitor(ctx)
	for lifecycle.Snapshot().State != LifecycleStopped {
		select {
		case <-ctx.Done():
			t.Fatalf("monitor did not retry cleanup; events=%v state=%#v", fake.events, lifecycle.Snapshot())
		case <-time.After(5 * time.Millisecond):
		}
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	want := []string{"gateway-deactivate", "gateway-deactivate", "core-stop"}
	if !slices.Equal(fake.events, want) {
		t.Fatalf("events %v, want %v", fake.events, want)
	}
}

func TestLifecycleRequiresDNSReadinessBeforeActivation(t *testing.T) {
	t.Parallel()
	fake := &lifecycleFake{
		prepared: engine.PreparedCore{
			Engine: "mihomo", BinaryPath: "/fake/core",
			Capture: engine.CapturePlan{DNS: engine.DNSEndpoint{Enabled: true, Host: "127.0.0.1", Port: 7874}},
		},
		health: engine.HealthStatus{Running: true, ControllerReady: true, DNSReady: false, PID: 42},
	}
	lifecycle := &Lifecycle{
		Preparer: fake, Core: fake, Activation: fake,
		ReadyTimeout: 20 * time.Millisecond, ReadyPollInterval: time.Millisecond,
		snap: LifecycleSnapshot{State: LifecycleStopped},
	}
	err := lifecycle.Start(context.Background())
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Start() error = %v, want readiness deadline", err)
	}
	want := []string{"prepare", "core-start", "gateway-deactivate", "core-stop"}
	if !slices.Equal(fake.events, want) {
		t.Fatalf("events %v, want %v", fake.events, want)
	}
	if lifecycle.Snapshot().State != LifecycleFailed {
		t.Fatalf("unexpected state %#v", lifecycle.Snapshot())
	}
}

func TestLifecycleAcceptsReadyDNSListener(t *testing.T) {
	t.Parallel()
	fake := &lifecycleFake{
		prepared: engine.PreparedCore{
			Engine: "mihomo", BinaryPath: "/fake/core",
			Capture: engine.CapturePlan{DNS: engine.DNSEndpoint{Enabled: true, Host: "127.0.0.1", Port: 7874}},
		},
		health: engine.HealthStatus{Running: true, ControllerReady: true, DNSReady: true, PID: 42},
	}
	lifecycle := &Lifecycle{
		Preparer: fake, Core: fake, Activation: fake,
		ReadyTimeout: time.Second, ReadyPollInterval: time.Millisecond,
		snap: LifecycleSnapshot{State: LifecycleStopped},
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fake.events, []string{"prepare", "core-start", "gateway-activate"}) {
		t.Fatalf("unexpected events %v", fake.events)
	}
}

func TestLifecycleRecoveredHealthClearsTransientError(t *testing.T) {
	t.Parallel()
	lifecycle := &Lifecycle{snap: LifecycleSnapshot{
		State: LifecycleRunning,
		Prepared: engine.PreparedCore{Capture: engine.CapturePlan{
			DNS: engine.DNSEndpoint{Enabled: true, Host: "127.0.0.1", Port: 7874},
		}},
		Health:    engine.HealthStatus{Running: true, PID: 42},
		LastError: "controller request timed out",
	}}

	lifecycle.recordHealth(engine.HealthStatus{
		Running: true, ControllerReady: true, DNSReady: true, PID: 42,
	}, nil)

	snapshot := lifecycle.Snapshot()
	if snapshot.LastError != "" {
		t.Fatalf("recovered health retained error %q", snapshot.LastError)
	}
}

func TestLifecycleHealthKeepsErrorUntilRunningCoreIsFullyReady(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		state  LifecycleState
		health engine.HealthStatus
	}{
		{name: "controller unavailable", state: LifecycleRunning, health: engine.HealthStatus{Running: true, PID: 42}},
		{name: "DNS unavailable", state: LifecycleRunning, health: engine.HealthStatus{Running: true, ControllerReady: true, PID: 42}},
		{name: "failed lifecycle", state: LifecycleFailed, health: engine.HealthStatus{Running: true, ControllerReady: true, DNSReady: true, PID: 42}},
		{name: "cleanup failed", state: LifecycleCleanupFailed, health: engine.HealthStatus{Running: true, ControllerReady: true, DNSReady: true, PID: 42}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			lifecycle := &Lifecycle{snap: LifecycleSnapshot{
				State: test.state,
				Prepared: engine.PreparedCore{Capture: engine.CapturePlan{
					DNS: engine.DNSEndpoint{Enabled: true, Host: "127.0.0.1", Port: 7874},
				}},
				LastError: "operation failed",
			}}

			lifecycle.recordHealth(test.health, nil)

			if snapshot := lifecycle.Snapshot(); snapshot.LastError != "operation failed" {
				t.Fatalf("health cleared lifecycle error in state %q: %#v", test.state, snapshot)
			}
		})
	}
}

func TestMonitorFailsOpenAfterCoreExit(t *testing.T) {
	t.Parallel()
	fake := &lifecycleFake{
		prepared: engine.PreparedCore{Engine: "mihomo", BinaryPath: "/fake/core"},
		health:   engine.HealthStatus{Running: true, ControllerReady: true, PID: 42},
	}
	lifecycle := &Lifecycle{
		Preparer: fake, Core: fake, Activation: fake,
		ReadyTimeout: time.Second, ReadyPollInterval: time.Millisecond, MonitorInterval: 5 * time.Millisecond,
		snap: LifecycleSnapshot{State: LifecycleStopped},
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.health = engine.HealthStatus{Running: false, LastExitError: "exited"}
	fake.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go lifecycle.Monitor(ctx)
	for lifecycle.Snapshot().State != LifecycleStopped {
		select {
		case <-ctx.Done():
			t.Fatalf("monitor did not fail open; events=%v state=%#v", fake.events, lifecycle.Snapshot())
		case <-time.After(5 * time.Millisecond):
		}
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if !slices.Contains(fake.events, "gateway-deactivate") || !slices.Contains(fake.events, "core-stop") {
		t.Fatalf("cleanup missing from %v", fake.events)
	}
}
