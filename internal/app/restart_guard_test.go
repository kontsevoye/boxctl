package app

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/web"
)

type restartGuardFake struct {
	core                *lifecycleFake
	enabled             bool
	beginErr, removeErr error
	verifyErrs          []error
	status              web.RestartGuardStatus
	onBegin             func()
}

func (guard *restartGuardFake) Enabled() (bool, error) { return guard.enabled, nil }

func (guard *restartGuardFake) Begin(_ context.Context, _ engine.PreparedCore, _ string) (bool, error) {
	if !guard.enabled {
		return false, nil
	}
	guard.core.event("guard-install")
	if guard.onBegin != nil {
		guard.onBegin()
	}
	guard.status.Active = guard.beginErr == nil
	return guard.status.Active, guard.beginErr
}
func (guard *restartGuardFake) Verify(context.Context, engine.PreparedCore) error {
	guard.core.event("guard-verify")
	if len(guard.verifyErrs) == 0 {
		return nil
	}
	err := guard.verifyErrs[0]
	guard.verifyErrs = guard.verifyErrs[1:]
	return err
}
func (guard *restartGuardFake) Remove(context.Context) error {
	guard.core.event("guard-remove")
	if guard.removeErr != nil {
		guard.status.LastError = "cleanup failed"
	} else {
		guard.status = web.RestartGuardStatus{}
	}
	return guard.removeErr
}
func (guard *restartGuardFake) Status() web.RestartGuardStatus { return guard.status }

func guardedLifecycle(t *testing.T) (*Lifecycle, *lifecycleFake, *restartGuardFake) {
	t.Helper()
	old := prepareLifecycleOwnedRuntime(t, t.TempDir())
	target := prepareLifecycleOwnedRuntime(t, t.TempDir())
	core := &lifecycleFake{prepared: target, health: engine.HealthStatus{Running: true, ControllerReady: true}}
	guard := &restartGuardFake{core: core, enabled: true}
	lifecycle := &Lifecycle{Preparer: core, Core: core, Activation: core, RestartGuard: guard, ReadyTimeout: time.Second, ReadyPollInterval: time.Millisecond, snap: LifecycleSnapshot{State: LifecycleRunning, Prepared: old, Health: core.health}}
	t.Cleanup(func() { engine.CleanupPreparedRuntime(lifecycle.Snapshot().Prepared) })
	return lifecycle, core, guard
}

func TestPanelRestartGuardOrderingAndRollback(t *testing.T) {
	for _, failure := range []string{"", "target", "double", "install", "prepare", "remove", "disconnect"} {
		t.Run(failure, func(t *testing.T) {
			lifecycle, core, guard := guardedLifecycle(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch failure {
			case "target":
				guard.verifyErrs = []error{errors.New("bad target"), nil}
			case "double":
				guard.verifyErrs = []error{errors.New("bad target"), errors.New("bad rollback")}
			case "install":
				guard.beginErr = errors.New("nft failed")
			case "prepare":
				core.prepareErr = errors.New("invalid config")
			case "remove":
				guard.removeErr = errors.New("nft busy")
			case "disconnect":
				guard.onBegin = cancel
			}
			err := (LifecycleService{Lifecycle: lifecycle}).Restart(ctx)
			if (err != nil) != (failure != "" && failure != "disconnect") {
				t.Fatalf("error = %v; events=%v", err, core.events)
			}
			if failure == "install" || failure == "prepare" {
				if slices.Contains(core.events, "gateway-deactivate") || slices.Contains(core.events, "core-stop") || guard.status.Active {
					t.Fatalf("failed preflight touched dataplane: %v", core.events)
				}
				return
			}
			wantPrefix := []string{"prepare", "guard-install", "gateway-deactivate", "core-stop", "core-start", "gateway-activate", "guard-verify"}
			if len(core.events) < len(wantPrefix) || !slices.Equal(core.events[:len(wantPrefix)], wantPrefix) || core.events[len(core.events)-1] != "guard-remove" {
				t.Fatalf("ordering = %v", core.events)
			}
			if failure == "remove" {
				if lifecycle.Snapshot().State != LifecycleRunning || !guard.status.Active {
					t.Fatalf("healthy target rolled back: %+v", lifecycle.Snapshot())
				}
				guard.removeErr = nil
				lifecycle.retryRestartGuardCleanup()
			}
			if guard.status.Active {
				t.Fatal("guard survived completed transaction")
			}
			if failure == "double" && lifecycle.Snapshot().State != LifecycleFailed {
				t.Fatalf("double failure state=%s", lifecycle.Snapshot().State)
			}
			if failure != "double" && lifecycle.Snapshot().State != LifecycleRunning {
				t.Fatalf("recovery state=%s", lifecycle.Snapshot().State)
			}
		})
	}
}

func TestRestartGuardOnlyEngagesForRunningPanelActions(t *testing.T) {
	for _, action := range []string{"start", "failed-start", "stop", "background-restart", "background-refresh", "stopped-restart", "disabled"} {
		t.Run(action, func(t *testing.T) {
			lifecycle, core, guard := guardedLifecycle(t)
			var err error
			switch action {
			case "start", "failed-start", "stopped-restart":
				lifecycle.snap.State = LifecycleStopped
				if action == "failed-start" {
					core.startErr = errors.New("cannot start")
				}
				if action == "stopped-restart" {
					err = (LifecycleService{Lifecycle: lifecycle}).Restart(context.Background())
				} else {
					err = lifecycle.Start(context.Background())
				}
			case "stop":
				err = lifecycle.Stop(context.Background())
			case "background-restart":
				err = lifecycle.Restart(context.Background())
			case "background-refresh":
				_, err = lifecycle.RestartIfRunning(context.Background())
			case "disabled":
				guard.enabled = false
				err = (LifecycleService{Lifecycle: lifecycle}).Restart(context.Background())
			}
			if (err != nil) != (action == "failed-start") {
				t.Fatal(err)
			}
			if slices.Contains(core.events, "guard-install") || guard.status.Active {
				t.Fatalf("unexpected guard: %v", core.events)
			}
		})
	}
}

func TestPreparedPanelSwitchAndReconfigureGuard(t *testing.T) {
	for _, switchProfile := range []bool{false, true} {
		lifecycle, core, guard := guardedLifecycle(t)
		ctx := panelRestart(context.Background(), "save-and-restart")
		commit := func() error { core.event("commit"); return nil }
		var err error
		if switchProfile {
			_, err = lifecycle.SwitchPrepared(ctx, core.prepared, commit)
		} else {
			_, err = lifecycle.ReconfigurePrepared(ctx, core.prepared, commit)
		}
		if err != nil {
			t.Fatal(err)
		}
		if core.events[0] != "guard-install" || core.events[len(core.events)-2] != "commit" || core.events[len(core.events)-1] != "guard-remove" || guard.status.Active {
			t.Fatalf("switch=%v events=%v", switchProfile, core.events)
		}
	}
}

func TestRestartGuardSettingsPersistWithoutRestartOrStartupBlock(t *testing.T) {
	service, err := NewSettingsService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service.Lifecycle = &Lifecycle{}
	configures := 0
	service.ConfigureRestartGuard = func(_ context.Context, candidate RuntimeSettings) error { configures++; return nil }
	service.OnChanged = func(_ context.Context, restart bool) error {
		if restart {
			t.Fatal("guard setting restarted the core")
		}
		return nil
	}
	for _, enabled := range []bool{true, false} {
		boot := false
		result, err := service.UpdateSettings(context.Background(), web.SettingsPatch{CoreRestartGuard: &enabled, StartOnBoot: &boot})
		if err != nil {
			t.Fatal(err)
		}
		if result.CoreRestartGuard != enabled || result.StartOnBoot {
			t.Fatalf("settings=%+v", result)
		}
		stored, err := LoadRuntimeSettings(service.State)
		if err != nil || stored.CoreRestartGuard != enabled {
			t.Fatalf("saved=%+v err=%v", stored, err)
		}
	}
	if configures != 2 {
		t.Fatalf("configures=%d", configures)
	}
	enabled := true
	service.ConfigureRestartGuard = func(context.Context, RuntimeSettings) error { return errors.New("offload enabled") }
	if _, err := service.UpdateSettings(context.Background(), web.SettingsPatch{CoreRestartGuard: &enabled}); err == nil {
		t.Fatal("unsupported guard enabled")
	}
	stored, _ := LoadRuntimeSettings(service.State)
	if stored.CoreRestartGuard {
		t.Fatal("failed enable persisted")
	}
	server := "server"
	if _, err := service.UpdateSettings(context.Background(), web.SettingsPatch{CoreRestartGuard: &enabled, OperatingMode: &server}); err == nil {
		t.Fatal("server mode accepted guard")
	}
}

func TestPanelRestartQueuedBehindStopDoesNotGuardStartup(t *testing.T) {
	lifecycle, core, guard := guardedLifecycle(t)
	lifecycle.opMu.Lock()
	done := make(chan error, 1)
	go func() { done <- (LifecycleService{Lifecycle: lifecycle}).Restart(context.Background()) }()
	if err := lifecycle.stopLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	lifecycle.opMu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if guard.status.Active || slices.Contains(core.events, "guard-install") {
		t.Fatalf("guarded queued start: %v", core.events)
	}
}

func TestMonitorCrashDoesNotInstallRestartGuard(t *testing.T) {
	lifecycle, core, guard := guardedLifecycle(t)
	core.health.Running = false
	core.health.ControllerReady = false
	lifecycle.MonitorInterval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	lifecycle.Monitor(ctx)
	if guard.status.Active || slices.Contains(core.events, "guard-install") {
		t.Fatalf("guarded crash: %v", core.events)
	}
	if !slices.Contains(core.events, "gateway-deactivate") {
		t.Fatalf("crash did not clean capture: %v", core.events)
	}
}
