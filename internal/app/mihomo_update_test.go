package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/update"
)

type updateSourceFake struct{ release update.Release }

func (source updateSourceFake) Latest(context.Context, update.Channel) (update.Release, error) {
	return source.release, nil
}

type updateInstallerFake struct{ content []byte }

func (installer updateInstallerFake) Stage(_ context.Context, _ update.Asset, directory string) (string, error) {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(directory, ".mihomo-staged-test-*")
	if err != nil {
		return "", err
	}
	path := file.Name()
	if _, err := file.Write(installer.content); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0o755); err != nil {
		return "", err
	}
	return path, nil
}

type fileVersioner struct{}

func (fileVersioner) Version(_ context.Context, path string) (string, error) {
	content, err := os.ReadFile(path)
	return string(content), err
}

type coreVersionerFunc func(context.Context, string) (string, error)

func (versioner coreVersionerFunc) Version(ctx context.Context, path string) (string, error) {
	return versioner(ctx, path)
}

type cancelOnNthStartCore struct {
	CoreRuntime
	cancel context.CancelFunc
	nth    int
	calls  int
}

type blockingUpdatePreparer struct{}

func (blockingUpdatePreparer) PrepareActive(ctx context.Context) (engine.PreparedCore, error) {
	<-ctx.Done()
	return engine.PreparedCore{}, ctx.Err()
}

type blockingUpdateActivation struct{}

func (blockingUpdateActivation) Activate(context.Context, engine.PreparedCore) error { return nil }
func (blockingUpdateActivation) Deactivate(ctx context.Context, _ engine.PreparedCore) error {
	<-ctx.Done()
	return ctx.Err()
}

func (core *cancelOnNthStartCore) Start(ctx context.Context, prepared engine.PreparedCore) error {
	core.calls++
	err := core.CoreRuntime.Start(ctx, prepared)
	if core.calls == core.nth {
		core.cancel()
	}
	return err
}

func TestMihomoUpdateStatusAndRunningInstall(t *testing.T) {
	root := t.TempDir()
	service, lifecycleFake := newUpdateServiceForTest(t, root, []byte("Mihomo Meta v1.19.30\n"))
	if err := service.Lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := service.CoreUpdateStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.CurrentVersion != "v1.19.29" || status.LatestVersion != "v1.19.30" || !status.UpdateAvailable || status.Channel != "stable" {
		t.Fatalf("status = %+v", status)
	}
	result, err := service.InstallCoreUpdate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.PreviousVersion != "v1.19.29" || result.CurrentVersion != "v1.19.30" || !result.Restarted {
		t.Fatalf("result = %+v", result)
	}
	target, _ := service.Preparer.binaryPath()
	assertUpdateFile(t, target, "Mihomo Meta v1.19.30\n")
	assertUpdateFile(t, target+".prev", "Mihomo Meta v1.19.29\n")
	if service.Lifecycle.Snapshot().State != LifecycleRunning {
		t.Fatalf("lifecycle after update = %+v", service.Lifecycle.Snapshot())
	}
	lifecycleFake.mu.Lock()
	events := append([]string(nil), lifecycleFake.events...)
	lifecycleFake.mu.Unlock()
	wantTail := []string{"gateway-deactivate", "core-stop", "prepare", "core-start", "gateway-activate"}
	if len(events) < len(wantTail) {
		t.Fatalf("events = %v", events)
	}
	for index := range wantTail {
		if got := events[len(events)-len(wantTail)+index]; got != wantTail[index] {
			t.Fatalf("events tail = %v, want %v", events, wantTail)
		}
	}
}

func TestMihomoUpdateStatusAndCleanInstallWithoutProfile(t *testing.T) {
	root := t.TempDir()
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	fake := &lifecycleFake{}
	lifecycle := &Lifecycle{
		Preparer: fake, Core: fake, Activation: fake,
		snap: LifecycleSnapshot{State: LifecycleFailed},
	}
	service := &MihomoUpdateService{
		Preparer: &ActiveMihomoPreparer{Layout: layout}, Lifecycle: lifecycle,
		Versioner: fileVersioner{}, State: store,
		Source:    updateSourceFake{release: testMihomoRelease()},
		Installer: updateInstallerFake{content: []byte("Mihomo Meta v1.19.30\n")},
		install:   update.Install, rollback: update.Rollback,
	}

	status, err := service.CoreUpdateStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.CurrentVersion != "" || status.LatestVersion != "v1.19.30" || !status.UpdateAvailable {
		t.Fatalf("clean-install status = %+v", status)
	}

	result, err := service.InstallCoreUpdate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.PreviousVersion != "" || result.CurrentVersion != "v1.19.30" || result.Restarted {
		t.Fatalf("clean-install result = %+v", result)
	}
	target := filepath.Join(layout.EnginesDir, "mihomo", "mihomo")
	assertUpdateFile(t, target, "Mihomo Meta v1.19.30\n")
	if _, err := os.Lstat(target + ".prev"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("clean install created rollback binary: %v", err)
	}
}

func TestMihomoUpdateLeavesRunningSingBoxUntouched(t *testing.T) {
	root := t.TempDir()
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(layout.EnginesDir, state.EngineMihomo, state.EngineMihomo)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("Mihomo Meta v1.19.29\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := state.NewProfileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	selected := state.ActiveProfile{Name: "selected", Engine: state.EngineSingBox}
	if err := profiles.Create(context.Background(), selected, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Activate(context.Background(), selected); err != nil {
		t.Fatal(err)
	}
	fake := &lifecycleFake{health: engine.HealthStatus{Running: true, ControllerReady: true, PID: 42}}
	lifecycle := &Lifecycle{
		Preparer: fake, Core: fake, Activation: fake,
		snap: LifecycleSnapshot{
			State:    LifecycleRunning,
			Prepared: engine.PreparedCore{Engine: state.EngineSingBox, BinaryPath: "/managed/sing-box"},
			Health:   engine.HealthStatus{Running: true, ControllerReady: true, PID: 42},
		},
	}
	service := &MihomoUpdateService{
		Preparer: &ActiveMihomoPreparer{Layout: layout, Profiles: profiles}, Lifecycle: lifecycle,
		Versioner: fileVersioner{}, State: store, Source: updateSourceFake{release: testMihomoRelease()},
		Installer: updateInstallerFake{content: []byte("Mihomo Meta v1.19.30\n")},
		install:   update.Install, rollback: update.Rollback,
	}

	result, err := service.InstallCoreUpdate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Restarted {
		t.Fatalf("inactive Mihomo update restarted the selected engine: %+v", result)
	}
	snapshot := lifecycle.Snapshot()
	if snapshot.State != LifecycleRunning || snapshot.Prepared.Engine != state.EngineSingBox || !snapshot.Health.Running {
		t.Fatalf("running sing-box changed during inactive Mihomo update: %+v", snapshot)
	}
	fake.mu.Lock()
	events := append([]string(nil), fake.events...)
	fake.mu.Unlock()
	if len(events) != 0 {
		t.Fatalf("inactive Mihomo update touched the running lifecycle: %v", events)
	}
	assertUpdateFile(t, target, "Mihomo Meta v1.19.30\n")
}

func TestStagedMihomoValidatorChecksOnlyBinaryWhenSingBoxIsSelected(t *testing.T) {
	root := t.TempDir()
	profiles, err := state.NewProfileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	selected := state.ActiveProfile{Name: "selected", Engine: state.EngineSingBox}
	if err := profiles.Create(context.Background(), selected, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Activate(context.Background(), selected); err != nil {
		t.Fatal(err)
	}
	versionCalls := 0
	validator := &stagedMihomoValidator{
		Preparer: &ActiveMihomoPreparer{Profiles: profiles},
		Versioner: coreVersionerFunc(func(context.Context, string) (string, error) {
			versionCalls++
			return "Mihomo Meta v1.19.30", nil
		}),
	}

	if err := validator.ValidateBinary(context.Background(), "/staged/mihomo"); err != nil {
		t.Fatal(err)
	}
	if versionCalls != 1 {
		t.Fatalf("staged binary version checks = %d, want 1", versionCalls)
	}
}

func TestMihomoUpdateRollsBackWhenNewCoreCannotStart(t *testing.T) {
	root := t.TempDir()
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(layout.EnginesDir, "mihomo", "mihomo")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("Mihomo Meta v1.19.29\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	fake := &binaryAwareLifecycleFake{target: target}
	lifecycle := &Lifecycle{Preparer: fake, Core: fake, Activation: fake, ReadyTimeout: time.Second, ReadyPollInterval: time.Millisecond}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	service := &MihomoUpdateService{
		Preparer: &ActiveMihomoPreparer{Layout: layout}, Lifecycle: lifecycle, Versioner: fileVersioner{}, State: store,
		Source: updateSourceFake{release: testMihomoRelease()}, Installer: updateInstallerFake{content: []byte("Mihomo Meta v1.19.30\n")},
		install: update.Install, rollback: update.Rollback,
	}
	if _, err := service.InstallCoreUpdate(context.Background()); err == nil || !errors.Is(err, errRejectedUpdatedCore) {
		t.Fatalf("InstallCoreUpdate() error = %v", err)
	}
	assertUpdateFile(t, target, "Mihomo Meta v1.19.29\n")
	assertUpdateFile(t, target+".failed", "Mihomo Meta v1.19.30\n")
	if lifecycle.Snapshot().State != LifecycleRunning {
		t.Fatalf("previous core was not restored: %+v", lifecycle.Snapshot())
	}
}

func TestMihomoUpdateRollsBackAndRestartsPreviousCoreWhenVersionCheckFails(t *testing.T) {
	root := t.TempDir()
	service, _ := newUpdateServiceForTest(t, root, []byte("Mihomo Meta v1.19.30\n"))
	if err := service.Lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	versionErr := errors.New("version command failed")
	versionCalls := 0
	service.Versioner = coreVersionerFunc(func(_ context.Context, path string) (string, error) {
		versionCalls++
		if versionCalls == 2 {
			return "", versionErr
		}
		return fileVersioner{}.Version(context.Background(), path)
	})
	if _, err := service.InstallCoreUpdate(context.Background()); !errors.Is(err, versionErr) {
		t.Fatalf("InstallCoreUpdate() error = %v, want version failure", err)
	}
	target, _ := service.Preparer.binaryPath()
	assertUpdateFile(t, target, "Mihomo Meta v1.19.29\n")
	assertUpdateFile(t, target+".failed", "Mihomo Meta v1.19.30\n")
	if service.Lifecycle.Snapshot().State != LifecycleRunning {
		t.Fatalf("previous running lifecycle was not restored: %+v", service.Lifecycle.Snapshot())
	}
}

func TestMihomoUpdateRollsBackVersionMismatchAndKeepsStoppedLifecycle(t *testing.T) {
	root := t.TempDir()
	service, _ := newUpdateServiceForTest(t, root, []byte("Mihomo Meta v1.19.31\n"))
	service.Lifecycle.snap = LifecycleSnapshot{State: LifecycleStopped}

	if _, err := service.InstallCoreUpdate(context.Background()); err == nil || !strings.Contains(err.Error(), "got v1.19.31, want v1.19.30") {
		t.Fatalf("InstallCoreUpdate() error = %v, want version mismatch", err)
	}
	target, _ := service.Preparer.binaryPath()
	assertUpdateFile(t, target, "Mihomo Meta v1.19.29\n")
	assertUpdateFile(t, target+".failed", "Mihomo Meta v1.19.31\n")
	if service.Lifecycle.Snapshot().State != LifecycleStopped {
		t.Fatalf("previous stopped lifecycle changed: %+v", service.Lifecycle.Snapshot())
	}
}

func TestMihomoUpdateFinishesSwapAfterClientDisconnect(t *testing.T) {
	root := t.TempDir()
	service, _ := newUpdateServiceForTest(t, root, []byte("Mihomo Meta v1.19.30\n"))
	if err := service.Lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	requestContext, cancelRequest := context.WithCancel(context.Background())
	originalInstall := service.install
	service.install = func(staged, target string) error {
		err := originalInstall(staged, target)
		cancelRequest()
		return err
	}
	result, err := service.InstallCoreUpdate(requestContext)
	if err != nil {
		t.Fatalf("InstallCoreUpdate() after client disconnect = %v", err)
	}
	if !result.Restarted || service.Lifecycle.Snapshot().State != LifecycleRunning {
		t.Fatalf("detached transaction did not restart core: result=%+v lifecycle=%+v", result, service.Lifecycle.Snapshot())
	}
}

func TestMihomoUpdateRollsBackSwapOnManagerShutdown(t *testing.T) {
	root := t.TempDir()
	service, _ := newUpdateServiceForTest(t, root, []byte("Mihomo Meta v1.19.30\n"))
	managerContext, cancelManager := context.WithCancel(context.Background())
	service.ServiceContext = managerContext
	if err := service.Lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	originalInstall := service.install
	service.install = func(staged, target string) error {
		err := originalInstall(staged, target)
		cancelManager()
		return err
	}
	_, err := service.InstallCoreUpdate(context.Background())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("InstallCoreUpdate() error = %v, want manager cancellation", err)
	}
	target, _ := service.Preparer.binaryPath()
	assertUpdateFile(t, target, "Mihomo Meta v1.19.29\n")
	assertUpdateFile(t, target+".failed", "Mihomo Meta v1.19.30\n")
	if service.Lifecycle.Snapshot().State != LifecycleStopped {
		t.Fatalf("shutdown transaction reactivated core: %+v", service.Lifecycle.Snapshot())
	}
}

func TestMihomoUpdateRollsBackWhenManagerCancelsAfterVersionCheck(t *testing.T) {
	root := t.TempDir()
	service, _ := newUpdateServiceForTest(t, root, []byte("Mihomo Meta v1.19.30\n"))
	service.Lifecycle.snap = LifecycleSnapshot{State: LifecycleStopped}
	managerContext, cancelManager := context.WithCancel(context.Background())
	service.ServiceContext = managerContext
	versionCalls := 0
	service.Versioner = coreVersionerFunc(func(_ context.Context, path string) (string, error) {
		versionCalls++
		version, err := fileVersioner{}.Version(context.Background(), path)
		if versionCalls == 2 {
			cancelManager()
		}
		return version, err
	})

	if _, err := service.InstallCoreUpdate(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("InstallCoreUpdate() error = %v, want manager cancellation", err)
	}
	target, _ := service.Preparer.binaryPath()
	assertUpdateFile(t, target, "Mihomo Meta v1.19.29\n")
	assertUpdateFile(t, target+".failed", "Mihomo Meta v1.19.30\n")
	if service.Lifecycle.Snapshot().State != LifecycleStopped {
		t.Fatalf("canceled stopped lifecycle changed: %+v", service.Lifecycle.Snapshot())
	}
}

func TestMihomoUpdateLeavesPreviousCoreStoppedWhenShutdownRacesWithRestart(t *testing.T) {
	root := t.TempDir()
	service, fake := newUpdateServiceForTest(t, root, []byte("Mihomo Meta v1.19.30\n"))
	managerContext, cancelManager := context.WithCancel(context.Background())
	service.ServiceContext = managerContext
	service.Lifecycle.Core = &cancelOnNthStartCore{CoreRuntime: fake, cancel: cancelManager, nth: 3}
	if err := service.Lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	versionErr := errors.New("version command failed")
	versionCalls := 0
	service.Versioner = coreVersionerFunc(func(_ context.Context, path string) (string, error) {
		versionCalls++
		if versionCalls == 2 {
			return "", versionErr
		}
		return fileVersioner{}.Version(context.Background(), path)
	})

	if _, err := service.InstallCoreUpdate(context.Background()); !errors.Is(err, versionErr) {
		t.Fatalf("InstallCoreUpdate() error = %v, want version failure", err)
	}
	target, _ := service.Preparer.binaryPath()
	assertUpdateFile(t, target, "Mihomo Meta v1.19.29\n")
	assertUpdateFile(t, target+".failed", "Mihomo Meta v1.19.30\n")
	if service.Lifecycle.Snapshot().State != LifecycleStopped {
		t.Fatalf("shutdown race left a core running: %+v", service.Lifecycle.Snapshot())
	}
}

func TestMihomoUpdateRecoveryReleasesLifecycleGateWithinShutdownSlice(t *testing.T) {
	t.Parallel()
	if mihomoUpdateRecoveryTimeout+2*defaultLifecycleCleanupTimeout+shutdownHandoffBudget > gracefulShutdownBudget {
		t.Fatalf("update recovery budget %v does not preserve shutdown cleanup reserve within %v", mihomoUpdateRecoveryTimeout, gracefulShutdownBudget)
	}

	for _, test := range []struct {
		name      string
		lifecycle *Lifecycle
	}{
		{
			name: "blocked stop",
			lifecycle: &Lifecycle{
				Preparer: blockingUpdatePreparer{}, Core: &lifecycleFake{}, Activation: blockingUpdateActivation{}, CleanupTimeout: time.Second,
				snap: LifecycleSnapshot{State: LifecycleRunning, Prepared: engine.PreparedCore{Engine: "mihomo"}, Health: engine.HealthStatus{Running: true}},
			},
		},
		{
			name: "blocked restart",
			lifecycle: &Lifecycle{
				Preparer: blockingUpdatePreparer{}, Core: &lifecycleFake{}, Activation: &lifecycleFake{}, CleanupTimeout: time.Second,
				snap: LifecycleSnapshot{State: LifecycleStopped},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			const recoveryTimeout = 40 * time.Millisecond
			service := &MihomoUpdateService{
				Lifecycle: test.lifecycle, ServiceContext: context.Background(), recoveryTimeout: recoveryTimeout,
				rollback: func(string) error { return nil },
			}
			test.lifecycle.opMu.Lock()
			recoveryDone := make(chan error, 1)
			go func() {
				defer test.lifecycle.opMu.Unlock()
				recoveryDone <- service.rollbackSwappedUpdate("ignored", true, true, errors.New("candidate failed"))
			}()

			started := time.Now()
			gateContext, cancelGate := context.WithTimeout(context.Background(), 10*recoveryTimeout)
			defer cancelGate()
			if err := test.lifecycle.lockOperation(gateContext); err != nil {
				t.Fatalf("lifecycle gate remained held after bounded recovery: %v", err)
			}
			test.lifecycle.opMu.Unlock()
			if elapsed := time.Since(started); elapsed > 5*recoveryTimeout {
				t.Fatalf("recovery held lifecycle gate for %v, budget %v", elapsed, recoveryTimeout)
			}
			if err := <-recoveryDone; err == nil {
				t.Fatal("failed update recovery unexpectedly succeeded")
			}
		})
	}
}

func newUpdateServiceForTest(t *testing.T, root string, staged []byte) (*MihomoUpdateService, *lifecycleFake) {
	t.Helper()
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(layout.EnginesDir, "mihomo", "mihomo")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("Mihomo Meta v1.19.29\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	fake := &lifecycleFake{
		prepared: engine.PreparedCore{Engine: "mihomo", BinaryPath: target},
		health:   engine.HealthStatus{Running: true, ControllerReady: true, PID: 42, CheckedAt: time.Now()},
	}
	lifecycle := &Lifecycle{Preparer: fake, Core: fake, Activation: fake, ReadyTimeout: time.Second, ReadyPollInterval: time.Millisecond}
	return &MihomoUpdateService{
		Preparer: &ActiveMihomoPreparer{Layout: layout}, Lifecycle: lifecycle, Versioner: fileVersioner{}, State: store,
		Source: updateSourceFake{release: testMihomoRelease()}, Installer: updateInstallerFake{content: staged},
		install: update.Install, rollback: update.Rollback,
	}, fake
}

func testMihomoRelease() update.Release {
	return update.Release{Tag: "v1.19.30", Assets: []update.Asset{{
		Name: "mihomo-linux-arm64-v1.19.30.gz", URL: "https://example.invalid/mihomo.gz",
		Digest: "sha256:58896873736d28628f66de3677c8654fa0f180662523148e136cff4f6e890069", Size: 10,
	}}}
}

func assertUpdateFile(t *testing.T, path, expected string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != expected {
		t.Fatalf("%s = %q, want %q", path, content, expected)
	}
}

var errRejectedUpdatedCore = errors.New("updated core rejected")

type binaryAwareLifecycleFake struct {
	target  string
	running bool
}

func (fake *binaryAwareLifecycleFake) PrepareActive(context.Context) (engine.PreparedCore, error) {
	return engine.PreparedCore{Engine: "mihomo", BinaryPath: fake.target}, nil
}

func (fake *binaryAwareLifecycleFake) Start(context.Context, engine.PreparedCore) error {
	content, err := os.ReadFile(fake.target)
	if err != nil {
		return err
	}
	if extractMihomoVersion(string(content)) == "v1.19.30" {
		fake.running = false
		return errRejectedUpdatedCore
	}
	fake.running = true
	return nil
}

func (fake *binaryAwareLifecycleFake) Stop(context.Context) error {
	fake.running = false
	return nil
}

func (fake *binaryAwareLifecycleFake) Health(context.Context) (engine.HealthStatus, error) {
	return engine.HealthStatus{Running: fake.running, ControllerReady: fake.running, PID: 42}, nil
}

func (*binaryAwareLifecycleFake) Activate(context.Context, engine.PreparedCore) error   { return nil }
func (*binaryAwareLifecycleFake) Deactivate(context.Context, engine.PreparedCore) error { return nil }
