package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/cli"
	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
	updatepkg "github.com/kontsevoye/boxctl/internal/update"
	"github.com/kontsevoye/boxctl/internal/web"
)

type singBoxUpdateSourceFake struct {
	release updatepkg.Release
	calls   int
}

func (source *singBoxUpdateSourceFake) Latest(ctx context.Context, _ updatepkg.Channel) (updatepkg.Release, error) {
	source.calls++
	if err := ctx.Err(); err != nil {
		return updatepkg.Release{}, err
	}
	return source.release, nil
}

type singBoxUpdateInstallerFake struct {
	staged updatepkg.StagedSingBox
	calls  int
}

func (installer *singBoxUpdateInstallerFake) StageRelease(ctx context.Context, _ updatepkg.Release, _ string) (updatepkg.StagedSingBox, error) {
	installer.calls++
	if err := ctx.Err(); err != nil {
		return updatepkg.StagedSingBox{}, err
	}
	return installer.staged, nil
}

func TestSingBoxUpdateDoesNotOfferOrInstallDowngrade(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	installManagedSingBoxPointerFixture(t, root, "1.14.5")
	source := &singBoxUpdateSourceFake{release: singBoxReleaseFixture("1.14.4")}
	installer := &singBoxUpdateInstallerFake{}
	service := singBoxUpdateServiceFixture(t, root, source, installer)

	status, err := service.EngineUpdateStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.UpdateAvailable || status.CurrentVersion != "1.14.5" || status.LatestVersion != "1.14.4" {
		t.Fatalf("downgrade status = %+v", status)
	}
	result, err := service.InstallEngineUpdate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.CurrentVersion != "1.14.5" || result.PreviousVersion != "1.14.5" || installer.calls != 0 {
		t.Fatalf("downgrade result=%+v stage calls=%d", result, installer.calls)
	}
}

func TestSingBoxUpdateUsesRequestContextForLegacyVersion(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(layout.EnginesDir, state.EngineSingBox, state.EngineSingBox)
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("legacy"), 0o700); err != nil {
		t.Fatal(err)
	}
	type contextKey string
	const key contextKey = "request"
	seen := false
	service := singBoxUpdateServiceFixture(t, root, &singBoxUpdateSourceFake{}, &singBoxUpdateInstallerFake{})
	service.Preparer.Version = coreVersionerFunc(func(ctx context.Context, path string) (string, error) {
		seen = ctx.Value(key) == "present" && path == legacy
		return "sing-box version 1.14.0\n", nil
	})
	status, err := service.EngineUpdateStatus(context.WithValue(context.Background(), key, "present"))
	if err != nil {
		t.Fatal(err)
	}
	if !seen || status.Channel != "custom" || status.UpdateAvailable {
		t.Fatalf("legacy status=%+v context seen=%t", status, seen)
	}
}

func TestSingBoxUpdateLeavesRunningUnselectedEngineUntouched(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source := &singBoxUpdateSourceFake{release: singBoxReleaseFixture("1.14.1")}
	installer := &singBoxUpdateInstallerFake{}
	service := singBoxUpdateServiceFixture(t, root, source, installer)
	runtime := &lifecycleFake{
		prepared: engine.PreparedCore{Engine: state.EngineMihomo, BinaryPath: "/managed/mihomo"},
		health:   engine.HealthStatus{Running: true, ControllerReady: true, PID: 42},
	}
	service.Lifecycle = &Lifecycle{
		Preparer: runtime, Core: runtime, Activation: runtime,
		snap: LifecycleSnapshot{State: LifecycleRunning, Prepared: runtime.prepared, Health: runtime.health},
	}
	publishCalls := 0
	service.Publish = func(_ string, _ updatepkg.StagedSingBox) (updatepkg.ManagedEnginePointer, error) {
		publishCalls++
		return updatepkg.ManagedEnginePointer{Current: updatepkg.ManagedEngineVersion{Version: "1.14.1"}}, nil
	}

	result, err := service.InstallEngineUpdate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if publishCalls != 1 || installer.calls != 1 || result.Restarted {
		t.Fatalf("inactive update result=%+v publish=%d stage=%d", result, publishCalls, installer.calls)
	}
	if snapshot := service.Lifecycle.Snapshot(); snapshot.State != LifecycleRunning || snapshot.Prepared.Engine != state.EngineMihomo {
		t.Fatalf("inactive update changed lifecycle: %+v", snapshot)
	}
	if len(runtime.events) != 0 {
		t.Fatalf("inactive update touched running Mihomo: %v", runtime.events)
	}
}

func TestSingBoxUpdateRefusesFailedLifecycleWithProcessOwnership(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source := &singBoxUpdateSourceFake{release: singBoxReleaseFixture("1.14.1")}
	installer := &singBoxUpdateInstallerFake{}
	service := singBoxUpdateServiceFixture(t, root, source, installer)
	runtime := &lifecycleFake{
		prepared: engine.PreparedCore{Engine: state.EngineMihomo, BinaryPath: "/managed/mihomo"},
		health:   engine.HealthStatus{Running: true, PID: 42},
	}
	service.Lifecycle = &Lifecycle{
		Preparer: runtime, Core: runtime, Activation: runtime,
		snap: LifecycleSnapshot{State: LifecycleFailed, Prepared: runtime.prepared, Health: runtime.health},
	}
	publishCalls := 0
	service.Publish = func(string, updatepkg.StagedSingBox) (updatepkg.ManagedEnginePointer, error) {
		publishCalls++
		return updatepkg.ManagedEnginePointer{}, nil
	}

	_, err := service.InstallEngineUpdate(context.Background())
	if !errors.Is(err, web.ErrConflict) {
		t.Fatalf("failed lifecycle update error = %v", err)
	}
	if publishCalls != 0 || len(runtime.events) != 0 {
		t.Fatalf("failed lifecycle was mutated: publish=%d events=%v", publishCalls, runtime.events)
	}
}

func TestFreshSingBoxRestartFailureRevertsPublishedInstall(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source := &singBoxUpdateSourceFake{release: singBoxReleaseFixture("1.14.1")}
	installer := &singBoxUpdateInstallerFake{}
	service := singBoxUpdateServiceFixture(t, root, source, installer)
	profile := state.ActiveProfile{Name: "selected", Engine: state.EngineSingBox}
	if err := service.Profiles.Create(context.Background(), profile, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := service.Profiles.Activate(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	config := &singBoxUpdateConfigFake{directory: t.TempDir()}
	service.Preparer.Config = config
	service.Preparer.Profiles = service.Profiles
	runtimeErr := errors.New("candidate did not become ready")
	runtime := &lifecycleFake{
		prepared: engine.PreparedCore{Engine: state.EngineSingBox, BinaryPath: "/managed/sing-box"},
		health:   engine.HealthStatus{Running: true, ControllerReady: true, PID: 42},
		startErr: runtimeErr,
	}
	service.Lifecycle = &Lifecycle{
		Preparer: runtime, Core: runtime, Activation: runtime,
		snap: LifecycleSnapshot{State: LifecycleRunning, Prepared: runtime.prepared, Health: runtime.health},
	}
	published := updatepkg.ManagedEnginePointer{Current: updatepkg.ManagedEngineVersion{Version: "1.14.1"}}
	service.Publish = func(string, updatepkg.StagedSingBox) (updatepkg.ManagedEnginePointer, error) { return published, nil }
	revertCalls := 0
	service.Revert = func(_ string, got updatepkg.ManagedEnginePointer, hadPrevious bool) error {
		revertCalls++
		if got.Current.Version != "1.14.1" || hadPrevious {
			t.Fatalf("revert args pointer=%+v hadPrevious=%t", got, hadPrevious)
		}
		return nil
	}

	_, err := service.InstallEngineUpdate(context.Background())
	if !errors.Is(err, runtimeErr) {
		t.Fatalf("fresh update error = %v", err)
	}
	if revertCalls != 1 || service.Lifecycle.Snapshot().State != LifecycleStopped {
		t.Fatalf("fresh rollback calls=%d lifecycle=%+v", revertCalls, service.Lifecycle.Snapshot())
	}
}

func TestSingBoxRollbackKeepsPublishedExecutableWhenFailedTargetCannotStop(t *testing.T) {
	t.Parallel()
	stopErr := errors.New("candidate process identity is uncertain")
	runtime := &lifecycleFake{
		prepared: engine.PreparedCore{Engine: state.EngineSingBox, BinaryPath: "/managed/sing-box"},
		health:   engine.HealthStatus{Running: true, ControllerReady: true, PID: 42},
		stopErr:  stopErr,
	}
	service := &SingBoxUpdateService{
		Lifecycle: &Lifecycle{
			Preparer: runtime, Core: runtime, Activation: runtime,
			snap: LifecycleSnapshot{State: LifecycleRunning, Prepared: runtime.prepared, Health: runtime.health},
		},
	}
	revertCalls := 0
	service.Revert = func(string, updatepkg.ManagedEnginePointer, bool) error {
		revertCalls++
		return nil
	}

	cause := errors.New("updated sing-box did not become ready")
	err := service.rollbackPublishedUpdate(context.Background(), t.TempDir(), updatepkg.ManagedEnginePointer{}, true, cause)
	if !errors.Is(err, cause) || !errors.Is(err, stopErr) {
		t.Fatalf("rollback error = %v", err)
	}
	if revertCalls != 0 {
		t.Fatalf("published executable was reverted after uncertain stop: %d calls", revertCalls)
	}
}

func TestSingBoxRollbackUsesDetachedContextAfterRequestCancellation(t *testing.T) {
	t.Parallel()
	runtime := &lifecycleFake{
		prepared: engine.PreparedCore{Engine: state.EngineSingBox, BinaryPath: "/managed/sing-box"},
		health:   engine.HealthStatus{Running: true, ControllerReady: true, PID: 42, CheckedAt: time.Now()},
	}
	service := &SingBoxUpdateService{
		Lifecycle: &Lifecycle{
			Preparer: runtime, Core: runtime, Activation: runtime,
			snap: LifecycleSnapshot{State: LifecycleRunning, Prepared: runtime.prepared, Health: runtime.health},
		},
		ServiceContext:  context.Background(),
		recoveryTimeout: time.Second,
	}
	revertCalls := 0
	service.Revert = func(string, updatepkg.ManagedEnginePointer, bool) error {
		revertCalls++
		return nil
	}
	requestContext, cancelRequest := context.WithCancel(context.Background())
	cancelRequest()
	cause := context.Canceled

	err := service.rollbackPublishedUpdate(requestContext, t.TempDir(), updatepkg.ManagedEnginePointer{}, true, cause)
	if !errors.Is(err, cause) {
		t.Fatalf("rollback error = %v", err)
	}
	if revertCalls != 1 {
		t.Fatalf("detached rollback revert calls = %d", revertCalls)
	}
	if snapshot := service.Lifecycle.Snapshot(); snapshot.State != LifecycleRunning || !snapshot.Health.Running {
		t.Fatalf("previous sing-box was not restarted: %+v", snapshot)
	}
}

func TestNonExecutableCustomSingBoxCanBeRepairedByManagedInstall(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(layout.EnginesDir, state.EngineSingBox, state.EngineSingBox)
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("damaged custom binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	service := singBoxUpdateServiceFixture(t, root, &singBoxUpdateSourceFake{}, &singBoxUpdateInstallerFake{})

	current, installed, err := service.current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if installed || current.Engine != "" || current.Version != "" || current.Binary != "" {
		t.Fatalf("non-executable custom sing-box reported as installed: installed=%t current=%+v", installed, current)
	}
}

func TestInstallEngineRejectsSymlinkChecksumCompanion(t *testing.T) {
	t.Parallel()
	archive := filepath.Join(t.TempDir(), "sing-box.tar.gz")
	if err := os.WriteFile(archive, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", archive+".sha256"); err != nil {
		t.Fatal(err)
	}
	actions := newIsolatedActions(t, io.Discard)
	err := actions.InstallEngine(context.Background(), cli.EngineInstallOptions{
		Engine: state.EngineSingBox, Root: t.TempDir(), File: archive,
	})
	if err == nil || !strings.Contains(err.Error(), "bounded regular non-symlink") {
		t.Fatalf("symlink companion error = %v", err)
	}
}

type singBoxUpdateConfigFake struct{ directory string }

func (fake *singBoxUpdateConfigFake) Prepare(_ context.Context, request engine.PrepareRequest) (engine.PreparedCore, error) {
	file, err := os.CreateTemp(fake.directory, "runtime-*.json")
	if err != nil {
		return engine.PreparedCore{}, err
	}
	if _, err := file.Write([]byte("{\"dns\":{\"servers\":[{\"type\":\"udp\",\"tag\":\"upstream\",\"server\":\"1.1.1.1\"}],\"final\":\"upstream\"}}\n")); err != nil {
		_ = file.Close()
		return engine.PreparedCore{}, err
	}
	if err := file.Close(); err != nil {
		return engine.PreparedCore{}, err
	}
	return engine.PreparedCore{
		Engine: state.EngineSingBox, BinaryPath: request.BinaryPath,
		RuntimeConfigPath: file.Name(), Capture: request.Capture, Controller: request.Controller,
	}, nil
}

func (*singBoxUpdateConfigFake) Validate(context.Context, engine.PreparedCore) error { return nil }

func singBoxUpdateServiceFixture(t *testing.T, root string, source singBoxReleaseSource, installer singBoxReleaseInstaller) *SingBoxUpdateService {
	t.Helper()
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := state.NewProfileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	preparer := &ActiveSingBoxPreparer{Layout: layout, Profiles: profiles, State: store, RuntimeDir: t.TempDir()}
	runtime := &lifecycleFake{}
	return &SingBoxUpdateService{
		Preparer: preparer, Lifecycle: &Lifecycle{Preparer: runtime, Core: runtime, Activation: runtime}, Profiles: profiles,
		Source: source, Installer: installer, Publish: updatepkg.PublishSingBoxVersion, Revert: updatepkg.RevertManagedEnginePublish,
		ServiceContext: context.Background(),
	}
}

func singBoxReleaseFixture(version string) updatepkg.Release {
	name := "sing-box-" + version + "-linux-arm64-musl.tar.gz"
	return updatepkg.Release{Tag: "v" + version, Assets: []updatepkg.Asset{{
		Name:   name,
		URL:    "https://github.com/SagerNet/sing-box/releases/download/v" + version + "/" + name,
		Digest: "sha256:" + strings.Repeat("a", 64), Size: 1,
	}}}
}

func installManagedSingBoxPointerFixture(t *testing.T, root, version string) {
	t.Helper()
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	engineRoot := filepath.Join(layout.EnginesDir, state.EngineSingBox)
	versionDirectory := filepath.Join(engineRoot, "versions", version)
	if err := os.MkdirAll(versionDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := []byte("static aarch64 fixture")
	license := []byte("license fixture")
	if err := os.WriteFile(filepath.Join(versionDirectory, state.EngineSingBox), binary, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(versionDirectory, "LICENSE"), license, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := updatepkg.ManagedEngineVersion{
		Engine: state.EngineSingBox, Version: version,
		Binary:  filepath.ToSlash(filepath.Join("versions", version, state.EngineSingBox)),
		License: filepath.ToSlash(filepath.Join("versions", version, "LICENSE")),
		Source:  "official", SourceURL: "https://github.com/SagerNet/sing-box/releases/download/v" + version + "/sing-box-" + version + "-linux-arm64-musl.tar.gz",
		ReleaseTag: "v" + version, ArchiveSHA256: strings.Repeat("a", 64), ArchiveSize: 1,
		BinarySHA256: digestBytes(binary), LicenseSHA256: digestBytes(license),
		BuildTags: []string{"with_clash_api", "with_gvisor", "with_musl"}, AutoUpdate: true,
		InstalledAt: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC), LicenseID: "GPL-3.0-or-later",
		LicenseNotice:   "upstream additional name-and-association restriction applies",
		UpstreamProject: "https://github.com/SagerNet/sing-box", NoAffiliation: true,
	}
	writeJSONFixture(t, filepath.Join(versionDirectory, "manifest.json"), manifest)
	writeJSONFixture(t, filepath.Join(engineRoot, "current.json"), updatepkg.ManagedEnginePointer{
		Schema: updatepkg.ManagedEnginePointerSchema, Engine: state.EngineSingBox, Current: manifest,
	})
}

func writeJSONFixture(t *testing.T, path string, value any) {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func digestBytes(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}
