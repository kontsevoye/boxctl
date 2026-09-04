package app

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/update"
	"github.com/kontsevoye/boxctl/internal/web"
)

func TestCleanInstallFlowCreatesAdminInstallsMihomoActivatesProfileAndStarts(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	credentials, err := NewCredentialStore(root)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := credentials.AdminSetupStatus(ctx)
	if err != nil || !setup.Required {
		t.Fatalf("initial setup status = %+v, err = %v", setup, err)
	}
	if err := credentials.InitializeAdmin(ctx, "correct-horse-battery-staple"); err != nil {
		t.Fatal(err)
	}
	setup, err = credentials.AdminSetupStatus(ctx)
	if err != nil || setup.Required {
		t.Fatalf("completed setup status = %+v, err = %v", setup, err)
	}

	core := &cleanInstallCore{}
	preparer, err := NewActiveMihomoPreparer(root, core)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := preparer.binaryPath(); !errors.Is(err, errMihomoBinaryNotInstalled) {
		t.Fatalf("initial Mihomo binary lookup error = %v", err)
	}
	if _, err := preparer.Profiles.Current(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("initial active profile error = %v", err)
	}
	lifecycle := &Lifecycle{
		Preparer:          preparer,
		Core:              core,
		Activation:        cleanInstallActivation{},
		ReadyTimeout:      time.Second,
		ReadyPollInterval: time.Millisecond,
		snap:              LifecycleSnapshot{State: LifecycleFailed},
	}
	updater := &MihomoUpdateService{
		Preparer:  preparer,
		Lifecycle: lifecycle,
		Versioner: fileVersioner{},
		State:     preparer.State,
		Source:    updateSourceFake{release: testMihomoRelease()},
		Installer: updateInstallerFake{content: []byte("Mihomo Meta v1.19.30\n")},
		install:   update.Install,
		rollback:  update.Rollback,
	}
	updateStatus, err := updater.CoreUpdateStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if updateStatus.CurrentVersion != "" || updateStatus.LatestVersion != "v1.19.30" || !updateStatus.UpdateAvailable {
		t.Fatalf("clean install update status = %+v", updateStatus)
	}
	installed, err := updater.InstallCoreUpdate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if installed.PreviousVersion != "" || installed.CurrentVersion != "v1.19.30" || installed.Restarted {
		t.Fatalf("clean install result = %+v", installed)
	}
	installedPath := filepath.Join(preparer.Layout.EnginesDir, "mihomo", "mihomo")
	if info, err := os.Stat(installedPath); err != nil || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("installed Mihomo = %v, err = %v", info, err)
	}

	profiles, err := NewProfilesService(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	profiles.ValidateMihomo = (&ConfigService{Preparer: preparer}).ValidateMihomoContent
	created, err := profiles.CreateProfile(ctx, web.ProfileDraft{
		Name:    "first",
		Content: "mode: rule\nexternal-controller: 127.0.0.1:9090\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Active || created.SourceKind != "local" || created.Engine != state.EngineMihomo {
		t.Fatalf("created profile = %+v", created)
	}
	activated, err := profiles.ActivateProfile(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !activated.Active {
		t.Fatalf("activated profile = %+v", activated)
	}
	if err := lifecycle.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if snapshot := lifecycle.Snapshot(); snapshot.State != LifecycleRunning || !snapshot.Health.Running || snapshot.Prepared.BinaryPath != installedPath {
		t.Fatalf("running lifecycle = %+v", snapshot)
	}
}

type cleanInstallCore struct {
	running bool
}

func (core *cleanInstallCore) Prepare(ctx context.Context, request engine.PrepareRequest) (engine.PreparedCore, error) {
	if err := ctx.Err(); err != nil {
		return engine.PreparedCore{}, err
	}
	if err := validateMihomoBinaryPath(request.BinaryPath); err != nil {
		return engine.PreparedCore{}, err
	}
	if _, err := os.ReadFile(request.SourceConfigPath); err != nil {
		return engine.PreparedCore{}, err
	}
	return engine.PreparedCore{
		Engine:            state.EngineMihomo,
		BinaryPath:        request.BinaryPath,
		SourceConfigPath:  request.SourceConfigPath,
		RuntimeConfigPath: request.SourceConfigPath,
		HomeDir:           request.HomeDir,
		Capture:           request.Capture,
		Controller:        request.Controller,
	}, nil
}

func (*cleanInstallCore) Validate(context.Context, engine.PreparedCore) error { return nil }

func (core *cleanInstallCore) Start(_ context.Context, prepared engine.PreparedCore) error {
	if err := validateMihomoBinaryPath(prepared.BinaryPath); err != nil {
		return err
	}
	core.running = true
	return nil
}

func (core *cleanInstallCore) Stop(context.Context) error {
	core.running = false
	return nil
}

func (core *cleanInstallCore) Health(context.Context) (engine.HealthStatus, error) {
	return engine.HealthStatus{
		Running:         core.running,
		ControllerReady: core.running,
		DNSReady:        core.running,
		PID:             42,
		Version:         "v1.19.30",
		CheckedAt:       time.Now().UTC(),
	}, nil
}

type cleanInstallActivation struct{}

func (cleanInstallActivation) Activate(context.Context, engine.PreparedCore) error   { return nil }
func (cleanInstallActivation) Deactivate(context.Context, engine.PreparedCore) error { return nil }
