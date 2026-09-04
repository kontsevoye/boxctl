package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
	updatepkg "github.com/kontsevoye/boxctl/internal/update"
	"github.com/kontsevoye/boxctl/internal/web"
)

type singBoxReleaseSource interface {
	Latest(context.Context, updatepkg.Channel) (updatepkg.Release, error)
}

type singBoxReleaseInstaller interface {
	StageRelease(context.Context, updatepkg.Release, string) (updatepkg.StagedSingBox, error)
}

const singBoxUpdateRecoveryTimeout = mihomoUpdateRecoveryTimeout

type SingBoxUpdateService struct {
	Preparer       *ActiveSingBoxPreparer
	Lifecycle      *Lifecycle
	Profiles       state.ProfileStore
	Source         singBoxReleaseSource
	Installer      singBoxReleaseInstaller
	Publish        func(string, updatepkg.StagedSingBox) (updatepkg.ManagedEnginePointer, error)
	Revert         func(string, updatepkg.ManagedEnginePointer, bool) error
	ServiceContext context.Context
	// recoveryTimeout is a package-private test hook. Production derives the
	// bound from the manager's graceful-shutdown budget.
	recoveryTimeout time.Duration
	mu              sync.Mutex
}

func NewSingBoxUpdateService(
	serviceContext context.Context,
	root string,
	client *http.Client,
	preparer *ActiveSingBoxPreparer,
	lifecycle *Lifecycle,
) (*SingBoxUpdateService, error) {
	if preparer == nil || lifecycle == nil {
		return nil, errors.New("sing-box update dependencies are incomplete")
	}
	profiles, err := state.NewProfileStore(root)
	if err != nil {
		return nil, err
	}
	return &SingBoxUpdateService{
		Preparer: preparer, Lifecycle: lifecycle, Profiles: profiles,
		Source: updatepkg.NewSingBoxSource(client), Installer: updatepkg.SingBoxInstaller{Client: client},
		Publish: updatepkg.PublishSingBoxVersion, Revert: updatepkg.RevertManagedEnginePublish,
		ServiceContext: serviceContext,
	}, nil
}

func (service *SingBoxUpdateService) EngineUpdateStatus(ctx context.Context) (web.CoreUpdateStatus, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.status(ctx)
}

func (service *SingBoxUpdateService) status(ctx context.Context) (web.CoreUpdateStatus, error) {
	if err := service.validate(); err != nil {
		return web.CoreUpdateStatus{}, err
	}
	current, installed, err := service.current(ctx)
	if err != nil {
		return web.CoreUpdateStatus{}, err
	}
	if installed && current.Source == "custom" {
		return web.CoreUpdateStatus{
			Engine: state.EngineSingBox, CurrentVersion: current.Version,
			LatestVersion: current.Version, Channel: "custom", UpdateAvailable: false,
		}, nil
	}
	release, err := service.Source.Latest(ctx, updatepkg.ChannelStable)
	if err != nil {
		return web.CoreUpdateStatus{}, fmt.Errorf("discover sing-box release: %w", err)
	}
	latest, err := updatepkg.ParseSingBoxReleaseTag(release.Tag)
	if err != nil {
		return web.CoreUpdateStatus{}, err
	}
	if _, err := release.SingBoxLinuxARM64Musl(); err != nil {
		return web.CoreUpdateStatus{}, err
	}
	updateAvailable := !installed
	if installed {
		comparison, compareErr := updatepkg.CompareSingBoxVersions(current.Version, latest)
		if compareErr != nil {
			return web.CoreUpdateStatus{}, fmt.Errorf("compare sing-box versions: %w", compareErr)
		}
		updateAvailable = comparison < 0
	}
	return web.CoreUpdateStatus{
		Engine: state.EngineSingBox, CurrentVersion: current.Version, LatestVersion: latest,
		Channel: string(updatepkg.ChannelStable), UpdateAvailable: updateAvailable,
	}, nil
}

func (service *SingBoxUpdateService) InstallEngineUpdate(ctx context.Context) (web.CoreUpdateResult, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := service.validate(); err != nil {
		return web.CoreUpdateResult{}, err
	}
	current, installed, err := service.current(ctx)
	if err != nil {
		return web.CoreUpdateResult{}, err
	}
	if installed && current.Source == "custom" {
		return web.CoreUpdateResult{}, &web.PublicError{
			Status: http.StatusConflict, Code: "custom_engine_update_disabled",
			Message: "Custom sing-box installations are never updated automatically",
		}
	}
	release, err := service.Source.Latest(ctx, updatepkg.ChannelStable)
	if err != nil {
		return web.CoreUpdateResult{}, fmt.Errorf("discover sing-box release: %w", err)
	}
	latest, err := updatepkg.ParseSingBoxReleaseTag(release.Tag)
	if err != nil {
		return web.CoreUpdateResult{}, err
	}
	if installed {
		comparison, compareErr := updatepkg.CompareSingBoxVersions(current.Version, latest)
		if compareErr != nil {
			return web.CoreUpdateResult{}, fmt.Errorf("compare sing-box versions: %w", compareErr)
		}
		if comparison >= 0 {
			return web.CoreUpdateResult{
				Engine: state.EngineSingBox, PreviousVersion: current.Version, CurrentVersion: current.Version,
			}, nil
		}
	}
	engineRoot := filepath.Join(service.Preparer.Layout.EnginesDir, state.EngineSingBox)
	staged, err := service.Installer.StageRelease(ctx, release, engineRoot)
	if err != nil {
		return web.CoreUpdateResult{}, err
	}
	defer func() { _ = staged.Cleanup() }()

	if err := service.Lifecycle.lockOperation(ctx); err != nil {
		return web.CoreUpdateResult{}, err
	}
	defer service.Lifecycle.opMu.Unlock()
	active, activeErr := service.Profiles.Current()
	if activeErr != nil && !errors.Is(activeErr, fs.ErrNotExist) {
		return web.CoreUpdateResult{}, activeErr
	}
	snapshot := service.Lifecycle.Snapshot()
	freshInstallAfterBootstrapFailure := !installed && snapshot.State == LifecycleFailed &&
		!snapshot.Health.Running && !lifecycleOwnsPreparedCore(snapshot.Prepared)
	if snapshot.State != LifecycleRunning && snapshot.State != LifecycleStopped && snapshot.State != "" && !freshInstallAfterBootstrapFailure {
		return web.CoreUpdateResult{}, errors.Join(web.ErrConflict, errors.New("lifecycle operation is already in progress"))
	}
	if snapshot.State == LifecycleRunning && snapshot.Prepared.Engine == state.EngineSingBox &&
		(activeErr != nil || active.Engine != state.EngineSingBox) {
		return web.CoreUpdateResult{}, errors.Join(web.ErrConflict, errors.New("running sing-box profile selection is inconsistent"))
	}
	if activeErr == nil && active.Engine == state.EngineSingBox {
		candidate := *service.Preparer
		candidate.BinaryOverride = filepath.Join(staged.Directory, state.EngineSingBox)
		prepared, prepareErr := candidate.PrepareProfile(ctx, active)
		if prepareErr != nil {
			return web.CoreUpdateResult{}, fmt.Errorf("preflight staged sing-box with selected profile: %w", prepareErr)
		}
		engine.CleanupPreparedRuntime(prepared)
	}
	transactionContext, cancel := context.WithTimeout(service.serviceContext(), 2*time.Minute)
	defer cancel()
	wasRunning := snapshot.State == LifecycleRunning && snapshot.Prepared.Engine == state.EngineSingBox
	if wasRunning {
		if err := service.Lifecycle.stopLocked(transactionContext); err != nil {
			return web.CoreUpdateResult{}, fmt.Errorf("stop sing-box before update: %w", err)
		}
	}
	pointer, publishErr := service.Publish(engineRoot, staged)
	if publishErr != nil {
		if wasRunning {
			restartErr := service.restartPreviousLifecycleBounded()
			return web.CoreUpdateResult{}, errors.Join(publishErr, wrapUpdateError("restart previous sing-box", restartErr))
		}
		return web.CoreUpdateResult{}, publishErr
	}
	if wasRunning {
		if err := service.Lifecycle.startLocked(transactionContext); err != nil {
			return web.CoreUpdateResult{}, service.rollbackPublishedUpdate(transactionContext, engineRoot, pointer, installed, err)
		}
	}
	return web.CoreUpdateResult{
		Engine: state.EngineSingBox, PreviousVersion: current.Version,
		CurrentVersion: pointer.Current.Version, Restarted: wasRunning,
	}, nil
}

func (service *SingBoxUpdateService) rollbackPublishedUpdate(_ context.Context, engineRoot string, published updatepkg.ManagedEnginePointer, hadPrevious bool, cause error) error {
	recoveryContext, cancelRecovery := context.WithTimeout(context.Background(), service.detachedRecoveryTimeout())
	defer cancelRecovery()

	var stopErr error
	if service.Lifecycle.Snapshot().State != LifecycleStopped {
		stopErr = service.Lifecycle.stopLocked(recoveryContext)
	}
	if stopErr != nil {
		// The candidate executable may still be mapped by a process which we no
		// longer control. Keep the published generation intact until a later
		// verified stop; deleting it here would turn an uncertain runtime into a
		// known broken one.
		return errors.Join(cause, wrapUpdateError("stop failed sing-box", stopErr))
	}
	revertErr := service.Revert(engineRoot, published, hadPrevious)
	var restartErr error
	if hadPrevious && revertErr == nil && service.serviceContext().Err() == nil {
		restartErr = service.restartPreviousLifecycle(recoveryContext)
	}
	return errors.Join(cause, wrapUpdateError("revert published sing-box", revertErr), wrapUpdateError("restart previous sing-box", restartErr))
}

func (service *SingBoxUpdateService) restartPreviousLifecycleBounded() error {
	recoveryContext, cancelRecovery := context.WithTimeout(context.Background(), service.detachedRecoveryTimeout())
	defer cancelRecovery()
	return service.restartPreviousLifecycle(recoveryContext)
}

func (service *SingBoxUpdateService) restartPreviousLifecycle(recoveryContext context.Context) error {
	var restartContext context.Context
	var cancelRestart context.CancelFunc
	if deadline, ok := recoveryContext.Deadline(); ok {
		restartContext, cancelRestart = context.WithDeadline(service.serviceContext(), deadline)
	} else {
		restartContext, cancelRestart = context.WithCancel(service.serviceContext())
	}
	stopAtRecoveryDeadline := context.AfterFunc(recoveryContext, cancelRestart)
	restartErr := service.Lifecycle.startLocked(restartContext)
	cancelRestart()
	stopAtRecoveryDeadline()
	if service.serviceContext().Err() == nil {
		return restartErr
	}
	stopErr := service.Lifecycle.stopLocked(recoveryContext)
	return errors.Join(restartErr, wrapUpdateError("stop previous sing-box after manager shutdown", stopErr))
}

func (service *SingBoxUpdateService) detachedRecoveryTimeout() time.Duration {
	if service.recoveryTimeout > 0 {
		return service.recoveryTimeout
	}
	return singBoxUpdateRecoveryTimeout
}

func (service *SingBoxUpdateService) current(ctx context.Context) (updatepkg.ManagedEngineVersion, bool, error) {
	if err := ctx.Err(); err != nil {
		return updatepkg.ManagedEngineVersion{}, false, err
	}
	engineRoot := filepath.Join(service.Preparer.Layout.EnginesDir, state.EngineSingBox)
	pointer, err := updatepkg.ReadManagedEnginePointer(engineRoot)
	if err == nil {
		if _, err := updatepkg.ResolveManagedEngineBinary(engineRoot, pointer.Current); err != nil {
			return updatepkg.ManagedEngineVersion{}, false, err
		}
		return pointer.Current, true, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return updatepkg.ManagedEngineVersion{}, false, err
	}
	legacy := filepath.Join(engineRoot, state.EngineSingBox)
	if info, statErr := os.Lstat(legacy); statErr == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o111 != 0 {
		version := "custom"
		if service.Preparer.Version != nil {
			if output, versionErr := service.Preparer.Version.Version(ctx, legacy); versionErr == nil {
				if match := singBoxVersionLine.FindStringSubmatch(output); len(match) == 2 {
					version = match[1]
				}
			} else if ctx.Err() != nil {
				return updatepkg.ManagedEngineVersion{}, false, ctx.Err()
			}
		}
		return updatepkg.ManagedEngineVersion{Engine: state.EngineSingBox, Version: version, Source: "custom"}, true, nil
	} else if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		return updatepkg.ManagedEngineVersion{}, false, statErr
	}
	return updatepkg.ManagedEngineVersion{}, false, nil
}

func (service *SingBoxUpdateService) validate() error {
	if service == nil || service.Preparer == nil || service.Lifecycle == nil || service.Source == nil || service.Installer == nil || service.Publish == nil || service.Revert == nil {
		return errors.New("sing-box update service is not initialized")
	}
	return nil
}

func (service *SingBoxUpdateService) serviceContext() context.Context {
	if service.ServiceContext != nil {
		return service.ServiceContext
	}
	return context.Background()
}

// MultiEngineUpdateService keeps the legacy /core/update route Mihomo-bound,
// while the engine-addressed API and automatic scheduler select explicitly.
type MultiEngineUpdateService struct {
	Mihomo   *MihomoUpdateService
	SingBox  *SingBoxUpdateService
	Selected func() string
}

func (service *MultiEngineUpdateService) CoreUpdateStatus(ctx context.Context) (web.CoreUpdateStatus, error) {
	return service.EngineUpdateStatus(ctx, state.EngineMihomo)
}

func (service *MultiEngineUpdateService) InstallCoreUpdate(ctx context.Context) (web.CoreUpdateResult, error) {
	return service.InstallEngineUpdate(ctx, state.EngineMihomo)
}

// InstallSelectedEngineUpdate is intentionally separate from the legacy
// Mihomo-bound CoreUpdateService contract. The automatic scheduler uses this
// explicit path so selecting sing-box does not silently redefine old API
// routes for existing clients.
func (service *MultiEngineUpdateService) InstallSelectedEngineUpdate(ctx context.Context) (web.CoreUpdateResult, error) {
	return service.InstallEngineUpdate(ctx, service.selected())
}

func (service *MultiEngineUpdateService) EngineUpdateStatus(ctx context.Context, engineName string) (web.CoreUpdateStatus, error) {
	switch engineName {
	case state.EngineMihomo:
		result, err := service.Mihomo.CoreUpdateStatus(ctx)
		result.Engine = state.EngineMihomo
		return result, err
	case state.EngineSingBox:
		return service.SingBox.EngineUpdateStatus(ctx)
	default:
		return web.CoreUpdateStatus{}, web.ErrNotFound
	}
}

func (service *MultiEngineUpdateService) InstallEngineUpdate(ctx context.Context, engineName string) (web.CoreUpdateResult, error) {
	switch engineName {
	case state.EngineMihomo:
		result, err := service.Mihomo.InstallCoreUpdate(ctx)
		result.Engine = state.EngineMihomo
		return result, err
	case state.EngineSingBox:
		return service.SingBox.InstallEngineUpdate(ctx)
	default:
		return web.CoreUpdateResult{}, web.ErrNotFound
	}
}

func (service *MultiEngineUpdateService) selected() string {
	if service != nil && service.Selected != nil {
		if selected := service.Selected(); selected != "" {
			return selected
		}
	}
	return state.EngineMihomo
}

var (
	_ web.CoreUpdateService   = (*MultiEngineUpdateService)(nil)
	_ web.EngineUpdateService = (*MultiEngineUpdateService)(nil)
)
