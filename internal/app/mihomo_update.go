package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/update"
	"github.com/kontsevoye/boxctl/internal/web"
)

type mihomoUpdateSource interface {
	Latest(context.Context, update.Channel) (update.Release, error)
}

type mihomoUpdateInstaller interface {
	Stage(context.Context, update.Asset, string) (string, error)
}

type coreVersioner interface {
	Version(context.Context, string) (string, error)
}

const (
	mihomoUpdateTransactionTimeout = 60 * time.Second
	// An in-flight start may already spend one lifecycle cleanup window after
	// manager cancellation. Bound every subsequent detached recovery to the
	// remaining shutdown slice, preserving one final lifecycle cleanup and the
	// process hand-off reserve before Serve returns.
	mihomoUpdateRecoveryTimeout = gracefulShutdownBudget - 2*defaultLifecycleCleanupTimeout - shutdownHandoffBudget
)

// MihomoUpdateService installs only GitHub-digest-attested Linux AArch64
// artifacts. A running lifecycle is stopped under its operation lock and is
// restarted only after the atomic binary swap succeeds.
type MihomoUpdateService struct {
	Preparer  *ActiveMihomoPreparer
	Lifecycle *Lifecycle
	Versioner coreVersioner
	State     state.Store
	Source    mihomoUpdateSource
	Installer mihomoUpdateInstaller
	// ServiceContext outlives an individual HTTP request but is canceled when
	// the manager shuts down. It bounds the binary swap/restart transaction.
	ServiceContext context.Context

	install  func(string, string) error
	rollback func(string) error
	// recoveryTimeout is a package-private test hook; production uses the shared
	// shutdown-derived constant above.
	recoveryTimeout time.Duration
	mu              sync.Mutex
}

func NewMihomoUpdateService(serviceContext context.Context, root string, client *http.Client, preparer *ActiveMihomoPreparer, lifecycle *Lifecycle, driver *engine.MihomoDriver) (*MihomoUpdateService, error) {
	if preparer == nil || lifecycle == nil || driver == nil {
		return nil, errors.New("mihomo update dependencies are incomplete")
	}
	store, err := state.NewStore(root)
	if err != nil {
		return nil, err
	}
	validator := &stagedMihomoValidator{Preparer: preparer, Versioner: driver}
	return &MihomoUpdateService{
		Preparer: preparer, Lifecycle: lifecycle, Versioner: driver, State: store,
		Source: update.NewMihomoSource(client), Installer: &update.Installer{Client: client, Validator: validator},
		ServiceContext: serviceContext, install: update.Install, rollback: update.Rollback,
	}, nil
}

func (service *MihomoUpdateService) CoreUpdateStatus(ctx context.Context) (web.CoreUpdateStatus, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.status(ctx)
}

func (service *MihomoUpdateService) status(ctx context.Context) (web.CoreUpdateStatus, error) {
	if err := service.validate(); err != nil {
		return web.CoreUpdateStatus{}, err
	}
	target, installed, err := service.targetPath()
	if err != nil {
		return web.CoreUpdateStatus{}, err
	}
	current := ""
	if installed {
		currentRaw, versionErr := service.Versioner.Version(ctx, target)
		if versionErr != nil {
			return web.CoreUpdateStatus{}, fmt.Errorf("read installed Mihomo version: %w", versionErr)
		}
		current = extractMihomoVersion(currentRaw)
	}
	channel, err := service.channel()
	if err != nil {
		return web.CoreUpdateStatus{}, err
	}
	release, err := service.Source.Latest(ctx, channel)
	if err != nil {
		return web.CoreUpdateStatus{}, fmt.Errorf("discover Mihomo release: %w", err)
	}
	if _, err := release.LinuxARM64(); err != nil {
		return web.CoreUpdateStatus{}, err
	}
	latest := release.Tag
	return web.CoreUpdateStatus{
		CurrentVersion: current, LatestVersion: latest, Channel: string(channel),
		UpdateAvailable: current == "" || current != latest,
	}, nil
}

func (service *MihomoUpdateService) InstallCoreUpdate(ctx context.Context) (web.CoreUpdateResult, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := service.validate(); err != nil {
		return web.CoreUpdateResult{}, err
	}
	target, installed, err := service.targetPath()
	if err != nil {
		return web.CoreUpdateResult{}, err
	}
	previousVersion := ""
	if installed {
		previousRaw, versionErr := service.Versioner.Version(ctx, target)
		if versionErr != nil {
			return web.CoreUpdateResult{}, fmt.Errorf("read installed Mihomo version: %w", versionErr)
		}
		previousVersion = extractMihomoVersion(previousRaw)
	}
	channel, err := service.channel()
	if err != nil {
		return web.CoreUpdateResult{}, err
	}
	release, err := service.Source.Latest(ctx, channel)
	if err != nil {
		return web.CoreUpdateResult{}, fmt.Errorf("discover Mihomo release: %w", err)
	}
	asset, err := release.LinuxARM64()
	if err != nil {
		return web.CoreUpdateResult{}, err
	}
	if previousVersion != "" && previousVersion == release.Tag {
		return web.CoreUpdateResult{PreviousVersion: previousVersion, CurrentVersion: previousVersion}, nil
	}
	staged, err := service.Installer.Stage(ctx, asset, filepath.Dir(target))
	if err != nil {
		return web.CoreUpdateResult{}, err
	}
	defer func() { _ = os.Remove(staged) }()

	if err := service.serviceContext().Err(); err != nil {
		return web.CoreUpdateResult{}, err
	}
	if err := service.Lifecycle.lockOperation(ctx); err != nil {
		return web.CoreUpdateResult{}, err
	}
	defer service.Lifecycle.opMu.Unlock()
	// From this point client disconnects must not interrupt stop/swap/restart.
	// Manager shutdown still cancels the transaction so lifecycle cleanup can
	// take ownership of the operation gate within procd's termination window.
	transactionContext, cancelTransaction := context.WithTimeout(service.serviceContext(), mihomoUpdateTransactionTimeout)
	defer cancelTransaction()
	snapshotBefore := service.Lifecycle.Snapshot()
	stateBefore := snapshotBefore.State
	freshInstallAfterBootstrapFailure := !installed && stateBefore == LifecycleFailed &&
		!snapshotBefore.Health.Running && !lifecycleOwnsPreparedCore(snapshotBefore.Prepared)
	if stateBefore != LifecycleRunning && stateBefore != LifecycleStopped && stateBefore != "" && !freshInstallAfterBootstrapFailure {
		return web.CoreUpdateResult{}, errors.Join(web.ErrConflict, errors.New("lifecycle operation is already in progress"))
	}
	// Updating an installed but unselected Mihomo binary must not interrupt a
	// different running engine. Only the runtime which owns the target binary
	// participates in the stop/swap/restart transaction.
	wasRunning := stateBefore == LifecycleRunning && snapshotBefore.Prepared.Engine == state.EngineMihomo
	if wasRunning {
		if err := service.Lifecycle.stopLocked(transactionContext); err != nil {
			return web.CoreUpdateResult{}, fmt.Errorf("stop Mihomo before update: %w", err)
		}
	}
	if err := transactionContext.Err(); err != nil {
		var restartErr error
		if wasRunning && service.serviceContext().Err() == nil {
			restartErr = service.restartPreviousLifecycleBounded()
		}
		return web.CoreUpdateResult{}, errors.Join(
			err,
			wrapUpdateError("restart previous Mihomo after canceled update", restartErr),
		)
	}
	if err := service.install(staged, target); err != nil {
		var restartErr error
		if wasRunning && !errors.Is(err, update.ErrInstallRollbackFailed) && service.serviceContext().Err() == nil {
			restartErr = service.restartPreviousLifecycleBounded()
		}
		return web.CoreUpdateResult{}, errors.Join(
			fmt.Errorf("install Mihomo update: %w", err),
			wrapUpdateError("restart previous Mihomo after failed install", restartErr),
		)
	}
	if err := transactionContext.Err(); err != nil {
		return web.CoreUpdateResult{}, service.rollbackSwappedUpdate(target, installed, wasRunning, err)
	}
	if wasRunning {
		if startErr := service.Lifecycle.startLocked(transactionContext); startErr != nil {
			return web.CoreUpdateResult{}, service.rollbackSwappedUpdate(
				target,
				installed,
				wasRunning,
				fmt.Errorf("updated Mihomo failed to start: %w", startErr),
			)
		}
	}
	currentRaw, err := service.Versioner.Version(transactionContext, target)
	if err != nil {
		return web.CoreUpdateResult{}, service.rollbackSwappedUpdate(
			target,
			installed,
			wasRunning,
			fmt.Errorf("verify installed Mihomo version: %w", err),
		)
	}
	currentVersion := extractMihomoVersion(currentRaw)
	if currentVersion == "" {
		return web.CoreUpdateResult{}, service.rollbackSwappedUpdate(
			target,
			installed,
			wasRunning,
			errors.New("verify installed Mihomo version: version output did not contain a semantic version"),
		)
	}
	if currentVersion != release.Tag {
		return web.CoreUpdateResult{}, service.rollbackSwappedUpdate(
			target,
			installed,
			wasRunning,
			fmt.Errorf("verify installed Mihomo version: got %s, want %s", currentVersion, release.Tag),
		)
	}
	if err := transactionContext.Err(); err != nil {
		return web.CoreUpdateResult{}, service.rollbackSwappedUpdate(target, installed, wasRunning, err)
	}
	return web.CoreUpdateResult{PreviousVersion: previousVersion, CurrentVersion: currentVersion, Restarted: wasRunning}, nil
}

// rollbackSwappedUpdate restores the on-disk binary for every failure after a
// successful swap. If the manager is still alive, a previously running core is
// brought back; during manager shutdown the safe prior service state is
// stopped. Recovery is detached from the failed transaction so cancellation
// cannot prevent the reverse swap or fail-open lifecycle cleanup.
func (service *MihomoUpdateService) rollbackSwappedUpdate(target string, hadPrevious, wasRunning bool, cause error) error {
	recoveryContext, cancelRecovery := context.WithTimeout(context.Background(), service.detachedRecoveryTimeout())
	defer cancelRecovery()

	var stopErr error
	if service.Lifecycle.Snapshot().State != LifecycleStopped {
		stopErr = service.Lifecycle.stopLocked(recoveryContext)
	}
	var rollbackErr error
	if hadPrevious {
		rollbackErr = service.rollback(target)
	} else {
		rollbackErr = removeFreshCoreInstall(target)
	}
	var restartErr error
	if wasRunning && stopErr == nil && rollbackErr == nil && service.serviceContext().Err() == nil {
		restartErr = service.restartPreviousLifecycle(recoveryContext)
	}
	return errors.Join(
		cause,
		wrapUpdateError("stop updated Mihomo", stopErr),
		wrapUpdateError("restore previous Mihomo", rollbackErr),
		wrapUpdateError("restart previous Mihomo", restartErr),
	)
}

func (service *MihomoUpdateService) restartPreviousLifecycleBounded() error {
	recoveryContext, cancelRecovery := context.WithTimeout(context.Background(), service.detachedRecoveryTimeout())
	defer cancelRecovery()
	return service.restartPreviousLifecycle(recoveryContext)
}

func (service *MihomoUpdateService) restartPreviousLifecycle(recoveryContext context.Context) error {
	// Combine manager cancellation with the detached recovery deadline. Keeping
	// that deadline visible is important: lifecycle cleanup detaches cancellation
	// but must never extend an expired recovery window.
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
	// Cancellation may race with the pre-restart check. Normalize that race to
	// the manager-shutdown contract: the old binary is restored but no core is
	// left running while the daemon exits.
	stopErr := service.Lifecycle.stopLocked(recoveryContext)
	return errors.Join(restartErr, wrapUpdateError("stop previous Mihomo after manager shutdown", stopErr))
}

func (service *MihomoUpdateService) detachedRecoveryTimeout() time.Duration {
	if service.recoveryTimeout > 0 {
		return service.recoveryTimeout
	}
	return mihomoUpdateRecoveryTimeout
}

func (service *MihomoUpdateService) validate() error {
	if service == nil || service.Preparer == nil || service.Lifecycle == nil || service.Versioner == nil || service.Source == nil || service.Installer == nil || service.install == nil || service.rollback == nil {
		return errors.New("mihomo update service is not initialized")
	}
	return nil
}

func (service *MihomoUpdateService) targetPath() (string, bool, error) {
	target, err := service.Preparer.binaryPath()
	if err == nil {
		return target, true, nil
	}
	if !errors.Is(err, errMihomoBinaryNotInstalled) {
		return "", false, err
	}
	// New installations use the engine-specific directory. Existing custom
	// binary paths continue to be resolved by binaryPath above.
	return filepath.Join(service.Preparer.Layout.EnginesDir, "mihomo", "mihomo"), false, nil
}

func removeFreshCoreInstall(target string) error {
	info, err := os.Lstat(target)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("refusing to remove an unsafe fresh Mihomo target")
	}
	if err := os.Remove(target); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (service *MihomoUpdateService) serviceContext() context.Context {
	if service.ServiceContext != nil {
		return service.ServiceContext
	}
	return context.Background()
}

func (service *MihomoUpdateService) channel() (update.Channel, error) {
	runtimeSettings, err := LoadRuntimeSettings(service.State)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	value := valueOr(runtimeSettings.Raw, "UPDATE_CHANNEL", string(update.ChannelStable))
	channel := update.Channel(value)
	if channel != update.ChannelStable && channel != update.ChannelAlpha {
		return "", fmt.Errorf("unsupported update channel %q", value)
	}
	return channel, nil
}

var mihomoVersionPattern = regexp.MustCompile(`(?i)\bv[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?\b`)

func extractMihomoVersion(value string) string {
	match := mihomoVersionPattern.FindString(value)
	if match == "" {
		return ""
	}
	return "v" + strings.TrimPrefix(strings.TrimPrefix(match, "v"), "V")
}

func wrapUpdateError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

type stagedMihomoValidator struct {
	Preparer  *ActiveMihomoPreparer
	Versioner coreVersioner
}

func (validator *stagedMihomoValidator) ValidateBinary(ctx context.Context, binaryPath string) error {
	if validator == nil || validator.Preparer == nil {
		return errors.New("staged Mihomo validator is not initialized")
	}
	active, activeErr := validator.Preparer.Profiles.Current()
	if activeErr == nil && active.Engine != "" && active.Engine != state.EngineMihomo {
		// There is no selected Mihomo configuration to validate while another
		// engine is active. Still execute the candidate and require native Mihomo
		// version output before it may replace the inactive binary.
		return validator.validateVersion(ctx, binaryPath)
	}
	if activeErr != nil && !errors.Is(activeErr, fs.ErrNotExist) {
		return fmt.Errorf("read active profile for staged Mihomo validation: %w", activeErr)
	}
	candidate := *validator.Preparer
	candidate.BinaryOverride = binaryPath
	prepared, err := candidate.PrepareActive(ctx)
	if errors.Is(err, fs.ErrNotExist) {
		// Clean install has no profile yet. Digest, gzip and ELF checks have
		// already succeeded; execute the candidate and require a parseable native
		// version before it can become the first installed core.
		return validator.validateVersion(ctx, binaryPath)
	}
	if err != nil {
		return err
	}
	engine.CleanupPreparedRuntime(prepared)
	return nil
}

func (validator *stagedMihomoValidator) validateVersion(ctx context.Context, binaryPath string) error {
	if validator.Versioner == nil {
		return errors.New("staged Mihomo version validator is unavailable")
	}
	version, err := validator.Versioner.Version(ctx, binaryPath)
	if err != nil {
		return err
	}
	if extractMihomoVersion(version) == "" {
		return errors.New("staged Mihomo version output is invalid")
	}
	return nil
}

var _ web.CoreUpdateService = (*MihomoUpdateService)(nil)
var _ update.BinaryValidator = (*stagedMihomoValidator)(nil)
