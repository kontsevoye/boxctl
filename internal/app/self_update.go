package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kontsevoye/boxctl/internal/cli"
	"github.com/kontsevoye/boxctl/internal/platform/openwrt"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/update"
)

const (
	managerServiceScript          = "/etc/init.d/boxctl"
	managerUpdateTransactionLimit = 60 * time.Second
	managerRestartPollInterval    = time.Second
	managerRestartStablePolls     = 2
)

type managerReleaseSource interface {
	Latest(context.Context, update.Channel) (update.Release, error)
}

type managerBinaryInstaller interface {
	StageRaw(context.Context, update.Asset, string) (string, error)
	StageFile(context.Context, string, string, string) (string, error)
}

type managerUpdateStatus struct {
	CurrentVersion  string
	LatestVersion   string
	ReleaseTag      string
	UpdateAvailable bool
}

type managerUpdateResult struct {
	PreviousVersion string
	CurrentVersion  string
	Source          string
	Changed         bool
	Restarted       bool
	RestartMode     managerRestartMode
}

type managerBuildInfo struct {
	Version                string `json:"version"`
	Commit                 string `json:"commit"`
	Date                   string `json:"date"`
	SettingsSchemaVersion  int    `json:"settingsSchemaVersion"`
	CaptureInjectorVersion int    `json:"captureInjectorVersion"`
}

type managerRestartMode string

const (
	managerRestartNone managerRestartMode = "none"
	managerRestartOnly managerRestartMode = "manager-only"
	managerRestartFull managerRestartMode = "full"
)

type managerUpdateService struct {
	Layout    state.Layout
	Store     state.Store
	Source    managerReleaseSource
	Installer managerBinaryInstaller
	Runner    openwrt.Runner

	install          func(string, string) error
	rollback         func(string) error
	readBuildInfo    func(context.Context, string) (managerBuildInfo, error)
	restartAndVerify func(context.Context, string, string, managerRestartMode) error
}

func newManagerUpdateService(root, repository string, runner openwrt.Runner) (*managerUpdateService, error) {
	layout, err := state.NewLayout(root)
	if err != nil {
		return nil, err
	}
	store, err := state.NewStore(root)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 90 * time.Second}
	service := &managerUpdateService{
		Layout: layout, Store: store, Source: update.NewBoxctlSource(client, repository),
		Installer: &update.Installer{Client: client}, Runner: runner,
		install: update.Install, rollback: update.Rollback,
	}
	service.readBuildInfo = service.readManagerBuildInfo
	service.restartAndVerify = service.restartManagerAndVerify
	return service, nil
}

// SelfUpdate performs only an explicit CLI-requested manager update. It is not
// exposed through the running HTTP process, avoiding a daemon replacing and
// terminating itself in the middle of an authenticated request.
func (actions *Actions) SelfUpdate(ctx context.Context, options cli.SelfUpdateOptions) error {
	root, err := actions.resolveRoot(options.Root)
	if err != nil {
		return err
	}
	if err := actions.requirePlatform(ctx); err != nil {
		return err
	}
	if options.Action != "check" && !options.NoRestart && root != state.DefaultRoot {
		return errors.New("self-update for a non-default root requires --no-restart")
	}
	service, err := newManagerUpdateService(root, options.Repository, actions.runner)
	if err != nil {
		return err
	}
	switch options.Action {
	case "check":
		status, err := service.Check(ctx)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(actions.out, "current: %s\nlatest: %s (%s)\nupdate available: %t\n", status.CurrentVersion, status.LatestVersion, status.ReleaseTag, status.UpdateAvailable)
		return err
	case "install":
		result, err := service.Install(ctx, options.File, options.SHA256, options.NoRestart, options.FullRestart, options.ConfirmFullRestart)
		if err != nil {
			return err
		}
		if !result.Changed {
			_, err = fmt.Fprintf(actions.out, "boxctl %s is already current\n", result.CurrentVersion)
			return err
		}
		_, err = fmt.Fprintf(actions.out, "updated boxctl %s -> %s from %s; restart: %s\n", result.PreviousVersion, result.CurrentVersion, result.Source, result.RestartMode)
		return err
	case "rollback":
		result, err := service.Rollback(ctx, options.NoRestart, options.FullRestart, options.ConfirmFullRestart)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(actions.out, "rolled back boxctl %s -> %s; restart: %s\n", result.PreviousVersion, result.CurrentVersion, result.RestartMode)
		return err
	default:
		return fmt.Errorf("unknown self-update action %q", options.Action)
	}
}

func (service *managerUpdateService) Check(ctx context.Context) (status managerUpdateStatus, returnErr error) {
	lock, err := service.Store.Lock(ctx, "self-update")
	if err != nil {
		return status, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Unlock()) }()
	return service.checkLocked(ctx)
}

func (service *managerUpdateService) checkLocked(ctx context.Context) (managerUpdateStatus, error) {
	if err := service.validate(); err != nil {
		return managerUpdateStatus{}, err
	}
	target := filepath.Join(service.Layout.BinDir, "boxctl")
	if err := validateManagerTarget(target, service.Layout); err != nil {
		return managerUpdateStatus{}, err
	}
	currentBuild, err := service.readBuildInfo(ctx, target)
	if err != nil {
		return managerUpdateStatus{}, fmt.Errorf("read installed boxctl version: %w", err)
	}
	release, err := service.Source.Latest(ctx, update.ChannelStable)
	if err != nil {
		return managerUpdateStatus{}, fmt.Errorf("discover boxctl release: %w", err)
	}
	latest, err := update.ParseBoxctlCalVerTag(release.Tag)
	if err != nil {
		return managerUpdateStatus{}, err
	}
	if _, err := release.BoxctlLinuxARM64(); err != nil {
		return managerUpdateStatus{}, err
	}
	return managerUpdateStatus{
		CurrentVersion: currentBuild.Version, LatestVersion: latest, ReleaseTag: release.Tag,
		UpdateAvailable: managerUpdateAvailable(currentBuild.Version, latest),
	}, nil
}

func (service *managerUpdateService) Install(ctx context.Context, localFile, requestedDigest string, noRestart, fullRestart bool, confirm func(string) (bool, error)) (result managerUpdateResult, returnErr error) {
	lock, err := service.Store.Lock(ctx, "self-update")
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Unlock()) }()
	if err := service.validate(); err != nil {
		return result, err
	}
	target := filepath.Join(service.Layout.BinDir, "boxctl")
	if err := validateManagerTarget(target, service.Layout); err != nil {
		return result, err
	}
	currentBuild, err := service.readBuildInfo(ctx, target)
	if err != nil {
		return result, fmt.Errorf("read installed boxctl build information: %w", err)
	}
	current := currentBuild.Version

	var staged, expectedVersion, sourceName string
	if strings.TrimSpace(localFile) != "" {
		localFile = filepath.Clean(strings.TrimSpace(localFile))
		if !filepath.IsAbs(localFile) {
			return result, errors.New("local update file path must be absolute")
		}
		digest, digestErr := resolveLocalUpdateDigest(localFile, requestedDigest)
		if digestErr != nil {
			return result, digestErr
		}
		staged, err = service.Installer.StageFile(ctx, localFile, digest, filepath.Dir(target))
		sourceName = localFile
	} else {
		release, releaseErr := service.Source.Latest(ctx, update.ChannelStable)
		if releaseErr != nil {
			return result, fmt.Errorf("discover boxctl release: %w", releaseErr)
		}
		expectedVersion, releaseErr = update.ParseBoxctlCalVerTag(release.Tag)
		if releaseErr != nil {
			return result, releaseErr
		}
		if !managerUpdateAvailable(current, expectedVersion) {
			return managerUpdateResult{PreviousVersion: current, CurrentVersion: current, Source: release.Tag}, nil
		}
		asset, assetErr := release.BoxctlLinuxARM64()
		if assetErr != nil {
			return result, assetErr
		}
		staged, err = service.Installer.StageRaw(ctx, asset, filepath.Dir(target))
		sourceName = release.Tag
	}
	if err != nil {
		return result, err
	}
	defer func() { _ = os.Remove(staged) }()
	candidateBuild, err := service.readBuildInfo(ctx, staged)
	if err != nil {
		return result, fmt.Errorf("validate staged boxctl: %w", err)
	}
	candidateVersion := candidateBuild.Version
	if expectedVersion != "" && candidateVersion != expectedVersion {
		return result, fmt.Errorf("release binary version mismatch: got %s, want %s", candidateVersion, expectedVersion)
	}
	if candidateVersion == current {
		return managerUpdateResult{PreviousVersion: current, CurrentVersion: current, Source: sourceName}, nil
	}
	restartMode, err := chooseManagerRestart(currentBuild, candidateBuild, noRestart, fullRestart, confirm)
	if err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	transactionContext, cancelTransaction := context.WithTimeout(context.Background(), managerUpdateTransactionLimit)
	defer cancelTransaction()
	if err := service.install(staged, target); err != nil {
		return result, fmt.Errorf("install boxctl update: %w", err)
	}
	result = managerUpdateResult{
		PreviousVersion: current, CurrentVersion: candidateVersion, Source: sourceName,
		Changed: true, Restarted: restartMode != managerRestartNone, RestartMode: restartMode,
	}
	if restartMode == managerRestartNone {
		return result, nil
	}
	if err := service.restartAndVerify(transactionContext, target, candidateVersion, restartMode); err != nil {
		recoveryContext, cancelRecovery := context.WithTimeout(context.Background(), managerUpdateTransactionLimit)
		defer cancelRecovery()
		rollbackErr := service.rollback(target)
		var restoreErr error
		if rollbackErr == nil {
			restoreErr = service.restartAndVerify(recoveryContext, target, current, managerRestartFull)
		}
		return managerUpdateResult{}, errors.Join(
			fmt.Errorf("updated boxctl failed verification: %w", err),
			wrapUpdateError("restore previous boxctl binary", rollbackErr),
			wrapUpdateError("restart previous boxctl binary", restoreErr),
		)
	}
	return result, nil
}

func (service *managerUpdateService) Rollback(ctx context.Context, noRestart, fullRestart bool, confirm func(string) (bool, error)) (result managerUpdateResult, returnErr error) {
	lock, err := service.Store.Lock(ctx, "self-update")
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Unlock()) }()
	if err := service.validate(); err != nil {
		return result, err
	}
	target := filepath.Join(service.Layout.BinDir, "boxctl")
	if err := validateManagerTarget(target, service.Layout); err != nil {
		return result, err
	}
	previousTarget := target + ".prev"
	if err := validateManagerBinary(previousTarget); err != nil {
		return result, fmt.Errorf("validate rollback boxctl binary: %w", err)
	}
	currentBuild, err := service.readBuildInfo(ctx, target)
	if err != nil {
		return result, fmt.Errorf("read installed boxctl version: %w", err)
	}
	previousBuild, err := service.readBuildInfo(ctx, previousTarget)
	if err != nil {
		return result, fmt.Errorf("read rollback boxctl version: %w", err)
	}
	restartMode, err := chooseManagerRestart(currentBuild, previousBuild, noRestart, fullRestart, confirm)
	if err != nil {
		return result, err
	}
	current, previous := currentBuild.Version, previousBuild.Version
	transactionContext, cancelTransaction := context.WithTimeout(context.Background(), managerUpdateTransactionLimit)
	defer cancelTransaction()
	if err := service.rollback(target); err != nil {
		return result, err
	}
	result = managerUpdateResult{PreviousVersion: current, CurrentVersion: previous, Source: "rollback", Changed: true, Restarted: restartMode != managerRestartNone, RestartMode: restartMode}
	if restartMode == managerRestartNone {
		return result, nil
	}
	if err := service.restartAndVerify(transactionContext, target, previous, restartMode); err != nil {
		return managerUpdateResult{}, fmt.Errorf("rolled back boxctl failed verification: %w", err)
	}
	return result, nil
}

func (service *managerUpdateService) validate() error {
	if service == nil || service.Source == nil || service.Installer == nil || service.Runner == nil || service.install == nil || service.rollback == nil || service.readBuildInfo == nil || service.restartAndVerify == nil {
		return errors.New("boxctl self-update service is not initialized")
	}
	return nil
}

func validateManagerTarget(target string, layout state.Layout) error {
	for _, directory := range []string{layout.Root, layout.BinDir} {
		info, err := os.Lstat(directory)
		if err != nil {
			return fmt.Errorf("inspect boxctl directory %s: %w", directory, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("boxctl directory must be a non-symlink directory: %s", directory)
		}
	}
	return validateManagerBinary(target)
}

func validateManagerBinary(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect boxctl binary: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return errors.New("boxctl binary must be an executable regular non-symlink file")
	}
	return update.ValidateLinuxARM64(path)
}

var managerVersionOutput = regexp.MustCompile(`^boxctl ([A-Za-z0-9][A-Za-z0-9._+-]*) \(commit [^,\r\n]+, built [^)\r\n]+\)$`)

func parseManagerVersionOutput(output []byte) (string, error) {
	match := managerVersionOutput.FindStringSubmatch(strings.TrimSpace(string(output)))
	if len(match) != 2 {
		return "", errors.New("boxctl version output is invalid")
	}
	return match[1], nil
}

func (service *managerUpdateService) readManagerBuildInfo(ctx context.Context, path string) (managerBuildInfo, error) {
	if err := validateManagerBinary(path); err != nil {
		return managerBuildInfo{}, err
	}
	result, jsonErr := service.Runner.Run(ctx, openwrt.Command{Name: path, Args: []string{"version", "--json"}})
	if jsonErr == nil && result.ExitCode == 0 {
		var info managerBuildInfo
		if err := json.Unmarshal(result.Stdout, &info); err == nil && info.Version != "" && info.SettingsSchemaVersion > 0 && info.CaptureInjectorVersion > 0 {
			return info, nil
		}
	}
	result, err := service.Runner.Run(ctx, openwrt.Command{Name: path, Args: []string{"version"}})
	if err != nil {
		return managerBuildInfo{}, err
	}
	if result.ExitCode != 0 {
		return managerBuildInfo{}, commandResultError(path+" version", result)
	}
	version, err := parseManagerVersionOutput(result.Stdout)
	return managerBuildInfo{Version: version}, err
}

func (service *managerUpdateService) restartManagerAndVerify(ctx context.Context, target, expectedVersion string, mode managerRestartMode) error {
	handoffPending := false
	if mode == managerRestartOnly {
		if err := writeManagerHandoff(service.Layout, expectedVersion); err != nil {
			return fmt.Errorf("prepare core-preserving manager handoff: %w", err)
		}
		handoffPending = true
	} else {
		_ = removeManagerHandoff(service.Layout)
	}
	defer func() {
		if handoffPending {
			_ = removeManagerHandoff(service.Layout)
		}
	}()
	action := "restart"
	if mode == managerRestartOnly {
		action = "manager_handoff"
	}
	result, err := service.Runner.Run(ctx, openwrt.Command{Name: managerServiceScript, Args: []string{action}})
	if err != nil {
		_ = removeManagerHandoff(service.Layout)
		return err
	}
	if result.ExitCode != 0 {
		_ = removeManagerHandoff(service.Layout)
		return commandResultError(action+" boxctl service", result)
	}
	stable := 0
	for stable < managerRestartStablePolls {
		if err := waitContext(ctx, managerRestartPollInterval); err != nil {
			return err
		}
		result, err = service.Runner.Run(ctx, openwrt.Command{Name: managerServiceScript, Args: []string{"running"}})
		if err != nil {
			return err
		}
		if result.ExitCode == 0 {
			if mode == managerRestartOnly {
				present, markerErr := managerHandoffPresent(service.Layout)
				if markerErr != nil {
					return markerErr
				}
				if present {
					stable = 0
					continue
				}
			}
			stable++
			continue
		}
		stable = 0
	}
	build, err := service.readBuildInfo(ctx, target)
	if err != nil {
		return err
	}
	if build.Version != expectedVersion {
		return fmt.Errorf("running boxctl target version is %s, want %s", build.Version, expectedVersion)
	}
	handoffPending = false
	return nil
}

func chooseManagerRestart(current, candidate managerBuildInfo, noRestart, fullRestart bool, confirm func(string) (bool, error)) (managerRestartMode, error) {
	if noRestart && fullRestart {
		return managerRestartNone, errors.New("--no-restart and --full-restart cannot be used together")
	}
	if noRestart {
		return managerRestartNone, nil
	}
	compatible := current.SettingsSchemaVersion > 0 && current.CaptureInjectorVersion > 0 &&
		current.SettingsSchemaVersion == candidate.SettingsSchemaVersion &&
		current.CaptureInjectorVersion == candidate.CaptureInjectorVersion
	if compatible && !fullRestart {
		return managerRestartOnly, nil
	}
	warning := fmt.Sprintf("WARNING: boxctl %s -> %s changes runtime compatibility (settings schema %d -> %d; capture injector %d -> %d).", current.Version, candidate.Version, current.SettingsSchemaVersion, candidate.SettingsSchemaVersion, current.CaptureInjectorVersion, candidate.CaptureInjectorVersion)
	if fullRestart {
		if confirm != nil {
			if _, err := confirm(warning); err != nil {
				return managerRestartNone, fmt.Errorf("report full restart: %w", err)
			}
		}
		return managerRestartFull, nil
	}
	if confirm == nil {
		return managerRestartNone, fmt.Errorf("%s Re-run with --full-restart to approve restarting Mihomo", warning)
	}
	approved, err := confirm(warning)
	if err != nil {
		return managerRestartNone, fmt.Errorf("confirm full restart: %w", err)
	}
	if !approved {
		return managerRestartNone, errors.New("self-update cancelled before replacing the binary")
	}
	return managerRestartFull, nil
}

func resolveLocalUpdateDigest(localFile, requested string) (string, error) {
	value := strings.TrimSpace(requested)
	if value == "" {
		content, err := readBoundedRegular(localFile+".sha256", 4096)
		if err != nil {
			return "", fmt.Errorf("read companion checksum %s.sha256: %w", localFile, err)
		}
		fields := strings.Fields(string(content))
		if len(fields) == 0 {
			return "", errors.New("companion checksum file is empty")
		}
		value = fields[0]
	}
	value = strings.TrimPrefix(strings.ToLower(value), "sha256:")
	if len(value) != 64 {
		return "", errors.New("SHA-256 must contain exactly 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", errors.New("SHA-256 contains non-hexadecimal characters")
	}
	return "sha256:" + value, nil
}

func managerUpdateAvailable(current, latest string) bool {
	if current == latest {
		return false
	}
	comparison, err := update.CompareBoxctlCalVer(current, latest)
	if err != nil {
		return true
	}
	return comparison < 0
}

func commandResultError(operation string, result openwrt.Result) error {
	detail := strings.TrimSpace(string(result.Stderr))
	if detail == "" {
		detail = strings.TrimSpace(string(result.Stdout))
	}
	if detail == "" {
		return fmt.Errorf("%s exited with %d", operation, result.ExitCode)
	}
	return fmt.Errorf("%s exited with %d: %s", operation, result.ExitCode, detail)
}

func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
