package app

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/platform/openwrt"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/update"
)

type managerReleaseSourceFake struct{ release update.Release }

func (source managerReleaseSourceFake) Latest(context.Context, update.Channel) (update.Release, error) {
	return source.release, nil
}

type managerBinaryInstallerFake struct{ content []byte }

func (installer managerBinaryInstallerFake) StageRaw(_ context.Context, _ update.Asset, directory string) (string, error) {
	return writeManagerStagedBinary(directory, installer.content)
}

func (installer managerBinaryInstallerFake) StageFile(_ context.Context, _, _, directory string) (string, error) {
	return writeManagerStagedBinary(directory, installer.content)
}

type unusedManagerRunner struct{}

func (unusedManagerRunner) Run(context.Context, openwrt.Command) (openwrt.Result, error) {
	return openwrt.Result{}, errors.New("unexpected manager runner call")
}

type recordingManagerRunner struct{ commands []openwrt.Command }

func (runner *recordingManagerRunner) Run(_ context.Context, command openwrt.Command) (openwrt.Result, error) {
	runner.commands = append(runner.commands, command)
	return openwrt.Result{}, nil
}

func TestManagerUpdateCheckAndRemoteInstall(t *testing.T) {
	root := t.TempDir()
	target := managerTestTarget(t, root, "2025.01.14")
	service := managerTestUpdateService(t, root, "2025.01.15")

	status, err := service.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.CurrentVersion != "2025.01.14" || status.LatestVersion != "2025.01.15" || !status.UpdateAvailable {
		t.Fatalf("unexpected update status: %#v", status)
	}

	var restarted []string
	service.restartAndVerify = func(_ context.Context, path, version string, mode managerRestartMode) error {
		restarted = append(restarted, version)
		if mode != managerRestartOnly {
			t.Fatalf("restart mode = %q, want manager-only", mode)
		}
		if path != target {
			t.Fatalf("restart target = %q, want %q", path, target)
		}
		return nil
	}
	result, err := service.Install(context.Background(), "", "", false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || !result.Restarted || result.PreviousVersion != "2025.01.14" || result.CurrentVersion != "2025.01.15" {
		t.Fatalf("unexpected install result: %#v", result)
	}
	if len(restarted) != 1 || restarted[0] != "2025.01.15" {
		t.Fatalf("restart versions = %v", restarted)
	}
	assertManagerBinaryVersion(t, target, "2025.01.15")
	assertManagerBinaryVersion(t, target+".prev", "2025.01.14")
}

func TestManagerUpdateRollbackAfterFailedRestart(t *testing.T) {
	root := t.TempDir()
	target := managerTestTarget(t, root, "2025.01.14")
	service := managerTestUpdateService(t, root, "2025.01.15")
	restartFailure := errors.New("new manager did not stay running")
	var restarted []string
	service.restartAndVerify = func(_ context.Context, _ string, version string, _ managerRestartMode) error {
		restarted = append(restarted, version)
		if version == "2025.01.15" {
			return restartFailure
		}
		return nil
	}

	if _, err := service.Install(context.Background(), "", "", false, false, nil); !errors.Is(err, restartFailure) {
		t.Fatalf("Install() error = %v, want restart failure", err)
	}
	if len(restarted) != 2 || restarted[1] != "2025.01.14" {
		t.Fatalf("restart recovery = %v", restarted)
	}
	assertManagerBinaryVersion(t, target, "2025.01.14")
	assertManagerBinaryVersion(t, target+".failed", "2025.01.15")
}

func TestManagerUpdateRejectsReleaseVersionMismatchBeforeSwap(t *testing.T) {
	root := t.TempDir()
	target := managerTestTarget(t, root, "2025.01.14")
	service := managerTestUpdateService(t, root, "2025.01.15")
	service.Installer = managerBinaryInstallerFake{content: managerTestELF("2025.01.16")}

	if _, err := service.Install(context.Background(), "", "", false, false, nil); err == nil {
		t.Fatal("release version mismatch was accepted")
	}
	assertManagerBinaryVersion(t, target, "2025.01.14")
	if _, err := os.Stat(target + ".prev"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target was swapped before version rejection: %v", err)
	}
}

func TestManagerUpdateFromLocalFileAndManualRollback(t *testing.T) {
	root := t.TempDir()
	target := managerTestTarget(t, root, "2025.01.14")
	candidate := filepath.Join(t.TempDir(), "boxctl-linux-arm64")
	content := managerTestELF("dev-local")
	if err := os.WriteFile(candidate, content, 0o755); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	if err := os.WriteFile(candidate+".sha256", []byte(hex.EncodeToString(digest[:])+"  boxctl-linux-arm64\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	service := &managerUpdateService{
		Layout: layout, Store: store, Source: managerReleaseSourceFake{release: managerTestRelease("2025.01.15")},
		Installer: &update.Installer{}, Runner: unusedManagerRunner{}, install: update.Install, rollback: update.Rollback,
	}
	service.readBuildInfo = readManagerTestBuildInfo
	service.restartAndVerify = func(context.Context, string, string, managerRestartMode) error { return nil }

	result, err := service.Install(context.Background(), candidate, "", true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Restarted || result.Source != candidate || result.CurrentVersion != "dev-local" {
		t.Fatalf("local install result = %#v", result)
	}
	assertManagerBinaryVersion(t, target, "dev-local")

	rolledBack, err := service.Rollback(context.Background(), true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.CurrentVersion != "2025.01.14" || rolledBack.Restarted {
		t.Fatalf("rollback result = %#v", rolledBack)
	}
	assertManagerBinaryVersion(t, target, "2025.01.14")
}

func TestResolveLocalUpdateDigestRequiresCanonicalSHA256(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	if actual, err := resolveLocalUpdateDigest("/unused", strings.ToUpper(digest)); err != nil || actual != "sha256:"+digest {
		t.Fatalf("explicit digest = %q, %v", actual, err)
	}
	if _, err := resolveLocalUpdateDigest("/missing", "not-a-digest"); err == nil {
		t.Fatal("invalid local digest was accepted")
	}
}

func TestParseManagerVersionOutputMatchesVersionCommand(t *testing.T) {
	version, err := parseManagerVersionOutput([]byte("boxctl 2025.01.15 (commit 0123456789abcdef, built 2025-01-31T16:00:00Z)\n"))
	if err != nil || version != "2025.01.15" {
		t.Fatalf("parseManagerVersionOutput() = %q, %v", version, err)
	}
	for _, invalid := range [][]byte{
		[]byte("boxctl 2025.01.15 (commit 0123456789abcdef)\n"),
		[]byte("boxctl 2025.01.15 (commit x, built y)\ntrailing"),
	} {
		if _, err := parseManagerVersionOutput(invalid); err == nil {
			t.Fatalf("invalid version output was accepted: %q", invalid)
		}
	}
}

func TestChooseManagerRestartUsesCompatibilityAndConfirmation(t *testing.T) {
	compatible := managerBuildInfo{Version: "2025.01.14", SettingsSchemaVersion: 1, CaptureInjectorVersion: 2}
	next := managerBuildInfo{Version: "2025.01.15", SettingsSchemaVersion: 1, CaptureInjectorVersion: 2}
	if mode, err := chooseManagerRestart(compatible, next, false, false, nil); err != nil || mode != managerRestartOnly {
		t.Fatalf("compatible restart = %q, %v", mode, err)
	}
	if mode, err := chooseManagerRestart(compatible, next, false, true, nil); err != nil || mode != managerRestartFull {
		t.Fatalf("forced restart = %q, %v", mode, err)
	}
	changed := next
	changed.CaptureInjectorVersion = 3
	called := false
	mode, err := chooseManagerRestart(compatible, changed, false, false, func(warning string) (bool, error) {
		called = strings.Contains(warning, "capture injector 2 -> 3")
		return true, nil
	})
	if err != nil || mode != managerRestartFull || !called {
		t.Fatalf("confirmed incompatible restart = %q, %v, called=%t", mode, err, called)
	}
	if _, err := chooseManagerRestart(compatible, changed, false, false, func(string) (bool, error) { return false, nil }); err == nil {
		t.Fatal("declined incompatible restart was accepted")
	}
	if mode, err := chooseManagerRestart(compatible, changed, true, false, nil); err != nil || mode != managerRestartNone {
		t.Fatalf("no-restart = %q, %v", mode, err)
	}
}

func TestManagerOnlyUpdateSignalsReloadAndCleansUnacknowledgedMarker(t *testing.T) {
	root := t.TempDir()
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingManagerRunner{}
	service := &managerUpdateService{Layout: layout, Runner: runner}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := service.restartManagerAndVerify(ctx, filepath.Join(layout.BinDir, "boxctl"), "next", managerRestartOnly); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("restartManagerAndVerify() error = %v", err)
	}
	if len(runner.commands) != 1 || runner.commands[0].Name != managerServiceScript || !slices.Equal(runner.commands[0].Args, []string{"manager_handoff"}) {
		t.Fatalf("manager handoff commands = %#v", runner.commands)
	}
	if present, err := managerHandoffPresent(layout); err != nil || present {
		t.Fatalf("unacknowledged handoff marker present=%t, err=%v", present, err)
	}
}

func managerTestUpdateService(t *testing.T, root, latest string) *managerUpdateService {
	t.Helper()
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	service := &managerUpdateService{
		Layout: layout, Store: store, Source: managerReleaseSourceFake{release: managerTestRelease(latest)},
		Installer: managerBinaryInstallerFake{content: managerTestELF(latest)}, Runner: unusedManagerRunner{},
		install: update.Install, rollback: update.Rollback,
	}
	service.readBuildInfo = readManagerTestBuildInfo
	service.restartAndVerify = func(context.Context, string, string, managerRestartMode) error { return nil }
	return service
}

func managerTestRelease(version string) update.Release {
	return update.Release{Tag: "v" + version, Assets: []update.Asset{{
		Name:   "boxctl-linux-arm64-" + version,
		URL:    "https://github.com/kontsevoye/boxctl/releases/download/v" + version + "/boxctl-linux-arm64-" + version,
		Digest: "sha256:58896873736d28628f66de3677c8654fa0f180662523148e136cff4f6e890069",
		Size:   1024,
	}}}
}

func managerTestTarget(t *testing.T, root, version string) string {
	t.Helper()
	directory := filepath.Join(root, "bin")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "boxctl")
	if err := os.WriteFile(target, managerTestELF(version), 0o755); err != nil {
		t.Fatal(err)
	}
	return target
}

func writeManagerStagedBinary(directory string, content []byte) (string, error) {
	file, err := os.CreateTemp(directory, ".boxctl-test-*")
	if err != nil {
		return "", err
	}
	path := file.Name()
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if err := os.Chmod(path, 0o755); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func managerTestELF(version string) []byte {
	header := make([]byte, 64)
	copy(header[:4], []byte{0x7f, 'E', 'L', 'F'})
	header[4], header[5], header[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(header[16:18], 2)
	binary.LittleEndian.PutUint16(header[18:20], 183)
	binary.LittleEndian.PutUint32(header[20:24], 1)
	binary.LittleEndian.PutUint16(header[52:54], 64)
	binary.LittleEndian.PutUint16(header[54:56], 56)
	binary.LittleEndian.PutUint16(header[58:60], 64)
	return append(header, []byte(version)...)
}

func readManagerTestVersion(_ context.Context, path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(content) < 64 {
		return "", errors.New("test binary is truncated")
	}
	return string(content[64:]), nil
}

func readManagerTestBuildInfo(ctx context.Context, path string) (managerBuildInfo, error) {
	version, err := readManagerTestVersion(ctx, path)
	return managerBuildInfo{Version: version, SettingsSchemaVersion: 1, CaptureInjectorVersion: 1}, err
}

func assertManagerBinaryVersion(t *testing.T, path, version string) {
	t.Helper()
	actual, err := readManagerTestVersion(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if actual != version {
		t.Fatalf("%s version = %q, want %q", path, actual, version)
	}
}
