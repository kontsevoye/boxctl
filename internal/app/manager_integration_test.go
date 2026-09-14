package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kontsevoye/boxctl/internal/state"
	openwrtfiles "github.com/kontsevoye/boxctl/packaging/openwrt"
)

func TestManagerIntegrationUpdateAndRollbackPreserveUCI(t *testing.T) {
	service, target, old, next := integrationUpdateFixture(t)
	store := state.Store{Root: service.IntegrationRoot}
	custom := []byte("config boxctl 'main'\n option public_origin 'https://boxctl.lan'\n")
	if err := store.Write("etc/config/boxctl", custom, 0o600); err != nil {
		t.Fatal(err)
	}
	var modes []managerRestartMode
	service.restartAndVerify = func(_ context.Context, _, _ string, mode managerRestartMode) error {
		modes = append(modes, mode)
		return nil
	}
	confirmed := false
	result, err := service.Install(context.Background(), "", "", false, false, func(warning string) (bool, error) {
		confirmed = strings.Contains(warning, "OpenWrt integration")
		return true, nil
	})
	if err != nil || result.RestartMode != managerRestartFull || !confirmed {
		t.Fatalf("integration update = %+v, %v; confirmed=%t", result, err, confirmed)
	}
	assertIntegrationManifest(t, service, next)
	assertIntegrationData(t, store, "etc/config/boxctl", custom)
	// Administrator changes made after an update must also survive rollback.
	custom = append(custom, []byte(" option allowed_hosts 'router.home'\n")...)
	if err := store.Write("etc/config/boxctl", custom, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Rollback(context.Background(), false, true, nil); err != nil {
		t.Fatal(err)
	}
	assertManagerBinaryVersion(t, target, "2025.01.14")
	assertIntegrationManifest(t, service, old)
	assertIntegrationData(t, store, "etc/config/boxctl", custom)
	if !slices.Equal(modes, []managerRestartMode{managerRestartFull, managerRestartFull}) {
		t.Fatalf("activation modes = %v", modes)
	}
}

func TestManagerIntegrationDetectsInstalledDriftAndMissingFiles(t *testing.T) {
	for _, drift := range []string{"old-init", "missing-hook", "wrong-mode", "missing-uci", "unknown-version"} {
		t.Run(drift, func(t *testing.T) {
			root := t.TempDir()
			target := managerTestTarget(t, root, "2025.01.14")
			service := managerTestUpdateService(t, root, "2025.01.15")
			store := state.Store{Root: service.IntegrationRoot}
			var err error
			switch drift {
			case "old-init":
				err = store.Write("etc/init.d/boxctl", []byte("#!/bin/sh\n# old service without UCI\n"), 0o755)
			case "missing-hook":
				err = store.RemoveRegular("etc/hotplug.d/net/99-boxctl-tun")
			case "wrong-mode":
				err = os.Chmod(filepath.Join(store.Root, "etc/init.d/boxctl"), 0o644)
			case "missing-uci":
				err = store.RemoveRegular("etc/config/boxctl")
			case "unknown-version":
				service.readBuildInfo = func(ctx context.Context, binary string) (managerBuildInfo, error) {
					info, err := readManagerTestBuildInfo(ctx, binary)
					if binary == target {
						info.IntegrationVersion = ""
					}
					return info, err
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			// Refusal must happen before replacing any binary or system file.
			before, err := store.Read("etc/init.d/boxctl")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Install(context.Background(), "", "", false, false, func(string) (bool, error) { return false, nil }); err == nil {
				t.Fatal("unapproved full restart was accepted")
			}
			assertManagerBinaryVersion(t, target, "2025.01.14")
			assertIntegrationData(t, store, "etc/init.d/boxctl", before)
			result, err := service.Install(context.Background(), "", "", false, false, func(string) (bool, error) { return true, nil })
			if err != nil || result.RestartMode != managerRestartFull {
				t.Fatalf("drift update = %+v, %v", result, err)
			}
			manifest, err := openwrtfiles.Manifest()
			if err != nil {
				t.Fatal(err)
			}
			assertIntegrationManifest(t, service, manifest)
		})
	}
}

func TestManagerIntegrationFailureRestoresFilesAndBinary(t *testing.T) {
	for _, failure := range []string{"partial-write", "restart", "postflight-drift"} {
		t.Run(failure, func(t *testing.T) {
			service, target, old, _ := integrationUpdateFixture(t)
			store := state.Store{Root: service.IntegrationRoot}
			injected := errors.New("injected integration failure")
			failed := false
			if failure == "partial-write" {
				service.writeIntegration = func(name string, data []byte, mode os.FileMode) error {
					if name == "etc/init.d/boxctl" && !failed {
						failed = true
						return injected
					}
					return store.Write(name, data, mode)
				}
			}
			service.restartAndVerify = func(_ context.Context, _, version string, _ managerRestartMode) error {
				if version == "2025.01.15" {
					switch failure {
					case "restart":
						return injected
					case "postflight-drift":
						return store.Write("etc/init.d/boxctl", []byte("unexpected change"), 0o755)
					}
				}
				return nil
			}
			if _, err := service.Install(context.Background(), "", "", false, true, nil); err == nil {
				t.Fatal("failed update reported success")
			}
			assertManagerBinaryVersion(t, target, "2025.01.14")
			assertIntegrationManifest(t, service, old)
		})
	}
}

func TestManagerIntegrationRemovesRetiredHooksAndRestoresThemOnRollback(t *testing.T) {
	service, _, old, next := integrationUpdateFixture(t)
	retired := openwrtfiles.IntegrationFile{Path: "etc/hotplug.d/iface/41-boxctl-retired", Mode: 0o755, Data: []byte("#!/bin/sh\nexit 0\n")}
	old, err := openwrtfiles.NewManifest(append(old.Files, retired))
	if err != nil {
		t.Fatal(err)
	}
	configureIntegrationVersions(t, service, old, next)
	if _, err := service.Install(context.Background(), "", "", false, true, nil); err != nil {
		t.Fatal(err)
	}
	store := state.Store{Root: service.IntegrationRoot}
	if _, err := store.Read(retired.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired hook still present: %v", err)
	}
	if _, err := service.Rollback(context.Background(), false, true, nil); err != nil {
		t.Fatal(err)
	}
	assertIntegrationData(t, store, retired.Path, retired.Data)
}

func TestManagerIntegrationRejectsSymlinkBeforeBinarySwap(t *testing.T) {
	service, target, _, _ := integrationUpdateFixture(t)
	name := filepath.Join(service.IntegrationRoot, "etc/init.d/boxctl")
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "unrelated"), name); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Install(context.Background(), "", "", false, true, nil); err == nil {
		t.Fatal("symlink integration target was accepted")
	}
	assertManagerBinaryVersion(t, target, "2025.01.14")
}

func TestManagerIntegrationRepairsSameVersionAndRetainsLatestOnFailedRollback(t *testing.T) {
	service, target, _, next := integrationUpdateFixture(t)
	if _, err := service.Install(context.Background(), "", "", false, true, nil); err != nil {
		t.Fatal(err)
	}
	service.restartAndVerify = func(_ context.Context, _, version string, _ managerRestartMode) error {
		if version == "2025.01.14" {
			return errors.New("old manager cannot start")
		}
		return nil
	}
	if _, err := service.Rollback(context.Background(), false, true, nil); err == nil {
		t.Fatal("failed rollback reported success")
	}
	assertManagerBinaryVersion(t, target, "2025.01.15")
	assertIntegrationManifest(t, service, next)
	store := state.Store{Root: service.IntegrationRoot}
	if err := store.Write("etc/init.d/boxctl", []byte("outdated init"), 0o755); err != nil {
		t.Fatal(err)
	}
	result, err := service.Install(context.Background(), "", "", false, true, nil)
	if err != nil || !result.Changed || result.RestartMode != managerRestartFull {
		t.Fatalf("same-version repair = %+v, %v", result, err)
	}
	assertIntegrationManifest(t, service, next)
}

func integrationUpdateFixture(t *testing.T) (*managerUpdateService, string, openwrtfiles.IntegrationManifest, openwrtfiles.IntegrationManifest) {
	t.Helper()
	root := t.TempDir()
	target := managerTestTarget(t, root, "2025.01.14")
	service := managerTestUpdateService(t, root, "2025.01.15")
	old, err := openwrtfiles.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	files := slices.Clone(old.Files)
	for index := range files {
		files[index].Data = append(slices.Clone(files[index].Data), []byte("\n# updated integration\n")...)
	}
	next, err := openwrtfiles.NewManifest(files)
	if err != nil {
		t.Fatal(err)
	}
	configureIntegrationVersions(t, service, old, next)
	return service, target, old, next
}

func configureIntegrationVersions(t *testing.T, service *managerUpdateService, old, next openwrtfiles.IntegrationManifest) {
	t.Helper()
	service.readBuildInfo = func(ctx context.Context, binary string) (managerBuildInfo, error) {
		info, err := readManagerTestBuildInfo(ctx, binary)
		info.IntegrationVersion = old.Version
		if info.Version == "2025.01.15" {
			info.IntegrationVersion = next.Version
		}
		return info, err
	}
	service.readIntegration = func(_ context.Context, _, version string) (openwrtfiles.IntegrationManifest, error) {
		if version == next.Version {
			return next, nil
		}
		return old, nil
	}
	for _, file := range old.Files {
		if err := (state.Store{Root: service.IntegrationRoot}).Write(file.Path, file.Data, os.FileMode(file.Mode)); err != nil {
			t.Fatal(err)
		}
	}
}

func assertIntegrationManifest(t *testing.T, service *managerUpdateService, manifest openwrtfiles.IntegrationManifest) {
	t.Helper()
	for _, file := range manifest.Files {
		actual, err := service.readIntegrationFile(file.Path)
		if err != nil || !actual.Exists {
			t.Fatalf("integration file %s missing: %v", file.Path, err)
		}
		if file.Preserve {
			continue
		}
		if !sameIntegrationFile(actual, managerIntegrationFile{Path: file.Path, Exists: true, Mode: file.Mode, Data: file.Data}) {
			t.Fatalf("integration file %s differs from expected release", file.Path)
		}
	}
}

func assertIntegrationData(t *testing.T, store state.Store, name string, expected []byte) {
	t.Helper()
	actual, err := store.Read(name)
	if err != nil || !slices.Equal(actual, expected) {
		t.Fatalf("integration contents changed for %s: %v", name, err)
	}
}
