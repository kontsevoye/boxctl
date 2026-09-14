package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/kontsevoye/boxctl/internal/platform/openwrt"
	"github.com/kontsevoye/boxctl/internal/state"
	openwrtfiles "github.com/kontsevoye/boxctl/packaging/openwrt"
)

type managerIntegrationFile struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Mode   uint32 `json:"mode,omitempty"`
	Data   []byte `json:"data,omitempty"`
}

type managerIntegrationSnapshot struct {
	BinarySHA256 string                   `json:"binarySHA256"`
	Files        []managerIntegrationFile `json:"files"`
}

type managerIntegrationPlan struct {
	Before  managerIntegrationSnapshot
	After   []managerIntegrationFile
	Changed bool
}

func (service *managerUpdateService) readManagerIntegration(ctx context.Context, binary, version string) (openwrtfiles.IntegrationManifest, error) {
	if version == "" {
		return openwrtfiles.IntegrationManifest{}, errors.New("candidate has no OpenWrt integration manifest; use a full OpenWrt bundle to install legacy releases")
	}
	result, err := service.Runner.Run(ctx, openwrt.Command{Name: binary, Args: []string{"integration", "--json"}})
	if err != nil {
		return openwrtfiles.IntegrationManifest{}, err
	}
	if result.ExitCode != 0 {
		return openwrtfiles.IntegrationManifest{}, commandResultError("read OpenWrt integration", result)
	}
	if len(result.Stdout) > 2<<20 {
		return openwrtfiles.IntegrationManifest{}, errors.New("OpenWrt integration manifest exceeds limit")
	}
	var manifest openwrtfiles.IntegrationManifest
	if err := json.Unmarshal(result.Stdout, &manifest); err != nil {
		return manifest, err
	}
	if err := manifest.Validate(); err != nil {
		return manifest, err
	}
	if manifest.Version != version {
		return manifest, errors.New("OpenWrt integration differs from binary version metadata")
	}
	return manifest, nil
}

func (service *managerUpdateService) planIntegration(ctx context.Context, target, candidate string, current, next managerBuildInfo) (managerIntegrationPlan, error) {
	manifest, err := service.readIntegration(ctx, candidate, next.IntegrationVersion)
	if err != nil {
		return managerIntegrationPlan{}, err
	}
	if err := manifest.Validate(); err != nil {
		return managerIntegrationPlan{}, err
	}
	if manifest.Version != next.IntegrationVersion {
		return managerIntegrationPlan{}, errors.New("candidate integration version mismatch")
	}
	paths := make(map[string]bool)
	for _, file := range manifest.Files {
		paths[file.Path] = true
	}
	if current.IntegrationVersion != "" {
		old, err := service.readIntegration(ctx, target, current.IntegrationVersion)
		if err != nil {
			return managerIntegrationPlan{}, err
		}
		for _, file := range old.Files {
			paths[file.Path] = true
		}
	}
	before, err := service.snapshotIntegration(target, paths)
	if err != nil {
		return managerIntegrationPlan{}, err
	}
	desired := make(map[string]openwrtfiles.IntegrationFile)
	for _, file := range manifest.Files {
		desired[file.Path] = file
	}
	plan := managerIntegrationPlan{Before: before}
	for _, actual := range before.Files {
		file, present := desired[actual.Path]
		after := managerIntegrationFile{Path: actual.Path, Exists: present, Mode: file.Mode, Data: file.Data}
		if file.Preserve && actual.Exists {
			after = actual
		}
		if !sameIntegrationFile(actual, after) {
			plan.Changed = true
		}
		plan.After = append(plan.After, after)
	}
	return plan, nil
}

func (service *managerUpdateService) snapshotIntegration(binary string, paths map[string]bool) (managerIntegrationSnapshot, error) {
	digest, err := managerBinaryDigest(binary)
	if err != nil {
		return managerIntegrationSnapshot{}, err
	}
	snapshot := managerIntegrationSnapshot{BinarySHA256: digest}
	for name := range paths {
		file, err := service.readIntegrationFile(name)
		if err != nil {
			return snapshot, err
		}
		snapshot.Files = append(snapshot.Files, file)
	}
	slices.SortFunc(snapshot.Files, func(a, b managerIntegrationFile) int { return strings.Compare(a.Path, b.Path) })
	return snapshot, nil
}

func (service *managerUpdateService) readIntegrationFile(name string) (managerIntegrationFile, error) {
	file := managerIntegrationFile{Path: name}
	if !openwrtfiles.ManagedPath(name) {
		return file, fmt.Errorf("unmanaged integration path %q", name)
	}
	store := state.Store{Root: service.IntegrationRoot}
	// Store.Read rejects symlinks in every parent and at the target.
	data, err := store.Read(name)
	if errors.Is(err, os.ErrNotExist) {
		return file, nil
	}
	if err != nil {
		return file, err
	}
	if len(data) > 1<<20 {
		return file, fmt.Errorf("installed integration file too large: %s", name)
	}
	info, err := os.Lstat(filepath.Join(store.Root, name))
	if err != nil {
		return file, err
	}
	file.Exists, file.Mode, file.Data = true, uint32(info.Mode().Perm()), data
	return file, nil
}

func sameIntegrationFile(a, b managerIntegrationFile) bool {
	return a.Exists == b.Exists && (!a.Exists || (a.Mode == b.Mode && bytes.Equal(a.Data, b.Data)))
}

func (service *managerUpdateService) applyIntegration(files []managerIntegrationFile, restoring bool) error {
	store := state.Store{Root: service.IntegrationRoot}
	for _, file := range files {
		// UCI belongs to the administrator, including edits made since an update.
		if restoring && file.Path == "etc/config/boxctl" {
			continue
		}
		actual, err := service.readIntegrationFile(file.Path)
		if err != nil {
			return err
		}
		if sameIntegrationFile(actual, file) || (file.Path == "etc/config/boxctl" && actual.Exists) {
			continue
		}
		if !file.Exists {
			err = store.RemoveRegular(file.Path)
		} else if service.writeIntegration != nil {
			err = service.writeIntegration(file.Path, file.Data, os.FileMode(file.Mode))
		} else {
			err = store.Write(file.Path, file.Data, os.FileMode(file.Mode))
		}
		if err != nil {
			return fmt.Errorf("write OpenWrt integration %s: %w", file.Path, err)
		}
	}
	return nil
}

func (service *managerUpdateService) verifyIntegration(files []managerIntegrationFile, restoring bool) error {
	for _, expected := range files {
		if restoring && expected.Path == "etc/config/boxctl" {
			continue
		}
		actual, err := service.readIntegrationFile(expected.Path)
		if err != nil {
			return err
		}
		if expected.Path == "etc/config/boxctl" && actual.Exists {
			continue
		}
		if !sameIntegrationFile(actual, expected) {
			return fmt.Errorf("OpenWrt integration verification failed: %s", expected.Path)
		}
	}
	return nil
}

func integrationSnapshotName(digest string) string {
	return ".boxctl/manager-integration-" + digest + ".json"
}

func (service *managerUpdateService) saveIntegrationSnapshot(snapshot managerIntegrationSnapshot) error {
	return service.Store.WriteJSON(integrationSnapshotName(snapshot.BinarySHA256), snapshot, 0o600)
}

func (service *managerUpdateService) rollbackIntegration(binary string) (managerIntegrationSnapshot, bool, error) {
	digest, err := managerBinaryDigest(binary)
	if err != nil {
		return managerIntegrationSnapshot{}, false, err
	}
	data, err := service.Store.Read(integrationSnapshotName(digest))
	if err != nil {
		return managerIntegrationSnapshot{}, false, fmt.Errorf("read integration rollback snapshot: %w", err)
	}
	var snapshot managerIntegrationSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return snapshot, false, err
	}
	if snapshot.BinarySHA256 != digest {
		return snapshot, false, errors.New("integration rollback snapshot does not match binary")
	}
	changed := false
	seen := make(map[string]bool)
	for _, file := range snapshot.Files {
		if !openwrtfiles.ManagedPath(file.Path) || seen[file.Path] || len(file.Data) > 1<<20 || (file.Exists && (file.Mode == 0 || file.Mode&^0o777 != 0)) {
			return snapshot, false, errors.New("invalid integration rollback snapshot")
		}
		seen[file.Path] = true
		actual, err := service.readIntegrationFile(file.Path)
		if err != nil {
			return snapshot, false, err
		}
		if file.Path != "etc/config/boxctl" && !sameIntegrationFile(actual, file) {
			changed = true
		}
	}
	if !seen["etc/init.d/boxctl"] || !seen["etc/config/boxctl"] {
		return snapshot, false, errors.New("incomplete integration rollback snapshot")
	}
	return snapshot, changed, nil
}

func managerBinaryDigest(binary string) (string, error) {
	// The caller has already validated this manager-owned regular ELF path.
	// #nosec G304 -- validated installed/staged manager binary, never a request path.
	file, err := os.Open(binary)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
