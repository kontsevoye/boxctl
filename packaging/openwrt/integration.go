// Package openwrt embeds the service files shipped with each manager binary.
package openwrt

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
)

//go:embed files
var integrationFiles embed.FS

// IntegrationFile names an owned system file. Preserve files are defaults:
// their installed contents belong to the administrator and are never replaced.
type IntegrationFile struct {
	Path     string `json:"path"`
	Mode     uint32 `json:"mode"`
	Preserve bool   `json:"preserve,omitempty"`
	Data     []byte `json:"data"`
}

// IntegrationManifest is transported by the already digest-verified binary.
// Version covers paths, permissions, preservation policy, and file contents.
type IntegrationManifest struct {
	Version string            `json:"version"`
	Files   []IntegrationFile `json:"files"`
}

// Manifest uses the same source files as the OpenWrt bundle and APK build.
func Manifest() (IntegrationManifest, error) {
	var files []IntegrationFile
	err := fs.WalkDir(integrationFiles, "files", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		data, err := integrationFiles.ReadFile(name)
		if err != nil {
			return err
		}
		name = strings.TrimPrefix(name, "files/")
		mode := uint32(0o644)
		if strings.HasPrefix(name, "etc/init.d/") || strings.HasPrefix(name, "etc/hotplug.d/") {
			mode = 0o755
		}
		files = append(files, IntegrationFile{Path: name, Mode: mode, Preserve: name == "etc/config/boxctl", Data: data})
		return nil
	})
	if err != nil {
		return IntegrationManifest{}, err
	}
	return NewManifest(files)
}

// NewManifest canonicalizes and validates a manifest before hashing it.
func NewManifest(files []IntegrationFile) (IntegrationManifest, error) {
	if len(files) > 128 {
		return IntegrationManifest{}, errors.New("too many integration files")
	}
	files = slices.Clone(files)
	slices.SortFunc(files, func(a, b IntegrationFile) int { return strings.Compare(a.Path, b.Path) })
	seen := make(map[string]bool)
	total := 0
	for _, file := range files {
		if !ManagedPath(file.Path) || seen[file.Path] {
			return IntegrationManifest{}, fmt.Errorf("invalid or duplicate integration path %q", file.Path)
		}
		seen[file.Path] = true
		if file.Preserve != (file.Path == "etc/config/boxctl") || (file.Mode != 0o644 && file.Mode != 0o755) {
			return IntegrationManifest{}, fmt.Errorf("invalid integration policy for %s", file.Path)
		}
		total += len(file.Data)
		if len(file.Data) == 0 || len(file.Data) > 64<<10 || total > 1<<20 {
			return IntegrationManifest{}, errors.New("integration contents exceed limits")
		}
	}
	if !seen["etc/init.d/boxctl"] || !seen["etc/config/boxctl"] {
		return IntegrationManifest{}, errors.New("integration manifest lacks service or configuration")
	}
	data, err := json.Marshal(files)
	if err != nil {
		return IntegrationManifest{}, err
	}
	digest := sha256.Sum256(data)
	return IntegrationManifest{Version: hex.EncodeToString(digest[:]), Files: files}, nil
}

// Validate verifies the content fingerprint, not just a version label.
func (manifest IntegrationManifest) Validate() error {
	canonical, err := NewManifest(manifest.Files)
	if err != nil {
		return err
	}
	if manifest.Version != canonical.Version {
		return errors.New("integration manifest digest mismatch")
	}
	return nil
}

// ManagedPath confines future manifests to boxctl-owned integration names.
// New numbered hotplug hooks can be added without upgrading this allowlist.
func ManagedPath(name string) bool {
	if name != path.Clean(name) || strings.ContainsAny(name, "\\\x00") {
		return false
	}
	switch name {
	case "etc/init.d/boxctl", "etc/config/boxctl", "etc/apk/protected_paths.d/boxctl.list", "lib/upgrade/keep.d/boxctl":
		return true
	}
	directory, base := path.Split(name)
	if directory != "etc/hotplug.d/iface/" && directory != "etc/hotplug.d/net/" {
		return false
	}
	return len(base) >= 9 && base[0] >= '0' && base[0] <= '9' && base[1] >= '0' && base[1] <= '9' &&
		(base[2:] == "-boxctl" || strings.HasPrefix(base[2:], "-boxctl-"))
}
