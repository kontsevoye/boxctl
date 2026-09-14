package openwrt_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	openwrtfiles "github.com/kontsevoye/boxctl/packaging/openwrt"
)

func TestEmbeddedIntegrationCoversEveryPackagedFile(t *testing.T) {
	manifest, err := openwrtfiles.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(projectRoot(t), "packaging/openwrt/files")
	var paths []string
	if err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		relative, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		paths = append(paths, filepath.ToSlash(relative))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var embedded []string
	for _, file := range manifest.Files {
		embedded = append(embedded, file.Path)
		data, err := os.ReadFile(filepath.Join(root, file.Path))
		if err != nil || !slices.Equal(data, file.Data) {
			t.Fatalf("embedded artifact %s differs: %v", file.Path, err)
		}
		info, err := os.Stat(filepath.Join(root, file.Path))
		if err != nil || uint32(info.Mode().Perm()) != file.Mode {
			t.Fatalf("embedded permissions differ for %s: %v", file.Path, err)
		}
	}
	slices.Sort(paths)
	if !slices.Equal(paths, embedded) {
		t.Fatalf("packaged files %v differ from embedded files %v", paths, embedded)
	}
}

func TestIntegrationFingerprintChangesWithArtifactsAndRejectsTampering(t *testing.T) {
	manifest, err := openwrtfiles.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	files := slices.Clone(manifest.Files)
	files[0].Data = append(slices.Clone(files[0].Data), '\n')
	changed, err := openwrtfiles.NewManifest(files)
	if err != nil || changed.Version == manifest.Version {
		t.Fatalf("artifact change did not change version: %v", err)
	}
	changed.Version = manifest.Version
	if err := changed.Validate(); err == nil {
		t.Fatal("stale fingerprint was accepted")
	}
	for _, invalid := range []string{"../etc/passwd", "/etc/init.d/boxctl", "etc/init.d/unrelated", "etc/hotplug.d/iface/40-other", "etc/hotplug.d/iface/../net/99-boxctl-tun"} {
		files = slices.Clone(manifest.Files)
		files[0].Path = invalid
		if _, err := openwrtfiles.NewManifest(files); err == nil {
			t.Errorf("unmanaged path accepted: %s", invalid)
		}
	}
	files = append(slices.Clone(manifest.Files), manifest.Files[0])
	if _, err := openwrtfiles.NewManifest(files); err == nil {
		t.Fatal("duplicate target accepted")
	}
	files = slices.Clone(manifest.Files)
	for index := range files {
		if strings.HasPrefix(files[index].Path, "etc/init.d/") {
			files[index].Mode = 0o777
		}
	}
	if _, err := openwrtfiles.NewManifest(files); err == nil {
		t.Fatal("world-writable service accepted")
	}
}
