package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func TestCreateValidateRestoreAndSessionRotationBoundary(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	root := filepath.Join(parent, "clash")
	writeFixture(t, filepath.Join(root, "config.yaml"), "mode: rule\n", 0o600)
	writeFixture(t, filepath.Join(root, "configs", "default.yaml"), "mode: rule\n", 0o600)
	writeFixture(t, filepath.Join(root, "subscriptions", "providers.json"), "{\"provider\":\"remote\"}\n", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "password"), "pbkdf2$100000$salt$hash", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "session.secret"), "must-not-be-backed-up", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "session-secrets.v1.json"), "must-also-not-be-backed-up", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "active-gateway.json"), "must-not-export-live-controller-secret", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "dns-backup.json"), "must-not-restore-a-live-dns-transaction", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "dns_backup"), "must-not-restore-an-incomplete-dns-transaction", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "mihomo-process.json"), "must-not-restore-process-ownership", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "manager-handoff.json"), "must-not-restore-manager-handoff", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "imports", "upload.tar.gz"), "must-not-back-up-staging", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "locks", "state.lock"), "must-not-back-up-lock-inodes", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", ".boxctl-state-secret"), "must-not-export-an-atomic-secret-write", 0o600)
	writeFixture(t, filepath.Join(root, ".install", "start-stopped-until-first-success"), "", 0o600)
	writeFixture(t, filepath.Join(root, "local-rules", "stable.list"), "example.org\n", 0o600)
	writeFixture(t, filepath.Join(root, "local-rules", ".rule-list-partial"), "must-not-export-an-atomic-rule-write", 0o600)
	manager := Manager{Root: root, Now: func() time.Time { return time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC) }}
	archive, err := manager.Create(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := manager.Validate(context.Background(), archive)
	if err != nil {
		t.Fatal(err)
	}
	excluded := map[string]bool{
		".boxctl/session.secret":          true,
		".boxctl/session-secrets.v1.json": true,
		".boxctl/active-gateway.json":     true,
		".boxctl/dns-backup.json":         true,
		".boxctl/dns_backup":              true,
		".boxctl/mihomo-process.json":     true,
		".boxctl/manager-handoff.json":    true,
		".boxctl/imports/upload.tar.gz":   true,
		".boxctl/locks/state.lock":        true,
		".boxctl/.boxctl-state-secret":    true,
		"local-rules/.rule-list-partial":  true,
	}
	for _, entry := range manifest.Entries {
		if excluded[entry.Path] {
			t.Fatalf("ephemeral state %s was included in backup", entry.Path)
		}
	}
	writeFixture(t, filepath.Join(root, "config.yaml"), "broken\n", 0o600)
	if err := manager.Restore(context.Background(), archive); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(root, "config.yaml"))
	if err != nil || string(content) != "mode: rule\n" {
		t.Fatalf("restore result %q, %v", content, err)
	}
	subscription, err := os.ReadFile(filepath.Join(root, "subscriptions", "providers.json"))
	if err != nil || string(subscription) != "{\"provider\":\"remote\"}\n" {
		t.Fatalf("subscription restore = %q, %v", subscription, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".boxctl", "session.secret")); !os.IsNotExist(err) {
		t.Fatalf("session secret should be removed so the web layer can rotate it, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".boxctl", "session-secrets.v1.json")); !os.IsNotExist(err) {
		t.Fatalf("session signing state should be removed so the web layer can rotate it, got %v", err)
	}
	for relative := range excluded {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative))); !os.IsNotExist(err) {
			t.Fatalf("ephemeral state %s should not be restored, got %v", relative, err)
		}
	}
	assertFixtureContent(t, filepath.Join(root, ".install", "start-stopped-until-first-success"), "")
}

func TestValidateRejectsEphemeralProcessOwnershipState(t *testing.T) {
	t.Parallel()
	for _, relative := range []string{
		portableStateDir + "/mihomo-process.json",
		portableStateDir + "/manager-handoff.json",
	} {
		relative := relative
		t.Run(filepath.Base(relative), func(t *testing.T) {
			t.Parallel()
			archive := writeArchiveFixture(t, map[string]string{relative: "stale runtime ownership"})
			manager := Manager{Root: filepath.Join(t.TempDir(), "clash")}
			if _, err := manager.Validate(context.Background(), archive); err == nil {
				t.Fatalf("archive containing %s was accepted", relative)
			}
		})
	}
}

func TestCreateWithOptionsControlsSensitiveAndLargeGroups(t *testing.T) {
	root := filepath.Join(t.TempDir(), "clash")
	writeFixture(t, filepath.Join(root, "config.yaml"), "mode: rule\n", 0o600)
	writeFixture(t, filepath.Join(root, portableStateDir, "settings.json"), "{}\n", 0o600)
	writeFixture(t, filepath.Join(root, portableStateDir, "password"), "private-password-record", 0o600)
	writeFixture(t, filepath.Join(root, "proxy-providers", "nodes.yaml"), "proxies: []\n", 0o600)
	writeFixture(t, filepath.Join(root, "rule-providers", "rules.yaml"), "payload: []\n", 0o600)
	writeFixture(t, filepath.Join(root, "ui", "index.html"), "dashboard", 0o600)
	now := func() time.Time { return time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC) }

	minimalManager := Manager{Root: root, BackupDir: filepath.Join(root, "backups-minimal"), Now: now}
	minimalArchive, err := minimalManager.CreateWithOptions(context.Background(), ExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	minimal, err := minimalManager.Validate(context.Background(), minimalArchive)
	if err != nil {
		t.Fatal(err)
	}
	for _, excluded := range []string{
		portableStateDir + "/password",
		"proxy-providers/nodes.yaml",
		"rule-providers/rules.yaml",
		"ui/index.html",
	} {
		if manifestHasPath(minimal, excluded) {
			t.Fatalf("minimal export included %s", excluded)
		}
	}
	if !manifestHasPath(minimal, portableStateDir+"/settings.json") {
		t.Fatal("minimal export omitted portable non-password state")
	}

	allOptions := ExportOptions{IncludeAdminPassword: true, IncludeProviderCaches: true, IncludeDashboardUI: true}
	allManager := Manager{Root: root, BackupDir: filepath.Join(root, "backups-all"), Now: now}
	allArchive, err := allManager.CreateWithOptions(context.Background(), allOptions)
	if err != nil {
		t.Fatal(err)
	}
	all, err := allManager.Validate(context.Background(), allArchive)
	if err != nil {
		t.Fatal(err)
	}
	if all.Options != allOptions {
		t.Fatalf("manifest options = %+v, want %+v", all.Options, allOptions)
	}
	for _, included := range []string{
		portableStateDir + "/password",
		"proxy-providers/nodes.yaml",
		"rule-providers/rules.yaml",
		"ui/index.html",
	} {
		if !manifestHasPath(all, included) {
			t.Fatalf("full export omitted %s", included)
		}
	}
}

func TestRestoreWithoutPasswordPreservesCurrentCanonicalPassword(t *testing.T) {
	root := filepath.Join(t.TempDir(), "clash")
	writeFixture(t, filepath.Join(root, portableStateDir, "password"), "current-password-record", 0o600)
	writeFixture(t, filepath.Join(root, portableStateDir, "settings.json"), "current-settings", 0o600)
	archive := writeArchiveFixture(t, map[string]string{
		portableStateDir + "/settings.json": "restored-settings",
	})
	if err := (Manager{Root: root}).Restore(context.Background(), archive); err != nil {
		t.Fatal(err)
	}
	assertFixtureContent(t, filepath.Join(root, portableStateDir, "password"), "current-password-record")
	assertFixtureContent(t, filepath.Join(root, portableStateDir, "settings.json"), "restored-settings")
}

func manifestHasPath(manifest Manifest, wanted string) bool {
	for _, entry := range manifest.Entries {
		if entry.Path == wanted {
			return true
		}
	}
	return false
}

func TestRestoreConfigOnlyPreservesLivePortableState(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "clash")
	writeFixture(t, filepath.Join(root, portableStateDir, "password"), "keep-live-password", 0o600)
	writeFixture(t, filepath.Join(root, portableStateDir, "settings"), "keep-live-settings", 0o600)
	writeFixture(t, filepath.Join(root, "config.yaml"), "broken\n", 0o600)
	archive := writeArchiveFixture(t, map[string]string{"config.yaml": "mode: rule\n"})
	if err := (Manager{Root: root}).Restore(context.Background(), archive); err != nil {
		t.Fatal(err)
	}
	assertFixtureContent(t, filepath.Join(root, "config.yaml"), "mode: rule\n")
	assertFixtureContent(t, filepath.Join(root, portableStateDir, "password"), "keep-live-password")
	assertFixtureContent(t, filepath.Join(root, portableStateDir, "settings"), "keep-live-settings")
}

func TestValidateRejectsTraversal(t *testing.T) {
	t.Parallel()
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	content := []byte("owned")
	if err := tarWriter.WriteHeader(&tar.Header{Name: "payload/../../etc/passwd", Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "malicious.tar.gz")
	if err := os.WriteFile(path, archive.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := Manager{Root: filepath.Join(t.TempDir(), "clash")}
	if _, err := manager.Validate(context.Background(), path); err == nil {
		t.Fatal("path traversal archive was accepted")
	}
}

func TestCreateRejectsSymlink(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "clash")
	writeFixture(t, filepath.Join(root, "config.yaml"), "mode: rule\n", 0o600)
	if err := os.MkdirAll(filepath.Join(root, "configs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../config.yaml", filepath.Join(root, "configs", "linked.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := (Manager{Root: root}).Create(context.Background()); err == nil {
		t.Fatal("symlink was accepted")
	}
}

func TestNormalizedArchiveModeRejectsNarrowingOverflow(t *testing.T) {
	mode, bits, err := normalizedArchiveMode(0o4777)
	if err != nil || mode != 0o700 || bits != 0o700 {
		t.Fatalf("normalizedArchiveMode() = %o, %o, %v", mode, bits, err)
	}
	if _, _, err := normalizedArchiveMode(1 << 40); err == nil {
		t.Fatal("normalizedArchiveMode accepted a value outside uint32")
	}
}

func TestCreateBoundsCumulativeAndCompressedSize(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "clash")
	writeFixture(t, filepath.Join(root, "config.yaml"), "12345678", 0o600)
	writeFixture(t, filepath.Join(root, "configs", "second.yaml"), "abcdefgh", 0o600)
	manager := Manager{Root: root, MaxFileSize: 16, MaxExpandedSize: 12, MaxArchiveSize: 1 << 20}
	if _, err := manager.Create(context.Background()); err == nil {
		t.Fatal("cumulative expanded-size limit was ignored")
	}
	manager.MaxExpandedSize = 1 << 20
	manager.MaxArchiveSize = 32
	if _, err := manager.Create(context.Background()); err == nil {
		t.Fatal("compressed archive-size limit was ignored")
	}
}

func writeArchiveFixture(t *testing.T, entries map[string]string) string {
	t.Helper()
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	createdAt := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	manifest := Manifest{Schema: archiveSchema, CreatedAt: createdAt}
	for _, name := range names {
		content := []byte(entries[name])
		digest := sha256.Sum256(content)
		manifest.Entries = append(manifest.Entries, Entry{
			Path: name, Size: int64(len(content)), Mode: 0o600, SHA256: hex.EncodeToString(digest[:]),
		})
	}
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := writeManifest(tarWriter, manifest); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		content := []byte(entries[name])
		header := &tar.Header{Name: "payload/" + name, Mode: 0o600, Size: int64(len(content)), ModTime: createdAt, Typeflag: tar.TypeReg}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := os.WriteFile(archivePath, archive.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return archivePath
}

func assertFixtureContent(t *testing.T, filePath, expected string) {
	t.Helper()
	content, err := os.ReadFile(filePath)
	if err != nil || string(content) != expected {
		t.Fatalf("content of %s = %q, %v", filePath, content, err)
	}
}

func writeFixture(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}
