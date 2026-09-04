package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestCreateValidateRestoreAndSessionRotationBoundary(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	root := filepath.Join(parent, "clash")
	writeFixture(t, filepath.Join(root, "config.yaml"), "mode: rule\n", 0o600)
	writeFixture(t, filepath.Join(root, "config.json"), "{\"log\":{}}\n", 0o600)
	writeFixture(t, filepath.Join(root, "configs", "default.yaml"), "mode: rule\n", 0o600)
	writeFixture(t, filepath.Join(root, "configs", "travel.json"), "{\"route\":{}}\n", 0o600)
	writeFixture(t, filepath.Join(root, "subscriptions", "providers.json"), "{\"provider\":\"remote\"}\n", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "password"), "pbkdf2$100000$salt$hash", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "session.secret"), "must-not-be-backed-up", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "session-secrets.v1.json"), "must-also-not-be-backed-up", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "active-gateway.json"), "must-not-export-live-controller-secret", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "dns-backup.json"), "must-not-restore-a-live-dns-transaction", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "dns_backup"), "must-not-restore-an-incomplete-dns-transaction", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "mihomo-process.json"), "must-not-restore-process-ownership", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "sing-box-process.json"), "must-not-restore-process-ownership", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "core-process.json"), "must-not-restore-process-ownership", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "engine-transition.json"), "must-not-restore-live-transition", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "profile-transition.v1.json"), "must-not-restore-live-transition", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "sing-box-controller-secret"), "must-not-export-sing-box-controller-secret", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "mihomo-controller-secret"), "must-not-export-mihomo-controller-secret", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", ".sing-box-controller-secret-partial"), "must-not-export-partial-controller-secret", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "secrets", "controller"), "must-not-export-runtime-secret", 0o600)
	writeFixture(t, filepath.Join(root, ".boxctl", "engine-registry.json"), "{\"schema\":1}\n", 0o600)
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
		".boxctl/session.secret":                      true,
		".boxctl/session-secrets.v1.json":             true,
		".boxctl/active-gateway.json":                 true,
		".boxctl/dns-backup.json":                     true,
		".boxctl/dns_backup":                          true,
		".boxctl/mihomo-process.json":                 true,
		".boxctl/sing-box-process.json":               true,
		".boxctl/core-process.json":                   true,
		".boxctl/engine-transition.json":              true,
		".boxctl/profile-transition.v1.json":          true,
		".boxctl/sing-box-controller-secret":          true,
		".boxctl/mihomo-controller-secret":            true,
		".boxctl/.sing-box-controller-secret-partial": true,
		".boxctl/secrets/controller":                  true,
		".boxctl/manager-handoff.json":                true,
		".boxctl/imports/upload.tar.gz":               true,
		".boxctl/locks/state.lock":                    true,
		".boxctl/.boxctl-state-secret":                true,
		"local-rules/.rule-list-partial":              true,
	}
	if manifest.Schema != 2 || !manifestHasPath(manifest, "config.json") || !manifestHasPath(manifest, ".boxctl/engine-registry.json") {
		t.Fatalf("engine-aware manifest = %+v", manifest)
	}
	if len(manifest.Engines) != 2 || manifest.Engines[0].Engine != "mihomo" || manifest.Engines[1].Engine != "sing-box" {
		t.Fatalf("engine requirements = %+v", manifest.Engines)
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
	assertFixtureContent(t, filepath.Join(root, "config.json"), "{\"log\":{}}\n")
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
		portableStateDir + "/sing-box-process.json",
		portableStateDir + "/core-process.json",
		portableStateDir + "/engine-transition.json",
		portableStateDir + "/profile-transition.v1.json",
		portableStateDir + "/sing-box-controller-secret",
		portableStateDir + "/mihomo-controller-secret",
		portableStateDir + "/.sing-box-controller-secret-partial",
		portableStateDir + "/secrets/controller",
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

func TestValidateRejectsEmbeddedEngineBinary(t *testing.T) {
	t.Parallel()
	archive := writeArchiveFixture(t, map[string]string{"engines/sing-box/versions/1.14.0/sing-box": "binary"})
	manager := Manager{Root: filepath.Join(t.TempDir(), "clash")}
	if _, err := manager.Validate(context.Background(), archive); err == nil {
		t.Fatal("backup containing an engine binary was accepted")
	}
}

func TestValidateRejectsMissingEngineRequirementForNativeConfig(t *testing.T) {
	t.Parallel()
	archive := writeArchiveFixtureWithManifest(t, map[string]string{"config.json": "{}\n"}, archiveSchema, func(manifest *Manifest) {
		manifest.Engines = nil
	})
	manager := Manager{Root: filepath.Join(t.TempDir(), "clash")}
	if _, err := manager.Validate(context.Background(), archive); err == nil || !strings.Contains(err.Error(), "omits required engine sing-box") {
		t.Fatalf("missing engine requirement error = %v", err)
	}
}

func TestValidateAndRestoreReadsLegacySchemaOne(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "clash")
	writeFixture(t, filepath.Join(root, "config.yaml"), "broken\n", 0o600)
	archive := writeArchiveFixtureSchema(t, map[string]string{"config.yaml": "mode: rule\n"}, legacySchema)
	manager := Manager{Root: root}
	manifest, err := manager.Validate(context.Background(), archive)
	if err != nil || manifest.Schema != legacySchema {
		t.Fatalf("legacy validate = %+v, %v", manifest, err)
	}
	if err := manager.Restore(context.Background(), archive); err != nil {
		t.Fatal(err)
	}
	assertFixtureContent(t, filepath.Join(root, "config.yaml"), "mode: rule\n")
}

func TestRestoreChecksVersionedEngineBeforeReplacingState(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "clash")
	binary := []byte("verified-sing-box")
	digest := sha256.Sum256(binary)
	versionRoot := filepath.Join(root, "engines", "sing-box", "versions", "1.14.0")
	writeFixture(t, filepath.Join(versionRoot, "sing-box"), string(binary), 0o755)
	writeFixture(t, filepath.Join(root, "engines", "sing-box", "current.json"), `{
  "schema": 1,
  "engine": "sing-box",
  "current": {
    "engine": "sing-box",
    "version": "1.14.0",
    "binary": "versions/1.14.0/sing-box",
    "binarySHA256": "`+hex.EncodeToString(digest[:])+`"
  }
}
`, 0o600)
	writeFixture(t, filepath.Join(root, "config.json"), "{\"version\":\"backup\"}\n", 0o600)
	manager := Manager{Root: root, BackupDir: filepath.Join(root, "backup-output")}
	archive, err := manager.Create(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := manager.Validate(context.Background(), archive)
	if err != nil || len(manifest.Engines) != 1 || manifest.Engines[0].Version != "1.14.0" {
		t.Fatalf("versioned manifest = %+v, %v", manifest, err)
	}
	if err := os.Remove(filepath.Join(versionRoot, "sing-box")); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(root, "config.json"), "{\"version\":\"current\"}\n", 0o600)
	preflightCalled := false
	manager.RestorePreflight = func(context.Context, string, Manifest) error {
		preflightCalled = true
		return nil
	}
	if err := manager.Restore(context.Background(), archive); err == nil || !strings.Contains(err.Error(), "binary is unavailable") {
		t.Fatalf("restore error = %v", err)
	}
	if preflightCalled {
		t.Fatal("application preflight ran after the built-in engine check failed")
	}
	assertFixtureContent(t, filepath.Join(root, "config.json"), "{\"version\":\"current\"}\n")
}

func TestCreateRejectsFutureManagedEnginePointerSchema(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "clash")
	writeFixture(t, filepath.Join(root, "config.json"), "{}\n", 0o600)
	writeFixture(t, filepath.Join(root, "engines", "sing-box", "current.json"), `{
  "schema": 2,
  "engine": "sing-box",
  "current": {
    "engine": "sing-box",
    "version": "1.14.0",
    "binary": "versions/1.14.0/sing-box",
    "binarySHA256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
}
`, 0o600)
	manager := Manager{Root: root}
	if _, err := manager.Create(context.Background()); err == nil || !strings.Contains(err.Error(), "registry does not match") {
		t.Fatalf("Create() error = %v", err)
	}
}

func TestRestoreApplicationPreflightRunsBeforeReplacingState(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "clash")
	writeFixture(t, filepath.Join(root, "config.json"), "{\"state\":\"current\"}\n", 0o600)
	archive := writeArchiveFixture(t, map[string]string{"config.json": "{\"state\":\"backup\"}\n"})
	preflightErr := errors.New("native sing-box check failed")
	manager := Manager{Root: root, RestorePreflight: func(_ context.Context, payloadRoot string, manifest Manifest) error {
		if manifest.Schema != archiveSchema {
			t.Fatalf("preflight manifest = %+v", manifest)
		}
		content, err := os.ReadFile(filepath.Join(payloadRoot, "config.json"))
		if err != nil || string(content) != "{\"state\":\"backup\"}\n" {
			t.Fatalf("preflight payload = %q, %v", content, err)
		}
		return preflightErr
	}}
	if err := manager.Restore(context.Background(), archive); !errors.Is(err, preflightErr) {
		t.Fatalf("restore error = %v", err)
	}
	assertFixtureContent(t, filepath.Join(root, "config.json"), "{\"state\":\"current\"}\n")
}

func TestBeginRestoreSupportsPostflightCommitAndRollback(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "clash")
	current := "mode: direct\ngeneration: current\n"
	restored := "mode: rule\ngeneration: restored\n"
	writeFixture(t, filepath.Join(root, "config.yaml"), current, 0o600)
	archive := writeArchiveFixture(t, map[string]string{"config.yaml": restored})
	manager := Manager{Root: root}

	transaction, err := manager.BeginRestore(context.Background(), archive)
	if err != nil {
		t.Fatal(err)
	}
	assertFixtureContent(t, filepath.Join(root, "config.yaml"), restored)
	if err := transaction.Rollback(); err != nil {
		t.Fatal(err)
	}
	if !transaction.PreviousStateRestored() {
		t.Fatal("successful rollback did not report restored previous state")
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatalf("idempotent Rollback() = %v", err)
	}
	assertFixtureContent(t, filepath.Join(root, "config.yaml"), current)

	transaction, err = manager.BeginRestore(context.Background(), archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatalf("idempotent Commit() = %v", err)
	}
	assertFixtureContent(t, filepath.Join(root, "config.yaml"), restored)
}

func TestRollbackReportsRestoredStateWhenOnlyStagingCleanupFails(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "clash")
	current := "mode: direct\ngeneration: current\n"
	restored := "mode: rule\ngeneration: restored\n"
	writeFixture(t, filepath.Join(root, "config.yaml"), current, 0o600)
	archive := writeArchiveFixture(t, map[string]string{"config.yaml": restored})
	transaction, err := (Manager{Root: root}).BeginRestore(context.Background(), archive)
	if err != nil {
		t.Fatal(err)
	}
	cleanupErr := errors.New("cleanup unavailable")
	transaction.removeStaging = func(string) error { return cleanupErr }
	if err := transaction.Rollback(); !errors.Is(err, cleanupErr) {
		t.Fatalf("Rollback() error = %v, want cleanup error", err)
	}
	if !transaction.PreviousStateRestored() {
		t.Fatal("cleanup error hid a successful state rollback")
	}
	assertFixtureContent(t, filepath.Join(root, "config.yaml"), current)
	// The injected failure deliberately retained staging; clean the test-only
	// directory after proving the state outcome remains distinguishable.
	if err := os.RemoveAll(transaction.staging); err != nil {
		t.Fatal(err)
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
	return writeArchiveFixtureSchema(t, entries, archiveSchema)
}

func writeArchiveFixtureSchema(t *testing.T, entries map[string]string, schema int) string {
	return writeArchiveFixtureWithManifest(t, entries, schema, nil)
}

func writeArchiveFixtureWithManifest(t *testing.T, entries map[string]string, schema int, mutate func(*Manifest)) string {
	t.Helper()
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	createdAt := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	manifest := Manifest{Schema: schema, CreatedAt: createdAt}
	for _, name := range names {
		content := []byte(entries[name])
		digest := sha256.Sum256(content)
		manifest.Entries = append(manifest.Entries, Entry{
			Path: name, Size: int64(len(content)), Mode: 0o600, SHA256: hex.EncodeToString(digest[:]),
		})
	}
	if schema == archiveSchema {
		required := make(map[string]struct{})
		for _, entry := range manifest.Entries {
			switch {
			case entry.Path == "config.yaml", strings.HasPrefix(entry.Path, "configs/") && strings.HasSuffix(entry.Path, ".yaml"):
				required["mihomo"] = struct{}{}
			case entry.Path == "config.json", strings.HasPrefix(entry.Path, "configs/") && strings.HasSuffix(entry.Path, ".json"):
				required["sing-box"] = struct{}{}
			}
		}
		for _, engineName := range []string{"mihomo", "sing-box"} {
			if _, ok := required[engineName]; ok {
				manifest.Engines = append(manifest.Engines, EngineRequirement{Engine: engineName})
			}
		}
	}
	if mutate != nil {
		mutate(&manifest)
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
