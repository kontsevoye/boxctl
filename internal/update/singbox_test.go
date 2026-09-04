package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSingBoxReleaseSelectsOnlyOfficialCompatibleMuslAsset(t *testing.T) {
	t.Parallel()
	digest := "sha256:" + strings.Repeat("a", 64)
	release := Release{Tag: "v1.14.2", Assets: []Asset{
		{Name: "sing-box-1.14.2-linux-arm64.tar.gz", URL: "https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-linux-arm64.tar.gz", Digest: digest, Size: 10},
		{Name: "sing-box-1.14.2-linux-arm64-musl.tar.gz", URL: "https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-linux-arm64-musl.tar.gz", Digest: digest, Size: 20},
	}}
	asset, err := release.SingBoxLinuxARM64Musl()
	if err != nil {
		t.Fatal(err)
	}
	if asset.Name != "sing-box-1.14.2-linux-arm64-musl.tar.gz" {
		t.Fatalf("selected asset = %q", asset.Name)
	}
	if comparison, err := CompareSingBoxVersions("1.14.1", "v1.14.2"); err != nil || comparison >= 0 {
		t.Fatalf("CompareSingBoxVersions() = %d, %v", comparison, err)
	}
	for _, tag := range []string{"v1.13.9", "v1.15.0", "v1.14.00", "v1.14.0-alpha.1", "1.14.0"} {
		release.Tag = tag
		if _, err := release.SingBoxLinuxARM64Musl(); err == nil {
			t.Fatalf("accepted unsupported release %q", tag)
		}
	}
	release.Tag = "v1.14.2"
	for _, unsafeURL := range []string{
		"https://example.invalid/sing-box-1.14.2-linux-arm64-musl.tar.gz",
		"https://user@github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-linux-arm64-musl.tar.gz",
		"https://github.com:443/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-linux-arm64-musl.tar.gz",
		"https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-linux-arm64-musl.tar.gz?redirect=1",
	} {
		release.Assets[1].URL = unsafeURL
		if _, err := release.SingBoxLinuxARM64Musl(); err == nil {
			t.Fatalf("accepted non-official asset URL %q", unsafeURL)
		}
	}
}

func TestStageLocalSingBoxArchiveAndVersionedRollback(t *testing.T) {
	t.Parallel()
	engineRoot := filepath.Join(t.TempDir(), "engines", "sing-box")
	installedAt := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	installer := SingBoxInstaller{Runner: fakeSingBoxRunner, Now: func() time.Time { return installedAt }}

	firstArchive := singBoxArchiveFixture(t, "1.14.0", minimalARM64ELF(), nil)
	firstDigest := fileDigest(t, firstArchive)
	first, err := installer.StageLocalArchive(context.Background(), firstArchive, firstDigest, engineRoot)
	if err != nil {
		t.Fatal(err)
	}
	if first.Manifest.AutoUpdate || first.Manifest.Source != "custom" || first.Manifest.Version != "1.14.0" {
		t.Fatalf("first manifest = %+v", first.Manifest)
	}
	pointer, err := PublishSingBoxVersion(engineRoot, first)
	if err != nil {
		t.Fatal(err)
	}
	if pointer.Current.Version != "1.14.0" || pointer.Previous != nil {
		t.Fatalf("first pointer = %+v", pointer)
	}
	assertManagedVersionFiles(t, engineRoot, pointer.Current)

	secondBinary := append(minimalARM64ELF(), []byte("second")...)
	secondArchive := singBoxArchiveFixture(t, "1.14.1", secondBinary, nil)
	secondInstaller := installer
	secondInstaller.Runner = singBoxRunnerForVersion("1.14.1")
	second, err := secondInstaller.StageLocalArchive(context.Background(), secondArchive, "sha256:"+fileDigest(t, secondArchive), engineRoot)
	if err != nil {
		t.Fatal(err)
	}
	pointer, err = PublishSingBoxVersion(engineRoot, second)
	if err != nil {
		t.Fatal(err)
	}
	if pointer.Current.Version != "1.14.1" || pointer.Previous == nil || pointer.Previous.Version != "1.14.0" {
		t.Fatalf("second pointer = %+v", pointer)
	}
	pointer, err = RollbackManagedEngine(engineRoot)
	if err != nil {
		t.Fatal(err)
	}
	if pointer.Current.Version != "1.14.0" || pointer.Previous == nil || pointer.Previous.Version != "1.14.1" {
		t.Fatalf("rolled-back pointer = %+v", pointer)
	}
	if info, err := os.Stat(filepath.Join(engineRoot, "current.json")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("current.json mode = %v, %v", info, err)
	}
	resolved, err := ResolveManagedEngineBinary(engineRoot, pointer.Current)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resolved, []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveManagedEngineBinary(engineRoot, pointer.Current); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("tampered binary resolve error = %v", err)
	}
}

func TestRevertManagedEnginePublishRestoresPreviousAndRemovesCandidate(t *testing.T) {
	t.Parallel()
	engineRoot := filepath.Join(t.TempDir(), "engines", "sing-box")
	installer := SingBoxInstaller{Runner: fakeSingBoxRunner}
	firstArchive := singBoxArchiveFixture(t, "1.14.0", minimalARM64ELF(), nil)
	first, err := installer.StageLocalArchive(context.Background(), firstArchive, fileDigest(t, firstArchive), engineRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublishSingBoxVersion(engineRoot, first); err != nil {
		t.Fatal(err)
	}

	secondArchive := singBoxArchiveFixture(t, "1.14.1", append(minimalARM64ELF(), "candidate"...), nil)
	secondInstaller := installer
	secondInstaller.Runner = singBoxRunnerForVersion("1.14.1")
	second, err := secondInstaller.StageLocalArchive(context.Background(), secondArchive, fileDigest(t, secondArchive), engineRoot)
	if err != nil {
		t.Fatal(err)
	}
	published, err := PublishSingBoxVersion(engineRoot, second)
	if err != nil {
		t.Fatal(err)
	}
	if err := RevertManagedEnginePublish(engineRoot, published, true); err != nil {
		t.Fatal(err)
	}
	pointer, err := ReadManagedEnginePointer(engineRoot)
	if err != nil {
		t.Fatal(err)
	}
	if pointer.Current.Version != "1.14.0" || pointer.Previous != nil {
		t.Fatalf("reverted pointer = %+v", pointer)
	}
	if _, err := os.Stat(filepath.Join(engineRoot, "versions", "1.14.1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reverted candidate still exists: %v", err)
	}
	if _, err := ResolveManagedEngineBinary(engineRoot, pointer.Current); err != nil {
		t.Fatalf("restored version is invalid: %v", err)
	}
}

func TestRevertFreshManagedEnginePublishRemovesPointerAndVersion(t *testing.T) {
	t.Parallel()
	engineRoot := filepath.Join(t.TempDir(), "engines", "sing-box")
	archive := singBoxArchiveFixture(t, "1.14.0", minimalARM64ELF(), nil)
	staged, err := (SingBoxInstaller{Runner: fakeSingBoxRunner}).StageLocalArchive(context.Background(), archive, fileDigest(t, archive), engineRoot)
	if err != nil {
		t.Fatal(err)
	}
	published, err := PublishSingBoxVersion(engineRoot, staged)
	if err != nil {
		t.Fatal(err)
	}
	if err := RevertManagedEnginePublish(engineRoot, published, false); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManagedEnginePointer(engineRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fresh pointer still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(engineRoot, "versions", "1.14.0")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fresh version still exists: %v", err)
	}
}

func TestRevertManagedEnginePublishRefusesChangedPointer(t *testing.T) {
	t.Parallel()
	engineRoot := filepath.Join(t.TempDir(), "engines", "sing-box")
	archive := singBoxArchiveFixture(t, "1.14.0", minimalARM64ELF(), nil)
	staged, err := (SingBoxInstaller{Runner: fakeSingBoxRunner}).StageLocalArchive(context.Background(), archive, fileDigest(t, archive), engineRoot)
	if err != nil {
		t.Fatal(err)
	}
	published, err := PublishSingBoxVersion(engineRoot, staged)
	if err != nil {
		t.Fatal(err)
	}
	changed := published
	changed.Current.InstalledAt = changed.Current.InstalledAt.Add(time.Second)
	if err := writeJSONAtomic(filepath.Join(engineRoot, "current.json"), changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RevertManagedEnginePublish(engineRoot, published, false); err == nil || !strings.Contains(err.Error(), "changed after publish") {
		t.Fatalf("changed pointer revert error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(engineRoot, "versions", "1.14.0")); err != nil {
		t.Fatalf("candidate was removed after failed CAS: %v", err)
	}
}

func TestPublishSingBoxRefusesTamperedExistingVersion(t *testing.T) {
	t.Parallel()
	engineRoot := filepath.Join(t.TempDir(), "engines", "sing-box")
	archive := singBoxArchiveFixture(t, "1.14.0", minimalARM64ELF(), nil)
	installer := SingBoxInstaller{Runner: fakeSingBoxRunner}
	first, err := installer.StageLocalArchive(context.Background(), archive, fileDigest(t, archive), engineRoot)
	if err != nil {
		t.Fatal(err)
	}
	pointer, err := PublishSingBoxVersion(engineRoot, first)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(engineRoot, filepath.FromSlash(pointer.Current.License)), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := installer.StageLocalArchive(context.Background(), archive, fileDigest(t, archive), engineRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Cleanup() }()
	if _, err := PublishSingBoxVersion(engineRoot, second); err == nil || !strings.Contains(err.Error(), "verify existing") {
		t.Fatalf("tampered existing version publish error = %v", err)
	}
}

func TestStageReleaseRecordsAutomaticOfficialProvenance(t *testing.T) {
	t.Parallel()
	archive := singBoxArchiveBytes(t, "1.14.0", minimalARM64ELF(), nil)
	digest := sha256.Sum256(archive)
	assetURL := "https://github.com/SagerNet/sing-box/releases/download/v1.14.0/sing-box-1.14.0-linux-arm64-musl.tar.gz"
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != assetURL {
			t.Errorf("download URL = %s", request.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(archive)), ContentLength: int64(len(archive)), Header: make(http.Header)}, nil
	})}
	installer := SingBoxInstaller{Client: client, Runner: fakeSingBoxRunner}
	engineRoot := filepath.Join(t.TempDir(), "sing-box")
	release := Release{Tag: "v1.14.0", Assets: []Asset{{
		Name: "sing-box-1.14.0-linux-arm64-musl.tar.gz", URL: assetURL,
		Digest: "sha256:" + hex.EncodeToString(digest[:]), Size: int64(len(archive)),
	}}}
	staged, err := installer.StageRelease(context.Background(), release, engineRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !staged.Manifest.AutoUpdate || staged.Manifest.Source != "official" || staged.Manifest.ReleaseTag != "v1.14.0" || !staged.Manifest.NoAffiliation {
		t.Fatalf("official manifest = %+v", staged.Manifest)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestSingBoxArchiveRejectsUnsafeShapeAndBuild(t *testing.T) {
	t.Parallel()
	validBinary := minimalARM64ELF()
	tests := []struct {
		name    string
		entries []singBoxTarEntry
		runner  CommandRunner
		limit   int64
		want    string
	}{
		{name: "traversal", entries: []singBoxTarEntry{{name: "../sing-box", body: validBinary, kind: tar.TypeReg}}, want: "unsafe"},
		{name: "symlink", entries: []singBoxTarEntry{{name: "sing-box-1.14.0-linux-arm64-musl/sing-box", kind: tar.TypeSymlink}, {name: "sing-box-1.14.0-linux-arm64-musl/LICENSE", body: []byte("GPL"), kind: tar.TypeReg}}, want: "unexpected"},
		{name: "hardlink", entries: []singBoxTarEntry{{name: "sing-box-1.14.0-linux-arm64-musl/sing-box", kind: tar.TypeLink, link: "elsewhere"}, {name: "sing-box-1.14.0-linux-arm64-musl/LICENSE", body: []byte("GPL"), kind: tar.TypeReg}}, want: "unexpected"},
		{name: "duplicate", entries: append(standardSingBoxEntries("1.14.0", validBinary), singBoxTarEntry{name: "sing-box-1.14.0-linux-arm64-musl/LICENSE", body: []byte("GPL"), kind: tar.TypeReg}), want: "duplicate"},
		{name: "unexpected", entries: append(standardSingBoxEntries("1.14.0", validBinary), singBoxTarEntry{name: "sing-box-1.14.0-linux-arm64-musl/config.json", body: []byte("{}"), kind: tar.TypeReg}), want: "unexpected"},
		{name: "expanded limit", entries: standardSingBoxEntries("1.14.0", validBinary), limit: 32, want: "extraction limit"},
		{name: "wrong ELF", entries: standardSingBoxEntries("1.14.0", []byte("not an executable")), want: "not ELF"},
		{name: "wrong license", entries: []singBoxTarEntry{{name: "sing-box-1.14.0-linux-arm64-musl/", kind: tar.TypeDir}, {name: "sing-box-1.14.0-linux-arm64-musl/sing-box", body: validBinary, kind: tar.TypeReg}, {name: "sing-box-1.14.0-linux-arm64-musl/LICENSE", body: []byte("MIT"), kind: tar.TypeReg}}, want: "reviewed upstream terms"},
		{name: "dynamic", entries: standardSingBoxEntries("1.14.0", arm64ELFWithInterpreter()), runner: fakeSingBoxRunner, want: "PT_INTERP"},
		{name: "wrong version", entries: standardSingBoxEntries("1.14.0", validBinary), runner: singBoxRunnerForVersion("1.14.1"), want: "reports version"},
		{name: "missing tag", entries: standardSingBoxEntries("1.14.0", validBinary), runner: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if slices.Equal(args, []string{"version", "-n"}) {
				return []byte("1.14.0\n"), nil
			}
			return []byte("sing-box version 1.14.0\nTags: with_musl,with_clash_api\n"), nil
		}, want: "with_gvisor"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive := arbitraryTarFixture(t, test.entries)
			installer := SingBoxInstaller{Runner: test.runner, MaxUncompressed: test.limit}
			if installer.Runner == nil {
				installer.Runner = fakeSingBoxRunner
			}
			_, err := installer.StageLocalArchive(context.Background(), archive, fileDigest(t, archive), filepath.Join(t.TempDir(), "sing-box"))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestStaticARM64ValidationRejectsInterpreter(t *testing.T) {
	t.Parallel()
	filePath := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(filePath, arm64ELFWithInterpreter(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ValidateStaticLinuxARM64(filePath); err == nil || !strings.Contains(err.Error(), "PT_INTERP") {
		t.Fatalf("validation error = %v", err)
	}
}

func TestResolveLocalSHA256ExplicitAndCompanion(t *testing.T) {
	t.Parallel()
	archivePath := filepath.Join(t.TempDir(), "sing-box.tar.gz")
	want := strings.Repeat("a", 64)
	if got, err := ResolveLocalSHA256(archivePath, want); err != nil || got != "sha256:"+want {
		t.Fatalf("explicit digest = %q, %v", got, err)
	}
	if err := os.WriteFile(archivePath+".sha256", []byte(want+"  sing-box.tar.gz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := ResolveLocalSHA256(archivePath, ""); err != nil || got != "sha256:"+want {
		t.Fatalf("companion digest = %q, %v", got, err)
	}
	if err := os.Remove(archivePath + ".sha256"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", archivePath+".sha256"); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveLocalSHA256(archivePath, ""); err == nil {
		t.Fatal("symlink checksum was accepted")
	}
}

func TestStageLocalSingBoxUsesCompanionChecksum(t *testing.T) {
	t.Parallel()
	archivePath := singBoxArchiveFixture(t, "1.14.0", minimalARM64ELF(), nil)
	if err := os.WriteFile(archivePath+".sha256", []byte(fileDigest(t, archivePath)+"  "+filepath.Base(archivePath)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	staged, err := (SingBoxInstaller{Runner: fakeSingBoxRunner}).StageLocalArchive(context.Background(), archivePath, "", filepath.Join(t.TempDir(), "sing-box"))
	if err != nil {
		t.Fatal(err)
	}
	if err := staged.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestSingBoxArchiveRejectsTrailingGzipMember(t *testing.T) {
	t.Parallel()
	member := singBoxArchiveBytes(t, "1.14.0", minimalARM64ELF(), nil)
	archivePath := filepath.Join(t.TempDir(), "concatenated.tar.gz")
	if err := os.WriteFile(archivePath, append(append([]byte(nil), member...), member...), 0o600); err != nil {
		t.Fatal(err)
	}
	installer := SingBoxInstaller{Runner: fakeSingBoxRunner}
	_, err := installer.StageLocalArchive(context.Background(), archivePath, fileDigest(t, archivePath), filepath.Join(t.TempDir(), "sing-box"))
	if err == nil || !strings.Contains(err.Error(), "trailing gzip member") {
		t.Fatalf("concatenated archive error = %v", err)
	}
}

func TestStageLocalSingBoxRejectsDigestMismatch(t *testing.T) {
	t.Parallel()
	archivePath := singBoxArchiveFixture(t, "1.14.0", minimalARM64ELF(), nil)
	installer := SingBoxInstaller{Runner: fakeSingBoxRunner}
	_, err := installer.StageLocalArchive(context.Background(), archivePath, strings.Repeat("0", 64), filepath.Join(t.TempDir(), "sing-box"))
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("digest mismatch error = %v", err)
	}
}

func fakeSingBoxRunner(_ context.Context, _ string, arguments ...string) ([]byte, error) {
	return singBoxRunnerForVersion("1.14.0")(context.Background(), "", arguments...)
}

func singBoxRunnerForVersion(version string) CommandRunner {
	return func(_ context.Context, _ string, arguments ...string) ([]byte, error) {
		if slices.Equal(arguments, []string{"version", "-n"}) {
			return []byte(version + "\n"), nil
		}
		if slices.Equal(arguments, []string{"version"}) {
			return []byte("sing-box version " + version + "\nTags: with_musl,with_clash_api,with_gvisor\n"), nil
		}
		return nil, errors.New("unexpected command")
	}
}

func singBoxArchiveFixture(t *testing.T, version string, binaryContent []byte, extra []singBoxTarEntry) string {
	t.Helper()
	archive := singBoxArchiveBytes(t, version, binaryContent, extra)
	filePath := filepath.Join(t.TempDir(), "sing-box-"+version+"-linux-arm64-musl.tar.gz")
	if err := os.WriteFile(filePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	return filePath
}

func singBoxArchiveBytes(t *testing.T, version string, binaryContent []byte, extra []singBoxTarEntry) []byte {
	t.Helper()
	return arbitraryTarBytes(t, append(standardSingBoxEntries(version, binaryContent), extra...))
}

type singBoxTarEntry struct {
	name string
	body []byte
	kind byte
	link string
}

func standardSingBoxEntries(version string, binaryContent []byte) []singBoxTarEntry {
	root := "sing-box-" + version + "-linux-arm64-musl"
	return []singBoxTarEntry{
		{name: root + "/", kind: tar.TypeDir},
		{name: root + "/sing-box", body: binaryContent, kind: tar.TypeReg},
		{name: root + "/LICENSE", body: []byte("GNU GENERAL PUBLIC LICENSE version 3 or later\nIn addition, no derivative work may use the name or imply association without prior consent.\n"), kind: tar.TypeReg},
	}
}

func arbitraryTarFixture(t *testing.T, entries []singBoxTarEntry) string {
	t.Helper()
	filePath := filepath.Join(t.TempDir(), "archive.tar.gz")
	if err := os.WriteFile(filePath, arbitraryTarBytes(t, entries), 0o600); err != nil {
		t.Fatal(err)
	}
	return filePath
}

func arbitraryTarBytes(t *testing.T, entries []singBoxTarEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		kind := entry.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		header := &tar.Header{Name: entry.name, Typeflag: kind, Size: int64(len(entry.body)), Mode: 0o755, Linkname: entry.link}
		if kind == tar.TypeDir || kind == tar.TypeSymlink {
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := tarWriter.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func arm64ELFWithInterpreter() []byte {
	header := minimalARM64ELF()
	binary.LittleEndian.PutUint64(header[32:40], 64) // e_phoff
	binary.LittleEndian.PutUint16(header[56:58], 1)  // e_phnum
	program := make([]byte, 56)
	binary.LittleEndian.PutUint32(program[0:4], 3) // PT_INTERP
	return append(header, program...)
}

func fileDigest(t *testing.T, filePath string) string {
	t.Helper()
	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func assertManagedVersionFiles(t *testing.T, engineRoot string, version ManagedEngineVersion) {
	t.Helper()
	for _, relative := range []string{version.Binary, version.License, filepath.ToSlash(filepath.Join("versions", version.Version, "manifest.json"))} {
		info, err := os.Stat(filepath.Join(engineRoot, filepath.FromSlash(relative)))
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("managed file %s = %v, %v", relative, info, err)
		}
	}
}
