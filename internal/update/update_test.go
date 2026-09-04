package update

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLatestAndAssetSelection(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/repos/MetaCubeX/mihomo/releases/latest" || request.URL.RawQuery != "" {
			t.Errorf("stable release endpoint = %s?%s", request.URL.Path, request.URL.RawQuery)
			response.WriteHeader(http.StatusNotFound)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`
          {"tag_name":"v1.19.30","assets":[{
            "name":"mihomo-linux-arm64-v1.19.30.gz",
            "browser_download_url":"https://example.invalid/mihomo.gz",
            "digest":"sha256:58896873736d28628f66de3677c8654fa0f180662523148e136cff4f6e890069",
            "size":16965828
          }]}
        `))
	}))
	defer server.Close()

	source := &Source{Client: server.Client(), APIBase: server.URL, Repo: "MetaCubeX/mihomo"}
	release, err := source.Latest(context.Background(), ChannelStable)
	if err != nil {
		t.Fatal(err)
	}
	if release.Tag != "v1.19.30" {
		t.Fatalf("unexpected stable release %q", release.Tag)
	}
	asset, err := release.LinuxARM64()
	if err != nil {
		t.Fatal(err)
	}
	if asset.Name != "mihomo-linux-arm64-v1.19.30.gz" {
		t.Fatalf("unexpected asset %q", asset.Name)
	}
}

func TestLatestAlphaUsesReleaseList(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/repos/MetaCubeX/mihomo/releases" || request.URL.Query().Get("per_page") != "30" {
			t.Errorf("alpha release endpoint = %s?%s", request.URL.Path, request.URL.RawQuery)
			response.WriteHeader(http.StatusNotFound)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`[
          {"tag_name":"v2.0.0-alpha.1","prerelease":true,"assets":[]},
          {"tag_name":"v1.19.30","assets":[]}
        ]`))
	}))
	defer server.Close()

	source := &Source{Client: server.Client(), APIBase: server.URL, Repo: "MetaCubeX/mihomo"}
	release, err := source.Latest(context.Background(), ChannelAlpha)
	if err != nil {
		t.Fatal(err)
	}
	if release.Tag != "v2.0.0-alpha.1" {
		t.Fatalf("unexpected alpha release %q", release.Tag)
	}
}

func TestLatestRejectsRepositoryPathTraversal(t *testing.T) {
	t.Parallel()
	for _, repository := range []string{"../boxctl", "kontsevoye/../boxctl", "kontsevoye/boxctl/extra"} {
		source := &Source{Repo: repository}
		if _, err := source.Latest(context.Background(), ChannelStable); err == nil || !strings.Contains(err.Error(), "invalid GitHub repository") {
			t.Fatalf("Latest() accepted repository %q: %v", repository, err)
		}
	}
}

func TestBoxctlCalVerReleaseAssetSelection(t *testing.T) {
	t.Parallel()
	release := Release{Tag: "v2025.01.15", Assets: []Asset{{
		Name:   "boxctl-linux-arm64-2025.01.15",
		URL:    "https://github.com/kontsevoye/boxctl/releases/download/v2025.01.15/boxctl-linux-arm64-2025.01.15",
		Digest: "sha256:58896873736d28628f66de3677c8654fa0f180662523148e136cff4f6e890069",
		Size:   1024,
	}}}
	asset, err := release.BoxctlLinuxARM64()
	if err != nil {
		t.Fatal(err)
	}
	if asset.Name != "boxctl-linux-arm64-2025.01.15" {
		t.Fatalf("unexpected boxctl asset %q", asset.Name)
	}
	if version, err := ParseBoxctlCalVerTag(release.Tag); err != nil || version != "2025.01.15" {
		t.Fatalf("ParseBoxctlCalVerTag() = %q, %v", version, err)
	}
	if comparison, err := CompareBoxctlCalVer("2025.01.14", "2025.01.15"); err != nil || comparison >= 0 {
		t.Fatalf("CompareBoxctlCalVer() = %d, %v", comparison, err)
	}
	for _, invalid := range []string{
		"2025.01.15", "v2025.1.15", "v2025.13.1", "v2025.01.0", "v2025.01.015", "v2025.01.15.1", "v1.2.3",
	} {
		if _, err := ParseBoxctlCalVerTag(invalid); err == nil {
			t.Fatalf("unsafe boxctl tag %q was accepted", invalid)
		}
	}
}

func TestStageVerifiesDigestAndELF(t *testing.T) {
	t.Parallel()
	compressed := gzipBytes(t, minimalARM64ELF())
	digest := sha256.Sum256(compressed)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = response.Write(compressed)
	}))
	defer server.Close()

	installer := Installer{Client: server.Client()}
	asset := Asset{
		Name:   "mihomo-linux-arm64-v1.2.3.gz",
		URL:    server.URL,
		Digest: "sha256:" + hex.EncodeToString(digest[:]),
		Size:   int64(len(compressed)),
	}
	path, err := installer.Stage(context.Background(), asset, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("unexpected mode %o", info.Mode().Perm())
	}

	asset.Digest = "sha256:" + string(bytes.Repeat([]byte{'0'}, 64))
	if _, err := installer.Stage(context.Background(), asset, t.TempDir()); err == nil {
		t.Fatal("digest mismatch was accepted")
	}
}

func TestStageRawAndLocalFileVerifyDigestAndELF(t *testing.T) {
	t.Parallel()
	binaryContent := minimalARM64ELF()
	digest := sha256.Sum256(binaryContent)
	digestText := "sha256:" + hex.EncodeToString(digest[:])
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = response.Write(binaryContent)
	}))
	defer server.Close()

	installer := Installer{Client: server.Client()}
	remote, err := installer.StageRaw(context.Background(), Asset{
		Name: "boxctl-linux-arm64-2025.01.15", URL: server.URL, Digest: digestText, Size: int64(len(binaryContent)),
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(remote); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("remote staged mode = %v, %v", info, err)
	}

	localSource := filepath.Join(t.TempDir(), "boxctl-linux-arm64")
	if err := os.WriteFile(localSource, binaryContent, 0o644); err != nil {
		t.Fatal(err)
	}
	local, err := installer.StageFile(context.Background(), localSource, digestText, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(local); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("local staged mode = %v, %v", info, err)
	}
	if _, err := installer.StageFile(context.Background(), localSource, "sha256:"+string(bytes.Repeat([]byte{'0'}, 64)), t.TempDir()); err == nil {
		t.Fatal("local digest mismatch was accepted")
	}
}

func TestInstallAndRollback(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := filepath.Join(directory, "clash")
	staged := filepath.Join(directory, ".staged")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Install(staged, target); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, target, "new")
	assertFileContent(t, target+".prev", "old")
	if err := Rollback(target); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, target, "old")
	assertFileContent(t, target+".failed", "new")
}

func TestInstallRestoresPreviousBinaryWhenDirectorySyncFails(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := filepath.Join(directory, "clash")
	staged := filepath.Join(directory, ".staged")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	syncErr := errors.New("directory sync failed")
	syncCalls := 0
	err := install(staged, target, func(string) error {
		syncCalls++
		if syncCalls == 1 {
			return syncErr
		}
		return nil
	})
	if !errors.Is(err, syncErr) {
		t.Fatalf("Install() error = %v, want directory sync failure", err)
	}
	if errors.Is(err, ErrInstallRollbackFailed) {
		t.Fatalf("Install() reported a rollback failure after restoring the target: %v", err)
	}
	assertFileContent(t, target, "old")
	assertFileContent(t, target+".failed", "new")
	if _, err := os.Stat(target + ".prev"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback source remains after restoration: %v", err)
	}
}

func TestInstallJoinsDirectorySyncAndRollbackSyncFailures(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := filepath.Join(directory, "clash")
	staged := filepath.Join(directory, ".staged")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	installSyncErr := errors.New("install sync failed")
	rollbackSyncErr := errors.New("rollback sync failed")
	syncCalls := 0
	err := install(staged, target, func(string) error {
		syncCalls++
		if syncCalls == 1 {
			return installSyncErr
		}
		return rollbackSyncErr
	})
	if !errors.Is(err, installSyncErr) || !errors.Is(err, rollbackSyncErr) || !errors.Is(err, ErrInstallRollbackFailed) {
		t.Fatalf("Install() error does not preserve both failures: %v", err)
	}
	assertFileContent(t, target, "old")
	assertFileContent(t, target+".failed", "new")
}

func TestInstallRemovesNewTargetWhenNoPreviousBinaryAndSyncFails(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := filepath.Join(directory, "clash")
	staged := filepath.Join(directory, ".staged")
	if err := os.WriteFile(staged, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	syncErr := errors.New("directory sync failed")
	syncCalls := 0
	err := install(staged, target, func(string) error {
		syncCalls++
		if syncCalls == 1 {
			return syncErr
		}
		return nil
	})
	if !errors.Is(err, syncErr) || errors.Is(err, ErrInstallRollbackFailed) {
		t.Fatalf("Install() error = %v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new target remains after failed first install: %v", err)
	}
	assertFileContent(t, target+".failed", "new")
}

func gzipBytes(t *testing.T, content []byte) []byte {
	t.Helper()
	var result bytes.Buffer
	writer := gzip.NewWriter(&result)
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return result.Bytes()
}

func minimalARM64ELF() []byte {
	header := make([]byte, 64)
	copy(header[:4], []byte{0x7f, 'E', 'L', 'F'})
	header[4] = byte(2) // ELFCLASS64
	header[5] = byte(1) // ELFDATA2LSB
	header[6] = byte(1) // EV_CURRENT
	binary.LittleEndian.PutUint16(header[16:18], 2)
	binary.LittleEndian.PutUint16(header[18:20], 183)
	binary.LittleEndian.PutUint32(header[20:24], 1)
	binary.LittleEndian.PutUint16(header[52:54], 64)
	binary.LittleEndian.PutUint16(header[54:56], 56)
	binary.LittleEndian.PutUint16(header[58:60], 64)
	return header
}

func assertFileContent(t *testing.T, path, expected string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != expected {
		t.Fatalf("%s contains %q, want %q", path, content, expected)
	}
}
