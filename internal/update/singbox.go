package update

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	// SingBoxRepository is the only repository eligible for managed automatic
	// sing-box updates. Locally supplied archives are recorded as custom and
	// never opt themselves into that update channel.
	SingBoxRepository = "SagerNet/sing-box"
	// ManagedEnginePointerSchema is the current on-disk current.json format.
	ManagedEnginePointerSchema = 1
	singBoxEngineName          = "sing-box"
	maxLicenseSize             = int64(1 << 20)
	commandOutputSize          = int64(1 << 20)
	commandTimeout             = 15 * time.Second
)

var singBoxArchiveRoot = regexp.MustCompile(`^sing-box-(1\.14\.[0-9]+)-linux-arm64-musl$`)

// NewSingBoxSource returns the official upstream release source. Only stable
// 1.14.x releases are accepted by SingBoxLinuxARM64Musl.
func NewSingBoxSource(client *http.Client) *Source {
	return &Source{Client: client, APIBase: defaultAPIBase, Repo: SingBoxRepository}
}

// ParseSingBoxReleaseTag accepts the deliberately narrow driver compatibility
// window >=1.14.0,<1.15.0. Widening it requires a reviewed driver change.
func ParseSingBoxReleaseTag(tag string) (string, error) {
	if !strings.HasPrefix(tag, "v") {
		return "", fmt.Errorf("unsupported sing-box release tag %q", tag)
	}
	version := strings.TrimPrefix(tag, "v")
	match := singBoxArchiveRoot.FindStringSubmatch("sing-box-" + version + "-linux-arm64-musl")
	if len(match) != 2 || match[1] != version {
		return "", fmt.Errorf("unsupported sing-box release tag %q; require >=1.14.0,<1.15.0", tag)
	}
	parts := strings.Split(version, ".")
	patch, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || strconv.FormatUint(patch, 10) != parts[2] {
		return "", fmt.Errorf("unsupported sing-box release tag %q; require canonical semver", tag)
	}
	return version, nil
}

// CompareSingBoxVersions compares canonical versions inside the supported
// 1.14.x range. It is intended for application-level update decisions.
func CompareSingBoxVersions(left, right string) (int, error) {
	leftVersion, err := ParseSingBoxReleaseTag("v" + strings.TrimPrefix(left, "v"))
	if err != nil {
		return 0, err
	}
	rightVersion, err := ParseSingBoxReleaseTag("v" + strings.TrimPrefix(right, "v"))
	if err != nil {
		return 0, err
	}
	leftPatch, _ := strconv.ParseUint(strings.Split(leftVersion, ".")[2], 10, 64)
	rightPatch, _ := strconv.ParseUint(strings.Split(rightVersion, ".")[2], 10, 64)
	switch {
	case leftPatch < rightPatch:
		return -1, nil
	case leftPatch > rightPatch:
		return 1, nil
	default:
		return 0, nil
	}
}

// SingBoxLinuxARM64Musl selects the official static musl archive. Generic,
// glibc, package-manager and architecture-specific APK assets are rejected.
func (r Release) SingBoxLinuxARM64Musl() (Asset, error) {
	if r.Draft || r.Prerelease {
		return Asset{}, errors.New("managed sing-box releases must be stable and published")
	}
	version, err := ParseSingBoxReleaseTag(r.Tag)
	if err != nil {
		return Asset{}, err
	}
	want := "sing-box-" + version + "-linux-arm64-musl.tar.gz"
	wantPath := "/" + SingBoxRepository + "/releases/download/" + url.PathEscape(r.Tag) + "/" + want
	for _, asset := range r.Assets {
		if asset.Name != want {
			continue
		}
		parsed, parseErr := url.Parse(asset.URL)
		if asset.Size <= 0 || parseErr != nil || parsed.Scheme != "https" || parsed.Host != "github.com" ||
			parsed.User != nil || parsed.Path != wantPath || parsed.RawQuery != "" || parsed.Fragment != "" {
			return Asset{}, fmt.Errorf("release asset %s has incomplete or non-official metadata", want)
		}
		if _, err := ParseDigest(asset.Digest); err != nil {
			return Asset{}, fmt.Errorf("release asset %s: %w", want, err)
		}
		return asset, nil
	}
	return Asset{}, fmt.Errorf("release %s has no %s asset", r.Tag, want)
}

// CommandRunner executes a staged sing-box binary. It is injectable so archive
// and metadata validation can be tested on a non-AArch64 development host.
type CommandRunner func(context.Context, string, ...string) ([]byte, error)

// ManagedEngineVersion is immutable provenance for one installed engine
// version. Binary and License are relative to the engine root.
type ManagedEngineVersion struct {
	Engine          string    `json:"engine"`
	Version         string    `json:"version"`
	Binary          string    `json:"binary"`
	License         string    `json:"license"`
	Source          string    `json:"source"`
	SourceURL       string    `json:"sourceURL,omitempty"`
	ReleaseTag      string    `json:"releaseTag,omitempty"`
	ArchiveSHA256   string    `json:"archiveSHA256"`
	ArchiveSize     int64     `json:"archiveSize"`
	BinarySHA256    string    `json:"binarySHA256"`
	LicenseSHA256   string    `json:"licenseSHA256"`
	BuildTags       []string  `json:"buildTags"`
	AutoUpdate      bool      `json:"autoUpdate"`
	InstalledAt     time.Time `json:"installedAt"`
	LicenseID       string    `json:"licenseID"`
	LicenseNotice   string    `json:"licenseNotice"`
	UpstreamProject string    `json:"upstreamProject"`
	NoAffiliation   bool      `json:"noAffiliation"`
}

// ManagedEnginePointer is the atomically replaced activation registry. The
// previous entry provides a one-step pointer rollback without deleting either
// immutable version directory.
type ManagedEnginePointer struct {
	Schema   int                   `json:"schema"`
	Engine   string                `json:"engine"`
	Current  ManagedEngineVersion  `json:"current"`
	Previous *ManagedEngineVersion `json:"previous,omitempty"`
}

// StagedSingBox is a fully verified, not-yet-published engine directory.
type StagedSingBox struct {
	Directory  string
	Manifest   ManagedEngineVersion
	engineRoot string
}

// Cleanup removes an unpublished private staging directory. A successfully
// published stage has already been renamed, so Cleanup is idempotent.
func (staged StagedSingBox) Cleanup() error {
	if staged.Directory == "" {
		return nil
	}
	if !strings.HasPrefix(filepath.Base(staged.Directory), ".sing-box-staging-") {
		return errors.New("refusing to remove an unexpected sing-box staging path")
	}
	if staged.engineRoot == "" || filepath.Clean(filepath.Dir(staged.Directory)) != filepath.Clean(staged.engineRoot) {
		return errors.New("refusing to remove sing-box staging outside its engine root")
	}
	info, err := os.Lstat(staged.Directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("sing-box staging path is not a regular directory")
	}
	return os.RemoveAll(staged.Directory)
}

// SingBoxInstaller stages official or explicitly checksummed local archives.
// Publishing is separate so the application can coordinate it with lifecycle
// and dataplane locks.
type SingBoxInstaller struct {
	Client          *http.Client
	Runner          CommandRunner
	MaxCompressed   int64
	MaxUncompressed int64
	RequiredTags    []string
	Now             func() time.Time
}

// StageRelease downloads, verifies and extracts one official GitHub release.
func (installer SingBoxInstaller) StageRelease(ctx context.Context, release Release, engineRoot string) (StagedSingBox, error) {
	asset, err := release.SingBoxLinuxARM64Musl()
	if err != nil {
		return StagedSingBox{}, err
	}
	version, _ := ParseSingBoxReleaseTag(release.Tag)
	expected, _ := ParseDigest(asset.Digest)
	archivePath, cleanup, err := installer.downloadArchive(ctx, asset, expected, engineRoot)
	if err != nil {
		return StagedSingBox{}, err
	}
	defer cleanup()
	return installer.stageArchive(ctx, archivePath, asset.Size, expected, version, "official", asset.URL, release.Tag, true, engineRoot)
}

// StageLocalArchive verifies a local official-shape musl archive. Digest may
// be sha256:<hex>, a plain 64-character checksum, or empty to require the
// bounded regular FILE.sha256 companion. Custom archives are never eligible
// for unattended replacement.
func (installer SingBoxInstaller) StageLocalArchive(ctx context.Context, archivePath, digest, engineRoot string) (StagedSingBox, error) {
	normalizedDigest, err := ResolveLocalSHA256(archivePath, digest)
	if err != nil {
		return StagedSingBox{}, err
	}
	expected, err := parseLocalDigest(normalizedDigest)
	if err != nil {
		return StagedSingBox{}, err
	}
	privateCopy, archiveSize, cleanup, err := installer.copyLocalArchive(ctx, archivePath, expected, engineRoot)
	if err != nil {
		return StagedSingBox{}, err
	}
	defer cleanup()
	return installer.stageArchive(ctx, privateCopy, archiveSize, expected, "", "custom", "", "", false, engineRoot)
}

func (installer SingBoxInstaller) copyLocalArchive(ctx context.Context, archivePath string, expected [sha256.Size]byte, engineRoot string) (string, int64, func(), error) {
	info, err := os.Lstat(archivePath)
	if err != nil {
		return "", 0, func() {}, fmt.Errorf("inspect local sing-box archive: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 {
		return "", 0, func() {}, errors.New("local sing-box archive must be a non-empty regular non-symlink file")
	}
	if info.Size() > installer.maxCompressed() {
		return "", 0, func() {}, fmt.Errorf("compressed asset exceeds %d bytes", installer.maxCompressed())
	}
	// #nosec G304 -- archivePath is the explicit administrator-selected file;
	// Lstat plus SameFile below rejects symlink and replacement races.
	source, err := os.Open(archivePath)
	if err != nil {
		return "", 0, func() {}, fmt.Errorf("open local sing-box archive: %w", err)
	}
	defer source.Close()
	openedInfo, err := source.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Size() != info.Size() {
		return "", 0, func() {}, errors.New("local sing-box archive changed during inspection")
	}
	if err := ensureManagedDirectory(engineRoot); err != nil {
		return "", 0, func() {}, err
	}
	destination, err := os.CreateTemp(engineRoot, ".sing-box-local-*.tar.gz")
	if err != nil {
		return "", 0, func() {}, fmt.Errorf("create private archive copy: %w", err)
	}
	destinationPath := destination.Name()
	cleanup := func() {
		_ = destination.Close()
		_ = os.Remove(destinationPath)
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(destination, hasher), io.LimitReader(source, installer.maxCompressed()+1))
	if copyErr == nil && written > installer.maxCompressed() {
		copyErr = fmt.Errorf("compressed asset exceeds %d bytes", installer.maxCompressed())
	}
	if copyErr == nil && written != info.Size() {
		copyErr = errors.New("local sing-box archive changed while copying")
	}
	if copyErr == nil && !bytes.Equal(hasher.Sum(nil), expected[:]) {
		copyErr = errors.New("local sing-box archive sha256 does not match expected digest")
	}
	if copyErr == nil {
		copyErr = ctx.Err()
	}
	if copyErr == nil {
		copyErr = destination.Sync()
	}
	if closeErr := destination.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		cleanup()
		return "", 0, func() {}, copyErr
	}
	if err := os.Chmod(destinationPath, 0o600); err != nil {
		cleanup()
		return "", 0, func() {}, err
	}
	return destinationPath, written, cleanup, nil
}

func (installer SingBoxInstaller) downloadArchive(ctx context.Context, asset Asset, expected [sha256.Size]byte, engineRoot string) (string, func(), error) {
	if asset.Size > installer.maxCompressed() {
		return "", func() {}, fmt.Errorf("compressed asset exceeds %d bytes", installer.maxCompressed())
	}
	if err := ensureManagedDirectory(engineRoot); err != nil {
		return "", func() {}, err
	}
	file, err := os.CreateTemp(engineRoot, ".sing-box-download-*.tar.gz")
	if err != nil {
		return "", func() {}, fmt.Errorf("create sing-box download: %w", err)
	}
	filePath := file.Name()
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(filePath)
	}
	download := Installer{Client: installer.Client}
	if err := download.download(ctx, asset, file, expected, installer.maxCompressed()); err != nil {
		cleanup()
		return "", func() {}, err
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("sync sing-box download: %w", err)
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("close sing-box download: %w", err)
	}
	if err := os.Chmod(filePath, 0o600); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("protect sing-box download: %w", err)
	}
	return filePath, cleanup, nil
}

func (installer SingBoxInstaller) stageArchive(ctx context.Context, archivePath string, archiveSize int64, archiveDigest [sha256.Size]byte, expectedVersion, source, sourceURL, releaseTag string, autoUpdate bool, engineRoot string) (result StagedSingBox, err error) {
	if err := ctx.Err(); err != nil {
		return StagedSingBox{}, err
	}
	if err := ensureManagedDirectory(engineRoot); err != nil {
		return StagedSingBox{}, err
	}
	stage, err := os.MkdirTemp(engineRoot, ".sing-box-staging-")
	if err != nil {
		return StagedSingBox{}, fmt.Errorf("create sing-box staging directory: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(stage)
		}
	}()
	version, err := extractSingBoxArchive(ctx, archivePath, stage, expectedVersion, installer.maxUncompressed())
	if err != nil {
		return StagedSingBox{}, err
	}
	binaryPath := filepath.Join(stage, singBoxEngineName)
	if err := ValidateStaticLinuxARM64(binaryPath); err != nil {
		return StagedSingBox{}, err
	}
	tags, err := installer.validateVersion(ctx, binaryPath, version)
	if err != nil {
		return StagedSingBox{}, err
	}
	binaryDigest, err := hashRegularFile(binaryPath, installer.maxUncompressed())
	if err != nil {
		return StagedSingBox{}, err
	}
	licensePath := filepath.Join(stage, "LICENSE")
	if err := validateSingBoxLicense(licensePath); err != nil {
		return StagedSingBox{}, err
	}
	licenseDigest, err := hashRegularFile(licensePath, maxLicenseSize)
	if err != nil {
		return StagedSingBox{}, err
	}
	now := time.Now().UTC()
	if installer.Now != nil {
		now = installer.Now().UTC()
	}
	manifest := ManagedEngineVersion{
		Engine: singBoxEngineName, Version: version,
		Binary:  filepath.ToSlash(filepath.Join("versions", version, singBoxEngineName)),
		License: filepath.ToSlash(filepath.Join("versions", version, "LICENSE")),
		Source:  source, SourceURL: sourceURL, ReleaseTag: releaseTag,
		ArchiveSHA256: hex.EncodeToString(archiveDigest[:]), ArchiveSize: archiveSize,
		BinarySHA256: binaryDigest, LicenseSHA256: licenseDigest, BuildTags: tags,
		AutoUpdate: autoUpdate, InstalledAt: now, LicenseID: "GPL-3.0-or-later",
		LicenseNotice:   "upstream additional name-and-association restriction applies",
		UpstreamProject: "https://github.com/SagerNet/sing-box", NoAffiliation: true,
	}
	if err := writeJSONExclusive(filepath.Join(stage, "manifest.json"), manifest, 0o600); err != nil {
		return StagedSingBox{}, err
	}
	if err := syncDirectory(stage); err != nil {
		return StagedSingBox{}, fmt.Errorf("sync sing-box staging directory: %w", err)
	}
	keep = true
	return StagedSingBox{Directory: stage, Manifest: manifest, engineRoot: engineRoot}, nil
}

func (installer SingBoxInstaller) validateVersion(ctx context.Context, binaryPath, expectedVersion string) ([]string, error) {
	runner := installer.Runner
	if runner == nil {
		runner = runCommand
	}
	short, err := runner(ctx, binaryPath, "version", "-n")
	if err != nil {
		return nil, fmt.Errorf("run sing-box version -n: %w", err)
	}
	reported := strings.TrimSpace(string(short))
	version, err := ParseSingBoxReleaseTag("v" + reported)
	if err != nil || version != expectedVersion {
		return nil, fmt.Errorf("staged sing-box reports version %q, require %s", reported, expectedVersion)
	}
	full, err := runner(ctx, binaryPath, "version")
	if err != nil {
		return nil, fmt.Errorf("run sing-box version: %w", err)
	}
	tags := parseSingBoxTags(full)
	required := installer.RequiredTags
	if len(required) == 0 {
		required = []string{"with_clash_api", "with_gvisor", "with_musl"}
	}
	for _, tag := range required {
		if !slices.Contains(tags, tag) {
			return nil, fmt.Errorf("staged sing-box is missing required build tag %s", tag)
		}
	}
	slices.Sort(tags)
	return tags, nil
}

func parseSingBoxTags(output []byte) []string {
	for _, line := range strings.Split(string(output), "\n") {
		label, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found || !strings.EqualFold(strings.TrimSpace(label), "tags") {
			continue
		}
		fields := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
		result := make([]string, 0, len(fields))
		for _, field := range fields {
			if field != "" && !slices.Contains(result, field) {
				result = append(result, field)
			}
		}
		return result
	}
	return nil
}

func validateSingBoxLicense(filePath string) error {
	info, err := os.Lstat(filePath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxLicenseSize {
		return errors.New("sing-box LICENSE is not a bounded regular file")
	}
	// #nosec G304 -- this is the fixed LICENSE path inside private staging.
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read sing-box LICENSE: %w", err)
	}
	normalized := strings.Join(strings.Fields(strings.ToLower(string(content))), " ")
	for _, required := range []string{
		"gnu general public license",
		"version 3",
		"no derivative work may use the name or imply association",
	} {
		if !strings.Contains(normalized, required) {
			return errors.New("sing-box LICENSE does not contain the reviewed upstream terms")
		}
	}
	return nil
}

func extractSingBoxArchive(ctx context.Context, archivePath, destination, expectedVersion string, maxExpanded int64) (string, error) {
	// #nosec G304 -- callers pass either a private verified download/copy and
	// extraction never derives this path from archive entry names.
	archive, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("open sing-box archive: %w", err)
	}
	defer archive.Close()
	bufferedArchive := bufio.NewReader(archive)
	gzipReader, err := gzip.NewReader(bufferedArchive)
	if err != nil {
		return "", fmt.Errorf("open sing-box gzip: %w", err)
	}
	gzipReader.Multistream(false)
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	seen := make(map[string]bool)
	rootName, version := "", ""
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read sing-box tar: %w", err)
		}
		name := strings.TrimSuffix(header.Name, "/")
		if name == "" || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") || name == ".." || strings.HasPrefix(name, "../") || path.Clean(name) != name {
			return "", fmt.Errorf("unsafe sing-box archive path %q", header.Name)
		}
		parts := strings.Split(name, "/")
		if len(parts) < 1 || len(parts) > 2 {
			return "", fmt.Errorf("unexpected sing-box archive entry %q", header.Name)
		}
		match := singBoxArchiveRoot.FindStringSubmatch(parts[0])
		if len(match) != 2 {
			return "", fmt.Errorf("unexpected sing-box archive root %q", parts[0])
		}
		if rootName == "" {
			rootName, version = parts[0], match[1]
		} else if parts[0] != rootName {
			return "", errors.New("sing-box archive contains multiple roots")
		}
		if expectedVersion != "" && version != expectedVersion {
			return "", fmt.Errorf("sing-box archive version %s does not match release %s", version, expectedVersion)
		}
		if len(parts) == 1 {
			if header.Typeflag != tar.TypeDir || header.Size != 0 || seen["directory"] {
				return "", errors.New("invalid sing-box archive root directory")
			}
			seen["directory"] = true
			continue
		}
		base := parts[1]
		if (base != singBoxEngineName && base != "LICENSE") || header.Typeflag != tar.TypeReg || header.Size <= 0 || seen[base] {
			return "", fmt.Errorf("unexpected or duplicate sing-box archive entry %q", header.Name)
		}
		limit := maxExpanded
		mode := os.FileMode(0o755)
		if base == "LICENSE" {
			limit = maxLicenseSize
			mode = 0o600
		}
		if header.Size > limit || total > maxExpanded-header.Size {
			return "", fmt.Errorf("sing-box archive entry %s exceeds extraction limit", base)
		}
		total += header.Size
		// #nosec G304 -- base is the two-value allowlist sing-box/LICENSE and
		// destination is a newly-created private staging directory.
		output, err := os.OpenFile(filepath.Join(destination, base), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return "", fmt.Errorf("create staged sing-box %s: %w", base, err)
		}
		written, copyErr := io.CopyN(output, tarReader, header.Size)
		if syncErr := output.Sync(); copyErr == nil {
			copyErr = syncErr
		}
		if closeErr := output.Close(); copyErr == nil {
			copyErr = closeErr
		}
		if copyErr != nil || written != header.Size {
			return "", fmt.Errorf("extract staged sing-box %s: %w", base, copyErr)
		}
		seen[base] = true
	}
	if version == "" || !seen[singBoxEngineName] || !seen["LICENSE"] {
		return "", errors.New("sing-box archive must contain exactly sing-box and LICENSE regular files")
	}
	remaining := maxExpanded - total
	drained, err := io.Copy(io.Discard, io.LimitReader(gzipReader, remaining+1))
	if err != nil {
		return "", fmt.Errorf("finish sing-box gzip: %w", err)
	}
	if drained > remaining {
		return "", errors.New("sing-box gzip trailer exceeds extraction limit")
	}
	if _, err := bufferedArchive.ReadByte(); !errors.Is(err, io.EOF) {
		if err == nil {
			return "", errors.New("sing-box archive contains a trailing gzip member")
		}
		return "", fmt.Errorf("inspect sing-box archive trailer: %w", err)
	}
	return version, nil
}

// ValidateStaticLinuxARM64 additionally rejects PT_INTERP. This excludes the
// generic upstream arm64 artifact, which requires a glibc dynamic loader.
func ValidateStaticLinuxARM64(filePath string) error {
	if err := ValidateLinuxARM64(filePath); err != nil {
		return err
	}
	binary, err := elf.Open(filePath)
	if err != nil {
		return fmt.Errorf("open staged ELF: %w", err)
	}
	defer binary.Close()
	for _, program := range binary.Progs {
		if program.Type == elf.PT_INTERP {
			return errors.New("staged binary is dynamically linked (PT_INTERP present); require static arm64-musl")
		}
		if program.Type == elf.PT_DYNAMIC {
			return errors.New("staged binary has a dynamic section; require static arm64-musl")
		}
	}
	return nil
}

// PublishSingBoxVersion atomically publishes a verified immutable version and
// updates current.json while retaining the former current entry as previous.
func PublishSingBoxVersion(engineRoot string, staged StagedSingBox) (ManagedEnginePointer, error) {
	if err := validateManagedVersion(staged.Manifest); err != nil {
		return ManagedEnginePointer{}, err
	}
	if staged.engineRoot == "" || filepath.Clean(staged.engineRoot) != filepath.Clean(engineRoot) {
		return ManagedEnginePointer{}, errors.New("staged sing-box belongs to a different engine root")
	}
	if err := ensureManagedDirectory(engineRoot); err != nil {
		return ManagedEnginePointer{}, err
	}
	rel, err := filepath.Rel(engineRoot, staged.Directory)
	if err != nil || filepath.Dir(rel) != "." || !strings.HasPrefix(filepath.Base(rel), ".sing-box-staging-") {
		return ManagedEnginePointer{}, errors.New("staged sing-box directory is outside the engine root")
	}
	stageInfo, err := os.Lstat(staged.Directory)
	if err != nil || stageInfo.Mode()&os.ModeSymlink != 0 || !stageInfo.IsDir() {
		return ManagedEnginePointer{}, errors.New("staged sing-box path is not a regular directory")
	}
	onDiskManifest, err := readManagedVersion(filepath.Join(staged.Directory, "manifest.json"))
	if err != nil || !reflect.DeepEqual(onDiskManifest, staged.Manifest) {
		return ManagedEnginePointer{}, errors.New("staged sing-box manifest changed before publish")
	}
	if err := ValidateStaticLinuxARM64(filepath.Join(staged.Directory, singBoxEngineName)); err != nil {
		return ManagedEnginePointer{}, err
	}
	if digest, err := hashRegularFile(filepath.Join(staged.Directory, singBoxEngineName), defaultMaxUncompressed); err != nil || digest != staged.Manifest.BinarySHA256 {
		return ManagedEnginePointer{}, errors.New("staged sing-box binary changed before publish")
	}
	if digest, err := hashRegularFile(filepath.Join(staged.Directory, "LICENSE"), maxLicenseSize); err != nil || digest != staged.Manifest.LicenseSHA256 {
		return ManagedEnginePointer{}, errors.New("staged sing-box license changed before publish")
	}
	versions := filepath.Join(engineRoot, "versions")
	if err := ensureManagedDirectory(versions); err != nil {
		return ManagedEnginePointer{}, err
	}
	target := filepath.Join(versions, staged.Manifest.Version)
	if existingInfo, statErr := os.Lstat(target); statErr == nil {
		if existingInfo.Mode()&os.ModeSymlink != 0 || !existingInfo.IsDir() {
			return ManagedEnginePointer{}, errors.New("installed sing-box version path is not a directory")
		}
		existing, readErr := readManagedVersion(filepath.Join(target, "manifest.json"))
		if readErr != nil || existing.BinarySHA256 != staged.Manifest.BinarySHA256 ||
			existing.LicenseSHA256 != staged.Manifest.LicenseSHA256 || existing.ArchiveSHA256 != staged.Manifest.ArchiveSHA256 {
			return ManagedEnginePointer{}, fmt.Errorf("sing-box version %s already exists with different provenance", staged.Manifest.Version)
		}
		if _, err := ResolveManagedEngineBinary(engineRoot, existing); err != nil {
			return ManagedEnginePointer{}, fmt.Errorf("verify existing sing-box version %s: %w", staged.Manifest.Version, err)
		}
		if err := os.RemoveAll(staged.Directory); err != nil {
			return ManagedEnginePointer{}, fmt.Errorf("remove duplicate staging directory: %w", err)
		}
		staged.Manifest = existing
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return ManagedEnginePointer{}, fmt.Errorf("inspect installed sing-box version: %w", statErr)
	} else {
		if err := os.Rename(staged.Directory, target); err != nil {
			return ManagedEnginePointer{}, fmt.Errorf("publish sing-box version: %w", err)
		}
		if err := syncDirectory(versions); err != nil {
			return ManagedEnginePointer{}, fmt.Errorf("sync sing-box versions: %w", err)
		}
	}
	pointer := ManagedEnginePointer{Schema: ManagedEnginePointerSchema, Engine: singBoxEngineName, Current: staged.Manifest}
	current, readErr := ReadManagedEnginePointer(engineRoot)
	if readErr == nil {
		if _, err := ResolveManagedEngineBinary(engineRoot, current.Current); err != nil {
			return ManagedEnginePointer{}, fmt.Errorf("verify current sing-box before publish: %w", err)
		}
		if current.Current.Version == staged.Manifest.Version && current.Current.BinarySHA256 == staged.Manifest.BinarySHA256 {
			return current, nil
		}
		previous := current.Current
		pointer.Previous = &previous
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return ManagedEnginePointer{}, readErr
	}
	if err := writeJSONAtomic(filepath.Join(engineRoot, "current.json"), pointer, 0o600); err != nil {
		return ManagedEnginePointer{}, err
	}
	return pointer, nil
}

// ReadManagedEnginePointer strictly reads and validates current.json.
func ReadManagedEnginePointer(engineRoot string) (ManagedEnginePointer, error) {
	filePath := filepath.Join(engineRoot, "current.json")
	info, err := os.Lstat(filePath)
	if err != nil {
		return ManagedEnginePointer{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 256<<10 {
		return ManagedEnginePointer{}, errors.New("managed engine pointer is not a bounded regular file")
	}
	// #nosec G304 -- filePath is engineRoot/current.json and Lstat/Stat
	// identity checks prevent following a replaced path.
	file, err := os.Open(filePath)
	if err != nil {
		return ManagedEnginePointer{}, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Size() != info.Size() {
		return ManagedEnginePointer{}, errors.New("managed engine pointer changed during inspection")
	}
	var pointer ManagedEnginePointer
	decoder := json.NewDecoder(io.LimitReader(file, (256<<10)+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pointer); err != nil {
		return ManagedEnginePointer{}, fmt.Errorf("decode managed engine pointer: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ManagedEnginePointer{}, errors.New("managed engine pointer has trailing data")
	}
	if pointer.Schema != ManagedEnginePointerSchema || pointer.Engine != singBoxEngineName {
		return ManagedEnginePointer{}, errors.New("unsupported managed engine pointer")
	}
	if err := validateManagedVersion(pointer.Current); err != nil {
		return ManagedEnginePointer{}, err
	}
	if pointer.Previous != nil {
		if err := validateManagedVersion(*pointer.Previous); err != nil {
			return ManagedEnginePointer{}, err
		}
	}
	return pointer, nil
}

// RollbackManagedEngine swaps current and previous atomically. It does not
// stop or start a process; callers must hold the lifecycle transaction lock.
func RollbackManagedEngine(engineRoot string) (ManagedEnginePointer, error) {
	pointer, err := ReadManagedEnginePointer(engineRoot)
	if err != nil {
		return ManagedEnginePointer{}, err
	}
	if pointer.Previous == nil {
		return ManagedEnginePointer{}, errors.New("managed sing-box rollback version is unavailable")
	}
	if _, err := ResolveManagedEngineBinary(engineRoot, *pointer.Previous); err != nil {
		return ManagedEnginePointer{}, fmt.Errorf("verify managed sing-box rollback version: %w", err)
	}
	oldCurrent := pointer.Current
	pointer.Current = *pointer.Previous
	pointer.Previous = &oldCurrent
	if err := writeJSONAtomic(filepath.Join(engineRoot, "current.json"), pointer, 0o600); err != nil {
		return ManagedEnginePointer{}, err
	}
	return pointer, nil
}

// RevertManagedEnginePublish restores the state that immediately preceded a
// successful PublishSingBoxVersion call and removes the now-unreferenced
// published version. Callers must serialize this operation with other engine
// publication operations. The published pointer is used as a compare-and-swap
// guard, so a newer activation is never overwritten accidentally.
func RevertManagedEnginePublish(engineRoot string, published ManagedEnginePointer, hadPrevious bool) error {
	if published.Schema != ManagedEnginePointerSchema || published.Engine != singBoxEngineName {
		return errors.New("invalid published managed engine pointer")
	}
	if err := validateManagedVersion(published.Current); err != nil {
		return err
	}
	if hadPrevious {
		if published.Previous == nil {
			return errors.New("published managed engine pointer has no previous version")
		}
		if err := validateManagedVersion(*published.Previous); err != nil {
			return err
		}
		if published.Previous.Version == published.Current.Version {
			return errors.New("published and previous managed engine versions are identical")
		}
	} else if published.Previous != nil {
		return errors.New("fresh managed engine publish unexpectedly replaced a previous version")
	}
	current, err := ReadManagedEnginePointer(engineRoot)
	if err != nil {
		return fmt.Errorf("read managed engine pointer before revert: %w", err)
	}
	if !reflect.DeepEqual(current, published) {
		return errors.New("managed engine pointer changed after publish; refusing revert")
	}
	if _, err := ResolveManagedEngineBinary(engineRoot, published.Current); err != nil {
		return fmt.Errorf("verify published managed engine before revert: %w", err)
	}
	if hadPrevious {
		if _, err := ResolveManagedEngineBinary(engineRoot, *published.Previous); err != nil {
			return fmt.Errorf("verify previous managed engine before revert: %w", err)
		}
		restored := ManagedEnginePointer{
			Schema:  ManagedEnginePointerSchema,
			Engine:  singBoxEngineName,
			Current: *published.Previous,
		}
		if err := writeJSONAtomic(filepath.Join(engineRoot, "current.json"), restored, 0o600); err != nil {
			return fmt.Errorf("restore previous managed engine pointer: %w", err)
		}
	} else {
		if err := os.Remove(filepath.Join(engineRoot, "current.json")); err != nil {
			return fmt.Errorf("remove fresh managed engine pointer: %w", err)
		}
		if err := syncDirectory(engineRoot); err != nil {
			return fmt.Errorf("sync reverted managed engine pointer: %w", err)
		}
	}
	if err := removeManagedEngineVersion(engineRoot, published.Current); err != nil {
		return fmt.Errorf("remove reverted managed engine version: %w", err)
	}
	return nil
}

func removeManagedEngineVersion(engineRoot string, version ManagedEngineVersion) error {
	versionDirectory := filepath.Join(engineRoot, "versions", version.Version)
	info, err := os.Lstat(versionDirectory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("managed engine version path is not a regular directory")
	}
	manifest, err := readManagedVersion(filepath.Join(versionDirectory, "manifest.json"))
	if err != nil || !reflect.DeepEqual(manifest, version) {
		return errors.New("managed engine version manifest changed before removal")
	}
	entries, err := os.ReadDir(versionDirectory)
	if err != nil {
		return err
	}
	allowed := map[string]bool{singBoxEngineName: true, "LICENSE": true, "manifest.json": true}
	if len(entries) != len(allowed) {
		return errors.New("managed engine version directory contains unexpected entries")
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("managed engine version directory contains an unsafe entry")
		}
	}
	for _, name := range []string{singBoxEngineName, "LICENSE", "manifest.json"} {
		if err := os.Remove(filepath.Join(versionDirectory, name)); err != nil {
			return err
		}
	}
	if err := os.Remove(versionDirectory); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(versionDirectory))
}

// ResolveManagedEngineBinary verifies that the immutable binary selected by a
// registry entry still has the recorded digest before a lifecycle starts it.
func ResolveManagedEngineBinary(engineRoot string, version ManagedEngineVersion) (string, error) {
	if err := validateManagedVersion(version); err != nil {
		return "", err
	}
	binaryPath, err := verifyManagedFile(engineRoot, version.Binary, version.BinarySHA256, defaultMaxUncompressed)
	if err != nil {
		return "", fmt.Errorf("inspect managed sing-box binary: %w", err)
	}
	if _, err := verifyManagedFile(engineRoot, version.License, version.LicenseSHA256, maxLicenseSize); err != nil {
		return "", fmt.Errorf("inspect managed sing-box license: %w", err)
	}
	return binaryPath, nil
}

func verifyManagedFile(engineRoot, relativePath, expectedDigest string, limit int64) (string, error) {
	if !filepath.IsAbs(engineRoot) {
		return "", errors.New("managed engine root must be absolute")
	}
	rootInfo, err := os.Lstat(engineRoot)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return "", errors.New("managed engine root is not a regular directory")
	}
	filePath := filepath.Join(engineRoot, filepath.FromSlash(relativePath))
	relative, err := filepath.Rel(engineRoot, filePath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("managed file escapes the engine root")
	}
	for current := filepath.Dir(filePath); current != filepath.Clean(engineRoot); current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", errors.New("managed file has an unsafe parent directory")
		}
		if filepath.Dir(current) == current {
			return "", errors.New("managed file parent traversal escaped the engine root")
		}
	}
	digest, err := hashRegularFile(filePath, limit)
	if err != nil {
		return "", err
	}
	if digest != expectedDigest {
		return "", errors.New("managed file digest does not match current registry")
	}
	return filePath, nil
}

func validateManagedVersion(version ManagedEngineVersion) error {
	parsed, err := ParseSingBoxReleaseTag("v" + version.Version)
	if err != nil || parsed != version.Version || version.Engine != singBoxEngineName {
		return errors.New("invalid managed sing-box version metadata")
	}
	wantBinary := filepath.ToSlash(filepath.Join("versions", version.Version, singBoxEngineName))
	wantLicense := filepath.ToSlash(filepath.Join("versions", version.Version, "LICENSE"))
	if version.Binary != wantBinary || version.License != wantLicense || !validHexDigest(version.ArchiveSHA256) || !validHexDigest(version.BinarySHA256) || !validHexDigest(version.LicenseSHA256) || version.ArchiveSize <= 0 {
		return errors.New("invalid managed sing-box provenance")
	}
	if version.Source != "official" && version.Source != "custom" {
		return errors.New("invalid managed sing-box source")
	}
	for _, required := range []string{"with_clash_api", "with_gvisor", "with_musl"} {
		if !slices.Contains(version.BuildTags, required) {
			return fmt.Errorf("managed sing-box provenance is missing build tag %s", required)
		}
	}
	if version.InstalledAt.IsZero() || version.LicenseID != "GPL-3.0-or-later" ||
		version.LicenseNotice != "upstream additional name-and-association restriction applies" ||
		version.UpstreamProject != "https://github.com/SagerNet/sing-box" || !version.NoAffiliation {
		return errors.New("managed sing-box license provenance is incomplete")
	}
	if version.Source == "custom" {
		if version.AutoUpdate || version.SourceURL != "" || version.ReleaseTag != "" {
			return errors.New("custom sing-box version cannot enable or impersonate automatic updates")
		}
	} else {
		parsed, err := ParseSingBoxReleaseTag(version.ReleaseTag)
		wantName := "sing-box-" + version.Version + "-linux-arm64-musl.tar.gz"
		wantURL := "https://github.com/" + SingBoxRepository + "/releases/download/" + version.ReleaseTag + "/" + wantName
		if err != nil || parsed != version.Version || !version.AutoUpdate || version.SourceURL != wantURL {
			return errors.New("official sing-box provenance is incomplete")
		}
	}
	return nil
}

func readManagedVersion(filePath string) (ManagedEngineVersion, error) {
	info, err := os.Lstat(filePath)
	if err != nil {
		return ManagedEngineVersion{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 256<<10 {
		return ManagedEngineVersion{}, errors.New("managed version manifest is not a bounded regular file")
	}
	// #nosec G304 -- filePath is the fixed manifest name under a previously
	// bounded staging or immutable version directory.
	data, err := os.ReadFile(filePath)
	if err != nil {
		return ManagedEngineVersion{}, err
	}
	var version ManagedEngineVersion
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&version); err != nil {
		return ManagedEngineVersion{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ManagedEngineVersion{}, errors.New("managed version manifest has trailing data")
	}
	if err := validateManagedVersion(version); err != nil {
		return ManagedEngineVersion{}, err
	}
	return version, nil
}

func parseLocalDigest(value string) ([sha256.Size]byte, error) {
	value = strings.TrimSpace(value)
	if !strings.Contains(value, ":") {
		value = "sha256:" + value
	}
	return ParseDigest(value)
}

// ResolveLocalSHA256 normalizes an explicit checksum or reads the first field
// of FILE.sha256. The archive is still hashed and compared during staging.
func ResolveLocalSHA256(archivePath, explicit string) (string, error) {
	value := strings.TrimSpace(explicit)
	if value == "" {
		checksumPath := archivePath + ".sha256"
		info, err := os.Lstat(checksumPath)
		if err != nil {
			return "", fmt.Errorf("inspect companion checksum: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4096 {
			return "", errors.New("companion checksum must be a bounded regular non-symlink file")
		}
		// #nosec G304 -- checksumPath is the explicit archive path plus a fixed
		// suffix and is verified with Lstat/Stat identity checks.
		file, err := os.Open(checksumPath)
		if err != nil {
			return "", err
		}
		openedInfo, statErr := file.Stat()
		if statErr != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Size() != info.Size() {
			_ = file.Close()
			return "", errors.New("companion checksum changed during inspection")
		}
		content, readErr := io.ReadAll(io.LimitReader(file, 4097))
		closeErr := file.Close()
		if len(content) > 4096 {
			return "", errors.New("companion checksum exceeds size limit")
		}
		if readErr != nil || closeErr != nil {
			return "", fmt.Errorf("read companion checksum: %w", errors.Join(readErr, closeErr))
		}
		fields := strings.Fields(string(content))
		if len(fields) == 0 {
			return "", errors.New("companion checksum is empty")
		}
		value = fields[0]
	}
	digest, err := parseLocalDigest(strings.ToLower(value))
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validHexDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func hashRegularFile(filePath string, limit int64) (string, error) {
	info, err := os.Lstat(filePath)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > limit {
		return "", errors.New("file is not a bounded regular file")
	}
	// #nosec G304 -- the caller supplies a manager-owned path and Lstat/Stat
	// identity checks below prevent symlink replacement.
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Size() != info.Size() {
		return "", errors.New("file changed during inspection")
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, limit+1))
	if err != nil || written != info.Size() || written > limit {
		return "", errors.New("file changed or exceeded its limit while hashing")
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func ensureManagedDirectory(directory string) error {
	if !filepath.IsAbs(directory) {
		return errors.New("managed engine root must be absolute")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create managed engine directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("managed engine path is not a regular directory")
	}
	// #nosec G302 -- directories require execute permission; 0700 is the
	// intended private mode for managed engine artifacts.
	return os.Chmod(directory, 0o700)
}

func writeJSONExclusive(filePath string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	// #nosec G304 -- caller supplies the fixed manifest path inside a private
	// newly-created staging directory; O_EXCL prevents replacement.
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func writeJSONAtomic(filePath string, value any, mode os.FileMode) error {
	directory := filepath.Dir(filePath)
	if err := ensureManagedDirectory(directory); err != nil {
		return err
	}
	if info, err := os.Lstat(filePath); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return errors.New("managed engine pointer target is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(directory, ".current-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, filePath); err != nil {
		return err
	}
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("sync managed engine pointer: %w", err)
	}
	return nil
}

func runCommand(ctx context.Context, binary string, arguments ...string) ([]byte, error) {
	// #nosec G204 -- binary is the private staged file after digest, ELF and
	// static-link validation; arguments are fixed by validateVersion.
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	// #nosec G204 -- see the staged-binary trust boundary above.
	command := exec.CommandContext(commandCtx, binary, arguments...)
	output := &limitedCommandOutput{remaining: commandOutputSize}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	if output.exceeded {
		return output.Bytes(), errors.New("sing-box validation output exceeds 1048576 bytes")
	}
	if errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
		return output.Bytes(), errors.New("sing-box validation command timed out")
	}
	return output.Bytes(), err
}

type limitedCommandOutput struct {
	bytes.Buffer
	remaining int64
	exceeded  bool
}

func (output *limitedCommandOutput) Write(content []byte) (int, error) {
	if int64(len(content)) > output.remaining {
		allowed := output.remaining
		if allowed > 0 {
			_, _ = output.Buffer.Write(content[:allowed])
			output.remaining = 0
		}
		output.exceeded = true
		return int(allowed), errors.New("command output limit exceeded")
	}
	written, err := output.Buffer.Write(content)
	output.remaining -= int64(written)
	return written, err
}

func (installer SingBoxInstaller) maxCompressed() int64 {
	if installer.MaxCompressed > 0 {
		return installer.MaxCompressed
	}
	return defaultMaxCompressed
}

func (installer SingBoxInstaller) maxUncompressed() int64 {
	if installer.MaxUncompressed > 0 {
		return installer.MaxUncompressed
	}
	return defaultMaxUncompressed
}
