// Package backup creates and restores integrity-checked boxctl state archives.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	manifestName     = "manifest.json"
	archiveSchema    = 2
	legacySchema     = 1
	portableStateDir = ".boxctl"
)

// CurrentManifestSchema is exported so application preflight hooks can avoid
// interpreting fields that legacy manifests did not authenticate.
const CurrentManifestSchema = archiveSchema

var baseExportIncludes = []string{
	portableStateDir,
	"cache.db",
	"config.json",
	"config.yaml",
	"configs",
	"local-rules",
	"subscriptions",
}

var restorableIncludes = []string{
	portableStateDir,
	"cache.db",
	"config.json",
	"config.yaml",
	"configs",
	"local-rules",
	"proxy-providers",
	"rule-providers",
	"subscriptions",
	"ui",
}

// ExportOptions controls the three potentially large or sensitive optional
// groups exposed by the web backup workflow.
type ExportOptions struct {
	IncludeAdminPassword  bool `json:"includeAdminPassword"`
	IncludeProviderCaches bool `json:"includeProviderCaches"`
	IncludeDashboardUI    bool `json:"includeDashboardUI"`
}

// Entry records the integrity and mode of one regular payload file.
type Entry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}

// EngineRequirement records an installed binary needed to activate restored
// profiles. Engine binaries and runtime state are never embedded in backups.
type EngineRequirement struct {
	Engine       string `json:"engine"`
	Version      string `json:"version,omitempty"`
	Binary       string `json:"binary,omitempty"`
	BinarySHA256 string `json:"binarySHA256,omitempty"`
}

// Manifest describes a portable boxctl state archive.
type Manifest struct {
	Schema    int                 `json:"schema"`
	CreatedAt time.Time           `json:"createdAt"`
	Options   ExportOptions       `json:"options,omitempty"`
	Engines   []EngineRequirement `json:"engines,omitempty"`
	Entries   []Entry             `json:"entries"`
}

// Manager creates and restores archives for one boxctl root.
type Manager struct {
	Root            string
	BackupDir       string
	Now             func() time.Time
	MaxFiles        int
	MaxFileSize     int64
	MaxExpandedSize int64
	MaxArchiveSize  int64
	// RestorePreflight runs after integrity and installed-engine checks but
	// before any current state is moved. payloadRoot is the fully extracted,
	// integrity-checked candidate tree. The application can use it for native
	// engine config validation without coupling this package to a core driver.
	// The callback must treat payloadRoot as read-only.
	RestorePreflight func(context.Context, string, Manifest) error
}

type sourceFile struct {
	rel  string
	abs  string
	info os.FileInfo
	hash string
}

// Create writes a mode-0600 tar.gz archive atomically and returns its path.
func (m Manager) Create(ctx context.Context) (string, error) {
	// Preserve the historical programmatic contract. Web exports call
	// CreateWithOptions explicitly and default every optional group to false.
	return m.CreateWithOptions(ctx, ExportOptions{IncludeAdminPassword: true, IncludeProviderCaches: true})
}

// CreateWithOptions writes a backup containing only the selected optional
// groups. Session signing state and live OpenWrt transaction data are excluded
// regardless of these flags.
func (m Manager) CreateWithOptions(ctx context.Context, options ExportOptions) (string, error) {
	root, backupDir, err := m.paths()
	if err != nil {
		return "", err
	}
	files, manifest, err := m.collect(ctx, root, options)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	temporary, err := os.CreateTemp(backupDir, ".boxctl-backup-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create backup file: %w", err)
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return "", fmt.Errorf("protect backup file: %w", err)
	}
	boundedOutput := &boundedWriter{writer: temporary, remaining: m.maxArchiveSize()}
	gzipWriter := gzip.NewWriter(boundedOutput)
	gzipWriter.Name = "boxctl-backup.tar"
	tarWriter := tar.NewWriter(gzipWriter)
	if err := writeManifest(tarWriter, manifest); err != nil {
		return "", err
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := writeFile(tarWriter, file); err != nil {
			return "", err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return "", fmt.Errorf("finish backup tar: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return "", fmt.Errorf("finish backup gzip: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return "", fmt.Errorf("sync backup: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close backup: %w", err)
	}
	if _, err := m.Validate(ctx, temporaryPath); err != nil {
		return "", fmt.Errorf("validate created backup: %w", err)
	}
	now := m.now()
	finalPath := filepath.Join(backupDir, "boxctl-"+now.UTC().Format("20060102T150405Z")+".tar.gz")
	if _, err := os.Lstat(finalPath); err == nil {
		return "", fmt.Errorf("backup already exists: %s", finalPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect backup path: %w", err)
	}
	if err := os.Rename(temporaryPath, finalPath); err != nil {
		return "", fmt.Errorf("publish backup: %w", err)
	}
	keep = true
	if err := syncDirectory(backupDir); err != nil {
		return "", fmt.Errorf("sync backup directory: %w", err)
	}
	return finalPath, nil
}

func (m Manager) collect(ctx context.Context, root string, options ExportOptions) ([]sourceFile, Manifest, error) {
	manifest := Manifest{Schema: archiveSchema, CreatedAt: m.now().UTC(), Options: options}
	var files []sourceFile
	var total int64
	for _, include := range exportIncludes(options) {
		absolute := filepath.Join(root, include)
		if _, err := os.Lstat(absolute); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, Manifest{}, fmt.Errorf("inspect %s: %w", include, err)
		}
		err := filepath.Walk(absolute, func(current string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			relative, err := filepath.Rel(root, current)
			if err != nil {
				return err
			}
			relative = filepath.ToSlash(relative)
			if shouldExcludeExport(relative, options) {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing symbolic link %s", relative)
			}
			if info.IsDir() {
				return nil
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("refusing non-regular file %s", relative)
			}
			if info.Size() > m.maxFileSize() {
				return fmt.Errorf("file %s exceeds backup limit", relative)
			}
			if info.Size() < 0 || total > m.maxExpandedSize()-info.Size() {
				return errors.New("backup expanded-size limit exceeded")
			}
			total += info.Size()
			digest, err := hashFile(current)
			if err != nil {
				return fmt.Errorf("hash %s: %w", relative, err)
			}
			files = append(files, sourceFile{rel: relative, abs: current, info: info, hash: digest})
			if len(files) > m.maxFiles() {
				return errors.New("backup file-count limit exceeded")
			}
			return nil
		})
		if err != nil {
			return nil, Manifest{}, fmt.Errorf("collect %s: %w", include, err)
		}
	}
	sort.Slice(files, func(left, right int) bool { return files[left].rel < files[right].rel })
	for _, file := range files {
		manifest.Entries = append(manifest.Entries, Entry{
			Path: file.rel, Size: file.info.Size(), Mode: uint32(safeMode(file.info.Mode())), SHA256: file.hash,
		})
	}
	engineRequirements, err := collectEngineRequirements(root, files)
	if err != nil {
		return nil, Manifest{}, err
	}
	manifest.Engines = engineRequirements
	return files, manifest, nil
}

func exportIncludes(options ExportOptions) []string {
	includes := append([]string(nil), baseExportIncludes...)
	if options.IncludeProviderCaches {
		includes = append(includes, "proxy-providers", "rule-providers")
	}
	if options.IncludeDashboardUI {
		includes = append(includes, "ui")
	}
	return includes
}

var (
	backupEngineName    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	backupEngineVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
)

func collectEngineRequirements(root string, files []sourceFile) ([]EngineRequirement, error) {
	required := make(map[string]struct{})
	for _, file := range files {
		switch {
		case file.rel == "config.yaml", strings.HasPrefix(file.rel, "configs/") && strings.HasSuffix(file.rel, ".yaml"):
			required["mihomo"] = struct{}{}
		case file.rel == "config.json", strings.HasPrefix(file.rel, "configs/") && strings.HasSuffix(file.rel, ".json"):
			required["sing-box"] = struct{}{}
		}
	}
	engines := make([]string, 0, len(required))
	for engine := range required {
		engines = append(engines, engine)
	}
	sort.Strings(engines)
	result := make([]EngineRequirement, 0, len(engines))
	for _, engine := range engines {
		requirement, err := installedEngineRequirement(root, engine)
		if err != nil {
			return nil, fmt.Errorf("record required engine %s: %w", engine, err)
		}
		result = append(result, requirement)
	}
	return result, nil
}

func installedEngineRequirement(root, engine string) (EngineRequirement, error) {
	requirement := EngineRequirement{Engine: engine}
	engineRoot := filepath.Join(root, "engines", engine)
	engineInfo, err := os.Lstat(engineRoot)
	if errors.Is(err, os.ErrNotExist) {
		return requirement, nil
	}
	if err != nil || engineInfo.Mode()&os.ModeSymlink != 0 || !engineInfo.IsDir() {
		return EngineRequirement{}, errors.New("engine root is not a regular directory")
	}
	pointerPath := filepath.Join(engineRoot, "current.json")
	info, err := os.Lstat(pointerPath)
	if errors.Is(err, os.ErrNotExist) {
		return requirement, nil
	}
	if err != nil {
		return EngineRequirement{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 256<<10 {
		return EngineRequirement{}, errors.New("current engine registry is not a bounded regular file")
	}
	// #nosec G304 -- pointerPath is the fixed current.json below a validated
	// engine directory; descriptor identity is checked before parsing.
	file, err := os.Open(pointerPath)
	if err != nil {
		return EngineRequirement{}, err
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Size() != info.Size() {
		_ = file.Close()
		return EngineRequirement{}, errors.New("current engine registry changed during inspection")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, (256<<10)+1))
	closeErr := file.Close()
	if len(data) > 256<<10 {
		return EngineRequirement{}, errors.New("current engine registry exceeds size limit")
	}
	if readErr != nil || closeErr != nil {
		return EngineRequirement{}, fmt.Errorf("read current engine registry: %w", errors.Join(readErr, closeErr))
	}
	var pointer struct {
		Schema  int    `json:"schema"`
		Engine  string `json:"engine"`
		Current struct {
			Engine       string `json:"engine"`
			Version      string `json:"version"`
			Binary       string `json:"binary"`
			BinarySHA256 string `json:"binarySHA256"`
		} `json:"current"`
	}
	if err := json.Unmarshal(data, &pointer); err != nil {
		return EngineRequirement{}, fmt.Errorf("decode current engine registry: %w", err)
	}
	if pointer.Schema != 1 || pointer.Engine != engine || pointer.Current.Engine != engine {
		return EngineRequirement{}, errors.New("current engine registry does not match required engine")
	}
	requirement.Version = pointer.Current.Version
	requirement.Binary = pointer.Current.Binary
	requirement.BinarySHA256 = pointer.Current.BinarySHA256
	if err := validateEngineRequirements([]EngineRequirement{requirement}); err != nil {
		return EngineRequirement{}, err
	}
	return requirement, nil
}

func validateEngineRequirements(requirements []EngineRequirement) error {
	seen := make(map[string]struct{}, len(requirements))
	for _, requirement := range requirements {
		if !backupEngineName.MatchString(requirement.Engine) || (requirement.Engine != "mihomo" && requirement.Engine != "sing-box") {
			return fmt.Errorf("backup manifest has unsupported engine %q", requirement.Engine)
		}
		if _, duplicate := seen[requirement.Engine]; duplicate {
			return fmt.Errorf("backup manifest repeats engine %s", requirement.Engine)
		}
		seen[requirement.Engine] = struct{}{}
		if requirement.Version == "" {
			if requirement.Binary != "" || requirement.BinarySHA256 != "" {
				return fmt.Errorf("backup manifest has incomplete engine requirement for %s", requirement.Engine)
			}
			continue
		}
		if !backupEngineVersion.MatchString(requirement.Version) {
			return fmt.Errorf("backup manifest has unsafe version for %s", requirement.Engine)
		}
		wantBinary := path.Join("versions", requirement.Version, requirement.Engine)
		if requirement.Binary != wantBinary || len(requirement.BinarySHA256) != sha256.Size*2 {
			return fmt.Errorf("backup manifest has invalid binary provenance for %s", requirement.Engine)
		}
		if _, err := hex.DecodeString(requirement.BinarySHA256); err != nil {
			return fmt.Errorf("backup manifest has invalid binary digest for %s", requirement.Engine)
		}
	}
	return nil
}

func validateManifestEngineCoverage(manifest Manifest) error {
	required := make(map[string]struct{})
	for _, entry := range manifest.Entries {
		switch {
		case entry.Path == "config.yaml", strings.HasPrefix(entry.Path, "configs/") && strings.HasSuffix(entry.Path, ".yaml"):
			required["mihomo"] = struct{}{}
		case entry.Path == "config.json", strings.HasPrefix(entry.Path, "configs/") && strings.HasSuffix(entry.Path, ".json"):
			required["sing-box"] = struct{}{}
		}
	}
	provided := make(map[string]struct{}, len(manifest.Engines))
	for _, requirement := range manifest.Engines {
		provided[requirement.Engine] = struct{}{}
	}
	for engine := range required {
		if _, ok := provided[engine]; !ok {
			return fmt.Errorf("backup manifest omits required engine %s", engine)
		}
	}
	for engine := range provided {
		if _, ok := required[engine]; !ok {
			return fmt.Errorf("backup manifest has an engine requirement without %s configuration", engine)
		}
	}
	return nil
}

func checkEngineRequirements(root string, manifest Manifest) error {
	if manifest.Schema == legacySchema {
		return nil
	}
	for _, requirement := range manifest.Engines {
		if requirement.Version == "" {
			continue
		}
		engineRoot := filepath.Join(root, "engines", requirement.Engine)
		engineInfo, err := os.Lstat(engineRoot)
		if err != nil || engineInfo.Mode()&os.ModeSymlink != 0 || !engineInfo.IsDir() {
			return fmt.Errorf("required %s %s is not installed", requirement.Engine, requirement.Version)
		}
		binaryPath := filepath.Join(engineRoot, filepath.FromSlash(requirement.Binary))
		relative, err := filepath.Rel(engineRoot, binaryPath)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("required %s binary path escapes engine root", requirement.Engine)
		}
		if err := checkPathComponents(engineRoot, requirement.Binary); err != nil {
			return fmt.Errorf("required %s %s binary is unavailable", requirement.Engine, requirement.Version)
		}
		digest, err := hashFile(binaryPath)
		if err != nil || digest != requirement.BinarySHA256 {
			return fmt.Errorf("required %s %s binary digest does not match", requirement.Engine, requirement.Version)
		}
	}
	return nil
}

func checkPathComponents(root, relative string) error {
	current := root
	parts := strings.Split(filepath.FromSlash(relative), string(filepath.Separator))
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			return errors.New("unsafe engine path component")
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("missing or symbolic-link engine path component")
		}
		if index < len(parts)-1 && !info.IsDir() {
			return errors.New("non-directory engine path component")
		}
		if index == len(parts)-1 && !info.Mode().IsRegular() {
			return errors.New("engine binary is not regular")
		}
	}
	return nil
}

type boundedWriter struct {
	writer    io.Writer
	remaining int64
}

func (writer *boundedWriter) Write(content []byte) (int, error) {
	if int64(len(content)) > writer.remaining {
		return 0, errors.New("compressed backup exceeds archive-size limit")
	}
	written, err := writer.writer.Write(content)
	writer.remaining -= int64(written)
	return written, err
}

// Validate fully reads an archive and verifies its manifest without extracting.
func (m Manager) Validate(ctx context.Context, archivePath string) (Manifest, error) {
	archive, err := os.Open(archivePath)
	if err != nil {
		return Manifest{}, fmt.Errorf("open backup: %w", err)
	}
	defer archive.Close()
	return m.validateStream(ctx, archive, "")
}

// RestoreTransaction keeps the previous top-level state available until the
// application has proved that the restored selection can start. Callers must
// finish every successful BeginRestore with either Commit or Rollback.
type RestoreTransaction struct {
	root      string
	payload   string
	staging   string
	movedOld  []string
	movedNew  []string
	mu        sync.Mutex
	finalized bool
	// previousStateRestored is independent from staging cleanup. Callers must
	// still restart the previous runtime when every compensating rename and the
	// root-directory sync succeeded, even if deleting the now-redundant staging
	// directory reports an error.
	previousStateRestored bool
	removeStaging         func(string) error
	// retainStaging prevents cleanup from destroying the only copy of a path
	// which could not be restored during compensation.
	retainStaging bool
}

// Restore preserves the historical one-shot contract. Application workflows
// which need a post-swap readiness check use BeginRestore directly.
func (m Manager) Restore(ctx context.Context, archivePath string) error {
	transaction, err := m.BeginRestore(ctx, archivePath)
	if err != nil {
		return err
	}
	return transaction.Commit()
}

// BeginRestore validates into a staging tree and swaps the included top-level
// paths while retaining the previous state for an explicit postflight. Unknown
// files in the current root remain untouched.
func (m Manager) BeginRestore(ctx context.Context, archivePath string) (*RestoreTransaction, error) {
	root, _, err := m.paths()
	if err != nil {
		return nil, err
	}
	parent := filepath.Dir(root)
	staging, err := os.MkdirTemp(parent, ".boxctl-restore-")
	if err != nil {
		return nil, fmt.Errorf("create restore staging directory: %w", err)
	}
	keepStaging := false
	defer func() {
		if !keepStaging {
			_ = os.RemoveAll(staging)
		}
	}()
	payload := filepath.Join(staging, "payload")
	if err := os.Mkdir(payload, 0o700); err != nil {
		return nil, fmt.Errorf("create restore payload: %w", err)
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("open backup: %w", err)
	}
	manifest, validateErr := m.validateStream(ctx, archive, payload)
	closeErr := archive.Close()
	if validateErr != nil {
		return nil, validateErr
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close backup: %w", closeErr)
	}
	if err := checkEngineRequirements(root, manifest); err != nil {
		return nil, fmt.Errorf("restore engine preflight: %w", err)
	}
	if m.RestorePreflight != nil {
		if err := m.RestorePreflight(ctx, payload, manifest); err != nil {
			return nil, fmt.Errorf("restore application preflight: %w", err)
		}
	}
	if err := preserveLocalAdminPassword(root, payload); err != nil {
		return nil, err
	}
	transaction, err := beginSwapPayload(root, payload, staging)
	if err != nil {
		if transaction != nil && transaction.retainStaging {
			keepStaging = true
		}
		return nil, err
	}
	keepStaging = true
	return transaction, nil
}

// preserveLocalAdminPassword keeps the current canonical credential whenever
// the imported archive contains portable state but intentionally omits the
// password. An explicitly included backup password still replaces it.
func preserveLocalAdminPassword(root, payload string) error {
	const maximumPasswordRecordBytes = 16 << 10
	stagedState := filepath.Join(payload, portableStateDir)
	stagedInfo, err := os.Lstat(stagedState)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect staged portable state: %w", err)
	}
	if stagedInfo.Mode()&os.ModeSymlink != 0 || !stagedInfo.IsDir() {
		return errors.New("staged portable state is not a directory")
	}
	destination := filepath.Join(stagedState, "password")
	if info, destinationErr := os.Lstat(destination); destinationErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("staged administrator password is not a regular file")
		}
		return nil
	} else if !errors.Is(destinationErr, os.ErrNotExist) {
		return fmt.Errorf("inspect staged administrator password: %w", destinationErr)
	}

	source := filepath.Join(root, portableStateDir, "password")
	info, err := os.Lstat(source)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect current administrator password: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maximumPasswordRecordBytes {
		return errors.New("current administrator password is not a bounded regular file")
	}
	sourceFile, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open current administrator password: %w", err)
	}
	openedInfo, statErr := sourceFile.Stat()
	if statErr != nil || !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Size() > maximumPasswordRecordBytes {
		_ = sourceFile.Close()
		return errors.New("current administrator password changed during inspection")
	}
	content, readErr := io.ReadAll(io.LimitReader(sourceFile, maximumPasswordRecordBytes+1))
	closeErr := sourceFile.Close()
	if len(content) > maximumPasswordRecordBytes {
		return errors.New("current administrator password exceeds size limit")
	}
	if readErr != nil || closeErr != nil {
		return fmt.Errorf("read current administrator password: %w", errors.Join(readErr, closeErr))
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("stage current administrator password: %w", err)
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return fmt.Errorf("write current administrator password: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync current administrator password: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close current administrator password: %w", err)
	}
	if err := syncDirectory(stagedState); err != nil {
		return fmt.Errorf("sync staged portable state: %w", err)
	}
	return nil
}

func (m Manager) validateStream(ctx context.Context, source io.Reader, extractRoot string) (Manifest, error) {
	gzipReader, err := gzip.NewReader(source)
	if err != nil {
		return Manifest{}, fmt.Errorf("open backup gzip: %w", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	var manifest Manifest
	manifestSeen := false
	computed := make(map[string]Entry)
	restoreDestinations := make(map[string]string)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return Manifest{}, err
		}
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("read backup tar: %w", err)
		}
		clean, err := cleanArchivePath(header.Name)
		if err != nil {
			return Manifest{}, err
		}
		if clean == manifestName {
			if manifestSeen || header.Typeflag != tar.TypeReg || header.Size > 2<<20 {
				return Manifest{}, errors.New("invalid backup manifest entry")
			}
			manifestSeen = true
			decoder := json.NewDecoder(io.LimitReader(tarReader, header.Size))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&manifest); err != nil {
				return Manifest{}, fmt.Errorf("decode backup manifest: %w", err)
			}
			continue
		}
		if !strings.HasPrefix(clean, "payload/") || clean == "payload" {
			return Manifest{}, fmt.Errorf("unexpected archive entry %q", header.Name)
		}
		relative := strings.TrimPrefix(clean, "payload/")
		restoreRelative, included := restorableArchivePath(relative)
		if !included || shouldExcludeArchivePath(relative, restoreRelative) {
			return Manifest{}, fmt.Errorf("archive entry is outside the restorable set: %s", relative)
		}
		if original, collision := restoreDestinations[restoreRelative]; collision {
			return Manifest{}, fmt.Errorf("archive paths %s and %s map to the same restore path %s", original, relative, restoreRelative)
		}
		restoreDestinations[restoreRelative] = relative
		if header.Typeflag != tar.TypeReg {
			return Manifest{}, fmt.Errorf("unsupported archive entry type for %s", relative)
		}
		if header.Size < 0 || header.Size > m.maxFileSize() {
			return Manifest{}, fmt.Errorf("archive file %s exceeds restore limit", relative)
		}
		archiveMode, archiveModeBits, err := normalizedArchiveMode(header.Mode)
		if err != nil {
			return Manifest{}, fmt.Errorf("archive file %s has an invalid mode: %w", relative, err)
		}
		if _, duplicate := computed[relative]; duplicate {
			return Manifest{}, fmt.Errorf("duplicate archive path %s", relative)
		}
		total += header.Size
		if total > m.maxExpandedSize() || len(computed)+1 > m.maxFiles() {
			return Manifest{}, errors.New("expanded backup exceeds restore limits")
		}
		hasher := sha256.New()
		var destination io.Writer = hasher
		var file *os.File
		if extractRoot != "" {
			pathOnDisk := filepath.Join(extractRoot, filepath.FromSlash(restoreRelative))
			if err := ensureWithin(extractRoot, pathOnDisk); err != nil {
				return Manifest{}, err
			}
			if err := os.MkdirAll(filepath.Dir(pathOnDisk), 0o700); err != nil {
				return Manifest{}, fmt.Errorf("create restore directory: %w", err)
			}
			file, err = os.OpenFile(pathOnDisk, os.O_WRONLY|os.O_CREATE|os.O_EXCL, archiveMode)
			if err != nil {
				return Manifest{}, fmt.Errorf("create restore file %s: %w", relative, err)
			}
			destination = io.MultiWriter(hasher, file)
		}
		written, copyErr := io.CopyN(destination, tarReader, header.Size)
		if file != nil {
			if syncErr := file.Sync(); copyErr == nil {
				copyErr = syncErr
			}
			if closeErr := file.Close(); copyErr == nil {
				copyErr = closeErr
			}
		}
		if copyErr != nil || written != header.Size {
			return Manifest{}, fmt.Errorf("extract %s: %w", relative, copyErr)
		}
		computed[relative] = Entry{Path: relative, Size: header.Size, Mode: archiveModeBits, SHA256: hex.EncodeToString(hasher.Sum(nil))}
	}
	if !manifestSeen || (manifest.Schema != archiveSchema && manifest.Schema != legacySchema) || manifest.CreatedAt.IsZero() {
		return Manifest{}, errors.New("backup has no supported manifest")
	}
	if manifest.Schema == archiveSchema {
		if err := validateEngineRequirements(manifest.Engines); err != nil {
			return Manifest{}, err
		}
		if err := validateManifestEngineCoverage(manifest); err != nil {
			return Manifest{}, err
		}
	}
	if err := compareManifest(manifest, computed); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func compareManifest(manifest Manifest, computed map[string]Entry) error {
	if len(manifest.Entries) != len(computed) {
		return errors.New("backup manifest file count does not match payload")
	}
	seen := make(map[string]struct{}, len(manifest.Entries))
	for _, expected := range manifest.Entries {
		if _, duplicate := seen[expected.Path]; duplicate {
			return fmt.Errorf("duplicate manifest path %s", expected.Path)
		}
		seen[expected.Path] = struct{}{}
		actual, ok := computed[expected.Path]
		if !ok || actual.Size != expected.Size || actual.Mode != expected.Mode || actual.SHA256 != expected.SHA256 {
			return fmt.Errorf("backup integrity mismatch for %s", expected.Path)
		}
	}
	return nil
}

func beginSwapPayload(root, payload, staging string) (*RestoreTransaction, error) {
	entries, err := os.ReadDir(payload)
	if err != nil {
		return nil, fmt.Errorf("read restore payload: %w", err)
	}
	rollback := filepath.Join(staging, "rollback")
	if err := os.Mkdir(rollback, 0o700); err != nil {
		return nil, fmt.Errorf("create restore rollback: %w", err)
	}
	transaction := &RestoreTransaction{
		root: root, payload: payload, staging: staging,
		movedOld: make([]string, 0, len(entries)), movedNew: make([]string, 0, len(entries)),
	}
	for _, entry := range entries {
		name := entry.Name()
		current := filepath.Join(root, name)
		if _, err := os.Lstat(current); err == nil {
			if err := os.Rename(current, filepath.Join(rollback, name)); err != nil {
				return transaction, transaction.rollbackWithCause(fmt.Errorf("stage current %s for rollback: %w", name, err))
			}
			transaction.movedOld = append(transaction.movedOld, name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return transaction, transaction.rollbackWithCause(fmt.Errorf("inspect current %s: %w", name, err))
		}
	}
	for _, entry := range entries {
		name := entry.Name()
		if err := os.Rename(filepath.Join(payload, name), filepath.Join(root, name)); err != nil {
			return transaction, transaction.rollbackWithCause(fmt.Errorf("activate restored %s: %w", name, err))
		}
		transaction.movedNew = append(transaction.movedNew, name)
	}
	if err := syncDirectory(root); err != nil {
		return transaction, transaction.rollbackWithCause(fmt.Errorf("sync restored state: %w", err))
	}
	return transaction, nil
}

// Commit discards the retained previous state. The restored files are already
// active; cleanup failure is reported but never turns a partial staging delete
// into an unsafe rollback attempt.
func (transaction *RestoreTransaction) Commit() error {
	if transaction == nil {
		return errors.New("restore transaction is nil")
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.finalized {
		return nil
	}
	transaction.finalized = true
	cleanupErr := transaction.removeStagingDirectory()
	syncErr := syncDirectory(filepath.Dir(transaction.staging))
	return errors.Join(
		wrapRestoreTransactionError("remove committed restore staging", cleanupErr),
		wrapRestoreTransactionError("sync committed restore staging", syncErr),
	)
}

// Rollback restores the exact top-level paths retained by BeginRestore.
func (transaction *RestoreTransaction) Rollback() error {
	if transaction == nil {
		return errors.New("restore transaction is nil")
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.finalized {
		return nil
	}
	return transaction.rollbackWithCause(nil)
}

// PreviousStateRestored reports whether Rollback restored and synced every
// retained top-level path. It deliberately does not depend on best-effort
// cleanup of the now-redundant staging directory.
func (transaction *RestoreTransaction) PreviousStateRestored() bool {
	if transaction == nil {
		return false
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	return transaction.previousStateRestored
}

func (transaction *RestoreTransaction) rollbackWithCause(cause error) error {
	var failures []error
	for index := len(transaction.movedNew) - 1; index >= 0; index-- {
		name := transaction.movedNew[index]
		if err := os.Rename(filepath.Join(transaction.root, name), filepath.Join(transaction.payload, name)); err != nil {
			failures = append(failures, fmt.Errorf("remove restored %s during rollback: %w", name, err))
		}
	}
	rollback := filepath.Join(transaction.staging, "rollback")
	for index := len(transaction.movedOld) - 1; index >= 0; index-- {
		name := transaction.movedOld[index]
		if err := os.Rename(filepath.Join(rollback, name), filepath.Join(transaction.root, name)); err != nil {
			failures = append(failures, fmt.Errorf("restore previous %s during rollback: %w", name, err))
		}
	}
	if err := syncDirectory(transaction.root); err != nil {
		failures = append(failures, fmt.Errorf("sync rollback state: %w", err))
	}
	transaction.finalized = true
	rollbackErr := errors.Join(failures...)
	if rollbackErr != nil {
		transaction.retainStaging = true
		return errors.Join(cause, rollbackErr, errors.New("restore rollback staging was retained for manual recovery"))
	}
	transaction.previousStateRestored = true
	cleanupErr := transaction.removeStagingDirectory()
	syncErr := syncDirectory(filepath.Dir(transaction.staging))
	return errors.Join(
		cause,
		wrapRestoreTransactionError("remove rolled-back restore staging", cleanupErr),
		wrapRestoreTransactionError("sync rolled-back restore staging", syncErr),
	)
}

func (transaction *RestoreTransaction) removeStagingDirectory() error {
	if transaction.removeStaging != nil {
		return transaction.removeStaging(transaction.staging)
	}
	return os.RemoveAll(transaction.staging)
}

func wrapRestoreTransactionError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func writeManifest(writer *tar.Writer, manifest Manifest) error {
	content, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode backup manifest: %w", err)
	}
	header := &tar.Header{Name: manifestName, Mode: 0o600, Size: int64(len(content)), ModTime: manifest.CreatedAt, Typeflag: tar.TypeReg}
	if err := writer.WriteHeader(header); err != nil {
		return fmt.Errorf("write backup manifest header: %w", err)
	}
	if _, err := writer.Write(content); err != nil {
		return fmt.Errorf("write backup manifest: %w", err)
	}
	return nil
}

func writeFile(writer *tar.Writer, file sourceFile) error {
	header := &tar.Header{Name: "payload/" + file.rel, Mode: int64(safeMode(file.info.Mode())), Size: file.info.Size(), ModTime: file.info.ModTime().UTC(), Typeflag: tar.TypeReg}
	if err := writer.WriteHeader(header); err != nil {
		return fmt.Errorf("write %s header: %w", file.rel, err)
	}
	source, err := os.Open(file.abs)
	if err != nil {
		return fmt.Errorf("open %s: %w", file.rel, err)
	}
	defer source.Close()
	written, err := io.Copy(writer, source)
	if err != nil || written != file.info.Size() {
		return fmt.Errorf("write %s: %w", file.rel, err)
	}
	return nil
}

func (m Manager) paths() (string, string, error) {
	root, err := filepath.Abs(m.Root)
	if err != nil || root == string(filepath.Separator) || root == "." {
		return "", "", errors.New("invalid boxctl root")
	}
	backupDir := m.BackupDir
	if backupDir == "" {
		backupDir = filepath.Join(root, "backups")
	}
	backupDir, err = filepath.Abs(backupDir)
	if err != nil {
		return "", "", fmt.Errorf("resolve backup directory: %w", err)
	}
	return root, backupDir, nil
}

func (m Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m Manager) maxFiles() int {
	if m.MaxFiles > 0 {
		return m.MaxFiles
	}
	return 20_000
}

func (m Manager) maxFileSize() int64 {
	if m.MaxFileSize > 0 {
		return m.MaxFileSize
	}
	return 256 << 20
}

func (m Manager) maxExpandedSize() int64 {
	if m.MaxExpandedSize > 0 {
		return m.MaxExpandedSize
	}
	return 1 << 30
}

func (m Manager) maxArchiveSize() int64 {
	if m.MaxArchiveSize > 0 {
		return m.MaxArchiveSize
	}
	return 64 << 20
}

func shouldExclude(relative string) bool {
	return shouldExcludeStatePath(relative, portableStateDir)
}

func shouldExcludeExport(relative string, options ExportOptions) bool {
	if !options.IncludeAdminPassword && relative == portableStateDir+"/password" {
		return true
	}
	return shouldExclude(relative)
}

func shouldExcludeArchivePath(original, restoreRelative string) bool {
	return shouldExclude(restoreRelative)
}

func shouldExcludeStatePath(relative, stateDir string) bool {
	base := strings.ToLower(path.Base(relative))
	return withinArchivePath(relative, stateDir+"/runtime") ||
		withinArchivePath(relative, stateDir+"/imports") ||
		withinArchivePath(relative, stateDir+"/locks") ||
		withinArchivePath(relative, stateDir+"/secrets") ||
		withinArchivePath(relative, stateDir+"/transition") ||
		relative == stateDir+"/active-gateway.json" ||
		relative == stateDir+"/dns-backup.json" ||
		relative == stateDir+"/dns_backup" ||
		relative == stateDir+"/mihomo-process.json" ||
		relative == stateDir+"/sing-box-process.json" ||
		relative == stateDir+"/core-process.json" ||
		relative == stateDir+"/engine-process.json" ||
		relative == stateDir+"/transition.json" ||
		relative == stateDir+"/core-transition.json" ||
		relative == stateDir+"/engine-transition.json" ||
		relative == stateDir+"/manager-handoff.json" ||
		strings.HasPrefix(base, stateDir+"-state-") ||
		strings.HasPrefix(base, ".rule-list-") ||
		strings.HasPrefix(base, "session.") ||
		strings.HasPrefix(base, "session-") ||
		strings.HasPrefix(base, "session_") ||
		base == "session-secret" ||
		strings.HasPrefix(base, "controller-secret") ||
		(withinArchivePath(relative, stateDir) && engineControllerSecretName(base)) ||
		strings.HasPrefix(base, "core-secret") ||
		strings.HasPrefix(base, "runtime-secret") ||
		withinArchivePath(relative, stateDir) && strings.Contains(base, "transition") && strings.HasSuffix(base, ".json")
}

func engineControllerSecretName(base string) bool {
	// Atomic writers prefix temporary files with a dot and suffix them with a
	// random component. Exclude both the canonical engine-prefixed secret and
	// any interrupted atomic-write sibling below the private state tree.
	base = strings.TrimPrefix(base, ".")
	return strings.HasPrefix(base, "controller-secret") || strings.Contains(base, "-controller-secret")
}

func restorableArchivePath(relative string) (string, bool) {
	return relative, isIncluded(relative)
}

func withinArchivePath(relative, directory string) bool {
	return relative == directory || strings.HasPrefix(relative, directory+"/")
}

func isIncluded(relative string) bool {
	for _, include := range restorableIncludes {
		if relative == include || strings.HasPrefix(relative, include+"/") {
			return true
		}
	}
	return false
}

func cleanArchivePath(value string) (string, error) {
	if value == "" || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
		return "", fmt.Errorf("unsafe archive path %q", value)
	}
	clean := path.Clean(value)
	if clean != value || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("unsafe archive path %q", value)
	}
	return clean, nil
}

func ensureWithin(root, candidate string) error {
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("restore path escapes staging root")
	}
	return nil
}

func safeMode(mode os.FileMode) os.FileMode {
	mode &= 0o700
	if mode&0o400 == 0 {
		mode |= 0o400
	}
	return mode
}

func normalizedArchiveMode(value int64) (os.FileMode, uint32, error) {
	if value < 0 || value > int64(^uint32(0)) {
		return 0, 0, errors.New("mode is outside the uint32 range")
	}
	mode := safeMode(os.FileMode(uint32(value)))
	return mode, uint32(mode), nil
}

func hashFile(filePath string) (string, error) {
	info, err := os.Lstat(filePath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("hash target is not a regular file")
	}
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Size() != info.Size() {
		return "", errors.New("hash target changed during inspection")
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func syncDirectory(directoryPath string) error {
	directory, err := os.Open(directoryPath)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
