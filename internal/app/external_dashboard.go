package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/update"
	"github.com/kontsevoye/boxctl/internal/web"
)

const (
	externalDashboardName             = "Zashboard"
	externalDashboardRepo             = "Zephyruso/zashboard"
	externalDashboardAsset            = "dist-no-fonts.zip"
	externalDashboardArchiveRoot      = "dist"
	externalDashboardMetadataName     = ".boxctl-dashboard.json"
	externalDashboardPublicPath       = "/external-ui/"
	externalDashboardControllerPath   = "/external-ui/controller"
	defaultDashboardArchiveLimit      = int64(16 << 20)
	defaultDashboardExpandedLimit     = int64(64 << 20)
	defaultDashboardFileLimit         = 4096
	defaultDashboardIndividualLimit   = int64(16 << 20)
	defaultDashboardProxyRequestLimit = int64(32 << 20)
	maximumDashboardEntrySize         = uint64(1<<63 - 1)
)

var (
	externalDashboardVersion      = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$`)
	externalDashboardManifestLink = regexp.MustCompile(`(?i)<link\b[^>]*\brel\s*=\s*(?:"manifest"|'manifest')[^>]*>`)
	externalDashboardCrossOrigin  = regexp.MustCompile(`(?i)\bcrossorigin\s*=`)
)

type externalDashboardReleaseSource interface {
	Latest(context.Context, update.Channel) (update.Release, error)
}

type externalDashboardMetadata struct {
	Name        string    `json:"name"`
	Repository  string    `json:"repository"`
	Version     string    `json:"version"`
	Asset       string    `json:"asset"`
	Digest      string    `json:"digest"`
	InstalledAt time.Time `json:"installedAt"`
}

type externalDashboardTarget func() (engine.ControllerEndpoint, error)

// ExternalDashboardManager downloads a digest-attested Zashboard release into
// root/ui and serves it next to a same-origin proxy for the loopback-only
// controller of the active Clash-compatible engine. Controller credentials
// are injected only into proxied requests and never enter a web API response
// or browser URL.
type ExternalDashboardManager struct {
	Layout           state.Layout
	Source           externalDashboardReleaseSource
	Client           *http.Client
	ControllerTarget externalDashboardTarget
	Now              func() time.Time
	MaxArchiveBytes  int64
	MaxExpandedBytes int64
	MaxFiles         int
	MaxFileBytes     int64

	installMu sync.Mutex
	contentMu sync.RWMutex
}

func NewExternalDashboardManager(root string, client *http.Client, provider ActiveControllerProvider) (*ExternalDashboardManager, error) {
	layout, err := state.NewLayout(root)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}
	manager := &ExternalDashboardManager{
		Layout: layout,
		Source: &update.Source{Client: client, Repo: externalDashboardRepo},
		Client: client,
		Now:    time.Now,
	}
	if provider != nil {
		manager.ControllerTarget = provider.ActiveControllerEndpoint
	}
	if err := manager.recoverInterruptedPublish(); err != nil {
		return nil, err
	}
	return manager, nil
}

func (manager *ExternalDashboardManager) ExternalDashboardStatus(ctx context.Context, checkUpdates bool) (web.ExternalDashboardStatus, error) {
	manager.contentMu.RLock()
	status, err := manager.localStatusLocked()
	manager.contentMu.RUnlock()
	if err != nil || !checkUpdates {
		return status, err
	}
	release, _, err := manager.latest(ctx)
	if err != nil {
		// Update discovery is advisory. Keep the locally installed dashboard
		// usable while making the failed check visible to the client.
		status.UpdateCheckFailed = true
		return status, nil //nolint:nilerr // The response carries the advisory failure explicitly.
	}
	status.LatestVersion = release.Tag
	status.UpdateAvailable = !status.Installed || status.CurrentVersion == "" || status.CurrentVersion != release.Tag
	return status, nil
}

func (manager *ExternalDashboardManager) InstallExternalDashboard(ctx context.Context) (web.ExternalDashboardResult, error) {
	return manager.installLatest(ctx, false)
}

func (manager *ExternalDashboardManager) UpdateExternalDashboard(ctx context.Context) (web.ExternalDashboardResult, error) {
	manager.contentMu.RLock()
	status, err := manager.localStatusLocked()
	manager.contentMu.RUnlock()
	if err != nil {
		return web.ExternalDashboardResult{}, err
	}
	if !status.Installed {
		return web.ExternalDashboardResult{}, web.ErrNotFound
	}
	return manager.installLatest(ctx, true)
}

func (manager *ExternalDashboardManager) OpenExternalDashboard(context.Context) (web.ExternalDashboardOpen, error) {
	manager.contentMu.RLock()
	defer manager.contentMu.RUnlock()
	status, err := manager.localStatusLocked()
	if err != nil {
		return web.ExternalDashboardOpen{}, err
	}
	if !status.Installed {
		return web.ExternalDashboardOpen{}, web.ErrNotFound
	}
	return web.ExternalDashboardOpen{Path: externalDashboardPublicPath, ControllerPath: externalDashboardControllerPath}, nil
}

func (manager *ExternalDashboardManager) installLatest(ctx context.Context, requireExisting bool) (web.ExternalDashboardResult, error) {
	manager.installMu.Lock()
	defer manager.installMu.Unlock()

	manager.contentMu.Lock()
	err := manager.recoverInterruptedPublish()
	manager.contentMu.Unlock()
	if err != nil {
		return web.ExternalDashboardResult{}, err
	}
	manager.contentMu.RLock()
	current, err := manager.localStatusLocked()
	manager.contentMu.RUnlock()
	if err != nil {
		return web.ExternalDashboardResult{}, err
	}
	if requireExisting && !current.Installed {
		return web.ExternalDashboardResult{}, web.ErrNotFound
	}

	release, asset, err := manager.latest(ctx)
	if err != nil {
		return web.ExternalDashboardResult{}, dashboardPublicError("dashboard_release_failed", "Unable to discover a verified Zashboard release", err)
	}
	if current.Installed && current.CurrentVersion == release.Tag {
		current.LatestVersion = release.Tag
		current.UpdateAvailable = false
		return web.ExternalDashboardResult{ExternalDashboardStatus: current, Changed: false}, nil
	}

	staging, err := manager.stage(ctx, release, asset)
	if err != nil {
		return web.ExternalDashboardResult{}, dashboardPublicError("dashboard_install_failed", "Unable to download and verify Zashboard", err)
	}
	defer os.RemoveAll(staging)

	manager.contentMu.Lock()
	err = manager.publish(staging)
	manager.contentMu.Unlock()
	if err != nil {
		return web.ExternalDashboardResult{}, dashboardPublicError("dashboard_publish_failed", "Unable to publish the verified Zashboard files", err)
	}
	return web.ExternalDashboardResult{ExternalDashboardStatus: web.ExternalDashboardStatus{
		Name: externalDashboardName, Installed: true, CurrentVersion: release.Tag,
		LatestVersion: release.Tag, UpdateAvailable: false,
	}, Changed: true}, nil
}

func dashboardPublicError(code, message string, cause error) error {
	return errors.Join(&web.PublicError{Status: http.StatusBadGateway, Code: code, Message: message}, cause)
}

func (manager *ExternalDashboardManager) localStatusLocked() (web.ExternalDashboardStatus, error) {
	status := web.ExternalDashboardStatus{Name: externalDashboardName}
	installed, err := validDashboardDirectory(manager.Layout.DashboardDir)
	if err != nil {
		return status, err
	}
	status.Installed = installed
	if !installed {
		return status, nil
	}
	metadata, err := readExternalDashboardMetadata(filepath.Join(manager.Layout.DashboardDir, externalDashboardMetadataName))
	if errors.Is(err, os.ErrNotExist) {
		// A manually installed/restored Zashboard remains usable. Its version is
		// unknown until boxctl replaces it with a verified release.
		return status, nil
	}
	if err != nil {
		return status, fmt.Errorf("read installed dashboard metadata: %w", err)
	}
	status.CurrentVersion = metadata.Version
	return status, nil
}

func validDashboardDirectory(directory string) (bool, error) {
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect dashboard directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, errors.New("dashboard path is not a regular directory")
	}
	index := filepath.Join(directory, "index.html")
	indexInfo, err := os.Lstat(index)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect dashboard index: %w", err)
	}
	if indexInfo.Mode()&os.ModeSymlink != 0 || !indexInfo.Mode().IsRegular() {
		return false, errors.New("dashboard index is not a regular file")
	}
	return true, nil
}

func readExternalDashboardMetadata(filename string) (externalDashboardMetadata, error) {
	file, err := os.Open(filename)
	if err != nil {
		return externalDashboardMetadata{}, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, (16<<10)+1))
	if err != nil {
		return externalDashboardMetadata{}, fmt.Errorf("read dashboard metadata: %w", err)
	}
	if len(content) > 16<<10 {
		return externalDashboardMetadata{}, errors.New("dashboard metadata exceeds limit")
	}
	var metadata externalDashboardMetadata
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return externalDashboardMetadata{}, fmt.Errorf("decode dashboard metadata: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return externalDashboardMetadata{}, errors.New("decode dashboard metadata: trailing data")
	}
	if metadata.Name != externalDashboardName || metadata.Repository != externalDashboardRepo || metadata.Asset != externalDashboardAsset ||
		!externalDashboardVersion.MatchString(metadata.Version) {
		return externalDashboardMetadata{}, errors.New("dashboard metadata is invalid")
	}
	if _, err := update.ParseDigest(metadata.Digest); err != nil {
		return externalDashboardMetadata{}, errors.New("dashboard metadata digest is invalid")
	}
	return metadata, nil
}

func (manager *ExternalDashboardManager) latest(ctx context.Context) (update.Release, update.Asset, error) {
	source := manager.Source
	if source == nil {
		source = &update.Source{Client: manager.Client, Repo: externalDashboardRepo}
	}
	release, err := source.Latest(ctx, update.ChannelStable)
	if err != nil {
		return update.Release{}, update.Asset{}, err
	}
	if !externalDashboardVersion.MatchString(release.Tag) {
		return update.Release{}, update.Asset{}, fmt.Errorf("unsafe Zashboard release tag %q", release.Tag)
	}
	var selected *update.Asset
	for index := range release.Assets {
		asset := &release.Assets[index]
		if asset.Name != externalDashboardAsset {
			continue
		}
		if selected != nil {
			return update.Release{}, update.Asset{}, fmt.Errorf("release %s contains duplicate %s assets", release.Tag, externalDashboardAsset)
		}
		selected = asset
	}
	if selected != nil {
		asset := *selected
		if asset.Size <= 0 || asset.Size > manager.maxArchiveBytes() {
			return update.Release{}, update.Asset{}, errors.New("zashboard asset size is invalid")
		}
		if _, err := update.ParseDigest(asset.Digest); err != nil {
			return update.Release{}, update.Asset{}, fmt.Errorf("zashboard asset digest: %w", err)
		}
		parsed, err := url.Parse(asset.URL)
		if err != nil || parsed.Scheme != "https" || !strings.EqualFold(parsed.Hostname(), "github.com") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return update.Release{}, update.Asset{}, errors.New("zashboard asset URL is unsafe")
		}
		wantPath := "/" + externalDashboardRepo + "/releases/download/" + release.Tag + "/" + externalDashboardAsset
		if parsed.EscapedPath() != wantPath {
			return update.Release{}, update.Asset{}, errors.New("zashboard asset URL does not match its release")
		}
		return release, asset, nil
	}
	return update.Release{}, update.Asset{}, fmt.Errorf("release %s has no %s asset", release.Tag, externalDashboardAsset)
}

func (manager *ExternalDashboardManager) stage(ctx context.Context, release update.Release, asset update.Asset) (staging string, err error) {
	if err := os.MkdirAll(manager.Layout.Root, 0o700); err != nil {
		return "", fmt.Errorf("create boxctl root: %w", err)
	}
	download, err := os.CreateTemp(manager.Layout.Root, ".boxctl-dashboard-download-*.zip")
	if err != nil {
		return "", fmt.Errorf("create dashboard download: %w", err)
	}
	downloadPath := download.Name()
	defer func() {
		_ = download.Close()
		_ = os.Remove(downloadPath)
		if err != nil && staging != "" {
			_ = os.RemoveAll(staging)
		}
	}()
	if err := download.Chmod(0o600); err != nil {
		return "", err
	}
	if err := manager.download(ctx, asset, download); err != nil {
		return "", err
	}
	if err := download.Sync(); err != nil {
		return "", fmt.Errorf("sync dashboard download: %w", err)
	}
	if err := download.Close(); err != nil {
		return "", fmt.Errorf("close dashboard download: %w", err)
	}

	staging, err = os.MkdirTemp(manager.Layout.Root, ".boxctl-dashboard-staged-")
	if err != nil {
		return "", fmt.Errorf("create dashboard staging directory: %w", err)
	}
	if err := os.Chmod(staging, 0o700); err != nil {
		return "", err
	}
	if err := manager.extract(downloadPath, staging); err != nil {
		return "", err
	}
	if err := validateZashboardIndex(filepath.Join(staging, "index.html")); err != nil {
		return "", err
	}
	metadata := externalDashboardMetadata{
		Name: externalDashboardName, Repository: externalDashboardRepo, Version: release.Tag,
		Asset: externalDashboardAsset, Digest: asset.Digest, InstalledAt: manager.now().UTC(),
	}
	encoded, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return "", err
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(staging, externalDashboardMetadataName), encoded, 0o600); err != nil {
		return "", fmt.Errorf("write dashboard metadata: %w", err)
	}
	if err := syncTree(staging); err != nil {
		return "", err
	}
	return staging, nil
}

func (manager *ExternalDashboardManager) download(ctx context.Context, asset update.Asset, destination io.Writer) error {
	expected, err := update.ParseDigest(asset.Digest)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		return fmt.Errorf("create dashboard download request: %w", err)
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("User-Agent", "boxctl")
	client := manager.Client
	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download dashboard: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download dashboard: HTTP %d", resp.StatusCode)
	}
	if resp.Request == nil || resp.Request.URL == nil || resp.Request.URL.Scheme != "https" {
		return errors.New("dashboard download redirected to an unsafe URL")
	}
	limit := manager.maxArchiveBytes()
	if resp.ContentLength > limit {
		return fmt.Errorf("dashboard archive exceeds %d bytes", limit)
	}
	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, digest), io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("download dashboard: %w", err)
	}
	if written > limit {
		return fmt.Errorf("dashboard archive exceeds %d bytes", limit)
	}
	if written != asset.Size {
		return fmt.Errorf("dashboard download size mismatch: expected %d, got %d", asset.Size, written)
	}
	if !equalDashboardDigest(digest, expected[:]) {
		return errors.New("dashboard download sha256 does not match GitHub release digest")
	}
	return nil
}

func equalDashboardDigest(actual hash.Hash, expected []byte) bool {
	got := actual.Sum(nil)
	if len(got) != len(expected) {
		return false
	}
	var difference byte
	for index := range got {
		difference |= got[index] ^ expected[index]
	}
	return difference == 0
}

func (manager *ExternalDashboardManager) extract(archivePath, staging string) error {
	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open dashboard zip: %w", err)
	}
	defer archive.Close()
	if len(archive.File) == 0 || len(archive.File) > manager.maxFiles() {
		return errors.New("dashboard archive file count is invalid")
	}
	seen := make(map[string]struct{}, len(archive.File))
	var expanded int64
	for _, entry := range archive.File {
		if strings.Contains(entry.Name, "\\") || strings.ContainsRune(entry.Name, 0) {
			return fmt.Errorf("dashboard archive contains unsafe path %q", entry.Name)
		}
		clean := path.Clean(entry.Name)
		if clean == "." || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") ||
			(clean != entry.Name && clean+"/" != entry.Name) {
			return fmt.Errorf("dashboard archive contains unsafe path %q", entry.Name)
		}
		parts := strings.Split(clean, "/")
		if parts[0] != externalDashboardArchiveRoot {
			return fmt.Errorf("dashboard archive path %q is outside %s/", entry.Name, externalDashboardArchiveRoot)
		}
		if len(parts) == 1 {
			if !entry.FileInfo().IsDir() {
				return errors.New("dashboard archive root is not a directory")
			}
			continue
		}
		relative := path.Join(parts[1:]...)
		for _, segment := range parts[1:] {
			if strings.HasPrefix(segment, ".") {
				return fmt.Errorf("dashboard archive contains hidden path %q", entry.Name)
			}
		}
		if _, duplicate := seen[relative]; duplicate {
			return fmt.Errorf("dashboard archive contains duplicate path %q", relative)
		}
		seen[relative] = struct{}{}
		mode := entry.Mode()
		if mode&os.ModeSymlink != 0 || (!entry.FileInfo().IsDir() && !mode.IsRegular()) {
			return fmt.Errorf("dashboard archive contains non-regular entry %q", entry.Name)
		}
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(filepath.Join(staging, filepath.FromSlash(relative)), 0o755); err != nil {
				return err
			}
			continue
		}
		if entry.UncompressedSize64 > maximumDashboardEntrySize {
			return fmt.Errorf("dashboard file %q exceeds limit", relative)
		}
		size := int64(entry.UncompressedSize64)
		if size > manager.maxFileBytes() || size > manager.maxExpandedBytes() {
			return fmt.Errorf("dashboard file %q exceeds limit", relative)
		}
		if expanded > manager.maxExpandedBytes()-size {
			return errors.New("dashboard expanded-size limit exceeded")
		}
		expanded += size
		destination := filepath.Join(staging, filepath.FromSlash(relative))
		if err := ensureDashboardWithin(staging, destination); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return err
		}
		if err := extractDashboardFile(entry, destination, manager.maxFileBytes(), size); err != nil {
			return err
		}
	}
	return nil
}

func extractDashboardFile(entry *zip.File, destination string, limit, expectedSize int64) error {
	source, err := entry.Open()
	if err != nil {
		return fmt.Errorf("open dashboard file %q: %w", entry.Name, err)
	}
	defer source.Close()
	target, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create dashboard file %q: %w", entry.Name, err)
	}
	written, copyErr := io.Copy(target, io.LimitReader(source, limit+1))
	if copyErr == nil && written > limit {
		copyErr = errors.New("expanded dashboard file exceeds limit")
	}
	if copyErr == nil && written != expectedSize {
		copyErr = errors.New("expanded dashboard file size mismatch")
	}
	if syncErr := target.Sync(); copyErr == nil {
		copyErr = syncErr
	}
	if closeErr := target.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		_ = os.Remove(destination)
		return fmt.Errorf("extract dashboard file %q: %w", entry.Name, copyErr)
	}
	return nil
}

func validateZashboardIndex(filename string) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read dashboard index: %w", err)
	}
	if len(content) == 0 || len(content) > 1<<20 || !bytes.Contains(bytes.ToLower(content), []byte("zashboard")) ||
		!bytes.Contains(content, []byte("./assets/")) {
		return errors.New("dashboard archive does not contain a valid Zashboard index")
	}
	return nil
}

func (manager *ExternalDashboardManager) publish(staging string) error {
	target := manager.Layout.DashboardDir
	if err := ensureDashboardWithin(manager.Layout.Root, staging); err != nil {
		return err
	}
	if filepath.Dir(staging) != manager.Layout.Root || filepath.Dir(target) != manager.Layout.Root {
		return errors.New("dashboard staging and target must share the boxctl root")
	}
	backup, err := reserveDashboardRenamePath(manager.Layout.Root, ".boxctl-dashboard-previous-")
	if err != nil {
		return err
	}
	hadPrevious := false
	if info, inspectErr := os.Lstat(target); inspectErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("existing dashboard path is not a regular directory")
		}
		if renameErr := os.Rename(target, backup); renameErr != nil {
			return fmt.Errorf("stage previous dashboard: %w", renameErr)
		}
		hadPrevious = true
	} else if !errors.Is(inspectErr, os.ErrNotExist) {
		return inspectErr
	}
	if err := os.Rename(staging, target); err != nil {
		if hadPrevious {
			if rollbackErr := os.Rename(backup, target); rollbackErr != nil {
				return errors.Join(fmt.Errorf("publish dashboard: %w", err), fmt.Errorf("restore previous dashboard: %w", rollbackErr))
			}
		}
		return fmt.Errorf("publish dashboard: %w", err)
	}
	if err := syncDirectoryPath(manager.Layout.Root); err != nil {
		return manager.rollbackPublishedDashboard(target, backup, hadPrevious, err)
	}
	if hadPrevious {
		// The new tree is already published and durable. A cleanup failure must
		// not turn a successful update into a failed one or block future updates;
		// uniquely named recovery directories are cleaned on the next startup.
		_ = os.RemoveAll(backup)
		_ = syncDirectoryPath(manager.Layout.Root)
	}
	return nil
}

func reserveDashboardRenamePath(root, pattern string) (string, error) {
	directory, err := os.MkdirTemp(root, pattern)
	if err != nil {
		return "", fmt.Errorf("reserve dashboard recovery path: %w", err)
	}
	if err := os.Remove(directory); err != nil {
		return "", fmt.Errorf("prepare dashboard recovery path: %w", err)
	}
	return directory, nil
}

func (manager *ExternalDashboardManager) rollbackPublishedDashboard(target, backup string, hadPrevious bool, publishErr error) error {
	failed, reserveErr := reserveDashboardRenamePath(manager.Layout.Root, ".boxctl-dashboard-failed-")
	if reserveErr != nil {
		return errors.Join(fmt.Errorf("sync dashboard publish: %w", publishErr), reserveErr)
	}
	if err := os.Rename(target, failed); err != nil {
		return errors.Join(fmt.Errorf("sync dashboard publish: %w", publishErr), fmt.Errorf("stage failed dashboard: %w", err))
	}
	if hadPrevious {
		if err := os.Rename(backup, target); err != nil {
			return errors.Join(fmt.Errorf("sync dashboard publish: %w", publishErr), fmt.Errorf("restore previous dashboard: %w", err))
		}
	}
	if err := syncDirectoryPath(manager.Layout.Root); err != nil {
		return errors.Join(fmt.Errorf("sync dashboard publish: %w", publishErr), fmt.Errorf("sync dashboard rollback: %w", err))
	}
	_ = os.RemoveAll(failed)
	_ = syncDirectoryPath(manager.Layout.Root)
	return fmt.Errorf("sync dashboard publish: %w", publishErr)
}

func (manager *ExternalDashboardManager) recoverInterruptedPublish() error {
	backups, err := filepath.Glob(filepath.Join(manager.Layout.Root, ".boxctl-dashboard-previous-*"))
	if err != nil || len(backups) == 0 {
		return err
	}
	installed, statusErr := validDashboardDirectory(manager.Layout.DashboardDir)
	if statusErr != nil {
		return statusErr
	}
	if installed {
		for _, backup := range backups {
			_ = os.RemoveAll(backup)
		}
		_ = syncDirectoryPath(manager.Layout.Root)
		return nil
	}
	if _, err := os.Lstat(manager.Layout.DashboardDir); err == nil {
		return errors.New("cannot recover dashboard over an invalid ui directory")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(backups) != 1 {
		return errors.New("multiple interrupted dashboard updates require manual recovery")
	}
	if err := os.Rename(backups[0], manager.Layout.DashboardDir); err != nil {
		return fmt.Errorf("recover previous dashboard: %w", err)
	}
	return syncDirectoryPath(manager.Layout.Root)
}

func (manager *ExternalDashboardManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	writeExternalDashboardHeaders(w)
	if r.URL.Path == externalDashboardControllerPath || strings.HasPrefix(r.URL.Path, externalDashboardControllerPath+"/") {
		manager.serveController(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	manager.contentMu.RLock()
	defer manager.contentMu.RUnlock()
	installed, err := validDashboardDirectory(manager.Layout.DashboardDir)
	if err != nil || !installed {
		http.NotFound(w, r)
		return
	}
	manager.serveDashboardFile(w, r)
}

func writeExternalDashboardHeaders(w http.ResponseWriter) {
	applyExternalDashboardHeaders(w.Header())
}

func (manager *ExternalDashboardManager) serveDashboardFile(w http.ResponseWriter, r *http.Request) {
	relative := strings.TrimPrefix(r.URL.Path, externalDashboardPublicPath)
	if relative == "" {
		relative = "index.html"
	}
	if strings.Contains(relative, "\\") || strings.ContainsRune(relative, 0) {
		http.NotFound(w, r)
		return
	}
	clean := path.Clean(relative)
	if clean == "." || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
		http.NotFound(w, r)
		return
	}
	for _, segment := range strings.Split(clean, "/") {
		if strings.HasPrefix(segment, ".") {
			http.NotFound(w, r)
			return
		}
	}
	filename := filepath.Join(manager.Layout.DashboardDir, filepath.FromSlash(clean))
	if err := ensureDashboardWithin(manager.Layout.DashboardDir, filename); err != nil || hasDashboardSymlink(manager.Layout.DashboardDir, filename) {
		http.NotFound(w, r)
		return
	}
	file, err := os.Open(filename)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	if clean == "index.html" || clean == "sw.js" || clean == "registerSW.js" || clean == "manifest.webmanifest" {
		w.Header().Set("Cache-Control", "no-cache")
	} else if strings.HasPrefix(clean, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	if clean == "index.html" {
		content, err := io.ReadAll(io.LimitReader(file, manager.maxFileBytes()+1))
		if err != nil || int64(len(content)) > manager.maxFileBytes() {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		content = addDashboardManifestCredentials(content)
		http.ServeContent(w, r, path.Base(clean), info.ModTime(), bytes.NewReader(content))
		return
	}
	http.ServeContent(w, r, path.Base(clean), info.ModTime(), file)
}

// addDashboardManifestCredentials keeps the dashboard behind boxctl's normal
// authenticated route while making browser-initiated manifest requests carry
// the same HttpOnly session cookie as the document.
func addDashboardManifestCredentials(content []byte) []byte {
	return externalDashboardManifestLink.ReplaceAllFunc(content, func(link []byte) []byte {
		if externalDashboardCrossOrigin.Match(link) {
			return link
		}
		insertAt := len(link) - 1
		if insertAt > 0 && link[insertAt-1] == '/' {
			insertAt--
		}
		result := make([]byte, 0, len(link)+30)
		result = append(result, link[:insertAt]...)
		result = append(result, ` crossorigin="use-credentials"`...)
		result = append(result, link[insertAt:]...)
		return result
	})
}

func (manager *ExternalDashboardManager) serveController(w http.ResponseWriter, r *http.Request) {
	if manager.ControllerTarget == nil {
		http.Error(w, "Core controller is unavailable", http.StatusServiceUnavailable)
		return
	}
	endpoint, err := manager.ControllerTarget()
	if err != nil {
		http.Error(w, "Core controller is unavailable", http.StatusServiceUnavailable)
		return
	}
	target, err := url.Parse(endpoint.BaseURL)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" || target.User != nil ||
		target.RawQuery != "" || target.Fragment != "" || !isLoopbackControllerHost(target.Hostname()) {
		http.Error(w, "Core controller is unavailable", http.StatusServiceUnavailable)
		return
	}
	if !isWebSocketRequest(r) {
		r.Body = http.MaxBytesReader(w, r.Body, defaultDashboardProxyRequestLimit)
	}
	requestPath := strings.TrimPrefix(r.URL.Path, externalDashboardControllerPath)
	if requestPath == "" {
		requestPath = "/"
	}
	proxy := &httputil.ReverseProxy{Rewrite: func(request *httputil.ProxyRequest) {
		request.SetURL(target)
		request.Out.URL.Path = singleJoiningSlash(target.Path, requestPath)
		request.Out.URL.RawPath = ""
		for _, header := range []string{"Cookie", "Forwarded", "Origin", "Referer", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "X-CSRF-Token", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
			request.Out.Header.Del(header)
		}
		request.Out.Header["X-Forwarded-For"] = nil
		if endpoint.Secret == "" {
			request.Out.Header.Del("Authorization")
		} else {
			request.Out.Header.Set("Authorization", "Bearer "+endpoint.Secret)
		}
	}}
	proxy.ModifyResponse = func(response *http.Response) error {
		response.Header.Del("Access-Control-Allow-Credentials")
		response.Header.Del("Access-Control-Allow-Origin")
		response.Header.Del("Set-Cookie")
		applyExternalDashboardHeaders(response.Header)
		return nil
	}
	proxy.ErrorHandler = func(response http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(response, "Core controller is unavailable", http.StatusBadGateway)
	}
	proxy.FlushInterval = -1
	proxy.ServeHTTP(w, r)
}

func applyExternalDashboardHeaders(header http.Header) {
	header.Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; connect-src 'self' https://api.github.com; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data: blob: https:; manifest-src 'self'; object-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; worker-src 'self' blob:")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
}

func isLoopbackControllerHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	parsed := net.ParseIP(host)
	return parsed != nil && parsed.IsLoopback()
}

func isWebSocketRequest(r *http.Request) bool {
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		return false
	}
	for _, value := range r.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

func singleJoiningSlash(left, right string) string {
	return strings.TrimRight(left, "/") + "/" + strings.TrimLeft(right, "/")
}

func hasDashboardSymlink(root, filename string) bool {
	relative, err := filepath.Rel(root, filename)
	if err != nil {
		return true
	}
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

func ensureDashboardWithin(root, filename string) error {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(filename))
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return errors.New("dashboard path escapes its root")
	}
	return nil
}

func syncTree(root string) error {
	var directories []string
	if err := filepath.Walk(root, func(current string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing dashboard staging symlink")
		}
		if info.IsDir() {
			directories = append(directories, current)
			return nil
		}
		file, err := os.Open(current)
		if err != nil {
			return err
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}); err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := syncDirectoryPath(directories[index]); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectoryPath(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func (manager *ExternalDashboardManager) now() time.Time {
	if manager.Now != nil {
		return manager.Now()
	}
	return time.Now()
}

func (manager *ExternalDashboardManager) maxArchiveBytes() int64 {
	if manager.MaxArchiveBytes > 0 {
		return manager.MaxArchiveBytes
	}
	return defaultDashboardArchiveLimit
}

func (manager *ExternalDashboardManager) maxExpandedBytes() int64 {
	if manager.MaxExpandedBytes > 0 {
		return manager.MaxExpandedBytes
	}
	return defaultDashboardExpandedLimit
}

func (manager *ExternalDashboardManager) maxFiles() int {
	if manager.MaxFiles > 0 {
		return manager.MaxFiles
	}
	return defaultDashboardFileLimit
}

func (manager *ExternalDashboardManager) maxFileBytes() int64 {
	if manager.MaxFileBytes > 0 {
		return manager.MaxFileBytes
	}
	return defaultDashboardIndividualLimit
}

func dashboardDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}
