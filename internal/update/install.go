package update

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultMaxCompressed   = int64(64 << 20)
	defaultMaxUncompressed = int64(128 << 20)
)

// ErrInstallRollbackFailed marks an install error for which the previous
// on-disk state could not be restored completely. Callers must not assume the
// target contains either the old or the new binary when this error is present.
var ErrInstallRollbackFailed = errors.New("automatic install rollback failed")

// BinaryValidator performs engine-specific validation after integrity and ELF
// checks, for example `mihomo -v` and `mihomo -t` against the active profile.
type BinaryValidator interface {
	ValidateBinary(context.Context, string) error
}

// Installer downloads, stages and atomically installs verified binaries.
type Installer struct {
	Client          *http.Client
	Validator       BinaryValidator
	MaxCompressed   int64
	MaxUncompressed int64
}

// ParseDigest accepts only GitHub's sha256:<hex> release-asset digest.
func ParseDigest(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	prefix, encoded, ok := strings.Cut(value, ":")
	if !ok || prefix != "sha256" || len(encoded) != sha256.Size*2 {
		return result, errors.New("missing valid sha256 release digest")
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return result, errors.New("invalid sha256 release digest")
	}
	copy(result[:], decoded)
	return result, nil
}

// Stage downloads and validates an asset, placing the executable in dir. The
// caller should choose a directory on the same filesystem as the final target.
func (i *Installer) Stage(ctx context.Context, asset Asset, dir string) (path string, err error) {
	expected, err := ParseDigest(asset.Digest)
	if err != nil {
		return "", err
	}
	if asset.Size <= 0 {
		return "", errors.New("asset size must be positive")
	}
	maxCompressed := i.MaxCompressed
	if maxCompressed == 0 {
		maxCompressed = defaultMaxCompressed
	}
	if asset.Size > maxCompressed {
		return "", fmt.Errorf("compressed asset exceeds %d bytes", maxCompressed)
	}
	maxUncompressed := i.MaxUncompressed
	if maxUncompressed == 0 {
		maxUncompressed = defaultMaxUncompressed
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create staging directory: %w", err)
	}
	compressed, err := os.CreateTemp(dir, ".mihomo-download-*.gz")
	if err != nil {
		return "", fmt.Errorf("create download: %w", err)
	}
	compressedPath := compressed.Name()
	defer func() {
		_ = compressed.Close()
		_ = os.Remove(compressedPath)
		if err != nil && path != "" {
			_ = os.Remove(path)
		}
	}()

	if err := i.download(ctx, asset, compressed, expected, maxCompressed); err != nil {
		return "", err
	}
	if err := compressed.Close(); err != nil {
		return "", fmt.Errorf("close download: %w", err)
	}
	if err := os.Chmod(compressedPath, 0o600); err != nil {
		return "", fmt.Errorf("protect download: %w", err)
	}

	archive, err := os.Open(compressedPath)
	if err != nil {
		return "", fmt.Errorf("open download: %w", err)
	}
	defer archive.Close()
	reader, err := gzip.NewReader(archive)
	if err != nil {
		return "", fmt.Errorf("open gzip asset: %w", err)
	}
	defer reader.Close()

	staged, err := os.CreateTemp(dir, ".mihomo-staged-*")
	if err != nil {
		return "", fmt.Errorf("create staged binary: %w", err)
	}
	path = staged.Name()
	written, copyErr := io.Copy(staged, io.LimitReader(reader, maxUncompressed+1))
	if copyErr == nil && written > maxUncompressed {
		copyErr = fmt.Errorf("uncompressed asset exceeds %d bytes", maxUncompressed)
	}
	if syncErr := staged.Sync(); copyErr == nil {
		copyErr = syncErr
	}
	if closeErr := staged.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return "", fmt.Errorf("extract asset: %w", copyErr)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		return "", fmt.Errorf("mark staged binary executable: %w", err)
	}
	if err := ValidateLinuxARM64(path); err != nil {
		return "", err
	}
	if i.Validator != nil {
		if err := i.Validator.ValidateBinary(ctx, path); err != nil {
			return "", fmt.Errorf("validate staged core: %w", err)
		}
	}
	return path, nil
}

// StageRaw downloads and validates an uncompressed Linux/AArch64 executable,
// placing it in dir so it can be atomically installed on the same filesystem.
func (i *Installer) StageRaw(ctx context.Context, asset Asset, dir string) (path string, err error) {
	expected, err := ParseDigest(asset.Digest)
	if err != nil {
		return "", err
	}
	limit := i.rawLimit()
	if asset.Size <= 0 {
		return "", errors.New("asset size must be positive")
	}
	if asset.Size > limit {
		return "", fmt.Errorf("binary asset exceeds %d bytes", limit)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create staging directory: %w", err)
	}
	staged, err := os.CreateTemp(dir, ".boxctl-staged-*")
	if err != nil {
		return "", fmt.Errorf("create staged binary: %w", err)
	}
	path = staged.Name()
	defer func() {
		_ = staged.Close()
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	if err := i.download(ctx, asset, staged, expected, limit); err != nil {
		return "", err
	}
	if err := finishStagedExecutable(ctx, staged, path, i.Validator); err != nil {
		return "", err
	}
	return path, nil
}

// StageFile copies and validates a local Linux/AArch64 executable. Digest must
// use sha256:<hex>; callers may obtain it from an explicit value or companion
// checksum file, but the installer never accepts an unverified local source.
func (i *Installer) StageFile(ctx context.Context, sourcePath, digest, dir string) (path string, err error) {
	expected, err := ParseDigest(digest)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	info, err := os.Lstat(sourcePath)
	if err != nil {
		return "", fmt.Errorf("inspect local update file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("local update file must be a regular non-symlink file")
	}
	limit := i.rawLimit()
	if info.Size() <= 0 {
		return "", errors.New("local update file is empty")
	}
	if info.Size() > limit {
		return "", fmt.Errorf("binary asset exceeds %d bytes", limit)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return "", fmt.Errorf("open local update file: %w", err)
	}
	defer source.Close()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create staging directory: %w", err)
	}
	staged, err := os.CreateTemp(dir, ".boxctl-staged-*")
	if err != nil {
		return "", fmt.Errorf("create staged binary: %w", err)
	}
	path = staged.Name()
	defer func() {
		_ = staged.Close()
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	digestWriter := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(staged, digestWriter), io.LimitReader(source, limit+1))
	if copyErr == nil && written > limit {
		copyErr = fmt.Errorf("binary asset exceeds %d bytes", limit)
	}
	if copyErr == nil && written != info.Size() {
		copyErr = fmt.Errorf("local update size changed while reading: expected %d, got %d", info.Size(), written)
	}
	if copyErr != nil {
		return "", fmt.Errorf("copy local update file: %w", copyErr)
	}
	if !equalDigest(digestWriter, expected) {
		return "", errors.New("local update sha256 does not match expected digest")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := finishStagedExecutable(ctx, staged, path, i.Validator); err != nil {
		return "", err
	}
	return path, nil
}

func (i *Installer) rawLimit() int64 {
	if i.MaxUncompressed > 0 {
		return i.MaxUncompressed
	}
	return defaultMaxUncompressed
}

func finishStagedExecutable(ctx context.Context, staged *os.File, path string, validator BinaryValidator) error {
	if err := staged.Sync(); err != nil {
		return fmt.Errorf("sync staged binary: %w", err)
	}
	if err := staged.Close(); err != nil {
		return fmt.Errorf("close staged binary: %w", err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		return fmt.Errorf("mark staged binary executable: %w", err)
	}
	if err := ValidateLinuxARM64(path); err != nil {
		return err
	}
	if validator != nil {
		if err := validator.ValidateBinary(ctx, path); err != nil {
			return fmt.Errorf("validate staged binary: %w", err)
		}
	}
	return nil
}

func (i *Installer) download(ctx context.Context, asset Asset, destination io.Writer, expected [sha256.Size]byte, limit int64) error {
	client := i.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		return fmt.Errorf("create download request: %w", err)
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("User-Agent", "boxctl")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download asset: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download asset: HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return fmt.Errorf("compressed asset exceeds %d bytes", limit)
	}
	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, digest), io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("download asset: %w", err)
	}
	if written > limit {
		return fmt.Errorf("compressed asset exceeds %d bytes", limit)
	}
	if asset.Size != written {
		return fmt.Errorf("download size mismatch: expected %d, got %d", asset.Size, written)
	}
	if !equalDigest(digest, expected) {
		return errors.New("download sha256 does not match GitHub release digest")
	}
	return nil
}

func equalDigest(actual hash.Hash, expected [sha256.Size]byte) bool {
	actualBytes := actual.Sum(nil)
	if len(actualBytes) != len(expected) {
		return false
	}
	var difference byte
	for index := range actualBytes {
		difference |= actualBytes[index] ^ expected[index]
	}
	return difference == 0
}

// ValidateLinuxARM64 requires a regular 64-bit little-endian AArch64 ELF
// executable. It performs no target-specific execution or configuration work.
func ValidateLinuxARM64(path string) error {
	binary, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("staged binary is not ELF: %w", err)
	}
	defer binary.Close()
	if binary.Class != elf.ELFCLASS64 || binary.Data != elf.ELFDATA2LSB || binary.Machine != elf.EM_AARCH64 {
		return fmt.Errorf("staged binary has unsupported ELF target: class=%s data=%s machine=%s", binary.Class, binary.Data, binary.Machine)
	}
	if binary.Type != elf.ET_EXEC && binary.Type != elf.ET_DYN {
		return fmt.Errorf("staged binary has unsupported ELF type %s", binary.Type)
	}
	return nil
}

// Install swaps a staged binary into target and retains target.prev. Staged
// must live on the same filesystem so the final rename is atomic. A failure
// after the swap restores the prior target and retains the candidate as
// target.failed; ErrInstallRollbackFailed marks an incomplete restoration.
func Install(staged, target string) error {
	return install(staged, target, syncDirectory)
}

func install(staged, target string, syncDir func(string) error) error {
	stagedDir, err := filepath.Abs(filepath.Dir(staged))
	if err != nil {
		return fmt.Errorf("resolve staged directory: %w", err)
	}
	targetDir, err := filepath.Abs(filepath.Dir(target))
	if err != nil {
		return fmt.Errorf("resolve target directory: %w", err)
	}
	if stagedDir != targetDir {
		return errors.New("staged binary must be in the target directory for atomic install")
	}
	info, err := os.Lstat(staged)
	if err != nil {
		return fmt.Errorf("inspect staged binary: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("staged binary is not a regular file")
	}
	previous := target + ".prev"
	hadPrevious := false
	if _, err := os.Lstat(target); err == nil {
		if err := os.Remove(previous); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove older rollback binary: %w", err)
		}
		if err := os.Rename(target, previous); err != nil {
			return fmt.Errorf("save previous binary: %w", err)
		}
		hadPrevious = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect current binary: %w", err)
	}
	if err := os.Rename(staged, target); err != nil {
		installErr := fmt.Errorf("install binary: %w", err)
		if !hadPrevious {
			return installErr
		}
		return joinInstallRollbackError(installErr, restorePreviousTarget(previous, target, targetDir, syncDir))
	}
	if err := syncDir(targetDir); err != nil {
		installErr := fmt.Errorf("sync installed binary: %w", err)
		return joinInstallRollbackError(installErr, rollbackInstalledTarget(target, hadPrevious, syncDir))
	}
	return nil
}

func restorePreviousTarget(previous, target, targetDir string, syncDir func(string) error) error {
	if err := os.Rename(previous, target); err != nil {
		return fmt.Errorf("restore previous binary: %w", err)
	}
	if err := syncDir(targetDir); err != nil {
		return fmt.Errorf("sync restored binary: %w", err)
	}
	return nil
}

func rollbackInstalledTarget(target string, hadPrevious bool, syncDir func(string) error) error {
	if hadPrevious {
		return rollback(target, syncDir)
	}
	failed := target + ".failed"
	if err := os.Remove(failed); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove older failed binary: %w", err)
	}
	if err := os.Rename(target, failed); err != nil {
		return fmt.Errorf("retain failed binary: %w", err)
	}
	if err := syncDir(filepath.Dir(target)); err != nil {
		return fmt.Errorf("sync removed installation: %w", err)
	}
	return nil
}

func joinInstallRollbackError(installErr, rollbackErr error) error {
	if rollbackErr == nil {
		return installErr
	}
	return errors.Join(
		installErr,
		ErrInstallRollbackFailed,
		fmt.Errorf("automatic install rollback: %w", rollbackErr),
	)
}

// Rollback restores target.prev and retains the failed binary as target.failed.
func Rollback(target string) error {
	return rollback(target, syncDirectory)
}

func rollback(target string, syncDir func(string) error) error {
	previous := target + ".prev"
	if _, err := os.Lstat(previous); err != nil {
		return fmt.Errorf("rollback binary is unavailable: %w", err)
	}
	failed := target + ".failed"
	if err := os.Remove(failed); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove older failed binary: %w", err)
	}
	if _, err := os.Lstat(target); err == nil {
		if err := os.Rename(target, failed); err != nil {
			return fmt.Errorf("retain failed binary: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect failed binary: %w", err)
	}
	if err := os.Rename(previous, target); err != nil {
		restoreErr := fmt.Errorf("restore previous binary: %w", err)
		if recoveryErr := os.Rename(failed, target); recoveryErr != nil {
			return errors.Join(restoreErr, fmt.Errorf("put failed binary back after rollback failure: %w", recoveryErr))
		}
		return restoreErr
	}
	if err := syncDir(filepath.Dir(target)); err != nil {
		return fmt.Errorf("sync rolled back binary: %w", err)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
