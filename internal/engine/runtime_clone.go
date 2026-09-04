package engine

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kontsevoye/boxctl/internal/state"
)

// ClonePreparedRuntime snapshots an immutable manager-owned runtime before a
// core is stopped. The clone has an independent 0700 root and 0600 config, so
// normal supervisor cleanup of the live generation cannot invalidate rollback.
// User source is never read: this deliberately captures the exact applied
// runtime even when the profile source has already advanced to a pending value.
func ClonePreparedRuntime(prepared PreparedCore) (cloned PreparedCore, returnErr error) {
	engineName := prepared.Engine
	if engineName == "" {
		engineName = mihomoEngineName
	}
	prefix, extension, err := runtimeFilePattern(engineName)
	if err != nil {
		return PreparedCore{}, err
	}
	if !runtimeFileOwnedBy(prepared, prefix, extension) {
		return PreparedCore{}, fmt.Errorf("clone %s runtime: config lacks private ownership", engineName)
	}
	root := filepath.Clean(prepared.runtimeConfigRoot)
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return PreparedCore{}, fmt.Errorf("clone %s runtime: inspect root: %w", engineName, err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() || rootInfo.Mode().Perm()&0o077 != 0 {
		return PreparedCore{}, fmt.Errorf("clone %s runtime: root is not a private directory", engineName)
	}

	path := filepath.Clean(prepared.RuntimeConfigPath)
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return PreparedCore{}, fmt.Errorf("clone %s runtime: inspect config: %w", engineName, err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || pathInfo.Mode().Perm()&0o077 != 0 {
		return PreparedCore{}, fmt.Errorf("clone %s runtime: config is not a private regular file", engineName)
	}
	// The private root prevents untrusted replacement, but compare the opened
	// descriptor with Lstat as a second guard against accidental path races.
	//nolint:gosec // path is exact unexported manager ownership under a verified 0700 root
	input, err := os.Open(path)
	if err != nil {
		return PreparedCore{}, fmt.Errorf("clone %s runtime: open config: %w", engineName, err)
	}
	defer input.Close()
	openedInfo, err := input.Stat()
	if err != nil {
		return PreparedCore{}, fmt.Errorf("clone %s runtime: stat open config: %w", engineName, err)
	}
	if !os.SameFile(pathInfo, openedInfo) || !openedInfo.Mode().IsRegular() {
		return PreparedCore{}, fmt.Errorf("clone %s runtime: config changed while opening", engineName)
	}
	content, err := io.ReadAll(io.LimitReader(input, maxControllerResponse+1))
	if err != nil {
		return PreparedCore{}, fmt.Errorf("clone %s runtime: read config: %w", engineName, err)
	}
	if len(content) > maxControllerResponse {
		return PreparedCore{}, fmt.Errorf("clone %s runtime: config exceeds size limit", engineName)
	}

	parent := filepath.Dir(root)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return PreparedCore{}, fmt.Errorf("clone %s runtime: inspect base: %w", engineName, err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return PreparedCore{}, fmt.Errorf("clone %s runtime: base is not a non-symlink directory", engineName)
	}
	cloneRoot, err := os.MkdirTemp(parent, "boxctl-"+engineName+"-rollback-")
	if err != nil {
		return PreparedCore{}, fmt.Errorf("clone %s runtime: create private root: %w", engineName, err)
	}
	//nolint:gosec // 0700 is intentionally required for directory traversal by the owner
	if err := os.Chmod(cloneRoot, 0o700); err != nil {
		_ = os.Remove(cloneRoot)
		return PreparedCore{}, fmt.Errorf("clone %s runtime: protect root: %w", engineName, err)
	}
	clonePath := filepath.Join(cloneRoot, filepath.Base(path))
	cloned = clonePreparedCore(prepared)
	cloned.RuntimeConfigPath = clonePath
	cloned.runtimeConfigRoot = cloneRoot
	cloned.runtimeConfigOwnedPath = clonePath
	cloned.Args, err = cloneRuntimeArgs(prepared, engineName, path, clonePath)
	if err != nil {
		CleanupPreparedRuntime(cloned)
		return PreparedCore{}, err
	}
	if err := state.WriteFileAtomic(clonePath, content, 0o600); err != nil {
		CleanupPreparedRuntime(cloned)
		return PreparedCore{}, fmt.Errorf("clone %s runtime: write snapshot: %w", engineName, err)
	}
	return cloned, nil
}

func runtimeFilePattern(engineName string) (prefix, extension string, err error) {
	switch engineName {
	case mihomoEngineName:
		return "mihomo-", ".yaml", nil
	case SingBoxEngineName:
		return "sing-box-", ".json", nil
	default:
		return "", "", fmt.Errorf("clone runtime: unsupported engine %q", engineName)
	}
}

func cloneRuntimeArgs(prepared PreparedCore, engineName, oldPath, newPath string) ([]string, error) {
	if len(prepared.Args) == 0 {
		switch engineName {
		case mihomoEngineName:
			return []string{"-d", prepared.HomeDir, "-f", newPath}, nil
		case SingBoxEngineName:
			return []string{"run", "-D", prepared.HomeDir, "-c", newPath}, nil
		}
	}
	args := append([]string(nil), prepared.Args...)
	replaced := false
	for index, argument := range args {
		if argument == oldPath {
			args[index] = newPath
			replaced = true
			continue
		}
		for _, flag := range []string{"-c=", "--config=", "-f="} {
			if argument == flag+oldPath {
				args[index] = flag + newPath
				replaced = true
				break
			}
		}
	}
	if !replaced {
		return nil, fmt.Errorf("clone %s runtime: launch arguments do not reference the owned config", engineName)
	}
	for _, argument := range args {
		if argument == oldPath || strings.HasSuffix(argument, "="+oldPath) {
			return nil, errors.New("clone runtime: old config path survived argument rewrite")
		}
	}
	return args, nil
}
