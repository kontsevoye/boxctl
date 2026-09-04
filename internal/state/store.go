package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type Store struct {
	Root string
}

func NewStore(root string) (Store, error) {
	if root == "" {
		return Store{}, errors.New("state: empty root")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return Store{}, fmt.Errorf("state: resolve root: %w", err)
	}
	return Store{Root: filepath.Clean(absolute)}, nil
}

func (store Store) path(name string) (string, error) {
	if name == "" || filepath.IsAbs(name) {
		return "", fmt.Errorf("state: invalid relative name %q", name)
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("state: path escapes root: %q", name)
	}
	path := filepath.Join(store.Root, clean)
	relative, err := filepath.Rel(store.Root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("state: path escapes root: %q", name)
	}
	return path, nil
}

func (store Store) Read(name string) ([]byte, error) {
	path, err := store.path(name)
	if err != nil {
		return nil, err
	}
	if err := store.checkParents(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("state: refusing non-regular file %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("state: read %s: %w", path, err)
	}
	return data, nil
}

func (store Store) Write(name string, data []byte, permission fs.FileMode) error {
	path, err := store.path(name)
	if err != nil {
		return err
	}
	if err := store.checkParents(path); err != nil {
		return err
	}
	return WriteFileAtomic(path, data, permission)
}

func (store Store) checkParents(target string) error {
	return store.checkDirectory(filepath.Dir(target))
}

func (store Store) checkDirectory(directory string) error {
	relative, err := filepath.Rel(store.Root, directory)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("state: directory escapes root: %s", directory)
	}
	current := store.Root
	components := []string{current}
	if relative != "." {
		for _, component := range strings.Split(relative, string(filepath.Separator)) {
			current = filepath.Join(current, component)
			components = append(components, current)
		}
	}
	for _, component := range components {
		info, err := os.Lstat(component)
		if errors.Is(err, fs.ErrNotExist) {
			// Once a component is absent, none of its children can currently be
			// symlinks. The atomic writer creates the missing remainder.
			return nil
		}
		if err != nil {
			return fmt.Errorf("state: inspect directory %s: %w", component, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("state: refusing non-directory path component %s", component)
		}
	}
	return nil
}

func (store Store) WriteJSON(name string, value any, permission fs.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("state: encode JSON: %w", err)
	}
	data = append(data, '\n')
	return store.Write(name, data, permission)
}

// RemoveRegular atomically unlinks one regular file below the store root and
// fsyncs its directory. Missing files are accepted; symlinks and other file
// types are rejected instead of being followed or silently removed.
func (store Store) RemoveRegular(name string) error {
	path, err := store.path(name)
	if err != nil {
		return err
	}
	if err := store.checkParents(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("state: inspect removal target: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("state: refusing to remove non-regular file %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("state: remove %s: %w", path, err)
	}
	return syncDirectory(filepath.Dir(path))
}

// WriteFileAtomic writes and fsyncs a same-directory temporary file before an
// atomic rename. Existing symlink targets are rejected.
func WriteFileAtomic(path string, data []byte, permission fs.FileMode) (returnErr error) {
	if permission.Perm() == 0 || permission&^fs.ModePerm != 0 {
		return fmt.Errorf("state: invalid file mode %v", permission)
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("state: create directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("state: refusing to replace non-regular file %s", path)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("state: inspect target: %w", err)
	}

	temporary, err := os.CreateTemp(directory, ".boxctl-state-*")
	if err != nil {
		return fmt.Errorf("state: create temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	closed := false
	defer func() {
		var closeErr error
		if !closed {
			closeErr = temporary.Close()
		}
		removeErr := os.Remove(temporaryName)
		if returnErr == nil && closeErr != nil {
			returnErr = closeErr
		}
		if returnErr == nil && removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			returnErr = removeErr
		}
	}()

	if err := temporary.Chmod(permission.Perm()); err != nil {
		return fmt.Errorf("state: chmod temporary file: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("state: write temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("state: fsync temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("state: close temporary file: %w", err)
	}
	closed = true
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("state: atomic rename: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("state: open directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return fmt.Errorf("state: fsync directory: %w", err)
	}
	return nil
}

type Lock struct {
	file *os.File
}

func (lock *Lock) Unlock() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	return errors.Join(unlockErr, closeErr)
}

// Lock acquires an advisory exclusive lock. It polls so context cancellation
// remains effective on both Linux/OpenWrt and macOS tests.
func (store Store) Lock(ctx context.Context, name string) (*Lock, error) {
	path, err := store.path(filepath.Join("locks", name+".lock"))
	if err != nil {
		return nil, err
	}
	if err := store.checkParents(path); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("state: create lock directory: %w", err)
	}
	if info, inspectErr := os.Lstat(path); inspectErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("state: refusing non-regular lock file %s", path)
		}
	} else if !errors.Is(inspectErr, fs.ErrNotExist) {
		return nil, fmt.Errorf("state: inspect lock: %w", inspectErr)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("state: open lock: %w", err)
	}
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &Lock{file: file}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("state: acquire lock: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (store Store) WithLock(ctx context.Context, name string, callback func() error) error {
	lock, err := store.Lock(ctx, name)
	if err != nil {
		return err
	}
	callbackErr := callback()
	return errors.Join(callbackErr, lock.Unlock())
}
