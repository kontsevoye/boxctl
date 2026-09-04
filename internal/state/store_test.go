package state

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func newTestStore(t *testing.T) Store {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestStoreAtomicWriteAndPermissions(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	if err := store.Write("nested/state", []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Write("nested/state", []byte("second"), 0o640); err != nil {
		t.Fatal(err)
	}
	data, err := store.Read("nested/state")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "second" {
		t.Fatalf("data = %q", data)
	}
	info, err := os.Stat(filepath.Join(store.Root, "nested/state"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	matches, err := filepath.Glob(filepath.Join(store.Root, "nested/.boxctl-state-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files = %v, %v", matches, err)
	}
}

func TestStoreRejectsTraversalAndSymlinks(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	for _, name := range []string{"../outside", "/absolute", ""} {
		if err := store.Write(name, []byte("x"), 0o600); err == nil {
			t.Errorf("Write(%q) succeeded", name)
		}
	}
	if runtime.GOOS == "windows" {
		return
	}
	target := filepath.Join(store.Root, "target")
	if err := os.WriteFile(target, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(store.Root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read("link"); err == nil {
		t.Fatal("symlink read succeeded")
	}
	if err := store.Write("link", []byte("unsafe"), 0o600); err == nil {
		t.Fatal("symlink replacement succeeded")
	}
	if err := os.Mkdir(filepath.Join(store.Root, "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(store.Root, "real"), filepath.Join(store.Root, "linked-dir")); err != nil {
		t.Fatal(err)
	}
	if err := store.Write("linked-dir/value", []byte("unsafe"), 0o600); err == nil {
		t.Fatal("write through symlinked parent succeeded")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "safe" {
		t.Fatalf("target changed: %q, %v", data, err)
	}
}

func TestStoreLockHonorsContext(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	lock, err := store.Lock(context.Background(), "profiles")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Unlock() }()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err = store.Lock(ctx, "profiles")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock error = %v", err)
	}
}

func TestStoreLockRejectsSymlinkFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic-link locking is Unix-specific")
	}
	store := newTestStore(t)
	lockDir := filepath.Join(store.Root, "locks")
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(store.Root, "foreign")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(lockDir, "gateway.lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Lock(context.Background(), "gateway"); err == nil {
		t.Fatal("symlink lock file was accepted")
	}
}

func TestStoreJSON(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	if err := store.WriteJSON("value.json", map[string]int{"answer": 42}, fs.FileMode(0o600)); err != nil {
		t.Fatal(err)
	}
	data, err := store.Read("value.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{\n  \"answer\": 42\n}\n" {
		t.Fatalf("JSON = %q", data)
	}
}
