package rulelist

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCRUDWithRevisions(t *testing.T) {
	t.Parallel()
	store := Store{Directory: filepath.Join(t.TempDir(), "local-rules")}
	created, err := store.Put("Streaming_US", "example.com\r\n# comment\n", "")
	if err != nil {
		t.Fatal(err)
	}
	if created.Name != "streaming_us" || created.Content != "example.com\n# comment\n" || created.Revision == "" {
		t.Fatalf("unexpected item %#v", created)
	}
	if _, err := store.Put(created.Name, "changed", "wrong"); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	updated, err := store.Put(created.Name, "changed", created.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(created.Name, created.Revision); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale delete accepted: %v", err)
	}
	if err := store.Delete(created.Name, updated.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(created.Name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted list still exists: %v", err)
	}
}

func TestCreateNeverOverwrites(t *testing.T) {
	t.Parallel()
	store := Store{Directory: filepath.Join(t.TempDir(), "local-rules")}
	created, err := store.Create("local", "first")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("local", "second"); !errors.Is(err, ErrConflict) {
		t.Fatalf("second create = %v", err)
	}
	current, err := store.Get("local")
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != created.Revision || current.Content != "first\n" {
		t.Fatalf("current = %#v", current)
	}
}

func TestRejectsTraversalAndSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store := Store{Directory: filepath.Join(root, "local-rules")}
	for _, name := range []string{"../secret", "a/b", ".hidden", "bad name"} {
		if _, err := store.Put(name, "value", ""); err == nil {
			t.Fatalf("unsafe name %q accepted", name)
		}
	}
	if err := os.MkdirAll(store.Directory, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(store.Directory, "linked.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("linked"); err == nil {
		t.Fatal("symlink file was accepted")
	}
}

func TestListIsStableAndOmitsUnknownFiles(t *testing.T) {
	t.Parallel()
	store := Store{Directory: filepath.Join(t.TempDir(), "local-rules")}
	if _, err := store.Put("z-last", "z", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("a-first", "a", ""); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Directory, "README"), []byte("ignore"), 0o600); err != nil {
		t.Fatal(err)
	}
	items, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Name != "a-first" || items[1].Name != "z-last" {
		t.Fatalf("unexpected list %#v", items)
	}
}
