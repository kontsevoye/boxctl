package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagerExecutablePathRequiresRegularExecutable(t *testing.T) {
	original := os.Args
	defer func() { os.Args = original }()
	directory := t.TempDir()
	binary := filepath.Join(directory, "boxctl")
	if err := os.WriteFile(binary, []byte("test"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{binary}
	if actual, err := managerExecutablePath(); err != nil || actual != binary {
		t.Fatalf("managerExecutablePath() = %q, %v", actual, err)
	}
	symlink := filepath.Join(directory, "boxctl-link")
	if err := os.Symlink(binary, symlink); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{symlink}
	if _, err := managerExecutablePath(); err == nil {
		t.Fatal("managerExecutablePath accepted a symlink")
	}
}
