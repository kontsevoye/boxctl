package app

import (
	"fmt"
	"os"
)

// writeConfigSnapshot gives an engine an immutable-by-convention private copy
// of the exact bytes that were inspected and revisioned by the application.
// This closes the gap where an atomically replaced profile path could otherwise
// make native preparation consume different bytes than SourceRevision names.
func writeConfigSnapshot(runtimeDir, pattern string, content []byte) (string, error) {
	file, err := os.CreateTemp(runtimeDir, pattern)
	if err != nil {
		return "", fmt.Errorf("create configuration snapshot: %w", err)
	}
	path := file.Name()
	removeOnError := true
	defer func() {
		if removeOnError {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("protect configuration snapshot: %w", err)
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("write configuration snapshot: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("sync configuration snapshot: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close configuration snapshot: %w", err)
	}
	removeOnError = false
	return path, nil
}
