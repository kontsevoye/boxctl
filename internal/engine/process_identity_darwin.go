//go:build darwin

package engine

import "errors"

func captureProcessIdentity(int) (string, error) {
	return "", errors.New("persistent Mihomo handoff is supported only on Linux")
}

func validatePersistedProcess(int, string, string, []string) error {
	return errors.New("persistent Mihomo handoff is supported only on Linux")
}

func persistedProcessAlive(int, string) bool { return false }

func waitAdoptedChild(int) (bool, error) { return false, nil }
