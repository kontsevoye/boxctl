//go:build darwin

package engine

import "errors"

func captureProcessExecution(int) (string, string, []string, error) {
	return "", "", nil, errors.New("persistent engine handoff is supported only on Linux")
}

func validatePersistedProcessExecution(int, string, string, []string, string) error {
	return errors.New("persistent engine handoff is supported only on Linux")
}

func validatePersistedProcess(int, string, string, []string) error {
	return errors.New("persistent Mihomo handoff is supported only on Linux")
}

func persistedProcessAlive(int, string) bool { return false }

func waitAdoptedChild(int) (bool, error) { return false, nil }
