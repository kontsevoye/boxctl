//go:build linux

package engine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func captureProcessIdentity(pid int) (string, error) {
	if pid <= 1 {
		return "", fmt.Errorf("unsafe process id %d", pid)
	}
	content, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	closing := strings.LastIndexByte(string(content), ')')
	if closing < 0 {
		return "", errors.New("invalid process stat")
	}
	fields := strings.Fields(string(content[closing+1:]))
	// The suffix starts at field 3; Linux starttime is field 22.
	if len(fields) <= 19 {
		return "", errors.New("process stat lacks start time")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", errors.New("invalid process start time")
	}
	return fields[19], nil
}

// captureProcessExecution returns the kernel-observed executable and complete
// argv together with the start-time identity. Persisting observed values (not
// reconstructed command options) makes manager handoff resistant to PID reuse,
// symlink retargeting and argv substitution.
func captureProcessExecution(pid int) (identity, executable string, argv []string, returnErr error) {
	identity, returnErr = captureProcessIdentity(pid)
	if returnErr != nil {
		return
	}
	executable, returnErr = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if returnErr != nil {
		returnErr = fmt.Errorf("read process executable: %w", returnErr)
		return
	}
	content, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return identity, executable, nil, fmt.Errorf("read process command line: %w", err)
	}
	if len(content) == 0 || content[len(content)-1] != 0 {
		return identity, executable, nil, errors.New("process command line is incomplete")
	}
	parts := strings.Split(string(content[:len(content)-1]), "\x00")
	if len(parts) == 0 || parts[0] == "" {
		return identity, executable, nil, errors.New("process command line is empty")
	}
	return identity, executable, parts, nil
}

func validatePersistedProcessExecution(pid int, identity, executable string, argv []string, binary string) error {
	actualIdentity, actualExecutable, actualArgv, err := captureProcessExecution(pid)
	if err != nil {
		return fmt.Errorf("inspect persisted process: %w", err)
	}
	if actualIdentity != identity {
		return errors.New("persisted process identity changed")
	}
	group, err := syscall.Getpgid(pid)
	if err != nil || group != pid {
		return errors.New("persisted process no longer owns its process group")
	}
	wantExecutable, err := filepath.EvalSymlinks(binary)
	if err != nil {
		return fmt.Errorf("resolve configured engine executable: %w", err)
	}
	if filepath.Clean(actualExecutable) != filepath.Clean(executable) || filepath.Clean(actualExecutable) != filepath.Clean(wantExecutable) {
		return fmt.Errorf("persisted process executable changed: got %s, recorded %s, configured %s", actualExecutable, executable, wantExecutable)
	}
	if len(actualArgv) != len(argv) {
		return errors.New("persisted process command line changed")
	}
	for index := range argv {
		if actualArgv[index] != argv[index] {
			return errors.New("persisted process command line changed")
		}
	}
	return nil
}

func validatePersistedProcess(pid int, identity, binary string, args []string) error {
	actualIdentity, err := captureProcessIdentity(pid)
	if err != nil {
		return fmt.Errorf("inspect Mihomo process: %w", err)
	}
	if actualIdentity != identity {
		return errors.New("mihomo process identity changed")
	}
	group, err := syscall.Getpgid(pid)
	if err != nil || group != pid {
		return errors.New("mihomo no longer owns its process group")
	}
	executable, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return fmt.Errorf("read Mihomo executable: %w", err)
	}
	wantExecutable, err := filepath.EvalSymlinks(binary)
	if err != nil {
		return fmt.Errorf("resolve configured Mihomo executable: %w", err)
	}
	if filepath.Clean(executable) != filepath.Clean(wantExecutable) {
		return fmt.Errorf("mihomo executable changed: got %s, want %s", executable, wantExecutable)
	}
	content, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return fmt.Errorf("read Mihomo command line: %w", err)
	}
	parts := strings.Split(strings.TrimSuffix(string(content), "\x00"), "\x00")
	if len(parts) != len(args)+1 {
		return errors.New("mihomo command line changed")
	}
	for index, arg := range args {
		if parts[index+1] != arg {
			return errors.New("mihomo command line changed")
		}
	}
	return nil
}

func persistedProcessAlive(pid int, identity string) bool {
	actual, err := captureProcessIdentity(pid)
	return err == nil && actual == identity
}

func waitAdoptedChild(pid int) (bool, error) {
	for {
		var status syscall.WaitStatus
		waited, err := syscall.Wait4(pid, &status, 0, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.ECHILD) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return waited == pid, nil
	}
}
