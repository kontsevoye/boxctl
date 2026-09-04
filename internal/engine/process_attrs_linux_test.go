//go:build linux

package engine

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestStartChildProcessDefersReapUntilOwnerWait(t *testing.T) {
	t.Parallel()
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	cmd.SysProcAttr = childProcessAttributes(false)
	process, err := startChildProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = process.Wait()
		}
	}()

	statusPath := fmt.Sprintf("/proc/%d/stat", cmd.Process.Pid)
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, readErr := os.ReadFile(statusPath)
		if readErr == nil && procState(data) == "Z" {
			break
		}
		if errors.Is(readErr, os.ErrNotExist) {
			t.Fatal("child was reaped before its owner called Wait")
		}
		if readErr != nil {
			t.Fatalf("read child process state: %v", readErr)
		}
		if time.Now().After(deadline) {
			t.Fatalf("child did not reach zombie state before Wait: %q", procState(data))
		}
		time.Sleep(5 * time.Millisecond)
	}

	if err := process.Wait(); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	waited = true
}

func procState(stat []byte) string {
	closing := strings.LastIndexByte(string(stat), ')')
	if closing < 0 || closing+1 >= len(stat) {
		return ""
	}
	fields := strings.Fields(string(stat[closing+1:]))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
