//go:build linux

package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestMihomoDriverAdoptsExactPersistedProcess(t *testing.T) {
	directory := t.TempDir()
	runtimeRoot := filepath.Join(directory, "boxctl-mihomo-test")
	if err := os.Mkdir(runtimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	runtimePath := filepath.Join(runtimeRoot, "mihomo-runtime.yaml")
	if err := os.WriteFile(runtimePath, []byte("mode: rule\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := "/bin/sleep"
	args := []string{"30"}
	cmd := exec.Command(binary, args...)
	cmd.SysProcAttr = childProcessAttributes(true)
	process, err := startChildProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	waited := make(chan struct{})
	go func() { _ = process.Wait(); close(waited) }()
	t.Cleanup(func() {
		_ = signalProcessGroup(cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-waited:
		case <-time.After(time.Second):
		}
	})
	identity, err := captureProcessIdentity(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	prepared := PreparedCore{
		Engine: "mihomo", BinaryPath: binary, RuntimeConfigPath: runtimePath, HomeDir: directory,
		Args: args, Controller: ControllerEndpoint{BaseURL: "http://127.0.0.1:1"}, Capabilities: mihomoCapabilities,
		runtimeConfigRoot: runtimeRoot, runtimeConfigOwnedPath: runtimePath,
	}
	statePath := filepath.Join(directory, "mihomo-process.json")
	writer := NewMihomoDriver(MihomoOptions{ProcessStatePath: statePath})
	startedAt := time.Now().UTC().Add(-time.Minute)
	if err := writer.writeProcessState(cmd.Process.Pid, identity, startedAt, args, prepared); err != nil {
		t.Fatal(err)
	}

	driver := NewMihomoDriver(MihomoOptions{ProcessStatePath: statePath, StopTimeout: time.Second})
	adopted, health, err := driver.Adopt(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.PID != cmd.Process.Pid || !health.Running || adopted.RuntimeConfigPath != runtimePath {
		t.Fatalf("adoption = %#v, %#v", adopted, health)
	}
	if err := driver.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-waited
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("process state survived stop: %v", err)
	}
	if _, err := os.Stat(runtimePath); !os.IsNotExist(err) {
		t.Fatalf("runtime survived stop: %v", err)
	}
}
