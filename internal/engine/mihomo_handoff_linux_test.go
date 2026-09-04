//go:build linux

package engine

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	identity, executable, argv, err := captureProcessExecution(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	prepared := PreparedCore{
		Engine: "mihomo", BinaryPath: binary, RuntimeConfigPath: runtimePath, HomeDir: directory,
		SourceRevision: "sha256:applied",
		Args:           args, Controller: ControllerEndpoint{BaseURL: "http://127.0.0.1:1"}, Capabilities: mihomoCapabilities,
		runtimeConfigRoot: runtimeRoot, runtimeConfigOwnedPath: runtimePath,
	}
	statePath := filepath.Join(directory, "mihomo-process.json")
	writer := NewMihomoDriver(MihomoOptions{ProcessStatePath: statePath})
	startedAt := time.Now().UTC().Add(-time.Minute)
	if err := writer.supervisor.writeProcessStateValues(cmd.Process.Pid, identity, executable, argv, startedAt, prepared); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var exact persistedProcess
	if err := json.Unmarshal(content, &exact); err != nil {
		t.Fatal(err)
	}
	if exact.Version != persistedProcessVersion || exact.Engine != mihomoEngineName || exact.Prepared.SourceRevision != "sha256:applied" || exact.Executable == "" ||
		len(exact.Argv) != 2 || exact.Argv[1] != "30" {
		t.Fatalf("process state is not exact v2: %#v", exact)
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

func TestAdoptedDriverRefusesToSignalChangedExecutionRecord(t *testing.T) {
	directory := t.TempDir()
	runtimeRoot := filepath.Join(directory, "boxctl-mihomo-stop-identity")
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
	identity, executable, argv, err := captureProcessExecution(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	prepared := PreparedCore{
		Engine: mihomoEngineName, BinaryPath: binary, RuntimeConfigPath: runtimePath, HomeDir: directory,
		Args: args, Controller: ControllerEndpoint{BaseURL: "http://127.0.0.1:1"}, Capabilities: mihomoCapabilities,
		runtimeConfigRoot: runtimeRoot, runtimeConfigOwnedPath: runtimePath,
	}
	statePath := filepath.Join(directory, "core-process.json")
	writer := NewMihomoDriver(MihomoOptions{ProcessStatePath: statePath})
	if err := writer.supervisor.writeProcessStateValues(cmd.Process.Pid, identity, executable, argv, time.Now().UTC(), prepared); err != nil {
		t.Fatal(err)
	}
	driver := NewMihomoDriver(MihomoOptions{ProcessStatePath: statePath, StopTimeout: time.Second})
	if _, _, err := driver.Adopt(context.Background()); err != nil {
		t.Fatal(err)
	}

	driver.supervisor.mu.Lock()
	recordedArgv := append([]string(nil), driver.supervisor.argv...)
	driver.supervisor.argv = []string{recordedArgv[0], "unexpected"}
	driver.supervisor.mu.Unlock()
	if err := driver.Stop(context.Background()); err == nil || !strings.Contains(err.Error(), "refusing to signal a changed process") {
		t.Fatalf("Stop() with changed record error = %v", err)
	}
	if !processExists(cmd.Process.Pid) {
		t.Fatal("changed execution record caused the live process to be signalled")
	}

	driver.supervisor.mu.Lock()
	driver.supervisor.argv = recordedArgv
	driver.supervisor.mu.Unlock()
	if err := driver.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-waited
}

func TestMihomoDriverAdoptsAndUpgradesLegacyV1State(t *testing.T) {
	directory := t.TempDir()
	runtimeRoot := filepath.Join(directory, "boxctl-mihomo-legacy")
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
	legacy := legacyMihomoProcess{
		Version: 1, PID: cmd.Process.Pid, Identity: identity,
		StartedAt: time.Now().UTC().Add(-time.Minute), LaunchArgs: args,
		Prepared: legacyMihomoPrepared{
			Engine: mihomoEngineName, BinaryPath: binary, RuntimeConfigPath: runtimePath,
			RuntimeConfigRoot: runtimeRoot, HomeDir: directory, Args: args,
			Controller: ControllerEndpoint{BaseURL: "http://127.0.0.1:1"}, Capabilities: mihomoCapabilities,
		},
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(directory, "core-process.json")
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	driver := NewMihomoDriver(MihomoOptions{ProcessStatePath: statePath, StopTimeout: time.Second})
	adopted, health, err := driver.Adopt(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if adopted.Engine != mihomoEngineName || !health.Running || health.PID != cmd.Process.Pid {
		t.Fatalf("legacy adoption = %#v, %#v", adopted, health)
	}
	upgradedContent, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var upgraded persistedProcess
	if err := json.Unmarshal(upgradedContent, &upgraded); err != nil {
		t.Fatal(err)
	}
	if upgraded.Version != persistedProcessVersion || upgraded.Engine != mihomoEngineName || upgraded.Executable == "" || len(upgraded.Argv) != 2 {
		t.Fatalf("upgraded process state = %#v", upgraded)
	}
	if err := driver.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-waited
}

func TestSingBoxDriverRejectsLegacyMihomoState(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "core-process.json")
	if err := os.WriteFile(statePath, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	driver := NewSingBoxDriver(SingBoxOptions{ProcessStatePath: statePath})
	if _, _, err := driver.Adopt(context.Background()); err == nil || !strings.Contains(err.Error(), "belongs to Mihomo") {
		t.Fatalf("Adopt() error = %v", err)
	}
}
