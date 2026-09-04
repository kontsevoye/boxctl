//go:build linux

package engine

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSingBoxDriverAdoptsExactEngineQualifiedV2Process(t *testing.T) {
	directory := t.TempDir()
	runtimeRoot := filepath.Join(directory, "boxctl-sing-box-test")
	if err := os.Mkdir(runtimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	runtimePath := filepath.Join(runtimeRoot, "sing-box-runtime.json")
	if err := os.WriteFile(runtimePath, []byte("{}\n"), 0o600); err != nil {
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
		Engine: SingBoxEngineName, BinaryPath: binary,
		RuntimeConfigPath: runtimePath, HomeDir: directory, Args: args,
		Controller: ControllerEndpoint{BaseURL: "http://127.0.0.1:1"}, Capabilities: singBoxCapabilities,
		runtimeConfigRoot: runtimeRoot, runtimeConfigOwnedPath: runtimePath,
	}
	statePath := filepath.Join(directory, "core-process.json")
	writer := NewSingBoxDriver(SingBoxOptions{ProcessStatePath: statePath})
	startedAt := time.Now().UTC().Add(-time.Minute)
	if err := writer.supervisor.writeProcessStateValues(cmd.Process.Pid, identity, executable, argv, startedAt, prepared); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var recorded persistedProcess
	if err := json.Unmarshal(content, &recorded); err != nil {
		t.Fatal(err)
	}
	if recorded.Version != persistedProcessVersion || recorded.Engine != SingBoxEngineName || recorded.Executable != executable ||
		len(recorded.Argv) != len(argv) || recorded.Argv[0] != argv[0] {
		t.Fatalf("persisted state = %#v", recorded)
	}

	driver := NewSingBoxDriver(SingBoxOptions{ProcessStatePath: statePath, StopTimeout: time.Second})
	adopted, health, err := driver.Adopt(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if adopted.Engine != SingBoxEngineName || adopted.RuntimeConfigPath != runtimePath || !health.Running || health.PID != cmd.Process.Pid {
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
