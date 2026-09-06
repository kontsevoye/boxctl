//go:build linux

package engine

import (
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func TestCaptureProcessExecutionImmediatelyAfterExec(t *testing.T) {
	executable, err := filepath.EvalSymlinks("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	// Repeated immediate reads cover the short exec window where Linux has
	// published /proc/<pid>/exe but has not yet populated its command line.
	for attempt := range 64 {
		cmd := exec.Command("/bin/sleep", "30")
		cmd.SysProcAttr = childProcessAttributes(true)
		process, err := startChildProcess(cmd)
		if err != nil {
			t.Fatal(err)
		}
		identity, observed, argv, captureErr := captureProcessExecution(cmd.Process.Pid)
		_ = cmd.Process.Kill()
		_ = process.Wait()
		if captureErr != nil || identity == "" || observed != executable || !slices.Equal(argv, []string{"/bin/sleep", "30"}) {
			t.Fatalf("capture %d: identity=%q executable=%q argv=%q err=%v", attempt, identity, observed, argv, captureErr)
		}
	}
}
