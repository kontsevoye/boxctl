//go:build linux

package engine

import (
	"os/exec"
	"runtime"
	"sync"
	"syscall"
)

func childProcessAttributes(surviveParent bool) *syscall.SysProcAttr {
	attributes := &syscall.SysProcAttr{Setpgid: true}
	if !surviveParent {
		attributes.Pdeathsig = syscall.SIGKILL
	}
	return attributes
}

// startChildProcess must keep the exact Linux thread which called cmd.Start
// alive: PR_SET_PDEATHSIG observes the creating thread, not merely the Go
// process. The registration gate also prevents a fast child from being reaped
// before its owner has published cmd/done/PID state.
func startChildProcess(cmd *exec.Cmd) (*startedProcess, error) {
	started := make(chan error, 1)
	registered := make(chan struct{})
	waited := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		err := cmd.Start()
		started <- err
		if err != nil {
			return
		}
		<-registered
		waited <- cmd.Wait()
	}()
	if err := <-started; err != nil {
		return nil, err
	}
	var releaseOnce sync.Once
	return newStartedProcess(
		func() { releaseOnce.Do(func() { close(registered) }) },
		func() error { return <-waited },
	), nil
}
