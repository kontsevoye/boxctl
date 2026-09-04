//go:build darwin

package engine

import (
	"os/exec"
	"syscall"
)

func childProcessAttributes(bool) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

func startChildProcess(cmd *exec.Cmd) (*startedProcess, error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return newStartedProcess(nil, cmd.Wait), nil
}
