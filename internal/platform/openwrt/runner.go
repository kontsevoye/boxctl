package openwrt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
)

// Command is a single, non-shell command. Stdin is passed verbatim to the
// process; callers must never interpolate plan values into a shell command.
type Command struct {
	Name  string
	Args  []string
	Stdin []byte
}

// Result is returned for both zero and non-zero process exits. Runner errors
// are reserved for failures to start or wait for the process.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runner makes every OpenWrt command injectable. Production code should use
// ExecRunner; tests should provide a recording fake.
type Runner interface {
	Run(context.Context, Command) (Result, error)
}

// ExecRunner executes commands directly, without a shell.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, command Command) (Result, error) {
	if command.Name == "" {
		return Result{}, errors.New("openwrt: empty command name")
	}

	cmd := exec.CommandContext(ctx, command.Name, command.Args...)
	cmd.Stdin = bytes.NewReader(command.Stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if err == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}
	return Result{}, fmt.Errorf("openwrt: run %s: %w", command.Name, err)
}

func runOK(ctx context.Context, runner Runner, command Command) (Result, error) {
	if runner == nil {
		return Result{}, errors.New("openwrt: nil runner")
	}
	result, err := runner.Run(ctx, command)
	if err != nil {
		return Result{}, err
	}
	if result.ExitCode != 0 {
		return result, fmt.Errorf("openwrt: %s exited with %d: %s", command.Name, result.ExitCode, bytes.TrimSpace(result.Stderr))
	}
	return result, nil
}
