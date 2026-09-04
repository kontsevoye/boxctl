package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/kontsevoye/boxctl/internal/app"
	"github.com/kontsevoye/boxctl/internal/cli"
)

func main() {
	ctx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	stopReexec := installReexecHandler()
	defer stopReexec()

	actions := app.NewActions(app.ActionOptions{
		Out: os.Stdout,
		Err: os.Stderr,
	})
	err := cli.Execute(ctx, os.Args[1:], cli.Streams{In: os.Stdin, Out: os.Stdout, Err: os.Stderr}, actions)
	if err == nil {
		return
	}
	_, _ = fmt.Fprintln(os.Stderr, "boxctl:", err)
	if cli.IsUsage(err) {
		os.Exit(2)
	}
	os.Exit(1)
}

func installReexecHandler() func() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR2)
	go func() {
		for range signals {
			path, err := managerExecutablePath()
			if err == nil {
				err = syscall.Exec(path, os.Args, os.Environ())
			}
			_, _ = fmt.Fprintln(os.Stderr, "boxctl: manager re-exec failed:", err)
		}
	}()
	return func() { signal.Stop(signals) }
}

func managerExecutablePath() (string, error) {
	path := os.Args[0]
	if !filepath.IsAbs(path) {
		resolved, err := exec.LookPath(path)
		if err != nil {
			return "", err
		}
		path = resolved
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return "", fmt.Errorf("manager executable is not an executable regular file: %s", path)
	}
	return filepath.Clean(path), nil
}
