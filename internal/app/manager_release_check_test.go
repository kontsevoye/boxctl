package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/update"
)

type managerReleaseSourceStub struct {
	mu      sync.Mutex
	release update.Release
	err     error
	calls   int
}

func (source *managerReleaseSourceStub) Latest(context.Context, update.Channel) (update.Release, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.calls++
	return source.release, source.err
}

func (source *managerReleaseSourceStub) Calls() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.calls
}

func TestManagerReleaseCheckerPublishesInstallableUpdate(t *testing.T) {
	checkedAt := time.Date(2026, 9, 6, 9, 30, 0, 0, time.UTC)
	source := &managerReleaseSourceStub{release: managerReleaseFixture("v2026.09.4")}
	checker := NewManagerReleaseChecker("2026.09.3", source, nil)
	checker.Now = func() time.Time { return checkedAt }
	if err := checker.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := checker.ManagerUpdateStatus()
	if status.CurrentVersion != "2026.09.3" || status.LatestVersion != "2026.09.4" || !status.UpdateAvailable ||
		status.CheckFailed || status.ReleaseURL != "https://github.com/kontsevoye/boxctl/releases/tag/v2026.09.4" || status.CheckedAt == nil || !status.CheckedAt.Equal(checkedAt) {
		t.Fatalf("status = %+v", status)
	}
}

func TestManagerReleaseCheckerDoesNotFlagDevelopmentOrNewerBuild(t *testing.T) {
	for _, current := range []string{"dev", "live-abcdef", "2026.09.5"} {
		checker := NewManagerReleaseChecker(current, &managerReleaseSourceStub{release: managerReleaseFixture("v2026.09.4")}, nil)
		if err := checker.Check(context.Background()); err != nil {
			t.Fatalf("current %q: %v", current, err)
		}
		if checker.ManagerUpdateStatus().UpdateAvailable {
			t.Fatalf("current %q was reported as outdated", current)
		}
	}
}

func TestManagerReleaseCheckerPreservesLastSuccessOnFailure(t *testing.T) {
	source := &managerReleaseSourceStub{release: managerReleaseFixture("v2026.09.4")}
	checker := NewManagerReleaseChecker("2026.09.3", source, nil)
	if err := checker.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	source.mu.Lock()
	source.err = errors.New("offline")
	source.mu.Unlock()
	if err := checker.Check(context.Background()); err == nil {
		t.Fatal("failed release check unexpectedly succeeded")
	}
	status := checker.ManagerUpdateStatus()
	if status.LatestVersion != "2026.09.4" || !status.UpdateAvailable || !status.CheckFailed {
		t.Fatalf("status after failure = %+v", status)
	}
}

func TestManagerReleaseCheckerRunsImmediatelyAndPeriodically(t *testing.T) {
	source := &managerReleaseSourceStub{release: managerReleaseFixture("v2026.09.4")}
	checker := NewManagerReleaseChecker("2026.09.3", source, nil)
	checker.Interval = 5 * time.Millisecond
	context, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		checker.Run(context)
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for source.Calls() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("release checker did not stop")
	}
	if source.Calls() < 2 {
		t.Fatalf("release checks = %d, want at least 2", source.Calls())
	}
}

func managerReleaseFixture(tag string) update.Release {
	version := tag[1:]
	return update.Release{Tag: tag, Assets: []update.Asset{{
		Name:   "boxctl-linux-arm64-" + version,
		URL:    "https://github.com/kontsevoye/boxctl/releases/download/" + tag + "/boxctl-linux-arm64-" + version,
		Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Size:   1024,
	}}}
}
