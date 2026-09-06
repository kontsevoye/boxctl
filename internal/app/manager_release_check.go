package app

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kontsevoye/boxctl/internal/update"
	"github.com/kontsevoye/boxctl/internal/web"
)

const (
	defaultManagerReleaseCheckInterval = 6 * time.Hour
	defaultManagerReleaseCheckTimeout  = 10 * time.Second
	defaultManagerRepository           = "kontsevoye/boxctl"
)

// ManagerReleaseChecker keeps a small, secret-free snapshot of the latest
// installable boxctl release. Checks run outside HTTP requests so a slow or
// unavailable GitHub API never delays the management UI.
type ManagerReleaseChecker struct {
	CurrentVersion string
	Source         managerReleaseSource
	Interval       time.Duration
	Timeout        time.Duration
	Logger         *slog.Logger
	Now            func() time.Time

	mu     sync.RWMutex
	status web.ManagerUpdateStatus
}

func NewManagerReleaseChecker(currentVersion string, source managerReleaseSource, logger *slog.Logger) *ManagerReleaseChecker {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &ManagerReleaseChecker{
		CurrentVersion: strings.TrimSpace(currentVersion), Source: source,
		Interval: defaultManagerReleaseCheckInterval,
		Timeout:  defaultManagerReleaseCheckTimeout, Logger: logger, Now: time.Now,
		status: web.ManagerUpdateStatus{CurrentVersion: strings.TrimSpace(currentVersion)},
	}
}

func (checker *ManagerReleaseChecker) ManagerUpdateStatus() web.ManagerUpdateStatus {
	if checker == nil {
		return web.ManagerUpdateStatus{}
	}
	checker.mu.RLock()
	defer checker.mu.RUnlock()
	return checker.status
}

func (checker *ManagerReleaseChecker) Check(ctx context.Context) error {
	if checker == nil || checker.Source == nil {
		return fmt.Errorf("manager release checker is not configured")
	}
	timeout := checker.Timeout
	if timeout <= 0 {
		timeout = defaultManagerReleaseCheckTimeout
	}
	checkContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	release, err := checker.Source.Latest(checkContext, update.ChannelStable)
	checkedAt := checker.now().UTC()
	if err != nil {
		checker.recordFailure(checkedAt)
		return fmt.Errorf("discover boxctl release: %w", err)
	}
	latest, err := update.ParseBoxctlCalVerTag(release.Tag)
	if err != nil {
		checker.recordFailure(checkedAt)
		return err
	}
	if _, err := release.BoxctlLinuxARM64(); err != nil {
		checker.recordFailure(checkedAt)
		return err
	}
	available := false
	if comparison, compareErr := update.CompareBoxctlCalVer(checker.CurrentVersion, latest); compareErr == nil {
		available = comparison < 0
	}
	checker.mu.Lock()
	checkedAtCopy := checkedAt
	checker.status = web.ManagerUpdateStatus{
		CurrentVersion:  checker.CurrentVersion,
		LatestVersion:   latest,
		UpdateAvailable: available,
		ReleaseURL:      "https://github.com/" + defaultManagerRepository + "/releases/tag/" + release.Tag,
		CheckedAt:       &checkedAtCopy,
	}
	checker.mu.Unlock()
	return nil
}

func (checker *ManagerReleaseChecker) Run(ctx context.Context) {
	if checker == nil {
		return
	}
	for {
		if err := checker.Check(ctx); err != nil && ctx.Err() == nil {
			checker.logger().Warn("boxctl release check failed", "error", err)
		}
		interval := checker.Interval
		if interval <= 0 {
			interval = defaultManagerReleaseCheckInterval
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (checker *ManagerReleaseChecker) recordFailure(checkedAt time.Time) {
	checker.mu.Lock()
	checkedAtCopy := checkedAt
	checker.status.CurrentVersion = checker.CurrentVersion
	checker.status.CheckFailed = true
	checker.status.CheckedAt = &checkedAtCopy
	checker.mu.Unlock()
}

func (checker *ManagerReleaseChecker) now() time.Time {
	if checker.Now != nil {
		return checker.Now()
	}
	return time.Now()
}

func (checker *ManagerReleaseChecker) logger() *slog.Logger {
	if checker.Logger != nil {
		return checker.Logger
	}
	return slog.New(slog.DiscardHandler)
}

var _ ManagerUpdateStatusProvider = (*ManagerReleaseChecker)(nil)
