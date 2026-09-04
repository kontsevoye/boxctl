package app

import (
	"context"
	"errors"
	"io/fs"
	"sync"
	"time"

	"github.com/kontsevoye/boxctl/internal/buildinfo"
	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

type StatusService struct {
	Lifecycle *Lifecycle
	Profiles  state.ProfileStore
	Control   engine.Control
	StartedAt time.Time

	ReadProcessResources func(int) (processResourceSnapshot, error)
	resourcesMu          sync.Mutex
	resourceSamples      map[int]processResourcePrevious
}

func (service *StatusService) Status(ctx context.Context) (web.StatusSnapshot, error) {
	started := service.StartedAt
	if started.IsZero() {
		started = time.Now().UTC()
	}
	snapshot := service.Lifecycle.Snapshot()
	coreName := snapshot.Prepared.Engine
	if coreName == "" {
		coreName = state.EngineMihomo
	}
	coreState := snapshot.State
	if coreState == "" {
		coreState = LifecycleStopped
	}
	now := time.Now().UTC()
	result := web.StatusSnapshot{
		Healthy:             snapshot.LastError == "" && coreState != LifecycleFailed,
		Version:             buildinfo.Version,
		BoxctlUptimeSeconds: elapsedSeconds(now, started),
		Core: web.CoreHealth{
			Name: coreName, Version: snapshot.Health.Version, State: string(coreState),
			Since: snapshot.StartedAt,
		},
	}
	if coreState == LifecycleRunning && !snapshot.StartedAt.IsZero() {
		result.CoreUptimeSeconds = elapsedSeconds(now, snapshot.StartedAt)
	}
	if snapshot.LastError != "" {
		result.Core.LastError = "A lifecycle operation failed; see the authenticated system log"
	}
	if active, err := service.Profiles.Current(); err == nil {
		result.ActiveProfile = &web.ProfileRef{ID: profileID(active), Name: active.Name}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return web.StatusSnapshot{}, err
	}
	if service.Control != nil && coreState == LifecycleRunning {
		connections, err := service.Control.Connections(ctx)
		if err == nil {
			result.Traffic = &web.TrafficStats{
				UploadBytes: connections.UploadTotal, DownloadBytes: connections.DownloadTotal,
				Connections: len(connections.Connections),
			}
		}
	}
	result.Resources = service.collectResources(snapshot.Health.PID, coreState == LifecycleRunning)
	return result, nil
}

func elapsedSeconds(now, started time.Time) int64 {
	return max(0, int64(now.Sub(started).Seconds()))
}

type LifecycleService struct{ Lifecycle *Lifecycle }

func (service LifecycleService) Start(ctx context.Context) error {
	return service.Lifecycle.Start(ctx)
}
func (service LifecycleService) Stop(ctx context.Context) error {
	return service.Lifecycle.Stop(ctx)
}
func (service LifecycleService) Restart(ctx context.Context) error {
	return service.Lifecycle.Restart(ctx)
}

var _ web.StatusService = (*StatusService)(nil)
var _ web.LifecycleService = LifecycleService{}
