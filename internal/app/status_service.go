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
	Lifecycle      *Lifecycle
	Profiles       state.ProfileStore
	Control        engine.Control
	Host           *EngineHost
	Revisions      *ProfileRevisionStore
	Switcher       *ProfileSwitcher
	StartedAt      time.Time
	ManagerUpdates ManagerUpdateStatusProvider

	ReadProcessResources func(int) (processResourceSnapshot, error)
	resourcesMu          sync.Mutex
	resourceSamples      map[int]processResourcePrevious
}

type ManagerUpdateStatusProvider interface {
	ManagerUpdateStatus() web.ManagerUpdateStatus
}

func (service *StatusService) Status(ctx context.Context) (web.StatusSnapshot, error) {
	started := service.StartedAt
	if started.IsZero() {
		started = time.Now().UTC()
	}
	snapshot := service.Lifecycle.Snapshot()
	selectedEngine := state.EngineMihomo
	var activeProfile *state.ActiveProfile
	if active, err := service.Profiles.Current(); err == nil {
		selectedEngine = active.Engine
		activeProfile = &active
	} else if !errors.Is(err, fs.ErrNotExist) {
		return web.StatusSnapshot{}, err
	}
	runningEngine := snapshot.Prepared.Engine
	if service.Host != nil {
		if running := service.Host.RunningEngine(); running != "" {
			runningEngine = running
		}
	}
	coreName := runningEngine
	if coreName == "" {
		coreName = selectedEngine
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
		SelectedEngine: selectedEngine,
		RunningEngine:  runningEngine,
	}
	if service.ManagerUpdates != nil {
		managerUpdate := service.ManagerUpdates.ManagerUpdateStatus()
		result.ManagerUpdate = &managerUpdate
	}
	if service.Host != nil {
		result.RuntimeEpoch = service.Host.RuntimeEpoch()
	}
	if service.Switcher != nil {
		result.Transition = service.Switcher.CurrentPhase()
	}
	if coreState == LifecycleRunning && !snapshot.StartedAt.IsZero() {
		result.CoreUptimeSeconds = elapsedSeconds(now, snapshot.StartedAt)
	}
	if snapshot.LastError != "" {
		result.Core.LastError = "A lifecycle operation failed; see the authenticated system log"
	}
	if activeProfile != nil {
		result.ActiveProfile = &web.ProfileRef{ID: profileID(*activeProfile), Name: activeProfile.Name, Engine: activeProfile.Engine}
		if service.Revisions != nil {
			revision, pending, err := service.Revisions.Pending(*activeProfile)
			if err != nil {
				return web.StatusSnapshot{}, err
			}
			// The content digest is authoritative. This also keeps status honest
			// if a previous process died between publishing a profile and updating
			// the convenience pendingRevision field.
			if content, contentErr := service.Profiles.Get(*activeProfile); contentErr == nil {
				current := contentRevision(content)
				pending = pending || (revision.AppliedRevision != "" && revision.AppliedRevision != current)
			} else {
				return web.StatusSnapshot{}, contentErr
			}
			if pending {
				result.PendingChanges = append(result.PendingChanges, "profile_config")
			}
		}
	}
	if coreState == LifecycleRunning && runningEngine != "" && runningEngine != selectedEngine {
		result.PendingChanges = append(result.PendingChanges, "engine_selection")
	}
	result.RestartRequired = coreState == LifecycleRunning && len(result.PendingChanges) > 0
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
