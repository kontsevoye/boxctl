package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kontsevoye/boxctl/internal/platform/openwrt"
	"github.com/kontsevoye/boxctl/internal/web"
)

const (
	managerUpdateJobFile       = ".boxctl/manager-update-job.json"
	managerUpdateJobLock       = "manager-update-job"
	managerUpdateWorkerService = "boxctl-update"
	managerUpdateStartGrace    = 10 * time.Second
)

type managerUpdateRecord struct {
	web.ManagerUpdateJob
	AllowFullRestart bool   `json:"allowFullRestart"`
	Failure          string `json:"failure,omitempty"`
}

// ManagerWebUpdater queues a one-shot service owned directly by procd. A
// goroutine would vanish on exec; a child of boxctl could be killed by procd
// during a full restart or rollback. The independent worker survives both.
type ManagerWebUpdater struct {
	Service   *managerUpdateService
	Checker   *ManagerReleaseChecker
	Now       func() time.Time
	Logger    *slog.Logger
	logMu     sync.Mutex
	loggedJob string
}

func (updater *ManagerWebUpdater) UpdateStatus(ctx context.Context, check bool) (view web.ManagerUpdateView, err error) {
	if check {
		// The snapshot records a failed discovery without losing the installed
		// version or hiding the result of an earlier install.
		_ = updater.Checker.Check(ctx)
	}
	view.ManagerUpdateStatus = updater.Checker.ManagerUpdateStatus()
	err = updater.Service.Store.WithLock(ctx, managerUpdateJobLock, func() error {
		record, err := updater.readRecord()
		if err != nil || record == nil {
			return err
		}
		if err := updater.reconcile(ctx, record); err != nil {
			return err
		}
		view.Job = &record.ManagerUpdateJob
		updater.logFailure(record)
		return nil
	})
	return view, err
}

func (updater *ManagerWebUpdater) StartUpdate(ctx context.Context, allowFullRestart bool) (job web.ManagerUpdateJob, err error) {
	err = updater.Service.Store.WithLock(ctx, managerUpdateJobLock, func() error {
		record, err := updater.readRecord()
		if err != nil {
			return err
		}
		if record != nil {
			if err := updater.reconcile(ctx, record); err != nil {
				return err
			}
			if managerJobActive(record.State) {
				job = record.ManagerUpdateJob
				return nil // Repeated clicks share the same job.
			}
		}
		// Do not replace an instance that is still finishing a prior job.
		running, err := updater.workerRunning(ctx)
		if err != nil {
			return err
		}
		if running || !updater.Checker.ManagerUpdateStatus().UpdateAvailable {
			return web.ErrConflict
		}
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			return err
		}
		now := updater.now()
		record = &managerUpdateRecord{
			ManagerUpdateJob: web.ManagerUpdateJob{ID: hex.EncodeToString(id), State: "queued", CreatedAt: now, UpdatedAt: now},
			AllowFullRestart: allowFullRestart,
		}
		if err := updater.saveRecord(record); err != nil {
			return err
		}
		// A separate service needs no installed init-script changes. There is
		// deliberately no respawn: rebooting must never retry an update.
		payload := struct {
			Name      string         `json:"name"`
			Instances map[string]any `json:"instances"`
		}{managerUpdateWorkerService, map[string]any{"update": map[string]any{
			"command": []string{filepath.Join(updater.Service.Layout.BinDir, "boxctl"), "self-update", "worker", "--job-id", record.ID},
			"stdout":  true, "stderr": true,
		}}}
		if _, err := updater.procd(ctx, "set", payload); err != nil {
			record.State, record.ErrorCode = "failed", "worker_start_failed"
			record.Failure = err.Error()
			return errors.Join(err, updater.saveRecord(record))
		}
		job = record.ManagerUpdateJob
		return nil
	})
	return job, err
}

// RunJob only accepts the queued private record with this exact random ID.
// Install retains its own cross-process self-update lock and rollback logic.
func (updater *ManagerWebUpdater) RunJob(ctx context.Context, id string) error {
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != 16 {
		return errors.New("invalid manager update job ID")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var record *managerUpdateRecord
	err = updater.Service.Store.WithLock(ctx, managerUpdateJobLock, func() error {
		var err error
		record, err = updater.readRecord()
		if err != nil {
			return err
		}
		if record == nil || record.ID != id || record.State != "queued" {
			return errors.New("manager update job is not queued")
		}
		record.State = "running"
		return updater.saveRecord(record)
	})
	if err != nil {
		return err
	}
	confirmationRequired := false
	result, installErr := updater.Service.Install(ctx, "", "", false, false, func(string) (bool, error) {
		confirmationRequired = !record.AllowFullRestart
		return record.AllowFullRestart, nil
	})
	// Save after the install transaction, even when its discovery context
	// expired. A new HTTP process will read this same atomic state file.
	finishContext, cancelFinish := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFinish()
	finishErr := updater.Service.Store.WithLock(finishContext, managerUpdateJobLock, func() error {
		current, err := updater.readRecord()
		if err != nil {
			return err
		}
		if current == nil || current.ID != id {
			return errors.New("manager update job changed while running")
		}
		switch {
		case confirmationRequired:
			record.State = "confirmation-required"
		case installErr != nil:
			record.State, record.ErrorCode = "failed", "update_failed"
			record.Failure = installErr.Error()
		default:
			record.State = "succeeded"
			record.CurrentVersion = result.CurrentVersion
			record.RestartMode = string(result.RestartMode)
		}
		return updater.saveRecord(record)
	})
	if confirmationRequired {
		return finishErr
	}
	return errors.Join(installErr, finishErr)
}

func managerJobActive(state string) bool { return state == "queued" || state == "running" }

// Called under the job lock, including after a router reboot. Never infer
// success from the on-disk version: only the worker can verify and finish it.
func (updater *ManagerWebUpdater) reconcile(ctx context.Context, record *managerUpdateRecord) error {
	if !managerJobActive(record.State) {
		return nil
	}
	running, err := updater.workerRunning(ctx)
	if err != nil {
		return err
	}
	age := updater.now().Sub(record.CreatedAt)
	if running || (record.State == "queued" && age >= 0 && age < managerUpdateStartGrace) {
		return nil
	}
	record.State, record.ErrorCode = "failed", "worker_interrupted"
	record.Failure = "manager update worker exited before recording a verified result"
	return updater.saveRecord(record)
}

func (updater *ManagerWebUpdater) workerRunning(ctx context.Context) (bool, error) {
	output, err := updater.procd(ctx, "list", map[string]string{"name": managerUpdateWorkerService})
	if err != nil {
		return false, err
	}
	var services map[string]struct {
		Instances map[string]struct {
			Running bool `json:"running"`
		} `json:"instances"`
	}
	if err := json.Unmarshal(output, &services); err != nil {
		return false, fmt.Errorf("decode manager update worker status: %w", err)
	}
	for _, instance := range services[managerUpdateWorkerService].Instances {
		if instance.Running {
			return true, nil
		}
	}
	return false, nil
}

func (updater *ManagerWebUpdater) procd(ctx context.Context, method string, payload any) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result, err := updater.Service.Runner.Run(ctx, openwrt.Command{Name: "ubus", Args: []string{"call", "service", method, string(data)}})
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("manager update procd %s exited with %d", method, result.ExitCode)
	}
	return result.Stdout, nil
}

func (updater *ManagerWebUpdater) readRecord() (*managerUpdateRecord, error) {
	data, err := updater.Service.Store.Read(managerUpdateJobFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var record managerUpdateRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func (updater *ManagerWebUpdater) saveRecord(record *managerUpdateRecord) error {
	record.UpdatedAt = updater.now()
	return updater.Service.Store.WriteJSON(managerUpdateJobFile, record, 0o600)
}

func (updater *ManagerWebUpdater) now() time.Time {
	if updater.Now != nil {
		return updater.Now().UTC()
	}
	return time.Now().UTC()
}

// The worker's stderr is in logread. Replay a failure once into the new
// manager's redacted ring as well, so it is reachable from the GUI system log.
func (updater *ManagerWebUpdater) logFailure(record *managerUpdateRecord) {
	if updater.Logger == nil || record.State != "failed" || record.Failure == "" {
		return
	}
	updater.logMu.Lock()
	defer updater.logMu.Unlock()
	if updater.loggedJob == record.ID {
		return
	}
	updater.Logger.Error("boxctl update failed", "job", record.ID, "error", record.Failure)
	updater.loggedJob = record.ID
}

var _ web.ManagerUpdateService = (*ManagerWebUpdater)(nil)
