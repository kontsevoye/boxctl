package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/platform/openwrt"
	"github.com/kontsevoye/boxctl/internal/web"
)

type managerWorkerRunner struct {
	mu       sync.Mutex
	running  bool
	commands []openwrt.Command
	startErr error
}

func (runner *managerWorkerRunner) Run(_ context.Context, command openwrt.Command) (openwrt.Result, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.commands = append(runner.commands, command)
	switch command.Args[2] {
	case "list":
		data, err := json.Marshal(map[string]any{managerUpdateWorkerService: map[string]any{"instances": map[string]any{"update": map[string]bool{"running": runner.running}}}})
		return openwrt.Result{Stdout: data}, err
	case "set":
		if runner.startErr != nil {
			return openwrt.Result{}, runner.startErr
		}
		runner.running = true
		return openwrt.Result{Stdout: []byte(`{}`)}, nil
	default:
		return openwrt.Result{}, errors.New("unexpected procd method")
	}
}

func newWebUpdaterTest(t *testing.T) (*ManagerWebUpdater, *managerWorkerRunner) {
	t.Helper()
	root := t.TempDir()
	managerTestTarget(t, root, "2025.01.14")
	service := managerTestUpdateService(t, root, "2025.01.15")
	runner := &managerWorkerRunner{}
	service.Runner = runner
	checker := NewManagerReleaseChecker("2025.01.14", service.Source, nil)
	if err := checker.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &ManagerWebUpdater{Service: service, Checker: checker}, runner
}

func TestWebManagerUpdateQueuesOneIndependentWorkerAndPersistsResult(t *testing.T) {
	updater, runner := newWebUpdaterTest(t)
	ctx := context.Background()
	var jobs [2]web.ManagerUpdateJob
	var errs [2]error
	var group sync.WaitGroup
	for i := range jobs {
		group.Go(func() { jobs[i], errs[i] = updater.StartUpdate(ctx, false) })
	}
	group.Wait()
	if errs[0] != nil || errs[1] != nil || jobs[0].ID != jobs[1].ID || jobs[0].State != "queued" {
		t.Fatalf("concurrent jobs = %+v, errors = %v", jobs, errs)
	}
	starts := 0
	for _, command := range runner.commands {
		if command.Name != "ubus" {
			t.Fatalf("unexpected launcher: %+v", command)
		}
		if command.Args[2] != "set" {
			continue
		}
		starts++
		var payload struct {
			Name      string `json:"name"`
			Instances map[string]struct {
				Command []string `json:"command"`
				Respawn any      `json:"respawn"`
			} `json:"instances"`
		}
		if err := json.Unmarshal([]byte(command.Args[3]), &payload); err != nil {
			t.Fatal(err)
		}
		instance := payload.Instances["update"]
		if payload.Name != "boxctl-update" || len(instance.Command) != 5 || instance.Command[4] != jobs[0].ID || instance.Respawn != nil {
			t.Fatalf("unsafe worker payload: %s", command.Args[3])
		}
	}
	if starts != 1 {
		t.Fatalf("launched %d workers", starts)
	}
	if err := updater.RunJob(ctx, jobs[0].ID); err != nil {
		t.Fatal(err)
	}
	// A new manager instance reads the worker result after in-place exec.
	restarted := &ManagerWebUpdater{Service: updater.Service, Checker: NewManagerReleaseChecker("2025.01.15", updater.Service.Source, nil)}
	view, err := restarted.UpdateStatus(ctx, false)
	if err != nil || view.CurrentVersion != "2025.01.15" || view.Job.State != "succeeded" || view.Job.RestartMode != "manager-only" {
		t.Fatalf("restored view = %+v, job = %+v, error = %v", view, view.Job, err)
	}
	if err := updater.RunJob(ctx, jobs[0].ID); err == nil {
		t.Fatal("completed job ran twice")
	}
	info, err := os.Stat(filepath.Join(updater.Service.Store.Root, managerUpdateJobFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("job permissions: %v, %v", info, err)
	}
}

func TestWebManagerUpdateRequiresConfirmationBeforeIncompatibleSwap(t *testing.T) {
	updater, runner := newWebUpdaterTest(t)
	updater.Service.readBuildInfo = func(ctx context.Context, path string) (managerBuildInfo, error) {
		info, err := readManagerTestBuildInfo(ctx, path)
		if info.Version == "2025.01.15" {
			info.SettingsSchemaVersion++
		}
		return info, err
	}
	var modes []managerRestartMode
	updater.Service.restartAndVerify = func(_ context.Context, _, _ string, mode managerRestartMode) error {
		modes = append(modes, mode)
		return nil
	}
	ctx := context.Background()
	job, err := updater.StartUpdate(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := updater.RunJob(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	view, err := updater.UpdateStatus(ctx, false)
	if err != nil || view.Job.State != "confirmation-required" || len(modes) != 0 {
		t.Fatalf("unapproved update: %+v %v", view.Job, err)
	}
	assertManagerBinaryVersion(t, filepath.Join(updater.Service.Layout.BinDir, "boxctl"), "2025.01.14")
	runner.running = false
	job, err = updater.StartUpdate(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := updater.RunJob(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	if len(modes) != 1 || modes[0] != managerRestartFull {
		t.Fatalf("approved restart = %v", modes)
	}
}

func TestWebManagerUpdateRecordsFailureOnlyAfterRollback(t *testing.T) {
	updater, _ := newWebUpdaterTest(t)
	var modes []managerRestartMode
	updater.Service.restartAndVerify = func(_ context.Context, _, version string, mode managerRestartMode) error {
		modes = append(modes, mode)
		if version == "2025.01.15" {
			return errors.New("injected readiness failure")
		}
		return nil
	}
	job, err := updater.StartUpdate(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := updater.RunJob(context.Background(), job.ID); err == nil {
		t.Fatal("verification failure was ignored")
	}
	view, err := updater.UpdateStatus(context.Background(), false)
	if err != nil || view.Job.State != "failed" || view.Job.ErrorCode != "update_failed" {
		t.Fatalf("failed job: %+v %v", view.Job, err)
	}
	if len(modes) != 2 || modes[1] != managerRestartFull {
		t.Fatalf("rollback modes = %v", modes)
	}
	assertManagerBinaryVersion(t, filepath.Join(updater.Service.Layout.BinDir, "boxctl"), "2025.01.14")
}

func TestWebManagerUpdateDetectsInterruptedWorkerAndAllowsRetry(t *testing.T) {
	for _, phase := range []string{"queued", "running"} {
		t.Run(phase, func(t *testing.T) {
			updater, runner := newWebUpdaterTest(t)
			job, err := updater.StartUpdate(context.Background(), false)
			if err != nil {
				t.Fatal(err)
			}
			record, _ := updater.readRecord()
			record.State = phase
			if err := updater.saveRecord(record); err != nil {
				t.Fatal(err)
			}
			runner.running = false // e.g. after reboot; the job file survived.
			updater.Now = func() time.Time { return job.CreatedAt.Add(time.Minute) }
			view, err := updater.UpdateStatus(context.Background(), false)
			if err != nil || view.Job.State != "failed" || view.Job.ErrorCode != "worker_interrupted" {
				t.Fatalf("interrupted job = %+v %v", view.Job, err)
			}
			next, err := updater.StartUpdate(context.Background(), false)
			if err != nil || next.ID == job.ID {
				t.Fatalf("retry = %+v %v", next, err)
			}
			if err := updater.RunJob(context.Background(), job.ID); err == nil {
				t.Fatal("stale job accepted")
			}
		})
	}
}

func TestWebManagerUpdateStartFailureAndNoAvailableRelease(t *testing.T) {
	updater, runner := newWebUpdaterTest(t)
	runner.startErr = errors.New("procd unavailable")
	if _, err := updater.StartUpdate(context.Background(), false); err == nil {
		t.Fatal("start failure ignored")
	}
	view, err := updater.UpdateStatus(context.Background(), false)
	if err != nil || view.Job.State != "failed" || view.Job.ErrorCode != "worker_start_failed" {
		t.Fatalf("start failure: %+v %v", view.Job, err)
	}
	updater.Checker = NewManagerReleaseChecker("2025.01.15", updater.Service.Source, nil)
	if err := updater.Checker.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := updater.StartUpdate(context.Background(), false); !errors.Is(err, web.ErrConflict) {
		t.Fatalf("current version update: %v", err)
	}
}
