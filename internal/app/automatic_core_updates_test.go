package app

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

type automaticUpdateFake struct {
	mu    sync.Mutex
	calls int
}

func (fake *automaticUpdateFake) InstallCoreUpdate(context.Context) (web.CoreUpdateResult, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.calls++
	return web.CoreUpdateResult{PreviousVersion: "v1", CurrentVersion: "v2"}, nil
}

func (fake *automaticUpdateFake) count() int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.calls
}

func TestAutomaticCoreUpdatesHonorsSetting(t *testing.T) {
	store, err := state.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fake := &automaticUpdateFake{}
	service := NewAutomaticCoreUpdates(store, fake, nil)
	if err := service.runOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.count() != 0 {
		t.Fatal("automatic update ran while disabled")
	}
	if err := store.SaveSettings(settingsRelativePath, state.Settings{"AUTO_UPDATE": "true"}); err != nil {
		t.Fatal(err)
	}
	if err := service.runOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.count() != 1 {
		t.Fatalf("update calls = %d", fake.count())
	}
}

func TestAutomaticCoreUpdatesReloadWakesScheduler(t *testing.T) {
	store, err := state.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSettings(settingsRelativePath, state.Settings{"AUTO_UPDATE": "true"}); err != nil {
		t.Fatal(err)
	}
	fake := &automaticUpdateFake{}
	service := NewAutomaticCoreUpdates(store, fake, nil)
	service.Interval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); service.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for fake.count() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	service.Reload()
	for fake.count() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if fake.count() != 2 {
		t.Fatalf("update calls = %d", fake.count())
	}
}

func TestStopAutomaticUpdateTimerDoesNotBlockAfterAlreadyStopped(t *testing.T) {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		t.Fatal("fresh timer was already stopped")
	}
	done := make(chan struct{})
	go func() {
		stopAutomaticUpdateTimer(timer)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stopping an already stopped timer blocked")
	}
}
