package app

import (
	"context"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
)

func TestStatusServiceUsesLifecycleAndActiveProfile(t *testing.T) {
	profiles, err := state.NewProfileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	profile := state.ActiveProfile{Name: "default", Engine: state.EngineMihomo}
	if err := profiles.Create(context.Background(), profile, []byte("external-controller: 127.0.0.1:9090\n")); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Activate(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	lifecycle := &Lifecycle{}
	now := time.Now().UTC()
	lifecycle.snap = LifecycleSnapshot{
		State: LifecycleRunning, Prepared: engine.PreparedCore{Engine: "mihomo"},
		Health: engine.HealthStatus{Version: "v1.2.3"}, StartedAt: now.Add(-time.Minute),
	}
	service := &StatusService{Lifecycle: lifecycle, Profiles: profiles, StartedAt: now.Add(-time.Hour)}
	status, err := service.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Healthy || status.Core.State != "running" || status.Core.Version != "v1.2.3" || status.ActiveProfile == nil || status.ActiveProfile.ID != "mihomo:default" {
		t.Fatalf("status = %+v", status)
	}
	if status.BoxctlUptimeSeconds < 3599 || status.BoxctlUptimeSeconds > 3601 {
		t.Fatalf("boxctl uptime = %d, want about 3600", status.BoxctlUptimeSeconds)
	}
	if status.CoreUptimeSeconds < 59 || status.CoreUptimeSeconds > 61 {
		t.Fatalf("core uptime = %d, want about 60", status.CoreUptimeSeconds)
	}
}

func TestStatusServiceOmitsCoreUptimeWhileStopped(t *testing.T) {
	profiles, err := state.NewProfileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service := &StatusService{
		Lifecycle: &Lifecycle{},
		Profiles:  profiles,
		StartedAt: time.Now().UTC().Add(-time.Minute),
	}
	status, err := service.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.CoreUptimeSeconds != 0 {
		t.Fatalf("core uptime = %d while stopped", status.CoreUptimeSeconds)
	}
}
