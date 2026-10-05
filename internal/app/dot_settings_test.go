package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/platform/openwrt"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

func TestDecodeDoTSettings(t *testing.T) {
	t.Parallel()
	if DefaultRuntimeSettings().BlockDoT {
		t.Fatal("DoT blocking must be opt-in")
	}
	for _, mode := range []string{"upstream", "redirect"} {
		raw := state.Settings{"BLOCK_DOT": "true", "ENABLE_DNS_UPSTREAM": "false", "ENABLE_DNS_REDIRECT": "false"}
		if mode == "upstream" {
			raw["ENABLE_DNS_UPSTREAM"] = "true"
		} else {
			raw["ENABLE_DNS_REDIRECT"] = "true"
		}
		settings, err := DecodeRuntimeSettings(raw)
		if err != nil || !settings.BlockDoT {
			t.Fatalf("%s: settings=%+v err=%v", mode, settings, err)
		}
		plan, err := settings.GatewayPlan(engine.CapturePlan{Destinations: engine.DestinationCapture{Mode: engine.DestinationCaptureAll}}, openwrt.InterfaceDiscovery{WANInterfaces: []string{"wan"}})
		if err != nil || !plan.BlockDoT {
			t.Fatalf("DoT not carried to gateway: plan=%+v err=%v", plan, err)
		}
	}
	for _, raw := range []state.Settings{
		{"BLOCK_DOT": "invalid"},
		{"BLOCK_DOT": "true", "OPERATING_MODE": "server"},
		{"BLOCK_DOT": "true", "ENABLE_DNS_UPSTREAM": "false", "ENABLE_DNS_REDIRECT": "false"},
	} {
		if _, err := DecodeRuntimeSettings(raw); err == nil {
			t.Fatalf("invalid settings accepted: %v", raw)
		}
	}
}

func TestDoTSettingsPersistenceAndRestart(t *testing.T) {
	t.Parallel()
	service, err := NewSettingsService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.State.SaveSettings(settingsRelativePath, state.Settings{"FUTURE_SETTING": "keep", "BYPASS_SOURCES": "192.0.2.5"}); err != nil {
		t.Fatal(err)
	}
	var restarts []bool
	service.OnChanged = func(_ context.Context, restart bool) error { restarts = append(restarts, restart); return nil }
	for _, enabled := range []bool{true, true, false} {
		result, err := service.UpdateSettings(context.Background(), web.SettingsPatch{BlockDoT: &enabled})
		if err != nil || result.BlockDoT != enabled {
			t.Fatalf("settings=%+v err=%v", result, err)
		}
		loaded, err := LoadRuntimeSettings(service.State)
		if err != nil || loaded.BlockDoT != enabled || loaded.Raw["FUTURE_SETTING"] != "keep" || loaded.Raw["BYPASS_SOURCES"] != "192.0.2.5" {
			t.Fatalf("persisted=%+v err=%v", loaded, err)
		}
	}
	if !reflect.DeepEqual(restarts, []bool{true, false, true}) {
		t.Fatalf("restart requirements=%v", restarts)
	}
}

func TestDoTInvalidSaveKeepsSavedSettings(t *testing.T) {
	t.Parallel()
	service, err := NewSettingsService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	if _, err := service.UpdateSettings(context.Background(), web.SettingsPatch{BlockDoT: &enabled}); err != nil {
		t.Fatal(err)
	}
	before, err := service.State.Read(settingsRelativePath)
	if err != nil {
		t.Fatal(err)
	}
	disabledDNS, serverMode := "disabled", "server"
	for _, patch := range []web.SettingsPatch{{DNSMode: &disabledDNS}, {OperatingMode: &serverMode}} {
		if _, err := service.UpdateSettings(context.Background(), patch); err == nil {
			t.Fatal("incompatible settings accepted")
		}
		after, err := service.State.Read(settingsRelativePath)
		if err != nil || string(after) != string(before) {
			t.Fatal("invalid save changed settings")
		}
	}
	disabled := false
	if _, err := service.UpdateSettings(context.Background(), web.SettingsPatch{DNSMode: &disabledDNS, BlockDoT: &disabled}); err != nil {
		t.Fatal(err)
	}
}

func TestDoTFailedSaveDoesNotApply(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	service, err := NewSettingsService(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.State.SaveSettings(settingsRelativePath, state.Settings{"BLOCK_DOT": "false", "FUTURE_SETTING": "keep"}); err != nil {
		t.Fatal(err)
	}
	store := service.State
	before, err := store.Read(settingsRelativePath)
	if err != nil {
		t.Fatal(err)
	}
	blockedRoot := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(blockedRoot, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Inject an unwritable store after loading the candidate, before persisting.
	service.ConfigureRestartGuard = func(context.Context, RuntimeSettings) error { service.State.Root = blockedRoot; return nil }
	service.OnChanged = func(context.Context, bool) error { t.Fatal("failed save applied settings"); return nil }
	enabled := true
	if _, err := service.UpdateSettings(context.Background(), web.SettingsPatch{BlockDoT: &enabled, CoreRestartGuard: &enabled}); err == nil {
		t.Fatal("failed write succeeded")
	}
	after, err := store.Read(settingsRelativePath)
	if err != nil || string(after) != string(before) {
		t.Fatal("failed write changed original settings")
	}
}

func TestDoTRuntimeRefreshFailureReportsSavedState(t *testing.T) {
	t.Parallel()
	service, err := NewSettingsService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service.OnChanged = func(context.Context, bool) error { return errors.New("restart failed") }
	enabled := true
	_, err = service.UpdateSettings(context.Background(), web.SettingsPatch{BlockDoT: &enabled})
	if err == nil || !strings.Contains(err.Error(), "settings saved but runtime refresh failed") {
		t.Fatalf("err=%v", err)
	}
	saved, err := service.Settings(context.Background())
	if err != nil || !saved.BlockDoT {
		t.Fatalf("saved=%+v err=%v", saved, err)
	}
}
