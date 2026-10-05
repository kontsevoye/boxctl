package app

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

func TestMipsCapturePlanUsesExplicitSavedStackForAllTUNModes(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"tun", "mixed", "mixed2"} {
		t.Run(mode, func(t *testing.T) {
			settings, err := DecodeRuntimeSettings(state.Settings{"PROXY_MODE": mode, "TUN_STACK": "mips"})
			if err != nil {
				t.Fatal(err)
			}
			capture, err := settings.CapturePlan(ManagedMihomoSettings{TUNStack: "system"})
			if err != nil || capture.TUNStack != "mips" || capture.UDP.Method != engine.CaptureTUN {
				t.Fatalf("capture = %+v, %v", capture, err)
			}
		})
	}
	settings, err := DecodeRuntimeSettings(state.Settings{})
	if err != nil || settings.TUNStack != "system" {
		t.Fatalf("default settings = %+v, %v", settings, err)
	}
	capture, err := settings.CapturePlan(ManagedMihomoSettings{TUNStack: "gvisor"})
	if err != nil || capture.TUNStack != "gvisor" {
		t.Fatalf("source stack without explicit setting = %q, %v", capture.TUNStack, err)
	}
}

func TestSettingsServiceMipsRoundTripAndRestart(t *testing.T) {
	t.Parallel()
	service, err := NewSettingsService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.State.SaveSettings(settingsRelativePath, state.Settings{"FUTURE_KEY": "preserve"}); err != nil {
		t.Fatal(err)
	}
	var restarts []bool
	service.OnChanged = func(_ context.Context, restart bool) error { restarts = append(restarts, restart); return nil }
	stack := "mips"
	saved, err := service.UpdateSettings(context.Background(), web.SettingsPatch{TUNStack: &stack})
	if err != nil || saved.TUNStack != stack {
		t.Fatalf("save = %+v, %v", saved, err)
	}
	read, err := service.Settings(context.Background())
	if err != nil || read.TUNStack != stack {
		t.Fatalf("read = %+v, %v", read, err)
	}
	if _, err := service.UpdateSettings(context.Background(), web.SettingsPatch{TUNStack: &stack}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restarts, []bool{true, false}) {
		t.Fatalf("restart requirements = %v", restarts)
	}
	raw, err := service.State.LoadSettings(settingsRelativePath)
	if err != nil || raw["FUTURE_KEY"] != "preserve" || raw["TUN_STACK"] != stack {
		t.Fatalf("saved state = %+v, %v", raw, err)
	}
}

func TestSettingsServiceRejectsSingBoxMipsWithoutMutation(t *testing.T) {
	t.Parallel()
	service, err := NewSettingsService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	original := state.Settings{"TUN_STACK": "mixed", "FUTURE_KEY": "preserve"}
	if err := service.State.SaveSettings(settingsRelativePath, original); err != nil {
		t.Fatal(err)
	}
	service.SelectedEngine = func() string { return state.EngineSingBox }
	service.OnChanged = func(context.Context, bool) error { t.Fatal("rejected save must not refresh runtime"); return nil }
	stack := "mips"
	_, err = service.UpdateSettings(context.Background(), web.SettingsPatch{TUNStack: &stack})
	var public *web.PublicError
	if !errors.As(err, &public) || public.Code != "unsupported_tun_stack" {
		t.Fatalf("save error = %v", err)
	}
	raw, err := service.State.LoadSettings(settingsRelativePath)
	if err != nil || !reflect.DeepEqual(raw, original) {
		t.Fatalf("rejected save changed settings = %+v, %v", raw, err)
	}
}
