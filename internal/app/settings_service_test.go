package app

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

func TestSettingsServicePreservesUnknownAndWritesAdvancedSettings(t *testing.T) {
	root := t.TempDir()
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSettings(settingsRelativePath, state.Settings{"FUTURE_KEY": "keep", "USE_TMPFS_RULES": "false"}); err != nil {
		t.Fatal(err)
	}
	service, err := NewSettingsService(root)
	if err != nil {
		t.Fatal(err)
	}
	mode := "mixed2"
	dnsMode := "redirect"
	bypassTCP := []uint16{6882, 6881}
	bypassUDP := []uint16{5353}
	reserved := []string{"192.168.0.0/16", "10.0.0.0/8"}
	autoDetectWAN := false
	autoDetectLAN := false
	interceptRouterOutput := false
	includeExternalIPProviders := true
	result, err := service.UpdateSettings(context.Background(), web.SettingsPatch{
		CaptureMode: &mode, DNSMode: &dnsMode, BypassTCPPorts: &bypassTCP, BypassUDPPorts: &bypassUDP, ReservedNetworks: &reserved,
		AutoDetectWAN: &autoDetectWAN, AutoDetectLAN: &autoDetectLAN, InterceptRouterOutput: &interceptRouterOutput,
		AutoFakeIPIncludeExternalIPProviders: &includeExternalIPProviders,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.CaptureMode != "mixed2" || result.DNSMode != "redirect" || result.AutoDetectWAN || result.AutoDetectLAN || result.InterceptRouterOutput || !result.AutoFakeIPIncludeExternalIPProviders || !reflect.DeepEqual(result.BypassTCPPorts, []uint16{6881, 6882}) {
		t.Fatalf("settings = %+v", result)
	}
	raw, err := store.LoadSettings(settingsRelativePath)
	if err != nil {
		t.Fatal(err)
	}
	if raw["FUTURE_KEY"] != "keep" || raw["ENABLE_DNS_REDIRECT"] != "true" || raw["BYPASS_DPORTS"] != "tcp:6881,tcp:6882,udp:5353" ||
		raw["AUTO_DETECT_WAN"] != "false" || raw["AUTO_DETECT_LAN"] != "false" || raw["INTERCEPT_ROUTER_OUTPUT"] != "false" ||
		raw["AUTO_FAKEIP_INCLUDE_EXTERNAL_IP_PROVIDERS"] != "true" {
		t.Fatalf("raw = %+v", raw)
	}
}

func TestSettingsServiceExposesDefaultCaptureDiscoveryAndRouterOutput(t *testing.T) {
	service, err := NewSettingsService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.AutoDetectWAN || !result.AutoDetectLAN || !result.InterceptRouterOutput ||
		!result.AutoRefreshProxyIPs || !result.AutoRefreshFakeIP || result.MaintenanceIntervalMinutes != 30 || result.Language != "en" {
		t.Fatalf("settings = %+v, want English with capture discovery, router output and 30-minute maintenance enabled", result)
	}
}

func TestSettingsServiceUpdatesMaintenanceWithoutCoreRestart(t *testing.T) {
	service, err := NewSettingsService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var restartRequired []bool
	service.OnChanged = func(_ context.Context, restart bool) error {
		restartRequired = append(restartRequired, restart)
		return nil
	}
	disabled := false
	interval := 1440
	result, err := service.UpdateSettings(context.Background(), web.SettingsPatch{
		AutoRefreshProxyIPs: &disabled, AutoRefreshFakeIP: &disabled, MaintenanceIntervalMinutes: &interval,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.AutoRefreshProxyIPs || result.AutoRefreshFakeIP || result.MaintenanceIntervalMinutes != interval {
		t.Fatalf("settings = %+v", result)
	}
	if !reflect.DeepEqual(restartRequired, []bool{false}) {
		t.Fatalf("maintenance-only change restart calls = %v, want [false]", restartRequired)
	}
}

func TestSettingsServiceRejectsMaintenanceIntervalOutsideBounds(t *testing.T) {
	t.Parallel()
	for _, value := range []int{4, 1441} {
		value := value
		t.Run(fmt.Sprint(value), func(t *testing.T) {
			t.Parallel()
			service, err := NewSettingsService(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.UpdateSettings(context.Background(), web.SettingsPatch{MaintenanceIntervalMinutes: &value}); err == nil {
				t.Fatalf("maintenance interval %d succeeded", value)
			}
			if _, err := service.State.Read(settingsRelativePath); err == nil {
				t.Fatalf("invalid maintenance interval %d was persisted", value)
			}
		})
	}
}

func TestSettingsServiceRejectsInvalidWithoutWriting(t *testing.T) {
	root := t.TempDir()
	service, err := NewSettingsService(root)
	if err != nil {
		t.Fatal(err)
	}
	bad := "anything"
	if _, err := service.UpdateSettings(context.Background(), web.SettingsPatch{CaptureMode: &bad}); err == nil {
		t.Fatal("invalid capture mode succeeded")
	}
	if _, err := service.State.Read(settingsRelativePath); err == nil {
		t.Fatal("invalid settings were persisted")
	}
}

func TestSettingsServiceAppliesChangedBootState(t *testing.T) {
	root := t.TempDir()
	service, err := NewSettingsService(root)
	if err != nil {
		t.Fatal(err)
	}
	var states []bool
	service.SetStartOnBoot = func(_ context.Context, enabled bool) error {
		states = append(states, enabled)
		return nil
	}
	disabled := false
	result, err := service.UpdateSettings(context.Background(), web.SettingsPatch{StartOnBoot: &disabled})
	if err != nil {
		t.Fatal(err)
	}
	if result.StartOnBoot || !reflect.DeepEqual(states, []bool{false}) {
		t.Fatalf("boot result=%+v calls=%v", result, states)
	}
}

func TestSettingsServiceAutoFakeIPChangeRequiresRestart(t *testing.T) {
	service, err := NewSettingsService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var restartRequired []bool
	service.OnChanged = func(_ context.Context, restart bool) error {
		restartRequired = append(restartRequired, restart)
		return nil
	}
	disabled := false
	result, err := service.UpdateSettings(context.Background(), web.SettingsPatch{AutoFakeIPWhitelist: &disabled})
	if err != nil {
		t.Fatal(err)
	}
	if result.AutoFakeIPWhitelist || !reflect.DeepEqual(restartRequired, []bool{true}) {
		t.Fatalf("settings=%+v restart calls=%v", result, restartRequired)
	}
}

func TestSettingsServiceExternalIPProviderInclusionChangeRequiresRestart(t *testing.T) {
	service, err := NewSettingsService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var restartRequired []bool
	service.OnChanged = func(_ context.Context, restart bool) error {
		restartRequired = append(restartRequired, restart)
		return nil
	}
	enabled := true
	result, err := service.UpdateSettings(context.Background(), web.SettingsPatch{AutoFakeIPIncludeExternalIPProviders: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	if !result.AutoFakeIPIncludeExternalIPProviders || !reflect.DeepEqual(restartRequired, []bool{true}) {
		t.Fatalf("settings=%+v restart calls=%v", result, restartRequired)
	}
}

func TestSettingsServiceCaptureDiscoveryAndRouterOutputChangesRequireRestart(t *testing.T) {
	for name, patch := range map[string]web.SettingsPatch{
		"auto-detect WAN":         {AutoDetectWAN: boolPointer(false)},
		"auto-detect LAN":         {AutoDetectLAN: boolPointer(false)},
		"intercept router output": {InterceptRouterOutput: boolPointer(false)},
	} {
		t.Run(name, func(t *testing.T) {
			service, err := NewSettingsService(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			var restartRequired []bool
			service.OnChanged = func(_ context.Context, restart bool) error {
				restartRequired = append(restartRequired, restart)
				return nil
			}
			if _, err := service.UpdateSettings(context.Background(), patch); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(restartRequired, []bool{true}) {
				t.Fatalf("restart calls=%v, want [true]", restartRequired)
			}
		})
	}
}

func TestSettingsServiceRuntimeProviderChangesRequireRestart(t *testing.T) {
	for name, patch := range map[string]web.SettingsPatch{
		"tmpfs rule providers": {UseTmpfsRules: boolPointer(true)},
		"device headers":       {EnableHWID: boolPointer(true)},
	} {
		t.Run(name, func(t *testing.T) {
			service, err := NewSettingsService(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			var restartRequired []bool
			service.OnChanged = func(_ context.Context, restart bool) error {
				restartRequired = append(restartRequired, restart)
				return nil
			}
			if _, err := service.UpdateSettings(context.Background(), patch); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(restartRequired, []bool{true}) {
				t.Fatalf("restart calls=%v, want [true]", restartRequired)
			}
		})
	}
}

func TestSettingsServiceScopesEngineSpecificRestartSettings(t *testing.T) {
	t.Run("Mihomo ignores sing-box TUN address", func(t *testing.T) {
		service, err := NewSettingsService(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		service.SelectedEngine = func() string { return state.EngineMihomo }
		var restart bool
		service.OnChanged = func(_ context.Context, required bool) error { restart = required; return nil }
		address := "172.20.0.1/30"
		if _, err := service.UpdateSettings(context.Background(), web.SettingsPatch{TUNAddress: &address}); err != nil {
			t.Fatal(err)
		}
		if restart {
			t.Fatal("Mihomo was restarted for a sing-box-only TUN address")
		}
	})

	t.Run("sing-box ignores Mihomo provider settings", func(t *testing.T) {
		service, err := NewSettingsService(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		service.SelectedEngine = func() string { return state.EngineSingBox }
		var restart bool
		service.OnChanged = func(_ context.Context, required bool) error { restart = required; return nil }
		enabled := true
		if _, err := service.UpdateSettings(context.Background(), web.SettingsPatch{UseTmpfsRules: &enabled}); err != nil {
			t.Fatal(err)
		}
		if restart {
			t.Fatal("sing-box was restarted for a Mihomo-only provider setting")
		}
	})

	t.Run("sing-box TUN address requires restart", func(t *testing.T) {
		service, err := NewSettingsService(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		service.SelectedEngine = func() string { return state.EngineSingBox }
		var restart bool
		service.OnChanged = func(_ context.Context, required bool) error { restart = required; return nil }
		address := "172.20.0.1/30"
		if _, err := service.UpdateSettings(context.Background(), web.SettingsPatch{TUNAddress: &address}); err != nil {
			t.Fatal(err)
		}
		if !restart {
			t.Fatal("sing-box TUN address did not require a restart")
		}
	})
}

func boolPointer(value bool) *bool {
	return &value
}
