package app

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/platform/openwrt"
	"github.com/kontsevoye/boxctl/internal/state"
)

func TestDecodeRuntimeSettingsAndPlans(t *testing.T) {
	settings, err := DecodeRuntimeSettings(state.Settings{
		"PROXY_MODE":            "mixed2",
		"ENABLE_DNS_UPSTREAM":   "false",
		"ENABLE_DNS_REDIRECT":   "true",
		"INTERFACE_MODE":        "explicit",
		"INCLUDED_INTERFACES":   "br-guest,br-lan",
		"RESERVED_NETWORKS":     "10.0.0.0/8,192.168.0.1",
		"BYPASS_SOURCES":        "192.0.2.12,198.51.100.0/24",
		"BYPASS_DPORTS":         "tcp:6881-6882,udp:5353",
		"PROXY_DPORTS":          "80,443",
		"BLOCK_QUIC":            "true",
		"AUTO_FAKEIP_WHITELIST": "true",
		"AUTO_FAKEIP_INCLUDE_EXTERNAL_IP_PROVIDERS": "true",
		"INTERCEPT_ROUTER_OUTPUT":                   "false",
		"FUTURE_SETTING":                            "preserved",
	})
	if err != nil {
		t.Fatal(err)
	}
	if settings.Raw["FUTURE_SETTING"] != "preserved" || settings.CaptureMode != openwrt.ModeMIXED2 || settings.DNSMode != openwrt.DNSRedirect || !settings.AutoFakeIPIncludeExternalIPProviders {
		t.Fatalf("settings = %+v", settings)
	}
	if !reflect.DeepEqual(settings.BypassTCPPorts, []uint16{6881, 6882}) || !reflect.DeepEqual(settings.BypassUDPPorts, []uint16{5353}) {
		t.Fatalf("bypass ports = %v %v", settings.BypassTCPPorts, settings.BypassUDPPorts)
	}
	capture, err := settings.CapturePlan(ManagedMihomoSettings{
		RedirectPort: 7893, DNSPort: 7874, TUNDevice: "clash-tun", LoopMark: 2,
		FakeIPRanges: []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if capture.TCP.Method != engine.CaptureRedirect || capture.UDP.Method != engine.CaptureTUN {
		t.Fatalf("capture = %+v", capture)
	}
	gateway, err := settings.GatewayPlan(capture, openwrt.InterfaceDiscovery{LANInterfaces: []string{"br-lan"}, WANInterfaces: []string{"eth1"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gateway.IncludeInterfaces, []string{"br-guest", "br-lan"}) || len(gateway.ExcludeInterfaces) != 0 {
		t.Fatalf("interfaces = include %v exclude %v", gateway.IncludeInterfaces, gateway.ExcludeInterfaces)
	}
	if len(gateway.CaptureCIDRs) != 0 || !gateway.RejectQUIC || gateway.InterceptOutput {
		t.Fatalf("gateway = %+v", gateway)
	}
}

func TestDecodeRuntimeSettingsRejectsUnsafeCombinations(t *testing.T) {
	tests := []state.Settings{
		{"PROXY_MODE": "unknown"},
		{"OPERATING_MODE": "router-ish"},
		{"ENABLE_DNS_UPSTREAM": "true", "ENABLE_DNS_REDIRECT": "true"},
		{"TUN_STACK": "magic"},
		{"BYPASS_DPORTS": "0"},
		{"RESERVED_NETWORKS": "::1/128"},
		{"MAINTENANCE_INTERVAL": "4"},
		{"MAINTENANCE_INTERVAL": "1441"},
		{"AUTO_FAKEIP_INCLUDE_EXTERNAL_IP_PROVIDERS": "sometimes"},
	}
	for _, input := range tests {
		if _, err := DecodeRuntimeSettings(input); err == nil {
			t.Fatalf("DecodeRuntimeSettings(%v) succeeded", input)
		}
	}
}

func TestDecodeRuntimeSettingsOperatingModes(t *testing.T) {
	settings, err := DecodeRuntimeSettings(state.Settings{})
	if err != nil {
		t.Fatal(err)
	}
	if settings.OperatingMode != "gateway" {
		t.Fatalf("default operating mode = %q", settings.OperatingMode)
	}
	settings, err = DecodeRuntimeSettings(state.Settings{"OPERATING_MODE": "server"})
	if err != nil {
		t.Fatal(err)
	}
	if settings.OperatingMode != "server" {
		t.Fatalf("server operating mode = %q", settings.OperatingMode)
	}
}

func TestDecodeRuntimeSettingsDoesNotIncludeExternalIPProvidersByDefault(t *testing.T) {
	settings, err := DecodeRuntimeSettings(state.Settings{})
	if err != nil {
		t.Fatal(err)
	}
	if settings.AutoFakeIPIncludeExternalIPProviders {
		t.Fatal("empty settings unexpectedly include external IP providers in the AUTO fake-IP pool")
	}
}

func TestDecodeRuntimeSettingsRejectQUICDefaultAndExplicitFalse(t *testing.T) {
	settings, err := DecodeRuntimeSettings(state.Settings{})
	if err != nil {
		t.Fatal(err)
	}
	if !settings.RejectQUIC {
		t.Fatal("empty settings must retain the BLOCK_QUIC default")
	}

	settings, err = DecodeRuntimeSettings(state.Settings{"BLOCK_QUIC": "false"})
	if err != nil {
		t.Fatal(err)
	}
	if settings.RejectQUIC {
		t.Fatal("explicit BLOCK_QUIC=false was replaced by the default")
	}
}

func TestGatewayPlanRequiresSafeInterfaceTopology(t *testing.T) {
	settings := DefaultRuntimeSettings()
	if !settings.RejectQUIC {
		t.Fatal("OpenWrt compatibility defaults must block QUIC")
	}
	capture, err := settings.CapturePlan(ManagedMihomoSettings{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settings.GatewayPlan(capture, openwrt.InterfaceDiscovery{}); err == nil {
		t.Fatal("missing WAN topology succeeded")
	}
	settings.InterfaceMode = "explicit"
	settings.AutoDetectLAN = false
	if _, err := settings.GatewayPlan(capture, openwrt.InterfaceDiscovery{}); err == nil {
		t.Fatal("empty explicit topology succeeded")
	}
}

func TestCapturePlanFakeIPDestinationModes(t *testing.T) {
	settings := DefaultRuntimeSettings()
	settings.InterfaceMode = "exclude"
	settings.AutoDetectWAN = false
	settings.Excluded = []string{"wan"}
	fakeRange := netip.MustParsePrefix("198.18.0.1/16")
	extra := []netip.Prefix{
		netip.MustParsePrefix("149.154.167.1/24"),
		netip.MustParsePrefix("91.108.4.0/22"),
		netip.MustParsePrefix("91.108.4.1/22"),
	}

	for _, mode := range []string{"", "blacklist", "invalid"} {
		capture, err := settings.CapturePlan(ManagedMihomoSettings{
			DNSFakeIP: true, FakeIPFilterMode: mode, FakeIPRanges: []netip.Prefix{fakeRange}, AdditionalCaptureCIDRs: extra,
		})
		if err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		want := []netip.Prefix{netip.MustParsePrefix("198.18.0.0/16")}
		if capture.Destinations.Mode != engine.DestinationCaptureAllowlist || !reflect.DeepEqual(capture.Destinations.CIDRs, want) {
			t.Fatalf("mode %q destinations = %+v", mode, capture.Destinations)
		}
	}

	settings.AutoFakeIP = false
	for _, mode := range []string{"whitelist", "rule"} {
		capture, err := settings.CapturePlan(ManagedMihomoSettings{
			DNSFakeIP: true, FakeIPFilterMode: mode, FakeIPRanges: []netip.Prefix{fakeRange}, AdditionalCaptureCIDRs: extra,
		})
		if err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		want := []netip.Prefix{
			netip.MustParsePrefix("149.154.167.0/24"),
			netip.MustParsePrefix("198.18.0.0/16"),
			netip.MustParsePrefix("91.108.4.0/22"),
		}
		if capture.Destinations.Mode != engine.DestinationCaptureAllowlist || !reflect.DeepEqual(capture.Destinations.CIDRs, want) {
			t.Fatalf("mode %q destinations = %+v, want %v", mode, capture.Destinations, want)
		}
		gateway, err := settings.GatewayPlan(capture, openwrt.InterfaceDiscovery{})
		if err != nil {
			t.Fatalf("mode %q gateway: %v", mode, err)
		}
		if !gateway.CaptureCIDRsConfigured || !reflect.DeepEqual(gateway.CaptureCIDRs, []string{"149.154.167.0/24", "198.18.0.0/16", "91.108.4.0/22"}) {
			t.Fatalf("mode %q gateway capture = %+v", mode, gateway)
		}
	}
}

func TestCapturePlanNonFakeIPRemainsBroad(t *testing.T) {
	settings := DefaultRuntimeSettings()
	capture, err := settings.CapturePlan(ManagedMihomoSettings{
		FakeIPRanges:           []netip.Prefix{netip.MustParsePrefix("198.18.0.0/16")},
		AdditionalCaptureCIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if capture.Destinations.Mode != engine.DestinationCaptureAll || len(capture.Destinations.CIDRs) != 0 {
		t.Fatalf("non-fake capture is not broad: %+v", capture.Destinations)
	}
}

func TestCapturePlanAllowsDisabledDNS(t *testing.T) {
	settings := DefaultRuntimeSettings()
	settings.DNSMode = openwrt.DNSDisabled
	capture, err := settings.CapturePlan(ManagedMihomoSettings{DNSPort: 7874})
	if err != nil {
		t.Fatal(err)
	}
	if capture.DNS != (engine.DNSEndpoint{}) {
		t.Fatalf("disabled DNS endpoint = %+v", capture.DNS)
	}
}

func TestGatewayPlanPreservesExplicitEmptyReservedNetworks(t *testing.T) {
	settings, err := DecodeRuntimeSettings(state.Settings{
		"RESERVED_NETWORKS":   "",
		"EXCLUDED_INTERFACES": "wan",
		"AUTO_DETECT_WAN":     "false",
	})
	if err != nil {
		t.Fatal(err)
	}
	capture, err := settings.CapturePlan(ManagedMihomoSettings{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := settings.GatewayPlan(capture, openwrt.InterfaceDiscovery{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.BypassCIDRsConfigured || len(plan.BypassCIDRs) != 0 {
		t.Fatalf("explicit empty RESERVED_NETWORKS was not preserved: %+v", plan)
	}
}

func TestCheckedPortRejectsNarrowingOverflow(t *testing.T) {
	port, err := checkedPort(65_535)
	if err != nil || port != 65_535 {
		t.Fatalf("checkedPort(max) = %d, %v", port, err)
	}
	if _, err := checkedPort(65_536); err == nil {
		t.Fatal("checkedPort accepted a value outside uint16")
	}
}
