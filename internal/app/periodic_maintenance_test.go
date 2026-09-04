package app

import (
	"context"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
)

type maintenanceActivationStub struct {
	base         engine.CapturePlan
	destinations engine.DestinationCapture
	endpoints    []netip.Prefix
	calls        int
}

func (activation *maintenanceActivationStub) RefreshDynamicCapture(_ context.Context, destinations engine.DestinationCapture, endpoints []netip.Prefix) (engine.CapturePlan, error) {
	activation.calls++
	activation.destinations = destinations
	activation.endpoints = append([]netip.Prefix(nil), endpoints...)
	result := cloneCapturePlan(activation.base)
	result.Destinations = destinations
	result.EndpointBypassCIDRs = append([]netip.Prefix(nil), endpoints...)
	return result, nil
}

func TestPeriodicMaintenanceRefreshesFakeIPAndEndpointSetsWithoutCoreReload(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := state.NewProfileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	source := []byte(`
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
proxies:
  - name: remote
    server: node.example
rules:
  - IP-CIDR,203.0.113.99/24,PROXY
`)
	if err := os.WriteFile(layout.MihomoConfig, source, 0o600); err != nil {
		t.Fatal(err)
	}
	runtimeProviderRoot := t.TempDir()
	runtimeProviderPath := runtimeProviderRoot + "/remote.yaml"
	if err := os.WriteFile(runtimeProviderPath, []byte("payload:\n  - 198.51.100.99/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runtimePath := runtimeProviderRoot + "/runtime.yaml"
	runtimeSource := []byte(`
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
proxies:
  - name: runtime-remote
    server: runtime-node.example
rules:
  - RULE-SET,runtime-ip,PROXY
rule-providers:
  runtime-ip:
    type: http
    behavior: ipcidr
    format: yaml
    url: https://rules.example.invalid/remote.yaml
    path: ` + runtimeProviderPath + `
`)
	if err := os.WriteFile(runtimePath, runtimeSource, 0o600); err != nil {
		t.Fatal(err)
	}
	endpointManager := NewEndpointBypassManager(layout, store)
	endpointManager.Resolver = &endpointResolverStub{addresses: map[string][]netip.Addr{
		"node.example":          {netip.MustParseAddr("192.0.2.7")},
		"runtime-node.example":  {netip.MustParseAddr("198.51.100.7")},
		"rules.example.invalid": {netip.MustParseAddr("198.51.100.8")},
	}, errors: map[string]error{}}
	fakeIPManager := NewFakeIPCaptureManager(layout)
	fakeIPManager.TrustedProviderCacheRoots = []string{runtimeProviderRoot}
	preparer := &ActiveMihomoPreparer{
		Layout: layout, Profiles: profiles, State: store,
		FakeIP: fakeIPManager, Endpoints: endpointManager,
	}
	initial := engine.CapturePlan{
		TCP:       engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		UDP:       engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		TUNDevice: "clash-tun", LoopMark: 2,
		Destinations:        engine.DestinationCapture{Mode: engine.DestinationCaptureAll},
		EndpointBypassCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.7/32")},
	}
	lifecycle := &Lifecycle{snap: LifecycleSnapshot{
		State: LifecycleRunning,
		Prepared: engine.PreparedCore{
			Engine: state.EngineMihomo, RuntimeConfigPath: runtimePath, Capture: initial,
		},
	}}
	activation := &maintenanceActivationStub{base: initial}
	service := NewPeriodicMaintenance(store, preparer, lifecycle, activation, nil)
	settings := DefaultRuntimeSettings()
	settings.AutoFakeIPIncludeExternalIPProviders = true

	if err := service.Refresh(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	if activation.calls != 1 {
		t.Fatalf("activation calls = %d, want 1", activation.calls)
	}
	wantDestinations := engine.DestinationCapture{Mode: engine.DestinationCaptureAllowlist, CIDRs: []netip.Prefix{
		netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	}}
	if !reflect.DeepEqual(activation.destinations, wantDestinations) {
		t.Fatalf("destinations = %+v, want %+v", activation.destinations, wantDestinations)
	}
	if want := []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32"), netip.MustParsePrefix("198.51.100.8/32")}; !reflect.DeepEqual(activation.endpoints, want) {
		t.Fatalf("endpoint bypasses = %v, want %v", activation.endpoints, want)
	}
	updated := lifecycle.Snapshot().Prepared.Capture
	if !reflect.DeepEqual(updated.Destinations, wantDestinations) || !reflect.DeepEqual(updated.EndpointBypassCIDRs, activation.endpoints) {
		t.Fatalf("lifecycle snapshot did not receive refreshed sets: %+v", updated)
	}
}

func TestPeriodicMaintenanceWakeRecalculatesScheduleWithoutRunningEarly(t *testing.T) {
	t.Parallel()
	service := NewPeriodicMaintenance(state.Store{}, nil, nil, nil, nil)
	service.Reload()
	fired, ok := service.wait(context.Background(), time.Hour)
	if !ok || fired {
		t.Fatalf("settings wake = fired %t ok %t, want false true", fired, ok)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	fired, ok = service.wait(ctx, time.Millisecond)
	if !ok || !fired {
		t.Fatalf("timer = fired %t ok %t, want true true", fired, ok)
	}
}

func TestPeriodicMaintenanceDoesNothingInServerMode(t *testing.T) {
	t.Parallel()
	settings := DefaultRuntimeSettings()
	settings.OperatingMode = "server"
	if err := (*PeriodicMaintenance)(nil).Refresh(context.Background(), settings); err != nil {
		t.Fatalf("server-mode maintenance = %v, want no-op", err)
	}
}
