package app

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/platform/openwrt"
	"github.com/kontsevoye/boxctl/internal/state"
)

type fakeGatewayController struct {
	events             *[]string
	appliedPlans       *[]openwrt.GatewayPlan
	checkedPlans       *[]openwrt.GatewayPlan
	applyErr           error
	cleanupErr         error
	detectErr          *error
	cleanupWasCanceled *bool
}

func (gateway fakeGatewayController) Detect(context.Context) (openwrt.InterfaceDiscovery, error) {
	if gateway.detectErr != nil && *gateway.detectErr != nil {
		return openwrt.InterfaceDiscovery{}, *gateway.detectErr
	}
	return openwrt.InterfaceDiscovery{LANInterfaces: []string{"br-lan"}, WANInterfaces: []string{"eth1"}}, nil
}
func (gateway fakeGatewayController) Apply(_ context.Context, plan openwrt.GatewayPlan) error {
	*gateway.events = append(*gateway.events, "gateway-apply")
	if gateway.appliedPlans != nil {
		*gateway.appliedPlans = append(*gateway.appliedPlans, plan)
	}
	return gateway.applyErr
}
func (gateway fakeGatewayController) Cleanup(ctx context.Context, _ openwrt.GatewayPlan) error {
	*gateway.events = append(*gateway.events, "gateway-cleanup")
	if gateway.cleanupWasCanceled != nil {
		*gateway.cleanupWasCanceled = ctx.Err() != nil
	}
	return gateway.cleanupErr
}
func (gateway fakeGatewayController) Check(_ context.Context, plan openwrt.GatewayPlan) (openwrt.CheckResult, error) {
	if gateway.checkedPlans != nil {
		*gateway.checkedPlans = append(*gateway.checkedPlans, plan)
	}
	return openwrt.CheckResult{Exists: true, Owned: true}, nil
}

type fakeDNSController struct {
	events             *[]string
	applyErr           error
	cancelOnApply      context.CancelFunc
	restoreWasCanceled *bool
	restoreErr         *error
}

func (dns fakeDNSController) Backup(context.Context) (openwrt.DNSBackup, error) {
	*dns.events = append(*dns.events, "dns-backup")
	return testDNSBackup(), nil
}
func (dns fakeDNSController) Apply(context.Context, openwrt.GatewayPlan, openwrt.DNSBackup) error {
	*dns.events = append(*dns.events, "dns-apply")
	if dns.cancelOnApply != nil {
		dns.cancelOnApply()
	}
	return dns.applyErr
}
func (dns fakeDNSController) Restore(ctx context.Context, _ openwrt.DNSBackup) error {
	*dns.events = append(*dns.events, "dns-restore")
	if dns.restoreWasCanceled != nil {
		*dns.restoreWasCanceled = ctx.Err() != nil
	}
	if dns.restoreErr != nil {
		return *dns.restoreErr
	}
	return nil
}

func testDNSBackup() openwrt.DNSBackup {
	return openwrt.DNSBackup{Version: 1, Package: "dhcp", Section: "@dnsmasq[0]", Options: map[string]openwrt.UCIOptionState{
		"cachesize": {}, "noresolv": {}, "server": {},
	}}
}

func completePrepared(capture engine.CapturePlan) engine.PreparedCore {
	return engine.PreparedCore{
		Engine: state.EngineMihomo,
		Controller: engine.ControllerEndpoint{
			Listen: "127.0.0.1:9090", BaseURL: "http://127.0.0.1:9090",
		},
		Capture: capture,
	}
}

func seedActiveGatewayState(t *testing.T, activation *OpenWrtActivation, prepared engine.PreparedCore) {
	t.Helper()
	_, active, err := activation.buildPlanAndState(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	if err := activation.saveActiveGatewayState(active); err != nil {
		t.Fatal(err)
	}
}

func testActivation(t *testing.T, gateway fakeGatewayController, dns fakeDNSController) *OpenWrtActivation {
	t.Helper()
	root := t.TempDir()
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	locks, err := state.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &OpenWrtActivation{Layout: layout, State: store, Locks: locks, gateway: gateway, dns: dns}
}

func TestOpenWrtActivationOrdersAndReversesTransaction(t *testing.T) {
	events := []string{}
	activation := testActivation(t, fakeGatewayController{events: &events}, fakeDNSController{events: &events})
	prepared := completePrepared(engine.CapturePlan{
		TCP:      engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		UDP:      engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		DNS:      engine.DNSEndpoint{Enabled: true, Host: "0.0.0.0", Port: 7874},
		LoopMark: 2,
	})
	if err := activation.Activate(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	if err := activation.Deactivate(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	want := []string{"dns-backup", "gateway-apply", "dns-apply", "dns-restore", "gateway-cleanup"}
	if len(events) != len(want) {
		t.Fatalf("events = %v", events)
	}
	for index := range want {
		if events[index] != want[index] {
			t.Fatalf("events = %v", events)
		}
	}
	if _, err := os.Stat(activation.Layout.DNSBackup); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("DNS backup still exists: %v", err)
	}
	if _, err := activation.State.Read(activeGatewayStatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active gateway generation still exists: %v", err)
	}
}

func TestOpenWrtActivationServerModeLeavesNetworkUntouched(t *testing.T) {
	events := []string{}
	activation := testActivation(t, fakeGatewayController{events: &events}, fakeDNSController{events: &events})
	if err := activation.State.SaveSettings(settingsRelativePath, state.Settings{"OPERATING_MODE": "server"}); err != nil {
		t.Fatal(err)
	}
	prepared := completePrepared(engine.CapturePlan{
		TCP: engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		UDP: engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
	})
	if err := activation.Activate(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	if err := activation.Deactivate(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("server mode touched OpenWrt networking: %v", events)
	}
}

func TestOpenWrtActivationDefersDNSFailureRollbackToLifecycle(t *testing.T) {
	events := []string{}
	activation := testActivation(t, fakeGatewayController{events: &events}, fakeDNSController{events: &events, applyErr: errors.New("dns failed")})
	prepared := engine.PreparedCore{Capture: engine.CapturePlan{
		TCP:      engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		UDP:      engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		DNS:      engine.DNSEndpoint{Enabled: true, Host: "0.0.0.0", Port: 7874},
		LoopMark: 2,
	}}
	if err := activation.Activate(context.Background(), prepared); err == nil {
		t.Fatal("DNS failure succeeded")
	}
	want := []string{"dns-backup", "gateway-apply", "dns-apply"}
	if !slices.Equal(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	if _, err := os.Stat(activation.Layout.DNSBackup); err != nil {
		t.Fatalf("failed activation did not retain DNS transaction for lifecycle rollback: %v", err)
	}
}

func TestOpenWrtActivationDefersPartialGatewayRollbackToLifecycle(t *testing.T) {
	events := []string{}
	activation := testActivation(t, fakeGatewayController{events: &events, applyErr: errors.New("partial nft failure")}, fakeDNSController{events: &events})
	prepared := engine.PreparedCore{Capture: engine.CapturePlan{
		TCP: engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		UDP: engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		DNS: engine.DNSEndpoint{Enabled: true, Host: "0.0.0.0", Port: 7874},
	}}
	if err := activation.Activate(context.Background(), prepared); err == nil {
		t.Fatal("partial gateway failure succeeded")
	}
	want := []string{"dns-backup", "gateway-apply"}
	if !slices.Equal(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	if _, err := os.Stat(activation.Layout.DNSBackup); err != nil {
		t.Fatalf("failed activation did not retain DNS transaction for lifecycle rollback: %v", err)
	}
}

func TestOpenWrtReconcileRollbackUsesFreshContextAfterApplyCancellation(t *testing.T) {
	events := []string{}
	cleanupCanceled := true
	restoreCanceled := true
	ctx, cancel := context.WithCancel(context.Background())
	activation := testActivation(t, fakeGatewayController{
		events: &events, cleanupWasCanceled: &cleanupCanceled,
	}, fakeDNSController{
		events: &events, applyErr: context.Canceled, cancelOnApply: cancel,
		restoreWasCanceled: &restoreCanceled,
	})
	prepared := completePrepared(engine.CapturePlan{
		TCP: engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		UDP: engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		DNS: engine.DNSEndpoint{Enabled: true, Host: "0.0.0.0", Port: 7874},
	})
	seedActiveGatewayState(t, activation, prepared)
	if err := activation.Reconcile(ctx, prepared); !errors.Is(err, context.Canceled) {
		t.Fatalf("Reconcile() error = %v, want cancellation", err)
	}
	if cleanupCanceled || restoreCanceled {
		t.Fatalf("rollback inherited canceled context: cleanup=%v restore=%v", cleanupCanceled, restoreCanceled)
	}
}

func TestOpenWrtReconcileFailsOpenOnDNSFailure(t *testing.T) {
	events := []string{}
	activation := testActivation(t, fakeGatewayController{events: &events}, fakeDNSController{events: &events, applyErr: errors.New("dns failed")})
	prepared := completePrepared(engine.CapturePlan{
		TCP: engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		UDP: engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		DNS: engine.DNSEndpoint{Enabled: true, Host: "0.0.0.0", Port: 7874},
	})
	seedActiveGatewayState(t, activation, prepared)
	if err := activation.Reconcile(context.Background(), prepared); err == nil {
		t.Fatal("DNS reconcile failure succeeded")
	}
	want := []string{"dns-backup", "gateway-apply", "dns-apply", "dns-restore", "gateway-cleanup"}
	if !slices.Equal(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	if _, err := os.Stat(activation.Layout.DNSBackup); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed reconcile retained DNS transaction: %v", err)
	}
}

func TestOpenWrtReconcileUsesPersistedActiveGenerationAfterDiskChange(t *testing.T) {
	events := []string{}
	applied := []openwrt.GatewayPlan{}
	activation := testActivation(t,
		fakeGatewayController{events: &events, appliedPlans: &applied},
		fakeDNSController{events: &events},
	)
	active := completePrepared(engine.CapturePlan{
		TCP:       engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		UDP:       engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		DNS:       engine.DNSEndpoint{Enabled: true, Host: "0.0.0.0", Port: 7874},
		TUNDevice: "clash-tun", LoopMark: 2,
	})
	if err := activation.Activate(context.Background(), active); err != nil {
		t.Fatal(err)
	}
	if err := activation.State.SaveSettings(settingsRelativePath, state.Settings{
		"PROXY_MODE": "hybrid", "ENABLE_DNS_UPSTREAM": "true",
	}); err != nil {
		t.Fatal(err)
	}
	diskGeneration := completePrepared(engine.CapturePlan{
		TCP:       engine.ProtocolCapture{Method: engine.CaptureRedirect, Port: 19093},
		UDP:       engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 19094},
		DNS:       engine.DNSEndpoint{Enabled: true, Host: "0.0.0.0", Port: 19074},
		TUNDevice: "new-tun", LoopMark: 9,
	})
	if err := activation.Reconcile(context.Background(), diskGeneration); err != nil {
		t.Fatal(err)
	}
	if len(applied) != 2 {
		t.Fatalf("applied plans = %+v", applied)
	}
	reconciled := applied[1]
	if reconciled.Mode != openwrt.ModeTPROXY || reconciled.TProxyPort != 7894 || reconciled.DNSPort != 7874 || reconciled.LoopMark != 2 {
		t.Fatalf("reconcile used unactivated disk generation: %+v", reconciled)
	}
}

func TestOpenWrtRefreshDynamicCaptureReconcilesOnlyLiveNFTSets(t *testing.T) {
	events := []string{}
	applied := []openwrt.GatewayPlan{}
	activation := testActivation(t,
		fakeGatewayController{events: &events, appliedPlans: &applied},
		fakeDNSController{events: &events},
	)
	active := completePrepared(engine.CapturePlan{
		TCP:       engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		UDP:       engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		DNS:       engine.DNSEndpoint{Enabled: true, Host: "0.0.0.0", Port: 7874},
		TUNDevice: "clash-tun", LoopMark: 2,
		Destinations:        engine.DestinationCapture{Mode: engine.DestinationCaptureAll},
		EndpointBypassCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.7/32")},
	})
	seedActiveGatewayState(t, activation, active)

	destinations := engine.DestinationCapture{
		Mode:  engine.DestinationCaptureAllowlist,
		CIDRs: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/15"), netip.MustParsePrefix("203.0.113.9/24")},
	}
	endpoints := []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")}
	refreshed, err := activation.RefreshDynamicCapture(context.Background(), destinations, endpoints)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(events, []string{"gateway-apply"}) {
		t.Fatalf("dynamic refresh touched DNS or cleanup: %v", events)
	}
	if len(applied) != 1 {
		t.Fatalf("applied plans = %+v", applied)
	}
	plan := applied[0]
	if !plan.CaptureCIDRsConfigured || !slices.Equal(plan.CaptureCIDRs, []string{"198.18.0.0/15", "203.0.113.0/24"}) {
		t.Fatalf("capture set = %+v", plan.CaptureCIDRs)
	}
	if !slices.Equal(plan.ProxyServerCIDRs, []string{"198.51.100.7/32"}) {
		t.Fatalf("endpoint bypass set = %+v", plan.ProxyServerCIDRs)
	}
	if refreshed.TCP != active.Capture.TCP || refreshed.UDP != active.Capture.UDP || refreshed.DNS != active.Capture.DNS {
		t.Fatalf("dynamic refresh changed immutable capture fields: %+v", refreshed)
	}
	persisted, err := activation.ActivePrepared(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(persisted.Capture.Destinations, destinations) || !reflect.DeepEqual(persisted.Capture.EndpointBypassCIDRs, endpoints) {
		t.Fatalf("persisted dynamic capture = %+v", persisted.Capture)
	}
}

func TestOpenWrtDiagnoseUsesPersistedActiveGenerationAfterDiskChange(t *testing.T) {
	events := []string{}
	checked := []openwrt.GatewayPlan{}
	activation := testActivation(t,
		fakeGatewayController{events: &events, checkedPlans: &checked},
		fakeDNSController{events: &events},
	)
	active := completePrepared(engine.CapturePlan{
		TCP:       engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		UDP:       engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		DNS:       engine.DNSEndpoint{Enabled: true, Host: "0.0.0.0", Port: 7874},
		TUNDevice: "clash-tun", LoopMark: 2,
	})
	if err := activation.Activate(context.Background(), active); err != nil {
		t.Fatal(err)
	}
	if err := activation.State.SaveSettings(settingsRelativePath, state.Settings{
		"PROXY_MODE": "hybrid", "ENABLE_DNS_UPSTREAM": "true",
	}); err != nil {
		t.Fatal(err)
	}
	diskGeneration := completePrepared(engine.CapturePlan{
		TCP:       engine.ProtocolCapture{Method: engine.CaptureRedirect, Port: 19093},
		UDP:       engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 19094},
		DNS:       engine.DNSEndpoint{Enabled: true, Host: "0.0.0.0", Port: 19074},
		TUNDevice: "new-tun", LoopMark: 9,
	})
	if _, err := activation.Diagnose(context.Background(), diskGeneration); err != nil {
		t.Fatal(err)
	}
	if len(checked) != 1 {
		t.Fatalf("checked plans = %+v", checked)
	}
	plan := checked[0]
	if plan.Mode != openwrt.ModeTPROXY || plan.TProxyPort != 7894 || plan.DNSPort != 7874 || plan.LoopMark != 2 {
		t.Fatalf("diagnose used unactivated disk generation: %+v", plan)
	}
}

func TestOpenWrtActivationRejectsOneShotFromDifferentDataRoot(t *testing.T) {
	firstEvents := []string{}
	secondEvents := []string{}
	first := testActivation(t, fakeGatewayController{events: &firstEvents}, fakeDNSController{events: &firstEvents})
	second := testActivation(t, fakeGatewayController{events: &secondEvents}, fakeDNSController{events: &secondEvents})
	locks, err := state.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first.Locks = locks
	second.Locks = locks
	prepared := completePrepared(engine.CapturePlan{
		TCP:       engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		UDP:       engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		TUNDevice: "clash-tun", LoopMark: 2,
	})
	if err := first.Activate(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	err = second.Deactivate(context.Background(), engine.PreparedCore{})
	if err == nil || !strings.Contains(err.Error(), "another boxctl data root") {
		t.Fatalf("different-root Deactivate() error = %v", err)
	}
	if len(secondEvents) != 0 {
		t.Fatalf("different-root one-shot mutated global state: %v", secondEvents)
	}
}

func TestOpenWrtDeactivateDoesNotRecreateClearedOwnerState(t *testing.T) {
	events := []string{}
	activation := testActivation(t, fakeGatewayController{events: &events}, fakeDNSController{events: &events})
	if err := claimOpenWrtOwnerState(context.Background(), activation.Locks, activation.State.Root); err != nil {
		t.Fatal(err)
	}
	if err := clearOpenWrtOwnerState(context.Background(), activation.Locks, activation.State.Root); err != nil {
		t.Fatal(err)
	}
	if err := activation.Deactivate(context.Background(), engine.PreparedCore{}); err != nil {
		t.Fatal(err)
	}
	if _, err := activation.Locks.Read(openWrtOwnerStatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanup recreated owner state: %v", err)
	}
}

func TestOpenWrtActivationUsesGlobalInterprocessTransactionLockAcrossDataRoots(t *testing.T) {
	firstEvents := []string{}
	secondEvents := []string{}
	lockRoot := t.TempDir()
	first := testActivation(t, fakeGatewayController{events: &firstEvents}, fakeDNSController{events: &firstEvents})
	second := testActivation(t, fakeGatewayController{events: &secondEvents}, fakeDNSController{events: &secondEvents})
	locks, err := state.NewStore(lockRoot)
	if err != nil {
		t.Fatal(err)
	}
	first.Locks = locks
	second.Locks = locks
	if first.State.Root == second.State.Root || first.Locks.Root != second.Locks.Root {
		t.Fatalf("test roots are not isolated: first=%q second=%q locks=%q", first.State.Root, second.State.Root, first.Locks.Root)
	}
	lock, err := first.Locks.Lock(context.Background(), "gateway-dns")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Unlock() }()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	err = second.Activate(ctx, engine.PreparedCore{Capture: engine.CapturePlan{
		TCP: engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		UDP: engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		DNS: engine.DNSEndpoint{Enabled: true, Host: "0.0.0.0", Port: 7874},
	}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Activate() lock error = %v", err)
	}
	if len(firstEvents) != 0 || len(secondEvents) != 0 {
		t.Fatalf("transaction ran without global cross-process lock: first=%v second=%v", firstEvents, secondEvents)
	}
}

func TestOpenWrtDeactivateRetainsDNSBackupUntilRestoreSucceeds(t *testing.T) {
	events := []string{}
	restoreErr := errors.New("dnsmasq restart failed")
	activation := testActivation(t,
		fakeGatewayController{events: &events},
		fakeDNSController{events: &events, restoreErr: &restoreErr},
	)
	if _, _, err := activation.ensureDNSBackup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := activation.Deactivate(context.Background(), engine.PreparedCore{}); !errors.Is(err, restoreErr) {
		t.Fatalf("first Deactivate() error = %v, want restore failure", err)
	}
	if _, err := os.Stat(activation.Layout.DNSBackup); err != nil {
		t.Fatalf("failed restore removed its durable backup: %v", err)
	}
	restoreErr = nil
	if err := activation.Deactivate(context.Background(), engine.PreparedCore{}); err != nil {
		t.Fatalf("retry Deactivate() error = %v", err)
	}
	if _, err := os.Stat(activation.Layout.DNSBackup); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful restore retained backup: %v", err)
	}
}

func TestOpenWrtDeactivateFallsBackWhenSettingsAreInvalid(t *testing.T) {
	events := []string{}
	activation := testActivation(t, fakeGatewayController{events: &events}, fakeDNSController{events: &events})
	settingsPath := filepath.Join(activation.Layout.Root, ".boxctl", "settings")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte("PROXY_MODE=not-a-mode\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prepared := engine.PreparedCore{Capture: engine.CapturePlan{TUNDevice: "clash-tun", LoopMark: 2}}
	if err := activation.Deactivate(context.Background(), prepared); err != nil {
		t.Fatalf("Deactivate() with invalid settings = %v", err)
	}
	if !slices.Equal(events, []string{"gateway-cleanup"}) {
		t.Fatalf("fallback cleanup events = %v", events)
	}
}

func TestOpenWrtDeactivateUsesPersistedPlanWithoutTopologyDiscovery(t *testing.T) {
	events := []string{}
	var detectErr error
	activation := testActivation(t,
		fakeGatewayController{events: &events, detectErr: &detectErr},
		fakeDNSController{events: &events},
	)
	prepared := completePrepared(engine.CapturePlan{
		TCP:       engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		UDP:       engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		TUNDevice: "clash-tun", LoopMark: 2,
	})
	seedActiveGatewayState(t, activation, prepared)
	detectErr = errors.New("WAN topology unavailable")
	if err := activation.Deactivate(context.Background(), engine.PreparedCore{}); err != nil {
		t.Fatalf("Deactivate() rediscovered topology during cleanup: %v", err)
	}
	if !slices.Equal(events, []string{"gateway-cleanup"}) {
		t.Fatalf("cleanup events = %v", events)
	}
}
