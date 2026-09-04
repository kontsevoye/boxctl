package app

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/fakeip"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

const fakeIPServiceSelectiveConfig = `mode: rule
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/15
  fake-ip-filter-mode: whitelist
`

const fakeIPServiceRegenerationConfig = `mode: rule
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/15
  fake-ip-filter-mode: whitelist
rules:
  - IP-CIDR,203.0.113.7/24,PROXY
  - IP-CIDR,192.0.2.1/32,DIRECT
  - RULE-SET,inline-proxy,PROXY
rule-providers:
  inline-proxy:
    type: inline
    behavior: ipcidr
    payload:
      - 198.51.100.99/24
`

const fakeIPServiceBlacklistConfig = `mode: rule
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.0/15
  fake-ip-filter-mode: blacklist
`

var fakeIPServiceGeneratedAt = time.Date(2026, time.August, 25, 19, 46, 20, 0, time.UTC)

type fakeIPServiceFixture struct {
	service *FakeIPWhitelistService
	manager *FakeIPCaptureManager
	store   *fakeip.Store
	source  []byte
}

func newFakeIPServiceFixture(t *testing.T, source string) fakeIPServiceFixture {
	t.Helper()
	root := t.TempDir()
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := state.NewProfileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	stateStore, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.MihomoConfig, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	store := &fakeip.Store{Directory: layout.LocalRulesDir}
	manager := &FakeIPCaptureManager{
		Layout: layout,
		Store:  store,
		Now:    func() time.Time { return fakeIPServiceGeneratedAt },
	}
	preparer := &ActiveMihomoPreparer{
		Layout:   layout,
		Profiles: profiles,
		State:    stateStore,
		FakeIP:   manager,
	}
	return fakeIPServiceFixture{
		service: &FakeIPWhitelistService{Manager: manager, Preparer: preparer},
		manager: manager,
		store:   store,
		source:  []byte(source),
	}
}

type fakeIPServiceLifecycleFake struct {
	mu       sync.Mutex
	events   []string
	prepared engine.PreparedCore
	health   engine.HealthStatus
	startErr error
}

func (fake *fakeIPServiceLifecycleFake) record(event string) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.events = append(fake.events, event)
}

func (fake *fakeIPServiceLifecycleFake) PrepareActive(context.Context) (engine.PreparedCore, error) {
	fake.record("prepare")
	return fake.prepared, nil
}

func (fake *fakeIPServiceLifecycleFake) Start(context.Context, engine.PreparedCore) error {
	fake.record("core-start")
	if fake.startErr != nil {
		return fake.startErr
	}
	fake.mu.Lock()
	fake.health.Running = true
	fake.health.ControllerReady = true
	fake.mu.Unlock()
	return nil
}

func (fake *fakeIPServiceLifecycleFake) Stop(context.Context) error {
	fake.record("core-stop")
	fake.mu.Lock()
	fake.health.Running = false
	fake.health.ControllerReady = false
	fake.mu.Unlock()
	return nil
}

func (fake *fakeIPServiceLifecycleFake) Health(context.Context) (engine.HealthStatus, error) {
	fake.record("health")
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.health, nil
}

func (fake *fakeIPServiceLifecycleFake) Activate(context.Context, engine.PreparedCore) error {
	fake.record("gateway-activate")
	return nil
}

func (fake *fakeIPServiceLifecycleFake) Deactivate(context.Context, engine.PreparedCore) error {
	fake.record("gateway-deactivate")
	return nil
}

func (fake *fakeIPServiceLifecycleFake) recordedEvents() []string {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]string(nil), fake.events...)
}

func fakeIPServiceRunningLifecycle(prepared engine.PreparedCore) (*Lifecycle, *fakeIPServiceLifecycleFake) {
	health := engine.HealthStatus{Running: true, ControllerReady: true, PID: 42, CheckedAt: fakeIPServiceGeneratedAt}
	fake := &fakeIPServiceLifecycleFake{prepared: prepared, health: health}
	return &Lifecycle{
		Preparer:          fake,
		Core:              fake,
		Activation:        fake,
		ReadyTimeout:      time.Second,
		ReadyPollInterval: time.Millisecond,
		snap: LifecycleSnapshot{
			State:     LifecycleRunning,
			Prepared:  engine.PreparedCore{Engine: "mihomo", BinaryPath: "/fake/old-core"},
			Health:    health,
			StartedAt: fakeIPServiceGeneratedAt.Add(-time.Hour),
		},
	}, fake
}

func fakeIPServiceCapture(prefixes ...string) engine.CapturePlan {
	cidrs := make([]netip.Prefix, len(prefixes))
	for index, prefix := range prefixes {
		cidrs[index] = netip.MustParsePrefix(prefix)
	}
	return engine.CapturePlan{Destinations: engine.DestinationCapture{
		Mode:  engine.DestinationCaptureAllowlist,
		CIDRs: cidrs,
	}}
}

func fakeIPServiceRead(t *testing.T, store *fakeip.Store) fakeip.Document {
	t.Helper()
	document, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func fakeIPServiceAssertPublicError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var public *web.PublicError
	if !errors.As(err, &public) {
		t.Fatalf("error = %v, want *web.PublicError", err)
	}
	if public.Status != status || public.Code != code {
		t.Fatalf("public error = %#v, want status %d code %q", public, status, code)
	}
}

func TestFakeIPWhitelistServiceDocumentReportsCaptureApplication(t *testing.T) {
	fixture := newFakeIPServiceFixture(t, fakeIPServiceSelectiveConfig)
	current := fakeIPServiceRead(t, fixture.store)
	manual, err := fixture.store.SaveManual("# operator-owned\n203.0.113.7\n", current.Revision)
	if err != nil {
		t.Fatal(err)
	}
	generated, err := fixture.store.ReplaceGenerated(
		[]netip.Prefix{netip.MustParsePrefix("192.0.2.99/24")},
		manual.Revision,
		fakeIPServiceGeneratedAt,
	)
	if err != nil {
		t.Fatal(err)
	}

	matchingCapture := fakeIPServiceCapture("192.0.2.0/24", "198.18.0.0/15", "203.0.113.7/32")
	fixture.service.Lifecycle = &Lifecycle{snap: LifecycleSnapshot{
		State: LifecycleRunning,
		Prepared: engine.PreparedCore{
			Capture: matchingCapture,
		},
	}}
	document, err := fixture.service.FakeIPWhitelist(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantGenerated := []string{"192.0.2.0/24"}
	wantFakeRanges := []string{"198.18.0.0/15"}
	wantEffective := []string{"192.0.2.0/24", "198.18.0.0/15", "203.0.113.7/32"}
	if document.ManualContent != "# operator-owned\n203.0.113.7\n" ||
		!reflect.DeepEqual(document.GeneratedCIDRs, wantGenerated) ||
		!reflect.DeepEqual(document.FakeIPRanges, wantFakeRanges) ||
		!reflect.DeepEqual(document.EffectiveCIDRs, wantEffective) {
		t.Fatalf("document CIDRs = %#v", document)
	}
	if document.ManualCount != 1 || document.GeneratedCount != 1 || document.EffectiveCount != 3 {
		t.Fatalf("document counts = manual %d generated %d effective %d", document.ManualCount, document.GeneratedCount, document.EffectiveCount)
	}
	if document.Revision != generated.Revision || document.GeneratedAt == nil || !document.GeneratedAt.Equal(fakeIPServiceGeneratedAt) {
		t.Fatalf("document metadata = revision %q generatedAt %v", document.Revision, document.GeneratedAt)
	}
	if !document.Applicable || !document.Selective || !document.Applied || document.RestartRequired || len(document.Warnings) != 0 {
		t.Fatalf("document state = %#v", document)
	}

	fixture.service.Lifecycle.mu.Lock()
	fixture.service.Lifecycle.snap.Prepared.Capture = fakeIPServiceCapture("198.18.0.0/15")
	fixture.service.Lifecycle.mu.Unlock()
	staleRuntime, err := fixture.service.FakeIPWhitelist(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if staleRuntime.Applied || !staleRuntime.RestartRequired {
		t.Fatalf("stale runtime state = %#v", staleRuntime)
	}
}

func TestFakeIPWhitelistServiceUpdateRestartsRunningLifecycle(t *testing.T) {
	fixture := newFakeIPServiceFixture(t, fakeIPServiceSelectiveConfig)
	before := fakeIPServiceRead(t, fixture.store)
	prepared := engine.PreparedCore{
		Engine:     "mihomo",
		BinaryPath: "/fake/new-core",
		Capture:    fakeIPServiceCapture("198.18.0.0/15", "203.0.113.7/32"),
	}
	lifecycle, runtime := fakeIPServiceRunningLifecycle(prepared)
	lifecycle.snap.Prepared.Capture = fakeIPServiceCapture("198.18.0.0/15")
	fixture.service.Lifecycle = lifecycle

	document, err := fixture.service.UpdateFakeIPWhitelist(context.Background(), web.FakeIPWhitelistUpdate{
		ManualContent: "203.0.113.7\n",
		Revision:      before.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if document.Revision == before.Revision || document.ManualContent != "203.0.113.7\n" || document.ManualCount != 1 {
		t.Fatalf("updated document = %#v", document)
	}
	if !document.Applied || document.RestartRequired {
		t.Fatalf("updated document was not applied = %#v", document)
	}
	wantEvents := []string{"gateway-deactivate", "core-stop", "prepare", "core-start", "health", "gateway-activate", "health"}
	if got := runtime.recordedEvents(); !reflect.DeepEqual(got, wantEvents) {
		t.Fatalf("restart events = %v, want %v", got, wantEvents)
	}
	if got := fakeIPServiceRead(t, fixture.store); got.ManualContent != "203.0.113.7\n" {
		t.Fatalf("stored manual content = %q", got.ManualContent)
	}

	eventCount := len(runtime.recordedEvents())
	_, err = fixture.service.UpdateFakeIPWhitelist(context.Background(), web.FakeIPWhitelistUpdate{
		ManualContent: "198.51.100.0/24\n",
		Revision:      before.Revision,
	})
	if !errors.Is(err, web.ErrConflict) {
		t.Fatalf("stale update error = %v, want web.ErrConflict", err)
	}
	fakeIPServiceAssertPublicError(t, err, http.StatusConflict, "conflict")
	if got := len(runtime.recordedEvents()); got != eventCount {
		t.Fatalf("stale update triggered lifecycle events: before %d after %d", eventCount, got)
	}

	_, err = fixture.service.UpdateFakeIPWhitelist(context.Background(), web.FakeIPWhitelistUpdate{
		ManualContent: "not-an-ip\n",
		Revision:      document.Revision,
	})
	fakeIPServiceAssertPublicError(t, err, http.StatusBadRequest, "invalid_fakeip_destinations")
	if got := len(runtime.recordedEvents()); got != eventCount {
		t.Fatalf("invalid update triggered lifecycle events: before %d after %d", eventCount, got)
	}
}

func TestFakeIPWhitelistServiceRegenerateRestartsAndReturnsFinalDocument(t *testing.T) {
	fixture := newFakeIPServiceFixture(t, fakeIPServiceRegenerationConfig)
	before := fakeIPServiceRead(t, fixture.store)
	prepared := engine.PreparedCore{
		Engine:     "mihomo",
		BinaryPath: "/fake/new-core",
		Capture: fakeIPServiceCapture(
			"198.18.0.0/15",
			"198.51.100.0/24",
			"203.0.113.0/24",
		),
	}
	lifecycle, runtime := fakeIPServiceRunningLifecycle(prepared)
	lifecycle.snap.Prepared.Capture = fakeIPServiceCapture("198.18.0.0/15")
	fixture.service.Lifecycle = lifecycle

	document, err := fixture.service.RegenerateFakeIPWhitelist(context.Background(), before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	wantGenerated := []string{"198.51.100.0/24", "203.0.113.0/24"}
	if !reflect.DeepEqual(document.GeneratedCIDRs, wantGenerated) || document.GeneratedCount != 2 {
		t.Fatalf("generated document = %#v", document)
	}
	if document.GeneratedAt == nil || !document.GeneratedAt.Equal(fakeIPServiceGeneratedAt) || document.Revision == before.Revision {
		t.Fatalf("generated metadata = revision %q timestamp %v", document.Revision, document.GeneratedAt)
	}
	if !document.Applied || document.RestartRequired {
		t.Fatalf("regenerated document was not applied = %#v", document)
	}
	wantEvents := []string{"gateway-deactivate", "core-stop", "prepare", "core-start", "health", "gateway-activate", "health"}
	if got := runtime.recordedEvents(); !reflect.DeepEqual(got, wantEvents) {
		t.Fatalf("restart events = %v, want %v", got, wantEvents)
	}

	eventCount := len(runtime.recordedEvents())
	_, err = fixture.service.RegenerateFakeIPWhitelist(context.Background(), before.Revision)
	if !errors.Is(err, web.ErrConflict) {
		t.Fatalf("stale regenerate error = %v, want web.ErrConflict", err)
	}
	fakeIPServiceAssertPublicError(t, err, http.StatusConflict, "conflict")
	if got := len(runtime.recordedEvents()); got != eventCount {
		t.Fatalf("stale regenerate triggered lifecycle events: before %d after %d", eventCount, got)
	}
}

func TestFakeIPWhitelistServiceRegenerateHonorsExternalIPProviderInclusionSetting(t *testing.T) {
	providerRoot := t.TempDir()
	providerPath := providerRoot + "/geo-ip.yaml"
	if err := os.WriteFile(providerPath, []byte("payload:\n  - 203.0.113.99/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := `mode: rule
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
rules:
  - RULE-SET,geo-ip,PROXY
rule-providers:
  geo-ip:
    type: http
    behavior: ipcidr
    format: yaml
    url: https://rules.example.invalid/geo-ip.yaml
    path: ` + providerPath + "\n"
	fixture := newFakeIPServiceFixture(t, source)
	fixture.manager.TrustedProviderCacheRoots = []string{providerRoot}
	if err := fixture.service.Preparer.State.SaveSettings(settingsRelativePath, state.Settings{
		"AUTO_FAKEIP_INCLUDE_EXTERNAL_IP_PROVIDERS": "true",
	}); err != nil {
		t.Fatal(err)
	}
	before := fakeIPServiceRead(t, fixture.store)
	document, err := fixture.service.RegenerateFakeIPWhitelist(context.Background(), before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"203.0.113.0/24"}; !reflect.DeepEqual(document.GeneratedCIDRs, want) {
		t.Fatalf("generated CIDRs = %v, want %v", document.GeneratedCIDRs, want)
	}
}

func TestFakeIPWhitelistServiceDoesNotApplyIncompatibleMode(t *testing.T) {
	fixture := newFakeIPServiceFixture(t, fakeIPServiceBlacklistConfig)
	before := fakeIPServiceRead(t, fixture.store)
	lifecycle, runtime := fakeIPServiceRunningLifecycle(engine.PreparedCore{
		Engine:     "mihomo",
		BinaryPath: "/fake/core",
		Capture:    fakeIPServiceCapture("198.18.0.0/15"),
	})
	lifecycle.snap.Prepared.Capture = fakeIPServiceCapture("198.18.0.0/15")
	fixture.service.Lifecycle = lifecycle

	document, err := fixture.service.UpdateFakeIPWhitelist(context.Background(), web.FakeIPWhitelistUpdate{
		ManualContent: "203.0.113.0/24\n",
		Revision:      before.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if document.Applicable || !document.Selective || !document.Applied || document.RestartRequired {
		t.Fatalf("blacklist document state = %#v", document)
	}
	if got := runtime.recordedEvents(); len(got) != 0 {
		t.Fatalf("incompatible update restarted runtime: %v", got)
	}

	stored := fakeIPServiceRead(t, fixture.store)
	_, err = fixture.service.RegenerateFakeIPWhitelist(context.Background(), stored.Revision)
	fakeIPServiceAssertPublicError(t, err, http.StatusConflict, "fakeip_mode_not_applicable")
	if got := runtime.recordedEvents(); len(got) != 0 {
		t.Fatalf("incompatible regeneration restarted runtime: %v", got)
	}
}
