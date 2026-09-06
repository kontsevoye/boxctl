package app

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/rulelist"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

func TestLegacyProxySubscriptionsDefaultToMihomo(t *testing.T) {
	service, err := NewProxySubscriptionsService(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`{
  "schema": 1,
  "items": [{
    "id": "0123456789abcdef01234567",
    "name": "Legacy",
    "enabled": true,
    "shareLinks": "trojan://secret@proxy.example:443#Legacy",
    "updateIntervalHours": 24
  }]
}`)
	if err := service.State.Write(proxySubscriptionsPath, legacy, 0o600); err != nil {
		t.Fatal(err)
	}

	items, err := service.ProxySubscriptions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Engine != state.EngineMihomo {
		t.Fatalf("legacy subscriptions = %+v, want one Mihomo resource", items)
	}
	providers, err := service.EnabledProviderSpecs()
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 1 || providers[0].Name != providerName(items[0].ID) {
		t.Fatalf("legacy providers = %+v", providers)
	}
}

func TestProxySubscriptionDraftEngineRoundTripsAndRejectsSingBoxWithoutRestart(t *testing.T) {
	service, err := NewProxySubscriptionsService(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	restarts := 0
	service.OnChanged = func(context.Context) error {
		restarts++
		return nil
	}

	created, err := service.CreateProxySubscription(context.Background(), web.ProxySubscriptionDraft{
		Engine: state.EngineMihomo, Name: "Mihomo", ShareLinks: "trojan://secret@proxy.example:443#Mihomo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Engine != state.EngineMihomo || restarts != 1 {
		t.Fatalf("created = %+v, restarts = %d", created, restarts)
	}

	_, err = service.CreateProxySubscription(context.Background(), web.ProxySubscriptionDraft{
		Engine: state.EngineSingBox, Name: "sing-box", ShareLinks: "trojan://secret@proxy.example:443#Sing",
	})
	assertResourcePublicError(t, err, http.StatusConflict, "subscription_engine_unsupported")
	if restarts != 1 {
		t.Fatalf("unsupported sing-box subscription restarted runtime: %d", restarts)
	}
	items, listErr := service.ProxySubscriptions(context.Background())
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(items) != 1 {
		t.Fatalf("unsupported sing-box subscription was stored: %+v", items)
	}
}

func TestRuleListDraftEngineRoundTripsAndRejectsSingBoxWithoutReload(t *testing.T) {
	root := t.TempDir()
	reloads := 0
	service := RuleListService{
		Store: &rulelist.Store{Directory: filepath.Join(root, "local-rules")},
		Config: &ConfigService{OnReload: func(context.Context) (bool, error) {
			reloads++
			return true, nil
		}},
	}

	created, err := service.CreateRuleList(context.Background(), web.RuleListDraft{
		Engine: state.EngineMihomo, Name: "mihomo-list", Format: "text", Content: "192.0.2.0/24\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Engine != state.EngineMihomo {
		t.Fatalf("created rule list = %+v", created)
	}

	_, err = service.CreateRuleList(context.Background(), web.RuleListDraft{
		Engine: state.EngineSingBox, Name: "sing-box-list", Format: "text", Content: "example.com\n",
	})
	assertResourcePublicError(t, err, http.StatusConflict, "rule_list_engine_unsupported")
	if reloads != 0 {
		t.Fatalf("unsupported sing-box rule list reloaded runtime: %d", reloads)
	}
	lists, listErr := service.Store.List()
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(lists) != 1 {
		t.Fatalf("unsupported sing-box rule list was stored: %+v", lists)
	}
}

func TestMihomoRuleListMutationDoesNotReloadSelectedSingBox(t *testing.T) {
	root := t.TempDir()
	profiles, err := state.NewProfileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	selected := state.ActiveProfile{Name: "selected", Engine: state.EngineSingBox}
	if err := profiles.Create(context.Background(), selected, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Activate(context.Background(), selected); err != nil {
		t.Fatal(err)
	}
	preparer, err := NewActiveMihomoPreparer(root, &recordingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	reloads := 0
	configService := &ConfigService{
		Preparer: preparer,
		OnReload: func(context.Context) (bool, error) {
			reloads++
			return true, nil
		},
	}
	service := RuleListService{
		Store:  &rulelist.Store{Directory: filepath.Join(root, "local-rules")},
		Config: configService,
	}
	created, err := service.CreateRuleList(context.Background(), web.RuleListDraft{
		Engine: state.EngineMihomo, Name: "offline-mihomo", Format: "text", Content: "192.0.2.0/24\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	content := "198.51.100.0/24\n"
	if _, err := service.UpdateRuleList(context.Background(), created.ID, web.RuleListUpdate{
		Content: &content, Revision: created.Revision,
	}); err != nil {
		t.Fatal(err)
	}
	if reloads != 0 {
		t.Fatalf("offline Mihomo rule mutation reloaded selected sing-box: %d", reloads)
	}
	if _, err := service.AddRuleListToConfig(context.Background(), created.ID); err == nil {
		t.Fatal("Mihomo rule list was attached to a sing-box profile")
	} else {
		assertResourcePublicError(t, err, http.StatusConflict, "rule_list_engine_mismatch")
	}
}

func TestFakeIPResourceIsMihomoScoped(t *testing.T) {
	policy := fakeIPCapturePolicy{Applicable: true}
	lifecycle := &Lifecycle{snap: LifecycleSnapshot{
		State: LifecycleRunning,
		Prepared: engine.PreparedCore{
			Engine: state.EngineSingBox,
			Capture: engine.CapturePlan{
				Destinations: engine.DestinationCapture{Mode: engine.DestinationCaptureAll},
			},
		},
	}}
	service := &FakeIPWhitelistService{Lifecycle: lifecycle}
	document := service.webDocument(policy)
	if document.Engine != state.EngineMihomo {
		t.Fatalf("fake-IP engine = %q, want %q", document.Engine, state.EngineMihomo)
	}
	if document.Applied || document.RestartRequired {
		t.Fatalf("Mihomo fake-IP resource was compared with sing-box runtime: %+v", document)
	}
	if err := service.restartRunning(context.Background()); err != nil {
		t.Fatalf("offline Mihomo fake-IP resource restarted sing-box: %v", err)
	}
	if snapshot := lifecycle.Snapshot(); snapshot.State != LifecycleRunning || snapshot.Prepared.Engine != state.EngineSingBox {
		t.Fatalf("sing-box lifecycle changed: %+v", snapshot)
	}
}

func TestPeriodicMihomoResourceMaintenanceSkipsRunningSingBox(t *testing.T) {
	lifecycle := &Lifecycle{snap: LifecycleSnapshot{
		State:    LifecycleRunning,
		Prepared: engine.PreparedCore{Engine: state.EngineSingBox},
	}}
	activation := &maintenanceActivationStub{}
	service := NewPeriodicMaintenance(state.Store{}, &ActiveMihomoPreparer{}, lifecycle, activation, nil)
	if err := service.Refresh(context.Background(), DefaultRuntimeSettings()); err != nil {
		t.Fatal(err)
	}
	if activation.calls != 0 {
		t.Fatalf("Mihomo maintenance touched running sing-box: %d calls", activation.calls)
	}
	if snapshot := lifecycle.Snapshot(); snapshot.State != LifecycleRunning || snapshot.Prepared.Engine != state.EngineSingBox {
		t.Fatalf("sing-box lifecycle changed: %+v", snapshot)
	}
}

func TestEngineCatalogAdvertisesOnlyImplementedResourceManagement(t *testing.T) {
	root := t.TempDir()
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := state.NewProfileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(layout.EnginesDir, state.EngineMihomo), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout.EnginesDir, state.EngineMihomo, "mihomo"), []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}

	catalog := &EngineCatalogService{
		Layout: layout, Profiles: profiles, UnsafeExternalDashboard: true,
	}
	engines, err := catalog.Engines(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(engines) != 2 {
		t.Fatalf("engines = %+v", engines)
	}
	byID := make(map[string]web.EngineInfo, len(engines))
	for _, item := range engines {
		byID[item.ID] = item
	}
	mihomo := byID[state.EngineMihomo].Management
	if !mihomo.RemoteProfiles || !mihomo.ProxySubscriptions || !mihomo.LocalRuleLists || !mihomo.FakeIPCapture || !mihomo.Updates || !mihomo.ExternalDashboard {
		t.Fatalf("Mihomo management capabilities = %+v", mihomo)
	}
	singBox := byID[state.EngineSingBox].Management
	if !singBox.RemoteProfiles || !singBox.Updates || !singBox.ExternalDashboard || singBox.ProxySubscriptions || singBox.LocalRuleLists || singBox.FakeIPCapture {
		t.Fatalf("sing-box management capabilities overclaim support = %+v", singBox)
	}
}

func assertResourcePublicError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var public *web.PublicError
	if !errors.As(err, &public) {
		t.Fatalf("error = %v, want *web.PublicError", err)
	}
	if public.Status != status || public.Code != code {
		t.Fatalf("public error = %+v, want status %d code %q", public, status, code)
	}
}
