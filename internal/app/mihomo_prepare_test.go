package app

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	configpkg "github.com/kontsevoye/boxctl/internal/config"
	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/fakeip"
	"github.com/kontsevoye/boxctl/internal/state"
)

type recordingConfig struct {
	request engine.PrepareRequest
	source  []byte
	err     error
}

func (config *recordingConfig) Prepare(_ context.Context, request engine.PrepareRequest) (engine.PreparedCore, error) {
	config.request = request
	config.source, config.err = os.ReadFile(request.SourceConfigPath)
	if config.err != nil {
		return engine.PreparedCore{}, config.err
	}
	return engine.PreparedCore{Engine: "mihomo", SourceConfigPath: request.SourceConfigPath, Capture: request.Capture, Controller: request.Controller}, nil
}

func (*recordingConfig) Validate(context.Context, engine.PreparedCore) error { return nil }

func TestActiveMihomoPreparerPreservesManagedValues(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{"engines/mihomo", ".boxctl", "configs"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(root, "engines", "mihomo", "mihomo")
	if err := os.WriteFile(binary, []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	configuration := `external-controller: 0.0.0.0:9090
secret: keep-me
routing-mark: 2
tproxy-port: 17894
dns:
  enable: true
  listen: 0.0.0.0:17874
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.0/15
`
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSettings(settingsRelativePath, state.Settings{"PROXY_MODE": "tproxy"}); err != nil {
		t.Fatal(err)
	}
	recorder := &recordingConfig{}
	preparer, err := NewActiveMihomoPreparer(root, recorder)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := preparer.PrepareActive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Capture.TCP.Port != 17894 || prepared.Capture.DNS.Port != 17874 || len(prepared.Capture.FakeIPRanges) != 1 {
		t.Fatalf("capture = %+v", prepared.Capture)
	}
	if len(prepared.Capture.TUNAddresses) != 0 || prepared.Capture.TUNMTU != 0 {
		t.Fatalf("Mihomo capture unexpectedly contains sing-box TUN settings: %+v", prepared.Capture)
	}
	if recorder.request.Controller.Secret != "keep-me" || recorder.request.Controller.Listen != defaultMihomoControllerListen {
		t.Fatalf("controller = %+v", recorder.request.Controller)
	}
	originalPath := filepath.Join(root, "config.yaml")
	if recorder.request.SourceConfigPath == originalPath || !strings.HasPrefix(filepath.Base(recorder.request.SourceConfigPath), "boxctl-mihomo-source-") {
		t.Fatalf("driver source snapshot = %s", recorder.request.SourceConfigPath)
	}
	if !bytes.Equal(recorder.source, []byte(configuration)) {
		t.Fatalf("driver source snapshot = %q, want exact original config", recorder.source)
	}
	if prepared.SourceConfigPath != originalPath {
		t.Fatalf("prepared source = %s, want %s", prepared.SourceConfigPath, originalPath)
	}
	if prepared.SourceRevision != contentRevision([]byte(configuration)) {
		t.Fatalf("prepared source revision = %q", prepared.SourceRevision)
	}
}

func TestManagedRuntimeSettingsUsesMihomoFakeIPDefault(t *testing.T) {
	t.Parallel()
	enabled := true
	mode := "fake-ip"
	settings, err := managedRuntimeSettings(configpkg.MihomoManagedValues{
		DNSEnabled:      &enabled,
		DNSEnhancedMode: &mode,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix(defaultMihomoFakeIPRange)}
	if !reflect.DeepEqual(settings.FakeIPRanges, want) {
		t.Fatalf("fake-IP ranges = %v, want %v", settings.FakeIPRanges, want)
	}
}

func TestActiveMihomoPreparerHonorsExternalIPProviderInclusionSetting(t *testing.T) {
	root := t.TempDir()
	providerRoot := filepath.Join(root, "provider-cache")
	for _, directory := range []string{"engines/mihomo", ".boxctl", "provider-cache"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "engines", "mihomo", "mihomo"), []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	providerPath := filepath.Join(providerRoot, "geo-ip.yaml")
	if err := os.WriteFile(providerPath, []byte("payload:\n  - 203.0.113.99/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configuration := `mode: rule
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
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSettings(settingsRelativePath, state.Settings{
		"AUTO_FAKEIP_WHITELIST":                     "true",
		"AUTO_FAKEIP_INCLUDE_EXTERNAL_IP_PROVIDERS": "true",
	}); err != nil {
		t.Fatal(err)
	}
	recorder := &recordingConfig{}
	preparer, err := NewActiveMihomoPreparer(root, recorder)
	if err != nil {
		t.Fatal(err)
	}
	preparer.FakeIP.TrustedProviderCacheRoots = []string{providerRoot}
	prepared, err := preparer.PrepareActive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}
	if !reflect.DeepEqual(prepared.Capture.Destinations.CIDRs, want) {
		t.Fatalf("capture destinations = %v, want %v", prepared.Capture.Destinations.CIDRs, want)
	}
}

func TestActiveMihomoPreparerDefaultsControllerToLoopback(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "engines", "mihomo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "engines", "mihomo", "mihomo"), []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte("mixed-port: 7890\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recorder := &recordingConfig{}
	preparer, err := NewActiveMihomoPreparer(root, recorder)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := preparer.PrepareActive(context.Background()); err != nil {
		t.Fatal(err)
	}
	if recorder.request.Controller.Listen != defaultMihomoControllerListen || recorder.request.Controller.Secret != "" {
		t.Fatalf("default controller = %+v", recorder.request.Controller)
	}
}

func TestActiveMihomoPreparerPopulatesEndpointBypassCapture(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "engines", "mihomo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "engines", "mihomo", "mihomo"), []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	configuration := []byte(`
proxies:
  - name: remote
    server: node.example
proxy-providers:
  remote:
    type: http
    url: https://providers.example/private/subscription.yaml?token=secret
rule-providers:
  remote:
    type: http
    behavior: ipcidr
    url: https://rules.example/private/rules.mrs?token=secret
rules:
  - MATCH,DIRECT
`)
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), configuration, 0o600); err != nil {
		t.Fatal(err)
	}
	recorder := &recordingConfig{}
	preparer, err := NewActiveMihomoPreparer(root, recorder)
	if err != nil {
		t.Fatal(err)
	}
	preparer.Endpoints.Resolver = &endpointResolverStub{addresses: map[string][]netip.Addr{
		"node.example":      {netip.MustParseAddr("192.0.2.7")},
		"providers.example": {netip.MustParseAddr("198.51.100.7")},
		"rules.example":     {netip.MustParseAddr("203.0.113.7")},
	}, errors: map[string]error{}}
	prepared, err := preparer.PrepareActive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.7/32"),
		netip.MustParsePrefix("198.51.100.7/32"),
		netip.MustParsePrefix("203.0.113.7/32"),
	}
	if !reflect.DeepEqual(prepared.Capture.EndpointBypassCIDRs, want) {
		t.Fatalf("endpoint bypass capture = %v, want %v", prepared.Capture.EndpointBypassCIDRs, want)
	}
}

func TestActiveMihomoExplicitPreflightStagesSharedAUTOAndEndpointLKG(t *testing.T) {
	fixture := newMihomoPreflightStateFixture(t)
	ctx := context.Background()

	prepared, err := fixture.preparer.PrepareProfile(ctx, fixture.target)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.CleanupPreparedRuntime(prepared)
	if got := endpointPrefixStrings(prepared.Capture.Destinations.CIDRs); !reflect.DeepEqual(got, []string{"198.18.0.0/15", "203.0.113.0/24"}) {
		t.Fatalf("staged fake-IP capture = %v", got)
	}
	if got := endpointPrefixStrings(prepared.Capture.EndpointBypassCIDRs); !reflect.DeepEqual(got, []string{"198.51.100.7/32"}) {
		t.Fatalf("staged endpoint bypass = %v", got)
	}
	fixture.assertSharedStateUnchanged(t)

	if err := fixture.profiles.Activate(ctx, fixture.target); err != nil {
		t.Fatal(err)
	}
	dispatcher := &EnginePreparer{Profiles: fixture.profiles, Preparers: map[string]ExplicitProfilePreparer{
		state.EngineMihomo: fixture.preparer,
	}}
	active, err := dispatcher.PrepareActive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.CleanupPreparedRuntime(active)
	if current := fixture.readFakeIPState(t); bytes.Equal(current, fixture.fakeIPBefore) {
		t.Fatal("active preparation did not publish the candidate AUTO fake-IP state")
	}
	if current := fixture.readEndpointState(t); bytes.Equal(current, fixture.endpointBefore) {
		t.Fatal("active preparation did not publish the candidate endpoint LKG state")
	}
}

func TestFailedMihomoProfileSwitchLeavesSharedAUTOAndEndpointLKGUntouched(t *testing.T) {
	fixture := newMihomoPreflightStateFixture(t)
	ctx := context.Background()
	enginePreparer := &EnginePreparer{Profiles: fixture.profiles, Preparers: map[string]ExplicitProfilePreparer{
		state.EngineMihomo: fixture.preparer,
	}}
	lifecycle := &Lifecycle{
		Preparer: enginePreparer, Core: profileSwitchCore{}, Activation: profileSwitchActivation{},
		snap: LifecycleSnapshot{State: LifecycleStopped},
	}
	switcher := &ProfileSwitcher{
		State: fixture.store, Profiles: fixture.profiles, Preparer: enginePreparer, Lifecycle: lifecycle,
		Revisions: &recordingProfileRevisionApplier{err: errors.New("revision registry unavailable")},
	}

	if err := switcher.Switch(ctx, fixture.target, true); err == nil {
		t.Fatal("switch unexpectedly succeeded")
	}
	fixture.assertSharedStateUnchanged(t)
	active, err := fixture.profiles.Current()
	if err != nil {
		t.Fatal(err)
	}
	if active != fixture.old {
		t.Fatalf("active profile = %+v, want previous %+v", active, fixture.old)
	}
}

func TestSuccessfulMihomoProfileSwitchPublishesStagedAUTOAndEndpointLKG(t *testing.T) {
	fixture := newMihomoPreflightStateFixture(t)
	ctx := context.Background()
	enginePreparer := &EnginePreparer{Profiles: fixture.profiles, Preparers: map[string]ExplicitProfilePreparer{
		state.EngineMihomo: fixture.preparer,
	}}
	lifecycle := &Lifecycle{
		Preparer: enginePreparer, Core: profileSwitchCore{}, Activation: profileSwitchActivation{},
		snap: LifecycleSnapshot{State: LifecycleStopped},
	}
	switcher := &ProfileSwitcher{
		State: fixture.store, Profiles: fixture.profiles, Preparer: enginePreparer, Lifecycle: lifecycle,
	}

	if err := switcher.Switch(ctx, fixture.target, true); err != nil {
		t.Fatal(err)
	}
	if current := fixture.readFakeIPState(t); bytes.Equal(current, fixture.fakeIPBefore) {
		t.Fatal("successful switch did not publish staged AUTO fake-IP state")
	}
	if current := fixture.readEndpointState(t); bytes.Equal(current, fixture.endpointBefore) {
		t.Fatal("successful switch did not publish staged endpoint LKG state")
	}
	if _, err := fixture.store.Read(profileTransitionPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed switch journal remained: %v", err)
	}
}

type mihomoPreflightStateFixture struct {
	layout         state.Layout
	store          state.Store
	profiles       state.ProfileStore
	preparer       *ActiveMihomoPreparer
	old            state.ActiveProfile
	target         state.ActiveProfile
	fakeIPBefore   []byte
	endpointBefore []byte
}

func newMihomoPreflightStateFixture(t *testing.T) mihomoPreflightStateFixture {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(layout.EnginesDir, state.EngineMihomo), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout.EnginesDir, state.EngineMihomo, state.EngineMihomo), []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	profiles, err := state.NewProfileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	old := state.ActiveProfile{Name: "old", Engine: state.EngineMihomo}
	target := state.ActiveProfile{Name: "target", Engine: state.EngineMihomo}
	if err := profiles.Create(ctx, old, []byte("mode: direct\nrules:\n  - MATCH,DIRECT\n")); err != nil {
		t.Fatal(err)
	}
	targetSource := []byte(`mode: rule
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
proxies:
  - name: candidate
    type: socks5
    server: candidate.example
    port: 1080
rules:
  - IP-CIDR,203.0.113.0/24,PROXY
  - MATCH,DIRECT
`)
	if err := profiles.Create(ctx, target, targetSource); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Activate(ctx, old); err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSettings(settingsRelativePath, state.Settings{"AUTO_FAKEIP_WHITELIST": "true"}); err != nil {
		t.Fatal(err)
	}
	fakeIPStore := &fakeip.Store{Directory: layout.LocalRulesDir}
	empty, err := fakeIPStore.Read()
	if err != nil {
		t.Fatal(err)
	}
	generatedAt := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	if _, err := fakeIPStore.ReplaceGeneratedWithScope(
		[]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, empty.Revision, generatedAt, fakeip.AutoScopeLocalOnly,
	); err != nil {
		t.Fatal(err)
	}
	seedCache := endpointBypassCache{Version: 1, Hosts: map[string][]string{
		endpointHostKey("old.example"): {"192.0.2.9"},
	}}
	if err := store.WriteJSON(endpointBypassCachePath, seedCache, 0o600); err != nil {
		t.Fatal(err)
	}
	preparer, err := NewActiveMihomoPreparer(root, &recordingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	preparer.FakeIP.Now = func() time.Time { return generatedAt.Add(time.Hour) }
	preparer.Endpoints.Resolver = &endpointResolverStub{addresses: map[string][]netip.Addr{
		"candidate.example": {netip.MustParseAddr("198.51.100.7")},
	}, errors: map[string]error{}}
	fixture := mihomoPreflightStateFixture{
		layout: layout, store: store, profiles: profiles, preparer: preparer, old: old, target: target,
	}
	fixture.fakeIPBefore = fixture.readFakeIPState(t)
	fixture.endpointBefore = fixture.readEndpointState(t)
	return fixture
}

func (fixture mihomoPreflightStateFixture) readFakeIPState(t *testing.T) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(fixture.layout.LocalRulesDir, fakeip.FileName))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func (fixture mihomoPreflightStateFixture) readEndpointState(t *testing.T) []byte {
	t.Helper()
	content, err := fixture.store.Read(endpointBypassCachePath)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func (fixture mihomoPreflightStateFixture) assertSharedStateUnchanged(t *testing.T) {
	t.Helper()
	if current := fixture.readFakeIPState(t); !bytes.Equal(current, fixture.fakeIPBefore) {
		t.Fatalf("explicit preflight changed shared AUTO state:\n%s", current)
	}
	if current := fixture.readEndpointState(t); !bytes.Equal(current, fixture.endpointBefore) {
		t.Fatalf("explicit preflight changed shared endpoint LKG state:\n%s", current)
	}
}

func TestActiveMihomoPreparerForcesLANControllerToLoopback(t *testing.T) {
	tests := []struct {
		name   string
		secret string
	}{
		{name: "without secret"},
		{name: "with secret", secret: "keep-me"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "engines", "mihomo"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "engines", "mihomo", "mihomo"), []byte("fake"), 0o700); err != nil {
				t.Fatal(err)
			}
			configuration := "external-controller: 192.168.8.1:19090\n"
			if test.secret != "" {
				configuration += "secret: " + test.secret + "\n"
			}
			if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte(configuration), 0o600); err != nil {
				t.Fatal(err)
			}
			recorder := &recordingConfig{}
			preparer, err := NewActiveMihomoPreparer(root, recorder)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := preparer.PrepareActive(context.Background()); err != nil {
				t.Fatal(err)
			}
			if recorder.request.Controller.Listen != "127.0.0.1:19090" || recorder.request.Controller.Secret != test.secret {
				t.Fatalf("controller = %+v", recorder.request.Controller)
			}
		})
	}
}

func TestActiveMihomoPreparerRejectsSingBoxProfile(t *testing.T) {
	root := t.TempDir()
	profileStore, err := state.NewProfileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	profile := state.ActiveProfile{Name: "future", Engine: state.EngineSingBox}
	if err := profileStore.Create(context.Background(), profile, []byte(`{"log":{}}`)); err != nil {
		t.Fatal(err)
	}
	if err := profileStore.Activate(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	preparer, err := NewActiveMihomoPreparer(root, &recordingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := preparer.PrepareActive(context.Background()); err == nil {
		t.Fatal("sing-box profile prepared by Mihomo v1")
	}
}

func TestActiveMihomoPreparerAppliesHWIDAndTmpfsOnlyToRuntimeCopy(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{"engines/mihomo", ".boxctl", "rule-providers"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "engines", "mihomo", "mihomo"), []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte(`proxy-providers:
  remote:
    type: http
    url: https://example.invalid/subscription
    path: ./proxy-providers/remote.yaml
rule-providers:
  domains:
    type: http
    behavior: classical
    url: https://example.invalid/rules
    path: ./rule-providers/domains.yaml
rules:
  - MATCH,DIRECT
`)
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "rule-providers", "domains.yaml"), []byte("payload: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSettings(settingsRelativePath, state.Settings{"ENABLE_HWID": "true", "USE_TMPFS_RULES": "true"}); err != nil {
		t.Fatal(err)
	}
	recorder := &recordingConfig{}
	preparer, err := NewActiveMihomoPreparer(root, recorder)
	if err != nil {
		t.Fatal(err)
	}
	preparer.Identity = &DeviceIdentity{State: store, Random: bytes.NewReader(make([]byte, 16))}
	if _, err := preparer.PrepareActive(context.Background()); err != nil {
		t.Fatal(err)
	}
	runtime := string(recorder.source)
	for _, expected := range []string{"x-hwid:", "x-device-os:", "boxctl-rule-providers", "User-Agent:"} {
		if !strings.Contains(runtime, expected) {
			t.Fatalf("runtime config does not contain %q:\n%s", expected, runtime)
		}
	}
	current, err := os.ReadFile(filepath.Join(root, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, original) {
		t.Fatalf("user config changed:\n%s", current)
	}
}

func TestActiveMihomoPreparerSeedsPathlessMihomoRuleCacheIntoTmpfs(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "rules"), 0o700); err != nil {
		t.Fatal(err)
	}
	sourceURL := "https://rules.example.invalid/pathless.mrs?token=private"
	source := []byte("rule-providers:\n  pathless-seed-test:\n    type: http\n    behavior: ipcidr\n    format: mrs\n    url: " + sourceURL + "\nrules: []\n")
	cachePath := mihomoHashedProviderCachePath(root, "rules", sourceURL)
	cacheContent := []byte("cached-mrs-content")
	if err := os.WriteFile(cachePath, cacheContent, 0o600); err != nil {
		t.Fatal(err)
	}
	preparer, err := NewActiveMihomoPreparer(root, &recordingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := preparer.applyRuntimeProviderSettings(context.Background(), source, RuntimeSettings{UseTmpfsRules: true}, true)
	if err != nil {
		t.Fatal(err)
	}
	runtimeDirectory, err := preparer.tmpfsRuleProviderDirectory()
	if err != nil {
		t.Fatal(err)
	}
	_, relocations, err := configpkg.RelocateMihomoHTTPRuleProviders(source, runtimeDirectory)
	if err != nil || len(relocations) != 1 {
		t.Fatalf("relocations = %+v, err = %v", relocations, err)
	}
	defer os.Remove(relocations[0].RuntimePath)
	seeded, err := os.ReadFile(relocations[0].RuntimePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seeded, cacheContent) || !strings.Contains(string(updated), relocations[0].RuntimePath) {
		t.Fatalf("pathless cache was not seeded: content=%q config=%s", seeded, updated)
	}
}

func TestActiveMihomoPreparerDropsStaleTmpfsCacheWhenSeedIsMissing(t *testing.T) {
	root := t.TempDir()
	source := []byte("rule-providers:\n  stale-seed-test:\n    type: http\n    behavior: ipcidr\n    format: mrs\n    url: https://rules.example.invalid/missing.mrs\nrules: []\n")
	preparer, err := NewActiveMihomoPreparer(root, &recordingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	runtimeDirectory, err := preparer.tmpfsRuleProviderDirectory()
	if err != nil {
		t.Fatal(err)
	}
	_, relocations, err := configpkg.RelocateMihomoHTTPRuleProviders(source, runtimeDirectory)
	if err != nil || len(relocations) != 1 {
		t.Fatalf("relocations = %+v, err = %v", relocations, err)
	}
	runtimePath := relocations[0].RuntimePath
	t.Cleanup(func() { _ = os.Remove(runtimePath) })
	if err := os.WriteFile(runtimePath, []byte("stale-provider-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	updated, err := preparer.applyRuntimeProviderSettings(context.Background(), source, RuntimeSettings{UseTmpfsRules: true}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(runtimePath); !os.IsNotExist(err) {
		t.Fatalf("stale runtime target survived missing seed: %v", err)
	}
	if !strings.Contains(string(updated), runtimePath) {
		t.Fatalf("runtime config does not use reset target %q:\n%s", runtimePath, updated)
	}
}

func TestActiveMihomoPreparerIsolatesTmpfsCachesByStateRoot(t *testing.T) {
	first, err := NewActiveMihomoPreparer(t.TempDir(), &recordingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewActiveMihomoPreparer(t.TempDir(), &recordingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	firstDirectory, err := first.tmpfsRuleProviderDirectory()
	if err != nil {
		t.Fatal(err)
	}
	secondDirectory, err := second.tmpfsRuleProviderDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if firstDirectory == secondDirectory {
		t.Fatalf("different state roots share tmpfs cache directory %q", firstDirectory)
	}
}
