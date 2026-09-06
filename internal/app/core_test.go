package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

type corePreparerFake struct {
	mu       sync.Mutex
	prepared engine.PreparedCore
	err      error
	calls    int
	wait     bool
}

func (fake *corePreparerFake) PrepareActive(ctx context.Context) (engine.PreparedCore, error) {
	if err := ctx.Err(); err != nil {
		return engine.PreparedCore{}, err
	}
	if fake.wait {
		<-ctx.Done()
		return engine.PreparedCore{}, ctx.Err()
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.calls++
	return fake.prepared, fake.err
}

func (fake *corePreparerFake) setPrepared(prepared engine.PreparedCore) {
	fake.mu.Lock()
	fake.prepared = prepared
	fake.mu.Unlock()
}

func (fake *corePreparerFake) callCount() int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.calls
}

type coreBackendFake struct {
	mu sync.Mutex

	capabilities        engine.Capabilities
	health              engine.HealthStatus
	healthErr           error
	reloadErr           error
	reloads             []engine.PreparedCore
	groups              []engine.ProxyGroup
	groupsErr           error
	selections          [][2]string
	delay               time.Duration
	delayErr            error
	delayCalls          []coreDelayCall
	providers           map[engine.ProviderKind][]engine.Provider
	providersErr        error
	providerUpdates     []coreProviderUpdate
	providerUpdateErr   error
	routingMode         engine.RoutingMode
	routingModeErr      error
	routingModeUpdates  []engine.RoutingMode
	trafficStream       <-chan engine.TrafficSnapshot
	trafficStreamErr    error
	connections         engine.ConnectionsSnapshot
	connectionsErr      error
	connectionStream    <-chan engine.ConnectionsSnapshot
	connectionStreamErr error
	closedIDs           []string
	closedAll           int
	rules               []engine.Rule
	rulesErr            error
	logs                chan engine.LogEntry
}

type coreDelayCall struct {
	proxy   string
	testURL string
	timeout time.Duration
}

type coreProviderUpdate struct {
	kind engine.ProviderKind
	name string
}

func newCoreBackendFake() *coreBackendFake {
	return &coreBackendFake{logs: make(chan engine.LogEntry, 32)}
}

func (fake *coreBackendFake) Capabilities() engine.Capabilities {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.capabilities
}

func (fake *coreBackendFake) Start(context.Context, engine.PreparedCore) error { return nil }
func (fake *coreBackendFake) Stop(context.Context) error                       { return nil }

func (fake *coreBackendFake) Reload(ctx context.Context, prepared engine.PreparedCore) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.reloads = append(fake.reloads, prepared)
	return fake.reloadErr
}

func (fake *coreBackendFake) Health(ctx context.Context) (engine.HealthStatus, error) {
	if err := ctx.Err(); err != nil {
		return engine.HealthStatus{}, err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.health, fake.healthErr
}

func (fake *coreBackendFake) Version(context.Context, string) (string, error) { return "test", nil }
func (fake *coreBackendFake) Logs() <-chan engine.LogEntry                    { return fake.logs }
func (fake *coreBackendFake) Proxies(context.Context) ([]engine.Proxy, error) { return nil, nil }

func (fake *coreBackendFake) Groups(ctx context.Context) ([]engine.ProxyGroup, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]engine.ProxyGroup(nil), fake.groups...), fake.groupsErr
}

func (fake *coreBackendFake) Select(ctx context.Context, group, proxy string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.selections = append(fake.selections, [2]string{group, proxy})
	return nil
}

func (fake *coreBackendFake) Delay(ctx context.Context, proxy, testURL string, timeout time.Duration) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.delayCalls = append(fake.delayCalls, coreDelayCall{proxy: proxy, testURL: testURL, timeout: timeout})
	return fake.delay, fake.delayErr
}

func (fake *coreBackendFake) Providers(ctx context.Context, kind engine.ProviderKind) ([]engine.Provider, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]engine.Provider(nil), fake.providers[kind]...), fake.providersErr
}

func (fake *coreBackendFake) UpdateProvider(ctx context.Context, kind engine.ProviderKind, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.providerUpdates = append(fake.providerUpdates, coreProviderUpdate{kind: kind, name: name})
	return fake.providerUpdateErr
}

func (fake *coreBackendFake) RoutingMode(ctx context.Context) (engine.RoutingMode, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.routingMode, fake.routingModeErr
}

func (fake *coreBackendFake) SetRoutingMode(ctx context.Context, mode engine.RoutingMode) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.routingModeUpdates = append(fake.routingModeUpdates, mode)
	if fake.routingModeErr == nil {
		fake.routingMode = mode
	}
	return fake.routingModeErr
}

func (fake *coreBackendFake) StreamTraffic(ctx context.Context) (<-chan engine.TrafficSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.trafficStream, fake.trafficStreamErr
}

func (fake *coreBackendFake) Rules(ctx context.Context) ([]engine.Rule, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]engine.Rule(nil), fake.rules...), fake.rulesErr
}

func (fake *coreBackendFake) Connections(ctx context.Context) (engine.ConnectionsSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return engine.ConnectionsSnapshot{}, err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.connections, fake.connectionsErr
}

func (fake *coreBackendFake) StreamConnections(ctx context.Context, _ time.Duration) (<-chan engine.ConnectionsSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.connectionStream, fake.connectionStreamErr
}

func (fake *coreBackendFake) CloseConnection(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.closedIDs = append(fake.closedIDs, id)
	return nil
}

func (fake *coreBackendFake) CloseAllConnections(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.closedAll++
	return nil
}

func TestCoreServiceExternalDashboardIsDisabledByDefault(t *testing.T) {
	t.Parallel()
	backend := newCoreBackendFake()
	service, err := NewCoreService(&Lifecycle{}, &corePreparerFake{}, backend, CoreServiceOptions{CoreName: "mihomo"})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	capabilities, err := service.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if capabilities.Features["externalDashboard"] {
		t.Fatal("external dashboard was enabled without explicit opt-in")
	}
}

func TestCoreServiceCapabilitiesFollowSelectedEngineWhileStopped(t *testing.T) {
	t.Parallel()
	selected := state.EngineMihomo
	service, err := NewCoreService(
		&Lifecycle{snap: LifecycleSnapshot{State: LifecycleStopped}},
		&corePreparerFake{},
		newCoreBackendFake(),
		CoreServiceOptions{
			CoreName:                "core",
			SelectedEngine:          func() string { return selected },
			UnsafeExternalDashboard: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	mihomoCapabilities, err := service.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if mihomoCapabilities.CoreName != state.EngineMihomo || !mihomoCapabilities.Pages["ruleLists"] || !mihomoCapabilities.Features["externalDashboard"] {
		t.Fatalf("stopped Mihomo capabilities = %+v", mihomoCapabilities)
	}

	selected = state.EngineSingBox
	singBoxCapabilities, err := service.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if singBoxCapabilities.CoreName != state.EngineSingBox || singBoxCapabilities.Pages["ruleLists"] || !singBoxCapabilities.Features["externalDashboard"] {
		t.Fatalf("stopped sing-box capabilities = %+v", singBoxCapabilities)
	}
}

func TestCoreServiceCapabilitiesAndHealthAreSecretFree(t *testing.T) {
	t.Parallel()
	const secret = "do-not-expose-controller-secret"
	backend := newCoreBackendFake()
	backend.capabilities = engine.Capabilities{
		HotReload: true, Proxies: true, Groups: true, Selection: true, Delay: true,
		ProxyProviders: true, RuleProviders: true, Rules: true,
		Connections: true, CloseConnection: true, CloseAllConnections: true,
		RoutingMode: true, TrafficStream: true, RuleMutation: false, ProcessLogs: true,
	}
	started := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	backend.health = engine.HealthStatus{Running: true, ControllerReady: true, Version: "v1.20", StartedAt: started}
	prepared := engine.PreparedCore{Engine: "mihomo", Controller: engine.ControllerEndpoint{Secret: secret}}
	lifecycle := &Lifecycle{snap: LifecycleSnapshot{
		State: LifecycleRunning, Prepared: prepared, Health: engine.HealthStatus{Version: "cached-v1.20"},
		StartedAt: started, LastError: "secret=" + secret,
	}}
	preparer := &corePreparerFake{prepared: prepared}
	service, err := NewCoreService(lifecycle, preparer, backend, CoreServiceOptions{CoreName: "fallback", UnsafeExternalDashboard: true})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	capabilities, err := service.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if capabilities.CoreName != "mihomo" || capabilities.CoreVersion != "cached-v1.20" {
		t.Fatalf("Capabilities() identity = %#v", capabilities)
	}
	for _, key := range []string{"status", "profiles", "rawConfig", "ruleLists", "backups", "settings", "systemLogs", "proxies", "connections", "rules", "coreLogs"} {
		if !capabilities.Pages[key] {
			t.Errorf("Capabilities().Pages[%q] = false", key)
		}
	}
	for _, key := range []string{"createRuleList", "editRuleList", "deleteRuleList", "exportBackup", "importBackup", "updateCore", "reloadCore", "selectProxy", "testProxyDelay", "updateProxyProvider", "updateRuleProvider", "closeConnection", "closeAllConnections", "setRoutingMode", "startService", "stopService", "restartService"} {
		if !capabilities.Actions[key] {
			t.Errorf("Capabilities().Actions[%q] = false", key)
		}
	}
	for _, key := range []string{"delay", "proxyProviders", "ruleProviders", "closeAllConnections", "routingMode", "trafficStream", "externalDashboard"} {
		if !capabilities.Features[key] {
			t.Errorf("Capabilities().Features[%q] = false", key)
		}
	}
	if capabilities.Actions["toggleRule"] || capabilities.Features["ruleMutation"] {
		t.Fatal("Mihomo read-only runtime rules were advertised as mutable")
	}
	health, err := service.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Name != "mihomo" || health.Version != "v1.20" || health.State != "running" || !health.Since.Equal(started) {
		t.Fatalf("Health() = %#v", health)
	}
	if health.LastError != "core lifecycle operation failed" {
		t.Fatalf("Health().LastError = %q", health.LastError)
	}
	encoded, err := json.Marshal(struct {
		Capabilities web.Capabilities `json:"capabilities"`
		Health       web.CoreHealth   `json:"health"`
	}{capabilities, health})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("web DTOs leaked controller secret: %s", encoded)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Health(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Health(cancelled) error = %v", err)
	}
}

func TestCoreServiceReloadNeverRemovesRuntimeWithoutEngineOwnershipProof(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name          string
		currentEngine string
		changeCapture bool
		reloadErr     error
	}{
		{name: "backend failure", currentEngine: "mihomo", reloadErr: errors.New("reload failed")},
		{name: "capture change", currentEngine: "mihomo", changeCapture: true},
		{name: "engine change", currentEngine: "sing-box"},
	} {
		t.Run(test.name, func(t *testing.T) {
			temporaryRoot := filepath.Join(os.TempDir(), "boxctl")
			if err := os.MkdirAll(temporaryRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			directory, err := os.MkdirTemp(temporaryRoot, "reload-test-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(directory) })
			source := filepath.Join(directory, "mihomo-source.yaml")
			oldRuntime := filepath.Join(directory, "mihomo-old.yaml")
			newRuntime := filepath.Join(directory, "mihomo-new.yaml")
			for _, path := range []string{source, oldRuntime, newRuntime} {
				if err := os.WriteFile(path, []byte("private\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			capture := testCapturePlan()
			candidateCapture := capture
			if test.changeCapture {
				candidateCapture.LoopMark++
			}
			backend := newCoreBackendFake()
			backend.capabilities.HotReload = true
			backend.reloadErr = test.reloadErr
			current := engine.PreparedCore{Engine: test.currentEngine, RuntimeConfigPath: oldRuntime, Capture: capture}
			candidate := engine.PreparedCore{
				Engine: "mihomo", SourceConfigPath: source, RuntimeConfigPath: newRuntime, Capture: candidateCapture,
			}
			lifecycle := &Lifecycle{snap: LifecycleSnapshot{State: LifecycleRunning, Prepared: current}}
			service, err := NewCoreService(lifecycle, &corePreparerFake{prepared: candidate}, backend, CoreServiceOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()

			if err := service.Reload(context.Background()); err == nil {
				t.Fatal("Reload() succeeded, want rejection")
			}
			if _, err := os.Stat(newRuntime); err != nil {
				t.Fatalf("unowned rejected runtime was removed: %v", err)
			}
			for _, preserved := range []string{source, oldRuntime} {
				if _, err := os.Stat(preserved); err != nil {
					t.Fatalf("owned cleanup removed %s: %v", preserved, err)
				}
			}
			if snapshot := lifecycle.Snapshot(); snapshot.Prepared.RuntimeConfigPath != oldRuntime {
				t.Fatalf("failed reload replaced active runtime: %#v", snapshot.Prepared)
			}
		})
	}
}

func TestFailedReloadCleanupRefusesMihomoNamedFileOutsideOwnedRuntime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mihomo-user-owned.yaml")
	if err := os.WriteFile(path, []byte("user owned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	removeFailedReloadRuntime(engine.PreparedCore{Engine: "mihomo", RuntimeConfigPath: path}, coreLifecycleView{})
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cleanup removed non-runtime file: %v", err)
	}
}

func TestSafeCoreLogMessageRedactsURLsAndRuntimePaths(t *testing.T) {
	t.Parallel()
	for _, secret := range []string{"user-secret", "query-secret", "path-secret", "mihomo-private.yaml"} {
		message := "https://admin:user-secret@example.test/subscription/path-secret?opaque=query-secret " +
			"/tmp/boxctl-mihomo-123456789/mihomo-private.yaml"
		redacted := safeCoreLogMessage(message, 4<<10)
		if strings.Contains(redacted, secret) {
			t.Fatalf("safeCoreLogMessage leaked %q: %q", secret, redacted)
		}
	}
}

func TestCoreServiceReloadRepreparesAndUpdatesLifecycle(t *testing.T) {
	t.Parallel()
	backend := newCoreBackendFake()
	backend.capabilities.HotReload = true
	capture := testCapturePlan()
	oldPrepared := engine.PreparedCore{Engine: "mihomo", RuntimeConfigPath: "/runtime/old.yaml", Capture: capture}
	newPrepared := engine.PreparedCore{
		Engine: "mihomo", RuntimeConfigPath: "/runtime/new.yaml", Capture: capture,
		Controller: engine.ControllerEndpoint{Secret: "new-secret-must-not-be-read"},
	}
	lifecycle := &Lifecycle{snap: LifecycleSnapshot{State: LifecycleRunning, Prepared: oldPrepared, LastError: "old error"}}
	preparer := &corePreparerFake{prepared: newPrepared}
	service, err := NewCoreService(lifecycle, preparer, backend, CoreServiceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	if err := service.Reload(context.Background()); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	backend.mu.Lock()
	if len(backend.reloads) != 1 || backend.reloads[0].RuntimeConfigPath != "/runtime/new.yaml" {
		t.Fatalf("backend reloads = %#v", backend.reloads)
	}
	backend.mu.Unlock()
	if snapshot := lifecycle.Snapshot(); snapshot.Prepared.RuntimeConfigPath != "/runtime/new.yaml" || snapshot.LastError != "" {
		t.Fatalf("lifecycle snapshot after reload = %#v", snapshot)
	}

	restartPrepared := newPrepared
	restartPrepared.Capture.LoopMark++
	preparer.setPrepared(restartPrepared)
	if err := service.Reload(context.Background()); !errors.Is(err, web.ErrConflict) {
		t.Fatalf("Reload(capture change) error = %v, want web.ErrConflict", err)
	}
	backend.mu.Lock()
	if len(backend.reloads) != 1 {
		t.Fatalf("capture-changing reload reached backend: %#v", backend.reloads)
	}
	backend.mu.Unlock()

	lifecycle.mu.Lock()
	lifecycle.snap.State = LifecycleStopped
	lifecycle.mu.Unlock()
	calls := preparer.callCount()
	if err := service.Reload(context.Background()); !errors.Is(err, engine.ErrNotRunning) || !errors.Is(err, web.ErrConflict) {
		t.Fatalf("Reload(stopped) error = %v", err)
	}
	if preparer.callCount() != calls {
		t.Fatal("Reload prepared a profile while core was stopped")
	}
}

func TestCoreServiceReloadBoundsPreparationAndReleasesOperationGate(t *testing.T) {
	t.Parallel()
	backend := newCoreBackendFake()
	backend.capabilities.HotReload = true
	lifecycle := &Lifecycle{
		PrepareTimeout: 10 * time.Millisecond,
		snap:           LifecycleSnapshot{State: LifecycleRunning, Prepared: engine.PreparedCore{Engine: "mihomo"}},
	}
	service, err := NewCoreService(lifecycle, &corePreparerFake{wait: true}, backend, CoreServiceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = service.Close() }()
	if err := service.Reload(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Reload() error = %v, want bounded prepare deadline", err)
	}
	if !lifecycle.opMu.TryLock() {
		t.Fatal("Reload retained lifecycle operation gate after timeout")
	}
	lifecycle.opMu.Unlock()
}

func TestCoreServiceTranslatesControlDTOs(t *testing.T) {
	t.Parallel()
	backend := newCoreBackendFake()
	backend.capabilities = engine.Capabilities{Groups: true, Selection: true, Rules: true, Connections: true, CloseConnection: true, CloseAllConnections: true}
	backend.groups = []engine.ProxyGroup{
		{Name: "B", Type: "Selector", Now: "DIRECT", Members: []string{"DIRECT"}},
		{Name: "A", Type: "URLTest", Icon: "https://icons.example/group.png", Now: "node-1", Members: []string{"node-1", "node-2"}, Options: []engine.Proxy{{Name: "node-1", Type: "VLESS", Icon: "https://icons.example/node.png", History: []engine.DelaySample{{Delay: 37}}}}},
	}
	started := "2026-08-25T11:12:13.123Z"
	backend.connections = engine.ConnectionsSnapshot{Connections: []engine.Connection{{
		ID: "connection/1",
		Metadata: engine.ConnectionMetadata{
			Network: "tcp", Type: "TProxy", SourceIP: "2001:db8::1", SourcePort: "54321",
			DestinationIP: "198.51.100.2", DestinationPort: "443", Host: "example.test",
		},
		Upload: 11, Download: 22, Start: started, Chains: []string{"node-1", "A"}, Rule: "DOMAIN", RulePayload: "example.test",
	}}}
	backend.rules = []engine.Rule{{Type: "DOMAIN-SUFFIX", Payload: "example.test", Proxy: "A", Size: 17}}
	lifecycle := &Lifecycle{snap: LifecycleSnapshot{State: LifecycleRunning, Prepared: engine.PreparedCore{Engine: "mihomo"}}}
	preparer := &corePreparerFake{}
	service, err := NewCoreService(lifecycle, preparer, backend, CoreServiceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	groups, err := service.ProxyGroups(context.Background())
	if err != nil || len(groups) != 2 || groups[0].Name != "A" || groups[0].Selected != "node-1" || len(groups[0].Options) != 2 {
		t.Fatalf("ProxyGroups() = %#v, %v", groups, err)
	}
	if groups[0].Icon != "https://icons.example/group.png" || groups[0].Options[0].Icon != "https://icons.example/node.png" || groups[0].Options[0].Type != "VLESS" || groups[0].Options[0].DelayMS == nil || *groups[0].Options[0].DelayMS != 37 {
		t.Fatalf("ProxyGroups() did not preserve option metadata: %#v", groups[0].Options)
	}
	if err := service.SelectProxy(context.Background(), "A", "node-2"); err != nil {
		t.Fatal(err)
	}
	connections, err := service.Connections(context.Background())
	if err != nil || len(connections) != 1 {
		t.Fatalf("Connections() = %#v, %v", connections, err)
	}
	connection := connections[0]
	if connection.Source != "[2001:db8::1]:54321" || connection.Destination != "198.51.100.2:443" ||
		connection.Type != "TProxy" || connection.RulePayload != "example.test" || len(connection.Chains) != 2 ||
		connection.Outbound != "node-1" || connection.UploadBytes != 11 || connection.DownloadBytes != 22 || connection.StartedAt == nil || connection.StartedAt.IsZero() {
		t.Fatalf("translated connection = %#v", connection)
	}
	if err := service.CloseConnection(context.Background(), "connection/1"); err != nil {
		t.Fatal(err)
	}
	if err := service.CloseAllConnections(context.Background()); err != nil {
		t.Fatal(err)
	}
	rules, err := service.Rules(context.Background())
	if err != nil || len(rules) != 1 || rules[0].Index != 0 || rules[0].Action != "A" || rules[0].Size != 17 {
		t.Fatalf("Rules() = %#v, %v", rules, err)
	}
	backend.mu.Lock()
	if len(backend.selections) != 1 || backend.selections[0] != [2]string{"A", "node-2"} ||
		len(backend.closedIDs) != 1 || backend.closedIDs[0] != "connection/1" || backend.closedAll != 1 {
		t.Fatalf("control calls selection=%#v closed=%#v", backend.selections, backend.closedIDs)
	}
	backend.mu.Unlock()

	backend.mu.Lock()
	backend.capabilities.Selection = false
	backend.mu.Unlock()
	if err := service.SelectProxy(context.Background(), "A", "node-1"); !errors.Is(err, engine.ErrUnsupported) {
		t.Fatalf("SelectProxy(unsupported) error = %v", err)
	}
	var public *web.PublicError
	if err := service.SelectProxy(context.Background(), "A", "node-1"); !errors.As(err, &public) || public.Status != 501 {
		t.Fatalf("unsupported error lacks safe public mapping: %v", err)
	}
}

func TestSafeProxyIconAllowsOnlyCredentialFreeHTTPSURLs(t *testing.T) {
	t.Parallel()
	if got := safeProxyIcon(" https://icons.example/group.png?q=1 "); got != "https://icons.example/group.png?q=1" {
		t.Fatalf("safeProxyIcon(https) = %q", got)
	}
	for _, value := range []string{"http://icons.example/group.png", "file:///etc/shadow", "https://user:secret@icons.example/group.png", "not a URL"} {
		if got := safeProxyIcon(value); got != "" {
			t.Fatalf("safeProxyIcon(%q) = %q, want empty", value, got)
		}
	}
}

func TestCoreServiceStreamsConnectionsAndDerivesRates(t *testing.T) {
	t.Parallel()
	backend := newCoreBackendFake()
	backend.capabilities = engine.Capabilities{Connections: true}
	snapshots := make(chan engine.ConnectionsSnapshot, 3)
	backend.connectionStream = snapshots
	service, err := NewCoreService(
		&Lifecycle{snap: LifecycleSnapshot{State: LifecycleRunning}},
		&corePreparerFake{}, backend, CoreServiceOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	base := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	snapshots <- engine.ConnectionsSnapshot{
		CapturedAt:  base,
		Connections: []engine.Connection{{ID: "stable", Upload: 100, Download: 200}},
	}
	snapshots <- engine.ConnectionsSnapshot{
		CapturedAt: base.Add(2 * time.Second), DownloadTotal: 1_500, UploadTotal: 1_200, Memory: 4_096,
		Connections: []engine.Connection{
			{ID: "stable", Upload: 300, Download: 700},
			{ID: "new", Upload: 900, Download: 800},
		},
	}
	snapshots <- engine.ConnectionsSnapshot{
		CapturedAt: base.Add(3 * time.Second), DownloadTotal: 1_600, UploadTotal: 1_300, Memory: 4_200,
		Connections: []engine.Connection{{ID: "new", Upload: 950, Download: 900}},
	}
	close(snapshots)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stream, err := service.StreamConnections(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first := <-stream
	second := <-stream
	third := <-stream
	if len(first.Active) != 1 || first.Active[0].UploadRateBytes != 0 || first.Active[0].DownloadRateBytes != 0 {
		t.Fatalf("first snapshot = %#v", first)
	}
	if len(second.Active) != 2 || second.Active[0].UploadRateBytes != 100 || second.Active[0].DownloadRateBytes != 250 {
		t.Fatalf("second snapshot = %#v", second)
	}
	if second.Active[1].UploadRateBytes != 0 || second.Active[1].DownloadRateBytes != 0 {
		t.Fatalf("new connection inherited a synthetic rate: %#v", second.Active[1])
	}
	if second.DownloadTotalBytes != 1_500 || second.UploadTotalBytes != 1_200 || second.MemoryBytes != 4_096 {
		t.Fatalf("aggregate connection metadata = %#v", second)
	}
	if len(third.Closed) != 1 || third.Closed[0].ID != "stable" || third.Closed[0].ClosedAt == nil || third.Closed[0].ClosedAt.IsZero() {
		t.Fatalf("closed connection history = %#v", third.Closed)
	}
}

func TestCoreServiceTranslatesDelayAndProviderControlWithoutPaths(t *testing.T) {
	t.Parallel()
	const providerPathSecret = "/etc/boxctl/proxy-providers/private-subscription.yaml"
	backend := newCoreBackendFake()
	backend.capabilities = engine.Capabilities{Delay: true, ProxyProviders: true, RuleProviders: true}
	backend.delay = 187 * time.Millisecond
	backend.providers = map[engine.ProviderKind][]engine.Provider{
		engine.ProviderProxy: {
			{Name: "zeta", Type: "Proxy", VehicleType: "HTTP", Path: providerPathSecret, UpdatedAt: "2026-08-26T12:00:00Z"},
			{Name: "alpha", Type: "Proxy", VehicleType: "File", Path: "/tmp/also-private"},
		},
		engine.ProviderRule: {{Name: "rules", Type: "Rule", VehicleType: "HTTP", Path: "/private/rules.yaml"}},
	}
	service, err := NewCoreService(
		&Lifecycle{snap: LifecycleSnapshot{State: LifecycleRunning}},
		&corePreparerFake{}, backend, CoreServiceOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	delay, err := service.TestProxyDelay(context.Background(), "node-a", "https://example.test/generate_204?token=secret", 5*time.Second)
	if err != nil || delay.Proxy != "node-a" || delay.DelayMS != 187 {
		t.Fatalf("TestProxyDelay() = %#v, %v", delay, err)
	}
	providers, err := service.Providers(context.Background(), web.ProviderProxy)
	if err != nil || len(providers) != 2 || providers[0].Name != "alpha" || providers[1].Name != "zeta" {
		t.Fatalf("Providers() = %#v, %v", providers, err)
	}
	encoded, err := json.Marshal(providers)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), providerPathSecret) || strings.Contains(string(encoded), `"path"`) {
		t.Fatalf("provider DTO leaked native path: %s", encoded)
	}
	if err := service.UpdateProvider(context.Background(), web.ProviderRule, "rules"); err != nil {
		t.Fatal(err)
	}

	backend.mu.Lock()
	if len(backend.delayCalls) != 1 || backend.delayCalls[0] != (coreDelayCall{proxy: "node-a", testURL: "https://example.test/generate_204?token=secret", timeout: 5 * time.Second}) {
		t.Fatalf("delay calls = %#v", backend.delayCalls)
	}
	if len(backend.providerUpdates) != 1 || backend.providerUpdates[0] != (coreProviderUpdate{kind: engine.ProviderRule, name: "rules"}) {
		t.Fatalf("provider updates = %#v", backend.providerUpdates)
	}
	backend.capabilities.Delay = false
	backend.capabilities.ProxyProviders = false
	backend.mu.Unlock()

	if _, err := service.TestProxyDelay(context.Background(), "node-a", "https://example.test", time.Second); !errors.Is(err, engine.ErrUnsupported) {
		t.Fatalf("TestProxyDelay(unsupported) error = %v", err)
	}
	if _, err := service.Providers(context.Background(), web.ProviderProxy); !errors.Is(err, engine.ErrUnsupported) {
		t.Fatalf("Providers(unsupported) error = %v", err)
	}
	if _, err := service.Providers(context.Background(), web.ProviderKind("unknown")); err == nil {
		t.Fatal("Providers(unknown) unexpectedly succeeded")
	}
}

func TestCoreServiceStreamsDashboardFromCoreEventsAndMutationInvalidation(t *testing.T) {
	t.Parallel()
	backend := newCoreBackendFake()
	backend.capabilities = engine.Capabilities{
		HotReload: true, Groups: true, Selection: true, Delay: true,
		ProxyProviders: true, RuleProviders: true, RoutingMode: true, TrafficStream: true,
	}
	backend.routingMode = engine.RoutingModeRule
	backend.groups = []engine.ProxyGroup{{
		Name: "PROXY", Type: "Selector", Now: "node-a", Members: []string{"node-a", "node-b"},
		Options: []engine.Proxy{
			{Name: "node-a", Type: "VLESS", UDP: true, History: []engine.DelaySample{{Time: "now", Delay: 27}}},
			{Name: "node-b", Type: "Hysteria2", UDP: true},
		},
	}}
	backend.providers = map[engine.ProviderKind][]engine.Provider{
		engine.ProviderProxy: {{Name: "subscription", ProxyCount: 12, SubscriptionInfo: &engine.ProviderSubscriptionInfo{Total: 1_024}}},
		engine.ProviderRule:  {{Name: "rules", RuleCount: 42, Behavior: "domain", Format: "mrs"}},
	}
	traffic := make(chan engine.TrafficSnapshot, 1)
	backend.trafficStream = traffic
	prepared := engine.PreparedCore{Engine: "mihomo"}
	service, err := NewCoreService(
		&Lifecycle{snap: LifecycleSnapshot{State: LifecycleRunning, Prepared: prepared}},
		&corePreparerFake{prepared: prepared}, backend, CoreServiceOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stream, err := service.StreamDashboard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	initial := <-stream
	if initial.Mode != "rule" || len(initial.Groups) != 1 || !initial.Groups[0].Options[0].UDP || len(initial.ProxyProviders) != 1 || initial.ProxyProviders[0].SubscriptionInfo == nil || initial.RuleProviders[0].RuleCount != 42 {
		t.Fatalf("initial dashboard = %#v", initial)
	}

	backend.mu.Lock()
	backend.groups[0].Now = "node-b"
	backend.mu.Unlock()
	if err := service.SelectProxy(ctx, "PROXY", "node-b"); err != nil {
		t.Fatal(err)
	}
	selected := receiveDashboard(t, stream)
	if selected.Groups[0].Selected != "node-b" {
		t.Fatalf("selection invalidation snapshot = %#v", selected)
	}

	backend.mu.Lock()
	backend.delay = 73 * time.Millisecond
	backend.groups[0].Options[1].History = []engine.DelaySample{{Time: "later", Delay: 73}}
	backend.mu.Unlock()
	if _, err := service.TestProxyDelay(ctx, "node-b", "https://example.test/generate_204", time.Second); err != nil {
		t.Fatal(err)
	}
	delayChanged := receiveDashboard(t, stream)
	if delayChanged.Groups[0].Options[1].DelayMS == nil || *delayChanged.Groups[0].Options[1].DelayMS != 73 {
		t.Fatalf("delay invalidation snapshot = %#v", delayChanged)
	}

	backend.mu.Lock()
	backend.providers[engine.ProviderRule][0].RuleCount = 43
	backend.mu.Unlock()
	if err := service.UpdateProvider(ctx, web.ProviderRule, "rules"); err != nil {
		t.Fatal(err)
	}
	providerChanged := receiveDashboard(t, stream)
	if providerChanged.RuleProviders[0].RuleCount != 43 {
		t.Fatalf("provider invalidation snapshot = %#v", providerChanged)
	}

	if err := service.SetRoutingMode(ctx, "direct"); err != nil {
		t.Fatal(err)
	}
	if err := service.SetRoutingMode(ctx, "script"); err == nil {
		t.Fatal("SetRoutingMode accepted an operation unsupported by the advertised mode contract")
	}
	modeChanged := receiveDashboard(t, stream)
	if modeChanged.Mode != "direct" {
		t.Fatalf("mode invalidation snapshot = %#v", modeChanged)
	}

	backend.mu.Lock()
	backend.groups[0].Members = append(backend.groups[0].Members, "node-c")
	backend.groups[0].Options = append(backend.groups[0].Options, engine.Proxy{Name: "node-c", Type: "WireGuard", UDP: true})
	backend.mu.Unlock()
	if err := service.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	reloaded := receiveDashboard(t, stream)
	if len(reloaded.Groups[0].Options) != 3 {
		t.Fatalf("config reload invalidation snapshot = %#v", reloaded)
	}
	metadataCapturedAt := reloaded.CapturedAt

	traffic <- engine.TrafficSnapshot{UploadRateBytes: 12, DownloadRateBytes: 34, CapturedAt: time.Now()}
	live := receiveDashboard(t, stream)
	if live.Traffic == nil || live.Traffic.UploadRateBytes != 12 || live.Traffic.DownloadRateBytes != 34 {
		t.Fatalf("live traffic dashboard = %#v", live)
	}
	if !live.CapturedAt.Equal(metadataCapturedAt) {
		t.Fatalf("traffic event changed metadata capturedAt: before=%s after=%s", metadataCapturedAt, live.CapturedAt)
	}
}

func TestCoreServiceDashboardStreamClosesWhenNativeTrafficSocketCloses(t *testing.T) {
	t.Parallel()
	backend := newCoreBackendFake()
	backend.capabilities = engine.Capabilities{TrafficStream: true}
	traffic := make(chan engine.TrafficSnapshot)
	backend.trafficStream = traffic
	service, err := NewCoreService(
		&Lifecycle{snap: LifecycleSnapshot{State: LifecycleRunning}},
		&corePreparerFake{}, backend, CoreServiceOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stream, err := service.StreamDashboard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = receiveDashboard(t, stream)
	close(traffic)
	select {
	case _, open := <-stream:
		if open {
			t.Fatal("dashboard emitted an event after native traffic socket closed")
		}
	case <-ctx.Done():
		t.Fatal("dashboard SSE stayed open after native traffic socket closed")
	}
}

func TestCoreServiceRejectsNilAdvertisedTrafficStream(t *testing.T) {
	t.Parallel()
	backend := newCoreBackendFake()
	backend.capabilities = engine.Capabilities{TrafficStream: true}
	service, err := NewCoreService(
		&Lifecycle{snap: LifecycleSnapshot{State: LifecycleRunning}},
		&corePreparerFake{}, backend, CoreServiceOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if _, err := service.StreamDashboard(context.Background()); !errors.Is(err, web.ErrUnavailable) {
		t.Fatalf("StreamDashboard(nil traffic) error = %v, want unavailable", err)
	}
}

func receiveDashboard(t *testing.T, stream <-chan web.CoreDashboard) web.CoreDashboard {
	t.Helper()
	select {
	case snapshot, open := <-stream:
		if !open {
			t.Fatal("dashboard stream closed before expected event")
		}
		return snapshot
	case <-time.After(time.Second):
		t.Fatal("dashboard stream did not emit expected event")
		return web.CoreDashboard{}
	}
}

func TestCoreServiceLogHistoryAndStreamAreBoundedAndRedacted(t *testing.T) {
	t.Parallel()
	const secret = "log-secret-value"
	backend := newCoreBackendFake()
	backend.capabilities.ProcessLogs = true
	lifecycle := &Lifecycle{snap: LifecycleSnapshot{State: LifecycleRunning}}
	preparer := &corePreparerFake{}
	service, err := NewCoreService(lifecycle, preparer, backend, CoreServiceOptions{LogHistory: 2, MaxLogMessageBytes: 12})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	backend.logs <- engine.LogEntry{Time: time.Now(), Stream: "stdout", Message: "first entry"}
	backend.logs <- engine.LogEntry{Time: time.Now(), Stream: "stderr", Message: "password=" + secret}
	backend.logs <- engine.LogEntry{Time: time.Now(), Stream: "stdout", Message: "0123456789abcdefghijkl"}
	waitForCoreLogMessage(t, service, "0123456789ab…")

	entries, err := service.CoreLogs(context.Background(), web.LogQuery{Limit: 100})
	if err != nil || len(entries) != 2 {
		t.Fatalf("CoreLogs() = %#v, %v", entries, err)
	}
	if entries[0].Message != "[REDACTED]" || entries[0].Level != "error" || strings.Contains(entries[0].Message, secret) {
		t.Fatalf("sensitive log was exposed: %#v", entries[0])
	}
	if entries[1].Message != "0123456789ab…" {
		t.Fatalf("long log was not bounded: %q", entries[1].Message)
	}
	errorEntries, err := service.CoreLogs(context.Background(), web.LogQuery{Limit: 2, Level: "ERROR"})
	if err != nil || len(errorEntries) != 1 || errorEntries[0].Level != "error" {
		t.Fatalf("filtered CoreLogs() = %#v, %v", errorEntries, err)
	}

	streamContext, cancelStream := context.WithCancel(context.Background())
	stream, err := service.StreamCoreLogs(streamContext, web.LogQuery{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case replay := <-stream:
		if replay.Message != "0123456789ab…" {
			t.Fatalf("stream replay = %#v", replay)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for log replay")
	}
	backend.logs <- engine.LogEntry{Time: time.Now(), Stream: "stdout", Message: "token:" + secret}
	select {
	case live := <-stream:
		if live.Message != "[REDACTED]" || strings.Contains(live.Message, secret) {
			t.Fatalf("live stream exposed secret: %#v", live)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for live log")
	}
	cancelStream()
	select {
	case _, open := <-stream:
		if open {
			t.Fatal("log stream remained open after context cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("log stream did not close after context cancellation")
	}
}

func TestCoreLogMetadataPreservesEngineHostStream(t *testing.T) {
	t.Parallel()
	entry := engine.LogEntry{Stream: "sing-box/stderr", Message: "native warning without a level prefix"}
	if level := coreLogLevel(entry); level != "error" {
		t.Fatalf("prefixed stderr level = %q, want error", level)
	}
	if component := coreLogComponent(entry.Stream); component != "core.sing-box.stderr" {
		t.Fatalf("prefixed stderr component = %q", component)
	}
	if component := coreLogComponent("stdout"); component != "core.stdout" {
		t.Fatalf("legacy stdout component = %q", component)
	}
}

func TestCoreServiceHealthFailureAndClose(t *testing.T) {
	t.Parallel()
	backend := newCoreBackendFake()
	backend.capabilities.ProcessLogs = true
	backend.health = engine.HealthStatus{Running: true}
	backend.healthErr = errors.New("controller at secret=config-value failed")
	service, err := NewCoreService(&Lifecycle{}, &corePreparerFake{}, backend, CoreServiceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	health, err := service.Health(context.Background())
	if !errors.Is(err, web.ErrUnavailable) || strings.Contains(health.LastError, "config-value") {
		t.Fatalf("Health() = %#v, %v", health, err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if _, err := service.CoreLogs(context.Background(), web.LogQuery{}); !errors.Is(err, web.ErrUnavailable) {
		t.Fatalf("CoreLogs() after Close error = %v", err)
	}
}

func TestNewCoreServiceValidatesDependencies(t *testing.T) {
	t.Parallel()
	backend := newCoreBackendFake()
	if _, err := NewCoreService(nil, &corePreparerFake{}, backend, CoreServiceOptions{}); err == nil {
		t.Fatal("NewCoreService accepted nil lifecycle")
	}
	if _, err := NewCoreService(&Lifecycle{}, nil, backend, CoreServiceOptions{}); err == nil {
		t.Fatal("NewCoreService accepted nil preparer")
	}
	if _, err := NewCoreService(&Lifecycle{}, &corePreparerFake{}, nil, CoreServiceOptions{}); err == nil {
		t.Fatal("NewCoreService accepted nil backend")
	}
	var typedNilPreparer *corePreparerFake
	if _, err := NewCoreService(&Lifecycle{}, typedNilPreparer, backend, CoreServiceOptions{}); err == nil {
		t.Fatal("NewCoreService accepted typed-nil preparer")
	}
	var typedNilBackend *coreBackendFake
	if _, err := NewCoreService(&Lifecycle{}, &corePreparerFake{}, typedNilBackend, CoreServiceOptions{}); err == nil {
		t.Fatal("NewCoreService accepted typed-nil backend")
	}
	if _, err := NewCoreService(&Lifecycle{}, &corePreparerFake{}, backend, CoreServiceOptions{CoreName: "bad\nname"}); err == nil {
		t.Fatal("NewCoreService accepted multiline core name")
	}
}

func waitForCoreLogMessage(t *testing.T, service *CoreService, message string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		entries, err := service.CoreLogs(context.Background(), web.LogQuery{Limit: 100})
		if err == nil && len(entries) > 0 && entries[len(entries)-1].Message == message {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for core log %q", message)
}

func testCapturePlan() engine.CapturePlan {
	return engine.CapturePlan{
		TCP:      engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		UDP:      engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		LoopMark: 2,
	}
}
