package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/cli"
	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/eventlog"
	"github.com/kontsevoye/boxctl/internal/platform/openwrt"
	"github.com/kontsevoye/boxctl/internal/state"
)

type forbiddenRunner struct{ t *testing.T }

func (runner forbiddenRunner) Run(context.Context, openwrt.Command) (openwrt.Result, error) {
	runner.t.Helper()
	runner.t.Fatal("unexpected host command")
	return openwrt.Result{}, nil
}

type testLifecycle struct {
	mu          sync.Mutex
	starts      int
	stops       int
	monitors    int
	monitorDone chan struct{}
	startErr    error
}

func (lifecycle *testLifecycle) Start(context.Context) error {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	lifecycle.starts++
	return lifecycle.startErr
}

func (lifecycle *testLifecycle) Stop(context.Context) error {
	lifecycle.mu.Lock()
	lifecycle.stops++
	lifecycle.mu.Unlock()
	return nil
}

func (lifecycle *testLifecycle) Monitor(ctx context.Context) {
	lifecycle.mu.Lock()
	lifecycle.monitors++
	lifecycle.mu.Unlock()
	<-ctx.Done()
	if lifecycle.monitorDone != nil {
		close(lifecycle.monitorDone)
	}
}

func (lifecycle *testLifecycle) counts() (int, int, int) {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	return lifecycle.starts, lifecycle.stops, lifecycle.monitors
}

type cancelListener struct {
	once     sync.Once
	closed   chan struct{}
	onAccept func()
}

func newCancelListener(onAccept func()) *cancelListener {
	return &cancelListener{closed: make(chan struct{}), onAccept: onAccept}
}

func (listener *cancelListener) Accept() (net.Conn, error) {
	listener.once.Do(listener.onAccept)
	<-listener.closed
	return nil, net.ErrClosed
}

func (listener *cancelListener) Close() error {
	select {
	case <-listener.closed:
	default:
		close(listener.closed)
	}
	return nil
}

func (*cancelListener) Addr() net.Addr { return testAddress("127.0.0.1:9091") }

type testAddress string

func (address testAddress) Network() string { return "tcp" }
func (address testAddress) String() string  { return string(address) }

type singleConnListener struct {
	mu     sync.Mutex
	conn   net.Conn
	closed chan struct{}
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{conn: conn, closed: make(chan struct{})}
}

func (listener *singleConnListener) Accept() (net.Conn, error) {
	listener.mu.Lock()
	if listener.conn != nil {
		conn := listener.conn
		listener.conn = nil
		listener.mu.Unlock()
		return conn, nil
	}
	listener.mu.Unlock()
	<-listener.closed
	return nil, net.ErrClosed
}

func (listener *singleConnListener) Close() error {
	select {
	case <-listener.closed:
	default:
		close(listener.closed)
	}
	return nil
}

func (*singleConnListener) Addr() net.Addr { return testAddress("127.0.0.1:9091") }

type requestAwareLifecycle struct {
	requestDone <-chan struct{}
}

func (*requestAwareLifecycle) Start(context.Context) error { return nil }

func (lifecycle *requestAwareLifecycle) Stop(ctx context.Context) error {
	select {
	case <-lifecycle.requestDone:
		return nil
	case <-ctx.Done():
		return errors.New("request context was not canceled before lifecycle stop")
	}
}

func (*requestAwareLifecycle) Monitor(ctx context.Context) { <-ctx.Done() }

func supportedPlatform(context.Context, openwrt.Runner) (PlatformReport, error) {
	return PlatformReport{Distribution: "OpenWrt", Model: "Example Router", Board: "vendor,router", Architecture: "aarch64", Supported: true}, nil
}

func newIsolatedActions(t *testing.T, output io.Writer) *Actions {
	t.Helper()
	actions := NewActions(ActionOptions{
		Runner: forbiddenRunner{t: t},
		Getenv: func(string) string { return "" },
		Out:    output,
		Err:    io.Discard,
	})
	actions.probePlatform = supportedPlatform
	actions.probeRoutingIP = func(context.Context, openwrt.Runner) error { return nil }
	actions.openWrtLockRoot = t.TempDir()
	return actions
}

func TestServeWithoutCoreDoesNotOwnLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	lifecycle := &testLifecycle{}
	actions := newIsolatedActions(t, io.Discard)
	actions.listen = func(string, string) (net.Listener, error) {
		return newCancelListener(cancel), nil
	}
	actions.buildServe = func(context.Context, string, serveBuildOptions, openwrt.Runner, *slog.Logger, *eventlog.Ring) (*serveRuntime, error) {
		return &serveRuntime{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Lifecycle: lifecycle}, nil
	}
	if err := actions.Serve(ctx, cli.ServeOptions{Root: t.TempDir(), Listen: "127.0.0.1:9091", NoCore: true}); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	starts, stops, monitors := lifecycle.counts()
	if starts != 0 || stops != 0 || monitors != 0 {
		t.Fatalf("no-core mode mutated lifecycle: start=%d stop=%d monitor=%d", starts, stops, monitors)
	}
}

func TestServeOwnsLifecycleAndGracefullyStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	lifecycle := &testLifecycle{monitorDone: make(chan struct{})}
	closed := false
	actions := newIsolatedActions(t, io.Discard)
	actions.listen = func(string, string) (net.Listener, error) {
		return newCancelListener(cancel), nil
	}
	actions.buildServe = func(context.Context, string, serveBuildOptions, openwrt.Runner, *slog.Logger, *eventlog.Ring) (*serveRuntime, error) {
		return &serveRuntime{
			Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Lifecycle: lifecycle,
			Close: func() error { closed = true; return nil },
		}, nil
	}
	if err := actions.Serve(ctx, cli.ServeOptions{Root: t.TempDir(), Listen: "127.0.0.1:9091"}); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	select {
	case <-lifecycle.monitorDone:
	case <-time.After(time.Second):
		t.Fatal("monitor was not canceled")
	}
	starts, stops, monitors := lifecycle.counts()
	if starts != 1 || stops != 1 || monitors != 1 {
		t.Fatalf("unexpected lifecycle calls: start=%d stop=%d monitor=%d", starts, stops, monitors)
	}
	if !closed {
		t.Fatal("runtime resources were not closed")
	}
}

func TestServeSelfUpdateHandoffPreservesLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	lifecycle := &testLifecycle{monitorDone: make(chan struct{})}
	root := t.TempDir()
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeManagerHandoff(layout, "next"); err != nil {
		t.Fatal(err)
	}
	actions := newIsolatedActions(t, io.Discard)
	actions.listen = func(string, string) (net.Listener, error) { return newCancelListener(cancel), nil }
	actions.buildServe = func(context.Context, string, serveBuildOptions, openwrt.Runner, *slog.Logger, *eventlog.Ring) (*serveRuntime, error) {
		return &serveRuntime{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Lifecycle: lifecycle}, nil
	}
	if err := actions.Serve(ctx, cli.ServeOptions{Root: root, Listen: "127.0.0.1:9091"}); err != nil {
		t.Fatal(err)
	}
	starts, stops, monitors := lifecycle.counts()
	if starts != 1 || stops != 0 || monitors != 1 {
		t.Fatalf("handoff lifecycle calls: start=%d stop=%d monitor=%d", starts, stops, monitors)
	}
}

func TestServeStartStoppedBuildsManagementAndMonitorsWithoutInitialStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	lifecycle := &testLifecycle{monitorDone: make(chan struct{})}
	closed := false
	actions := newIsolatedActions(t, io.Discard)
	actions.listen = func(string, string) (net.Listener, error) {
		return newCancelListener(cancel), nil
	}
	actions.buildServe = func(context.Context, string, serveBuildOptions, openwrt.Runner, *slog.Logger, *eventlog.Ring) (*serveRuntime, error) {
		return &serveRuntime{
			Handler:   http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
			Lifecycle: lifecycle,
			Close:     func() error { closed = true; return nil },
		}, nil
	}
	if err := actions.Serve(ctx, cli.ServeOptions{
		Root: t.TempDir(), Listen: "127.0.0.1:9091", StartStopped: true,
	}); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	select {
	case <-lifecycle.monitorDone:
	case <-time.After(time.Second):
		t.Fatal("monitor was not canceled")
	}
	starts, stops, monitors := lifecycle.counts()
	if starts != 0 || stops != 2 || monitors != 1 {
		t.Fatalf("unexpected lifecycle calls: start=%d stop=%d monitor=%d", starts, stops, monitors)
	}
	if !closed {
		t.Fatal("runtime resources were not closed")
	}
}

func TestServeCancelsActiveRequestBeforeLifecycleStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	listener := newSingleConnListener(serverConn)
	handlerStarted := make(chan struct{})
	requestDone := make(chan struct{})
	lifecycle := &requestAwareLifecycle{requestDone: requestDone}
	actions := newIsolatedActions(t, io.Discard)
	actions.listen = func(string, string) (net.Listener, error) { return listener, nil }
	actions.buildServe = func(context.Context, string, serveBuildOptions, openwrt.Runner, *slog.Logger, *eventlog.Ring) (*serveRuntime, error) {
		return &serveRuntime{
			Lifecycle: lifecycle,
			Handler: http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
				close(handlerStarted)
				<-request.Context().Done()
				close(requestDone)
			}),
		}, nil
	}
	result := make(chan error, 1)
	go func() {
		result <- actions.Serve(ctx, cli.ServeOptions{Root: t.TempDir(), Listen: "127.0.0.1:9091"})
	}()
	if _, err := io.WriteString(clientConn, "GET / HTTP/1.1\r\nHost: router\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.Copy(io.Discard, clientConn) }()
	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("request handler did not start")
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not stop after request cancellation")
	}
}

func TestServeWaitsForCanceledActiveOperationThenStopsLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fake := &lifecycleFake{health: engine.HealthStatus{Running: true, ControllerReady: true}}
	lifecycle := &Lifecycle{
		Preparer: fake, Core: fake, Activation: fake,
		CleanupTimeout: 50 * time.Millisecond,
		snap: LifecycleSnapshot{
			State:    LifecycleRunning,
			Prepared: engine.PreparedCore{Engine: "mihomo", BinaryPath: "/fake/core"},
			Health:   engine.HealthStatus{Running: true, ControllerReady: true},
		},
	}
	var serviceContext context.Context
	activeDone := make(chan struct{})
	actions := newIsolatedActions(t, io.Discard)
	actions.buildServe = func(runtimeContext context.Context, _ string, _ serveBuildOptions, _ openwrt.Runner, _ *slog.Logger, _ *eventlog.Ring) (*serveRuntime, error) {
		serviceContext = runtimeContext
		return &serveRuntime{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Lifecycle: lifecycle}, nil
	}
	actions.listen = func(string, string) (net.Listener, error) {
		return newCancelListener(func() {
			lifecycle.opMu.Lock()
			go func() {
				<-serviceContext.Done()
				time.Sleep(25 * time.Millisecond)
				lifecycle.opMu.Unlock()
				close(activeDone)
			}()
			cancel()
		}), nil
	}

	started := time.Now()
	if err := actions.Serve(ctx, cli.ServeOptions{Root: t.TempDir(), Listen: "127.0.0.1:9091"}); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("Serve shutdown took %v after active operation cancellation", elapsed)
	}
	select {
	case <-activeDone:
	default:
		t.Fatal("active operation did not release lifecycle gate")
	}
	if !slices.Equal(fake.events, []string{"gateway-deactivate", "core-stop"}) {
		t.Fatalf("shutdown events = %v", fake.events)
	}
}

type retryingShutdownLifecycle struct {
	mu       sync.Mutex
	stops    int
	failures int
}

func (*retryingShutdownLifecycle) Start(context.Context) error { return nil }
func (*retryingShutdownLifecycle) Monitor(ctx context.Context) { <-ctx.Done() }
func (lifecycle *retryingShutdownLifecycle) Stop(context.Context) error {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	lifecycle.stops++
	if lifecycle.stops <= lifecycle.failures {
		return errors.New("gateway lock is still owned by hotplug")
	}
	return nil
}

func TestShutdownRetriesCleanupBeforeAllowingCoreExit(t *testing.T) {
	lifecycle := &retryingShutdownLifecycle{failures: 2}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := stopLifecycleForShutdown(ctx, lifecycle); err != nil {
		t.Fatalf("stopLifecycleForShutdown() error = %v", err)
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.stops != 3 {
		t.Fatalf("shutdown cleanup attempts = %d, want 3", lifecycle.stops)
	}
}

func TestServeKeepsManagementAvailableWhenInitialCoreStartFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	lifecycle := &testLifecycle{startErr: errors.New("missing Mihomo"), monitorDone: make(chan struct{})}
	actions := newIsolatedActions(t, io.Discard)
	accepted := make(chan struct{})
	actions.listen = func(string, string) (net.Listener, error) {
		return newCancelListener(func() {
			close(accepted)
			cancel()
		}), nil
	}
	actions.buildServe = func(context.Context, string, serveBuildOptions, openwrt.Runner, *slog.Logger, *eventlog.Ring) (*serveRuntime, error) {
		return &serveRuntime{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Lifecycle: lifecycle}, nil
	}
	if err := actions.Serve(ctx, cli.ServeOptions{Root: t.TempDir(), Listen: "127.0.0.1:9091"}); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	select {
	case <-accepted:
	default:
		t.Fatal("management listener never accepted after lifecycle failure")
	}
	select {
	case <-lifecycle.monitorDone:
	case <-time.After(time.Second):
		t.Fatal("monitor was not canceled")
	}
	starts, stops, monitors := lifecycle.counts()
	if starts != 1 || stops != 1 || monitors != 1 {
		t.Fatalf("unexpected lifecycle calls: start=%d stop=%d monitor=%d", starts, stops, monitors)
	}
}

func TestServeNoGatewayStillSupervisesCoreThroughInjectedNoopGraph(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	lifecycle := &testLifecycle{}
	actions := newIsolatedActions(t, io.Discard)
	actions.listen = func(string, string) (net.Listener, error) { return newCancelListener(cancel), nil }
	actions.buildServe = func(_ context.Context, _ string, options serveBuildOptions, _ openwrt.Runner, _ *slog.Logger, _ *eventlog.Ring) (*serveRuntime, error) {
		if !options.NoGateway || options.NoCore || options.UnsafeExternalDashboard || options.PublicOrigin != "" {
			t.Fatalf("wrong build options: %#v", options)
		}
		return &serveRuntime{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Lifecycle: lifecycle}, nil
	}
	if err := actions.Serve(ctx, cli.ServeOptions{Root: t.TempDir(), Listen: "127.0.0.1:9091", NoGateway: true}); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	starts, stops, _ := lifecycle.counts()
	if starts != 1 || stops != 1 {
		t.Fatalf("core-only lifecycle calls = start %d stop %d", starts, stops)
	}
}

func TestServeWiresExplicitPublicWebOptions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	actions := newIsolatedActions(t, io.Discard)
	actions.getenv = func(key string) string {
		return map[string]string{
			"BOXCTL_ALLOWED_HOSTS":                    "router.example, router.home",
			"BOXCTL_PUBLIC_ORIGIN":                    "https://router.example",
			"BOXCTL_ENABLE_UNSAFE_EXTERNAL_DASHBOARD": "true",
		}[key]
	}
	actions.listen = func(string, string) (net.Listener, error) { return newCancelListener(cancel), nil }
	actions.buildServe = func(_ context.Context, _ string, options serveBuildOptions, _ openwrt.Runner, _ *slog.Logger, _ *eventlog.Ring) (*serveRuntime, error) {
		if options.PublicOrigin != "https://router.example" || !options.UnsafeExternalDashboard {
			t.Fatalf("web options = %#v", options)
		}
		if !slices.Equal(options.AllowedHosts, []string{"127.0.0.1", "router.example", "router.home"}) {
			t.Fatalf("allowed hosts = %#v", options.AllowedHosts)
		}
		return &serveRuntime{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Lifecycle: &testLifecycle{}}, nil
	}
	if err := actions.Serve(ctx, cli.ServeOptions{Root: t.TempDir(), Listen: "127.0.0.1:9091", NoGateway: true}); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
}

func TestServeRejectsWildcardBeforeBuildingOrListening(t *testing.T) {
	actions := newIsolatedActions(t, io.Discard)
	actions.getenv = func(key string) string {
		if key == "BOXCTL_ADDR" {
			return "0.0.0.0:9091"
		}
		return ""
	}
	called := false
	actions.buildServe = func(context.Context, string, serveBuildOptions, openwrt.Runner, *slog.Logger, *eventlog.Ring) (*serveRuntime, error) {
		called = true
		return nil, nil
	}
	err := actions.Serve(context.Background(), cli.ServeOptions{Root: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("wildcard bind error = %v", err)
	}
	if called {
		t.Fatal("runtime built after unsafe bind")
	}
}

func TestExplicitBooleanSettingRejectsAmbiguousValues(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"", "0", "false", "off", "no"} {
		enabled, err := parseExplicitBoolSetting("FEATURE", value)
		if err != nil || enabled {
			t.Errorf("parseExplicitBoolSetting(%q) = %v, %v", value, enabled, err)
		}
	}
	for _, value := range []string{"1", "true", "on", "yes"} {
		enabled, err := parseExplicitBoolSetting("FEATURE", value)
		if err != nil || !enabled {
			t.Errorf("parseExplicitBoolSetting(%q) = %v, %v", value, enabled, err)
		}
	}
	if _, err := parseExplicitBoolSetting("FEATURE", "enabled-ish"); err == nil {
		t.Fatal("ambiguous boolean value was accepted")
	}
}

func TestManagerSingletonLockRejectsSecondOwner(t *testing.T) {
	root := t.TempDir()
	first, err := acquireManagerLock(context.Background(), root, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Unlock() }()
	second, err := acquireManagerLock(context.Background(), root, 40*time.Millisecond)
	if second != nil {
		_ = second.Unlock()
		t.Fatal("second manager acquired singleton lock")
	}
	if err == nil || !strings.Contains(err.Error(), "already owns") {
		t.Fatalf("second manager lock error = %v", err)
	}
}

func TestOpenWrtOwnerLockIsGlobalAcrossDifferentDataRoots(t *testing.T) {
	firstRoot := t.TempDir()
	secondRoot := t.TempDir()
	firstManager, err := acquireManagerLock(context.Background(), firstRoot, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = firstManager.Unlock() }()
	secondManager, err := acquireManagerLock(context.Background(), secondRoot, time.Second)
	if err != nil {
		t.Fatalf("different data root unexpectedly shared local daemon lock: %v", err)
	}
	defer func() { _ = secondManager.Unlock() }()

	lockRoot := t.TempDir()
	firstOwner, err := acquireOpenWrtOwnerLock(context.Background(), lockRoot, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = firstOwner.Unlock() }()
	secondOwner, err := acquireOpenWrtOwnerLock(context.Background(), lockRoot, 40*time.Millisecond)
	if secondOwner != nil {
		_ = secondOwner.Unlock()
		t.Fatal("second data root acquired the global OpenWrt owner lock")
	}
	if err == nil || !strings.Contains(err.Error(), "owns the OpenWrt gateway") {
		t.Fatalf("second OpenWrt owner lock error = %v", err)
	}
}

type fakePreparer struct {
	prepared engine.PreparedCore
	calls    int
}

func (preparer *fakePreparer) PrepareActive(context.Context) (engine.PreparedCore, error) {
	preparer.calls++
	return preparer.prepared, nil
}

type fakeActivation struct {
	activated            int
	deactivated          int
	reconciled           int
	diagnosed            int
	activePrepared       engine.PreparedCore
	activeErr            error
	reconciledPrepared   engine.PreparedCore
	diagnosedPrepared    engine.PreparedCore
	activateErr          error
	reconcileErr         error
	deactivateErr        error
	cancelOnActivate     context.CancelFunc
	deactivateContextErr error
}

func (activation *fakeActivation) Activate(context.Context, engine.PreparedCore) error {
	activation.activated++
	if activation.cancelOnActivate != nil {
		activation.cancelOnActivate()
	}
	return activation.activateErr
}

func (activation *fakeActivation) Deactivate(ctx context.Context, _ engine.PreparedCore) error {
	activation.deactivated++
	activation.deactivateContextErr = ctx.Err()
	return activation.deactivateErr
}

func TestFirewallStartFailureIsHandledByActiveGenerationReconcile(t *testing.T) {
	server, prepared := readyController(t)
	defer server.Close()
	activation := &fakeActivation{activePrepared: prepared, reconcileErr: context.Canceled}
	preparer := &fakePreparer{prepared: engine.PreparedCore{}}
	actions := newIsolatedActions(t, io.Discard)
	actions.buildOneShot = func(string, openwrt.Runner) (*oneShotRuntime, error) {
		return &oneShotRuntime{Preparer: preparer, Activation: activation}, nil
	}

	err := actions.Firewall(context.Background(), "start")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Firewall(start) error = %v, want cancellation", err)
	}
	if activation.reconciled != 1 || activation.activated != 0 || activation.deactivated != 0 || preparer.calls != 0 {
		t.Fatalf("start calls: reconcile=%d activate=%d deactivate=%d prepare=%d", activation.reconciled, activation.activated, activation.deactivated, preparer.calls)
	}
}

func (activation *fakeActivation) Reconcile(_ context.Context, prepared engine.PreparedCore) error {
	activation.reconciled++
	activation.reconciledPrepared = prepared
	return activation.reconcileErr
}

func (activation *fakeActivation) ActivePrepared(context.Context) (engine.PreparedCore, error) {
	return activation.activePrepared, activation.activeErr
}

func (activation *fakeActivation) Diagnose(_ context.Context, prepared engine.PreparedCore) (openwrt.CheckResult, error) {
	activation.diagnosed++
	activation.diagnosedPrepared = prepared
	return openwrt.CheckResult{Exists: true, Owned: true, PlanMatches: true, PolicyMatches: true, FirewallMatches: true}, nil
}

func readyController(t *testing.T) (*httptest.Server, engine.PreparedCore) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/version" {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"version":"v1.19.30","meta":true}`)
	}))
	return server, engine.PreparedCore{Controller: engine.ControllerEndpoint{BaseURL: server.URL}}
}

func TestFirewallAndHotplugUseInjectedRuntime(t *testing.T) {
	server, prepared := readyController(t)
	defer server.Close()
	for _, test := range []struct {
		command     string
		want        func(*fakeActivation) int
		wantPrepare int
	}{
		{command: "start", want: func(value *fakeActivation) int { return value.reconciled }},
		{command: "update", want: func(value *fakeActivation) int { return value.reconciled }},
		{command: "diagnose", want: func(value *fakeActivation) int { return value.diagnosed }},
	} {
		t.Run(test.command, func(t *testing.T) {
			activation := &fakeActivation{activePrepared: prepared}
			preparer := &fakePreparer{prepared: prepared}
			var output bytes.Buffer
			actions := newIsolatedActions(t, &output)
			actions.buildOneShot = func(string, openwrt.Runner) (*oneShotRuntime, error) {
				return &oneShotRuntime{Preparer: preparer, Activation: activation}, nil
			}
			if err := actions.Firewall(context.Background(), test.command); err != nil {
				t.Fatalf("Firewall() error = %v", err)
			}
			if test.want(activation) != 1 || preparer.calls != test.wantPrepare {
				t.Fatalf("wrong calls: activation=%#v prepare=%d", activation, preparer.calls)
			}
		})
	}

	activation := &fakeActivation{activePrepared: prepared}
	preparer := &fakePreparer{prepared: prepared}
	actions := newIsolatedActions(t, io.Discard)
	actions.buildOneShot = func(string, openwrt.Runner) (*oneShotRuntime, error) {
		return &oneShotRuntime{Preparer: preparer, Activation: activation}, nil
	}
	if err := actions.Hotplug(context.Background(), cli.HotplugOptions{Event: "wan"}); err != nil {
		t.Fatalf("Hotplug() error = %v", err)
	}
	if activation.reconciled != 1 {
		t.Fatalf("hotplug reconcile calls = %d", activation.reconciled)
	}
}

func TestFirewallStartAndDiagnoseIgnoreUnactivatedDiskGeneration(t *testing.T) {
	server, ready := readyController(t)
	defer server.Close()
	active := ready
	active.Capture = engine.CapturePlan{
		TCP: engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
		UDP: engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894},
	}
	disk := ready
	disk.Capture = engine.CapturePlan{
		TCP: engine.ProtocolCapture{Method: engine.CaptureRedirect, Port: 19093},
		UDP: engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 19094},
	}
	for _, command := range []string{"start", "diagnose"} {
		t.Run(command, func(t *testing.T) {
			activation := &fakeActivation{activePrepared: active}
			preparer := &fakePreparer{prepared: disk}
			actions := newIsolatedActions(t, io.Discard)
			actions.buildOneShot = func(string, openwrt.Runner) (*oneShotRuntime, error) {
				return &oneShotRuntime{Preparer: preparer, Activation: activation}, nil
			}
			if err := actions.Firewall(context.Background(), command); err != nil {
				t.Fatalf("Firewall(%s) error = %v", command, err)
			}
			if preparer.calls != 0 {
				t.Fatalf("Firewall(%s) prepared an unactivated disk generation", command)
			}
			got := activation.reconciledPrepared
			if command == "diagnose" {
				got = activation.diagnosedPrepared
			}
			if !reflect.DeepEqual(got.Capture, active.Capture) {
				t.Fatalf("Firewall(%s) generation = %+v, want active %+v", command, got.Capture, active.Capture)
			}
		})
	}
}

func TestFirewallMutationsAndDiagnoseFailClosedWithoutActiveGeneration(t *testing.T) {
	for _, command := range []string{"start", "update", "diagnose"} {
		t.Run(command, func(t *testing.T) {
			activation := &fakeActivation{activeErr: os.ErrNotExist}
			preparer := &fakePreparer{prepared: engine.PreparedCore{
				Controller: engine.ControllerEndpoint{BaseURL: "http://127.0.0.1:9090"},
			}}
			actions := newIsolatedActions(t, io.Discard)
			actions.buildOneShot = func(string, openwrt.Runner) (*oneShotRuntime, error) {
				return &oneShotRuntime{Preparer: preparer, Activation: activation}, nil
			}
			err := actions.Firewall(context.Background(), command)
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("Firewall(%s) error = %v", command, err)
			}
			if preparer.calls != 0 || activation.reconciled != 0 || activation.diagnosed != 0 || activation.activated != 0 {
				t.Fatalf("Firewall(%s) mutated without an active generation: prepare=%d activation=%+v", command, preparer.calls, activation)
			}
		})
	}
}

func TestTUNHotplugOnlyReconcilesMatchingActiveTUN(t *testing.T) {
	t.Parallel()
	server, ready := readyController(t)
	defer server.Close()

	for _, test := range []struct {
		name      string
		capture   engine.CapturePlan
		reported  string
		wantCalls int
	}{
		{
			name:      "custom device matches",
			capture:   engine.CapturePlan{UDP: engine.ProtocolCapture{Method: engine.CaptureTUN}, TUNDevice: "mihomo0"},
			reported:  "mihomo0",
			wantCalls: 1,
		},
		{
			name:     "different device",
			capture:  engine.CapturePlan{UDP: engine.ProtocolCapture{Method: engine.CaptureTUN}, TUNDevice: "mihomo0"},
			reported: "unrelated0",
		},
		{
			name:     "active mode does not use TUN",
			capture:  engine.CapturePlan{TCP: engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894}, UDP: engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 7894}, TUNDevice: "mihomo0"},
			reported: "mihomo0",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			activePrepared := ready
			activePrepared.Capture = test.capture
			activation := &fakeActivation{activePrepared: activePrepared}
			prepared := ready
			prepared.Capture = engine.CapturePlan{
				TCP: engine.ProtocolCapture{Method: engine.CaptureRedirect, Port: 6553},
				UDP: engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: 6554},
			}
			preparer := &fakePreparer{prepared: prepared}
			actions := newIsolatedActions(t, io.Discard)
			actions.buildOneShot = func(string, openwrt.Runner) (*oneShotRuntime, error) {
				return &oneShotRuntime{Preparer: preparer, Activation: activation}, nil
			}

			err := actions.Hotplug(context.Background(), cli.HotplugOptions{Event: "tun", Interface: test.reported})
			if err != nil {
				t.Fatalf("Hotplug() error = %v", err)
			}
			if activation.reconciled != test.wantCalls || preparer.calls != 0 {
				t.Fatalf("hotplug calls: reconcile=%d prepare=%d", activation.reconciled, preparer.calls)
			}
			if test.wantCalls == 1 && activation.reconciledPrepared.Capture.TUNDevice != test.reported {
				t.Fatalf("hotplug used disk capture instead of active generation: %+v", activation.reconciledPrepared.Capture)
			}
		})
	}
}

func TestTUNHotplugRejectsMissingReportedInterface(t *testing.T) {
	t.Parallel()
	actions := newIsolatedActions(t, io.Discard)
	err := actions.Hotplug(context.Background(), cli.HotplugOptions{Event: "tun"})
	if err == nil || !strings.Contains(err.Error(), "requires an interface") {
		t.Fatalf("Hotplug() error = %v", err)
	}
}

func TestCleanupDoesNotPrepareOrRunHostCommandsThroughTestRunner(t *testing.T) {
	activation := &fakeActivation{}
	preparer := &fakePreparer{}
	actions := newIsolatedActions(t, io.Discard)
	locks, err := state.NewStore(actions.openWrtLockRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := claimOpenWrtOwnerState(context.Background(), locks, state.DefaultRoot); err != nil {
		t.Fatal(err)
	}
	actions.buildOneShot = func(string, openwrt.Runner) (*oneShotRuntime, error) {
		return &oneShotRuntime{Preparer: preparer, Activation: activation}, nil
	}
	if err := actions.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if activation.deactivated != 1 || preparer.calls != 0 {
		t.Fatalf("cleanup calls: deactivate=%d prepare=%d", activation.deactivated, preparer.calls)
	}
	if _, err := locks.Read(openWrtOwnerStatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful standalone cleanup retained owner state: %v", err)
	}
}

func TestCleanupRetainsOwnerStateWhenDeactivationFails(t *testing.T) {
	actions := newIsolatedActions(t, io.Discard)
	locks, err := state.NewStore(actions.openWrtLockRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := claimOpenWrtOwnerState(context.Background(), locks, state.DefaultRoot); err != nil {
		t.Fatal(err)
	}
	cleanupErr := errors.New("policy cleanup incomplete")
	actions.buildOneShot = func(string, openwrt.Runner) (*oneShotRuntime, error) {
		return &oneShotRuntime{Activation: &fakeActivation{deactivateErr: cleanupErr}}, nil
	}
	if err := actions.Cleanup(context.Background()); !errors.Is(err, cleanupErr) {
		t.Fatalf("Cleanup() error = %v", err)
	}
	owner, err := loadOpenWrtOwnerState(locks)
	if err != nil || owner.Root != state.DefaultRoot {
		t.Fatalf("failed cleanup owner state = %+v, %v", owner, err)
	}
}

func TestDoctorJSONIsReadOnlyAndReturnsFailedStatus(t *testing.T) {
	var output bytes.Buffer
	actions := newIsolatedActions(t, &output)
	root := t.TempDir()
	actions.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	err := actions.Doctor(context.Background(), cli.DoctorOptions{Root: root, JSON: true})
	var doctorErr *DoctorError
	if !errors.As(err, &doctorErr) || doctorErr.Failures == 0 {
		t.Fatalf("Doctor() error = %#v", err)
	}
	var report DoctorReport
	if decodeErr := json.Unmarshal(output.Bytes(), &report); decodeErr != nil {
		t.Fatalf("decode doctor output: %v: %q", decodeErr, output.String())
	}
	if report.Root != root || report.Platform.Supported != true {
		t.Fatalf("doctor report = %#v", report)
	}
}

func TestDoctorReportsMissingIPFull(t *testing.T) {
	var output bytes.Buffer
	actions := newIsolatedActions(t, &output)
	actions.probeRoutingIP = func(context.Context, openwrt.Runner) error {
		return errors.New("ip-full is required: ip -j link show exited with 1")
	}
	root := t.TempDir()
	err := actions.Doctor(context.Background(), cli.DoctorOptions{Root: root, JSON: true})
	var doctorErr *DoctorError
	if !errors.As(err, &doctorErr) {
		t.Fatalf("Doctor() error = %#v", err)
	}
	var report DoctorReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("decode doctor output: %v", err)
	}
	for _, check := range report.Checks {
		if check.Name == "ip-full" {
			if check.OK || !strings.Contains(check.Message, "ip-full is required") {
				t.Fatalf("ip-full check = %#v", check)
			}
			return
		}
	}
	t.Fatalf("ip-full check missing from %#v", report.Checks)
}

func TestSetPasswordAndValidationUseInjectedFilesystemBoundaries(t *testing.T) {
	actions := newIsolatedActions(t, io.Discard)
	root := t.TempDir()
	actions.getenv = func(key string) string {
		if key == "BOXCTL_ROOT" {
			return root
		}
		return ""
	}
	setCalled := false
	actions.setPassword = func(gotRoot string, input io.Reader, output io.Writer) error {
		setCalled = gotRoot == root && input != nil && output != nil
		return nil
	}
	if err := actions.SetPassword(context.Background(), strings.NewReader("password\npassword\n"), io.Discard); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}
	if !setCalled {
		t.Fatal("password hook was not called")
	}

	validateCalled := false
	actions.validateConfig = func(context.Context, string, string) error { validateCalled = true; return nil }
	if err := actions.ValidateConfig(context.Background(), "relative.yaml"); err == nil {
		t.Fatal("relative config path accepted")
	}
	path := filepath.Join(root, "config.yaml")
	if err := actions.ValidateConfig(context.Background(), path); err != nil {
		t.Fatalf("ValidateConfig() error = %v", err)
	}
	if !validateCalled {
		t.Fatal("validation hook was not called")
	}
}

func TestSetPasswordSerializesWithStateMaintenance(t *testing.T) {
	actions := newIsolatedActions(t, io.Discard)
	root := t.TempDir()
	actions.getenv = func(key string) string {
		if key == "BOXCTL_ROOT" {
			return root
		}
		return ""
	}
	called := 0
	actions.setPassword = func(string, io.Reader, io.Writer) error {
		called++
		return nil
	}
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	stateLock, err := store.Lock(context.Background(), "state")
	if err != nil {
		t.Fatal(err)
	}
	blockedContext, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	err = actions.SetPassword(blockedContext, strings.NewReader("password\npassword\n"), io.Discard)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || called != 0 {
		t.Fatalf("blocked SetPassword() error=%v calls=%d", err, called)
	}
	if err := stateLock.Unlock(); err != nil {
		t.Fatal(err)
	}
	if err := actions.SetPassword(context.Background(), strings.NewReader("password\npassword\n"), io.Discard); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("unblocked SetPassword() calls=%d", called)
	}
}

func TestTLSAndListenValidation(t *testing.T) {
	for _, address := range []string{
		"0.0.0.0:9091",
		"[::]:9091",
		"[0:0:0:0:0:0:0:0]:9091",
		"[::0]:9091",
		":9091",
	} {
		if _, err := validateListenAddress(address); err == nil {
			t.Fatalf("unsafe address %q accepted", address)
		}
	}
	if got, err := validateListenAddress("192.168.1.1"); err != nil || got != "192.168.1.1:9091" {
		t.Fatalf("LAN address = %q, %v", got, err)
	}
	if _, err := parseTLSSetting("true"); err == nil {
		t.Fatal("TLS enabled without certificate/key")
	}
	directory := t.TempDir()
	certificate := filepath.Join(directory, "cert.pem")
	key := filepath.Join(directory, "key.pem")
	if err := os.WriteFile(certificate, []byte("certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	settings, err := parseTLSSetting(certificate + "," + key)
	if err != nil || !settings.Enabled || settings.Certificate != certificate || settings.Key != key {
		t.Fatalf("TLS settings = %#v, %v", settings, err)
	}
}

type platformRunner struct{ commands []openwrt.Command }

func (runner *platformRunner) Run(_ context.Context, command openwrt.Command) (openwrt.Result, error) {
	runner.commands = append(runner.commands, command)
	switch command.Name {
	case "ubus":
		return openwrt.Result{Stdout: []byte(`{"model":"Example Router","board_name":"vendor,router","release":{"distribution":"OpenWrt"}}`)}, nil
	case "uname":
		return openwrt.Result{Stdout: []byte("aarch64\n")}, nil
	default:
		return openwrt.Result{}, errors.New("unexpected command")
	}
}

func TestPlatformProbeUsesReadOnlyBoardCommands(t *testing.T) {
	runner := &platformRunner{}
	report, err := probeOpenWrt(context.Background(), runner)
	if err != nil || !report.Supported {
		t.Fatalf("probe = %#v, %v", report, err)
	}
	if len(runner.commands) != 2 || runner.commands[0].Name != "ubus" || runner.commands[1].Name != "uname" {
		t.Fatalf("commands = %#v", runner.commands)
	}
}

type ipProbeRunner struct {
	commands  []openwrt.Command
	failIndex int
}

func (runner *ipProbeRunner) Run(_ context.Context, command openwrt.Command) (openwrt.Result, error) {
	runner.commands = append(runner.commands, command)
	if runner.failIndex > 0 && len(runner.commands) == runner.failIndex {
		return openwrt.Result{ExitCode: 1, Stderr: []byte("unrecognized option")}, nil
	}
	return openwrt.Result{}, nil
}

func TestIPFullProbeUsesRequiredReadOnlyCommands(t *testing.T) {
	runner := &ipProbeRunner{}
	if err := probeIPFull(context.Background(), runner); err != nil {
		t.Fatalf("probeIPFull() error = %v", err)
	}
	want := [][]string{
		{"-j", "link", "show"},
		{"-j", "-4", "route", "show"},
		{"-N", "-4", "rule", "show"},
		{"-N", "-4", "route", "show", "table", "all", "proto", "196"},
	}
	if len(runner.commands) != len(want) {
		t.Fatalf("commands = %#v", runner.commands)
	}
	for index, command := range runner.commands {
		if command.Name != "ip" || !slices.Equal(command.Args, want[index]) || len(command.Stdin) != 0 {
			t.Fatalf("command[%d] = %#v", index, command)
		}
	}
}

func TestIPFullProbeExplainsBusyBoxFailure(t *testing.T) {
	runner := &ipProbeRunner{failIndex: 3}
	err := probeIPFull(context.Background(), runner)
	if err == nil || !strings.Contains(err.Error(), "ip-full is required") || !strings.Contains(err.Error(), "ip -N -4 rule show") {
		t.Fatalf("probeIPFull() error = %v", err)
	}
}
