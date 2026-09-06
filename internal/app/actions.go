package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kontsevoye/boxctl/internal/buildinfo"
	"github.com/kontsevoye/boxctl/internal/cli"
	configpkg "github.com/kontsevoye/boxctl/internal/config"
	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/eventlog"
	"github.com/kontsevoye/boxctl/internal/platform/openwrt"
	"github.com/kontsevoye/boxctl/internal/rulelist"
	"github.com/kontsevoye/boxctl/internal/state"
	updatepkg "github.com/kontsevoye/boxctl/internal/update"
	"github.com/kontsevoye/boxctl/internal/web"
)

const (
	defaultListenPort       = 9091
	serveLockTimeout        = 2 * time.Second
	oneShotOperationTimeout = 10 * time.Second
	shutdownRetryInterval   = 100 * time.Millisecond
	shutdownHandoffBudget   = 5 * time.Second
	// A separate hotplug process can spend one operation timeout followed by a
	// fresh OpenWrt rollback while holding the interprocess gateway lock. Keep
	// the core alive and retry long enough for that owner plus one final cleanup,
	// with five seconds left for hand-off/process reap. procd gives 45 seconds.
	gracefulShutdownBudget = oneShotOperationTimeout + openWrtRollbackTimeout + defaultLifecycleCleanupTimeout + shutdownHandoffBudget
)

// ActionOptions supplies process-wide dependencies. The zero value is the
// production OpenWrt implementation; fields exist so the executable boundary
// remains testable without running nft, ip, uci, ubus, or dnsmasq.
type ActionOptions struct {
	Runner openwrt.Runner
	Getenv func(string) string
	Out    io.Writer
	Err    io.Writer
}

// Actions implements the explicit command surface parsed by internal/cli.
// Host commands are reached only through the injected OpenWrt Runner.
type Actions struct {
	runner openwrt.Runner
	getenv func(string) string
	out    io.Writer
	err    io.Writer

	listen          func(string, string) (net.Listener, error)
	lanListen       func(context.Context, openwrt.Runner) (string, error)
	probePlatform   func(context.Context, openwrt.Runner) (PlatformReport, error)
	probeRoutingIP  func(context.Context, openwrt.Runner) error
	buildServe      func(context.Context, string, serveBuildOptions, openwrt.Runner, *slog.Logger, *eventlog.Ring) (*serveRuntime, error)
	buildOneShot    func(string, openwrt.Runner) (*oneShotRuntime, error)
	validateConfig  func(context.Context, string, string) error
	setPassword     func(string, io.Reader, io.Writer) error
	now             func() time.Time
	openWrtLockRoot string
}

// NewActions returns the real OpenWrt executable integration.
func NewActions(options ActionOptions) *Actions {
	runner := options.Runner
	if runner == nil {
		runner = openwrt.ExecRunner{}
	}
	getenv := options.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	out := options.Out
	if out == nil {
		out = io.Discard
	}
	errOut := options.Err
	if errOut == nil {
		errOut = io.Discard
	}
	actions := &Actions{
		runner: runner, getenv: getenv, out: out, err: errOut,
		listen: net.Listen, lanListen: defaultLANListen, probePlatform: probeOpenWrt, probeRoutingIP: probeIPFull,
		buildServe: defaultServeRuntime,
		now:        time.Now, openWrtLockRoot: defaultOpenWrtLockRoot,
	}
	actions.buildOneShot = func(root string, runner openwrt.Runner) (*oneShotRuntime, error) {
		return defaultOneShotRuntime(root, actions.openWrtLockRoot, runner)
	}
	actions.validateConfig = actions.defaultValidateConfig
	actions.setPassword = defaultSetPassword
	return actions
}

type serveBuildOptions struct {
	NoCore                  bool
	NoGateway               bool
	StartStopped            bool
	CookieSecure            bool
	AllowedHosts            []string
	PublicOrigin            string
	UnsafeExternalDashboard bool
	lockRoot                string
}

type lifecycleOwner interface {
	Start(context.Context) error
	Stop(context.Context) error
	Monitor(context.Context)
}

type serveRuntime struct {
	Handler              http.Handler
	Lifecycle            lifecycleOwner
	HandoffMarkerPending bool
	Close                func() error
}

type platformActivation interface {
	Activate(context.Context, engine.PreparedCore) error
	Deactivate(context.Context, engine.PreparedCore) error
	Reconcile(context.Context, engine.PreparedCore) error
	Diagnose(context.Context, engine.PreparedCore) (openwrt.CheckResult, error)
}

type activeGenerationProvider interface {
	ActivePrepared(context.Context) (engine.PreparedCore, error)
}

type oneShotRuntime struct {
	Preparer   ActivePreparer
	Activation platformActivation
}

// Serve starts only when the requested platform, bind address, and complete
// application graph have been validated. --no-gateway may supervise a core
// without touching routing, while --no-core never activates a gateway alone.
func (actions *Actions) Serve(ctx context.Context, options cli.ServeOptions) (returnErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := actions.resolveRoot(options.Root)
	if err != nil {
		return err
	}
	platform, err := actions.probePlatform(ctx, actions.runner)
	if err != nil {
		return fmt.Errorf("probe OpenWrt platform: %w", err)
	}
	if !platform.Supported {
		return fmt.Errorf("unsupported platform: boxctl requires OpenWrt (found %s)", platform.Description())
	}
	ownsOpenWrt := !options.NoCore && !options.NoGateway
	var ownerMayBeDirty, ownerClean bool
	daemonLock, lockErr := acquireManagerLock(ctx, root, serveLockTimeout)
	if lockErr != nil {
		return lockErr
	}
	defer func() { _ = daemonLock.Unlock() }()
	if ownsOpenWrt {
		ownerLock, ownerErr := acquireOpenWrtOwnerLock(ctx, actions.openWrtLockRoot, serveLockTimeout)
		if ownerErr != nil {
			return ownerErr
		}
		locks, storeErr := state.NewStore(actions.openWrtLockRoot)
		if storeErr != nil {
			_ = ownerLock.Unlock()
			return storeErr
		}
		if claimErr := claimOpenWrtOwnerState(ctx, locks, root); claimErr != nil {
			_ = ownerLock.Unlock()
			return claimErr
		}
		defer func() {
			var clearErr error
			if !ownerMayBeDirty || ownerClean {
				clearContext, cancelClear := context.WithTimeout(context.Background(), serveLockTimeout)
				clearErr = clearOpenWrtOwnerState(clearContext, locks, root)
				cancelClear()
			}
			returnErr = errors.Join(returnErr, clearErr, ownerLock.Unlock())
		}()
	}
	listenAddress, err := actions.resolveListen(ctx, options.Listen)
	if err != nil {
		return err
	}
	allowedHosts, err := managementAllowedHosts(listenAddress, actions.getenv("BOXCTL_ALLOWED_HOSTS"))
	if err != nil {
		return err
	}
	tlsSettings, err := parseTLSSetting(actions.getenv("BOXCTL_TLS"))
	if err != nil {
		return err
	}
	unsafeExternalDashboard, err := parseExplicitBoolSetting("BOXCTL_ENABLE_UNSAFE_EXTERNAL_DASHBOARD", actions.getenv("BOXCTL_ENABLE_UNSAFE_EXTERNAL_DASHBOARD"))
	if err != nil {
		return err
	}
	runtimeContext, cancelRuntime := context.WithCancel(ctx)
	defer cancelRuntime()

	ring := eventlog.New(1_000)
	logger := slog.New(ring.Handler(slog.LevelInfo))
	runtimeState, err := actions.buildServe(runtimeContext, root, serveBuildOptions{
		NoCore: options.NoCore, NoGateway: options.NoGateway, StartStopped: options.StartStopped,
		CookieSecure: tlsSettings.Enabled, AllowedHosts: allowedHosts,
		PublicOrigin:            strings.TrimSpace(actions.getenv("BOXCTL_PUBLIC_ORIGIN")),
		UnsafeExternalDashboard: unsafeExternalDashboard, lockRoot: actions.openWrtLockRoot,
	}, actions.runner, logger, ring)
	if err != nil {
		return fmt.Errorf("initialize service: %w", err)
	}
	if runtimeState == nil {
		return errors.New("initialize service: runtime is missing")
	}
	if runtimeState.Close == nil {
		runtimeState.Close = func() error { return nil }
	}
	defer func() {
		returnErr = errors.Join(returnErr, runtimeState.Close())
	}()
	if runtimeState.Handler == nil {
		return errors.New("initialize service: HTTP handler is missing")
	}

	listener, err := actions.listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listenAddress, err)
	}
	listenerOpen := true
	defer func() {
		if listenerOpen {
			_ = listener.Close()
		}
	}()

	// A no-core run must not make gateway/DNS changes. A no-gateway run may
	// still supervise Mihomo using the no-op activation installed by the builder.
	ownLifecycle := !options.NoCore
	monitorContext, cancelMonitor := context.WithCancel(runtimeContext)
	defer cancelMonitor()
	if ownLifecycle {
		if runtimeState.Lifecycle == nil {
			return errors.New("initialize service: lifecycle is missing")
		}
		if ownsOpenWrt {
			ownerMayBeDirty = true
		}
		if options.StartStopped {
			// Management-only startup is also a fail-open recovery point. A
			// predecessor may have died after installing owned DNS/capture state but
			// before persisting the successful first-start decision. Reconcile that
			// state to stopped before exposing the UI; cleanup-failed remains visible
			// and Monitor keeps retrying it.
			if err := runtimeState.Lifecycle.Stop(ctx); err != nil {
				logger.Error("initial management-only cleanup failed; management remains available", "error", err)
			}
		} else {
			if err := runtimeState.Lifecycle.Start(ctx); err != nil {
				// Keep the authenticated management plane available so an invalid
				// profile or missing core can be diagnosed and repaired. Lifecycle
				// startup is fail-open: activation has already rolled back before the
				// error is returned and the failed state is visible through /status.
				logger.Error("initial selective-routing start failed; management remains available", "error", err)
			}
		}
		go runtimeState.Lifecycle.Monitor(monitorContext)
	}

	requestContext, cancelRequests := context.WithCancel(runtimeContext)
	defer cancelRequests()
	server := &http.Server{
		Handler:           runtimeState.Handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
		BaseContext: func(net.Listener) context.Context {
			return requestContext
		},
	}
	serveResult := make(chan error, 1)
	go func() {
		var serveErr error
		if tlsSettings.Enabled {
			serveErr = server.ServeTLS(listener, tlsSettings.Certificate, tlsSettings.Key)
		} else {
			serveErr = server.Serve(listener)
		}
		serveResult <- serveErr
	}()
	listenerOpen = false
	logger.Info("management service listening", "address", listenAddress, "tls", tlsSettings.Enabled)
	if runtimeState.HandoffMarkerPending {
		layout, layoutErr := state.NewLayout(root)
		if layoutErr != nil {
			logger.Error("could not resolve manager handoff marker", "error", layoutErr)
		} else if removeErr := removeManagerHandoff(layout); removeErr != nil {
			logger.Error("could not consume manager handoff marker", "error", removeErr)
		} else {
			logger.Info("self-update handoff completed; Mihomo process and active connections were preserved")
		}
	}

	var cause error
	select {
	case <-ctx.Done():
		cause = ctx.Err()
	case serveErr := <-serveResult:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			cause = fmt.Errorf("serve management HTTP: %w", serveErr)
		}
	}
	// Quiesce handlers before lifecycle cleanup. This releases lifecycle's
	// context-aware operation gate when an API restart/reload/update is active.
	cancelRequests()
	cancelRuntime()
	cancelMonitor()
	cleanupContext, cancelCleanup := context.WithTimeout(context.Background(), gracefulShutdownBudget)
	var lifecycleErr error
	preserveCore, handoffErr := validManagerHandoff(root, "")
	if handoffErr != nil {
		logger.Error("could not validate manager handoff marker; performing a full shutdown", "error", handoffErr)
	}
	if ownLifecycle && preserveCore && handoffErr == nil {
		logger.Warn("self-update handoff: leaving Mihomo and the active dataplane running while only the manager restarts")
	} else if ownLifecycle {
		lifecycleErr = stopLifecycleForShutdown(cleanupContext, runtimeState.Lifecycle)
	}
	if ownsOpenWrt && lifecycleErr == nil && !preserveCore {
		ownerClean = true
	}
	// Remove capture and restore DNS before waiting for long-lived HTTP/SSE
	// clients. The total budget stays below procd's term_timeout so the manager
	// normally completes fail-open cleanup before a forced SIGKILL.
	shutdownErr := server.Shutdown(cleanupContext)
	cancelCleanup()
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		cause = nil
	}
	return errors.Join(cause, shutdownErr, lifecycleErr)
}

func stopLifecycleForShutdown(ctx context.Context, lifecycle lifecycleOwner) error {
	var lastErr error
	for {
		if err := lifecycle.Stop(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		timer := time.NewTimer(shutdownRetryInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return errors.Join(lastErr, ctx.Err())
		case <-timer.C:
		}
	}
}

func acquireManagerLock(ctx context.Context, root string, timeout time.Duration) (*state.Lock, error) {
	store, err := state.NewStore(root)
	if err != nil {
		return nil, err
	}
	lockContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	lock, err := store.Lock(lockContext, "daemon")
	if err == nil {
		return lock, nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		if parentErr := ctx.Err(); parentErr != nil {
			return nil, parentErr
		}
		return nil, errors.New("another boxctl manager instance already owns this root")
	}
	return nil, fmt.Errorf("acquire manager singleton lock: %w", err)
}

func acquireOpenWrtOwnerLock(ctx context.Context, lockRoot string, timeout time.Duration) (*state.Lock, error) {
	store, err := state.NewStore(lockRoot)
	if err != nil {
		return nil, err
	}
	lockContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	lock, err := store.Lock(lockContext, "openwrt-owner")
	if err == nil {
		return lock, nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		if parentErr := ctx.Err(); parentErr != nil {
			return nil, parentErr
		}
		return nil, errors.New("another boxctl manager instance already owns the OpenWrt gateway")
	}
	return nil, fmt.Errorf("acquire OpenWrt owner lock: %w", err)
}

// Firewall reconciles only boxctl-owned OpenWrt objects. Enabling or updating
// capture additionally requires a responsive controller, preventing a manual
// one-shot invocation from blackholing traffic into a dead core.
func (actions *Actions) Firewall(ctx context.Context, action string) error {
	return actions.firewall(ctx, action, "")
}

func (actions *Actions) firewall(ctx context.Context, action, reportedTUN string) error {
	operationContext, cancelOperation := context.WithTimeout(ctx, oneShotOperationTimeout)
	defer cancelOperation()
	ctx = operationContext
	root, err := actions.resolveRoot("")
	if err != nil {
		return err
	}
	if err := actions.requirePlatform(ctx); err != nil {
		return err
	}
	oneShot, err := actions.buildOneShot(root, actions.runner)
	if err != nil {
		return err
	}
	if oneShot == nil || oneShot.Preparer == nil || oneShot.Activation == nil {
		return errors.New("initialize firewall command: runtime is incomplete")
	}
	settingsStore, settingsErr := state.NewStore(root)
	if settingsErr != nil {
		return settingsErr
	}
	settings, settingsErr := LoadRuntimeSettings(settingsStore)
	if settingsErr != nil {
		return settingsErr
	}
	if settings.OperatingMode == "server" && action != "stop" {
		return nil
	}
	switch action {
	case "stop":
		return oneShot.Activation.Deactivate(ctx, engine.PreparedCore{})
	case "start", "update", "diagnose":
		active, ok := oneShot.Activation.(activeGenerationProvider)
		if !ok {
			return fmt.Errorf("initialize firewall %s: active gateway generation is unavailable", action)
		}
		prepared, err := active.ActivePrepared(ctx)
		if err != nil {
			return err
		}
		if reportedTUN != "" {
			usesTUN := prepared.Capture.TCP.Method == engine.CaptureTUN || prepared.Capture.UDP.Method == engine.CaptureTUN
			if !usesTUN || prepared.Capture.TUNDevice != reportedTUN {
				return nil
			}
		}
		if err := preparedCoreReady(ctx, prepared); err != nil {
			return fmt.Errorf("core readiness check failed: %w", err)
		}
		switch action {
		case "start", "update":
			// Primary activation belongs to the lifecycle transaction. External
			// firewall/hotplug processes may only reconcile the exact generation
			// which that transaction durably published.
			return oneShot.Activation.Reconcile(ctx, prepared)
		default:
			result, err := oneShot.Activation.Diagnose(ctx, prepared)
			if err == nil && (!result.Exists || !result.Owned || !result.PlanMatches || !result.PolicyMatches || !result.FirewallMatches) {
				err = errors.New("gateway state does not match the active capture plan")
			}
			if encodeErr := json.NewEncoder(actions.out).Encode(result); encodeErr != nil {
				return errors.Join(err, encodeErr)
			}
			return err
		}
	default:
		return fmt.Errorf("unknown firewall action %q", action)
	}
}

// Hotplug is an idempotent update after procd has confirmed the daemon is
// running. A TUN event is reconciled only when its reported interface matches
// the active prepared capture plan; WAN events always use the same
// ownership-safe reconcile.
func (actions *Actions) Hotplug(ctx context.Context, options cli.HotplugOptions) error {
	switch options.Event {
	case "wan":
		if options.Interface != "" {
			return errors.New("WAN hotplug event must not include an interface")
		}
		return actions.firewall(ctx, "update", "")
	case "tun":
		if strings.TrimSpace(options.Interface) == "" {
			return errors.New("TUN hotplug event requires an interface")
		}
		return actions.firewall(ctx, "update", options.Interface)
	default:
		return fmt.Errorf("unknown hotplug event %q", options.Event)
	}
}

// Cleanup is a fail-open, idempotent removal pass. It does not need the active
// profile to be valid and never signals a process it did not supervise.
func (actions *Actions) Cleanup(ctx context.Context) (returnErr error) {
	root, err := actions.resolveRoot("")
	if err != nil {
		return err
	}
	if err := actions.requirePlatform(ctx); err != nil {
		return err
	}
	oneShot, err := actions.buildOneShot(root, actions.runner)
	if err != nil {
		return err
	}
	if oneShot == nil || oneShot.Activation == nil {
		return errors.New("initialize cleanup command: runtime is incomplete")
	}
	ownerLock, err := acquireOpenWrtOwnerLock(ctx, actions.openWrtLockRoot, serveLockTimeout)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, ownerLock.Unlock()) }()
	if err := oneShot.Activation.Deactivate(ctx, engine.PreparedCore{}); err != nil {
		return err
	}
	locks, err := state.NewStore(actions.openWrtLockRoot)
	if err != nil {
		return err
	}
	return clearOpenWrtOwnerState(ctx, locks, root)
}

func (actions *Actions) SetPassword(ctx context.Context, input io.Reader, output io.Writer) (returnErr error) {
	root, err := actions.resolveRoot("")
	if err != nil {
		return err
	}
	store, err := state.NewStore(root)
	if err != nil {
		return err
	}
	stateLock, err := store.Lock(ctx, "state")
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, stateLock.Unlock()) }()
	return actions.setPassword(root, input, output)
}

func (actions *Actions) ValidateConfig(ctx context.Context, path string) error {
	root, err := actions.resolveRoot("")
	if err != nil {
		return err
	}
	if !filepath.IsAbs(path) {
		return errors.New("configuration path must be absolute")
	}
	return actions.validateConfig(ctx, root, filepath.Clean(path))
}

func (actions *Actions) ValidateEngineConfig(ctx context.Context, options cli.ConfigValidateOptions) error {
	if options.Engine == "" || options.Engine == state.EngineMihomo {
		return actions.ValidateConfig(ctx, options.File)
	}
	if options.Engine != state.EngineSingBox {
		return fmt.Errorf("unsupported configuration engine %q", options.Engine)
	}
	root, err := actions.resolveRoot("")
	if err != nil {
		return err
	}
	if !filepath.IsAbs(options.File) {
		return errors.New("configuration path must be absolute")
	}
	content, err := readBoundedRegular(filepath.Clean(options.File), 32<<20)
	if err != nil {
		return err
	}
	driver := engine.NewSingBoxDriver(engine.SingBoxOptions{})
	preparer, err := NewActiveSingBoxPreparer(root, driver)
	if err != nil {
		return err
	}
	return preparer.ValidateContent(ctx, content)
}

func (actions *Actions) InstallEngine(ctx context.Context, options cli.EngineInstallOptions) error {
	if options.Engine != state.EngineSingBox {
		return fmt.Errorf("unsupported managed engine %q", options.Engine)
	}
	root, err := actions.resolveRoot(options.Root)
	if err != nil {
		return err
	}
	archivePath := filepath.Clean(strings.TrimSpace(options.File))
	if !filepath.IsAbs(archivePath) {
		return errors.New("engine archive path must be absolute")
	}
	digest, err := updatepkg.ResolveLocalSHA256(archivePath, options.SHA256)
	if err != nil {
		return fmt.Errorf("resolve engine archive checksum: %w", err)
	}
	managerLock, err := acquireManagerLock(ctx, root, serveLockTimeout)
	if err != nil {
		return fmt.Errorf("install engine only while boxctl is stopped: %w", err)
	}
	defer func() { _ = managerLock.Unlock() }()
	layout, err := state.NewLayout(root)
	if err != nil {
		return err
	}
	engineRoot := filepath.Join(layout.EnginesDir, state.EngineSingBox)
	installer := updatepkg.SingBoxInstaller{}
	staged, err := installer.StageLocalArchive(ctx, archivePath, digest, engineRoot)
	if err != nil {
		return err
	}
	defer func() { _ = staged.Cleanup() }()
	pointer, err := updatepkg.PublishSingBoxVersion(engineRoot, staged)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(actions.out, "installed sing-box %s (%s)\n", pointer.Current.Version, pointer.Current.Source)
	return err
}

// Doctor performs existence, format, and platform checks only. It never calls
// mutating OpenWrt commands and never prints config content or credentials.
func (actions *Actions) Doctor(ctx context.Context, options cli.DoctorOptions) error {
	root, err := actions.resolveRoot(options.Root)
	if err != nil {
		return err
	}
	report := DoctorReport{Version: buildinfo.Version, Root: root, CheckedAt: actions.now().UTC()}
	platform, platformErr := actions.probePlatform(ctx, actions.runner)
	report.Platform = platform
	report.add("platform", platformErr == nil && platform.Supported, publicCheckError(platformErr, "unsupported OpenWrt board or architecture"))
	ipErr := actions.probeRoutingIP(ctx, actions.runner)
	report.add("ip-full", ipErr == nil, publicCheckError(ipErr, "iproute2 ip-full capabilities are unavailable"))
	layout, layoutErr := state.NewLayout(root)
	rootInfo, rootErr := os.Stat(root)
	report.add("root", layoutErr == nil && rootErr == nil && rootInfo.IsDir(), publicCheckError(errors.Join(layoutErr, rootErr), "root does not exist"))
	if layoutErr == nil && rootErr == nil && rootInfo.IsDir() {
		store, storeErr := state.NewStore(root)
		if storeErr == nil {
			_, storeErr = LoadRuntimeSettings(store)
		}
		report.add("settings", storeErr == nil, publicCheckError(storeErr, "settings are invalid"))
		profiles, profilesErr := state.NewProfileStore(root)
		selected := state.ActiveProfile{Engine: state.EngineMihomo}
		if profilesErr == nil {
			active, activeErr := profiles.Current()
			switch {
			case activeErr == nil:
				selected = active
			case !errors.Is(activeErr, fs.ErrNotExist):
				profilesErr = activeErr
			}
		}
		report.SelectedEngine = selected.Engine
		report.add("selected-engine", profilesErr == nil, publicCheckError(profilesErr, "active profile metadata is invalid"))
		if profilesErr == nil {
			switch selected.Engine {
			case state.EngineMihomo:
				doctorMihomo(&report, layout)
			case state.EngineSingBox:
				doctorSingBox(ctx, &report, layout, profiles, selected)
			default:
				report.add("selected-engine-supported", false, "selected profile uses an unsupported engine")
			}
		}
	}
	if options.JSON {
		err = json.NewEncoder(actions.out).Encode(report)
	} else {
		err = writeDoctorText(actions.out, report)
	}
	if err != nil {
		return err
	}
	if report.Healthy() {
		return nil
	}
	return &DoctorError{Failures: report.failureCount()}
}

func doctorMihomo(report *DoctorReport, layout state.Layout) {
	binary := filepath.Join(layout.EnginesDir, state.EngineMihomo, state.EngineMihomo)
	report.add("mihomo-binary", regularExecutable(binary), "Mihomo executable is missing")
	configInfo, configErr := os.Lstat(layout.MihomoConfig)
	hasConfig := configErr == nil && configInfo.Mode().IsRegular() && configInfo.Mode()&os.ModeSymlink == 0
	report.add("mihomo-config", hasConfig, publicCheckError(configErr, "config.yaml is missing"))
	if !hasConfig {
		return
	}
	content, readErr := readBoundedRegular(layout.MihomoConfig, 32<<20)
	if readErr == nil {
		_, readErr = configpkg.InspectMihomo(content)
	}
	report.add("config-structure", readErr == nil, publicCheckError(readErr, "config.yaml structure is invalid"))
}

func doctorSingBox(ctx context.Context, report *DoctorReport, layout state.Layout, profiles state.ProfileStore, selected state.ActiveProfile) {
	binary, metadata, binaryErr := resolveSingBoxBinary(layout)
	if binaryErr == nil && !regularExecutable(binary) {
		binaryErr = errors.New("sing-box binary is not a regular executable")
	}
	report.add("sing-box-binary", binaryErr == nil, publicCheckError(binaryErr, "sing-box executable is missing"))

	driver := engine.NewSingBoxDriver(engine.SingBoxOptions{})
	var versionErr error
	if binaryErr == nil {
		var output string
		output, versionErr = driver.Version(ctx, binary)
		if versionErr == nil && !singBoxVersionLine.MatchString(output) {
			versionErr = errors.New("unsupported sing-box version; require >=1.14.0,<1.15.0")
		}
		if versionErr == nil && metadata.Version != "" {
			match := singBoxVersionLine.FindStringSubmatch(output)
			if len(match) != 2 || match[1] != metadata.Version {
				versionErr = errors.New("managed sing-box version does not match current.json")
			}
		}
	} else {
		versionErr = binaryErr
	}
	report.add("sing-box-version", versionErr == nil, publicCheckError(versionErr, "sing-box version is incompatible"))

	content, configErr := profiles.Get(selected)
	report.add("sing-box-config", configErr == nil, publicCheckError(configErr, "selected sing-box profile is missing"))
	if configErr != nil || versionErr != nil {
		return
	}
	preparer, prepareErr := NewActiveSingBoxPreparer(layout.Root, driver)
	if prepareErr == nil {
		preparer.BinaryOverride = binary
		preparer.ControllerSecretOverride = "boxctl-read-only-validation-secret-000000000000"
		prepareErr = preparer.ValidateContent(ctx, content)
	}
	report.add("config-native", prepareErr == nil, "sing-box rejected the selected native JSON configuration")
}

func (actions *Actions) requirePlatform(ctx context.Context) error {
	report, err := actions.probePlatform(ctx, actions.runner)
	if err != nil {
		return fmt.Errorf("probe OpenWrt platform: %w", err)
	}
	if !report.Supported {
		return fmt.Errorf("unsupported platform: %s", report.Description())
	}
	return nil
}

func (actions *Actions) resolveRoot(requested string) (string, error) {
	root := strings.TrimSpace(requested)
	if fromEnvironment := strings.TrimSpace(actions.getenv("BOXCTL_ROOT")); fromEnvironment != "" && (root == "" || root == state.DefaultRoot) {
		root = fromEnvironment
	}
	if root == "" {
		root = state.DefaultRoot
	}
	layout, err := state.NewLayout(root)
	if err != nil {
		return "", err
	}
	return layout.Root, nil
}

func (actions *Actions) resolveListen(ctx context.Context, requested string) (string, error) {
	address := strings.TrimSpace(requested)
	if address == "" {
		address = strings.TrimSpace(actions.getenv("BOXCTL_ADDR"))
	}
	if address == "" {
		var err error
		address, err = actions.lanListen(ctx, actions.runner)
		if err != nil || address == "" {
			address = net.JoinHostPort("127.0.0.1", strconv.Itoa(defaultListenPort))
		}
	}
	return validateListenAddress(address)
}

func validateListenAddress(address string) (string, error) {
	address = strings.TrimSpace(address)
	if !strings.Contains(address, ":") {
		address = net.JoinHostPort(address, strconv.Itoa(defaultListenPort))
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("invalid management listen address: %w", err)
	}
	parsedHost, parsedHostErr := netip.ParseAddr(host)
	if host == "" || host == "0.0.0.0" || host == "::" || (parsedHostErr == nil && parsedHost.Unmap().IsUnspecified()) {
		return "", errors.New("management UI must bind to a specific LAN or loopback address, not a wildcard")
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return "", errors.New("management listen port is invalid")
	}
	return net.JoinHostPort(host, strconv.FormatUint(parsedPort, 10)), nil
}

func managementAllowedHosts(listenAddress, configured string) ([]string, error) {
	host, _, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return nil, fmt.Errorf("resolve management host: %w", err)
	}
	values := []string{host}
	for _, value := range strings.Split(configured, ",") {
		value = strings.TrimSpace(value)
		if value != "" {
			values = append(values, value)
		}
	}
	return values, nil
}

func parseExplicitBoolSetting(name, value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "0", "false", "off", "no":
		return false, nil
	case "1", "true", "on", "yes":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be a boolean", name)
	}
}

func defaultLANListen(ctx context.Context, runner openwrt.Runner) (string, error) {
	discovered, err := openwrt.DetectInterfaces(ctx, runner)
	if err != nil {
		return "", err
	}
	for _, name := range discovered.LANInterfaces {
		interfaceValue, err := net.InterfaceByName(name)
		if err != nil {
			continue
		}
		addresses, err := interfaceValue.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr().Unmap()
			if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || !ip.IsPrivate() {
				continue
			}
			return net.JoinHostPort(ip.String(), strconv.Itoa(defaultListenPort)), nil
		}
	}
	return "", errors.New("no private address found on a detected LAN interface")
}

type tlsSetting struct {
	Enabled     bool
	Certificate string
	Key         string
}

// BOXCTL_TLS is either empty/off, or CERTIFICATE_PATH,PRIVATE_KEY_PATH.
// Requiring both files avoids a misleading secure-cookie-only mode.
func parseTLSSetting(value string) (tlsSetting, error) {
	value = strings.TrimSpace(value)
	switch strings.ToLower(value) {
	case "", "0", "false", "off", "no":
		return tlsSetting{}, nil
	case "1", "true", "on", "yes":
		return tlsSetting{}, errors.New("BOXCTL_TLS must name certificate and private-key files as CERT,KEY")
	}
	parts := strings.Split(value, ",")
	if len(parts) != 2 {
		return tlsSetting{}, errors.New("BOXCTL_TLS must be off or CERTIFICATE_PATH,PRIVATE_KEY_PATH")
	}
	certificate := filepath.Clean(strings.TrimSpace(parts[0]))
	key := filepath.Clean(strings.TrimSpace(parts[1]))
	if !filepath.IsAbs(certificate) || !filepath.IsAbs(key) {
		return tlsSetting{}, errors.New("BOXCTL_TLS certificate and key paths must be absolute")
	}
	for label, path := range map[string]string{"certificate": certificate, "private key": key} {
		info, err := os.Lstat(path)
		if err != nil {
			return tlsSetting{}, fmt.Errorf("inspect TLS %s: %w", label, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return tlsSetting{}, fmt.Errorf("TLS %s is not a regular file", label)
		}
	}
	return tlsSetting{Enabled: true, Certificate: certificate, Key: key}, nil
}

// PlatformReport contains no host secrets and is safe for doctor JSON.
type PlatformReport struct {
	Distribution string `json:"distribution,omitempty"`
	Model        string `json:"model,omitempty"`
	Board        string `json:"board,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	Supported    bool   `json:"supported"`
}

func (report PlatformReport) Description() string {
	parts := []string{report.Distribution, report.Model, report.Board, report.Architecture}
	parts = slices.DeleteFunc(parts, func(value string) bool { return strings.TrimSpace(value) == "" })
	if len(parts) == 0 {
		return "unknown platform"
	}
	return strings.Join(parts, "/")
}

func probeOpenWrt(ctx context.Context, runner openwrt.Runner) (PlatformReport, error) {
	boardResult, err := runner.Run(ctx, openwrt.Command{Name: "ubus", Args: []string{"call", "system", "board"}})
	if err != nil {
		return PlatformReport{}, err
	}
	if boardResult.ExitCode != 0 {
		return PlatformReport{}, fmt.Errorf("ubus board probe exited with %d", boardResult.ExitCode)
	}
	var board struct {
		Model     string `json:"model"`
		BoardName string `json:"board_name"`
		Release   struct {
			Distribution string `json:"distribution"`
		} `json:"release"`
	}
	if err := json.Unmarshal(boardResult.Stdout, &board); err != nil {
		return PlatformReport{}, fmt.Errorf("decode OpenWrt board data: %w", err)
	}
	architecture := runtime.GOARCH
	unameResult, unameErr := runner.Run(ctx, openwrt.Command{Name: "uname", Args: []string{"-m"}})
	if unameErr == nil && unameResult.ExitCode == 0 && strings.TrimSpace(string(unameResult.Stdout)) != "" {
		architecture = strings.TrimSpace(string(unameResult.Stdout))
	}
	report := PlatformReport{
		Distribution: strings.TrimSpace(board.Release.Distribution), Model: strings.TrimSpace(board.Model),
		Board: strings.TrimSpace(board.BoardName), Architecture: architecture,
	}
	report.Supported = strings.EqualFold(report.Distribution, "OpenWrt")
	return report, nil
}

// probeIPFull exercises every read-only iproute2 command shape used while
// discovering interfaces and inspecting owned policy routing. BusyBox ip lacks
// JSON output, numeric names and rule protocol support, so testing the actual
// command resolved through PATH is more reliable than checking package state.
func probeIPFull(ctx context.Context, runner openwrt.Runner) error {
	commands := []openwrt.Command{
		{Name: "ip", Args: []string{"-j", "link", "show"}},
		{Name: "ip", Args: []string{"-j", "-4", "route", "show"}},
		{Name: "ip", Args: []string{"-N", "-4", "rule", "show"}},
		{Name: "ip", Args: []string{"-N", "-4", "route", "show", "table", "all", "proto", strconv.Itoa(openwrt.PolicyProtocol)}},
	}
	for _, command := range commands {
		result, err := runner.Run(ctx, command)
		invocation := "ip " + strings.Join(command.Args, " ")
		if err != nil {
			return fmt.Errorf("ip-full is required: run %s: %w", invocation, err)
		}
		if result.ExitCode != 0 {
			detail := strings.TrimSpace(string(result.Stderr))
			if detail == "" {
				detail = strings.TrimSpace(string(result.Stdout))
			}
			if detail == "" {
				return fmt.Errorf("ip-full is required: %s exited with %d", invocation, result.ExitCode)
			}
			return fmt.Errorf("ip-full is required: %s exited with %d: %s", invocation, result.ExitCode, detail)
		}
	}
	return nil
}

type noopActivation struct{}

func (noopActivation) Activate(context.Context, engine.PreparedCore) error   { return nil }
func (noopActivation) Deactivate(context.Context, engine.PreparedCore) error { return nil }

func defaultServeRuntime(ctx context.Context, root string, options serveBuildOptions, runner openwrt.Runner, logger *slog.Logger, ring *eventlog.Ring) (*serveRuntime, error) {
	layout, err := state.NewLayout(root)
	if err != nil {
		return nil, err
	}
	mihomoOptions := engine.MihomoOptions{}
	singBoxOptions := engine.SingBoxOptions{ClashAPIAllowedOrigins: singBoxControllerOrigins(options.PublicOrigin)}
	if runtime.GOOS == "linux" {
		// Both mutually-exclusive drivers share the historical state path. The
		// v2 record is engine-qualified, while Mihomo can still adopt and upgrade
		// a live v1 process during the migration release.
		processStatePath := filepath.Join(layout.StateDir, "mihomo-process.json")
		mihomoOptions.ProcessStatePath = processStatePath
		singBoxOptions.ProcessStatePath = processStatePath
	}
	mihomoDriver := engine.NewMihomoDriver(mihomoOptions)
	singBoxDriver := engine.NewSingBoxDriver(singBoxOptions)
	mihomoPreparer, err := NewActiveMihomoPreparer(root, mihomoDriver)
	if err != nil {
		return nil, err
	}
	singBoxPreparer, err := NewActiveSingBoxPreparer(root, singBoxDriver)
	if err != nil {
		return nil, err
	}
	enginePreparer := &EnginePreparer{
		Profiles: mihomoPreparer.Profiles,
		Preparers: map[string]ExplicitProfilePreparer{
			state.EngineMihomo:  mihomoPreparer,
			state.EngineSingBox: singBoxPreparer,
		},
		Legacy: mihomoPreparer,
	}
	host, err := NewEngineHost(map[string]CoreBackend{
		state.EngineMihomo: mihomoDriver, state.EngineSingBox: singBoxDriver,
	}, func() string {
		active, currentErr := mihomoPreparer.Profiles.Current()
		if currentErr == nil {
			return active.Engine
		}
		return state.EngineMihomo
	})
	if err != nil {
		return nil, err
	}
	hostOwned := true
	defer func() {
		if hostOwned {
			_ = host.Close()
		}
	}()
	profilesService, err := NewProfilesService(root, nil)
	if err != nil {
		return nil, err
	}
	openWrtActivation, err := newOpenWrtActivation(root, options.lockRoot, runner)
	if err != nil {
		return nil, err
	}
	var activation Activation = openWrtActivation
	if options.NoGateway {
		activation = noopActivation{}
	}
	lifecycle := &Lifecycle{
		Preparer: enginePreparer, Core: host, Activation: activation, Logger: logger,
	}
	lifecycle.OnStarted = func(prepared engine.PreparedCore) error {
		markerErr := mihomoPreparer.State.RemoveRegular(state.FirstStartPending)
		active, activeErr := mihomoPreparer.Profiles.Current()
		if activeErr != nil {
			if errors.Is(activeErr, fs.ErrNotExist) {
				return markerErr
			}
			return errors.Join(markerErr, activeErr)
		}
		if preparedMatchesProfile(layout, prepared, active) && prepared.SourceRevision != "" {
			return errors.Join(markerErr, profilesService.Revisions.MarkAppliedRevision(context.Background(), active, prepared.SourceRevision))
		}
		return markerErr
	}
	switcher := &ProfileSwitcher{
		State: mihomoPreparer.State, Profiles: mihomoPreparer.Profiles, Preparer: enginePreparer,
		Lifecycle: lifecycle, Revisions: profilesService.Revisions,
	}
	if err := switcher.RecoverSelection(); err != nil {
		return nil, fmt.Errorf("recover interrupted profile selection: %w", err)
	}
	recoveryProfile, recoveryRevision, recovering, err := switcher.RecoveryProfile()
	if err != nil {
		return nil, fmt.Errorf("inspect interrupted profile selection: %w", err)
	}
	requested, markerErr := validManagerHandoff(root, buildinfo.Version)
	if markerErr != nil {
		logger.Error("invalid manager handoff marker; starting with normal lifecycle recovery", "error", markerErr)
		_ = removeManagerHandoff(layout)
	}
	handoffAdopted := false
	if shouldAttemptCoreAdoption(options.NoCore, runtime.GOOS) {
		selected, selectedErr := selectedProfile(mihomoPreparer.Profiles)
		if selectedErr != nil && !errors.Is(selectedErr, fs.ErrNotExist) {
			return nil, selectedErr
		}
		selectedEngine := state.EngineMihomo
		if selectedErr == nil {
			selectedEngine = selected.Engine
		}
		prepared, health, adoptErr := adoptSelectedEngine(ctx, selectedEngine, map[string]adoptableCore{
			state.EngineMihomo: mihomoDriver, state.EngineSingBox: singBoxDriver,
		}, logger)
		if adoptErr == nil {
			adoptErr = host.SetAdopted(prepared.Engine)
		}
		if adoptErr == nil {
			matchesSelection := selectedErr == nil && preparedMatchesProfileRevision(layout, mihomoPreparer.Profiles, prepared, selected, "")
			if recovering {
				matchesSelection = recoveryProfile != nil && preparedMatchesProfileRevision(
					layout, mihomoPreparer.Profiles, prepared, *recoveryProfile, recoveryRevision,
				)
			}
			if !matchesSelection {
				logger.Warn("stopping an interrupted core generation which does not match the recovered selection",
					"runningEngine", prepared.Engine, "selectedEngine", selectedEngine)
			}
			handoffAdopted, adoptErr = acceptAdoptedGeneration(
				ctx, lifecycle, prepared, health, requested, matchesSelection, options.StartStopped,
			)
		} else if !errors.Is(adoptErr, os.ErrNotExist) {
			logger.Error("could not adopt the previous core generation; starting with normal lifecycle recovery", "error", adoptErr)
		}
		if recovering {
			if adoptErr != nil && !errors.Is(adoptErr, os.ErrNotExist) {
				return nil, fmt.Errorf("reconcile interrupted profile switch runtime: %w", adoptErr)
			}
			if completeErr := switcher.CompleteRecovery(ctx); completeErr != nil {
				return nil, fmt.Errorf("complete interrupted profile switch recovery: %w", completeErr)
			}
			recovering = false
		}
		if requested && adoptErr != nil {
			return nil, fmt.Errorf("complete core-preserving manager handoff: %w", adoptErr)
		}
	}
	if recovering && (options.NoCore || runtime.GOOS != "linux") {
		// Persistent process adoption exists only for the normal Linux/OpenWrt
		// runtime. With --no-core, retain the journal for a later normal start;
		// on other platforms no process can survive this manager instance.
		if !options.NoCore {
			if err := switcher.CompleteRecovery(ctx); err != nil {
				return nil, fmt.Errorf("complete metadata-only profile switch recovery: %w", err)
			}
		}
	}
	if requested && !handoffAdopted {
		return nil, errors.New("complete core-preserving manager handoff: core adoption is unavailable")
	}
	if !requested {
		if removeErr := removeManagerHandoff(layout); removeErr != nil {
			logger.Error("could not remove stale manager handoff marker", "error", removeErr)
		}
	}
	var maintenance *PeriodicMaintenance
	stopMaintenance := func() {}
	var automaticUpdates *AutomaticCoreUpdates
	stopAutomaticUpdates := func() {}
	if !options.NoCore && !options.NoGateway {
		maintenance = NewPeriodicMaintenance(mihomoPreparer.State, mihomoPreparer, lifecycle, openWrtActivation, logger)
	}
	credentials, err := NewCredentialStore(root)
	if err != nil {
		return nil, err
	}
	var managerUpdates *ManagerReleaseChecker
	if _, versionErr := updatepkg.CompareBoxctlCalVer(buildinfo.Version, buildinfo.Version); versionErr == nil {
		managerUpdateClient := &http.Client{Timeout: defaultManagerReleaseCheckTimeout}
		managerUpdates = NewManagerReleaseChecker(
			buildinfo.Version,
			updatepkg.NewBoxctlSource(managerUpdateClient, defaultManagerRepository),
			logger,
		)
	}

	services := web.Services{Credentials: credentials, Status: &StatusService{
		Lifecycle: lifecycle, Profiles: mihomoPreparer.Profiles, Control: host, Host: host,
		Revisions: profilesService.Revisions, Switcher: switcher, StartedAt: time.Now().UTC(), ManagerUpdates: managerUpdates,
	}}
	services.Engines = &EngineCatalogService{
		Layout: layout, Profiles: mihomoPreparer.Profiles, Lifecycle: lifecycle, Host: host,
		SingBoxVersion:          singBoxDriver.Version,
		UnsafeExternalDashboard: options.UnsafeExternalDashboard,
	}
	services.SessionSecrets = credentials
	services.AdminSetup = credentials
	settingsService, err := NewSettingsService(root)
	if err != nil {
		return nil, err
	}
	settingsService.SelectedEngine = func() string { return selectedProfileEngine(mihomoPreparer.Profiles) }
	settingsService.DiscoverInterfaces = func(discoveryContext context.Context) (web.InterfaceCatalog, error) {
		discovery, discoveryErr := openWrtActivation.gateway.Detect(discoveryContext)
		if discoveryErr != nil {
			return web.InterfaceCatalog{}, discoveryErr
		}
		return runtimeInterfaceCatalog(discovery), nil
	}
	configService := &ConfigService{
		Preparer: mihomoPreparer, EnginePreparer: enginePreparer, Lifecycle: lifecycle,
		Revisions: profilesService.Revisions, MutationMu: &profilesService.mutationMu,
	}
	configService.ValidateEngine = func(validateContext context.Context, engineName string, content []byte) error {
		switch engineName {
		case state.EngineMihomo:
			return configService.ValidateMihomoContent(validateContext, content)
		case state.EngineSingBox:
			return singBoxPreparer.ValidateContent(validateContext, content)
		default:
			return engine.ErrUnsupported
		}
	}
	configService.OnChanged = func(callbackContext context.Context) (bool, error) {
		return lifecycle.RestartIfRunning(callbackContext)
	}
	profilesService.ValidateMihomo = configService.ValidateMihomoContent
	profilesService.ValidateSingBox = singBoxPreparer.ValidateContent
	profilesService.SwitchProfile = switcher.Switch
	proxySubscriptions, err := NewProxySubscriptionsService(root, nil)
	if err != nil {
		return nil, err
	}
	mihomoPreparer.Subscriptions = proxySubscriptions
	rules := &rulelist.Store{Directory: mihomoPreparer.Layout.LocalRulesDir}
	settingsService.OnChanged = func(callbackContext context.Context, restartRequired bool) error {
		if restartRequired {
			if _, err := lifecycle.RestartIfRunning(callbackContext); err != nil {
				return err
			}
		}
		if maintenance != nil {
			maintenance.Reload()
		}
		if automaticUpdates != nil {
			automaticUpdates.Reload()
		}
		return nil
	}
	settingsService.SetStartOnBoot = func(callbackContext context.Context, enabled bool) error {
		action := "disable"
		if enabled {
			action = "enable"
		}
		result, runErr := runner.Run(callbackContext, openwrt.Command{Name: "/etc/init.d/boxctl", Args: []string{action}})
		if runErr != nil {
			return runErr
		}
		if result.ExitCode != 0 {
			return fmt.Errorf("service boot action exited with %d", result.ExitCode)
		}
		return nil
	}
	profilesService.OnActivated = func(callbackContext context.Context) error {
		_, err := lifecycle.RestartIfRunning(callbackContext)
		return err
	}
	proxySubscriptions.OnChanged = func(callbackContext context.Context) error {
		if selectedProfileEngine(mihomoPreparer.Profiles) != state.EngineMihomo {
			return nil
		}
		_, err := lifecycle.RestartIfRunning(callbackContext)
		return err
	}
	services.Settings = settingsService
	services.Config = configService
	services.Profiles = profilesService
	services.ProxySubscriptions = proxySubscriptions
	services.RuleLists = RuleListService{Store: rules, Config: configService}
	services.FakeIPWhitelist = &FakeIPWhitelistService{
		Manager: mihomoPreparer.FakeIP, Preparer: mihomoPreparer, Lifecycle: lifecycle,
	}
	services.Backups = BackupService{
		Manager: DefaultBackupManager(root),
		LockManagedState: func(lockContext context.Context) (func() error, error) {
			return lockBackupManagedState(lockContext, profilesService, proxySubscriptions)
		},
		WasRunning: func() bool {
			snapshot := lifecycle.Snapshot()
			return snapshot.State == LifecycleRunning || snapshot.Health.Running
		},
		StopCore:  lifecycle.Stop,
		StartCore: lifecycle.Start,
		LockExport: func(exportContext context.Context) (func() error, error) {
			return lockBackupExport(exportContext, mihomoPreparer.State)
		},
		LockImport: func(importContext context.Context) (func() error, error) {
			return lockBackupImport(importContext, lifecycle, mihomoPreparer.State, openWrtActivation.Locks)
		},
		CanImport: func() bool {
			return lifecycleAllowsBackupImport(lifecycle.Snapshot())
		},
	}
	var coreService *CoreService
	if !options.NoCore {
		coreService, err = NewCoreService(lifecycle, enginePreparer, host, CoreServiceOptions{
			CoreName: "core", UnsafeExternalDashboard: options.UnsafeExternalDashboard,
			SelectedEngine:  func() string { return selectedProfileEngine(mihomoPreparer.Profiles) },
			ConnectionNames: newConnectionNameResolver(connectionNameResolverOptions{}),
		})
		if err != nil {
			return nil, err
		}
		services.Core = coreService
		services.Lifecycle = LifecycleService{Lifecycle: lifecycle}
		updateClient := &http.Client{Timeout: 90 * time.Second}
		mihomoUpdates, updateErr := NewMihomoUpdateService(ctx, root, updateClient, mihomoPreparer, lifecycle, mihomoDriver)
		if updateErr != nil {
			_ = coreService.Close()
			return nil, updateErr
		}
		singBoxUpdates, updateErr := NewSingBoxUpdateService(ctx, root, updateClient, singBoxPreparer, lifecycle)
		if updateErr != nil {
			_ = coreService.Close()
			return nil, updateErr
		}
		updates := &MultiEngineUpdateService{
			Mihomo: mihomoUpdates, SingBox: singBoxUpdates,
			Selected: func() string { return selectedProfileEngine(mihomoPreparer.Profiles) },
		}
		services.CoreUpdates = updates
		if options.UnsafeExternalDashboard {
			dashboardManager, dashboardErr := NewExternalDashboardManager(root, &http.Client{Timeout: 90 * time.Second}, host)
			if dashboardErr != nil {
				_ = coreService.Close()
				return nil, dashboardErr
			}
			dashboard := clashExternalDashboard{
				manager:  dashboardManager,
				selected: func() string { return selectedProfileEngine(mihomoPreparer.Profiles) },
			}
			services.ExternalDashboard = dashboard
			services.ExternalDashboardHTTP = dashboard
		}
		automaticUpdates = NewAutomaticCoreUpdates(mihomoPreparer.State, updates, logger)
		configService.OnReload = func(callbackContext context.Context) (bool, error) {
			if lifecycle.Snapshot().State != LifecycleRunning {
				return false, nil
			}
			return true, coreService.Reload(callbackContext)
		}
	}
	services.SystemLogs = SystemLogs{Ring: ring}
	handler, err := web.NewHandlerContext(ctx, web.Config{
		CookieSecure: options.CookieSecure,
		AllowedHosts: options.AllowedHosts,
		PublicOrigin: options.PublicOrigin,
		Logger:       logger.WithGroup("http"),
	}, services)
	if err != nil {
		stopMaintenance()
		stopAutomaticUpdates()
		if coreService != nil {
			_ = coreService.Close()
		}
		return nil, err
	}
	stopProfileScheduler := profilesService.StartScheduler(ctx)
	stopProxySubscriptionScheduler := proxySubscriptions.StartScheduler(ctx)
	if maintenance != nil {
		maintenanceContext, cancelMaintenance := context.WithCancel(ctx)
		stopMaintenance = cancelMaintenance
		go maintenance.Run(maintenanceContext)
	}
	if automaticUpdates != nil {
		automaticUpdateContext, cancelAutomaticUpdates := context.WithCancel(ctx)
		stopAutomaticUpdates = cancelAutomaticUpdates
		go automaticUpdates.Run(automaticUpdateContext)
	}
	if managerUpdates != nil {
		go managerUpdates.Run(ctx)
	}
	hostOwned = false
	return &serveRuntime{Handler: handler, Lifecycle: lifecycle, HandoffMarkerPending: handoffAdopted, Close: func() error {
		stopMaintenance()
		stopAutomaticUpdates()
		stopProfileScheduler()
		stopProxySubscriptionScheduler()
		var coreErr error
		if coreService != nil {
			coreErr = coreService.Close()
		}
		return errors.Join(coreErr, host.Close())
	}}, nil
}

func singBoxControllerOrigins(publicOrigin string) []string {
	origins := []string{"http://127.0.0.1"}
	if origin := strings.TrimSpace(publicOrigin); origin != "" && origin != origins[0] {
		origins = append(origins, origin)
	}
	return origins
}

func preparedMatchesProfile(layout state.Layout, prepared engine.PreparedCore, profile state.ActiveProfile) bool {
	if prepared.Engine != profile.Engine {
		return false
	}
	source := filepath.Clean(prepared.SourceConfigPath)
	if profile.Engine == state.EngineMihomo && source == filepath.Clean(layout.MihomoConfig) {
		return true
	}
	return source == filepath.Join(layout.ProfilesDir, state.ProfileConfigName(profile))
}

func preparedMatchesProfileRevision(layout state.Layout, profiles state.ProfileStore, prepared engine.PreparedCore, profile state.ActiveProfile, requiredRevision string) bool {
	if !preparedMatchesProfile(layout, prepared, profile) {
		return false
	}
	if requiredRevision != "" {
		return prepared.SourceRevision == requiredRevision
	}
	if prepared.SourceRevision == "" {
		// Legacy Mihomo handoff records predate revision identity. Keep the
		// existing path check for that one migration case; all v2 records below
		// must also match the current source bytes.
		return profile.Engine == state.EngineMihomo
	}
	content, err := profiles.Get(profile)
	return err == nil && contentRevision(content) == prepared.SourceRevision
}

func selectedProfile(profiles state.ProfileStore) (state.ActiveProfile, error) {
	active, err := profiles.Current()
	if err != nil {
		return state.ActiveProfile{}, err
	}
	if active.Engine == "" {
		active.Engine = state.EngineMihomo
	}
	return active, nil
}

func selectedProfileEngine(profiles state.ProfileStore) string {
	active, err := profiles.Current()
	if err == nil && active.Engine != "" {
		return active.Engine
	}
	return state.EngineMihomo
}

type adoptableCore interface {
	Adopt(context.Context) (engine.PreparedCore, engine.HealthStatus, error)
}

func shouldAttemptCoreAdoption(noCore bool, goos string) bool {
	return !noCore && goos == "linux"
}

type adoptedGenerationLifecycle interface {
	Adopt(engine.PreparedCore, engine.HealthStatus) error
	RecoverAdopted(context.Context, engine.PreparedCore, engine.HealthStatus) error
	DiscardAdopted(context.Context, engine.PreparedCore, engine.HealthStatus) error
}

// acceptAdoptedGeneration keeps the no-touch path exclusive to a verified
// manager handoff. An unrequested crash must rebuild capture/DNS ownership from
// the exact persisted generation before it can be reported as running, unless
// start-stopped mode requires that surviving process to be cleaned up instead.
func acceptAdoptedGeneration(
	ctx context.Context,
	lifecycle adoptedGenerationLifecycle,
	prepared engine.PreparedCore,
	health engine.HealthStatus,
	verifiedHandoff bool,
	matchesSelection bool,
	startStopped bool,
) (bool, error) {
	if !matchesSelection || (!verifiedHandoff && startStopped) {
		return false, lifecycle.DiscardAdopted(ctx, prepared, health)
	}
	if verifiedHandoff {
		err := lifecycle.Adopt(prepared, health)
		return err == nil, err
	}
	return false, lifecycle.RecoverAdopted(ctx, prepared, health)
}

func adoptSelectedEngine(
	ctx context.Context,
	selected string,
	backends map[string]adoptableCore,
	logger *slog.Logger,
) (engine.PreparedCore, engine.HealthStatus, error) {
	order := []string{selected}
	for _, candidate := range []string{state.EngineMihomo, state.EngineSingBox} {
		if candidate != selected {
			order = append(order, candidate)
		}
	}
	var failures []error
	for _, engineName := range order {
		backend := backends[engineName]
		if backend == nil {
			continue
		}
		prepared, health, err := backend.Adopt(ctx)
		if err == nil {
			return prepared, health, nil
		}
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, engine.ErrProcessStateNotOwned) {
			failures = append(failures, fmt.Errorf("%s adoption: %w", engineName, err))
			if logger != nil {
				logger.Debug("core adoption candidate rejected", "engine", engineName, "error", err)
			}
		}
	}
	if len(failures) > 0 {
		return engine.PreparedCore{}, engine.HealthStatus{}, errors.Join(failures...)
	}
	return engine.PreparedCore{}, engine.HealthStatus{}, os.ErrNotExist
}

func lockBackupExport(ctx context.Context, store state.Store) (func() error, error) {
	lock, err := store.Lock(ctx, "state")
	if err != nil {
		return nil, err
	}
	return lock.Unlock, nil
}

// Profile and subscription refreshes hold their mutation mutex while fetching,
// publishing private metadata/caches, and applying a running-core refresh.
// Backup must take the same locks first, matching mutation -> lifecycle lock
// order, before it stops the core and swaps the state tree.
func lockBackupManagedState(ctx context.Context, profiles *ProfilesService, subscriptions *ProxySubscriptionsService) (func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if profiles != nil {
		profiles.mutationMu.Lock()
	}
	if err := ctx.Err(); err != nil {
		if profiles != nil {
			profiles.mutationMu.Unlock()
		}
		return nil, err
	}
	if subscriptions != nil {
		subscriptions.mu.Lock()
	}
	if err := ctx.Err(); err != nil {
		if subscriptions != nil {
			subscriptions.mu.Unlock()
		}
		if profiles != nil {
			profiles.mutationMu.Unlock()
		}
		return nil, err
	}
	return func() error {
		if subscriptions != nil {
			subscriptions.mu.Unlock()
		}
		if profiles != nil {
			profiles.mutationMu.Unlock()
		}
		return nil
	}, nil
}

func lifecycleAllowsBackupImport(snapshot LifecycleSnapshot) bool {
	if snapshot.Health.Running || lifecycleOwnsPreparedCore(snapshot.Prepared) {
		return false
	}
	return snapshot.State == LifecycleStopped || snapshot.State == LifecycleFailed
}

func lifecycleOwnsPreparedCore(prepared engine.PreparedCore) bool {
	return prepared.Engine != "" || prepared.BinaryPath != "" || prepared.RuntimeConfigPath != "" ||
		prepared.SourceConfigPath != "" || prepared.HomeDir != "" || len(prepared.Args) != 0 || len(prepared.Env) != 0
}

// Backup restore swaps state directories. Serialize it in lifecycle ->
// gateway/DNS -> state -> credentials order. The final lock prevents a
// background session-secret writer from publishing into a state tree while it
// is being swapped. BackupService checks stopped state only after all locks are
// held, closing the stopped-check/start TOCTOU window.
func lockBackupImport(ctx context.Context, lifecycle *Lifecycle, store, openWrtLocks state.Store) (func() error, error) {
	if err := lifecycle.lockOperation(ctx); err != nil {
		return nil, err
	}
	gatewayLock, err := openWrtLocks.Lock(ctx, "gateway-dns")
	if err != nil {
		lifecycle.opMu.Unlock()
		return nil, err
	}
	stateLock, err := store.Lock(ctx, "state")
	if err != nil {
		unlockErr := gatewayLock.Unlock()
		lifecycle.opMu.Unlock()
		return nil, errors.Join(err, unlockErr)
	}
	credentialsLock, err := store.Lock(ctx, "credentials")
	if err != nil {
		unlockErr := errors.Join(stateLock.Unlock(), gatewayLock.Unlock())
		lifecycle.opMu.Unlock()
		return nil, errors.Join(err, unlockErr)
	}
	return func() error {
		unlockErr := errors.Join(credentialsLock.Unlock(), stateLock.Unlock(), gatewayLock.Unlock())
		lifecycle.opMu.Unlock()
		return unlockErr
	}, nil
}

func defaultOneShotRuntime(root, lockRoot string, runner openwrt.Runner) (*oneShotRuntime, error) {
	mihomoDriver := engine.NewMihomoDriver(engine.MihomoOptions{})
	singBoxDriver := engine.NewSingBoxDriver(engine.SingBoxOptions{})
	mihomoPreparer, err := NewActiveMihomoPreparer(root, mihomoDriver)
	if err != nil {
		return nil, err
	}
	singBoxPreparer, err := NewActiveSingBoxPreparer(root, singBoxDriver)
	if err != nil {
		return nil, err
	}
	preparer := &EnginePreparer{
		Profiles: mihomoPreparer.Profiles,
		Preparers: map[string]ExplicitProfilePreparer{
			state.EngineMihomo: mihomoPreparer, state.EngineSingBox: singBoxPreparer,
		},
		Legacy: mihomoPreparer,
	}
	activation, err := newOpenWrtActivation(root, lockRoot, runner)
	if err != nil {
		return nil, err
	}
	return &oneShotRuntime{Preparer: preparer, Activation: activation}, nil
}

func preparedCoreReady(ctx context.Context, prepared engine.PreparedCore) error {
	var controller interface {
		Version(context.Context) (string, error)
	}
	var err error
	switch prepared.Engine {
	case state.EngineMihomo, "":
		controller, err = engine.NewMihomoController(prepared.Controller, nil)
	case state.EngineSingBox:
		controller, err = engine.NewSingBoxController(prepared.Controller, nil)
	default:
		err = fmt.Errorf("unsupported prepared engine %q", prepared.Engine)
	}
	if err != nil {
		return err
	}
	if _, err = controller.Version(ctx); err != nil {
		return err
	}
	if prepared.Capture.DNS.Enabled {
		if err := engine.ProbeDNS(ctx, prepared.Capture.DNS); err != nil {
			return fmt.Errorf("probe core DNS listener: %w", err)
		}
	}
	return nil
}

func removeOneShotRuntime(prepared engine.PreparedCore) {
	engine.CleanupPreparedRuntime(prepared)
}

func (actions *Actions) defaultValidateConfig(ctx context.Context, root, path string) error {
	driver := engine.NewMihomoDriver(engine.MihomoOptions{})
	preparer, err := NewActiveMihomoPreparer(root, driver)
	if err != nil {
		return err
	}
	content, err := readBoundedRegular(path, 32<<20)
	if err != nil {
		return err
	}
	return (&ConfigService{Preparer: preparer}).ValidateMihomoContent(ctx, content)
}

func defaultSetPassword(root string, input io.Reader, output io.Writer) error {
	credentials, err := NewCredentialStore(root)
	if err != nil {
		return err
	}
	file, terminal := input.(*os.File)
	if !terminal {
		return credentials.ReadAndSetPassword(input, output)
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return credentials.ReadAndSetPassword(input, output)
	}
	disable := exec.Command("stty", "-echo")
	disable.Stdin = file
	if err := disable.Run(); err != nil {
		return fmt.Errorf("disable terminal echo: %w", err)
	}
	defer func() {
		restore := exec.Command("stty", "echo")
		restore.Stdin = file
		_ = restore.Run()
		_, _ = io.WriteString(output, "\n")
	}()
	return credentials.ReadAndSetPassword(input, output)
}

type DoctorCheck struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

type DoctorReport struct {
	Version        string         `json:"version"`
	Root           string         `json:"root"`
	SelectedEngine string         `json:"selectedEngine"`
	CheckedAt      time.Time      `json:"checkedAt"`
	Platform       PlatformReport `json:"platform"`
	Checks         []DoctorCheck  `json:"checks"`
}

func (report *DoctorReport) add(name string, ok bool, message string) {
	if ok {
		message = ""
	}
	report.Checks = append(report.Checks, DoctorCheck{Name: name, OK: ok, Message: message})
}

func (report DoctorReport) Healthy() bool { return report.failureCount() == 0 }

func (report DoctorReport) failureCount() int {
	count := 0
	for _, check := range report.Checks {
		if !check.OK {
			count++
		}
	}
	return count
}

type DoctorError struct{ Failures int }

func (err *DoctorError) Error() string {
	return fmt.Sprintf("doctor found %d failed check(s)", err.Failures)
}

func writeDoctorText(output io.Writer, report DoctorReport) error {
	if _, err := fmt.Fprintf(output, "boxctl %s doctor (%s)\nplatform: %s\n", report.Version, report.Root, report.Platform.Description()); err != nil {
		return err
	}
	for _, check := range report.Checks {
		status := "ok"
		if !check.OK {
			status = "fail"
		}
		if check.Message != "" {
			if _, err := fmt.Fprintf(output, "[%s] %s: %s\n", status, check.Name, check.Message); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintf(output, "[%s] %s\n", status, check.Name); err != nil {
			return err
		}
	}
	return nil
}

func publicCheckError(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	message := strings.ToValidUTF8(err.Error(), "?")
	message = strings.ReplaceAll(message, "\n", " ")
	message = strings.ReplaceAll(message, "\r", " ")
	if len(message) > 240 {
		message = message[:240] + "..."
	}
	return message
}

var (
	_ cli.Actions = (*Actions)(nil)
	_ Activation  = noopActivation{}
)
