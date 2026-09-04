package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	configpkg "github.com/kontsevoye/boxctl/internal/config"
	"github.com/kontsevoye/boxctl/internal/state"
)

const (
	mihomoEngineName         = "mihomo"
	defaultMihomoStopTimeout = 10 * time.Second
	defaultMihomoLogBuffer   = 512
	maxCommandOutput         = 1 << 20
)

var mihomoCapabilities = Capabilities{
	HotReload:           true,
	Proxies:             true,
	Groups:              true,
	Selection:           true,
	Delay:               true,
	ProxyProviders:      true,
	RuleProviders:       true,
	Rules:               true,
	Connections:         true,
	CloseConnection:     true,
	CloseAllConnections: true,
	RoutingMode:         true,
	TrafficStream:       true,
	// Mihomo exposes the evaluated rule list as read-only. Its external
	// controller has no supported per-rule enable/disable operation.
	RuleMutation: false,
	ProcessLogs:  true,
}

// MihomoOptions controls supervision and HTTP behavior. Zero values are safe
// production defaults.
type MihomoOptions struct {
	HTTPClient  *http.Client
	StopTimeout time.Duration
	LogBuffer   int
	// ProcessStatePath enables Linux manager-to-manager process handoff. The
	// core then inherits stable stdio descriptors instead of parent-owned pipes.
	ProcessStatePath string
}

// MihomoDriver implements Config, Runtime and Control for an external Mihomo
// binary. One driver supervises at most one process at a time.
type MihomoDriver struct {
	httpClient       *http.Client
	stopTimeout      time.Duration
	logs             chan LogEntry
	processStatePath string
	sequence         atomic.Uint64

	mu              sync.RWMutex
	cmd             *exec.Cmd
	pid             int
	processIdentity string
	launchArgs      []string
	done            chan struct{}
	prepared        PreparedCore
	startedAt       time.Time
	lastExitError   string
	logCancel       context.CancelFunc
}

func NewMihomoDriver(options MihomoOptions) *MihomoDriver {
	stopTimeout := options.StopTimeout
	if stopTimeout <= 0 {
		stopTimeout = defaultMihomoStopTimeout
	}
	logBuffer := options.LogBuffer
	if logBuffer <= 0 {
		logBuffer = defaultMihomoLogBuffer
	}
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &MihomoDriver{
		httpClient:       httpClient,
		stopTimeout:      stopTimeout,
		logs:             make(chan LogEntry, logBuffer),
		processStatePath: options.ProcessStatePath,
	}
}

const persistedMihomoProcessVersion = 1

type persistedMihomoPrepared struct {
	Engine            string             `json:"engine"`
	BinaryPath        string             `json:"binaryPath"`
	SourceConfigPath  string             `json:"sourceConfigPath"`
	RuntimeConfigPath string             `json:"runtimeConfigPath"`
	RuntimeConfigRoot string             `json:"runtimeConfigRoot"`
	HomeDir           string             `json:"homeDir"`
	Args              []string           `json:"args"`
	Env               []string           `json:"env,omitempty"`
	Capture           CapturePlan        `json:"capture"`
	Controller        ControllerEndpoint `json:"controller"`
	Capabilities      Capabilities       `json:"capabilities"`
}

type persistedMihomoProcess struct {
	Version    int                     `json:"version"`
	PID        int                     `json:"pid"`
	Identity   string                  `json:"identity"`
	StartedAt  time.Time               `json:"startedAt"`
	LaunchArgs []string                `json:"launchArgs"`
	Prepared   persistedMihomoPrepared `json:"prepared"`
}

func (d *MihomoDriver) Capabilities() Capabilities {
	return mihomoCapabilities
}

// Prepare writes and validates a private runtime YAML copy. It never writes to
// SourceConfigPath.
func (d *MihomoDriver) Prepare(ctx context.Context, request PrepareRequest) (PreparedCore, error) {
	if err := ctx.Err(); err != nil {
		return PreparedCore{}, err
	}
	if err := verifyExecutable(request.BinaryPath); err != nil {
		return PreparedCore{}, err
	}
	if request.SourceConfigPath == "" {
		return PreparedCore{}, errors.New("mihomo source config path is required")
	}
	if request.RuntimeDir == "" {
		return PreparedCore{}, errors.New("mihomo runtime base directory is required")
	}
	runtimeBase, err := filepath.Abs(request.RuntimeDir)
	if err != nil {
		return PreparedCore{}, fmt.Errorf("resolve Mihomo runtime base directory: %w", err)
	}
	if err := request.Capture.Validate(); err != nil {
		return PreparedCore{}, fmt.Errorf("invalid Mihomo capture plan: %w", err)
	}

	request.Capture.Capabilities = mihomoCapabilities
	if request.Capture.LoopMark == 0 {
		request.Capture.LoopMark = 2
	}
	if (request.Capture.TCP.Method == CaptureTUN || request.Capture.UDP.Method == CaptureTUN) && request.Capture.TUNStack == "" {
		request.Capture.TUNStack = "system"
	}
	home := request.HomeDir
	if home == "" {
		home = filepath.Dir(request.SourceConfigPath)
	}
	home, err = filepath.Abs(home)
	if err != nil {
		return PreparedCore{}, fmt.Errorf("resolve Mihomo home: %w", err)
	}
	controller, err := normalizeController(request.Controller)
	if err != nil {
		return PreparedCore{}, err
	}

	capture, err := mihomoCaptureFromPlan(request.Capture)
	if err != nil {
		return PreparedCore{}, err
	}
	listen := controller.Listen
	secret := controller.Secret
	loopMark := request.Capture.LoopMark
	patch := configpkg.MihomoPatch{
		Capture:            &capture,
		ExternalController: &listen,
		Secret:             &secret,
		RoutingMark:        &loopMark,
	}
	if request.Capture.DNS.Enabled {
		dnsEnabled := true
		dnsListen := net.JoinHostPort(request.Capture.DNS.Host, fmt.Sprintf("%d", request.Capture.DNS.Port))
		if request.Capture.DNS.Host == "" {
			dnsListen = fmt.Sprintf(":%d", request.Capture.DNS.Port)
		}
		patch.DNSEnabled = &dnsEnabled
		patch.DNSListen = &dnsListen
	}

	runtimeRoot, err := createMihomoRuntimeRoot(runtimeBase)
	if err != nil {
		return PreparedCore{}, err
	}
	runtimePath := filepath.Join(runtimeRoot, "mihomo-runtime.yaml")
	prepared := PreparedCore{
		Engine:                 mihomoEngineName,
		BinaryPath:             request.BinaryPath,
		SourceConfigPath:       request.SourceConfigPath,
		RuntimeConfigPath:      runtimePath,
		HomeDir:                home,
		Args:                   []string{"-d", home, "-f", runtimePath},
		Capture:                request.Capture,
		Controller:             controller,
		Capabilities:           mihomoCapabilities,
		runtimeConfigRoot:      runtimeRoot,
		runtimeConfigOwnedPath: runtimePath,
	}
	if err := configpkg.WriteMihomoRuntime(request.SourceConfigPath, runtimePath, patch); err != nil {
		CleanupPreparedRuntime(prepared)
		return PreparedCore{}, fmt.Errorf("prepare Mihomo runtime config: %w", err)
	}

	if err := d.Validate(ctx, prepared); err != nil {
		CleanupPreparedRuntime(prepared)
		return PreparedCore{}, err
	}
	return prepared, nil
}

func createMihomoRuntimeRoot(base string) (string, error) {
	info, err := os.Lstat(base)
	if err != nil {
		return "", fmt.Errorf("inspect Mihomo runtime base directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("mihomo runtime base must be an existing non-symlink directory")
	}
	root, err := os.MkdirTemp(base, "boxctl-mihomo-")
	if err != nil {
		return "", fmt.Errorf("create private Mihomo runtime directory: %w", err)
	}
	return root, nil
}

func verifyExecutable(path string) error {
	if path == "" {
		return errors.New("engine binary path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat engine binary: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("engine binary is not a regular file")
	}
	if info.Mode().Perm()&0o111 == 0 {
		return errors.New("engine binary is not executable")
	}
	return nil
}

func normalizeController(endpoint ControllerEndpoint) (ControllerEndpoint, error) {
	if endpoint.Listen == "" {
		endpoint.Listen = "127.0.0.1:9090"
	}
	if strings.ContainsAny(endpoint.Listen, "\r\n") || strings.ContainsAny(endpoint.Secret, "\r\n") {
		return ControllerEndpoint{}, errors.New("mihomo controller settings contain a newline")
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(endpoint.Listen))
	if err != nil {
		return ControllerEndpoint{}, fmt.Errorf("parse Mihomo controller listen address: %w", err)
	}
	if port == "" {
		return ControllerEndpoint{}, errors.New("mihomo controller listen port is required")
	}
	// The source host is intentionally discarded for the private copy.
	endpoint.Listen = net.JoinHostPort("127.0.0.1", port)
	if endpoint.BaseURL == "" {
		endpoint.BaseURL = "http://" + endpoint.Listen
	}
	if _, err := NewMihomoController(endpoint, nil); err != nil {
		return ControllerEndpoint{}, err
	}
	return endpoint, nil
}

func mihomoCaptureFromPlan(plan CapturePlan) (configpkg.MihomoCapture, error) {
	if plan.TCP.Method == CaptureTPROXY && plan.UDP.Method == CaptureTPROXY && plan.TCP.Port != plan.UDP.Port {
		return configpkg.MihomoCapture{}, fmt.Errorf("%w: Mihomo requires one shared TPROXY port for TCP and UDP", ErrUnsupported)
	}
	capture := configpkg.MihomoCapture{
		TProxyPort:   firstPortFor(plan, CaptureTPROXY),
		RedirectPort: firstPortFor(plan, CaptureRedirect),
		TUNDevice:    plan.TUNDevice,
		TUNStack:     plan.TUNStack,
	}
	switch {
	case plan.TCP.Method == CaptureTPROXY && plan.UDP.Method == CaptureTPROXY:
		capture.Mode = configpkg.MihomoCaptureTPROXY
	case plan.TCP.Method == CaptureRedirect && plan.UDP.Method == CaptureTPROXY:
		capture.Mode = configpkg.MihomoCaptureHybrid
	case plan.TCP.Method == CaptureTUN && plan.UDP.Method == CaptureTUN:
		capture.Mode = configpkg.MihomoCaptureTUN
	case plan.TCP.Method == CaptureTPROXY && plan.UDP.Method == CaptureTUN:
		capture.Mode = configpkg.MihomoCaptureMixed
	case plan.TCP.Method == CaptureRedirect && plan.UDP.Method == CaptureTUN:
		capture.Mode = configpkg.MihomoCaptureMixed2
	default:
		return configpkg.MihomoCapture{}, fmt.Errorf("%w: Mihomo does not support TCP=%s UDP=%s", ErrUnsupported, plan.TCP.Method, plan.UDP.Method)
	}
	return capture, nil
}

func firstPortFor(plan CapturePlan, method CaptureMethod) uint16 {
	if plan.TCP.Method == method {
		return plan.TCP.Port
	}
	if plan.UDP.Method == method {
		return plan.UDP.Port
	}
	return 0
}

// Validate executes Mihomo's native config check in a disposable process
// group, so context cancellation cannot leave validation children behind.
func (d *MihomoDriver) Validate(ctx context.Context, prepared PreparedCore) error {
	if err := validatePreparedMihomo(prepared); err != nil {
		return err
	}
	args := []string{"-t", "-d", prepared.HomeDir, "-f", prepared.RuntimeConfigPath}
	output, err := runCommandGroup(ctx, prepared.BinaryPath, args, prepared.Env)
	if err != nil {
		return fmt.Errorf("mihomo config validation failed: %w: %s", err, strings.TrimSpace(output))
	}
	return nil
}

func validatePreparedMihomo(prepared PreparedCore) error {
	if prepared.Engine != "" && prepared.Engine != mihomoEngineName {
		return fmt.Errorf("prepared core is %q, not Mihomo", prepared.Engine)
	}
	if err := verifyExecutable(prepared.BinaryPath); err != nil {
		return err
	}
	if prepared.RuntimeConfigPath == "" || prepared.HomeDir == "" {
		return errors.New("prepared Mihomo core lacks runtime config or home")
	}
	runtimePath := filepath.Clean(prepared.RuntimeConfigPath)
	runtimeRoot := filepath.Clean(prepared.runtimeConfigRoot)
	if runtimeRoot == "." || filepath.Clean(prepared.runtimeConfigOwnedPath) != runtimePath || filepath.Dir(runtimePath) != runtimeRoot {
		return errors.New("prepared Mihomo runtime config lacks private ownership")
	}
	rootInfo, err := os.Lstat(runtimeRoot)
	if err != nil {
		return fmt.Errorf("stat Mihomo runtime root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() || rootInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("mihomo runtime root is not a private directory")
	}
	info, err := os.Lstat(runtimePath)
	if err != nil {
		return fmt.Errorf("stat Mihomo runtime config: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("mihomo runtime config is not a regular file")
	}
	return nil
}

func persistedPreparedCore(prepared PreparedCore) persistedMihomoPrepared {
	return persistedMihomoPrepared{
		Engine: prepared.Engine, BinaryPath: prepared.BinaryPath,
		SourceConfigPath: prepared.SourceConfigPath, RuntimeConfigPath: prepared.RuntimeConfigPath,
		RuntimeConfigRoot: prepared.runtimeConfigRoot, HomeDir: prepared.HomeDir,
		Args: append([]string(nil), prepared.Args...), Env: append([]string(nil), prepared.Env...),
		Capture: prepared.Capture, Controller: prepared.Controller, Capabilities: prepared.Capabilities,
	}
}

func (persisted persistedMihomoPrepared) preparedCore() PreparedCore {
	return PreparedCore{
		Engine: persisted.Engine, BinaryPath: persisted.BinaryPath,
		SourceConfigPath: persisted.SourceConfigPath, RuntimeConfigPath: persisted.RuntimeConfigPath,
		HomeDir: persisted.HomeDir, Args: append([]string(nil), persisted.Args...), Env: append([]string(nil), persisted.Env...),
		Capture: persisted.Capture, Controller: persisted.Controller, Capabilities: persisted.Capabilities,
		runtimeConfigRoot: persisted.RuntimeConfigRoot, runtimeConfigOwnedPath: persisted.RuntimeConfigPath,
	}
}

func (d *MihomoDriver) writeProcessState(pid int, identity string, startedAt time.Time, launchArgs []string, prepared PreparedCore) error {
	if d.processStatePath == "" {
		return nil
	}
	data, err := json.MarshalIndent(persistedMihomoProcess{
		Version: persistedMihomoProcessVersion, PID: pid, Identity: identity,
		StartedAt: startedAt, LaunchArgs: append([]string(nil), launchArgs...), Prepared: persistedPreparedCore(prepared),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Mihomo process state: %w", err)
	}
	data = append(data, '\n')
	if err := state.WriteFileAtomic(d.processStatePath, data, 0o600); err != nil {
		return fmt.Errorf("persist Mihomo process state: %w", err)
	}
	return nil
}

func (d *MihomoDriver) readProcessState() (persistedMihomoProcess, error) {
	if d.processStatePath == "" {
		return persistedMihomoProcess{}, os.ErrNotExist
	}
	info, err := os.Lstat(d.processStatePath)
	if err != nil {
		return persistedMihomoProcess{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxControllerResponse {
		return persistedMihomoProcess{}, errors.New("mihomo process state is not a private regular file")
	}
	content, err := os.ReadFile(d.processStatePath)
	if err != nil {
		return persistedMihomoProcess{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var persisted persistedMihomoProcess
	if err := decoder.Decode(&persisted); err != nil {
		return persistedMihomoProcess{}, fmt.Errorf("decode Mihomo process state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return persistedMihomoProcess{}, errors.New("decode Mihomo process state: trailing data")
	}
	if persisted.Version != persistedMihomoProcessVersion || persisted.PID <= 1 || persisted.Identity == "" || persisted.StartedAt.IsZero() {
		return persistedMihomoProcess{}, errors.New("mihomo process state is invalid")
	}
	return persisted, nil
}

func (d *MihomoDriver) removeProcessState() {
	if d.processStatePath == "" {
		return
	}
	if info, err := os.Lstat(d.processStatePath); err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		_ = os.Remove(d.processStatePath)
	}
}

// Adopt takes supervision of the exact still-running Mihomo process recorded
// by a previous manager. PID reuse, executable substitution, changed argv, and
// non-private runtime state are all rejected before any in-memory state changes.
func (d *MihomoDriver) Adopt(ctx context.Context) (PreparedCore, HealthStatus, error) {
	if err := ctx.Err(); err != nil {
		return PreparedCore{}, HealthStatus{}, err
	}
	persisted, err := d.readProcessState()
	if err != nil {
		return PreparedCore{}, HealthStatus{}, err
	}
	prepared := persisted.Prepared.preparedCore()
	if err := validatePreparedMihomo(prepared); err != nil {
		return PreparedCore{}, HealthStatus{}, err
	}
	if err := validatePersistedProcess(persisted.PID, persisted.Identity, prepared.BinaryPath, persisted.LaunchArgs); err != nil {
		return PreparedCore{}, HealthStatus{}, err
	}
	d.mu.Lock()
	if d.pid != 0 {
		d.mu.Unlock()
		return PreparedCore{}, HealthStatus{}, ErrAlreadyRunning
	}
	d.pid = persisted.PID
	d.processIdentity = persisted.Identity
	d.launchArgs = append([]string(nil), persisted.LaunchArgs...)
	d.prepared = clonePreparedCore(prepared)
	d.startedAt = persisted.StartedAt
	d.lastExitError = ""
	d.mu.Unlock()
	d.emitLog("supervisor", fmt.Sprintf("Mihomo process %d adopted from the previous boxctl manager", persisted.PID))
	d.startControllerLogPump(prepared.Controller)
	go d.reapAdoptedChild(persisted.PID, persisted.Identity, prepared)
	health, healthErr := d.Health(ctx)
	if healthErr != nil {
		d.emitLog("supervisor", "adopted Mihomo readiness check: "+healthErr.Error())
	}
	return prepared, health, nil
}

func (d *MihomoDriver) reapAdoptedChild(pid int, identity string, prepared PreparedCore) {
	reaped, err := waitAdoptedChild(pid)
	if err != nil {
		d.emitLog("supervisor", "could not wait for adopted Mihomo process: "+err.Error())
		return
	}
	if !reaped {
		return
	}
	d.mu.Lock()
	if d.pid != pid || d.processIdentity != identity {
		d.mu.Unlock()
		return
	}
	d.pid = 0
	d.processIdentity = ""
	d.launchArgs = nil
	d.prepared = PreparedCore{}
	d.lastExitError = "adopted Mihomo process exited"
	if d.logCancel != nil {
		d.logCancel()
		d.logCancel = nil
	}
	d.mu.Unlock()
	d.removeProcessState()
	removeMihomoRuntime(prepared)
	d.emitLog("supervisor", "adopted Mihomo process exited")
}

func (d *MihomoDriver) Start(ctx context.Context, prepared PreparedCore) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := d.Validate(ctx, prepared); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	d.mu.Lock()
	if d.pid != 0 {
		d.mu.Unlock()
		return ErrAlreadyRunning
	}
	args := append([]string(nil), prepared.Args...)
	if len(args) == 0 {
		args = []string{"-d", prepared.HomeDir, "-f", prepared.RuntimeConfigPath}
	}
	cmd := exec.Command(prepared.BinaryPath, args...)
	cmd.Dir = prepared.HomeDir
	cmd.Env = append(os.Environ(), prepared.Env...)
	cmd.SysProcAttr = childProcessAttributes(d.processStatePath != "")
	var stdout, stderr *lineLogWriter
	if d.processStatePath == "" {
		stdout = &lineLogWriter{driver: d, stream: "stdout"}
		stderr = &lineLogWriter{driver: d, stream: "stderr"}
		cmd.Stdout = stdout
		cmd.Stderr = stderr
	} else {
		// These descriptors belong to the stable service logger, not to a pipe
		// drained by this manager process, so Mihomo survives manager replacement.
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	process, err := startChildProcess(cmd)
	if err != nil {
		d.mu.Unlock()
		return fmt.Errorf("start Mihomo: %w", err)
	}
	done := make(chan struct{})
	d.cmd = cmd
	d.pid = cmd.Process.Pid
	d.done = done
	d.prepared = clonePreparedCore(prepared)
	d.startedAt = time.Now().UTC()
	d.launchArgs = append([]string(nil), args...)
	d.lastExitError = ""
	if d.processStatePath != "" {
		identity, identityErr := captureProcessIdentity(cmd.Process.Pid)
		if identityErr != nil {
			d.cmd, d.pid, d.done = nil, 0, nil
			d.prepared = PreparedCore{}
			d.launchArgs = nil
			d.mu.Unlock()
			_ = signalProcessGroup(cmd.Process.Pid, syscall.SIGKILL)
			_ = process.Wait()
			return fmt.Errorf("identify Mihomo process: %w", identityErr)
		}
		d.processIdentity = identity
		if stateErr := d.writeProcessState(cmd.Process.Pid, identity, d.startedAt, args, prepared); stateErr != nil {
			d.cmd, d.pid, d.done = nil, 0, nil
			d.processIdentity = ""
			d.prepared = PreparedCore{}
			d.launchArgs = nil
			d.mu.Unlock()
			_ = signalProcessGroup(cmd.Process.Pid, syscall.SIGKILL)
			_ = process.Wait()
			return stateErr
		}
	}
	d.mu.Unlock()

	d.emitLog("supervisor", fmt.Sprintf("Mihomo started with pid %d", cmd.Process.Pid))
	go d.waitProcess(cmd, process, done, stdout, stderr)
	if d.processStatePath != "" {
		d.startControllerLogPump(prepared.Controller)
	}
	return nil
}

func clonePreparedCore(prepared PreparedCore) PreparedCore {
	prepared.Args = append([]string(nil), prepared.Args...)
	prepared.Env = append([]string(nil), prepared.Env...)
	prepared.Capture.FakeIPRanges = append([]netip.Prefix(nil), prepared.Capture.FakeIPRanges...)
	prepared.Capture.Destinations.CIDRs = append([]netip.Prefix(nil), prepared.Capture.Destinations.CIDRs...)
	prepared.Capture.EndpointBypassCIDRs = append([]netip.Prefix(nil), prepared.Capture.EndpointBypassCIDRs...)
	return prepared
}

func (d *MihomoDriver) waitProcess(cmd *exec.Cmd, process *startedProcess, done chan struct{}, stdout, stderr *lineLogWriter) {
	err := process.Wait()
	if stdout != nil {
		stdout.Flush()
	}
	if stderr != nil {
		stderr.Flush()
	}
	var finished PreparedCore
	d.mu.Lock()
	if d.cmd == cmd {
		finished = d.prepared
		d.cmd = nil
		d.pid = 0
		d.processIdentity = ""
		d.launchArgs = nil
		d.done = nil
		d.prepared = PreparedCore{}
		if d.logCancel != nil {
			d.logCancel()
			d.logCancel = nil
		}
		if err != nil {
			d.lastExitError = err.Error()
		}
	}
	d.mu.Unlock()
	d.removeProcessState()
	removeMihomoRuntime(finished)
	close(done)
	if err != nil {
		d.emitLog("supervisor", "Mihomo exited: "+err.Error())
	} else {
		d.emitLog("supervisor", "Mihomo exited")
	}
}

func (d *MihomoDriver) Stop(ctx context.Context) error {
	d.mu.RLock()
	pid := d.pid
	identity := d.processIdentity
	done := d.done
	prepared := clonePreparedCore(d.prepared)
	d.mu.RUnlock()
	if pid == 0 {
		return nil
	}

	if err := signalProcessGroup(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("terminate Mihomo process group: %w", err)
	}
	timer := time.NewTimer(d.stopTimeout)
	defer timer.Stop()
	waitExited := func() bool {
		if done != nil {
			select {
			case <-done:
				return true
			default:
				return false
			}
		}
		return !persistedProcessAlive(pid, identity)
	}
	finishAdopted := func() {
		if done != nil {
			return
		}
		d.mu.Lock()
		if d.pid == pid && d.processIdentity == identity {
			d.pid = 0
			d.processIdentity = ""
			d.launchArgs = nil
			d.prepared = PreparedCore{}
			if d.logCancel != nil {
				d.logCancel()
				d.logCancel = nil
			}
		}
		d.mu.Unlock()
		d.removeProcessState()
		removeMihomoRuntime(prepared)
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	killed := false
	for {
		if waitExited() {
			finishAdopted()
			return nil
		}
		select {
		case <-ctx.Done():
			_ = signalProcessGroup(pid, syscall.SIGKILL)
			return ctx.Err()
		case <-timer.C:
			if killed {
				return errors.New("mihomo process did not exit after SIGKILL")
			}
			d.emitLog("supervisor", "Mihomo did not stop after SIGTERM; sending SIGKILL")
			if err := signalProcessGroup(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
				return fmt.Errorf("kill Mihomo process group: %w", err)
			}
			killed = true
			timer.Reset(2 * time.Second)
		case <-ticker.C:
		}
	}
}

func signalProcessGroup(pid int, signal syscall.Signal) error {
	if pid <= 1 {
		return fmt.Errorf("refusing to signal unsafe process group %d", pid)
	}
	return syscall.Kill(-pid, signal)
}

func (d *MihomoDriver) Reload(ctx context.Context, prepared PreparedCore) error {
	if !prepared.Capabilities.Supports(CapabilityHotReload) {
		return unsupported(CapabilityHotReload)
	}
	d.mu.RLock()
	running := d.pid != 0
	d.mu.RUnlock()
	if !running {
		return ErrNotRunning
	}
	if err := d.Validate(ctx, prepared); err != nil {
		return err
	}
	controller, err := NewMihomoController(prepared.Controller, d.httpClient)
	if err != nil {
		return err
	}
	if err := controller.Reload(ctx, prepared.RuntimeConfigPath); err != nil {
		return err
	}
	d.mu.Lock()
	if d.pid == 0 {
		d.mu.Unlock()
		return ErrNotRunning
	}
	previous := d.prepared
	d.prepared = clonePreparedCore(prepared)
	persistErr := d.writeProcessState(d.pid, d.processIdentity, d.startedAt, d.launchArgs, prepared)
	d.mu.Unlock()
	if persistErr != nil {
		return persistErr
	}
	removeMihomoRuntime(previous)
	d.emitLog("supervisor", "Mihomo configuration hot-reloaded")
	return nil
}

// CleanupPreparedRuntime removes only the exact private runtime file and root
// recorded by the concrete engine preparer. Callers cannot manufacture this
// ownership metadata because it is private to the engine package.
func CleanupPreparedRuntime(prepared PreparedCore) {
	path := filepath.Clean(prepared.RuntimeConfigPath)
	root := filepath.Clean(prepared.runtimeConfigRoot)
	ownedPath := filepath.Clean(prepared.runtimeConfigOwnedPath)
	if path == "." || root == "." || ownedPath == "." || path != ownedPath || path == filepath.Clean(prepared.SourceConfigPath) ||
		filepath.Dir(path) != root || !strings.HasPrefix(filepath.Base(path), "mihomo-") || filepath.Ext(path) != ".yaml" {
		return
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return
	}
	info, err := os.Lstat(path)
	switch {
	case err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0:
		if os.Remove(path) != nil {
			return
		}
	case errors.Is(err, os.ErrNotExist):
		// The runtime file may not have been installed yet after a failed
		// preparation. The exact private root is still safe to remove.
	default:
		return
	}
	_ = os.Remove(root)
}

func removeMihomoRuntime(prepared PreparedCore) { CleanupPreparedRuntime(prepared) }

func (d *MihomoDriver) Health(ctx context.Context) (HealthStatus, error) {
	now := time.Now().UTC()
	d.mu.RLock()
	pid := d.pid
	identity := d.processIdentity
	prepared := clonePreparedCore(d.prepared)
	startedAt := d.startedAt
	lastExit := d.lastExitError
	d.mu.RUnlock()
	status := HealthStatus{CheckedAt: now, StartedAt: startedAt, LastExitError: lastExit}
	if pid == 0 || (identity != "" && !persistedProcessAlive(pid, identity)) {
		return status, nil
	}
	status.Running = true
	status.PID = pid
	controller, err := NewMihomoController(prepared.Controller, d.httpClient)
	if err != nil {
		return status, err
	}
	version, err := controller.Version(ctx)
	if err != nil {
		return status, err
	}
	status.ControllerReady = true
	status.Version = version
	if prepared.Capture.DNS.Enabled {
		if err := ProbeDNS(ctx, prepared.Capture.DNS); err != nil {
			return status, fmt.Errorf("probe Mihomo DNS listener: %w", err)
		}
		status.DNSReady = true
	}
	return status, nil
}

func (d *MihomoDriver) Version(ctx context.Context, binaryPath string) (string, error) {
	if err := verifyExecutable(binaryPath); err != nil {
		return "", err
	}
	output, err := runCommandGroup(ctx, binaryPath, []string{"-v"}, nil)
	if err != nil {
		return "", fmt.Errorf("read Mihomo version: %w: %s", err, strings.TrimSpace(output))
	}
	version := strings.TrimSpace(output)
	if version == "" {
		return "", errors.New("mihomo returned an empty version")
	}
	return version, nil
}

func (d *MihomoDriver) Logs() <-chan LogEntry {
	return d.logs
}

func (d *MihomoDriver) emitLog(stream, message string) {
	entry := LogEntry{
		Sequence: d.sequence.Add(1),
		Time:     time.Now().UTC(),
		Stream:   stream,
		Message:  message,
	}
	select {
	case d.logs <- entry:
	default:
	}
}

func (d *MihomoDriver) startControllerLogPump(endpoint ControllerEndpoint) {
	d.mu.Lock()
	if d.logCancel != nil {
		d.logCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.logCancel = cancel
	d.mu.Unlock()
	go func() {
		for {
			if err := ctx.Err(); err != nil {
				return
			}
			controller, err := NewMihomoController(endpoint, d.httpClient)
			if err == nil {
				var stream <-chan MihomoLog
				stream, err = controller.StreamLogs(ctx)
				if err == nil {
					for entry := range stream {
						level := strings.ToLower(strings.TrimSpace(entry.Level))
						message := strings.TrimSpace(entry.Message)
						if message != "" {
							if level != "" {
								message = "level=" + level + " " + message
							}
							d.emitLog("stdout", message)
						}
						if ctx.Err() != nil {
							return
						}
					}
				}
			}
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
			}
		}
	}()
}

type lineLogWriter struct {
	driver *MihomoDriver
	stream string
	mu     sync.Mutex
	buffer []byte
}

func (w *lineLogWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buffer = append(w.buffer, data...)
	for {
		index := bytes.IndexByte(w.buffer, '\n')
		if index < 0 {
			break
		}
		line := strings.TrimSuffix(string(w.buffer[:index]), "\r")
		w.buffer = w.buffer[index+1:]
		w.driver.emitLog(w.stream, line)
	}
	if len(w.buffer) > maxCommandOutput {
		w.driver.emitLog(w.stream, string(w.buffer[:maxCommandOutput])+"…")
		w.buffer = w.buffer[:0]
	}
	return len(data), nil
}

func (w *lineLogWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buffer) == 0 {
		return
	}
	w.driver.emitLog(w.stream, strings.TrimSuffix(string(w.buffer), "\r"))
	w.buffer = nil
}

type limitedOutput struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	truncated bool
}

func (w *limitedOutput) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	original := len(data)
	remaining := maxCommandOutput - w.buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
			w.truncated = true
		}
		_, _ = w.buffer.Write(data)
	} else {
		w.truncated = true
	}
	return original, nil
}

func (w *limitedOutput) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	result := w.buffer.String()
	if w.truncated {
		result += "\n[output truncated]"
	}
	return result
}

func runCommandGroup(ctx context.Context, binary string, args, environment []string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	cmd := exec.Command(binary, args...)
	cmd.SysProcAttr = childProcessAttributes(false)
	if len(environment) > 0 {
		cmd.Env = append(os.Environ(), environment...)
	}
	output := &limitedOutput{}
	cmd.Stdout = output
	cmd.Stderr = output
	process, err := startChildProcess(cmd)
	if err != nil {
		return output.String(), err
	}
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	select {
	case err := <-done:
		return output.String(), err
	case <-ctx.Done():
		_ = signalProcessGroup(cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return output.String(), ctx.Err()
	}
}

func unsupported(capability Capability) error {
	return fmt.Errorf("%w: %s", ErrUnsupported, capability)
}

func (d *MihomoDriver) controller(capability Capability) (*MihomoController, error) {
	d.mu.RLock()
	running := d.pid != 0
	prepared := clonePreparedCore(d.prepared)
	d.mu.RUnlock()
	if !running {
		return nil, ErrNotRunning
	}
	if !prepared.Capabilities.Supports(capability) {
		return nil, unsupported(capability)
	}
	return NewMihomoController(prepared.Controller, d.httpClient)
}

// ActiveControllerEndpoint returns the running loopback controller endpoint
// for trusted in-process adapters such as the authenticated external-dashboard
// proxy. Callers must never serialize the returned Secret or put it in a URL.
func (d *MihomoDriver) ActiveControllerEndpoint() (ControllerEndpoint, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.pid == 0 {
		return ControllerEndpoint{}, ErrNotRunning
	}
	return d.prepared.Controller, nil
}

func (d *MihomoDriver) Proxies(ctx context.Context) ([]Proxy, error) {
	controller, err := d.controller(CapabilityProxies)
	if err != nil {
		return nil, err
	}
	return controller.Proxies(ctx)
}

func (d *MihomoDriver) Groups(ctx context.Context) ([]ProxyGroup, error) {
	controller, err := d.controller(CapabilityGroups)
	if err != nil {
		return nil, err
	}
	return controller.Groups(ctx)
}

func (d *MihomoDriver) Select(ctx context.Context, group, proxy string) error {
	controller, err := d.controller(CapabilitySelection)
	if err != nil {
		return err
	}
	return controller.Select(ctx, group, proxy)
}

func (d *MihomoDriver) Delay(ctx context.Context, proxy, testURL string, timeout time.Duration) (time.Duration, error) {
	controller, err := d.controller(CapabilityDelay)
	if err != nil {
		return 0, err
	}
	return controller.Delay(ctx, proxy, testURL, timeout)
}

func (d *MihomoDriver) Providers(ctx context.Context, kind ProviderKind) ([]Provider, error) {
	capability := CapabilityProxyProviders
	if kind == ProviderRule {
		capability = CapabilityRuleProviders
	}
	controller, err := d.controller(capability)
	if err != nil {
		return nil, err
	}
	return controller.Providers(ctx, kind)
}

func (d *MihomoDriver) UpdateProvider(ctx context.Context, kind ProviderKind, name string) error {
	capability := CapabilityProxyProviders
	if kind == ProviderRule {
		capability = CapabilityRuleProviders
	}
	controller, err := d.controller(capability)
	if err != nil {
		return err
	}
	return controller.UpdateProvider(ctx, kind, name)
}

func (d *MihomoDriver) Rules(ctx context.Context) ([]Rule, error) {
	controller, err := d.controller(CapabilityRules)
	if err != nil {
		return nil, err
	}
	return controller.Rules(ctx)
}

func (d *MihomoDriver) Connections(ctx context.Context) (ConnectionsSnapshot, error) {
	controller, err := d.controller(CapabilityConnections)
	if err != nil {
		return ConnectionsSnapshot{}, err
	}
	return controller.Connections(ctx)
}

func (d *MihomoDriver) StreamConnections(ctx context.Context, interval time.Duration) (<-chan ConnectionsSnapshot, error) {
	controller, err := d.controller(CapabilityConnections)
	if err != nil {
		return nil, err
	}
	return controller.StreamConnections(ctx, interval)
}

func (d *MihomoDriver) CloseConnection(ctx context.Context, id string) error {
	controller, err := d.controller(CapabilityCloseConnection)
	if err != nil {
		return err
	}
	return controller.CloseConnection(ctx, id)
}

func (d *MihomoDriver) CloseAllConnections(ctx context.Context) error {
	controller, err := d.controller(CapabilityCloseAllConnections)
	if err != nil {
		return err
	}
	return controller.CloseAllConnections(ctx)
}

func (d *MihomoDriver) RoutingMode(ctx context.Context) (RoutingMode, error) {
	controller, err := d.controller(CapabilityRoutingMode)
	if err != nil {
		return "", err
	}
	return controller.RoutingMode(ctx)
}

func (d *MihomoDriver) SetRoutingMode(ctx context.Context, mode RoutingMode) error {
	controller, err := d.controller(CapabilityRoutingMode)
	if err != nil {
		return err
	}
	return controller.SetRoutingMode(ctx, mode)
}

func (d *MihomoDriver) StreamTraffic(ctx context.Context) (<-chan TrafficSnapshot, error) {
	controller, err := d.controller(CapabilityTrafficStream)
	if err != nil {
		return nil, err
	}
	return controller.StreamTraffic(ctx)
}

var (
	_ Config    = (*MihomoDriver)(nil)
	_ Runtime   = (*MihomoDriver)(nil)
	_ Control   = (*MihomoDriver)(nil)
	_ io.Writer = (*lineLogWriter)(nil)
)
