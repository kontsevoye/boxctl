package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	configpkg "github.com/kontsevoye/boxctl/internal/config"
)

const (
	mihomoEngineName = "mihomo"
	maxCommandOutput = 1 << 20
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
	httpClient *http.Client
	supervisor *externalProcessSupervisor
}

func NewMihomoDriver(options MihomoOptions) *MihomoDriver {
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	driver := &MihomoDriver{httpClient: httpClient}
	driver.supervisor = newExternalProcessSupervisor(externalProcessSupervisorOptions{
		Engine: mihomoEngineName, DisplayName: "Mihomo",
		ProcessStatePath: options.ProcessStatePath, StopTimeout: options.StopTimeout, LogBuffer: options.LogBuffer,
		DefaultArgs: func(prepared PreparedCore) []string {
			return []string{"-d", prepared.HomeDir, "-f", prepared.RuntimeConfigPath}
		},
		Validate: driver.Validate, ValidatePrepared: validatePreparedMihomo,
		Cleanup: CleanupPreparedRuntime, LogPump: driver.controllerLogPump,
	})
	return driver
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

// Adopt takes supervision of the exact still-running Mihomo process recorded
// by a previous manager. PID reuse, executable substitution, changed argv, and
// non-private runtime state are all rejected before any in-memory state changes.
func (d *MihomoDriver) Adopt(ctx context.Context) (PreparedCore, HealthStatus, error) {
	prepared, err := d.supervisor.Adopt(ctx)
	if err != nil {
		return PreparedCore{}, HealthStatus{}, err
	}
	health, healthErr := d.Health(ctx)
	if healthErr != nil {
		d.supervisor.emitLog("supervisor", "adopted Mihomo readiness check: "+healthErr.Error())
	}
	return prepared, health, nil
}

func (d *MihomoDriver) Start(ctx context.Context, prepared PreparedCore) error {
	return d.supervisor.Start(ctx, prepared)
}

func (d *MihomoDriver) Stop(ctx context.Context) error {
	return d.supervisor.Stop(ctx)
}

func (d *MihomoDriver) Reload(ctx context.Context, prepared PreparedCore) error {
	if !prepared.Capabilities.Supports(CapabilityHotReload) {
		return unsupported(CapabilityHotReload)
	}
	pid, _, _, _, _ := d.supervisor.snapshot()
	if pid == 0 {
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
	previous, persistErr := d.supervisor.replacePrepared(prepared)
	if persistErr != nil {
		return persistErr
	}
	removeMihomoRuntime(previous)
	d.supervisor.emitLog("supervisor", "Mihomo configuration hot-reloaded")
	return nil
}

// CleanupPreparedRuntime removes only the exact private runtime file and root
// recorded by the concrete engine preparer. Callers cannot manufacture this
// ownership metadata because it is private to the engine package.
func CleanupPreparedRuntime(prepared PreparedCore) {
	path := filepath.Clean(prepared.RuntimeConfigPath)
	root := filepath.Clean(prepared.runtimeConfigRoot)
	owned := false
	switch prepared.Engine {
	case "", mihomoEngineName:
		owned = runtimeFileOwnedBy(prepared, "mihomo-", ".yaml")
	case SingBoxEngineName:
		owned = runtimeFileOwnedBy(prepared, "sing-box-", ".json")
	}
	if !owned {
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
	pid, identity, prepared, startedAt, lastExit := d.supervisor.snapshot()
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
	return d.supervisor.Logs()
}

func (d *MihomoDriver) controllerLogPump(ctx context.Context, prepared PreparedCore, emit func(string, string)) {
	for {
		if ctx.Err() != nil {
			return
		}
		controller, err := NewMihomoController(prepared.Controller, d.httpClient)
		if err == nil {
			var stream <-chan MihomoLog
			stream, err = controller.StreamLogs(ctx)
			if err == nil {
				for entry := range stream {
					emitControllerLog(ctx, entry, emit)
					if ctx.Err() != nil {
						return
					}
				}
			}
		}
		if !waitLogReconnect(ctx) {
			return
		}
	}
}

func emitControllerLog(ctx context.Context, entry MihomoLog, emit func(string, string)) {
	if ctx.Err() != nil {
		return
	}
	level := strings.ToLower(strings.TrimSpace(entry.Level))
	message := strings.TrimSpace(entry.Message)
	if message == "" {
		return
	}
	if level != "" {
		message = "level=" + level + " " + message
	}
	emit("stdout", message)
}

func waitLogReconnect(ctx context.Context) bool {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
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
	pid, _, prepared, _, _ := d.supervisor.snapshot()
	if pid == 0 {
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
	return d.supervisor.ActiveControllerEndpoint()
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
	_ Config  = (*MihomoDriver)(nil)
	_ Runtime = (*MihomoDriver)(nil)
	_ Control = (*MihomoDriver)(nil)
)
