package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/platform/openwrt"
	"github.com/kontsevoye/boxctl/internal/state"
)

const (
	openWrtRollbackTimeout    = 10 * time.Second
	defaultOpenWrtLockRoot    = "/var/run/boxctl"
	activeGatewayStatePath    = ".boxctl/active-gateway.json"
	activeGatewayStateVersion = 1
)

// activeGatewayState is the exact successfully activated generation consumed
// by external hotplug processes. It deliberately contains only the live
// controller/capture contract and gateway plan, never runtime file paths.
type activeGatewayState struct {
	Version        int                       `json:"version"`
	Engine         string                    `json:"engine"`
	Controller     engine.ControllerEndpoint `json:"controller"`
	Capture        engine.CapturePlan        `json:"capture"`
	Plan           openwrt.GatewayPlan       `json:"plan"`
	AutoDetectLAN  bool                      `json:"autoDetectLAN,omitempty"`
	AutoDetectWAN  bool                      `json:"autoDetectWAN,omitempty"`
	StaticExcluded []string                  `json:"staticExcluded,omitempty"`
}

type gatewayController interface {
	Detect(context.Context) (openwrt.InterfaceDiscovery, error)
	Apply(context.Context, openwrt.GatewayPlan) error
	Cleanup(context.Context, openwrt.GatewayPlan) error
	Check(context.Context, openwrt.GatewayPlan) (openwrt.CheckResult, error)
}

type dnsController interface {
	Backup(context.Context) (openwrt.DNSBackup, error)
	Apply(context.Context, openwrt.GatewayPlan, openwrt.DNSBackup) error
	Restore(context.Context, openwrt.DNSBackup) error
}

type execGateway struct{ runner openwrt.Runner }

func (gateway execGateway) Detect(ctx context.Context) (openwrt.InterfaceDiscovery, error) {
	return openwrt.DetectInterfaces(ctx, gateway.runner)
}
func (gateway execGateway) Apply(ctx context.Context, plan openwrt.GatewayPlan) error {
	return openwrt.Apply(ctx, gateway.runner, plan)
}
func (gateway execGateway) Cleanup(ctx context.Context, plan openwrt.GatewayPlan) error {
	return openwrt.Cleanup(ctx, gateway.runner, plan)
}
func (gateway execGateway) Check(ctx context.Context, plan openwrt.GatewayPlan) (openwrt.CheckResult, error) {
	return openwrt.Check(ctx, gateway.runner, plan)
}

// OpenWrtActivation owns only the marked nft/policy state and the exact JSON
// dnsmasq backup. Malformed backup state is rejected rather than guessed.
type OpenWrtActivation struct {
	Layout state.Layout
	// State contains root-scoped settings and the durable DNS backup. Locks is
	// a system-wide namespace because nftables, policy routing, and dnsmasq are
	// host-global even when two processes select different data roots.
	State   state.Store
	Locks   state.Store
	gateway gatewayController
	dns     dnsController

	mu       sync.Mutex
	lastPlan *openwrt.GatewayPlan
}

func NewOpenWrtActivation(root string, runner openwrt.Runner) (*OpenWrtActivation, error) {
	return newOpenWrtActivation(root, defaultOpenWrtLockRoot, runner)
}

func newOpenWrtActivation(root, lockRoot string, runner openwrt.Runner) (*OpenWrtActivation, error) {
	if runner == nil {
		return nil, errors.New("OpenWrt runner is required")
	}
	layout, err := state.NewLayout(root)
	if err != nil {
		return nil, err
	}
	store, err := state.NewStore(layout.Root)
	if err != nil {
		return nil, err
	}
	locks, err := state.NewStore(lockRoot)
	if err != nil {
		return nil, err
	}
	dns := openwrt.NewDNSManager(runner)
	return &OpenWrtActivation{Layout: layout, State: store, Locks: locks, gateway: execGateway{runner: runner}, dns: dns}, nil
}

func (activation *OpenWrtActivation) Activate(ctx context.Context, prepared engine.PreparedCore) error {
	enabled, err := activation.gatewayModeEnabled()
	if err != nil {
		return err
	}
	if !enabled {
		activation.mu.Lock()
		activation.lastPlan = nil
		activation.mu.Unlock()
		return nil
	}
	return activation.withTransaction(ctx, true, func() error {
		plan, active, err := activation.buildPlanAndState(ctx, prepared)
		if err != nil {
			return err
		}
		backup, _, err := activation.ensureDNSBackup(ctx)
		if err != nil {
			return err
		}
		if err := activation.gateway.Apply(ctx, plan); err != nil {
			return err
		}
		if err := activation.dns.Apply(ctx, plan, backup); err != nil {
			return err
		}
		copy := plan
		activation.lastPlan = &copy
		return activation.saveActiveGatewayState(active)
	})
}

// Deactivate is deliberately best-effort across both owners: a firewall
// cleanup failure must not prevent restoration of dnsmasq, and vice versa.
func (activation *OpenWrtActivation) Deactivate(ctx context.Context, prepared engine.PreparedCore) error {
	if enabled, err := activation.gatewayModeEnabled(); err == nil && !enabled && !activation.hasGatewayOwnership() {
		activation.mu.Lock()
		activation.lastPlan = nil
		activation.mu.Unlock()
		return nil
	}
	return activation.withTransaction(ctx, false, func() error {
		plan, planErr := activation.planForCleanup(ctx, prepared)
		backup, backupErr := activation.loadDNSBackup()
		var restoreErr error
		if backupErr == nil {
			// Restore resolver ownership first. If the shared cleanup deadline
			// expires later in nft/ip cleanup, DNS never remains pointed at a
			// core which may be stopped by the service manager.
			restoreErr = activation.dns.Restore(ctx, backup)
			if restoreErr == nil {
				restoreErr = activation.removeDNSBackup()
			}
		} else if !errors.Is(backupErr, fs.ErrNotExist) {
			restoreErr = backupErr
		}
		var gatewayErr error
		if planErr == nil {
			gatewayErr = activation.gateway.Cleanup(ctx, plan)
		}
		joined := errors.Join(planErr, gatewayErr, restoreErr)
		if joined == nil {
			joined = activation.removeActiveGatewayState()
		}
		if joined == nil {
			activation.lastPlan = nil
		}
		return joined
	})
}

func (activation *OpenWrtActivation) gatewayModeEnabled() (bool, error) {
	settings, err := LoadRuntimeSettings(activation.State)
	if err != nil {
		return false, err
	}
	return settings.OperatingMode == "gateway", nil
}

func (activation *OpenWrtActivation) hasGatewayOwnership() bool {
	activation.mu.Lock()
	defer activation.mu.Unlock()
	if activation.lastPlan != nil {
		return true
	}
	for _, path := range []string{filepath.Join(activation.Layout.Root, activeGatewayStatePath), activation.Layout.DNSBackup} {
		if _, err := os.Lstat(path); err == nil || !errors.Is(err, fs.ErrNotExist) {
			return true
		}
	}
	return false
}

func (activation *OpenWrtActivation) Reconcile(ctx context.Context, _ engine.PreparedCore) error {
	return activation.withTransaction(ctx, true, func() error {
		active, err := activation.loadActiveGatewayState()
		if err != nil {
			return fmt.Errorf("load active gateway generation: %w", err)
		}
		plan, err := activation.refreshActiveGatewayPlan(ctx, active)
		if err != nil {
			return err
		}
		backup, _, err := activation.ensureDNSBackup(ctx)
		if err != nil {
			return err
		}
		if err := activation.gateway.Apply(ctx, plan); err != nil {
			return errors.Join(err, activation.rollbackLocked(ctx, plan, backup))
		}
		if err := activation.dns.Apply(ctx, plan, backup); err != nil {
			return errors.Join(err, activation.rollbackLocked(ctx, plan, backup))
		}
		copy := plan
		activation.lastPlan = &copy
		return nil
	})
}

// RefreshDynamicCapture atomically reconciles the two sets that can change
// while Mihomo keeps running: the selective destination pool and router-side
// endpoint bypasses. Core listener/inbound settings remain pinned to the
// active generation.
func (activation *OpenWrtActivation) RefreshDynamicCapture(ctx context.Context, destinations engine.DestinationCapture, endpoints []netip.Prefix) (engine.CapturePlan, error) {
	var refreshed engine.CapturePlan
	err := activation.withTransaction(ctx, true, func() error {
		active, err := activation.loadActiveGatewayState()
		if err != nil {
			return fmt.Errorf("load active gateway generation: %w", err)
		}
		previousPlan := active.Plan
		candidate := cloneCapturePlan(active.Capture)
		candidate.Destinations = destinations
		candidate.EndpointBypassCIDRs = append([]netip.Prefix(nil), endpoints...)
		if err := candidate.Validate(); err != nil {
			return fmt.Errorf("validate refreshed capture: %w", err)
		}
		plan, err := dynamicGatewayPlan(active.Plan, candidate)
		if err != nil {
			return err
		}
		active.Plan = plan
		active.Capture = candidate
		plan, err = activation.refreshActiveGatewayPlan(ctx, active)
		if err != nil {
			return err
		}
		active.Plan = plan
		if err := activation.gateway.Apply(ctx, plan); err != nil {
			return err
		}
		if err := activation.saveActiveGatewayState(active); err != nil {
			rollbackContext, cancel := context.WithTimeout(context.Background(), openWrtRollbackTimeout)
			defer cancel()
			return errors.Join(err, activation.gateway.Apply(rollbackContext, previousPlan))
		}
		copy := plan
		activation.lastPlan = &copy
		refreshed = cloneCapturePlan(candidate)
		return nil
	})
	return refreshed, err
}

func dynamicGatewayPlan(plan openwrt.GatewayPlan, capture engine.CapturePlan) (openwrt.GatewayPlan, error) {
	switch capture.Destinations.Mode {
	case engine.DestinationCaptureAll:
		plan.CaptureCIDRs = nil
		plan.CaptureCIDRsConfigured = false
	case engine.DestinationCaptureAllowlist:
		plan.CaptureCIDRsConfigured = true
		plan.CaptureCIDRs = make([]string, 0, len(capture.Destinations.CIDRs))
		for _, prefix := range capture.Destinations.CIDRs {
			if !prefix.IsValid() || !prefix.Addr().Is4() {
				return openwrt.GatewayPlan{}, fmt.Errorf("OpenWrt destination capture is IPv4-only: %s", prefix)
			}
			plan.CaptureCIDRs = append(plan.CaptureCIDRs, prefix.Masked().String())
		}
	default:
		return openwrt.GatewayPlan{}, fmt.Errorf("unsupported destination capture mode %q", capture.Destinations.Mode)
	}
	plan.ProxyServerCIDRs = make([]string, 0, len(capture.EndpointBypassCIDRs))
	for _, prefix := range capture.EndpointBypassCIDRs {
		if !prefix.IsValid() || !prefix.Addr().Is4() {
			return openwrt.GatewayPlan{}, fmt.Errorf("OpenWrt endpoint bypass is IPv4-only: %s", prefix)
		}
		plan.ProxyServerCIDRs = append(plan.ProxyServerCIDRs, prefix.Masked().String())
	}
	return plan, openwrt.Validate(plan)
}

func (activation *OpenWrtActivation) Diagnose(ctx context.Context, _ engine.PreparedCore) (openwrt.CheckResult, error) {
	activation.mu.Lock()
	defer activation.mu.Unlock()
	lock, err := activation.Locks.Lock(ctx, "gateway-dns")
	if err != nil {
		return openwrt.CheckResult{}, err
	}
	if err := authorizeOpenWrtRootLocked(activation.Locks, activation.State.Root, false); err != nil {
		return openwrt.CheckResult{}, errors.Join(err, lock.Unlock())
	}
	active, err := activation.loadActiveGatewayState()
	if err != nil {
		return openwrt.CheckResult{}, errors.Join(fmt.Errorf("load active gateway generation: %w", err), lock.Unlock())
	}
	plan, err := activation.refreshActiveGatewayPlan(ctx, active)
	if err != nil {
		return openwrt.CheckResult{}, errors.Join(err, lock.Unlock())
	}
	result, diagnoseErr := activation.gateway.Check(ctx, plan)
	return result, errors.Join(diagnoseErr, lock.Unlock())
}

// withTransaction serializes the nftables, policy-route, and dnsmasq ownership
// transaction both inside the daemon and across one-shot hotplug/cleanup
// processes. The lock uses a host-global namespace independent of the selected
// data root and is context-aware.
func (activation *OpenWrtActivation) withTransaction(ctx context.Context, claimMissingOwner bool, callback func() error) error {
	activation.mu.Lock()
	defer activation.mu.Unlock()
	return activation.Locks.WithLock(ctx, "gateway-dns", func() error {
		if err := authorizeOpenWrtRootLocked(activation.Locks, activation.State.Root, claimMissingOwner); err != nil {
			return err
		}
		return callback()
	})
}

func (activation *OpenWrtActivation) rollbackLocked(_ context.Context, plan openwrt.GatewayPlan, backup openwrt.DNSBackup) error {
	// Apply commonly fails because its context was canceled or timed out. Use a
	// fresh bounded context so fail-open cleanup still gets a real opportunity.
	cleanupContext, cancel := context.WithTimeout(context.Background(), openWrtRollbackTimeout)
	defer cancel()
	restoreErr := activation.dns.Restore(cleanupContext, backup)
	var removeErr error
	if restoreErr == nil {
		removeErr = activation.removeDNSBackup()
	}
	gatewayErr := activation.gateway.Cleanup(cleanupContext, plan)
	joined := errors.Join(gatewayErr, restoreErr, removeErr)
	if joined == nil {
		joined = activation.removeActiveGatewayState()
	}
	if joined == nil {
		activation.lastPlan = nil
	}
	return joined
}

func (activation *OpenWrtActivation) buildPlan(ctx context.Context, prepared engine.PreparedCore) (openwrt.GatewayPlan, error) {
	plan, _, err := activation.buildPlanAndState(ctx, prepared)
	return plan, err
}

func (activation *OpenWrtActivation) buildPlanAndState(ctx context.Context, prepared engine.PreparedCore) (openwrt.GatewayPlan, activeGatewayState, error) {
	settings, err := LoadRuntimeSettings(activation.State)
	if err != nil {
		return openwrt.GatewayPlan{}, activeGatewayState{}, err
	}
	var discovered openwrt.InterfaceDiscovery
	needsLAN := settings.InterfaceMode == "explicit" && len(settings.Included) == 0 && settings.AutoDetectLAN
	needsWAN := settings.InterfaceMode == "exclude" && settings.AutoDetectWAN
	if needsLAN || needsWAN {
		discovered, err = activation.gateway.Detect(ctx)
		if err != nil {
			return openwrt.GatewayPlan{}, activeGatewayState{}, err
		}
	}
	plan, err := settings.GatewayPlan(prepared.Capture, discovered)
	if err != nil {
		return openwrt.GatewayPlan{}, activeGatewayState{}, err
	}
	active := activeGatewayState{
		Version: activeGatewayStateVersion, Engine: prepared.Engine,
		Controller: prepared.Controller, Capture: cloneCapturePlan(prepared.Capture), Plan: plan,
		AutoDetectLAN: needsLAN, AutoDetectWAN: needsWAN,
		StaticExcluded: append([]string(nil), settings.Excluded...),
	}
	return plan, active, nil
}

// ActivePrepared returns only the immutable live-generation fields required by
// hotplug readiness checks and gateway reconciliation. Disk configuration may
// already contain a newer generation which the daemon has not activated.
func (activation *OpenWrtActivation) ActivePrepared(ctx context.Context) (engine.PreparedCore, error) {
	if err := ctx.Err(); err != nil {
		return engine.PreparedCore{}, err
	}
	active, err := activation.loadActiveGatewayState()
	if err != nil {
		return engine.PreparedCore{}, fmt.Errorf("load active gateway generation: %w", err)
	}
	return engine.PreparedCore{
		Engine: active.Engine, Controller: active.Controller,
		Capture: cloneCapturePlan(active.Capture),
	}, nil
}

func (activation *OpenWrtActivation) refreshActiveGatewayPlan(ctx context.Context, active activeGatewayState) (openwrt.GatewayPlan, error) {
	plan := active.Plan
	if !active.AutoDetectLAN && !active.AutoDetectWAN {
		return plan, openwrt.Validate(plan)
	}
	discovered, err := activation.gateway.Detect(ctx)
	if err != nil {
		return openwrt.GatewayPlan{}, err
	}
	if active.AutoDetectLAN {
		plan.IncludeInterfaces = append([]string(nil), discovered.LANInterfaces...)
		if len(plan.IncludeInterfaces) == 0 {
			return openwrt.GatewayPlan{}, errors.New("active gateway generation cannot identify LAN")
		}
	}
	if active.AutoDetectWAN {
		plan.ExcludeInterfaces = append(append([]string(nil), active.StaticExcluded...), discovered.WANInterfaces...)
		if len(discovered.WANInterfaces) == 0 {
			return openwrt.GatewayPlan{}, errors.New("active gateway generation cannot identify WAN")
		}
	}
	return plan, openwrt.Validate(plan)
}

func (activation *OpenWrtActivation) saveActiveGatewayState(active activeGatewayState) error {
	if err := validateActiveGatewayState(active); err != nil {
		return err
	}
	return activation.State.WriteJSON(activeGatewayStatePath, active, 0o600)
}

func (activation *OpenWrtActivation) loadActiveGatewayState() (activeGatewayState, error) {
	content, err := activation.State.Read(activeGatewayStatePath)
	if err != nil {
		return activeGatewayState{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var active activeGatewayState
	if err := decoder.Decode(&active); err != nil {
		return activeGatewayState{}, fmt.Errorf("decode active gateway generation: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return activeGatewayState{}, errors.New("decode active gateway generation: trailing data")
	}
	if err := validateActiveGatewayState(active); err != nil {
		return activeGatewayState{}, err
	}
	return active, nil
}

func (activation *OpenWrtActivation) removeActiveGatewayState() error {
	return activation.State.RemoveRegular(activeGatewayStatePath)
}

func validateActiveGatewayState(active activeGatewayState) error {
	if active.Version != activeGatewayStateVersion {
		return fmt.Errorf("unsupported active gateway generation version %d", active.Version)
	}
	if active.Engine != state.EngineMihomo {
		return fmt.Errorf("active gateway generation has unsupported engine %q", active.Engine)
	}
	if err := active.Capture.Validate(); err != nil {
		return fmt.Errorf("invalid active capture generation: %w", err)
	}
	if err := openwrt.Validate(active.Plan); err != nil {
		return fmt.Errorf("invalid active gateway plan: %w", err)
	}
	if active.Plan.TUNDevice != active.Capture.TUNDevice || active.Plan.LoopMark != active.Capture.LoopMark {
		return errors.New("active gateway plan does not match its capture generation")
	}
	if _, err := engine.NewMihomoController(active.Controller, nil); err != nil {
		return fmt.Errorf("invalid active controller generation: %w", err)
	}
	return nil
}

func (activation *OpenWrtActivation) planForCleanup(ctx context.Context, prepared engine.PreparedCore) (openwrt.GatewayPlan, error) {
	if activation.lastPlan != nil {
		return *activation.lastPlan, nil
	}
	if active, err := activation.loadActiveGatewayState(); err == nil {
		// Cleanup must use the last successfully applied interface set. Re-running
		// discovery during a WAN outage can fail precisely when fail-open removal
		// is most important, while nft/policy ownership does not require a fresh
		// topology snapshot.
		return active.Plan, nil
	}
	if plan, err := activation.buildPlan(ctx, prepared); err == nil {
		return plan, nil
	}
	settings, err := LoadRuntimeSettings(activation.State)
	mode := openwrt.ModeTPROXY
	dnsMode := openwrt.DNSDisabled
	if err == nil {
		mode = settings.CaptureMode
		dnsMode = settings.DNSMode
	}
	// Cleanup needs stable ownership/table/mark identifiers, not an interface
	// match or valid current settings. This fallback lets a WAN topology outage
	// or a manually corrupted settings file fail open safely.
	plan := openwrt.DefaultGatewayPlan(mode)
	plan.DNSMode = dnsMode
	plan.TUNDevice = prepared.Capture.TUNDevice
	if plan.TUNDevice == "" {
		plan.TUNDevice = "clash-tun"
	}
	if prepared.Capture.LoopMark != 0 {
		plan.LoopMark = prepared.Capture.LoopMark
	}
	return plan, openwrt.Validate(plan)
}

func (activation *OpenWrtActivation) ensureDNSBackup(ctx context.Context) (openwrt.DNSBackup, bool, error) {
	backup, err := activation.loadDNSBackup()
	if err == nil {
		return backup, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return openwrt.DNSBackup{}, false, err
	}
	backup, err = activation.dns.Backup(ctx)
	if err != nil {
		return openwrt.DNSBackup{}, false, err
	}
	relative, err := filepath.Rel(activation.Layout.Root, activation.Layout.DNSBackup)
	if err != nil {
		return openwrt.DNSBackup{}, false, err
	}
	if err := activation.State.WriteJSON(relative, backup, 0o600); err != nil {
		return openwrt.DNSBackup{}, false, err
	}
	return backup, true, nil
}

func (activation *OpenWrtActivation) loadDNSBackup() (openwrt.DNSBackup, error) {
	relative, err := filepath.Rel(activation.Layout.Root, activation.Layout.DNSBackup)
	if err != nil {
		return openwrt.DNSBackup{}, err
	}
	content, err := activation.State.Read(relative)
	if err != nil {
		return openwrt.DNSBackup{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var backup openwrt.DNSBackup
	if err := decoder.Decode(&backup); err != nil {
		return openwrt.DNSBackup{}, fmt.Errorf("decode DNS backup: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return openwrt.DNSBackup{}, errors.New("decode DNS backup: trailing data")
	}
	return backup, nil
}

func (activation *OpenWrtActivation) removeDNSBackup() error {
	info, err := os.Lstat(activation.Layout.DNSBackup)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("refusing to remove non-regular DNS backup")
	}
	return os.Remove(activation.Layout.DNSBackup)
}
