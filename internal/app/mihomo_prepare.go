package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	configpkg "github.com/kontsevoye/boxctl/internal/config"
	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
)

const defaultMihomoControllerListen = "127.0.0.1:9090"

var errMihomoBinaryNotInstalled = errors.New("mihomo binary is not installed")

func tmpfsRuleProviderPath() string {
	return filepath.Join(os.TempDir(), "boxctl-rule-providers")
}

// ActiveMihomoPreparer resolves the boxctl layout, reads only managed
// values from the selected native YAML, and asks the driver to create a private
// validated runtime copy. It never writes config.yaml.
type ActiveMihomoPreparer struct {
	Layout        state.Layout
	Profiles      state.ProfileStore
	State         state.Store
	Config        engine.Config
	RuntimeDir    string
	FakeIP        *FakeIPCaptureManager
	Subscriptions *ProxySubscriptionsService
	Endpoints     *EndpointBypassManager
	Identity      *DeviceIdentity
	// BinaryOverride is used only for validating a staged update. Normal daemon
	// construction leaves it empty and resolves the configured layout.
	BinaryOverride string
}

func NewActiveMihomoPreparer(root string, driver engine.Config) (*ActiveMihomoPreparer, error) {
	layout, err := state.NewLayout(root)
	if err != nil {
		return nil, err
	}
	profiles, err := state.NewProfileStore(layout.Root)
	if err != nil {
		return nil, err
	}
	store, err := state.NewStore(layout.Root)
	if err != nil {
		return nil, err
	}
	return &ActiveMihomoPreparer{
		Layout: layout, Profiles: profiles, State: store, Config: driver,
		FakeIP: NewFakeIPCaptureManager(layout), Endpoints: NewEndpointBypassManager(layout, store),
		Identity: NewDeviceIdentity(store),
		// RuntimeDir is a base for os.MkdirTemp, not a shared runtime
		// directory. The engine creates a new mode-0700 private root below it
		// for every prepared configuration.
		RuntimeDir: os.TempDir(),
	}, nil
}

func (preparer *ActiveMihomoPreparer) PrepareActive(ctx context.Context) (engine.PreparedCore, error) {
	if preparer == nil || preparer.Config == nil {
		return engine.PreparedCore{}, errors.New("mihomo preparer is not initialized")
	}
	active, activeErr := preparer.Profiles.Current()
	if activeErr != nil && !errors.Is(activeErr, fs.ErrNotExist) {
		return engine.PreparedCore{}, fmt.Errorf("read active profile: %w", activeErr)
	}
	if activeErr == nil && active.Engine != "" && active.Engine != state.EngineMihomo {
		return engine.PreparedCore{}, fmt.Errorf("%w: active engine %q has no v1 driver", engine.ErrUnsupported, active.Engine)
	}

	sourcePath, err := preparer.sourcePath(active, activeErr)
	if err != nil {
		return engine.PreparedCore{}, err
	}
	source, err := readBoundedRegular(sourcePath, 32<<20)
	if err != nil {
		return engine.PreparedCore{}, fmt.Errorf("read active Mihomo profile: %w", err)
	}
	managed, err := configpkg.InspectMihomo(source)
	if err != nil {
		return engine.PreparedCore{}, fmt.Errorf("inspect active Mihomo profile: %w", err)
	}
	runtimeSettings, err := LoadRuntimeSettings(preparer.State)
	if err != nil {
		return engine.PreparedCore{}, fmt.Errorf("load runtime settings: %w", err)
	}
	managedSettings, err := managedRuntimeSettings(managed)
	if err != nil {
		return engine.PreparedCore{}, err
	}
	if managedSettings.DNSFakeIP {
		fakeIPManager := preparer.FakeIP
		if fakeIPManager == nil {
			fakeIPManager = NewFakeIPCaptureManager(preparer.Layout)
		}
		policy, policyErr := fakeIPManager.PrepareWithOptions(source, runtimeSettings.AutoFakeIP, FakeIPCaptureOptions{
			IncludeExternalIPProviders: runtimeSettings.AutoFakeIPIncludeExternalIPProviders,
		})
		if policyErr != nil {
			return engine.PreparedCore{}, fmt.Errorf("prepare fake-IP destination policy: %w", policyErr)
		}
		managedSettings.DNSFakeIP = policy.Selective
		managedSettings.FakeIPFilterMode = policy.FilterMode
		managedSettings.FakeIPRanges = append([]netip.Prefix(nil), policy.FakeIPRanges...)
		managedSettings.AdditionalCaptureCIDRs = append([]netip.Prefix(nil), policy.Document.Effective...)
	}
	capture, err := runtimeSettings.CapturePlan(managedSettings)
	if err != nil {
		return engine.PreparedCore{}, err
	}
	runtimeSource := source
	if preparer.Subscriptions != nil {
		providers, providerErr := preparer.Subscriptions.EnabledProviderSpecs()
		if providerErr != nil {
			return engine.PreparedCore{}, fmt.Errorf("load proxy subscriptions: %w", providerErr)
		}
		if len(providers) > 0 {
			runtimeSource, err = configpkg.InjectMihomoProxyProviders(source, providers)
			if err != nil {
				return engine.PreparedCore{}, fmt.Errorf("inject proxy subscriptions: %w", err)
			}
		}
	}
	runtimeSource, err = preparer.applyRuntimeProviderSettings(ctx, runtimeSource, runtimeSettings, true)
	if err != nil {
		return engine.PreparedCore{}, err
	}
	endpointManager := preparer.Endpoints
	if endpointManager == nil {
		endpointManager = NewEndpointBypassManager(preparer.Layout, preparer.State)
	}
	capture.EndpointBypassCIDRs, err = endpointManager.Prepare(ctx, runtimeSource)
	if err != nil {
		return engine.PreparedCore{}, fmt.Errorf("prepare endpoint bypass policy: %w", err)
	}
	controller := managedMihomoController(managed)
	binaryPath, err := preparer.binaryPath()
	if err != nil {
		return engine.PreparedCore{}, err
	}
	runtimeDir := preparer.RuntimeDir
	if runtimeDir == "" {
		runtimeDir = os.TempDir()
	}
	driverSourcePath := sourcePath
	if !bytes.Equal(runtimeSource, source) {
		temporary, createErr := os.CreateTemp(runtimeDir, "boxctl-subscriptions-*.yaml")
		if createErr != nil {
			return engine.PreparedCore{}, fmt.Errorf("create subscription config: %w", createErr)
		}
		driverSourcePath = temporary.Name()
		defer os.Remove(driverSourcePath)
		if chmodErr := temporary.Chmod(0o600); chmodErr != nil {
			_ = temporary.Close()
			return engine.PreparedCore{}, chmodErr
		}
		if _, writeErr := temporary.Write(runtimeSource); writeErr != nil {
			_ = temporary.Close()
			return engine.PreparedCore{}, writeErr
		}
		if closeErr := temporary.Close(); closeErr != nil {
			return engine.PreparedCore{}, closeErr
		}
	}
	prepared, err := preparer.Config.Prepare(ctx, engine.PrepareRequest{
		BinaryPath:       binaryPath,
		SourceConfigPath: driverSourcePath,
		RuntimeDir:       runtimeDir,
		HomeDir:          preparer.Layout.Root,
		Capture:          capture,
		Controller:       controller,
	})
	if err == nil {
		prepared.SourceConfigPath = sourcePath
	}
	return prepared, err
}

func (preparer *ActiveMihomoPreparer) applyRuntimeProviderSettings(ctx context.Context, source []byte, settings RuntimeSettings, copyExisting bool) ([]byte, error) {
	runtimeSource := source
	if settings.EnableHWID {
		identity := preparer.Identity
		if identity == nil {
			identity = NewDeviceIdentity(preparer.State)
		}
		headers, err := identity.Headers(ctx)
		if err != nil {
			return nil, fmt.Errorf("prepare proxy-provider device headers: %w", err)
		}
		runtimeSource, err = configpkg.InjectMihomoProxyProviderHeaders(runtimeSource, headers)
		if err != nil {
			return nil, fmt.Errorf("inject proxy-provider device headers: %w", err)
		}
	}
	if !settings.UseTmpfsRules {
		return runtimeSource, nil
	}
	runtimeDirectory, err := preparer.tmpfsRuleProviderDirectory()
	if err != nil {
		return nil, fmt.Errorf("prepare tmpfs rule-provider directory: %w", err)
	}
	runtimeSource, relocations, err := configpkg.RelocateMihomoHTTPRuleProviders(runtimeSource, runtimeDirectory)
	if err != nil {
		return nil, fmt.Errorf("relocate HTTP rule providers to tmpfs: %w", err)
	}
	if copyExisting {
		for _, relocation := range relocations {
			// A deterministic runtime path can survive a daemon restart. Clear it
			// before looking for a seed so a missing/renamed persistent cache can
			// never make Mihomo consume bytes left by an earlier generation.
			if err := preparer.removeExistingProviderRuntime(relocation.RuntimePath); err != nil {
				return nil, fmt.Errorf("reset tmpfs rule provider %q: %w", relocation.Name, err)
			}
			sourcePath := relocation.ConfiguredPath
			if strings.TrimSpace(sourcePath) == "" && relocation.MihomoCacheName != "" {
				sourcePath = filepath.Join("rules", relocation.MihomoCacheName)
			}
			if err := preparer.copyExistingProviderCache(sourcePath, relocation.RuntimePath); err != nil {
				return nil, fmt.Errorf("seed tmpfs rule provider %q: %w", relocation.Name, err)
			}
		}
	}
	return runtimeSource, nil
}

func (preparer *ActiveMihomoPreparer) tmpfsRuleProviderDirectory() (string, error) {
	base := tmpfsRuleProviderPath()
	if err := os.Mkdir(base, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	info, err := os.Lstat(base)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		if err != nil {
			return "", err
		}
		return "", errors.New("tmpfs rule-provider path is not a private directory")
	}
	if err := os.Chmod(base, 0o700); err != nil {
		return "", err
	}
	// The common tmpfs root is trusted by fake-IP provider parsing, but cache
	// files from separate boxctl state roots must not share a namespace.
	digest := sha256.Sum256([]byte(filepath.Clean(preparer.Layout.Root)))
	runtimeDirectory := filepath.Join(base, hex.EncodeToString(digest[:8]))
	if err := os.Mkdir(runtimeDirectory, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	info, err = os.Lstat(runtimeDirectory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		if err != nil {
			return "", err
		}
		return "", errors.New("tmpfs rule-provider state path is not a private directory")
	}
	if err := os.Chmod(runtimeDirectory, 0o700); err != nil {
		return "", err
	}
	return runtimeDirectory, nil
}

func (preparer *ActiveMihomoPreparer) removeExistingProviderRuntime(runtimePath string) error {
	if _, err := preparer.validateProviderRuntimeTarget(runtimePath); err != nil {
		return err
	}
	info, err := os.Lstat(runtimePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("tmpfs rule-provider target is not a regular file")
	}
	return os.Remove(runtimePath)
}

func (preparer *ActiveMihomoPreparer) validateProviderRuntimeTarget(runtimePath string) (string, error) {
	targetDirectory := filepath.Dir(filepath.Clean(runtimePath))
	expected, err := preparer.tmpfsRuleProviderDirectory()
	if err != nil {
		return "", err
	}
	if targetDirectory != filepath.Clean(expected) {
		return "", errors.New("invalid tmpfs rule-provider target")
	}
	return targetDirectory, nil
}

func (preparer *ActiveMihomoPreparer) copyExistingProviderCache(configuredPath, runtimePath string) error {
	configuredPath = strings.TrimSpace(configuredPath)
	if configuredPath == "" {
		return nil
	}
	sourcePath := filepath.Clean(configuredPath)
	if !filepath.IsAbs(sourcePath) {
		sourcePath = filepath.Join(preparer.Layout.Root, sourcePath)
	}
	withinRoot, err := filepath.Rel(preparer.Layout.Root, sourcePath)
	if err != nil || withinRoot == ".." || strings.HasPrefix(withinRoot, ".."+string(filepath.Separator)) {
		// An external cache path is valid Mihomo configuration, but boxctl never
		// reads outside its own state root. Mihomo can refresh the relocated cache.
		return nil
	}
	if err := rejectSymlinkComponents(preparer.Layout.Root, sourcePath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	content, err := readBoundedRegular(sourcePath, 64<<20)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	targetDirectory, err := preparer.validateProviderRuntimeTarget(runtimePath)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(targetDirectory, ".provider-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, runtimePath)
}

func rejectSymlinkComponents(root, candidate string) error {
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("provider cache escapes the state root")
	}
	current := filepath.Clean(root)
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("provider cache path contains a symbolic link")
		}
	}
	return nil
}

func managedMihomoController(managed configpkg.MihomoManagedValues) engine.ControllerEndpoint {
	controller := engine.ControllerEndpoint{Listen: defaultMihomoControllerListen}
	if managed.ExternalController != nil && strings.TrimSpace(*managed.ExternalController) != "" {
		listen := strings.TrimSpace(*managed.ExternalController)
		if _, port, err := net.SplitHostPort(listen); err == nil && port != "" {
			// config.yaml remains user-owned, but the generated runtime copy must
			// never expose the management API to the LAN. Preserve only the
			// configured port; authentication is defense in depth, not a reason
			// to bind the controller publicly.
			listen = net.JoinHostPort("127.0.0.1", port)
		}
		controller.Listen = listen
	}
	if managed.Secret != nil {
		controller.Secret = managed.Secret.Reveal()
	}
	return controller
}

func (preparer *ActiveMihomoPreparer) sourcePath(active state.ActiveProfile, activeErr error) (string, error) {
	if info, err := os.Lstat(preparer.Layout.MihomoConfig); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", errors.New("active Mihomo config is not a regular file")
		}
		return preparer.Layout.MihomoConfig, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if activeErr == nil && active.Name != "" {
		entries, err := preparer.Profiles.List()
		if err != nil {
			return "", err
		}
		for _, entry := range entries {
			if entry.ActiveProfile == active {
				return entry.Path, nil
			}
		}
	}
	return "", fs.ErrNotExist
}

func (preparer *ActiveMihomoPreparer) binaryPath() (string, error) {
	if preparer.BinaryOverride != "" {
		if err := validateMihomoBinaryPath(preparer.BinaryOverride); err != nil {
			return "", err
		}
		return preparer.BinaryOverride, nil
	}
	candidate := filepath.Join(preparer.Layout.EnginesDir, "mihomo", "mihomo")
	if err := validateMihomoBinaryPath(candidate); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", errMihomoBinaryNotInstalled
		}
		return "", err
	}
	return candidate, nil
}

func validateMihomoBinaryPath(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("mihomo binary is not a regular executable: %s", path)
	}
	return nil
}

func readBoundedRegular(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("path is not a regular file")
	}
	if info.Size() > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	return os.ReadFile(path)
}

func managedRuntimeSettings(values configpkg.MihomoManagedValues) (ManagedMihomoSettings, error) {
	result := ManagedMihomoSettings{}
	if values.TProxyPort != nil {
		result.TProxyPort = *values.TProxyPort
	}
	if values.RedirectPort != nil {
		result.RedirectPort = *values.RedirectPort
	}
	if values.RoutingMark != nil {
		result.LoopMark = *values.RoutingMark
	}
	if values.TUNDevice != nil {
		result.TUNDevice = strings.TrimSpace(*values.TUNDevice)
	}
	if values.TUNStack != nil {
		result.TUNStack = strings.TrimSpace(*values.TUNStack)
	}
	if values.DNSListen != nil {
		_, port, err := parseListenPort(*values.DNSListen)
		if err != nil {
			return ManagedMihomoSettings{}, fmt.Errorf("parse Mihomo DNS listen: %w", err)
		}
		result.DNSPort = port
	}
	dnsEnabled := values.DNSEnabled != nil && *values.DNSEnabled
	result.DNSFakeIP = dnsEnabled && values.DNSEnhancedMode != nil && strings.EqualFold(strings.TrimSpace(*values.DNSEnhancedMode), "fake-ip")
	if values.DNSFakeIPFilterMode != nil {
		result.FakeIPFilterMode = strings.ToLower(strings.TrimSpace(*values.DNSFakeIPFilterMode))
	}
	if result.DNSFakeIP {
		fakeIPRange := defaultMihomoFakeIPRange
		if values.DNSFakeIPRange != nil && strings.TrimSpace(*values.DNSFakeIPRange) != "" {
			fakeIPRange = strings.TrimSpace(*values.DNSFakeIPRange)
		}
		prefix, err := netip.ParsePrefix(fakeIPRange)
		if err != nil {
			return ManagedMihomoSettings{}, fmt.Errorf("parse Mihomo fake-IP range: %w", err)
		}
		if !prefix.Addr().Is4() {
			return ManagedMihomoSettings{}, errors.New("mihomo fake-IP range must be IPv4")
		}
		result.FakeIPRanges = []netip.Prefix{prefix.Masked()}
	}
	return result, nil
}

func parseListenPort(value string) (string, uint16, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, ":") {
		value = "0.0.0.0" + value
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("invalid port %q", portText)
	}
	return host, uint16(port), nil
}
