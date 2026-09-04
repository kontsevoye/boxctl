package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/platform/openwrt"
	"github.com/kontsevoye/boxctl/internal/state"
)

const (
	singBoxControllerStatePath = ".boxctl/sing-box-controller-secret"
	defaultSingBoxController   = "127.0.0.1:9090"
	defaultSingBoxTUNDevice    = "sing-box-tun"
)

var singBoxVersionLine = regexp.MustCompile(`(?m)^sing-box version (1\.14\.[0-9]+)(?:\s|$)`)

// ActiveSingBoxPreparer turns a selected native JSON/JSONC profile into a
// private, checked runtime generation. Capture listeners, route marks and the
// loopback Clash API remain manager-owned and never alter the source profile.
type ActiveSingBoxPreparer struct {
	Layout     state.Layout
	Profiles   state.ProfileStore
	State      state.Store
	Config     engine.Config
	RuntimeDir string
	Endpoints  *EndpointBypassManager
	// BinaryOverride is used only while a verified staged update is preflighted.
	BinaryOverride string
	// ControllerSecretOverride keeps read-only validation paths from creating
	// manager state. Production runtime preparation leaves it empty.
	ControllerSecretOverride string
	Version                  interface {
		Version(context.Context, string) (string, error)
	}
}

func NewActiveSingBoxPreparer(root string, driver engine.Config) (*ActiveSingBoxPreparer, error) {
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
	preparer := &ActiveSingBoxPreparer{
		Layout: layout, Profiles: profiles, State: store, Config: driver,
		RuntimeDir: os.TempDir(), Endpoints: NewEndpointBypassManager(layout, store),
	}
	if version, ok := driver.(interface {
		Version(context.Context, string) (string, error)
	}); ok {
		preparer.Version = version
	}
	return preparer, nil
}

func (preparer *ActiveSingBoxPreparer) PrepareActive(ctx context.Context) (engine.PreparedCore, error) {
	if preparer == nil || preparer.Config == nil {
		return engine.PreparedCore{}, errors.New("sing-box preparer is not initialized")
	}
	active, err := preparer.Profiles.Current()
	if err != nil {
		return engine.PreparedCore{}, fmt.Errorf("read active profile: %w", err)
	}
	return preparer.prepareProfile(ctx, active, true)
}

func (preparer *ActiveSingBoxPreparer) PrepareProfile(ctx context.Context, profile state.ActiveProfile) (engine.PreparedCore, error) {
	return preparer.prepareProfile(ctx, profile, false)
}

func (preparer *ActiveSingBoxPreparer) prepareProfile(ctx context.Context, profile state.ActiveProfile, persistEndpoints bool) (engine.PreparedCore, error) {
	if preparer == nil || preparer.Config == nil {
		return engine.PreparedCore{}, errors.New("sing-box preparer is not initialized")
	}
	if profile.Engine != state.EngineSingBox {
		return engine.PreparedCore{}, fmt.Errorf("%w: profile engine %q is not sing-box", engine.ErrUnsupported, profile.Engine)
	}
	entries, err := preparer.Profiles.List()
	if err != nil {
		return engine.PreparedCore{}, err
	}
	for _, entry := range entries {
		if entry.ActiveProfile == profile {
			return preparer.prepareSource(ctx, entry.Path, persistEndpoints)
		}
	}
	return engine.PreparedCore{}, fs.ErrNotExist
}

func (preparer *ActiveSingBoxPreparer) ValidateContent(ctx context.Context, content []byte) error {
	if err := validateRawDocument(string(content)); err != nil {
		return err
	}
	runtimeDir := preparer.RuntimeDir
	if runtimeDir == "" {
		runtimeDir = os.TempDir()
	}
	temporary, err := os.CreateTemp(runtimeDir, "boxctl-sing-box-source-*.json")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer os.Remove(path)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	prepared, err := preparer.prepareSource(ctx, path, false)
	engine.CleanupPreparedRuntime(prepared)
	return err
}

func (preparer *ActiveSingBoxPreparer) prepareSource(ctx context.Context, sourcePath string, persistEndpoints bool) (engine.PreparedCore, error) {
	source, err := readBoundedRegular(sourcePath, 32<<20)
	if err != nil {
		return engine.PreparedCore{}, fmt.Errorf("read sing-box profile: %w", err)
	}
	settings, err := LoadRuntimeSettings(preparer.State)
	if err != nil {
		return engine.PreparedCore{}, fmt.Errorf("load runtime settings: %w", err)
	}
	capture, err := settings.CapturePlan(ManagedMihomoSettings{
		TUNDevice: defaultSingBoxTUNDevice, TUNStack: settings.TUNStack, LoopMark: 2,
	})
	if err != nil {
		return engine.PreparedCore{}, err
	}
	if capture.TCP.Method == engine.CaptureTUN || capture.UDP.Method == engine.CaptureTUN {
		capture.TUNAddresses = []netip.Prefix{settings.TUNAddress}
		capture.TUNMTU = settings.TUNMTU
	}
	binary := preparer.BinaryOverride
	if binary == "" {
		binary, _, err = resolveSingBoxBinary(preparer.Layout)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return engine.PreparedCore{}, errors.New("sing-box binary is not installed")
			}
			return engine.PreparedCore{}, err
		}
	}
	if preparer.Version != nil {
		versionOutput, versionErr := preparer.Version.Version(ctx, binary)
		if versionErr != nil {
			return engine.PreparedCore{}, versionErr
		}
		if !singBoxVersionLine.MatchString(versionOutput) {
			return engine.PreparedCore{}, errors.New("unsupported sing-box version; require >=1.14.0,<1.15.0")
		}
	}
	secret, err := preparer.controllerSecret(ctx)
	if err != nil {
		return engine.PreparedCore{}, fmt.Errorf("load sing-box controller secret: %w", err)
	}
	runtimeDir := preparer.RuntimeDir
	if runtimeDir == "" {
		runtimeDir = os.TempDir()
	}
	driverSourcePath, err := writeConfigSnapshot(runtimeDir, "boxctl-sing-box-source-*.json", source)
	if err != nil {
		return engine.PreparedCore{}, err
	}
	defer os.Remove(driverSourcePath)
	prepared, err := preparer.Config.Prepare(ctx, engine.PrepareRequest{
		BinaryPath: binary, SourceConfigPath: driverSourcePath, RuntimeDir: runtimeDir,
		HomeDir: preparer.Layout.Root, Capture: capture,
		Controller: engine.ControllerEndpoint{Listen: defaultSingBoxController, Secret: secret},
	})
	if err != nil {
		return engine.PreparedCore{}, err
	}
	prepared.SourceConfigPath = sourcePath
	prepared.SourceRevision = contentRevision(source)
	runtimeContent, err := readBoundedRegular(prepared.RuntimeConfigPath, 32<<20)
	if err != nil {
		engine.CleanupPreparedRuntime(prepared)
		return engine.PreparedCore{}, err
	}
	if settings.DNSMode == openwrt.DNSUpstream {
		if err := validateSingBoxUpstreamDNS(runtimeContent, prepared.Capture.DNS.Port); err != nil {
			engine.CleanupPreparedRuntime(prepared)
			return engine.PreparedCore{}, err
		}
	}
	endpointManager := preparer.Endpoints
	if endpointManager == nil {
		endpointManager = NewEndpointBypassManager(preparer.Layout, preparer.State)
	}
	prepared.Capture.EndpointBypassCIDRs, err = endpointManager.PrepareSingBox(ctx, runtimeContent, persistEndpoints)
	if err != nil {
		engine.CleanupPreparedRuntime(prepared)
		return engine.PreparedCore{}, fmt.Errorf("prepare sing-box endpoint bypass policy: %w", err)
	}
	return prepared, nil
}

// validateSingBoxUpstreamDNS prevents the OpenWrt upstream mode from creating
// a resolver cycle. In that mode dnsmasq forwards to the manager-owned
// sing-box listener, so sing-box cannot safely fall back to the system/local
// resolver (normally dnsmasq itself on OpenWrt). The post-activation lifecycle
// probe remains the final check for topology-dependent cycles that static JSON
// inspection cannot identify.
func validateSingBoxUpstreamDNS(content []byte, managedPort uint16) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("inspect sing-box DNS configuration: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return fmt.Errorf("inspect sing-box DNS configuration: %w", err)
	}
	dns, ok := document["dns"].(map[string]any)
	if !ok {
		return errors.New("sing-box DNS upstream mode requires explicit dns.servers; implicit local resolution would recurse through OpenWrt dnsmasq")
	}
	servers, ok := dns["servers"].([]any)
	if !ok || len(servers) == 0 {
		return errors.New("sing-box DNS upstream mode requires at least one explicit DNS server")
	}
	serverByTag := make(map[string]map[string]any, len(servers))
	var firstServer map[string]any
	for index, raw := range servers {
		server, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("sing-box DNS server %d is not an object", index)
		}
		if index == 0 {
			firstServer = server
		}
		if tag, _ := server["tag"].(string); tag != "" {
			serverByTag[tag] = server
		}
		serverType, _ := server["type"].(string)
		serverType = strings.ToLower(strings.TrimSpace(serverType))
		if serverType == "local" || serverType == "resolved" {
			return fmt.Errorf("sing-box DNS server %d uses system resolver type %q which would recurse through OpenWrt dnsmasq", index, serverType)
		}
		switch serverType {
		case "udp", "tcp", "tls", "quic", "https", "h3":
			address, _ := server["server"].(string)
			address = strings.TrimSpace(address)
			port := singBoxDNSServerPort(serverType, server["server_port"])
			if strings.EqualFold(address, "localhost") && (port == 53 || port == managedPort) {
				return fmt.Errorf("sing-box DNS server %d points back to a local managed resolver", index)
			}
			parsedAddress := strings.TrimSuffix(strings.TrimPrefix(address, "["), "]")
			if zone := strings.LastIndexByte(parsedAddress, '%'); zone >= 0 {
				parsedAddress = parsedAddress[:zone]
			}
			if ip, parseErr := netip.ParseAddr(parsedAddress); parseErr == nil {
				if ip.IsUnspecified() || (ip.IsLoopback() && (port == 53 || port == managedPort)) {
					return fmt.Errorf("sing-box DNS server %d points back to a local managed resolver", index)
				}
			}
		}
	}
	finalServer := firstServer
	finalTag, _ := dns["final"].(string)
	if finalTag != "" {
		finalServer = serverByTag[finalTag]
	}
	if finalServer == nil || !singBoxDNSProvidesGeneralResolution(finalServer) {
		finalType, _ := finalServer["type"].(string)
		if finalType == "" {
			finalType = "legacy or unknown"
		}
		return fmt.Errorf("sing-box DNS upstream mode requires a recursive default server; final server type %q only provides scoped or synthetic answers", finalType)
	}
	return nil
}

func singBoxDNSProvidesGeneralResolution(server map[string]any) bool {
	serverType, _ := server["type"].(string)
	switch strings.ToLower(strings.TrimSpace(serverType)) {
	case "udp", "tcp", "tls", "quic", "https", "h3", "dhcp":
		return true
	case "tailscale":
		accepted, _ := server["accept_default_resolvers"].(bool)
		return accepted
	default:
		return false
	}
}

func singBoxDNSServerPort(serverType string, raw any) uint16 {
	defaultPort := uint16(53)
	switch serverType {
	case "tls", "quic":
		defaultPort = 853
	case "https", "h3":
		defaultPort = 443
	}
	number, ok := raw.(json.Number)
	if !ok {
		return defaultPort
	}
	parsed, err := strconv.ParseUint(number.String(), 10, 16)
	if err != nil || parsed == 0 {
		return defaultPort
	}
	return uint16(parsed)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("configuration contains trailing JSON data")
		}
		return err
	}
	return nil
}

func (preparer *ActiveSingBoxPreparer) controllerSecret(ctx context.Context) (string, error) {
	if preparer.ControllerSecretOverride != "" {
		if err := validateSingBoxControllerSecret(preparer.ControllerSecretOverride); err != nil {
			return "", err
		}
		return preparer.ControllerSecretOverride, nil
	}
	var secret string
	err := preparer.State.WithLock(ctx, "sing-box-controller-secret", func() error {
		content, err := preparer.State.Read(singBoxControllerStatePath)
		if err == nil {
			info, statErr := os.Lstat(filepath.Join(preparer.Layout.Root, filepath.FromSlash(singBoxControllerStatePath)))
			if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
				return errors.New("sing-box controller secret is not a private regular file")
			}
			secret = strings.TrimSpace(string(content))
			return validateSingBoxControllerSecret(secret)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		random := make([]byte, 32)
		if _, err := rand.Read(random); err != nil {
			return err
		}
		secret = base64.RawURLEncoding.EncodeToString(random)
		return preparer.State.Write(singBoxControllerStatePath, []byte(secret+"\n"), 0o600)
	})
	return secret, err
}

func validateSingBoxControllerSecret(secret string) error {
	if len(secret) < 32 || len(secret) > 256 || strings.TrimSpace(secret) != secret || strings.ContainsAny(secret, "\r\n") {
		return errors.New("sing-box controller secret is invalid")
	}
	return nil
}

var _ ExplicitProfilePreparer = (*ActiveSingBoxPreparer)(nil)
