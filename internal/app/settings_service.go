package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/kontsevoye/boxctl/internal/platform/openwrt"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

type SettingsService struct {
	State              state.Store
	OnChanged          func(context.Context, bool) error
	SetStartOnBoot     func(context.Context, bool) error
	DiscoverInterfaces func(context.Context) (web.InterfaceCatalog, error)
	SelectedEngine     func() string
}

func NewSettingsService(root string) (*SettingsService, error) {
	store, err := state.NewStore(root)
	if err != nil {
		return nil, err
	}
	return &SettingsService{State: store}, nil
}

func (service *SettingsService) Settings(ctx context.Context) (web.Settings, error) {
	runtimeSettings, err := LoadRuntimeSettings(service.State)
	if err != nil {
		return web.Settings{}, err
	}
	result := runtimeSettingsWeb(runtimeSettings)
	if service.DiscoverInterfaces != nil {
		if catalog, discoverErr := service.DiscoverInterfaces(ctx); discoverErr == nil {
			result.Interfaces = append([]web.InterfaceOption(nil), catalog.Interfaces...)
			result.InterfaceSource = catalog.Source
		}
	}
	return result, nil
}

func (service *SettingsService) UpdateSettings(ctx context.Context, patch web.SettingsPatch) (web.Settings, error) {
	current, err := LoadRuntimeSettings(service.State)
	if err != nil {
		return web.Settings{}, err
	}
	raw := cloneSettings(current.Raw)
	applyStringPatch(raw, "LANGUAGE", patch.Language)
	applyStringPatch(raw, "THEME", patch.Theme)
	applyStringPatch(raw, "LOG_LEVEL", patch.LogLevel)
	applyStringPatch(raw, "UPDATE_CHANNEL", patch.UpdateChannel)
	applyStringPatch(raw, "PROXY_MODE", patch.CaptureMode)
	applyBoolPatch(raw, "START_ON_BOOT", patch.StartOnBoot)
	applyBoolPatch(raw, "AUTO_UPDATE", patch.AutoUpdate)
	applyStringPatch(raw, "OPERATING_MODE", patch.OperatingMode)
	applyStringPatch(raw, "INTERFACE_MODE", patch.InterfaceMode)
	applyBoolPatch(raw, "AUTO_DETECT_WAN", patch.AutoDetectWAN)
	applyBoolPatch(raw, "AUTO_DETECT_LAN", patch.AutoDetectLAN)
	applyBoolPatch(raw, "INTERCEPT_ROUTER_OUTPUT", patch.InterceptRouterOutput)
	applyStringPatch(raw, "TUN_STACK", patch.TUNStack)
	applyStringPatchPreserveCase(raw, "SINGBOX_TUN_ADDRESS", patch.TUNAddress)
	if patch.TUNMTU != nil {
		raw["SINGBOX_TUN_MTU"] = strconv.FormatUint(uint64(*patch.TUNMTU), 10)
	}
	applyBoolPatch(raw, "BLOCK_QUIC", patch.RejectQUIC)
	applyBoolPatch(raw, "AUTO_FAKEIP_WHITELIST", patch.AutoFakeIPWhitelist)
	applyBoolPatch(raw, "AUTO_FAKEIP_INCLUDE_EXTERNAL_IP_PROVIDERS", patch.AutoFakeIPIncludeExternalIPProviders)
	applyBoolPatch(raw, "USE_TMPFS_RULES", patch.UseTmpfsRules)
	applyBoolPatch(raw, "ENABLE_HWID", patch.EnableHWID)
	applyBoolPatch(raw, "AUTO_REFRESH_PROXY_IPS", patch.AutoRefreshProxyIPs)
	applyBoolPatch(raw, "AUTO_REFRESH_FAKEIP", patch.AutoRefreshFakeIP)
	if patch.MaintenanceIntervalMinutes != nil {
		raw["MAINTENANCE_INTERVAL"] = strconv.Itoa(*patch.MaintenanceIntervalMinutes)
	}
	if patch.DNSMode != nil {
		switch strings.ToLower(strings.TrimSpace(*patch.DNSMode)) {
		case "upstream":
			raw["ENABLE_DNS_UPSTREAM"], raw["ENABLE_DNS_REDIRECT"] = "true", "false"
		case "redirect":
			raw["ENABLE_DNS_UPSTREAM"], raw["ENABLE_DNS_REDIRECT"] = "false", "true"
		case "disabled":
			raw["ENABLE_DNS_UPSTREAM"], raw["ENABLE_DNS_REDIRECT"] = "false", "false"
		default:
			return web.Settings{}, invalidSetting("dnsMode")
		}
	}
	if patch.IncludedInterfaces != nil {
		raw["INCLUDED_INTERFACES"] = strings.Join(normalizeStringList(*patch.IncludedInterfaces), ",")
	}
	if patch.ExcludedInterfaces != nil {
		raw["EXCLUDED_INTERFACES"] = strings.Join(normalizeStringList(*patch.ExcludedInterfaces), ",")
	}
	if patch.ReservedNetworks != nil {
		raw["RESERVED_NETWORKS"] = strings.Join(normalizeStringList(*patch.ReservedNetworks), ",")
	}
	if patch.BypassSources != nil {
		raw["BYPASS_SOURCES"] = strings.Join(normalizeStringList(*patch.BypassSources), ",")
	}
	if patch.BypassTCPPorts != nil || patch.BypassUDPPorts != nil {
		tcpPorts := current.BypassTCPPorts
		udpPorts := current.BypassUDPPorts
		if patch.BypassTCPPorts != nil {
			tcpPorts = append([]uint16(nil), (*patch.BypassTCPPorts)...)
		}
		if patch.BypassUDPPorts != nil {
			udpPorts = append([]uint16(nil), (*patch.BypassUDPPorts)...)
		}
		raw["BYPASS_DPORTS"] = formatProtocolPorts(tcpPorts, udpPorts)
	}
	if patch.ProxyOnlyTCPPorts != nil || patch.ProxyOnlyUDPPorts != nil {
		tcpPorts := current.ProxyTCPPorts
		udpPorts := current.ProxyUDPPorts
		if patch.ProxyOnlyTCPPorts != nil {
			tcpPorts = append([]uint16(nil), (*patch.ProxyOnlyTCPPorts)...)
		}
		if patch.ProxyOnlyUDPPorts != nil {
			udpPorts = append([]uint16(nil), (*patch.ProxyOnlyUDPPorts)...)
		}
		raw["PROXY_DPORTS"] = formatProtocolPorts(tcpPorts, udpPorts)
	}

	candidate, err := DecodeRuntimeSettings(raw)
	if err != nil {
		return web.Settings{}, &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_settings", Message: "One or more gateway settings are invalid"}
	}
	if err := validatePublicSettings(candidate.Raw); err != nil {
		return web.Settings{}, err
	}
	currentBoot := settingBoolUnchecked(current.Raw, "START_ON_BOOT", true)
	candidateBoot := settingBoolUnchecked(candidate.Raw, "START_ON_BOOT", true)
	bootChanged := currentBoot != candidateBoot
	if bootChanged && service.SetStartOnBoot != nil {
		if err := service.SetStartOnBoot(ctx, candidateBoot); err != nil {
			return web.Settings{}, fmt.Errorf("change service boot state: %w", err)
		}
	}
	if err := service.State.SaveSettings(settingsRelativePath, candidate.Raw); err != nil {
		if bootChanged && service.SetStartOnBoot != nil {
			rollbackErr := service.SetStartOnBoot(context.Background(), currentBoot)
			return web.Settings{}, errors.Join(err, wrapUpdateError("restore service boot state", rollbackErr))
		}
		return web.Settings{}, err
	}
	selectedEngine := state.EngineMihomo
	if service.SelectedEngine != nil {
		selectedEngine = normalizedEngine(service.SelectedEngine())
	}
	restartRequired := current.CaptureMode != candidate.CaptureMode || current.DNSMode != candidate.DNSMode || current.TUNStack != candidate.TUNStack ||
		current.OperatingMode != candidate.OperatingMode ||
		current.InterfaceMode != candidate.InterfaceMode || current.AutoDetectWAN != candidate.AutoDetectWAN || current.AutoDetectLAN != candidate.AutoDetectLAN ||
		current.InterceptOutput != candidate.InterceptOutput || !slices.Equal(current.Included, candidate.Included) || !slices.Equal(current.Excluded, candidate.Excluded) ||
		current.RejectQUIC != candidate.RejectQUIC || !slices.Equal(current.ReservedNetworks, candidate.ReservedNetworks) || !slices.Equal(current.BypassSources, candidate.BypassSources) ||
		!slices.Equal(current.BypassTCPPorts, candidate.BypassTCPPorts) || !slices.Equal(current.BypassUDPPorts, candidate.BypassUDPPorts) ||
		!slices.Equal(current.ProxyTCPPorts, candidate.ProxyTCPPorts) || !slices.Equal(current.ProxyUDPPorts, candidate.ProxyUDPPorts)
	if selectedEngine == state.EngineSingBox {
		restartRequired = restartRequired || current.TUNAddress != candidate.TUNAddress || current.TUNMTU != candidate.TUNMTU
	} else {
		restartRequired = restartRequired || current.AutoFakeIP != candidate.AutoFakeIP ||
			current.AutoFakeIPIncludeExternalIPProviders != candidate.AutoFakeIPIncludeExternalIPProviders ||
			current.UseTmpfsRules != candidate.UseTmpfsRules || current.EnableHWID != candidate.EnableHWID
	}
	if service.OnChanged != nil {
		if err := service.OnChanged(ctx, restartRequired); err != nil {
			return web.Settings{}, fmt.Errorf("settings saved but runtime refresh failed: %w", err)
		}
	}
	result := runtimeSettingsWeb(candidate)
	if service.DiscoverInterfaces != nil {
		if catalog, discoverErr := service.DiscoverInterfaces(ctx); discoverErr == nil {
			result.Interfaces = append([]web.InterfaceOption(nil), catalog.Interfaces...)
			result.InterfaceSource = catalog.Source
		}
	}
	return result, nil
}

func runtimeInterfaceCatalog(discovery openwrt.InterfaceDiscovery) web.InterfaceCatalog {
	result := web.InterfaceCatalog{Source: discovery.Source, Interfaces: make([]web.InterfaceOption, 0, len(discovery.AllInterfaces))}
	for _, name := range discovery.AllInterfaces {
		role := "other"
		switch {
		case slices.Contains(discovery.WANInterfaces, name):
			role = "wan"
		case slices.Contains(discovery.LANInterfaces, name):
			role = "lan"
		}
		result.Interfaces = append(result.Interfaces, web.InterfaceOption{Name: name, Role: role})
	}
	return result
}

func runtimeSettingsWeb(settings RuntimeSettings) web.Settings {
	return web.Settings{
		Language: valueOr(settings.Raw, "LANGUAGE", "en"), Theme: valueOr(settings.Raw, "THEME", "system"),
		LogLevel: valueOr(settings.Raw, "LOG_LEVEL", "info"), UpdateChannel: valueOr(settings.Raw, "UPDATE_CHANNEL", "stable"),
		CaptureMode: string(settings.CaptureMode), AvailableCaptureModes: []string{"tproxy", "hybrid", "tun", "mixed", "mixed2"},
		StartOnBoot: settingBoolUnchecked(settings.Raw, "START_ON_BOOT", true), AutoUpdate: settingBoolUnchecked(settings.Raw, "AUTO_UPDATE", false),
		OperatingMode: settings.OperatingMode,
		DNSMode:       string(settings.DNSMode), InterfaceMode: settings.InterfaceMode,
		AutoDetectWAN: settings.AutoDetectWAN, AutoDetectLAN: settings.AutoDetectLAN, InterceptRouterOutput: settings.InterceptOutput,
		IncludedInterfaces: append([]string(nil), settings.Included...), ExcludedInterfaces: append([]string(nil), settings.Excluded...),
		TUNStack: settings.TUNStack, TUNAddress: settings.TUNAddress.String(), TUNMTU: settings.TUNMTU, RejectQUIC: settings.RejectQUIC,
		ReservedNetworks: append([]string(nil), settings.ReservedNetworks...), BypassSources: append([]string(nil), settings.BypassSources...),
		BypassTCPPorts: append([]uint16(nil), settings.BypassTCPPorts...), BypassUDPPorts: append([]uint16(nil), settings.BypassUDPPorts...),
		ProxyOnlyTCPPorts: append([]uint16(nil), settings.ProxyTCPPorts...), ProxyOnlyUDPPorts: append([]uint16(nil), settings.ProxyUDPPorts...),
		AutoFakeIPWhitelist: settings.AutoFakeIP, AutoFakeIPIncludeExternalIPProviders: settings.AutoFakeIPIncludeExternalIPProviders,
		UseTmpfsRules: settings.UseTmpfsRules, EnableHWID: settings.EnableHWID,
		AutoRefreshProxyIPs: settings.AutoRefreshProxyIPs, AutoRefreshFakeIP: settings.AutoRefreshFakeIP,
		MaintenanceIntervalMinutes: settings.MaintenanceInterval,
	}
}

func validatePublicSettings(raw state.Settings) error {
	allowed := map[string][]string{
		"LANGUAGE": {"ru", "en"}, "THEME": {"system", "light", "dark"},
		"LOG_LEVEL": {"debug", "info", "warn", "error"}, "UPDATE_CHANNEL": {"stable", "alpha"},
	}
	for key, values := range allowed {
		value := valueOr(raw, key, values[0])
		if !slices.Contains(values, value) {
			return invalidSetting(strings.ToLower(key))
		}
	}
	return nil
}

func invalidSetting(name string) error {
	return &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_setting", Message: "Invalid setting: " + name}
}

func applyStringPatch(settings state.Settings, key string, value *string) {
	if value != nil {
		settings[key] = strings.ToLower(strings.TrimSpace(*value))
	}
}

func applyStringPatchPreserveCase(settings state.Settings, key string, value *string) {
	if value != nil {
		settings[key] = strings.TrimSpace(*value)
	}
}

func applyBoolPatch(settings state.Settings, key string, value *bool) {
	if value != nil {
		settings[key] = strconv.FormatBool(*value)
	}
}

func valueOr(settings state.Settings, key, fallback string) string {
	if value := strings.TrimSpace(settings[key]); value != "" {
		return strings.ToLower(value)
	}
	return fallback
}

func settingBoolUnchecked(settings state.Settings, key string, fallback bool) bool {
	value, err := settingBool(settings, key, fallback)
	if err != nil {
		return fallback
	}
	return value
}

func normalizeStringList(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			result = append(result, value)
		}
	}
	slices.Sort(result)
	return slices.Compact(result)
}

func formatProtocolPorts(tcpPorts, udpPorts []uint16) string {
	tcpPorts = append([]uint16(nil), tcpPorts...)
	udpPorts = append([]uint16(nil), udpPorts...)
	slices.Sort(tcpPorts)
	slices.Sort(udpPorts)
	tcpPorts = slices.Compact(tcpPorts)
	udpPorts = slices.Compact(udpPorts)
	parts := make([]string, 0, len(tcpPorts)+len(udpPorts))
	for _, port := range tcpPorts {
		parts = append(parts, "tcp:"+strconv.FormatUint(uint64(port), 10))
	}
	for _, port := range udpPorts {
		parts = append(parts, "udp:"+strconv.FormatUint(uint64(port), 10))
	}
	return strings.Join(parts, ",")
}

func EnsureSettingsFile(store state.Store) error {
	_, err := store.LoadSettings(settingsRelativePath)
	if err == nil {
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return store.SaveSettings(settingsRelativePath, DefaultRuntimeSettings().Raw)
}

var _ web.SettingsService = (*SettingsService)(nil)
