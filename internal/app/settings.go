package app

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/platform/openwrt"
	"github.com/kontsevoye/boxctl/internal/state"
)

const settingsRelativePath = ".boxctl/settings"

// Mihomo uses the benchmarking block as the implicit fake-IP pool when
// dns.fake-ip-range is omitted.
const defaultMihomoFakeIPRange = "198.18.0.0/15"

// RuntimeSettings is the validated, OpenWrt-first manager configuration.
// Unknown keys are kept in Raw so a save never erases settings owned by a
// newer version.
type RuntimeSettings struct {
	Raw state.Settings

	CoreRestartGuard                     bool
	OperatingMode                        string
	CaptureMode                          openwrt.Mode
	DNSMode                              openwrt.DNSMode
	InterfaceMode                        string
	Included                             []string
	Excluded                             []string
	TUNStack                             string
	TUNAddress                           netip.Prefix
	TUNMTU                               uint32
	ReservedNetworks                     []string
	ReservedNetworksConfigured           bool
	BypassSources                        []string
	BypassTCPPorts                       []uint16
	BypassUDPPorts                       []uint16
	ProxyTCPPorts                        []uint16
	ProxyUDPPorts                        []uint16
	RejectQUIC                           bool
	AutoDetectWAN                        bool
	AutoDetectLAN                        bool
	AutoFakeIP                           bool
	AutoFakeIPIncludeExternalIPProviders bool
	UseTmpfsRules                        bool
	EnableHWID                           bool
	InterceptOutput                      bool
	AutoRefreshProxyIPs                  bool
	AutoRefreshFakeIP                    bool
	MaintenanceInterval                  int
}

// DefaultRuntimeSettings defines boxctl's OpenWrt gateway behaviour and
// proxy/DNS ports. Interface discovery is fail-closed: exclude mode still
// requires a positively identified WAN.
func DefaultRuntimeSettings() RuntimeSettings {
	plan := openwrt.DefaultGatewayPlan(openwrt.ModeTPROXY)
	return RuntimeSettings{
		Raw:                 make(state.Settings),
		OperatingMode:       "gateway",
		CaptureMode:         openwrt.ModeTPROXY,
		DNSMode:             openwrt.DNSUpstream,
		InterfaceMode:       "exclude",
		TUNStack:            "system",
		TUNAddress:          netip.MustParsePrefix("172.19.0.1/30"),
		TUNMTU:              1500,
		ReservedNetworks:    append([]string(nil), plan.BypassCIDRs...),
		RejectQUIC:          true,
		AutoDetectWAN:       true,
		AutoDetectLAN:       true,
		AutoFakeIP:          true,
		InterceptOutput:     true,
		AutoRefreshProxyIPs: true,
		AutoRefreshFakeIP:   true,
		MaintenanceInterval: 30,
	}
}

// LoadRuntimeSettings accepts an absent settings file as the default
// configuration, but never accepts a malformed existing file.
func LoadRuntimeSettings(store state.Store) (RuntimeSettings, error) {
	raw, err := store.LoadSettings(settingsRelativePath)
	if errors.Is(err, fs.ErrNotExist) {
		return DefaultRuntimeSettings(), nil
	}
	if err != nil {
		return RuntimeSettings{}, err
	}
	return DecodeRuntimeSettings(raw)
}

func DecodeRuntimeSettings(raw state.Settings) (RuntimeSettings, error) {
	result := DefaultRuntimeSettings()
	result.Raw = cloneSettings(raw)
	if value := strings.ToLower(strings.TrimSpace(raw["OPERATING_MODE"])); value != "" {
		result.OperatingMode = value
	}
	if result.OperatingMode != "gateway" && result.OperatingMode != "server" {
		return RuntimeSettings{}, fmt.Errorf("unsupported OPERATING_MODE %q", result.OperatingMode)
	}

	if value := strings.ToLower(strings.TrimSpace(raw["PROXY_MODE"])); value != "" {
		result.CaptureMode = openwrt.Mode(value)
	}
	switch result.CaptureMode {
	case openwrt.ModeTPROXY, openwrt.ModeHYBRID, openwrt.ModeTUN, openwrt.ModeMIXED, openwrt.ModeMIXED2:
	default:
		return RuntimeSettings{}, fmt.Errorf("unsupported PROXY_MODE %q", result.CaptureMode)
	}

	upstream, err := settingBool(raw, "ENABLE_DNS_UPSTREAM", result.DNSMode == openwrt.DNSUpstream)
	if err != nil {
		return RuntimeSettings{}, err
	}
	redirect, err := settingBool(raw, "ENABLE_DNS_REDIRECT", result.DNSMode == openwrt.DNSRedirect)
	if err != nil {
		return RuntimeSettings{}, err
	}
	if upstream && redirect {
		return RuntimeSettings{}, errors.New("ENABLE_DNS_UPSTREAM and ENABLE_DNS_REDIRECT are mutually exclusive")
	}
	switch {
	case upstream:
		result.DNSMode = openwrt.DNSUpstream
	case redirect:
		result.DNSMode = openwrt.DNSRedirect
	default:
		result.DNSMode = openwrt.DNSDisabled
	}

	if value := strings.ToLower(strings.TrimSpace(raw["INTERFACE_MODE"])); value != "" {
		result.InterfaceMode = value
	}
	if result.InterfaceMode != "explicit" && result.InterfaceMode != "exclude" {
		return RuntimeSettings{}, fmt.Errorf("unsupported INTERFACE_MODE %q", result.InterfaceMode)
	}
	result.Included = splitList(raw["INCLUDED_INTERFACES"])
	result.Excluded = splitList(raw["EXCLUDED_INTERFACES"])
	if value := strings.TrimSpace(raw["TUN_STACK"]); value != "" {
		result.TUNStack = value
	}
	if value := strings.TrimSpace(raw["SINGBOX_TUN_ADDRESS"]); value != "" {
		prefix, parseErr := netip.ParsePrefix(value)
		if parseErr != nil || !prefix.Addr().Is4() || prefix.Bits() < 1 || prefix.Bits() > 30 {
			return RuntimeSettings{}, fmt.Errorf("SINGBOX_TUN_ADDRESS must be an IPv4 interface prefix")
		}
		result.TUNAddress = prefix
	}
	if value := strings.TrimSpace(raw["SINGBOX_TUN_MTU"]); value != "" {
		parsed, parseErr := strconv.ParseUint(value, 10, 32)
		if parseErr != nil || parsed < 576 || parsed > 9000 {
			return RuntimeSettings{}, fmt.Errorf("SINGBOX_TUN_MTU must be between 576 and 9000")
		}
		result.TUNMTU = uint32(parsed)
	}
	switch result.TUNStack {
	case "system", "gvisor", "mixed":
	default:
		return RuntimeSettings{}, fmt.Errorf("unsupported TUN_STACK %q", result.TUNStack)
	}

	if value, exists := raw["RESERVED_NETWORKS"]; exists {
		result.ReservedNetworksConfigured = true
		result.ReservedNetworks, err = parseIPv4Prefixes(value, true)
		if err != nil {
			return RuntimeSettings{}, fmt.Errorf("RESERVED_NETWORKS: %w", err)
		}
	}
	result.BypassSources, err = parseIPv4Prefixes(raw["BYPASS_SOURCES"], false)
	if err != nil {
		return RuntimeSettings{}, fmt.Errorf("BYPASS_SOURCES: %w", err)
	}
	result.BypassTCPPorts, result.BypassUDPPorts, err = parseProtocolPorts(raw["BYPASS_DPORTS"])
	if err != nil {
		return RuntimeSettings{}, fmt.Errorf("BYPASS_DPORTS: %w", err)
	}
	result.ProxyTCPPorts, result.ProxyUDPPorts, err = parseProtocolPorts(raw["PROXY_DPORTS"])
	if err != nil {
		return RuntimeSettings{}, fmt.Errorf("PROXY_DPORTS: %w", err)
	}

	for key, target := range map[string]*bool{
		"CORE_RESTART_GUARD":    &result.CoreRestartGuard,
		"BLOCK_QUIC":            &result.RejectQUIC,
		"AUTO_DETECT_WAN":       &result.AutoDetectWAN,
		"AUTO_DETECT_LAN":       &result.AutoDetectLAN,
		"AUTO_FAKEIP_WHITELIST": &result.AutoFakeIP,
		"AUTO_FAKEIP_INCLUDE_EXTERNAL_IP_PROVIDERS": &result.AutoFakeIPIncludeExternalIPProviders,
		"USE_TMPFS_RULES":         &result.UseTmpfsRules,
		"ENABLE_HWID":             &result.EnableHWID,
		"INTERCEPT_ROUTER_OUTPUT": &result.InterceptOutput,
		"AUTO_REFRESH_PROXY_IPS":  &result.AutoRefreshProxyIPs,
		"AUTO_REFRESH_FAKEIP":     &result.AutoRefreshFakeIP,
	} {
		*target, err = settingBool(raw, key, *target)
		if err != nil {
			return RuntimeSettings{}, err
		}
	}
	result.MaintenanceInterval, err = settingInt(raw, "MAINTENANCE_INTERVAL", result.MaintenanceInterval, 5, 1440)
	if err != nil {
		return RuntimeSettings{}, err
	}
	return result, nil
}

func settingInt(settings state.Settings, key string, fallback, minimum, maximum int) (int, error) {
	value, exists := settings[key]
	if !exists || strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("%s must be between %d and %d", key, minimum, maximum)
	}
	return parsed, nil
}

func settingBool(settings state.Settings, key string, fallback bool) (bool, error) {
	value, exists := settings[key]
	if !exists || strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", key)
	}
	return parsed, nil
}

func splitList(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' })
	for index := range fields {
		fields[index] = strings.TrimSpace(fields[index])
	}
	slices.Sort(fields)
	return slices.Compact(fields)
}

func parseIPv4Prefixes(value string, allowEmpty bool) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		if allowEmpty {
			return []string{}, nil
		}
		return nil, nil
	}
	result := make([]string, 0)
	for _, item := range splitList(value) {
		if address, err := netip.ParseAddr(item); err == nil {
			if !address.Is4() {
				return nil, fmt.Errorf("%q is not IPv4", item)
			}
			result = append(result, netip.PrefixFrom(address, 32).String())
			continue
		}
		prefix, err := netip.ParsePrefix(item)
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("invalid IPv4 prefix %q", item)
		}
		result = append(result, prefix.Masked().String())
	}
	slices.Sort(result)
	return slices.Compact(result), nil
}

// parseProtocolPorts accepts unqualified values (both protocols), plus
// tcp:/udp: prefixes and bounded inclusive '-' ranges.
func parseProtocolPorts(value string) (tcpPorts, udpPorts []uint16, returnErr error) {
	const maxExpandedPorts = 8192
	for _, token := range splitList(value) {
		protocol := "both"
		lower := strings.ToLower(token)
		for _, prefix := range []string{"tcp:", "udp:"} {
			if strings.HasPrefix(lower, prefix) {
				protocol = strings.TrimSuffix(prefix, ":")
				token = token[len(prefix):]
				break
			}
		}
		startText, endText, rangeFound := strings.Cut(token, "-")
		start, err := parsePort(startText)
		if err != nil {
			return nil, nil, err
		}
		end := start
		if rangeFound {
			end, err = parsePort(endText)
			if err != nil || end < start {
				return nil, nil, fmt.Errorf("invalid port range %q", token)
			}
		}
		if int(end-start)+1+len(tcpPorts)+len(udpPorts) > maxExpandedPorts {
			return nil, nil, errors.New("expanded port list is too large")
		}
		for port := uint32(start); port <= uint32(end); port++ {
			expandedPort, err := checkedPort(port)
			if err != nil {
				return nil, nil, err
			}
			switch protocol {
			case "tcp":
				tcpPorts = append(tcpPorts, expandedPort)
			case "udp":
				udpPorts = append(udpPorts, expandedPort)
			default:
				tcpPorts = append(tcpPorts, expandedPort)
				udpPorts = append(udpPorts, expandedPort)
			}
		}
	}
	slices.Sort(tcpPorts)
	slices.Sort(udpPorts)
	return slices.Compact(tcpPorts), slices.Compact(udpPorts), nil
}

func checkedPort(value uint32) (uint16, error) {
	if value == 0 || value > uint32(^uint16(0)) {
		return 0, fmt.Errorf("invalid expanded port %d", value)
	}
	return uint16(value), nil
}

func parsePort(value string) (uint16, error) {
	number, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil || number == 0 {
		return 0, fmt.Errorf("invalid port %q", value)
	}
	return uint16(number), nil
}

func cloneSettings(settings state.Settings) state.Settings {
	result := make(state.Settings, len(settings))
	for key, value := range settings {
		result[key] = value
	}
	return result
}

// CapturePlan translates the five capture modes into the engine-neutral core
// contract. Native values discovered in the active profile win where safe.
func (settings RuntimeSettings) CapturePlan(managed ManagedMihomoSettings) (engine.CapturePlan, error) {
	tproxyPort := managed.TProxyPort
	if tproxyPort == 0 {
		tproxyPort = 7894
	}
	redirectPort := managed.RedirectPort
	if redirectPort == 0 {
		redirectPort = 7893
	}
	dnsPort := managed.DNSPort
	if dnsPort == 0 {
		dnsPort = 7874
	}
	device := managed.TUNDevice
	if device == "" {
		device = "clash-tun"
	}
	stack := managed.TUNStack
	if stack == "" {
		stack = settings.TUNStack
	}
	loopMark := managed.LoopMark
	if loopMark == 0 {
		loopMark = 2
	}
	dns := engine.DNSEndpoint{}
	if settings.DNSMode != openwrt.DNSDisabled {
		dns = engine.DNSEndpoint{Enabled: true, Host: "0.0.0.0", Port: dnsPort}
	}
	plan := engine.CapturePlan{
		DNS:       dns,
		TUNDevice: device,
		TUNStack:  stack,
		LoopMark:  loopMark,
	}
	switch settings.CaptureMode {
	case openwrt.ModeTPROXY:
		plan.TCP = engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: tproxyPort}
		plan.UDP = engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: tproxyPort}
	case openwrt.ModeHYBRID:
		plan.TCP = engine.ProtocolCapture{Method: engine.CaptureRedirect, Port: redirectPort}
		plan.UDP = engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: tproxyPort}
	case openwrt.ModeTUN:
		plan.TCP = engine.ProtocolCapture{Method: engine.CaptureTUN}
		plan.UDP = engine.ProtocolCapture{Method: engine.CaptureTUN}
	case openwrt.ModeMIXED:
		plan.TCP = engine.ProtocolCapture{Method: engine.CaptureTPROXY, Port: tproxyPort}
		plan.UDP = engine.ProtocolCapture{Method: engine.CaptureTUN}
	case openwrt.ModeMIXED2:
		plan.TCP = engine.ProtocolCapture{Method: engine.CaptureRedirect, Port: redirectPort}
		plan.UDP = engine.ProtocolCapture{Method: engine.CaptureTUN}
	default:
		return engine.CapturePlan{}, fmt.Errorf("unsupported capture mode %q", settings.CaptureMode)
	}
	// AUTO controls regeneration of the compatibility file, not whether
	// fake-IP traffic itself is captured. The policy below is therefore
	// intentionally independent of settings.AutoFakeIP.
	if managed.DNSFakeIP {
		plan.FakeIPRanges = normalizeNetPrefixes(managed.FakeIPRanges)
		effective := append([]netip.Prefix(nil), plan.FakeIPRanges...)
		switch strings.ToLower(strings.TrimSpace(managed.FakeIPFilterMode)) {
		case "whitelist", "rule":
			effective = append(effective, managed.AdditionalCaptureCIDRs...)
		}
		plan.Destinations = engine.DestinationCapture{
			Mode: engine.DestinationCaptureAllowlist, CIDRs: normalizeNetPrefixes(effective),
		}
	}
	return plan, plan.Validate()
}

// ManagedMihomoSettings contains only the non-secret settings inspected from
// the active profile. Controller credentials stay in the preparer.
type ManagedMihomoSettings struct {
	TProxyPort             uint16
	RedirectPort           uint16
	DNSPort                uint16
	TUNDevice              string
	TUNStack               string
	LoopMark               uint32
	DNSFakeIP              bool
	FakeIPFilterMode       string
	FakeIPRanges           []netip.Prefix
	AdditionalCaptureCIDRs []netip.Prefix
}

func (settings RuntimeSettings) GatewayPlan(capture engine.CapturePlan, discovered openwrt.InterfaceDiscovery) (openwrt.GatewayPlan, error) {
	plan := openwrt.DefaultGatewayPlan(settings.CaptureMode)
	plan.DNSMode = settings.DNSMode
	plan.TUNDevice = capture.TUNDevice
	plan.TUNMark = 3
	plan.LoopMark = capture.LoopMark
	plan.InterceptOutput = settings.InterceptOutput
	plan.RejectQUIC = settings.RejectQUIC
	plan.BypassCIDRs = append([]string(nil), settings.ReservedNetworks...)
	plan.BypassCIDRsConfigured = settings.ReservedNetworksConfigured
	plan.SourceBypassCIDRs = append([]string(nil), settings.BypassSources...)
	plan.ProxyServerCIDRs = make([]string, 0, len(capture.EndpointBypassCIDRs))
	for _, prefix := range capture.EndpointBypassCIDRs {
		if !prefix.IsValid() || !prefix.Addr().Is4() {
			return openwrt.GatewayPlan{}, fmt.Errorf("OpenWrt endpoint bypass is IPv4-only: %s", prefix)
		}
		plan.ProxyServerCIDRs = append(plan.ProxyServerCIDRs, prefix.Masked().String())
	}
	plan.BypassTCPPorts = mergePorts(plan.BypassTCPPorts, settings.BypassTCPPorts)
	plan.BypassUDPPorts = mergePorts(plan.BypassUDPPorts, settings.BypassUDPPorts)
	plan.ProxyOnlyTCPPorts = append([]uint16(nil), settings.ProxyTCPPorts...)
	plan.ProxyOnlyUDPPorts = append([]uint16(nil), settings.ProxyUDPPorts...)
	if capture.TCP.Method == engine.CaptureTPROXY {
		plan.TProxyPort = capture.TCP.Port
	} else if capture.UDP.Method == engine.CaptureTPROXY {
		plan.TProxyPort = capture.UDP.Port
	}
	if capture.TCP.Method == engine.CaptureRedirect {
		plan.RedirectPort = capture.TCP.Port
	}
	if capture.DNS.Enabled {
		plan.DNSPort = capture.DNS.Port
	}
	switch capture.Destinations.Mode {
	case engine.DestinationCaptureAll:
		plan.CaptureCIDRs = nil
		plan.CaptureCIDRsConfigured = false
	case engine.DestinationCaptureAllowlist:
		plan.CaptureCIDRsConfigured = true
		plan.CaptureCIDRs = make([]string, 0, len(capture.Destinations.CIDRs))
		for _, prefix := range capture.Destinations.CIDRs {
			if !prefix.Addr().Is4() {
				return openwrt.GatewayPlan{}, fmt.Errorf("OpenWrt destination capture is IPv4-only: %s", prefix)
			}
			plan.CaptureCIDRs = append(plan.CaptureCIDRs, prefix.Masked().String())
		}
	default:
		return openwrt.GatewayPlan{}, fmt.Errorf("unsupported destination capture mode %q", capture.Destinations.Mode)
	}

	switch settings.InterfaceMode {
	case "explicit":
		plan.IncludeInterfaces = append([]string(nil), settings.Included...)
		if len(plan.IncludeInterfaces) == 0 && settings.AutoDetectLAN {
			plan.IncludeInterfaces = append(plan.IncludeInterfaces, discovered.LANInterfaces...)
		}
		if len(plan.IncludeInterfaces) == 0 {
			return openwrt.GatewayPlan{}, errors.New("explicit interface mode has no positively identified LAN interface")
		}
	case "exclude":
		plan.ExcludeInterfaces = append([]string(nil), settings.Excluded...)
		if settings.AutoDetectWAN {
			plan.ExcludeInterfaces = append(plan.ExcludeInterfaces, discovered.WANInterfaces...)
		}
		if settings.AutoDetectWAN && len(discovered.WANInterfaces) == 0 {
			return openwrt.GatewayPlan{}, errors.New("exclude interface mode cannot identify WAN")
		}
	default:
		return openwrt.GatewayPlan{}, fmt.Errorf("unsupported interface mode %q", settings.InterfaceMode)
	}
	return plan, openwrt.Validate(plan)
}

func mergePorts(left, right []uint16) []uint16 {
	result := append(append([]uint16(nil), left...), right...)
	slices.Sort(result)
	return slices.Compact(result)
}

func normalizeNetPrefixes(values []netip.Prefix) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(values))
	for _, prefix := range values {
		if prefix.IsValid() {
			result = append(result, prefix.Masked())
		}
	}
	slices.SortFunc(result, func(left, right netip.Prefix) int {
		return strings.Compare(left.String(), right.String())
	})
	return slices.Compact(result)
}
