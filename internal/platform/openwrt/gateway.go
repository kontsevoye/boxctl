package openwrt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type Mode string

const (
	ModeTPROXY Mode = "tproxy"
	// ModeHYBRID sends TCP to a redirect inbound and UDP to TPROXY.
	ModeHYBRID Mode = "hybrid"
	ModeTUN    Mode = "tun"
	// ModeMIXED sends TCP to TPROXY and UDP through the TUN device.
	ModeMIXED Mode = "mixed"
	// ModeMIXED2 sends TCP to a redirect inbound and UDP through TUN.
	ModeMIXED2 Mode = "mixed2"
)

type DNSMode string

const (
	DNSDisabled DNSMode = "disabled"
	DNSUpstream DNSMode = "upstream"
	DNSRedirect DNSMode = "redirect"
)

const (
	defaultTable          = "clash"
	defaultOwner          = "boxctl/v1"
	defaultTProxyPort     = uint16(7894)
	defaultRedirectPort   = uint16(7893)
	defaultDNSPort        = uint16(7874)
	defaultRouterDNSPort  = uint16(53)
	defaultTProxyMark     = uint32(1)
	defaultTUNMark        = uint32(3)
	defaultTProxyTable    = 100
	defaultTUNTable       = 101
	defaultTProxyPriority = 1000
	defaultTUNPriority    = 1001
	defaultTUNDevice      = "clash-tun"
	defaultLoopMark       = uint32(2)
)

var defaultReservedCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
}

// GatewayPlan is an engine-neutral description of OpenWrt packet capture.
// All address sets are IPv4 because the current gateway contract is IPv4-only.
// CaptureCIDRs is the destination allowlist used for fake-IP/AUTO-whitelist
// capture. CaptureCIDRsConfigured distinguishes it from broad capture. ProxyOnly
// ports remain subject to this destination check; they are an exclusive port
// filter, not a way to force capture around it.
type GatewayPlan struct {
	Mode           Mode
	DNSMode        DNSMode
	Table          string
	Owner          string
	TProxyPort     uint16
	RedirectPort   uint16
	DNSPort        uint16
	RouterDNSPort  uint16
	TProxyMark     uint32
	TUNMark        uint32
	LoopMark       uint32
	TProxyTable    int
	TUNTable       int
	TProxyPriority int
	TUNPriority    int
	TUNDevice      string
	CaptureCIDRs   []string
	// CaptureCIDRsConfigured is false for broad capture. A non-empty legacy
	// CaptureCIDRs value implicitly enables it during normalization.
	CaptureCIDRsConfigured bool
	BypassCIDRs            []string
	// BypassCIDRsConfigured distinguishes an explicit empty list from an
	// omitted list, which receives the compatibility defaults.
	BypassCIDRsConfigured bool
	SourceBypassCIDRs     []string
	ProxyServerCIDRs      []string
	IncludeInterfaces     []string
	ExcludeInterfaces     []string
	BypassUIDs            []uint32
	BypassTCPPorts        []uint16
	BypassUDPPorts        []uint16
	ProxyOnlyTCPPorts     []uint16
	ProxyOnlyUDPPorts     []uint16
	InterceptOutput       bool
	RejectQUIC            bool
}

// DefaultGatewayPlan returns a complete plan with boxctl's ports and
// policy-routing identifiers.
func DefaultGatewayPlan(mode Mode) GatewayPlan {
	return GatewayPlan{
		Mode:           mode,
		DNSMode:        DNSDisabled,
		Table:          defaultTable,
		Owner:          defaultOwner,
		TProxyPort:     defaultTProxyPort,
		RedirectPort:   defaultRedirectPort,
		DNSPort:        defaultDNSPort,
		RouterDNSPort:  defaultRouterDNSPort,
		TProxyMark:     defaultTProxyMark,
		TUNMark:        defaultTUNMark,
		LoopMark:       defaultLoopMark,
		TProxyTable:    defaultTProxyTable,
		TUNTable:       defaultTUNTable,
		TProxyPriority: defaultTProxyPriority,
		TUNPriority:    defaultTUNPriority,
		TUNDevice:      defaultTUNDevice,
		BypassCIDRs:    append([]string(nil), defaultReservedCIDRs...),
		BypassTCPPorts: []uint16{7890, 7891, 7892, 7893, 7894},
		BypassUDPPorts: []uint16{7890, 7891, 7892, 7893, 7894},
	}
}

var nftIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,31}$`)
var interfaceName = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,15}$`)
var ownerName = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,64}$`)

func normalizedPlan(plan GatewayPlan) GatewayPlan {
	defaults := DefaultGatewayPlan(plan.Mode)
	if plan.DNSMode == "" {
		plan.DNSMode = defaults.DNSMode
	}
	if plan.Table == "" {
		plan.Table = defaults.Table
	}
	if plan.Owner == "" {
		plan.Owner = defaults.Owner
	}
	if plan.TProxyPort == 0 {
		plan.TProxyPort = defaults.TProxyPort
	}
	if plan.RedirectPort == 0 {
		plan.RedirectPort = defaults.RedirectPort
	}
	if plan.DNSPort == 0 {
		plan.DNSPort = defaults.DNSPort
	}
	if plan.RouterDNSPort == 0 {
		plan.RouterDNSPort = defaults.RouterDNSPort
	}
	if plan.TProxyMark == 0 {
		plan.TProxyMark = defaults.TProxyMark
	}
	if plan.TUNMark == 0 {
		plan.TUNMark = defaults.TUNMark
	}
	if plan.LoopMark == 0 {
		plan.LoopMark = defaults.LoopMark
	}
	if plan.TProxyTable == 0 {
		plan.TProxyTable = defaults.TProxyTable
	}
	if plan.TUNTable == 0 {
		plan.TUNTable = defaults.TUNTable
	}
	if plan.TProxyPriority == 0 {
		plan.TProxyPriority = defaults.TProxyPriority
	}
	if plan.TUNPriority == 0 {
		plan.TUNPriority = defaults.TUNPriority
	}
	if plan.TUNDevice == "" {
		plan.TUNDevice = defaults.TUNDevice
	}
	if !plan.BypassCIDRsConfigured {
		plan.BypassCIDRs = append([]string(nil), defaults.BypassCIDRs...)
		plan.BypassCIDRsConfigured = true
	}
	if plan.BypassTCPPorts == nil {
		plan.BypassTCPPorts = append([]uint16(nil), defaults.BypassTCPPorts...)
	}
	if plan.BypassUDPPorts == nil {
		plan.BypassUDPPorts = append([]uint16(nil), defaults.BypassUDPPorts...)
	}

	plan.CaptureCIDRs = normalizeCIDRs(plan.CaptureCIDRs)
	if len(plan.CaptureCIDRs) > 0 {
		plan.CaptureCIDRsConfigured = true
	}
	plan.BypassCIDRs = normalizeCIDRs(plan.BypassCIDRs)
	plan.SourceBypassCIDRs = normalizeCIDRs(plan.SourceBypassCIDRs)
	plan.ProxyServerCIDRs = normalizeCIDRs(plan.ProxyServerCIDRs)
	plan.IncludeInterfaces = normalizeStrings(plan.IncludeInterfaces)
	plan.ExcludeInterfaces = normalizeStrings(plan.ExcludeInterfaces)
	slices.Sort(plan.BypassUIDs)
	plan.BypassUIDs = slices.Compact(plan.BypassUIDs)
	plan.BypassTCPPorts = normalizePorts(plan.BypassTCPPorts)
	plan.BypassUDPPorts = normalizePorts(plan.BypassUDPPorts)
	plan.ProxyOnlyTCPPorts = normalizePorts(plan.ProxyOnlyTCPPorts)
	plan.ProxyOnlyUDPPorts = normalizePorts(plan.ProxyOnlyUDPPorts)
	return plan
}

func normalizePorts(values []uint16) []uint16 {
	result := append([]uint16(nil), values...)
	slices.Sort(result)
	return slices.Compact(result)
}

func normalizeStrings(values []string) []string {
	result := append([]string(nil), values...)
	slices.Sort(result)
	return slices.Compact(result)
}

func normalizeCIDRs(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		prefix, err := parseIPv4Prefix(value)
		if err != nil {
			result = append(result, value)
			continue
		}
		result = append(result, prefix.String())
	}
	slices.Sort(result)
	return slices.Compact(result)
}

func parseIPv4Prefix(value string) (netip.Prefix, error) {
	if address, err := netip.ParseAddr(value); err == nil {
		if !address.Is4() {
			return netip.Prefix{}, fmt.Errorf("not IPv4: %q", value)
		}
		return netip.PrefixFrom(address, 32), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("invalid IPv4 CIDR %q", value)
	}
	return prefix.Masked(), nil
}

// Validate rejects incomplete or unsafe plans before any command is executed.
func Validate(plan GatewayPlan) error {
	plan = normalizedPlan(plan)
	switch plan.Mode {
	case ModeTPROXY, ModeHYBRID, ModeTUN, ModeMIXED, ModeMIXED2:
	default:
		return fmt.Errorf("openwrt: unsupported gateway mode %q", plan.Mode)
	}
	switch plan.DNSMode {
	case DNSDisabled, DNSUpstream, DNSRedirect:
	default:
		return fmt.Errorf("openwrt: unsupported DNS mode %q", plan.DNSMode)
	}
	if !nftIdentifier.MatchString(plan.Table) {
		return fmt.Errorf("openwrt: unsafe nft table name %q", plan.Table)
	}
	if !ownerName.MatchString(plan.Owner) {
		return fmt.Errorf("openwrt: unsafe owner name %q", plan.Owner)
	}
	if !interfaceName.MatchString(plan.TUNDevice) {
		return fmt.Errorf("openwrt: invalid TUN device %q", plan.TUNDevice)
	}
	for _, value := range append(append([]string{}, plan.IncludeInterfaces...), plan.ExcludeInterfaces...) {
		if !interfaceName.MatchString(value) {
			return fmt.Errorf("openwrt: invalid interface name %q", value)
		}
	}
	for _, included := range plan.IncludeInterfaces {
		if slices.Contains(plan.ExcludeInterfaces, included) {
			return fmt.Errorf("openwrt: interface %q is both included and excluded", included)
		}
	}
	for _, list := range [][]string{plan.CaptureCIDRs, plan.BypassCIDRs, plan.SourceBypassCIDRs, plan.ProxyServerCIDRs} {
		for _, value := range list {
			if _, err := parseIPv4Prefix(value); err != nil {
				return err
			}
		}
	}
	if plan.CaptureCIDRsConfigured && len(plan.CaptureCIDRs) == 0 {
		return errors.New("openwrt: configured capture allowlist must not be empty")
	}
	if plan.TProxyMark == plan.TUNMark {
		return errors.New("openwrt: TPROXY and TUN marks must differ")
	}
	if plan.LoopMark == plan.TProxyMark || plan.LoopMark == plan.TUNMark {
		return errors.New("openwrt: loop mark must differ from capture marks")
	}
	for _, list := range [][]uint16{plan.BypassTCPPorts, plan.BypassUDPPorts, plan.ProxyOnlyTCPPorts, plan.ProxyOnlyUDPPorts} {
		if slices.Contains(list, 0) {
			return errors.New("openwrt: port lists must not contain zero")
		}
	}
	if plan.TProxyTable == plan.TUNTable || plan.TProxyPriority == plan.TUNPriority {
		return errors.New("openwrt: policy tables and priorities must be distinct")
	}
	if plan.TProxyTable < 1 || plan.TUNTable < 1 || plan.TProxyPriority < 1 || plan.TUNPriority < 1 {
		return errors.New("openwrt: invalid policy routing identifiers")
	}
	return nil
}

func planDigest(plan GatewayPlan) string {
	// Reconciliation must replace owned rules when rendering semantics change,
	// even if the user-facing plan stays identical. Bump this revision for any
	// incompatible renderer change so upgrades cannot retain a stale ruleset.
	const rendererRevision = 3
	encoded, _ := json.Marshal(struct {
		RendererRevision int         `json:"rendererRevision"`
		Plan             GatewayPlan `json:"plan"`
	}{RendererRevision: rendererRevision, Plan: plan})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func ownershipComment(plan GatewayPlan) string {
	return "managed-by=" + plan.Owner + " plan-sha256=" + planDigest(plan)
}

func ownerPrefix(plan GatewayPlan) string {
	return "managed-by=" + plan.Owner + " "
}

func hasOwnerPrefix(comment string, plan GatewayPlan) bool {
	return strings.HasPrefix(comment, ownerPrefix(plan))
}

// Render returns a deterministic nftables transaction body for a new table.
// DHCP client/server traffic (UDP 67/68) is always bypassed.
func Render(plan GatewayPlan) (string, error) {
	plan = normalizedPlan(plan)
	if err := Validate(plan); err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", plan.Table)
	fmt.Fprintf(&b, "\tcomment %s\n", strconv.Quote(ownershipComment(plan)))
	renderAddressSet(&b, "capture4", plan.CaptureCIDRs)
	renderAddressSet(&b, "bypass4", plan.BypassCIDRs)
	renderAddressSet(&b, "source_bypass4", plan.SourceBypassCIDRs)
	renderAddressSet(&b, "proxy_servers4", plan.ProxyServerCIDRs)
	renderUIDSet(&b, plan.BypassUIDs)

	// "mark" is a reserved token in current nftables (including OpenWrt
	// 25.12).  Using it as an unquoted chain name passes the in-memory golden
	// tests but is rejected by `nft -c` on the target platform.
	b.WriteString("\tchain mark_traffic {\n")
	renderCommonBypass(&b, plan, "iifname", false, plan.RejectQUIC, true)
	renderMarkRules(&b, plan)
	b.WriteString("\t}\n\n")

	b.WriteString("\tchain prerouting_mangle {\n")
	b.WriteString("\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	b.WriteString("\t\tct status dnat return\n")
	b.WriteString("\t\tjump mark_traffic\n")
	b.WriteString("\t}\n\n")

	if usesTProxyTCP(plan.Mode) || usesTProxyUDP(plan.Mode) {
		b.WriteString("\tchain prerouting_tproxy {\n")
		b.WriteString("\t\ttype filter hook prerouting priority dstnat; policy accept;\n")
		if usesTProxyTCP(plan.Mode) {
			fmt.Fprintf(&b, "\t\tmeta mark 0x%08x meta l4proto tcp tproxy ip to 127.0.0.1:%d\n", plan.TProxyMark, plan.TProxyPort)
		}
		if usesTProxyUDP(plan.Mode) {
			fmt.Fprintf(&b, "\t\tmeta mark 0x%08x meta l4proto udp tproxy ip to 127.0.0.1:%d\n", plan.TProxyMark, plan.TProxyPort)
		}
		b.WriteString("\t}\n\n")
	}

	if usesRedirectTCP(plan.Mode) {
		renderRedirectChain(&b, plan, "prerouting_redirect", "prerouting", "iifname")
	}

	if plan.InterceptOutput {
		b.WriteString("\tchain output_mark {\n")
		b.WriteString("\t\ttype route hook output priority mangle; policy accept;\n")
		b.WriteString("\t\tct status dnat return\n")
		renderCommonBypass(&b, plan, "oifname", true, false, true)
		renderMarkRules(&b, plan)
		b.WriteString("\t}\n\n")
		if usesRedirectTCP(plan.Mode) {
			renderRedirectChain(&b, plan, "output_redirect", "output", "oifname")
		}
	}

	if usesTUN(plan.Mode) {
		fmt.Fprintf(&b, "\tchain tun_input {\n\t\ttype filter hook input priority -10; policy accept;\n\t\tiifname %s accept\n\t}\n\n", strconv.Quote(plan.TUNDevice))
		fmt.Fprintf(&b, "\tchain tun_forward {\n\t\ttype filter hook forward priority -10; policy accept;\n\t\tiifname %s accept\n\t\toifname %s accept\n\t}\n\n", strconv.Quote(plan.TUNDevice), strconv.Quote(plan.TUNDevice))
	}

	if plan.DNSMode == DNSRedirect {
		b.WriteString("\tchain dns_redirect {\n")
		// Run before the mangle hook (-150). The following ct-status guard then
		// keeps DNS packets out of TPROXY/TUN capture after DNAT to the core.
		b.WriteString("\t\ttype nat hook prerouting priority -155; policy accept;\n")
		renderCommonBypass(&b, plan, "iifname", false, false, false)
		fmt.Fprintf(&b, "\t\ttcp dport %d redirect to :%d\n", plan.RouterDNSPort, plan.DNSPort)
		fmt.Fprintf(&b, "\t\tudp dport %d redirect to :%d\n", plan.RouterDNSPort, plan.DNSPort)
		b.WriteString("\t}\n\n")
	}

	b.WriteString("}\n")
	return b.String(), nil
}

func renderAddressSet(b *strings.Builder, name string, elements []string) {
	if len(elements) == 0 {
		return
	}
	fmt.Fprintf(b, "\tset %s {\n", name)
	b.WriteString("\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n")
	fmt.Fprintf(b, "\t\telements = { %s }\n", strings.Join(elements, ", "))
	b.WriteString("\t}\n\n")
}

func renderUIDSet(b *strings.Builder, values []uint32) {
	if len(values) == 0 {
		return
	}
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = strconv.FormatUint(uint64(value), 10)
	}
	b.WriteString("\tset bypass_uids {\n\t\ttype uid\n")
	fmt.Fprintf(b, "\t\telements = { %s }\n", strings.Join(parts, ", "))
	b.WriteString("\t}\n\n")
}

func renderCommonBypass(b *strings.Builder, plan GatewayPlan, interfaceExpression string, output bool, rejectQUIC bool, captureChain bool) {
	fmt.Fprintf(b, "\t\tmeta mark 0x%08x return\n", plan.LoopMark)
	b.WriteString("\t\tmeta mark & 0x0000ff00 != 0x00000000 return\n")
	if !output {
		// Traffic addressed to the router itself must stay on the local input
		// path. Reserved CIDRs alone are insufficient when a WAN interface owns
		// a public address; use the kernel FIB classification on prerouting.
		b.WriteString("\t\tfib daddr type local return\n")
	}
	b.WriteString("\t\tudp sport 67 udp dport 68 return\n")
	b.WriteString("\t\tudp sport 68 udp dport 67 return\n")
	if output {
		renderProtocolPorts(b, "tcp", "sport", plan.BypassTCPPorts, false)
		renderProtocolPorts(b, "udp", "sport", plan.BypassUDPPorts, false)
	} else {
		renderProtocolPorts(b, "tcp", "dport", plan.BypassTCPPorts, false)
		renderProtocolPorts(b, "udp", "dport", plan.BypassUDPPorts, false)
	}
	if output && len(plan.BypassUIDs) > 0 {
		b.WriteString("\t\tmeta skuid @bypass_uids return\n")
	}
	// Include/exclude interfaces describe ingress ownership. Applying the WAN
	// exclusion to a route/output chain would bypass every ordinary
	// router-originated packet before it can be marked. Output interception is
	// controlled independently by InterceptOutput.
	if !output {
		renderInterfaceBypass(b, plan, interfaceExpression)
	}
	if !output && len(plan.SourceBypassCIDRs) > 0 {
		b.WriteString("\t\tip saddr @source_bypass4 return\n")
	}
	// BLOCK_QUIC applies only in the shared prerouting mark chain, before
	// destination allowlists. Do not extend this setting
	// to router-originated output or duplicate it in redirect/DNS chains.
	if rejectQUIC {
		b.WriteString("\t\tudp dport 443 reject\n")
	}
	// A proxy endpoint must always bypass capture, including when its address is
	// also present in a selective AUTO pool. Otherwise the core's own outbound
	// connection can loop back into its transparent listener. Reserved networks
	// are different: an address explicitly selected for capture is allowed to
	// override that broad compatibility set.
	if len(plan.ProxyServerCIDRs) > 0 {
		b.WriteString("\t\tip daddr @proxy_servers4 return\n")
	}
	if !captureChain || !plan.CaptureCIDRsConfigured {
		if len(plan.BypassCIDRs) > 0 {
			b.WriteString("\t\tip daddr @bypass4 return\n")
		}
	}
	renderProtocolPorts(b, "tcp", "dport", plan.ProxyOnlyTCPPorts, true)
	renderProtocolPorts(b, "udp", "dport", plan.ProxyOnlyUDPPorts, true)
}

func renderInterfaceBypass(b *strings.Builder, plan GatewayPlan, expression string) {
	if len(plan.IncludeInterfaces) > 0 {
		fmt.Fprintf(b, "\t\t%s != { %s } return\n", expression, quoteStrings(plan.IncludeInterfaces))
	}
	if len(plan.ExcludeInterfaces) > 0 {
		fmt.Fprintf(b, "\t\t%s { %s } return\n", expression, quoteStrings(plan.ExcludeInterfaces))
	}
}

func quoteStrings(values []string) string {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = strconv.Quote(value)
	}
	return strings.Join(quoted, ", ")
}

func renderMarkRules(b *strings.Builder, plan GatewayPlan) {
	prefix := ""
	if plan.CaptureCIDRsConfigured {
		prefix = "ip daddr @capture4 "
	}
	if usesTProxyTCP(plan.Mode) {
		fmt.Fprintf(b, "\t\t%smeta l4proto tcp meta mark set 0x%08x\n", prefix, plan.TProxyMark)
	}
	if usesTProxyUDP(plan.Mode) {
		fmt.Fprintf(b, "\t\t%smeta l4proto udp meta mark set 0x%08x\n", prefix, plan.TProxyMark)
	}
	if usesTUNTCP(plan.Mode) {
		fmt.Fprintf(b, "\t\t%smeta l4proto tcp meta mark set 0x%08x\n", prefix, plan.TUNMark)
	}
	if usesTUNUDP(plan.Mode) {
		fmt.Fprintf(b, "\t\t%smeta l4proto udp meta mark set 0x%08x\n", prefix, plan.TUNMark)
	}
}

func renderRedirectChain(b *strings.Builder, plan GatewayPlan, name, hook, interfaceExpression string) {
	fmt.Fprintf(b, "\tchain %s {\n", name)
	fmt.Fprintf(b, "\t\ttype nat hook %s priority dstnat; policy accept;\n", hook)
	b.WriteString("\t\tct status dnat return\n")
	renderCommonBypass(b, plan, interfaceExpression, hook == "output", false, true)
	prefix := ""
	if plan.CaptureCIDRsConfigured {
		prefix = "ip daddr @capture4 "
	}
	fmt.Fprintf(b, "\t\t%smeta l4proto tcp redirect to :%d\n", prefix, plan.RedirectPort)
	b.WriteString("\t}\n\n")
}

func renderProtocolPorts(b *strings.Builder, protocol, direction string, ports []uint16, inverse bool) {
	if len(ports) == 0 {
		return
	}
	parts := make([]string, len(ports))
	for index, port := range ports {
		parts[index] = strconv.FormatUint(uint64(port), 10)
	}
	operator := ""
	if inverse {
		operator = " !="
	}
	fmt.Fprintf(b, "\t\t%s %s%s { %s } return\n", protocol, direction, operator, strings.Join(parts, ", "))
}

func usesTProxyTCP(mode Mode) bool   { return mode == ModeTPROXY || mode == ModeMIXED }
func usesTProxyUDP(mode Mode) bool   { return mode == ModeTPROXY || mode == ModeHYBRID }
func usesRedirectTCP(mode Mode) bool { return mode == ModeHYBRID || mode == ModeMIXED2 }
func usesTUNTCP(mode Mode) bool      { return mode == ModeTUN }
func usesTUNUDP(mode Mode) bool      { return mode == ModeTUN || mode == ModeMIXED || mode == ModeMIXED2 }
func usesTUN(mode Mode) bool         { return usesTUNTCP(mode) || usesTUNUDP(mode) }

type CheckResult struct {
	Exists          bool
	Owned           bool
	PlanMatches     bool
	PolicyMatches   bool
	FirewallMatches bool
	Comment         string
}

type nftListing struct {
	NFTables []struct {
		Table *struct {
			Family  string `json:"family"`
			Name    string `json:"name"`
			Comment string `json:"comment"`
		} `json:"table,omitempty"`
	} `json:"nftables"`
}

func inspectGatewayTable(ctx context.Context, runner Runner, plan GatewayPlan) (CheckResult, error) {
	result, err := runner.Run(ctx, Command{Name: "nft", Args: []string{"-j", "list", "table", "inet", plan.Table}})
	if err != nil {
		return CheckResult{}, err
	}
	if result.ExitCode != 0 {
		if nftObjectMissing(result.Stderr) {
			return CheckResult{}, nil
		}
		return CheckResult{}, fmt.Errorf("openwrt: inspect nft table: exit %d: %s", result.ExitCode, strings.TrimSpace(string(result.Stderr)))
	}
	var listing nftListing
	if err := json.Unmarshal(result.Stdout, &listing); err != nil {
		return CheckResult{}, fmt.Errorf("openwrt: parse nft table JSON: %w", err)
	}
	for _, object := range listing.NFTables {
		if object.Table == nil || object.Table.Family != "inet" || object.Table.Name != plan.Table {
			continue
		}
		comment := object.Table.Comment
		return CheckResult{
			Exists:      true,
			Owned:       hasOwnerPrefix(comment, plan),
			PlanMatches: comment == ownershipComment(plan),
			Comment:     comment,
		}, nil
	}
	return CheckResult{}, errors.New("openwrt: nft returned no matching table object")
}

func nftObjectMissing(stderr []byte) bool {
	message := strings.ToLower(string(stderr))
	return strings.Contains(message, "no such file") || strings.Contains(message, "does not exist") || strings.Contains(message, "not found")
}

// Check verifies the nft ownership/digest marker and protocol-owned policy
// rules/routes without treating otherwise identical foreign tuples as ours.
func Check(ctx context.Context, runner Runner, plan GatewayPlan) (CheckResult, error) {
	if runner == nil {
		return CheckResult{}, errors.New("openwrt: nil runner")
	}
	plan = normalizedPlan(plan)
	if err := Validate(plan); err != nil {
		return CheckResult{}, err
	}
	result, err := inspectGatewayTable(ctx, runner, plan)
	if err != nil || !result.Exists || !result.Owned || !result.PlanMatches {
		return result, err
	}
	result.PolicyMatches, err = checkPolicyRoutes(ctx, runner, plan)
	if err != nil {
		return result, err
	}
	firewall, err := inspectFirewallRules(ctx, runner, plan)
	result.FirewallMatches = err == nil && firewall.PlanMatches
	return result, err
}

// Apply preflights an atomic nft transaction and every selected policy
// priority/table, reconciles protocol-owned routes, and then commits the nft
// table. Foreign nft or policy state is never flushed or replaced.
func Apply(ctx context.Context, runner Runner, plan GatewayPlan) error {
	if runner == nil {
		return errors.New("openwrt: nil runner")
	}
	plan = normalizedPlan(plan)
	if err := Validate(plan); err != nil {
		return err
	}
	rendered, err := Render(plan)
	if err != nil {
		return err
	}
	current, err := inspectGatewayTable(ctx, runner, plan)
	if err != nil {
		return err
	}
	if current.Exists && !current.Owned {
		return fmt.Errorf("openwrt: refusing to replace foreign nft table inet %s", plan.Table)
	}
	firewall, err := inspectFirewallRules(ctx, runner, plan)
	if err != nil {
		return err
	}
	if current.PlanMatches && firewall.PlanMatches {
		return reconcilePolicyRoutes(ctx, runner, plan)
	}
	var transactionBuilder strings.Builder
	if !current.PlanMatches {
		if current.Exists {
			fmt.Fprintf(&transactionBuilder, "delete table inet %s\n", plan.Table)
		}
		transactionBuilder.WriteString(rendered)
	}
	if !firewall.PlanMatches {
		if err := renderFirewallReconcile(&transactionBuilder, plan, firewall); err != nil {
			return err
		}
	}
	transaction := transactionBuilder.String()
	if _, err := runOK(ctx, runner, Command{Name: "nft", Args: []string{"-c", "-f", "-"}, Stdin: []byte(transaction)}); err != nil {
		return fmt.Errorf("openwrt: nft preflight: %w", err)
	}
	if err := reconcilePolicyRoutes(ctx, runner, plan); err != nil {
		if !current.Exists {
			return errors.Join(err, cleanupPolicyRoutes(ctx, runner, plan))
		}
		return err
	}
	if _, err := runOK(ctx, runner, Command{Name: "nft", Args: []string{"-f", "-"}, Stdin: []byte(transaction)}); err != nil {
		applyErr := fmt.Errorf("openwrt: apply nft gateway: %w", err)
		// With no prior owned table the just-created policy tuples are ours and
		// can be rolled back. If replacing a table, deleting them could break the
		// still-active old transaction, so leave them for the next reconcile.
		if !current.Exists {
			return errors.Join(applyErr, cleanupPolicyRoutes(ctx, runner, plan))
		}
		return applyErr
	}
	return nil
}

// Cleanup removes only a table carrying the matching owner marker, owned fw4
// rules, and policy objects matching the current plan's exact tuple and shape.
// Missing nft state does not skip policy cleanup: a crash may happen after
// routes are installed but before the nft transaction is committed.
func Cleanup(ctx context.Context, runner Runner, plan GatewayPlan) error {
	if runner == nil {
		return errors.New("openwrt: nil runner")
	}
	plan = normalizedPlan(plan)
	if err := Validate(plan); err != nil {
		return err
	}
	current, tableErr := inspectGatewayTable(ctx, runner, plan)
	var ownershipErr error
	if current.Exists && !current.Owned {
		ownershipErr = fmt.Errorf("openwrt: refusing to delete foreign nft table inet %s", plan.Table)
	}
	firewall, firewallErr := inspectFirewallRules(ctx, runner, plan)
	var nftErr error
	deleteTable := tableErr == nil && ownershipErr == nil && current.Exists
	if deleteTable || len(firewall.OwnedRules) > 0 {
		var transaction strings.Builder
		if firewallErr == nil {
			for _, rule := range firewall.OwnedRules {
				fmt.Fprintf(&transaction, "delete rule inet fw4 %s handle %d\n", rule.Chain, rule.Handle)
			}
		}
		if deleteTable {
			fmt.Fprintf(&transaction, "delete table inet %s\n", plan.Table)
		}
		if _, err := runOK(ctx, runner, Command{Name: "nft", Args: []string{"-c", "-f", "-"}, Stdin: []byte(transaction.String())}); err != nil {
			nftErr = fmt.Errorf("openwrt: cleanup nft preflight: %w", err)
		} else if _, err := runOK(ctx, runner, Command{Name: "nft", Args: []string{"-f", "-"}, Stdin: []byte(transaction.String())}); err != nil {
			nftErr = err
		}
	}
	// Policy objects have an independent protocol plus exact-shape ownership
	// contract and can be cleaned even when nft inspection failed.
	policyErr := cleanupPolicyRoutes(ctx, runner, plan)
	return errors.Join(tableErr, ownershipErr, firewallErr, nftErr, policyErr)
}
