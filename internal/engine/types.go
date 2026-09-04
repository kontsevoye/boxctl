// Package engine defines core-neutral proxy engine contracts and concrete
// drivers. Platform firewall and routing code consumes CapturePlan and does not
// need to understand an engine's native configuration format.
package engine

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"time"
)

var (
	// ErrUnsupported identifies an operation that the active engine does not
	// advertise through Capabilities.
	ErrUnsupported = errors.New("engine capability is unsupported")
	// ErrAlreadyRunning is returned when Start would replace a live process.
	ErrAlreadyRunning = errors.New("engine is already running")
	// ErrNotRunning is returned when an operation requires a live process.
	ErrNotRunning = errors.New("engine is not running")
	// ErrProcessStateNotOwned means the shared persisted process record belongs
	// to another known engine. Multi-engine adoption probes should continue with
	// that owner instead of treating the record as corrupt.
	ErrProcessStateNotOwned = errors.New("process state belongs to another engine")
)

// Capability is a stable name suitable for logs, APIs and feature gates.
type Capability string

const (
	CapabilityHotReload           Capability = "hot-reload"
	CapabilityProxies             Capability = "proxies"
	CapabilityGroups              Capability = "groups"
	CapabilitySelection           Capability = "selection"
	CapabilityDelay               Capability = "delay"
	CapabilityProxyProviders      Capability = "proxy-providers"
	CapabilityRuleProviders       Capability = "rule-providers"
	CapabilityRules               Capability = "rules"
	CapabilityConnections         Capability = "connections"
	CapabilityCloseConnection     Capability = "close-connection"
	CapabilityCloseAllConnections Capability = "close-all-connections"
	CapabilityRoutingMode         Capability = "routing-mode"
	CapabilityTrafficStream       Capability = "traffic-stream"
	CapabilityRuleMutation        Capability = "rule-mutation"
	CapabilityProcessLogs         Capability = "process-logs"
)

// Capabilities declares optional control-plane behavior. Unsupported methods
// return an error wrapping ErrUnsupported rather than pretending to succeed.
type Capabilities struct {
	HotReload           bool
	Proxies             bool
	Groups              bool
	Selection           bool
	Delay               bool
	ProxyProviders      bool
	RuleProviders       bool
	Rules               bool
	Connections         bool
	CloseConnection     bool
	CloseAllConnections bool
	RoutingMode         bool
	TrafficStream       bool
	RuleMutation        bool
	ProcessLogs         bool
}

// Supports reports whether a named optional feature is present.
func (c Capabilities) Supports(capability Capability) bool {
	switch capability {
	case CapabilityHotReload:
		return c.HotReload
	case CapabilityProxies:
		return c.Proxies
	case CapabilityGroups:
		return c.Groups
	case CapabilitySelection:
		return c.Selection
	case CapabilityDelay:
		return c.Delay
	case CapabilityProxyProviders:
		return c.ProxyProviders
	case CapabilityRuleProviders:
		return c.RuleProviders
	case CapabilityRules:
		return c.Rules
	case CapabilityConnections:
		return c.Connections
	case CapabilityCloseConnection:
		return c.CloseConnection
	case CapabilityCloseAllConnections:
		return c.CloseAllConnections
	case CapabilityRoutingMode:
		return c.RoutingMode
	case CapabilityTrafficStream:
		return c.TrafficStream
	case CapabilityRuleMutation:
		return c.RuleMutation
	case CapabilityProcessLogs:
		return c.ProcessLogs
	default:
		return false
	}
}

// CaptureMethod is how one protocol is delivered to a core.
type CaptureMethod string

const (
	CaptureNone     CaptureMethod = "none"
	CaptureTPROXY   CaptureMethod = "tproxy"
	CaptureRedirect CaptureMethod = "redirect"
	CaptureTUN      CaptureMethod = "tun"
)

// ProtocolCapture describes one TCP or UDP ingress. Port is required for
// tproxy/redirect and must be zero for none/tun.
type ProtocolCapture struct {
	Method CaptureMethod
	Port   uint16
}

// DNSEndpoint is the core listener targeted by the platform DNS policy.
type DNSEndpoint struct {
	Enabled bool
	Host    string
	Port    uint16
}

// DestinationCaptureMode describes whether the platform should intercept all
// otherwise eligible destinations or only an explicit set.  The zero value is
// intentionally the broad/all mode so active generations written by older
// versions keep their original meaning when decoded.
type DestinationCaptureMode string

const (
	DestinationCaptureAll       DestinationCaptureMode = ""
	DestinationCaptureAllowlist DestinationCaptureMode = "allowlist"
)

// DestinationCapture is an engine-neutral destination policy. CIDRs contains
// the complete effective set (for Mihomo fake-IP this is the synthetic range
// plus any manual and generated real-address ranges).
type DestinationCapture struct {
	Mode  DestinationCaptureMode
	CIDRs []netip.Prefix
}

// CapturePlan is the complete core-facing contract consumed by a platform
// firewall planner. It intentionally contains no nftables or iptables syntax.
type CapturePlan struct {
	TCP       ProtocolCapture
	UDP       ProtocolCapture
	DNS       DNSEndpoint
	TUNDevice string
	TUNStack  string
	// TUNAddresses and TUNMTU are engine-neutral interface parameters. An
	// empty address list lets a concrete preparer select its documented
	// compatibility default; callers should normally provide a prefix chosen
	// after checking LAN and VPN overlap.
	TUNAddresses        []netip.Prefix
	TUNMTU              uint32
	LoopMark            uint32
	FakeIPRanges        []netip.Prefix
	Destinations        DestinationCapture
	EndpointBypassCIDRs []netip.Prefix
	Capabilities        Capabilities
}

// Validate rejects contradictory plans before either a config or firewall is
// changed.
func (p CapturePlan) Validate() error {
	if err := validateProtocolCapture("TCP", p.TCP); err != nil {
		return err
	}
	if err := validateProtocolCapture("UDP", p.UDP); err != nil {
		return err
	}
	if (p.TCP.Method == CaptureTUN || p.UDP.Method == CaptureTUN) && p.TUNDevice == "" {
		return errors.New("TUN capture requires a device")
	}
	for _, prefix := range p.TUNAddresses {
		if !prefix.IsValid() {
			return errors.New("capture plan contains an invalid TUN address")
		}
	}
	if p.DNS.Enabled && p.DNS.Port == 0 {
		return errors.New("enabled DNS endpoint requires a port")
	}
	if !p.DNS.Enabled && (p.DNS.Host != "" || p.DNS.Port != 0) {
		return errors.New("disabled DNS endpoint must be empty")
	}
	for _, prefix := range p.FakeIPRanges {
		if !prefix.IsValid() {
			return errors.New("capture plan contains an invalid fake-IP range")
		}
	}
	for _, prefix := range p.EndpointBypassCIDRs {
		if !prefix.IsValid() || !prefix.Addr().Is4() {
			return errors.New("capture plan contains an invalid IPv4 endpoint bypass")
		}
	}
	switch p.Destinations.Mode {
	case DestinationCaptureAll:
		if len(p.Destinations.CIDRs) != 0 {
			return errors.New("all-destination capture must not specify CIDRs")
		}
	case DestinationCaptureAllowlist:
		if len(p.Destinations.CIDRs) == 0 {
			return errors.New("destination allowlist capture requires at least one CIDR")
		}
		for _, prefix := range p.Destinations.CIDRs {
			if !prefix.IsValid() {
				return errors.New("destination allowlist contains an invalid CIDR")
			}
		}
	default:
		return errors.New("destination capture mode is unknown")
	}
	return nil
}

func validateProtocolCapture(protocol string, capture ProtocolCapture) error {
	switch capture.Method {
	case CaptureNone, CaptureTUN:
		if capture.Port != 0 {
			return errors.New(protocol + " none/tun capture must not specify a port")
		}
	case CaptureTPROXY, CaptureRedirect:
		if capture.Port == 0 {
			return errors.New(protocol + " tproxy/redirect capture requires a port")
		}
	default:
		return errors.New(protocol + " capture method is unknown")
	}
	return nil
}

// ControllerEndpoint separates the core listen value written to native config
// from the URL used by the local management client.
type ControllerEndpoint struct {
	Listen  string
	BaseURL string
	Secret  string
}

// PreparedCore is an immutable launch description returned by Config.Prepare.
// SourceConfigPath always remains user-owned; only RuntimeConfigPath is passed
// to the process.
type PreparedCore struct {
	Engine           string
	BinaryPath       string
	SourceConfigPath string
	// SourceRevision is a caller-computed identity of the exact user profile
	// from which this runtime was prepared. It is persisted for crash recovery
	// but never interpreted by an engine driver.
	SourceRevision    string
	RuntimeConfigPath string
	HomeDir           string
	Args              []string
	Env               []string
	Capture           CapturePlan
	Controller        ControllerEndpoint
	Capabilities      Capabilities

	// Runtime ownership is set only by a concrete engine preparer. Keeping both
	// values private prevents external callers from marking arbitrary files as
	// disposable runtime state or substituting another file inside the temp dir.
	runtimeConfigRoot      string
	runtimeConfigOwnedPath string
}

// PrepareRequest contains only core-neutral settings. A concrete Config
// implementation translates the CapturePlan into native YAML or JSON.
type PrepareRequest struct {
	BinaryPath       string
	SourceConfigPath string
	// RuntimeDir is an existing base directory. Concrete engines must create
	// an unguessable private child directory rather than storing runtime state
	// directly in this shared base.
	RuntimeDir string
	HomeDir    string
	Capture    CapturePlan
	Controller ControllerEndpoint
}

// Config owns native config preparation and validation.
type Config interface {
	Prepare(context.Context, PrepareRequest) (PreparedCore, error)
	Validate(context.Context, PreparedCore) error
}

// Runtime owns exactly one supervised process.
type Runtime interface {
	Start(context.Context, PreparedCore) error
	Stop(context.Context) error
	Reload(context.Context, PreparedCore) error
	Health(context.Context) (HealthStatus, error)
	Version(context.Context, string) (string, error)
	Logs() <-chan LogEntry
}

// Control is the optional interactive control plane exposed to the UI.
type Control interface {
	Proxies(context.Context) ([]Proxy, error)
	Groups(context.Context) ([]ProxyGroup, error)
	Select(context.Context, string, string) error
	Delay(context.Context, string, string, time.Duration) (time.Duration, error)
	Providers(context.Context, ProviderKind) ([]Provider, error)
	UpdateProvider(context.Context, ProviderKind, string) error
	Rules(context.Context) ([]Rule, error)
	Connections(context.Context) (ConnectionsSnapshot, error)
	StreamConnections(context.Context, time.Duration) (<-chan ConnectionsSnapshot, error)
	CloseConnection(context.Context, string) error
	CloseAllConnections(context.Context) error
	RoutingMode(context.Context) (RoutingMode, error)
	SetRoutingMode(context.Context, RoutingMode) error
	StreamTraffic(context.Context) (<-chan TrafficSnapshot, error)
}

// ReleaseSource is kept separate from Runtime so an installer can download a
// core before a driver exists and can verify it before replacement.
type ReleaseSource interface {
	Latest(context.Context) (Release, error)
	Open(context.Context, ReleaseAsset) (io.ReadCloser, error)
}

// HealthStatus distinguishes process liveness, controller readiness and the
// optional local DNS listener readiness.
type HealthStatus struct {
	Running         bool
	ControllerReady bool
	DNSReady        bool
	PID             int
	Version         string
	StartedAt       time.Time
	CheckedAt       time.Time
	LastExitError   string
}

// LogEntry is a bounded, non-blocking process log event.
type LogEntry struct {
	Sequence uint64
	Time     time.Time
	Stream   string
	Message  string
}

type DelaySample struct {
	Time  string `json:"time,omitempty"`
	Delay int    `json:"delay,omitempty"`
}

type Proxy struct {
	Name    string
	Type    string
	Icon    string
	UDP     bool
	Alive   *bool
	Now     string
	All     []string
	History []DelaySample
}

type ProxyGroup struct {
	Name    string
	Type    string
	Icon    string
	Now     string
	Members []string
	Options []Proxy
	History []DelaySample
}

// RoutingMode is Mihomo's global routing decision mode. Keeping it in the
// engine-neutral control contract lets another core report the operation as
// unsupported instead of leaking a native /configs call into the web layer.
type RoutingMode string

const (
	RoutingModeRule   RoutingMode = "rule"
	RoutingModeGlobal RoutingMode = "global"
	RoutingModeDirect RoutingMode = "direct"
)

func (mode RoutingMode) Valid() bool {
	switch mode {
	case RoutingModeRule, RoutingModeGlobal, RoutingModeDirect:
		return true
	default:
		return false
	}
}

type ProviderKind string

const (
	ProviderProxy ProviderKind = "proxy"
	ProviderRule  ProviderKind = "rule"
)

type Provider struct {
	Name             string
	Type             string
	VehicleType      string
	Path             string
	UpdatedAt        string
	ProxyCount       int
	RuleCount        int
	Behavior         string
	Format           string
	SubscriptionInfo *ProviderSubscriptionInfo
	HealthCheck      ProviderHealthCheck
}

type ProviderSubscriptionInfo struct {
	Upload   int64 `json:"upload,omitempty"`
	Download int64 `json:"download,omitempty"`
	Total    int64 `json:"total,omitempty"`
	Expire   int64 `json:"expire,omitempty"`
}

type ProviderHealthCheck struct {
	Enabled  bool  `json:"enabled"`
	Interval int64 `json:"interval,omitempty"`
	Lazy     bool  `json:"lazy,omitempty"`
}

type Rule struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
	Size    int    `json:"size,omitempty"`
}

type ConnectionMetadata struct {
	Network         string `json:"network"`
	Type            string `json:"type"`
	SourceIP        string `json:"sourceIP"`
	SourcePort      string `json:"sourcePort"`
	DestinationIP   string `json:"destinationIP"`
	DestinationPort string `json:"destinationPort"`
	Host            string `json:"host"`
	DNSMode         string `json:"dnsMode"`
}

type Connection struct {
	ID          string             `json:"id"`
	Metadata    ConnectionMetadata `json:"metadata"`
	Upload      int64              `json:"upload"`
	Download    int64              `json:"download"`
	Start       string             `json:"start"`
	Chains      []string           `json:"chains"`
	Rule        string             `json:"rule"`
	RulePayload string             `json:"rulePayload"`
}

type ConnectionsSnapshot struct {
	DownloadTotal int64        `json:"downloadTotal"`
	UploadTotal   int64        `json:"uploadTotal"`
	Memory        int64        `json:"memory"`
	Connections   []Connection `json:"connections"`
	CapturedAt    time.Time    `json:"-"`
}

type TrafficSnapshot struct {
	UploadRateBytes   int64     `json:"up"`
	DownloadRateBytes int64     `json:"down"`
	CapturedAt        time.Time `json:"-"`
}

type Release struct {
	Tag         string
	Name        string
	PublishedAt time.Time
	Assets      []ReleaseAsset
}

type ReleaseAsset struct {
	Name        string
	URL         string
	Size        int64
	ContentType string
}
