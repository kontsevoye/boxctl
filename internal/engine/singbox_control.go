package engine

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

var singBoxCapabilities = Capabilities{
	HotReload:           false,
	Proxies:             true,
	Groups:              true,
	Selection:           true,
	Delay:               true,
	ProxyProviders:      false,
	RuleProviders:       false,
	Rules:               true,
	Connections:         true,
	CloseConnection:     true,
	CloseAllConnections: true,
	RoutingMode:         false,
	TrafficStream:       true,
	RuleMutation:        false,
	ProcessLogs:         true,
}

// SingBoxLog is the Clash API log event shape implemented by sing-box.
type SingBoxLog = MihomoLog

// SingBoxController adapts sing-box's Clash API to the engine-neutral Control
// contract. Provider endpoints and hot reload are deliberately not emulated:
// sing-box exposes provider stubs and PUT /configs does not reload its native
// configuration.
type SingBoxController struct {
	clash *MihomoController
}

func NewSingBoxController(endpoint ControllerEndpoint, client *http.Client) (*SingBoxController, error) {
	clash, err := NewMihomoController(endpoint, client)
	if err != nil {
		return nil, singBoxControllerError(err)
	}
	return &SingBoxController{clash: clash}, nil
}

func (c *SingBoxController) Capabilities() Capabilities { return singBoxCapabilities }

func (c *SingBoxController) Version(ctx context.Context) (string, error) {
	value, err := c.clash.Version(ctx)
	return value, singBoxControllerError(err)
}

func (c *SingBoxController) Reload(context.Context, string) error {
	return unsupported(CapabilityHotReload)
}

func (c *SingBoxController) Proxies(ctx context.Context) ([]Proxy, error) {
	value, err := c.clash.Proxies(ctx)
	return value, singBoxControllerError(err)
}

func (c *SingBoxController) Groups(ctx context.Context) ([]ProxyGroup, error) {
	value, err := c.clash.Groups(ctx)
	return value, singBoxControllerError(err)
}

func (c *SingBoxController) Select(ctx context.Context, group, proxy string) error {
	return singBoxControllerError(c.clash.Select(ctx, group, proxy))
}

func (c *SingBoxController) Delay(ctx context.Context, proxy, testURL string, timeout time.Duration) (time.Duration, error) {
	value, err := c.clash.Delay(ctx, proxy, testURL, timeout)
	return value, singBoxControllerError(err)
}

func (c *SingBoxController) Providers(_ context.Context, kind ProviderKind) ([]Provider, error) {
	return nil, unsupported(providerCapability(kind))
}

func (c *SingBoxController) UpdateProvider(_ context.Context, kind ProviderKind, _ string) error {
	return unsupported(providerCapability(kind))
}

func (c *SingBoxController) Rules(ctx context.Context) ([]Rule, error) {
	value, err := c.clash.Rules(ctx)
	return value, singBoxControllerError(err)
}

func (c *SingBoxController) Connections(ctx context.Context) (ConnectionsSnapshot, error) {
	value, err := c.clash.Connections(ctx)
	return value, singBoxControllerError(err)
}

func (c *SingBoxController) StreamConnections(ctx context.Context, interval time.Duration) (<-chan ConnectionsSnapshot, error) {
	value, err := c.clash.StreamConnections(ctx, interval)
	return value, singBoxControllerError(err)
}

func (c *SingBoxController) CloseConnection(ctx context.Context, id string) error {
	return singBoxControllerError(c.clash.CloseConnection(ctx, id))
}

func (c *SingBoxController) CloseAllConnections(ctx context.Context) error {
	return singBoxControllerError(c.clash.CloseAllConnections(ctx))
}

func (*SingBoxController) RoutingMode(context.Context) (RoutingMode, error) {
	return "", unsupported(CapabilityRoutingMode)
}

func (*SingBoxController) SetRoutingMode(context.Context, RoutingMode) error {
	return unsupported(CapabilityRoutingMode)
}

func (c *SingBoxController) StreamTraffic(ctx context.Context) (<-chan TrafficSnapshot, error) {
	value, err := c.clash.StreamTraffic(ctx)
	return value, singBoxControllerError(err)
}

func (c *SingBoxController) StreamLogs(ctx context.Context) (<-chan SingBoxLog, error) {
	value, err := c.clash.StreamLogs(ctx)
	return value, singBoxControllerError(err)
}

func singBoxControllerError(err error) error {
	if err == nil || errors.Is(err, ErrUnsupported) {
		return err
	}
	message := strings.ReplaceAll(err.Error(), "Mihomo", "sing-box")
	message = strings.ReplaceAll(message, "mihomo", "sing-box")
	return singBoxClashError{message: message, cause: err}
}

type singBoxClashError struct {
	message string
	cause   error
}

func (e singBoxClashError) Error() string { return e.message }
func (e singBoxClashError) Unwrap() error { return e.cause }

func providerCapability(kind ProviderKind) Capability {
	if kind == ProviderRule {
		return CapabilityRuleProviders
	}
	return CapabilityProxyProviders
}

var _ Control = (*SingBoxController)(nil)
