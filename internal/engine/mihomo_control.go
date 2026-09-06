package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

const (
	maxControllerResponse      = 32 << 20
	defaultConnectionsInterval = time.Second
	minimumConnectionsInterval = 250 * time.Millisecond
	maximumConnectionsInterval = time.Minute
	defaultStreamSetupTimeout  = 15 * time.Second
	minimumStreamReadTimeout   = 2 * time.Second
	defaultTrafficReadTimeout  = 15 * time.Second
	defaultLogReadTimeout      = 45 * time.Second
)

type MihomoLog struct {
	Level   string `json:"type"`
	Message string `json:"payload"`
}

// MihomoController is a context-aware client for the Mihomo external
// controller. It is safe for concurrent use.
type MihomoController struct {
	baseURL string
	secret  string
	client  *http.Client
}

func NewMihomoController(endpoint ControllerEndpoint, client *http.Client) (*MihomoController, error) {
	base := strings.TrimRight(endpoint.BaseURL, "/")
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid Mihomo controller URL %q", endpoint.BaseURL)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported Mihomo controller scheme %q", parsed.Scheme)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("mihomo controller base URL must not contain query or fragment")
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &MihomoController{baseURL: base, secret: endpoint.Secret, client: client}, nil
}

func (c *MihomoController) Version(ctx context.Context) (string, error) {
	var response struct {
		Version string `json:"version"`
		Meta    bool   `json:"meta"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/version", nil, nil, &response, http.StatusOK); err != nil {
		return "", err
	}
	if response.Version == "" {
		return "", errors.New("mihomo controller returned an empty version")
	}
	return response.Version, nil
}

// Reload uses Mihomo's native inline-config API. A manager-owned runtime can
// live outside Mihomo's home (notably in /tmp), where the path API rejects it.
func (c *MihomoController) Reload(ctx context.Context, runtimeConfig []byte) error {
	if len(bytes.TrimSpace(runtimeConfig)) == 0 || len(runtimeConfig) > maxControllerResponse {
		return errors.New("mihomo reload config is empty or exceeds size limit")
	}
	payload := struct {
		Payload string `json:"payload"`
	}{Payload: string(runtimeConfig)}
	query := url.Values{"force": []string{"true"}}
	return c.doJSON(ctx, http.MethodPut, "/configs", query, payload, nil, http.StatusOK, http.StatusNoContent)
}

func (c *MihomoController) Proxies(ctx context.Context) ([]Proxy, error) {
	var response struct {
		Proxies map[string]struct {
			Name    string        `json:"name"`
			Type    string        `json:"type"`
			Icon    string        `json:"icon"`
			UDP     bool          `json:"udp"`
			Alive   *bool         `json:"alive"`
			Now     string        `json:"now"`
			All     []string      `json:"all"`
			History []DelaySample `json:"history"`
		} `json:"proxies"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/proxies", nil, nil, &response, http.StatusOK); err != nil {
		return nil, err
	}
	proxies := make([]Proxy, 0, len(response.Proxies))
	for mapName, item := range response.Proxies {
		name := item.Name
		if name == "" {
			name = mapName
		}
		proxies = append(proxies, Proxy{
			Name:    name,
			Type:    item.Type,
			Icon:    item.Icon,
			UDP:     item.UDP,
			Alive:   item.Alive,
			Now:     item.Now,
			All:     append([]string(nil), item.All...),
			History: append([]DelaySample(nil), item.History...),
		})
	}
	sort.Slice(proxies, func(i, j int) bool { return proxies[i].Name < proxies[j].Name })
	return proxies, nil
}

func (c *MihomoController) Groups(ctx context.Context) ([]ProxyGroup, error) {
	proxies, err := c.Proxies(ctx)
	if err != nil {
		return nil, err
	}
	proxiesByName := make(map[string]Proxy, len(proxies))
	for _, proxy := range proxies {
		proxiesByName[proxy.Name] = proxy
	}
	groups := make([]ProxyGroup, 0)
	for _, proxy := range proxies {
		if len(proxy.All) == 0 && !knownGroupType(proxy.Type) {
			continue
		}
		options := make([]Proxy, 0, len(proxy.All))
		for _, name := range proxy.All {
			option, ok := proxiesByName[name]
			if !ok {
				option = Proxy{Name: name}
			}
			option.All = append([]string(nil), option.All...)
			option.History = append([]DelaySample(nil), option.History...)
			options = append(options, option)
		}
		groups = append(groups, ProxyGroup{
			Name:    proxy.Name,
			Type:    proxy.Type,
			Icon:    proxy.Icon,
			Now:     proxy.Now,
			Members: append([]string(nil), proxy.All...),
			Options: options,
			History: append([]DelaySample(nil), proxy.History...),
		})
	}
	return groups, nil
}

func knownGroupType(value string) bool {
	switch strings.ToLower(strings.ReplaceAll(value, "-", "")) {
	case "selector", "urltest", "fallback", "loadbalance", "relay":
		return true
	default:
		return false
	}
}

func (c *MihomoController) Select(ctx context.Context, group, proxy string) error {
	if group == "" || proxy == "" {
		return errors.New("group and proxy names are required")
	}
	payload := struct {
		Name string `json:"name"`
	}{Name: proxy}
	return c.doJSON(ctx, http.MethodPut, "/proxies/"+url.PathEscape(group), nil, payload, nil, http.StatusOK, http.StatusNoContent)
}

func (c *MihomoController) Delay(ctx context.Context, proxy, testURL string, timeout time.Duration) (time.Duration, error) {
	if proxy == "" || testURL == "" {
		return 0, errors.New("proxy name and test URL are required")
	}
	if timeout <= 0 {
		return 0, errors.New("delay timeout must be positive")
	}
	timeoutMillis := timeout.Milliseconds()
	if timeoutMillis <= 0 {
		timeoutMillis = 1
	}
	query := url.Values{
		"url":     []string{testURL},
		"timeout": []string{strconv.FormatInt(timeoutMillis, 10)},
	}
	var response struct {
		Delay int64 `json:"delay"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/proxies/"+url.PathEscape(proxy)+"/delay", query, nil, &response, http.StatusOK); err != nil {
		return 0, err
	}
	if response.Delay < 0 {
		return 0, errors.New("mihomo returned a negative delay")
	}
	return time.Duration(response.Delay) * time.Millisecond, nil
}

func (c *MihomoController) Providers(ctx context.Context, kind ProviderKind) ([]Provider, error) {
	path, err := providerPath(kind)
	if err != nil {
		return nil, err
	}
	var response struct {
		Providers map[string]struct {
			Name             string                    `json:"name"`
			Type             string                    `json:"type"`
			VehicleType      string                    `json:"vehicleType"`
			Path             string                    `json:"path"`
			UpdatedAt        string                    `json:"updatedAt"`
			Proxies          []json.RawMessage         `json:"proxies"`
			RuleCount        int                       `json:"ruleCount"`
			Behavior         string                    `json:"behavior"`
			Format           string                    `json:"format"`
			SubscriptionInfo *ProviderSubscriptionInfo `json:"subscriptionInfo"`
			HealthCheck      struct {
				Enable   bool  `json:"enable"`
				Interval int64 `json:"interval"`
				Lazy     bool  `json:"lazy"`
			} `json:"healthCheck"`
		} `json:"providers"`
	}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &response, http.StatusOK); err != nil {
		return nil, err
	}
	providers := make([]Provider, 0, len(response.Providers))
	for mapName, item := range response.Providers {
		name := item.Name
		if name == "" {
			name = mapName
		}
		providers = append(providers, Provider{
			Name:             name,
			Type:             item.Type,
			VehicleType:      item.VehicleType,
			Path:             item.Path,
			UpdatedAt:        item.UpdatedAt,
			ProxyCount:       len(item.Proxies),
			RuleCount:        item.RuleCount,
			Behavior:         item.Behavior,
			Format:           item.Format,
			SubscriptionInfo: item.SubscriptionInfo,
			HealthCheck: ProviderHealthCheck{
				Enabled: item.HealthCheck.Enable, Interval: item.HealthCheck.Interval, Lazy: item.HealthCheck.Lazy,
			},
		})
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].Name < providers[j].Name })
	return providers, nil
}

func (c *MihomoController) UpdateProvider(ctx context.Context, kind ProviderKind, name string) error {
	path, err := providerPath(kind)
	if err != nil {
		return err
	}
	if name == "" {
		return errors.New("provider name is required")
	}
	return c.doJSON(ctx, http.MethodPut, path+"/"+url.PathEscape(name), nil, nil, nil, http.StatusOK, http.StatusNoContent)
}

func providerPath(kind ProviderKind) (string, error) {
	switch kind {
	case ProviderProxy:
		return "/providers/proxies", nil
	case ProviderRule:
		return "/providers/rules", nil
	default:
		return "", fmt.Errorf("unknown provider kind %q", kind)
	}
}

func (c *MihomoController) Rules(ctx context.Context) ([]Rule, error) {
	var response struct {
		Rules []Rule `json:"rules"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/rules", nil, nil, &response, http.StatusOK); err != nil {
		return nil, err
	}
	return response.Rules, nil
}

func (c *MihomoController) Connections(ctx context.Context) (ConnectionsSnapshot, error) {
	var response ConnectionsSnapshot
	if err := c.doJSON(ctx, http.MethodGet, "/connections", nil, nil, &response, http.StatusOK); err != nil {
		return ConnectionsSnapshot{}, err
	}
	response.CapturedAt = time.Now()
	return response, nil
}

// StreamConnections consumes Mihomo's native WebSocket snapshots. The caller
// owns ctx; canceling it closes both the socket and the returned channel.
func (c *MihomoController) StreamConnections(ctx context.Context, interval time.Duration) (<-chan ConnectionsSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	interval = boundedConnectionsInterval(interval)
	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse Mihomo controller URL: %w", err)
	}
	if parsed.Scheme == "https" {
		parsed.Scheme = "wss"
	} else {
		parsed.Scheme = "ws"
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/connections"
	parsed.RawQuery = url.Values{
		"interval": []string{strconv.FormatInt(interval.Milliseconds(), 10)},
	}.Encode()

	streamClient := *c.client
	if streamClient.Timeout <= 0 {
		streamClient.Timeout = defaultStreamSetupTimeout
	}
	headers := make(http.Header)
	if c.secret != "" {
		headers.Set("Authorization", "Bearer "+c.secret)
	}
	// coder/websocket converts HTTPClient.Timeout into a setup-only context and
	// clears the cloned client's timeout after the upgrade, so the handshake is
	// bounded without imposing a lifetime limit on the live socket.
	connection, response, err := websocket.Dial(ctx, parsed.String(), &websocket.DialOptions{
		HTTPClient: &streamClient,
		HTTPHeader: headers,
	})
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, fmt.Errorf("open Mihomo connections stream: %w", err)
	}
	connection.SetReadLimit(maxControllerResponse)

	stream := make(chan ConnectionsSnapshot, 1)
	go func() {
		defer close(stream)
		defer func() { _ = connection.CloseNow() }()
		for {
			var snapshot ConnectionsSnapshot
			readContext, cancelRead := context.WithTimeout(ctx, connectionsReadTimeout(interval))
			err := wsjson.Read(readContext, connection, &snapshot)
			cancelRead()
			if err != nil {
				return
			}
			snapshot.CapturedAt = time.Now()
			select {
			case stream <- snapshot:
			case <-ctx.Done():
				return
			}
		}
	}()
	return stream, nil
}

func connectionsReadTimeout(interval time.Duration) time.Duration {
	timeout := 4 * interval
	if timeout < minimumStreamReadTimeout {
		return minimumStreamReadTimeout
	}
	return timeout
}

func boundedConnectionsInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return defaultConnectionsInterval
	}
	if interval < minimumConnectionsInterval {
		return minimumConnectionsInterval
	}
	if interval > maximumConnectionsInterval {
		return maximumConnectionsInterval
	}
	return interval
}

func (c *MihomoController) CloseConnection(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("connection ID is required")
	}
	return c.doJSON(ctx, http.MethodDelete, "/connections/"+url.PathEscape(id), nil, nil, nil, http.StatusOK, http.StatusNoContent)
}

func (c *MihomoController) CloseAllConnections(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodDelete, "/connections", nil, nil, nil, http.StatusOK, http.StatusNoContent)
}

func (c *MihomoController) RoutingMode(ctx context.Context) (RoutingMode, error) {
	var response struct {
		Mode string `json:"mode"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/configs", nil, nil, &response, http.StatusOK); err != nil {
		return "", err
	}
	mode := RoutingMode(strings.ToLower(strings.TrimSpace(response.Mode)))
	if !mode.Valid() {
		return "", fmt.Errorf("mihomo returned unsupported routing mode %q", response.Mode)
	}
	return mode, nil
}

func (c *MihomoController) SetRoutingMode(ctx context.Context, mode RoutingMode) error {
	mode = RoutingMode(strings.ToLower(strings.TrimSpace(string(mode))))
	if !mode.Valid() {
		return fmt.Errorf("invalid routing mode %q", mode)
	}
	payload := struct {
		Mode RoutingMode `json:"mode"`
	}{Mode: mode}
	return c.doJSON(ctx, http.MethodPatch, "/configs", nil, payload, nil, http.StatusOK, http.StatusNoContent)
}

// StreamTraffic consumes Mihomo's native aggregate traffic WebSocket. Unlike
// a browser timer, each event originates from the running core and is relayed
// unchanged through the authenticated SSE dashboard stream.
func (c *MihomoController) StreamTraffic(ctx context.Context) (<-chan TrafficSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse Mihomo controller URL: %w", err)
	}
	if parsed.Scheme == "https" {
		parsed.Scheme = "wss"
	} else {
		parsed.Scheme = "ws"
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/traffic"
	parsed.RawQuery = ""

	streamClient := *c.client
	if streamClient.Timeout <= 0 {
		streamClient.Timeout = defaultStreamSetupTimeout
	}
	headers := make(http.Header)
	if c.secret != "" {
		headers.Set("Authorization", "Bearer "+c.secret)
	}
	connection, response, err := websocket.Dial(ctx, parsed.String(), &websocket.DialOptions{
		HTTPClient: &streamClient,
		HTTPHeader: headers,
	})
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, fmt.Errorf("open Mihomo traffic stream: %w", err)
	}
	connection.SetReadLimit(maxControllerResponse)

	stream := make(chan TrafficSnapshot, 1)
	go func() {
		defer close(stream)
		defer func() { _ = connection.CloseNow() }()
		for {
			var snapshot TrafficSnapshot
			readContext, cancelRead := context.WithTimeout(ctx, defaultTrafficReadTimeout)
			err := wsjson.Read(readContext, connection, &snapshot)
			cancelRead()
			if err != nil {
				return
			}
			snapshot.CapturedAt = time.Now()
			select {
			case stream <- snapshot:
			case <-ctx.Done():
				return
			}
		}
	}()
	return stream, nil
}

// StreamLogs consumes Mihomo's native log WebSocket so a newly started
// manager can resume UI log delivery after adopting an existing core process.
func (c *MihomoController) StreamLogs(ctx context.Context) (<-chan MihomoLog, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse Mihomo controller URL: %w", err)
	}
	if parsed.Scheme == "https" {
		parsed.Scheme = "wss"
	} else {
		parsed.Scheme = "ws"
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/logs"
	parsed.RawQuery = ""

	streamClient := *c.client
	if streamClient.Timeout <= 0 {
		streamClient.Timeout = defaultStreamSetupTimeout
	}
	headers := make(http.Header)
	if c.secret != "" {
		headers.Set("Authorization", "Bearer "+c.secret)
	}
	connection, response, err := websocket.Dial(ctx, parsed.String(), &websocket.DialOptions{HTTPClient: &streamClient, HTTPHeader: headers})
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, fmt.Errorf("open Mihomo log stream: %w", err)
	}
	connection.SetReadLimit(maxControllerResponse)
	stream := make(chan MihomoLog, 32)
	go func() {
		defer close(stream)
		defer func() { _ = connection.CloseNow() }()
		for {
			var entry MihomoLog
			readContext, cancelRead := context.WithTimeout(ctx, defaultLogReadTimeout)
			err := wsjson.Read(readContext, connection, &entry)
			cancelRead()
			if err != nil {
				return
			}
			select {
			case stream <- entry:
			case <-ctx.Done():
				return
			}
		}
	}()
	return stream, nil
}

func (c *MihomoController) doJSON(ctx context.Context, method, path string, query url.Values, requestBody, responseBody any, accepted ...int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	requestURL := c.baseURL + path
	if len(query) > 0 {
		requestURL += "?" + query.Encode()
	}
	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("encode Mihomo request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL, body)
	if err != nil {
		return fmt.Errorf("build Mihomo request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.secret != "" {
		request.Header.Set("Authorization", "Bearer "+c.secret)
	}

	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("mihomo controller %s %s: %w", method, path, err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxControllerResponse+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read Mihomo controller response: %w", err)
	}
	if len(data) > maxControllerResponse {
		return errors.New("mihomo controller response exceeds limit")
	}
	if !acceptedStatus(response.StatusCode, accepted) {
		detail := strings.TrimSpace(string(data))
		if len(detail) > 4096 {
			detail = detail[:4096] + "…"
		}
		if detail == "" {
			detail = http.StatusText(response.StatusCode)
		}
		return fmt.Errorf("mihomo controller %s %s returned %d: %s", method, path, response.StatusCode, detail)
	}
	if responseBody != nil {
		if len(bytes.TrimSpace(data)) == 0 {
			return errors.New("mihomo controller returned an empty JSON response")
		}
		if err := json.Unmarshal(data, responseBody); err != nil {
			return fmt.Errorf("decode Mihomo controller response: %w", err)
		}
	}
	return nil
}

func acceptedStatus(status int, accepted []int) bool {
	for _, candidate := range accepted {
		if status == candidate {
			return true
		}
	}
	return false
}
