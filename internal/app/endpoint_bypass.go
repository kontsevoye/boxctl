package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/kontsevoye/boxctl/internal/state"
	"go.yaml.in/yaml/v3"
)

const (
	endpointBypassCachePath = ".boxctl/endpoint-bypass.v1.json"
	maxEndpointHosts        = 4096
	maxEndpointAddresses    = 8192
	defaultLookupTimeout    = 5 * time.Second
)

type endpointIPResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type endpointBypassCache struct {
	Version int                 `json:"version"`
	Hosts   map[string][]string `json:"hosts"`
}

type mihomoEndpointProxy struct {
	Server string `yaml:"server"`
}

type mihomoEndpointProvider struct {
	URL  string `yaml:"url"`
	Path string `yaml:"path"`
}

type mihomoEndpointConfig struct {
	Proxies        []mihomoEndpointProxy             `yaml:"proxies"`
	ProxyProviders map[string]mihomoEndpointProvider `yaml:"proxy-providers"`
	RuleProviders  map[string]mihomoEndpointProvider `yaml:"rule-providers"`
}

// EndpointBypassManager resolves the IPv4 destinations used by the active
// profile, proxy nodes, and remote providers. Results are persisted by a hash
// of the hostname, so subscription URL credentials never enter the cache.
// A failed refresh retains only the last-known-good addresses for the same
// hostname; addresses belonging to removed endpoints are discarded.
type EndpointBypassManager struct {
	Layout        state.Layout
	State         state.Store
	Resolver      endpointIPResolver
	LookupTimeout time.Duration
}

func NewEndpointBypassManager(layout state.Layout, store state.Store) *EndpointBypassManager {
	return &EndpointBypassManager{Layout: layout, State: store, Resolver: net.DefaultResolver, LookupTimeout: defaultLookupTimeout}
}

func (manager *EndpointBypassManager) Prepare(ctx context.Context, source []byte) ([]netip.Prefix, error) {
	return manager.PrepareMihomo(ctx, source, true)
}

// PrepareMihomo extracts Mihomo endpoints and optionally publishes the
// last-known-good address cache. Explicit profile preflight passes false so a
// failed switch cannot change shared state before its journal exists.
func (manager *EndpointBypassManager) PrepareMihomo(ctx context.Context, source []byte, persist bool) ([]netip.Prefix, error) {
	if manager == nil {
		return nil, nil
	}
	hosts, err := manager.endpointHosts(source)
	if err != nil {
		return nil, err
	}
	return manager.prepareHosts(ctx, hosts, persist)
}

// PrepareSingBox extracts network endpoints from a normalized sing-box JSON
// document. Callers intentionally pass the driver's private merge result, not
// the user source, so JSONC and multi-file native syntax are handled by
// sing-box itself before boxctl inspects the stable structure.
func (manager *EndpointBypassManager) PrepareSingBox(ctx context.Context, source []byte, persist bool) ([]netip.Prefix, error) {
	if manager == nil {
		return nil, nil
	}
	hosts, err := manager.singBoxEndpointHosts(source)
	if err != nil {
		return nil, err
	}
	return manager.prepareHosts(ctx, hosts, persist)
}

func (manager *EndpointBypassManager) prepareHosts(ctx context.Context, hosts []string, persist bool) ([]netip.Prefix, error) {
	cache, err := manager.loadCache()
	if err != nil {
		return nil, fmt.Errorf("read endpoint bypass cache: %w", err)
	}
	if cache.Hosts == nil {
		cache.Hosts = make(map[string][]string)
	}

	next := endpointBypassCache{Version: 1, Hosts: make(map[string][]string, len(hosts))}
	result := make([]netip.Prefix, 0, len(hosts))
	seen := make(map[netip.Prefix]struct{}, len(hosts))
	for _, host := range hosts {
		key := endpointHostKey(host)
		addresses, lookupErr := manager.resolveHost(ctx, host)
		if lookupErr != nil || len(addresses) == 0 {
			addresses = cachedEndpointAddresses(cache.Hosts[key])
		}
		if len(addresses) == 0 {
			continue
		}
		encoded := make([]string, 0, len(addresses))
		for _, address := range addresses {
			if !address.Is4() {
				continue
			}
			prefix := netip.PrefixFrom(address.Unmap(), 32)
			encoded = append(encoded, prefix.Addr().String())
			if _, exists := seen[prefix]; exists {
				continue
			}
			if len(result) >= maxEndpointAddresses {
				return nil, errors.New("endpoint bypass address limit exceeded")
			}
			seen[prefix] = struct{}{}
			result = append(result, prefix)
		}
		slices.Sort(encoded)
		next.Hosts[key] = slices.Compact(encoded)
	}
	if persist && !reflect.DeepEqual(cache, next) {
		if err := manager.State.WriteJSON(endpointBypassCachePath, next, 0o600); err != nil {
			return nil, fmt.Errorf("save endpoint bypass cache: %w", err)
		}
	}
	return normalizeNetPrefixes(result), nil
}

func (manager *EndpointBypassManager) singBoxEndpointHosts(source []byte) ([]string, error) {
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil || document == nil {
		return nil, errors.New("inspect sing-box endpoint configuration")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("inspect sing-box endpoint configuration: trailing data")
	}
	seen := make(map[string]struct{})
	hosts := make([]string, 0)
	appendHost := func(value string) error {
		value = strings.TrimSpace(value)
		if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" && parsed.Scheme != "" {
			value = parsed.Hostname()
		}
		value = normalizeEndpointHost(value)
		if value == "" {
			return nil
		}
		if _, exists := seen[value]; exists {
			return nil
		}
		if len(hosts) >= maxEndpointHosts {
			return errors.New("endpoint host limit exceeded")
		}
		seen[value] = struct{}{}
		hosts = append(hosts, value)
		return nil
	}
	collectObjects := func(value any, keys ...string) error {
		items, ok := value.([]any)
		if !ok && value != nil {
			return errors.New("inspect sing-box endpoint collection")
		}
		for _, item := range items {
			object, ok := item.(map[string]any)
			if !ok {
				return errors.New("inspect sing-box endpoint item")
			}
			for _, key := range keys {
				if candidate, ok := object[key].(string); ok {
					if err := appendHost(candidate); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if err := collectObjects(document["outbounds"], "server"); err != nil {
		return nil, err
	}
	if err := collectObjects(document["endpoints"], "server"); err != nil {
		return nil, err
	}
	if dns, ok := document["dns"].(map[string]any); ok {
		if err := collectObjects(dns["servers"], "server", "address"); err != nil {
			return nil, err
		}
	}
	if route, ok := document["route"].(map[string]any); ok {
		if err := collectObjects(route["rule_set"], "url"); err != nil {
			return nil, err
		}
	}
	profileURLs, err := manager.profileSourceURLs()
	if err != nil {
		return nil, err
	}
	for _, sourceURL := range profileURLs {
		if err := appendHost(sourceURL); err != nil {
			return nil, err
		}
	}
	slices.Sort(hosts)
	return hosts, nil
}

func (manager *EndpointBypassManager) endpointHosts(source []byte) ([]string, error) {
	var document mihomoEndpointConfig
	decoder := yaml.NewDecoder(bytes.NewReader(source))
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("inspect Mihomo endpoint configuration")
	}
	seen := make(map[string]struct{})
	hosts := make([]string, 0)
	appendHost := func(host string) error {
		host = normalizeEndpointHost(host)
		if host == "" {
			return nil
		}
		if _, exists := seen[host]; exists {
			return nil
		}
		if len(hosts) >= maxEndpointHosts {
			return errors.New("endpoint host limit exceeded")
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
		return nil
	}
	appendURL := func(raw string) error {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			return errors.New("inspect provider endpoint URL")
		}
		if parsed.Hostname() == "" {
			return nil
		}
		return appendHost(parsed.Hostname())
	}

	for _, proxy := range document.Proxies {
		if err := appendHost(proxy.Server); err != nil {
			return nil, err
		}
	}
	for _, provider := range document.ProxyProviders {
		if err := appendURL(provider.URL); err != nil {
			return nil, err
		}
		pathOnDisk := ""
		var pathErr error
		if strings.TrimSpace(provider.Path) != "" {
			pathOnDisk, pathErr = manager.localProviderPath(provider.Path)
		} else if sourceURL := strings.TrimSpace(provider.URL); sourceURL != "" {
			pathOnDisk, pathErr = secureProviderPath(manager.Layout.Root, mihomoHashedProviderCachePath(manager.Layout.Root, "proxies", sourceURL))
		}
		if pathOnDisk == "" || pathErr != nil {
			continue
		}
		content, readErr := readBoundedRegular(pathOnDisk, maxRuleProviderBytes)
		if readErr != nil {
			continue
		}
		var cached struct {
			Proxies []mihomoEndpointProxy `yaml:"proxies"`
		}
		if yaml.Unmarshal(content, &cached) != nil {
			continue
		}
		for _, proxy := range cached.Proxies {
			if err := appendHost(proxy.Server); err != nil {
				return nil, err
			}
		}
	}
	for _, provider := range document.RuleProviders {
		if err := appendURL(provider.URL); err != nil {
			return nil, err
		}
	}
	profileURLs, err := manager.profileSourceURLs()
	if err != nil {
		return nil, err
	}
	for _, sourceURL := range profileURLs {
		if err := appendURL(sourceURL); err != nil {
			return nil, err
		}
	}
	subscriptions, err := manager.proxySubscriptionRecords()
	if err != nil {
		return nil, err
	}
	for _, subscription := range subscriptions {
		if normalizedEngine(subscription.Engine) != state.EngineMihomo {
			continue
		}
		if err := appendURL(subscription.SourceURL); err != nil {
			return nil, err
		}
		if !subscription.Enabled {
			continue
		}
		content, readErr := readBoundedRegular(filepath.Join(manager.Layout.Root, filepath.FromSlash(proxyProviderCachePath(subscription.ID))), maxRuleProviderBytes)
		if readErr != nil {
			continue
		}
		var cached struct {
			Proxies []mihomoEndpointProxy `yaml:"proxies"`
		}
		if yaml.Unmarshal(content, &cached) != nil {
			continue
		}
		for _, proxy := range cached.Proxies {
			if err := appendHost(proxy.Server); err != nil {
				return nil, err
			}
		}
	}
	slices.Sort(hosts)
	return hosts, nil
}

func (manager *EndpointBypassManager) localProviderPath(pathValue string) (string, error) {
	candidate := strings.TrimSpace(pathValue)
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(manager.Layout.Root, candidate)
	}
	return secureProviderPath(manager.Layout.Root, candidate)
}

func (manager *EndpointBypassManager) profileSourceURLs() ([]string, error) {
	entries, err := os.ReadDir(manager.Layout.ProfileSourcesDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		pathOnDisk := filepath.Join(manager.Layout.ProfileSourcesDir, entry.Name())
		content, readErr := readBoundedRegular(pathOnDisk, 64<<10)
		if readErr != nil {
			continue
		}
		var source profileSource
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&source) == nil && strings.TrimSpace(source.URL) != "" {
			result = append(result, source.URL)
		}
	}
	return result, nil
}

func (manager *EndpointBypassManager) proxySubscriptionRecords() ([]proxySubscriptionRecord, error) {
	content, err := manager.State.Read(proxySubscriptionsPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var registry proxySubscriptionRegistry
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&registry) != nil || registry.Schema != 1 {
		return nil, errors.New("inspect proxy subscription endpoints")
	}
	for index := range registry.Items {
		registry.Items[index].Engine = normalizedEngine(registry.Items[index].Engine)
	}
	return registry.Items, nil
}

func (manager *EndpointBypassManager) resolveHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Is4() {
			return []netip.Addr{address.Unmap()}, nil
		}
		return nil, nil
	}
	resolver := manager.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	timeout := manager.LookupTimeout
	if timeout <= 0 {
		timeout = defaultLookupTimeout
	}
	lookupContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addresses, err := resolver.LookupNetIP(lookupContext, "ip4", host)
	if err != nil {
		return nil, err
	}
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if address.Is4() {
			result = append(result, address.Unmap())
		}
	}
	slices.SortFunc(result, func(left, right netip.Addr) int { return left.Compare(right) })
	return slices.Compact(result), nil
}

func (manager *EndpointBypassManager) loadCache() (endpointBypassCache, error) {
	content, err := manager.State.Read(endpointBypassCachePath)
	if errors.Is(err, fs.ErrNotExist) {
		return endpointBypassCache{Version: 1, Hosts: map[string][]string{}}, nil
	}
	if err != nil {
		return endpointBypassCache{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var cache endpointBypassCache
	if err := decoder.Decode(&cache); err != nil || cache.Version != 1 {
		return endpointBypassCache{}, errors.New("invalid endpoint bypass cache")
	}
	return cache, nil
}

func normalizeEndpointHost(value string) string {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if len(value) > 253 || strings.ContainsAny(value, "\x00/\\?#@") {
		return ""
	}
	return value
}

func endpointHostKey(host string) string {
	digest := sha256.Sum256([]byte(host))
	return hex.EncodeToString(digest[:])
}

func cachedEndpointAddresses(values []string) []netip.Addr {
	result := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		address, err := netip.ParseAddr(value)
		if err == nil && address.Is4() {
			result = append(result, address.Unmap())
		}
	}
	return result
}
