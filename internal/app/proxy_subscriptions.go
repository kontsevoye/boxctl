package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	configpkg "github.com/kontsevoye/boxctl/internal/config"
	"github.com/kontsevoye/boxctl/internal/remote"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
	"go.yaml.in/yaml/v3"
)

const proxySubscriptionsPath = ".boxctl/proxy-subscriptions.v1.json"

var proxySubscriptionIDPattern = regexp.MustCompile(`^[0-9a-f]{24}$`)

type proxySubscriptionRecord struct {
	ID                  string            `json:"id"`
	Engine              string            `json:"engine,omitempty"`
	Name                string            `json:"name"`
	Enabled             bool              `json:"enabled"`
	SourceURL           string            `json:"sourceUrl,omitempty"`
	ShareLinks          string            `json:"shareLinks,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	UpdateIntervalHours int               `json:"updateIntervalHours"`
	IntervalExplicit    bool              `json:"intervalExplicit,omitempty"`
	ETag                string            `json:"etag,omitempty"`
	LastModified        string            `json:"lastModified,omitempty"`
	ProxyCount          int               `json:"proxyCount,omitempty"`
	UploadBytes         int64             `json:"uploadBytes,omitempty"`
	DownloadBytes       int64             `json:"downloadBytes,omitempty"`
	TotalBytes          int64             `json:"totalBytes,omitempty"`
	ExpiresAt           time.Time         `json:"expiresAt,omitempty"`
	UpdatedAt           time.Time         `json:"updatedAt,omitempty"`
	LastCheckedAt       time.Time         `json:"lastCheckedAt,omitempty"`
	LastError           string            `json:"lastError,omitempty"`
}

type proxySubscriptionRegistry struct {
	Schema int                       `json:"schema"`
	Items  []proxySubscriptionRecord `json:"items"`
}

// ProxySubscriptionsService owns private subscription sources and generated
// Mihomo proxy-provider caches. Browser DTOs expose neither URLs/share links
// nor header values.
type ProxySubscriptionsService struct {
	State     state.Store
	Fetcher   remote.Fetcher
	OnChanged func(context.Context) error
	mu        sync.Mutex
}

func NewProxySubscriptionsService(root string, client *http.Client) (*ProxySubscriptionsService, error) {
	store, err := state.NewStore(root)
	if err != nil {
		return nil, err
	}
	service := &ProxySubscriptionsService{State: store}
	service.Fetcher = remote.Fetcher{Client: client, Validator: remote.ValidatorFunc(func(_ context.Context, content []byte) error {
		_, _, err := normalizeProxyProvider(content)
		return err
	})}
	return service, nil
}

func (service *ProxySubscriptionsService) ProxySubscriptions(_ context.Context) ([]web.ProxySubscription, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	registry, err := service.load()
	if err != nil {
		return nil, err
	}
	result := make([]web.ProxySubscription, 0, len(registry.Items))
	for _, item := range registry.Items {
		result = append(result, subscriptionDTO(item))
	}
	sort.Slice(result, func(i, j int) bool { return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name) })
	return result, nil
}

func (service *ProxySubscriptionsService) ProxySubscription(_ context.Context, id string) (web.ProxySubscription, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	registry, err := service.load()
	if err != nil {
		return web.ProxySubscription{}, err
	}
	index := findProxySubscription(registry.Items, id)
	if index < 0 {
		return web.ProxySubscription{}, web.ErrNotFound
	}
	return subscriptionDTO(registry.Items[index]), nil
}

func (service *ProxySubscriptionsService) CreateProxySubscription(ctx context.Context, draft web.ProxySubscriptionDraft) (web.ProxySubscription, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	record, err := newProxySubscriptionRecord(draft)
	if err != nil {
		return web.ProxySubscription{}, err
	}
	registry, err := service.load()
	if err != nil {
		return web.ProxySubscription{}, err
	}
	for _, item := range registry.Items {
		if item.Engine == record.Engine && strings.EqualFold(item.Name, record.Name) {
			return web.ProxySubscription{}, &web.PublicError{Status: http.StatusConflict, Code: "subscription_exists", Message: "A proxy subscription with this name already exists"}
		}
	}
	if _, err := service.refreshRecord(ctx, &record, false); err != nil {
		return web.ProxySubscription{}, err
	}
	registry.Items = append(registry.Items, record)
	if err := service.save(registry); err != nil {
		return web.ProxySubscription{}, err
	}
	if err := service.changed(ctx); err != nil {
		return web.ProxySubscription{}, err
	}
	return subscriptionDTO(record), nil
}

func (service *ProxySubscriptionsService) UpdateProxySubscription(ctx context.Context, id string, patch web.ProxySubscriptionPatch) (web.ProxySubscription, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	registry, err := service.load()
	if err != nil {
		return web.ProxySubscription{}, err
	}
	index := findProxySubscription(registry.Items, id)
	if index < 0 {
		return web.ProxySubscription{}, web.ErrNotFound
	}
	record := registry.Items[index]
	original := record
	refresh := false
	if patch.Name != nil {
		name := strings.TrimSpace(*patch.Name)
		if err := validateSubscriptionName(name); err != nil {
			return web.ProxySubscription{}, err
		}
		for other, item := range registry.Items {
			if other != index && item.Engine == record.Engine && strings.EqualFold(item.Name, name) {
				return web.ProxySubscription{}, &web.PublicError{Status: http.StatusConflict, Code: "subscription_exists", Message: "A proxy subscription with this name already exists"}
			}
		}
		record.Name = name
	}
	if patch.SourceURL != nil && patch.ShareLinks != nil {
		return web.ProxySubscription{}, ambiguousProxySubscription()
	}
	if patch.SourceURL != nil {
		if strings.TrimSpace(*patch.SourceURL) == "" {
			return web.ProxySubscription{}, sourceRequiredProxySubscription()
		}
		record.SourceURL = strings.TrimSpace(*patch.SourceURL)
		record.ShareLinks = ""
		record.ETag, record.LastModified = "", ""
		clearSubscriptionUsage(&record)
		refresh = true
	}
	if patch.ShareLinks != nil {
		if strings.TrimSpace(*patch.ShareLinks) == "" {
			return web.ProxySubscription{}, sourceRequiredProxySubscription()
		}
		record.ShareLinks = strings.TrimSpace(*patch.ShareLinks)
		record.SourceURL = ""
		record.ETag, record.LastModified = "", ""
		clearSubscriptionUsage(&record)
		refresh = true
	}
	if patch.UpdateIntervalHours != nil {
		if err := validateProfileInterval(*patch.UpdateIntervalHours); err != nil {
			return web.ProxySubscription{}, err
		}
		record.UpdateIntervalHours = *patch.UpdateIntervalHours
		record.IntervalExplicit = true
	}
	if patch.UpdateIntervalAuto != nil {
		if *patch.UpdateIntervalAuto && patch.UpdateIntervalHours != nil {
			return web.ProxySubscription{}, &web.PublicError{Status: http.StatusBadRequest, Code: "ambiguous_update_interval", Message: "Choose an explicit interval or automatic response-header updates"}
		}
		if *patch.UpdateIntervalAuto {
			record.IntervalExplicit = false
		}
	}
	if patch.Headers != nil {
		headers, err := validateSubscriptionHeaders(*patch.Headers)
		if err != nil {
			return web.ProxySubscription{}, err
		}
		record.Headers = headers
		refresh = record.SourceURL != ""
	}
	if patch.Enabled != nil {
		record.Enabled = *patch.Enabled
	}
	runtimeChanged := false
	if refresh {
		var refreshErr error
		runtimeChanged, refreshErr = service.refreshRecord(ctx, &record, false)
		if refreshErr != nil {
			return web.ProxySubscription{}, refreshErr
		}
	}
	runtimeChanged = runtimeChanged || original.Enabled != record.Enabled || original.SourceURL != record.SourceURL ||
		original.UpdateIntervalHours != record.UpdateIntervalHours || !maps.Equal(original.Headers, record.Headers)
	if !original.Enabled && !record.Enabled {
		runtimeChanged = false
	}
	registry.Items[index] = record
	if err := service.save(registry); err != nil {
		return web.ProxySubscription{}, err
	}
	if runtimeChanged {
		if err := service.changed(ctx); err != nil {
			return web.ProxySubscription{}, err
		}
	}
	return subscriptionDTO(record), nil
}

func (service *ProxySubscriptionsService) DeleteProxySubscription(ctx context.Context, id string) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	registry, err := service.load()
	if err != nil {
		return err
	}
	index := findProxySubscription(registry.Items, id)
	if index < 0 {
		return web.ErrNotFound
	}
	wasEnabled := registry.Items[index].Enabled
	registry.Items = append(registry.Items[:index], registry.Items[index+1:]...)
	if err := service.save(registry); err != nil {
		return err
	}
	if err := service.State.RemoveRegular(proxyProviderCachePath(id)); err != nil {
		return err
	}
	if wasEnabled {
		return service.changed(ctx)
	}
	return nil
}

func (service *ProxySubscriptionsService) RefreshProxySubscription(ctx context.Context, id string) (web.ProxySubscription, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	registry, err := service.load()
	if err != nil {
		return web.ProxySubscription{}, err
	}
	index := findProxySubscription(registry.Items, id)
	if index < 0 {
		return web.ProxySubscription{}, web.ErrNotFound
	}
	runtimeChanged, refreshErr := service.refreshRecord(ctx, &registry.Items[index], true)
	if refreshErr != nil {
		_ = service.save(registry)
		return web.ProxySubscription{}, refreshErr
	}
	if err := service.save(registry); err != nil {
		return web.ProxySubscription{}, err
	}
	if runtimeChanged && registry.Items[index].Enabled {
		if err := service.changed(ctx); err != nil {
			return web.ProxySubscription{}, err
		}
	}
	return subscriptionDTO(registry.Items[index]), nil
}

func (service *ProxySubscriptionsService) refreshRecord(ctx context.Context, record *proxySubscriptionRecord, conditional bool) (bool, error) {
	now := time.Now().UTC()
	previousInterval := record.UpdateIntervalHours
	var content []byte
	if record.SourceURL != "" {
		request := remote.Request{URL: record.SourceURL, Headers: record.Headers}
		if conditional {
			request.ETag, request.LastModified = record.ETag, record.LastModified
		}
		result, err := service.Fetcher.Fetch(ctx, request)
		if err != nil && ctx.Err() != nil {
			return false, ctx.Err()
		}
		record.LastCheckedAt = now
		if err != nil {
			record.LastError = "Proxy subscription refresh failed"
			return false, &web.PublicError{Status: http.StatusBadGateway, Code: "subscription_refresh_failed", Message: "The proxy subscription could not be downloaded or parsed"}
		}
		if result.NotModified {
			if result.ETag != "" {
				record.ETag = result.ETag
			}
			if result.LastModified != "" {
				record.LastModified = result.LastModified
			}
			if result.SuggestedUpdate > 0 && !record.IntervalExplicit {
				record.UpdateIntervalHours = int(result.SuggestedUpdate / time.Hour)
			}
			applySubscriptionUsage(record, result.SubscriptionInfo)
			record.LastError = ""
			return previousInterval != record.UpdateIntervalHours, nil
		}
		content = result.Content
		record.ETag, record.LastModified = result.ETag, result.LastModified
		if result.SuggestedUpdate > 0 && !record.IntervalExplicit {
			record.UpdateIntervalHours = int(result.SuggestedUpdate / time.Hour)
		}
		applySubscriptionUsage(record, result.SubscriptionInfo)
	} else {
		content = []byte(record.ShareLinks)
		record.LastCheckedAt = now
	}
	normalized, count, err := normalizeProxyProvider(content)
	if err != nil {
		record.LastError = "Proxy subscription format is unsupported"
		return false, &web.PublicError{Status: http.StatusBadRequest, Code: "unsupported_subscription", Message: "Expected Mihomo proxy-provider YAML or supported proxy share links"}
	}
	cacheChanged := true
	current, readErr := service.State.Read(proxyProviderCachePath(record.ID))
	if readErr == nil {
		cacheChanged = !bytes.Equal(current, normalized)
	} else if !errors.Is(readErr, fs.ErrNotExist) {
		return false, readErr
	}
	if cacheChanged {
		if err := service.State.Write(proxyProviderCachePath(record.ID), normalized, 0o600); err != nil {
			return false, err
		}
	}
	record.ProxyCount = count
	record.UpdatedAt = now
	record.LastError = ""
	return cacheChanged || previousInterval != record.UpdateIntervalHours, nil
}

func (service *ProxySubscriptionsService) RefreshDueProxySubscriptions(ctx context.Context, now time.Time) error {
	items, err := service.ProxySubscriptions(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for _, item := range items {
		if !item.Enabled || item.SourceKind != "remote" || now.Before(item.NextUpdateAt) {
			continue
		}
		if _, err := service.RefreshProxySubscription(ctx, item.ID); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (service *ProxySubscriptionsService) StartScheduler(parent context.Context) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		_ = service.RefreshDueProxySubscriptions(ctx, time.Now().UTC())
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				_ = service.RefreshDueProxySubscriptions(ctx, now.UTC())
			}
		}
	}()
	return func() { cancel(); <-done }
}

// EnabledProviderSpecs returns runtime-only provider definitions. The source
// profile remains byte-for-byte user-owned.
func (service *ProxySubscriptionsService) EnabledProviderSpecs() ([]configpkg.MihomoProxyProvider, error) {
	// Registry publication is an atomic rename, so runtime preparation can read
	// a complete snapshot without taking the mutation mutex. This avoids lock
	// inversion when a mutation synchronously restarts Mihomo.
	registry, err := service.load()
	if err != nil {
		return nil, err
	}
	result := make([]configpkg.MihomoProxyProvider, 0, len(registry.Items))
	for _, item := range registry.Items {
		if !item.Enabled || item.Engine != state.EngineMihomo {
			continue
		}
		if item.SourceURL == "" {
			if err := service.ensureLocalProviderCache(item); err != nil {
				return nil, fmt.Errorf("rebuild local proxy subscription %q: %w", item.Name, err)
			}
		}
		// boxctl is the sole fetch/validation owner for managed subscriptions.
		// Mihomo always consumes the normalized mode-0600 cache as a file
		// provider; pointing it back at SourceURL would break base64/share-link
		// subscriptions and create an independent refresh race.
		result = append(result, configpkg.MihomoProxyProvider{
			Name: providerName(item.ID),
			Path: "./" + proxyProviderCachePath(item.ID), Interval: time.Duration(item.UpdateIntervalHours) * time.Hour,
			Local: true,
		})
	}
	return result, nil
}

func (service *ProxySubscriptionsService) ensureLocalProviderCache(item proxySubscriptionRecord) error {
	normalized, _, err := normalizeProxyProvider([]byte(item.ShareLinks))
	if err != nil {
		return err
	}
	path := proxyProviderCachePath(item.ID)
	current, readErr := service.State.Read(path)
	if readErr == nil && bytes.Equal(current, normalized) {
		return nil
	}
	if readErr != nil && !errors.Is(readErr, fs.ErrNotExist) {
		return readErr
	}
	return service.State.Write(path, normalized, 0o600)
}

// RemoteSourceURLs returns private endpoint inputs for the OpenWrt bypass
// resolver. Callers must never log or serialize the returned URLs.
func (service *ProxySubscriptionsService) RemoteSourceURLs() ([]string, error) {
	registry, err := service.load()
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(registry.Items))
	for _, item := range registry.Items {
		if item.Enabled && item.SourceURL != "" {
			result = append(result, item.SourceURL)
		}
	}
	return result, nil
}

func (service *ProxySubscriptionsService) load() (proxySubscriptionRegistry, error) {
	content, err := service.State.Read(proxySubscriptionsPath)
	if errors.Is(err, fs.ErrNotExist) {
		return proxySubscriptionRegistry{Schema: 1}, nil
	}
	if err != nil {
		return proxySubscriptionRegistry{}, err
	}
	var registry proxySubscriptionRegistry
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil || registry.Schema != 1 {
		return proxySubscriptionRegistry{}, errors.New("proxy subscription registry is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return proxySubscriptionRegistry{}, errors.New("proxy subscription registry has trailing data")
	}
	for index := range registry.Items {
		registry.Items[index].Engine = normalizedEngine(registry.Items[index].Engine)
	}
	if err := validateProxySubscriptionRegistry(registry); err != nil {
		return proxySubscriptionRegistry{}, err
	}
	return registry, nil
}

func validateProxySubscriptionRegistry(registry proxySubscriptionRegistry) error {
	ids := make(map[string]struct{}, len(registry.Items))
	names := make(map[string]struct{}, len(registry.Items))
	for _, item := range registry.Items {
		if item.Engine != state.EngineMihomo {
			return errors.New("proxy subscription registry contains an unsupported engine")
		}
		if !proxySubscriptionIDPattern.MatchString(item.ID) {
			return errors.New("proxy subscription registry contains an invalid id")
		}
		if _, duplicate := ids[item.ID]; duplicate {
			return errors.New("proxy subscription registry contains duplicate ids")
		}
		ids[item.ID] = struct{}{}
		if err := validateSubscriptionName(item.Name); err != nil {
			return errors.New("proxy subscription registry contains an invalid name")
		}
		foldedName := item.Engine + "\x00" + strings.ToLower(item.Name)
		if _, duplicate := names[foldedName]; duplicate {
			return errors.New("proxy subscription registry contains duplicate names")
		}
		names[foldedName] = struct{}{}
		if (item.SourceURL == "") == (strings.TrimSpace(item.ShareLinks) == "") {
			return errors.New("proxy subscription registry contains an invalid source")
		}
		if item.SourceURL != "" {
			if _, err := remoteSourceURL(item.SourceURL); err != nil {
				return errors.New("proxy subscription registry contains an invalid URL")
			}
		}
		if err := validateProfileInterval(item.UpdateIntervalHours); err != nil {
			return errors.New("proxy subscription registry contains an invalid interval")
		}
		if _, err := validateSubscriptionHeaders(item.Headers); err != nil {
			return errors.New("proxy subscription registry contains invalid headers")
		}
	}
	return nil
}

// Keep registry validation independent from Fetcher's unexported parser while
// enforcing the same transport boundary before a restored URL reaches runtime
// endpoint discovery.
func remoteSourceURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("remote subscription URL must be HTTPS without user-info or fragment")
	}
	return parsed, nil
}

func (service *ProxySubscriptionsService) save(registry proxySubscriptionRegistry) error {
	registry.Schema = 1
	return service.State.WriteJSON(proxySubscriptionsPath, registry, 0o600)
}

func (service *ProxySubscriptionsService) changed(ctx context.Context) error {
	if service.OnChanged == nil {
		return nil
	}
	if err := service.OnChanged(ctx); err != nil {
		return fmt.Errorf("proxy subscription saved but runtime refresh failed: %w", err)
	}
	return nil
}

func newProxySubscriptionRecord(draft web.ProxySubscriptionDraft) (proxySubscriptionRecord, error) {
	engineName := normalizedEngine(draft.Engine)
	if engineName != state.EngineMihomo {
		return proxySubscriptionRecord{}, &web.PublicError{
			Status: http.StatusConflict, Code: "subscription_engine_unsupported",
			Message: "Managed proxy subscriptions are not supported by this engine; add native outbounds to its JSON profile",
		}
	}
	name := strings.TrimSpace(draft.Name)
	if err := validateSubscriptionName(name); err != nil {
		return proxySubscriptionRecord{}, err
	}
	urlValue, links := strings.TrimSpace(draft.SourceURL), strings.TrimSpace(draft.ShareLinks)
	if (urlValue == "") == (links == "") {
		return proxySubscriptionRecord{}, ambiguousProxySubscription()
	}
	interval := defaultProfileUpdateIntervalHours
	if draft.UpdateIntervalHours != nil {
		interval = *draft.UpdateIntervalHours
	}
	if err := validateProfileInterval(interval); err != nil {
		return proxySubscriptionRecord{}, err
	}
	headers, err := validateSubscriptionHeaders(draft.Headers)
	if err != nil {
		return proxySubscriptionRecord{}, err
	}
	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		return proxySubscriptionRecord{}, errors.New("generate proxy subscription id")
	}
	return proxySubscriptionRecord{
		ID: hex.EncodeToString(idBytes), Engine: engineName, Name: name, Enabled: true,
		SourceURL: urlValue, ShareLinks: links, Headers: headers, UpdateIntervalHours: interval,
		IntervalExplicit: draft.UpdateIntervalHours != nil,
	}, nil
}

func validateSubscriptionName(name string) error {
	if name == "" || len(name) > 128 || strings.ContainsAny(name, "\r\n") {
		return &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_subscription_name", Message: "Subscription name must be between 1 and 128 characters"}
	}
	return nil
}

func validateSubscriptionHeaders(headers map[string]string) (map[string]string, error) {
	if len(headers) > 8 {
		return nil, &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_subscription_headers", Message: "Too many custom headers"}
	}
	result := make(map[string]string, len(headers))
	for name, value := range headers {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		switch canonical {
		case "User-Agent", "X-Hwid", "X-Device-Os", "X-Ver-Os", "X-Device-Model":
		default:
			return nil, &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_subscription_headers", Message: "Only the documented device headers are accepted"}
		}
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 512 || strings.ContainsAny(value, "\r\n") {
			return nil, &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_subscription_headers", Message: "Custom header values must be non-empty single-line strings"}
		}
		if _, duplicate := result[canonical]; duplicate {
			return nil, &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_subscription_headers", Message: "Custom header names must be unique"}
		}
		result[canonical] = value
	}
	return result, nil
}

func subscriptionDTO(record proxySubscriptionRecord) web.ProxySubscription {
	headerNames := make([]string, 0, len(record.Headers))
	for name := range record.Headers {
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)
	result := web.ProxySubscription{
		ID: record.ID, Engine: normalizedEngine(record.Engine), Name: record.Name, ProviderName: providerName(record.ID), Enabled: record.Enabled,
		SourceKind: "remote", HeaderNames: headerNames, UpdateIntervalHours: record.UpdateIntervalHours,
		UpdateIntervalAuto: !record.IntervalExplicit,
		ProxyCount:         record.ProxyCount, UploadBytes: record.UploadBytes, DownloadBytes: record.DownloadBytes,
		TotalBytes: record.TotalBytes, ExpiresAt: record.ExpiresAt, UpdatedAt: record.UpdatedAt,
		LastCheckedAt: record.LastCheckedAt, LastError: record.LastError,
	}
	if record.SourceURL == "" {
		result.SourceKind = "share-links"
	}
	if record.Enabled && record.SourceURL != "" && !record.LastCheckedAt.IsZero() {
		result.NextUpdateAt = record.LastCheckedAt.Add(time.Duration(record.UpdateIntervalHours) * time.Hour)
	}
	return result
}

func findProxySubscription(items []proxySubscriptionRecord, id string) int {
	for index := range items {
		if items[index].ID == id {
			return index
		}
	}
	return -1
}

func providerName(id string) string           { return "boxctl-" + id }
func proxyProviderCachePath(id string) string { return "proxy-providers/" + providerName(id) + ".yaml" }

func ambiguousProxySubscription() error {
	return &web.PublicError{Status: http.StatusBadRequest, Code: "ambiguous_subscription", Message: "Provide either one HTTPS subscription URL or proxy share links"}
}

func sourceRequiredProxySubscription() error {
	return &web.PublicError{Status: http.StatusBadRequest, Code: "subscription_source_required", Message: "A subscription URL or proxy share links are required"}
}

func applySubscriptionUsage(record *proxySubscriptionRecord, value string) {
	for _, part := range strings.Split(value, ";") {
		name, raw, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		number, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || number < 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "upload":
			record.UploadBytes = number
		case "download":
			record.DownloadBytes = number
		case "total":
			record.TotalBytes = number
		case "expire":
			if number > 0 {
				record.ExpiresAt = time.Unix(number, 0).UTC()
			} else {
				record.ExpiresAt = time.Time{}
			}
		}
	}
}

func clearSubscriptionUsage(record *proxySubscriptionRecord) {
	record.UploadBytes = 0
	record.DownloadBytes = 0
	record.TotalBytes = 0
	record.ExpiresAt = time.Time{}
}

func normalizeProxyProvider(content []byte) ([]byte, int, error) {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 {
		return nil, 0, errors.New("empty proxy subscription")
	}
	var document struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if yaml.Unmarshal(trimmed, &document) == nil && len(document.Proxies) > 0 {
		output, err := yaml.Marshal(map[string]any{"proxies": document.Proxies})
		return output, len(document.Proxies), err
	}
	text := string(trimmed)
	if !strings.Contains(text, "://") {
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			decoded, err := encoding.DecodeString(strings.Map(func(r rune) rune {
				if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
					return -1
				}
				return r
			}, text))
			if err == nil && strings.Contains(string(decoded), "://") {
				text = string(decoded)
				break
			}
		}
	}
	var proxies []map[string]any
	for _, line := range strings.Fields(text) {
		if strings.HasPrefix(line, "#") {
			continue
		}
		proxy, err := parseProxyShareLink(line)
		if err != nil {
			return nil, 0, err
		}
		proxies = append(proxies, proxy)
	}
	if len(proxies) == 0 {
		return nil, 0, errors.New("no supported proxy share links")
	}
	output, err := yaml.Marshal(map[string]any{"proxies": proxies})
	return output, len(proxies), err
}

func parseProxyShareLink(raw string) (map[string]any, error) {
	if strings.HasPrefix(raw, "vmess://") {
		return parseVMessLink(strings.TrimPrefix(raw, "vmess://"))
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("unsupported proxy share link")
	}
	if strings.EqualFold(parsed.Scheme, "ss") {
		return parseShadowsocksLink(raw)
	}
	if parsed.Host == "" {
		return nil, errors.New("unsupported proxy share link")
	}
	host := parsed.Hostname()
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("unsupported proxy share link")
	}
	name, _ := url.QueryUnescape(parsed.Fragment)
	if strings.TrimSpace(name) == "" {
		name = host + ":" + strconv.Itoa(port)
	}
	proxy := map[string]any{"name": name, "server": host, "port": port}
	query := parsed.Query()
	switch strings.ToLower(parsed.Scheme) {
	case "vless":
		credential := username(parsed)
		if credential == "" {
			return nil, errors.New("unsupported vless share link")
		}
		proxy["type"], proxy["uuid"], proxy["udp"] = "vless", credential, true
		applyVLESSOptions(proxy, query)
	case "trojan":
		credential := username(parsed)
		if credential == "" {
			return nil, errors.New("unsupported trojan share link")
		}
		proxy["type"], proxy["password"], proxy["udp"] = "trojan", credential, true
		applyTLSOptions(proxy, query)
	case "hysteria2", "hy2":
		password := username(parsed)
		if parsed.User != nil {
			if value, ok := parsed.User.Password(); ok {
				password = value
			}
		}
		if password == "" {
			return nil, errors.New("unsupported hysteria2 share link")
		}
		proxy["type"], proxy["password"] = "hysteria2", password
		applyTLSOptions(proxy, query)
	case "socks", "socks5", "socks5h":
		proxy["type"] = "socks5"
		if parsed.User != nil {
			proxy["username"] = parsed.User.Username()
			if password, ok := parsed.User.Password(); ok {
				proxy["password"] = password
			}
		}
	case "http", "https":
		proxy["type"], proxy["tls"] = "http", parsed.Scheme == "https"
		if parsed.User != nil {
			proxy["username"] = parsed.User.Username()
			if password, ok := parsed.User.Password(); ok {
				proxy["password"] = password
			}
		}
	default:
		return nil, errors.New("unsupported proxy share link")
	}
	return proxy, nil
}

func username(parsed *url.URL) string {
	if parsed == nil || parsed.User == nil {
		return ""
	}
	return parsed.User.Username()
}

func parseVMessLink(payload string) (map[string]any, error) {
	var decoded []byte
	var err error
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err = encoding.DecodeString(payload)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, errors.New("unsupported vmess share link")
	}
	var source struct {
		PS, Add, Port, ID, Aid, Net, Type, Host, Path, TLS, SNI string
	}
	if json.Unmarshal(decoded, &source) != nil {
		return nil, errors.New("unsupported vmess share link")
	}
	port, err := strconv.Atoi(source.Port)
	if err != nil || port < 1 || port > 65535 || source.Add == "" || source.ID == "" {
		return nil, errors.New("unsupported vmess share link")
	}
	name := source.PS
	if name == "" {
		name = source.Add + ":" + source.Port
	}
	proxy := map[string]any{"name": name, "type": "vmess", "server": source.Add, "port": port, "uuid": source.ID, "udp": true}
	if aid, err := strconv.Atoi(source.Aid); err == nil {
		proxy["alterId"] = aid
	}
	if source.Net != "" {
		proxy["network"] = source.Net
	}
	if source.TLS != "" && source.TLS != "none" {
		proxy["tls"] = true
	}
	if source.SNI != "" {
		proxy["servername"] = source.SNI
	}
	if source.Net == "ws" {
		options := map[string]any{}
		if source.Path != "" {
			options["path"] = source.Path
		}
		if source.Host != "" {
			options["headers"] = map[string]string{"Host": source.Host}
		}
		proxy["ws-opts"] = options
	}
	return proxy, nil
}

func parseShadowsocksLink(raw string) (map[string]any, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("unsupported shadowsocks share link")
	}
	name, _ := url.QueryUnescape(parsed.Fragment)
	userinfo := ""
	host, portRaw := parsed.Hostname(), parsed.Port()
	if parsed.User != nil {
		userinfo = parsed.User.Username()
		if password, ok := parsed.User.Password(); ok {
			userinfo += ":" + password
		}
	}
	if userinfo != "" && !strings.Contains(userinfo, ":") {
		if decoded, ok := decodeProxyBase64(userinfo); ok {
			userinfo = decoded
		}
	}
	if userinfo == "" {
		payload := strings.TrimPrefix(raw, "ss://")
		payload, _, _ = strings.Cut(payload, "#")
		payload, _, _ = strings.Cut(payload, "?")
		if decoded, ok := decodeProxyBase64(payload); ok {
			credentials, address, found := strings.Cut(decoded, "@")
			if found {
				userinfo = credentials
				if addressURL, addressErr := url.Parse("ss://" + address); addressErr == nil {
					host, portRaw = addressURL.Hostname(), addressURL.Port()
				}
			}
		}
	}
	method, password, ok := strings.Cut(userinfo, ":")
	port, portErr := strconv.Atoi(portRaw)
	if !ok || method == "" || password == "" || host == "" || portErr != nil || port < 1 || port > 65535 {
		return nil, errors.New("unsupported shadowsocks share link")
	}
	if name == "" {
		name = host + ":" + portRaw
	}
	return map[string]any{"name": name, "type": "ss", "server": host, "port": port, "cipher": method, "password": password, "udp": true}, nil
}

func decodeProxyBase64(value string) (string, bool) {
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return string(decoded), true
		}
	}
	return "", false
}

func applyTLSOptions(proxy map[string]any, query url.Values) {
	if serverName := firstNonEmpty(query.Get("sni"), query.Get("peer")); serverName != "" {
		proxy["sni"] = serverName
	}
	if query.Get("insecure") == "1" || strings.EqualFold(query.Get("allowInsecure"), "true") {
		proxy["skip-cert-verify"] = true
	}
}

func applyVLESSOptions(proxy map[string]any, query url.Values) {
	if flow := query.Get("flow"); flow != "" {
		proxy["flow"] = flow
	}
	if network := query.Get("type"); network != "" {
		proxy["network"] = network
	}
	if security := query.Get("security"); security == "tls" || security == "reality" {
		proxy["tls"] = true
	}
	if serverName := query.Get("sni"); serverName != "" {
		proxy["servername"] = serverName
	}
	if query.Get("security") == "reality" {
		proxy["reality-opts"] = map[string]any{"public-key": query.Get("pbk"), "short-id": query.Get("sid")}
	}
	if query.Get("type") == "ws" {
		options := map[string]any{}
		if path := query.Get("path"); path != "" {
			options["path"] = path
		}
		if host := query.Get("host"); host != "" {
			options["headers"] = map[string]string{"Host": host}
		}
		proxy["ws-opts"] = options
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

var _ web.ProxySubscriptionService = (*ProxySubscriptionsService)(nil)
