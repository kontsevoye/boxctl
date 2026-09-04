package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

func TestParseCommonProxyShareLinks(t *testing.T) {
	legacySS := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:secret@ss.example:8388"))
	tests := []struct {
		name     string
		link     string
		typeName string
	}{
		{name: "vless", link: "vless://uuid@vless.example:443?security=tls&sni=vless.example#VLESS", typeName: "vless"},
		{name: "trojan", link: "trojan://secret@trojan.example:443?sni=trojan.example#Trojan", typeName: "trojan"},
		{name: "hysteria2", link: "hysteria2://secret@hy.example:443?sni=hy.example#HY2", typeName: "hysteria2"},
		{name: "socks", link: "socks5://user:secret@socks.example:1080#SOCKS", typeName: "socks5"},
		{name: "http", link: "https://user:secret@http.example:443#HTTP", typeName: "http"},
		{name: "shadowsocks sip002", link: "ss://YWVzLTEyOC1nY206c2VjcmV0@ss.example:8388#SS", typeName: "ss"},
		{name: "shadowsocks legacy", link: "ss://" + legacySS + "#Legacy", typeName: "ss"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proxy, err := parseProxyShareLink(test.link)
			if err != nil {
				t.Fatal(err)
			}
			if proxy["type"] != test.typeName || proxy["name"] == "" || proxy["server"] == "" {
				t.Fatalf("proxy = %#v", proxy)
			}
		})
	}
	for _, invalid := range []string{"vless://host.example:443", "trojan://host.example:443", "hysteria2://host.example:443", "ss://not-base64"} {
		if _, err := parseProxyShareLink(invalid); err == nil {
			t.Fatalf("invalid link accepted: %s", invalid)
		}
	}
}

func TestProxySubscriptionsRejectIntervalOutsideOneTo168Hours(t *testing.T) {
	service, err := NewProxySubscriptionsService(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	interval := 169
	_, err = service.CreateProxySubscription(context.Background(), web.ProxySubscriptionDraft{
		Name: "invalid", ShareLinks: "trojan://secret@example.test:443", UpdateIntervalHours: &interval,
	})
	var public *web.PublicError
	if !errors.As(err, &public) || public.Code != "invalid_update_interval" {
		t.Fatalf("error = %v", err)
	}
}

func TestProxySubscriptionCanReturnToResponseHeaderInterval(t *testing.T) {
	service, err := NewProxySubscriptionsService(t.TempDir(), &http.Client{Transport: &subscriptionTransport{}})
	if err != nil {
		t.Fatal(err)
	}
	interval := 1
	created, err := service.CreateProxySubscription(context.Background(), web.ProxySubscriptionDraft{
		Name: "explicit", SourceURL: "https://example.test/subscription", UpdateIntervalHours: &interval,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.UpdateIntervalAuto {
		t.Fatalf("created = %+v", created)
	}
	automatic := true
	updated, err := service.UpdateProxySubscription(context.Background(), created.ID, web.ProxySubscriptionPatch{UpdateIntervalAuto: &automatic})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.UpdateIntervalAuto || updated.UpdateIntervalHours != 1 {
		t.Fatalf("updated = %+v", updated)
	}
	refreshed, err := service.RefreshProxySubscription(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !refreshed.UpdateIntervalAuto || refreshed.UpdateIntervalHours != 12 {
		t.Fatalf("refreshed = %+v", refreshed)
	}
}

func TestProxySubscriptionsShareLinksArePrivateAndGenerateProvider(t *testing.T) {
	root := t.TempDir()
	service, err := NewProxySubscriptionsService(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	secret := "password-secret"
	created, err := service.CreateProxySubscription(context.Background(), web.ProxySubscriptionDraft{
		Name: "Manual", ShareLinks: "trojan://" + secret + "@proxy.example:443?sni=proxy.example#Node",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.SourceKind != "share-links" || created.ProxyCount != 1 || !created.Enabled || strings.Contains(created.ProviderName, secret) {
		t.Fatalf("created = %+v", created)
	}
	cache, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(proxyProviderCachePath(created.ID))))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cache), "type: trojan") || !strings.Contains(string(cache), secret) {
		t.Fatalf("cache = %s", cache)
	}
	info, err := os.Stat(filepath.Join(root, proxySubscriptionsPath))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("registry mode = %v, %v", info, err)
	}
	specs, err := service.EnabledProviderSpecs()
	if err != nil || len(specs) != 1 || !specs[0].Local {
		t.Fatalf("specs = %+v, %v", specs, err)
	}
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(proxyProviderCachePath(created.ID)))); err != nil {
		t.Fatal(err)
	}
	if _, err := service.EnabledProviderSpecs(); err != nil {
		t.Fatal(err)
	}
	if rebuilt, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(proxyProviderCachePath(created.ID)))); err != nil || !strings.Contains(string(rebuilt), secret) {
		t.Fatalf("rebuilt cache = %q, %v", rebuilt, err)
	}
	enabled := false
	updated, err := service.UpdateProxySubscription(context.Background(), created.ID, web.ProxySubscriptionPatch{Enabled: &enabled})
	if err != nil || updated.Enabled {
		t.Fatalf("updated = %+v, %v", updated, err)
	}
	specs, err = service.EnabledProviderSpecs()
	if err != nil || len(specs) != 0 {
		t.Fatalf("disabled specs = %+v, %v", specs, err)
	}
}

func TestProxySubscriptionSourcesAndCachedNodesEnterEndpointBypass(t *testing.T) {
	root := t.TempDir()
	service, err := NewProxySubscriptionsService(root, &http.Client{Transport: &subscriptionTransport{}})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateProxySubscription(context.Background(), web.ProxySubscriptionDraft{Name: "Remote", SourceURL: "https://subscription.example/private"})
	if err != nil {
		t.Fatal(err)
	}
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewEndpointBypassManager(layout, store)
	manager.Resolver = &endpointResolverStub{addresses: map[string][]netip.Addr{
		"subscription.example": {netip.MustParseAddr("198.51.100.10")},
		"127.0.0.1":            {netip.MustParseAddr("127.0.0.1")},
	}, errors: map[string]error{}}
	prefixes, err := manager.Prepare(context.Background(), []byte("mode: rule\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.1/32", "198.51.100.10/32"}
	if got := endpointPrefixStrings(prefixes); !slices.Equal(got, want) {
		t.Fatalf("endpoint bypasses = %v, want %v", got, want)
	}

	enabled := false
	if _, err := service.UpdateProxySubscription(context.Background(), created.ID, web.ProxySubscriptionPatch{Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	prefixes, err = manager.Prepare(context.Background(), []byte("mode: rule\n"))
	if err != nil {
		t.Fatal(err)
	}
	// A disabled subscription can still be refreshed manually. Its source host
	// must bypass interception, while its inactive cached proxy nodes must not.
	want = []string{"198.51.100.10/32"}
	if got := endpointPrefixStrings(prefixes); !slices.Equal(got, want) {
		t.Fatalf("disabled endpoint bypasses = %v, want %v", got, want)
	}
}

func TestProxySubscriptionsRemoteRefreshUsesConditionalHeadersAndUsage(t *testing.T) {
	transport := &subscriptionTransport{}
	client := &http.Client{Transport: transport}
	service, err := NewProxySubscriptionsService(t.TempDir(), client)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRefreshes := 0
	service.OnChanged = func(context.Context) error {
		runtimeRefreshes++
		return nil
	}
	created, err := service.CreateProxySubscription(context.Background(), web.ProxySubscriptionDraft{
		Name: "Remote", SourceURL: "https://example.test/private-token", Headers: map[string]string{"User-Agent": "custom-agent"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ProxyCount != 1 || created.TotalBytes != 300 || created.DownloadBytes != 20 || len(created.HeaderNames) != 1 || created.UpdateIntervalHours != 6 || runtimeRefreshes != 1 {
		t.Fatalf("created = %+v", created)
	}
	specs, err := service.EnabledProviderSpecs()
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 || !specs[0].Local || specs[0].URL != "" || len(specs[0].Headers) != 0 {
		t.Fatalf("remote subscription was not isolated behind its normalized file cache: %+v", specs)
	}
	refreshed, err := service.RefreshProxySubscription(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.ProxyCount != 1 || refreshed.UpdateIntervalHours != 12 || refreshed.DownloadBytes != 25 || transport.requests() != 2 || !transport.conditional() {
		t.Fatalf("refreshed=%+v requests=%d conditional=%v", refreshed, transport.requests(), transport.conditional())
	}
	if _, err := service.RefreshProxySubscription(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	if runtimeRefreshes != 2 || transport.requests() != 3 {
		t.Fatalf("unchanged refresh restarted runtime: refreshes=%d requests=%d", runtimeRefreshes, transport.requests())
	}
	emptyHeaders := map[string]string{}
	withoutHeaders, err := service.UpdateProxySubscription(context.Background(), created.ID, web.ProxySubscriptionPatch{Headers: &emptyHeaders})
	if err != nil {
		t.Fatal(err)
	}
	if len(withoutHeaders.HeaderNames) != 0 {
		t.Fatalf("headers were not cleared: %+v", withoutHeaders)
	}
	encoded, err := service.State.Read(proxySubscriptionsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), "private-token") || strings.Contains(string(encoded), "custom-agent") || strings.Contains(mustJSON(t, refreshed), "private-token") {
		t.Fatal("private source did not stay write-only")
	}
}

func TestProxySubscriptionsRejectUnsafeCustomHeaders(t *testing.T) {
	service, err := NewProxySubscriptionsService(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.CreateProxySubscription(context.Background(), web.ProxySubscriptionDraft{
		Name: "unsafe", ShareLinks: "trojan://secret@example.test:443", Headers: map[string]string{"Authorization": "secret"},
	})
	var public *web.PublicError
	if !errors.As(err, &public) || public.Code != "invalid_subscription_headers" {
		t.Fatalf("error = %v", err)
	}
}

func TestProxySubscriptionsRejectRestoredTraversalIDBeforeRuntimePath(t *testing.T) {
	service, err := NewProxySubscriptionsService(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	registry := proxySubscriptionRegistry{Schema: 1, Items: []proxySubscriptionRecord{{
		ID: "../../../../etc/boxctl-secret", Name: "restored", Enabled: true,
		SourceURL: "https://example.test/subscription", UpdateIntervalHours: 24,
	}}}
	if err := service.State.WriteJSON(proxySubscriptionsPath, registry, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.EnabledProviderSpecs(); err == nil || !strings.Contains(err.Error(), "invalid id") {
		t.Fatalf("restored traversal id error = %v", err)
	}
}

type subscriptionTransport struct {
	mu              sync.Mutex
	count           int
	seenConditional bool
}

func (transport *subscriptionTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.count++
	if request.Header.Get("If-None-Match") == `"provider-v1"` {
		transport.seenConditional = true
		header := make(http.Header)
		header.Set("ETag", `"provider-v1"`)
		header.Set("Profile-Update-Interval", "12")
		header.Set("Subscription-Userinfo", "upload=10; download=25; total=300; expire=1893456000")
		return &http.Response{StatusCode: http.StatusNotModified, Header: header, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	}
	header := make(http.Header)
	header.Set("ETag", `"provider-v1"`)
	header.Set("Profile-Update-Interval", "6")
	header.Set("Subscription-Userinfo", "upload=10; download=20; total=300; expire=1893456000")
	return &http.Response{
		StatusCode: http.StatusOK, Header: header,
		Body: io.NopCloser(strings.NewReader("proxies:\n  - name: node\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n")), Request: request,
	}, nil
}

func (transport *subscriptionTransport) requests() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.count
}
func (transport *subscriptionTransport) conditional() bool {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.seenConditional
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
