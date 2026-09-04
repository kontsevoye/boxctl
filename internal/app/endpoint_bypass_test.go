package app

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kontsevoye/boxctl/internal/state"
)

type endpointResolverStub struct {
	addresses map[string][]netip.Addr
	errors    map[string]error
}

func (resolver *endpointResolverStub) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip4" {
		return nil, errors.New("unexpected network")
	}
	if err := resolver.errors[host]; err != nil {
		return nil, err
	}
	return append([]netip.Addr(nil), resolver.addresses[host]...), nil
}

func TestEndpointBypassManagerCollectsCachesAndRetainsPerHostLKG(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	layout, err := state.NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	providerCache := filepath.Join(layout.ProxyProvidersDir, "remote.yaml")
	if err := os.MkdirAll(filepath.Dir(providerCache), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(providerCache, []byte("proxies:\n  - name: cached\n    server: cached.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pathlessCache := filepath.Join(layout.Root, "proxies", "b357711745d3f0a58ac904c7ace86e7a")
	if err := os.MkdirAll(filepath.Dir(pathlessCache), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathlessCache, []byte("proxies:\n  - name: pathless\n    server: pathless-cache.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteJSON(profileSourcePath("mihomo:remote"), profileSource{
		URL: "https://profile.example/private/profile.yaml?token=secret",
	}, 0o600); err != nil {
		t.Fatal(err)
	}

	resolver := &endpointResolverStub{addresses: map[string][]netip.Addr{
		"node.example":              {netip.MustParseAddr("203.0.113.10")},
		"removed.example":           {netip.MustParseAddr("203.0.113.11")},
		"cached.example":            {netip.MustParseAddr("203.0.113.12")},
		"providers.example":         {netip.MustParseAddr("203.0.113.13")},
		"providers.example.invalid": {netip.MustParseAddr("203.0.113.16")},
		"pathless-cache.example":    {netip.MustParseAddr("203.0.113.17")},
		"rules.example":             {netip.MustParseAddr("203.0.113.14")},
		"profile.example":           {netip.MustParseAddr("203.0.113.15")},
	}, errors: map[string]error{}}
	manager := NewEndpointBypassManager(layout, store)
	manager.Resolver = resolver

	firstSource := []byte(`
proxies:
  - name: node
    server: node.example
  - name: removed
    server: removed.example
  - name: literal
    server: 192.0.2.7
proxy-providers:
  remote:
    type: http
    url: https://providers.example/private/subscription.yaml?token=secret
    path: ./proxy-providers/remote.yaml
  pathless:
    type: http
    url: https://providers.example.invalid/pathless.yaml
rule-providers:
  remote:
    type: http
    url: https://rules.example/private/rules.mrs?token=secret
`)
	first, err := manager.Prepare(context.Background(), firstSource)
	if err != nil {
		t.Fatal(err)
	}
	wantFirst := []string{
		"192.0.2.7/32", "203.0.113.10/32", "203.0.113.11/32", "203.0.113.12/32",
		"203.0.113.13/32", "203.0.113.14/32", "203.0.113.15/32", "203.0.113.16/32", "203.0.113.17/32",
	}
	if got := endpointPrefixStrings(first); !slices.Equal(got, wantFirst) {
		t.Fatalf("first endpoint bypasses = %v, want %v", got, wantFirst)
	}
	cache, err := store.Read(endpointBypassCachePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"node.example", "providers.example", "profile.example", "private", "secret"} {
		if strings.Contains(string(cache), secret) {
			t.Fatalf("endpoint cache leaked source material %q: %s", secret, cache)
		}
	}

	resolver.errors["node.example"] = errors.New("temporary DNS failure")
	resolver.addresses["cached.example"] = []netip.Addr{netip.MustParseAddr("203.0.113.22")}
	secondSource := []byte(`
proxies:
  - name: node
    server: node.example
  - name: literal
    server: 192.0.2.7
proxy-providers:
  remote:
    type: http
    url: https://providers.example/private/subscription.yaml?token=secret
    path: ./proxy-providers/remote.yaml
  pathless:
    type: http
    url: https://providers.example.invalid/pathless.yaml
rule-providers:
  remote:
    type: http
    url: https://rules.example/private/rules.mrs?token=secret
`)
	second, err := manager.Prepare(context.Background(), secondSource)
	if err != nil {
		t.Fatal(err)
	}
	wantSecond := []string{
		"192.0.2.7/32", "203.0.113.10/32", "203.0.113.13/32",
		"203.0.113.14/32", "203.0.113.15/32", "203.0.113.16/32", "203.0.113.17/32", "203.0.113.22/32",
	}
	if got := endpointPrefixStrings(second); !slices.Equal(got, wantSecond) {
		t.Fatalf("refreshed endpoint bypasses = %v, want %v", got, wantSecond)
	}
}

func endpointPrefixStrings(prefixes []netip.Prefix) []string {
	result := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		result[index] = prefix.String()
	}
	slices.Sort(result)
	return result
}
