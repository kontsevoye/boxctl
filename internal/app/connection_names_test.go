package app

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
)

func TestConnectionNameResolverPrefersBoundedLocalSources(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	hosts := filepath.Join(directory, "hosts")
	leases := filepath.Join(directory, "dhcp.leases")
	if err := os.WriteFile(hosts, []byte("192.168.69.20 configured.home configured\nfd00::20 ipv6.home\n203.0.113.20 public.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leases, []byte("0 aa:bb:cc:dd:ee:ff 192.168.69.20 client-name *\n0 aa:bb:cc:dd:ee:00 192.168.69.21 phone *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := newConnectionNameResolver(connectionNameResolverOptions{
		HostFiles: []string{hosts}, LeaseFiles: []string{leases}, HostGlobs: []string{}, ResolvFiles: []string{},
	})
	names := resolver.Resolve(context.Background(), []string{"192.168.69.20", "192.168.69.21", "fd00::20", "203.0.113.20", "invalid"})
	if names["192.168.69.20"] != "configured.home" || names["192.168.69.21"] != "phone" || names["fd00::20"] != "ipv6.home" {
		t.Fatalf("local names = %#v", names)
	}
	if _, exists := names["203.0.113.20"]; exists {
		t.Fatalf("public source was resolved: %#v", names)
	}
}

func TestConnectionNameResolverBoundsAndCachesWANPTRFallback(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	resolv := filepath.Join(directory, "resolv.conf.auto")
	content := "nameserver 127.0.0.1\nnameserver 192.168.69.1\nnameserver 192.168.69.254\nnameserver 1.1.1.1\n"
	if err := os.WriteFile(resolv, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	var lookups []netip.Addr
	resolver := newConnectionNameResolver(connectionNameResolverOptions{
		HostFiles: []string{}, LeaseFiles: []string{}, HostGlobs: []string{}, ResolvFiles: []string{resolv},
		MaxPTRLookups: 1, Now: func() time.Time { return now },
		LocalAddresses: func() map[netip.Addr]struct{} {
			return map[netip.Addr]struct{}{netip.MustParseAddr("192.168.69.1"): {}}
		},
		LookupPTR: func(_ context.Context, addr netip.Addr, servers []netip.Addr) string {
			mu.Lock()
			defer mu.Unlock()
			lookups = append(lookups, addr)
			if len(servers) != 2 || servers[0].String() != "192.168.69.254" || servers[1].String() != "1.1.1.1" {
				t.Errorf("PTR servers = %v", servers)
			}
			if addr.String() == "192.168.69.50" {
				return "living-room.home."
			}
			return ""
		},
	})

	names := resolver.Resolve(context.Background(), []string{"192.168.69.50", "192.168.69.51", "8.8.8.8"})
	if names["192.168.69.50"] != "living-room.home." || len(names) != 1 {
		t.Fatalf("PTR names = %#v", names)
	}
	mu.Lock()
	if len(lookups) != 1 || lookups[0].String() != "192.168.69.50" {
		t.Fatalf("PTR lookups = %v", lookups)
	}
	mu.Unlock()

	// The positive answer is cached, leaving the next bounded slot available
	// for the unresolved address on a later stream snapshot.
	_ = resolver.Resolve(context.Background(), []string{"192.168.69.50", "192.168.69.51"})
	mu.Lock()
	defer mu.Unlock()
	if len(lookups) != 2 || lookups[1].String() != "192.168.69.51" {
		t.Fatalf("cached/bounded PTR lookups = %v", lookups)
	}
}

func TestConnectionNameResolverCoalescesPTRAndEnforcesGlobalLimit(t *testing.T) {
	directory := t.TempDir()
	resolv := filepath.Join(directory, "resolv.conf.auto")
	if err := os.WriteFile(resolv, []byte("nameserver 1.1.1.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	started := make(chan netip.Addr, 4)
	release := make(chan struct{})
	var calls atomic.Int32
	resolver := newConnectionNameResolver(connectionNameResolverOptions{
		HostFiles: []string{}, LeaseFiles: []string{}, HostGlobs: []string{}, ResolvFiles: []string{resolv},
		MaxPTRLookups: 2,
		LookupPTR: func(_ context.Context, addr netip.Addr, _ []netip.Addr) string {
			calls.Add(1)
			started <- addr
			<-release
			return "client.lan."
		},
	})

	var group sync.WaitGroup
	resolveAsync := func(addr string) {
		group.Add(1)
		go func() {
			defer group.Done()
			_ = resolver.Resolve(context.Background(), []string{addr})
		}()
	}
	resolveAsync("192.168.69.50")
	if addr := <-started; addr.String() != "192.168.69.50" {
		t.Fatalf("first lookup = %s", addr)
	}
	for range 16 {
		resolveAsync("192.168.69.50")
	}
	resolveAsync("192.168.69.51")
	if addr := <-started; addr.String() != "192.168.69.51" {
		t.Fatalf("second lookup = %s", addr)
	}
	if names := resolver.Resolve(context.Background(), []string{"192.168.69.52"}); len(names) != 0 {
		t.Fatalf("lookup beyond global limit returned %#v", names)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("PTR calls while both global slots are occupied = %d, want 2", got)
	}

	close(release)
	group.Wait()
	if got := calls.Load(); got != 2 {
		t.Fatalf("coalesced PTR calls = %d, want 2", got)
	}
}

type connectionNameResolverStub map[string]string

func (stub connectionNameResolverStub) Resolve(_ context.Context, _ []string) map[string]string {
	return stub
}

func TestCoreServiceEnrichesConnectionSourceWithoutReplacingRawIP(t *testing.T) {
	t.Parallel()
	backend := newCoreBackendFake()
	backend.capabilities = engine.Capabilities{Connections: true}
	backend.connections = engine.ConnectionsSnapshot{Connections: []engine.Connection{{
		ID: "named", Metadata: engine.ConnectionMetadata{SourceIP: "192.168.69.42", SourcePort: "54321"},
	}}}
	service, err := NewCoreService(
		&Lifecycle{snap: LifecycleSnapshot{State: LifecycleRunning}},
		&corePreparerFake{}, backend,
		CoreServiceOptions{ConnectionNames: connectionNameResolverStub{"192.168.69.42": "phone.home."}},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	connections, err := service.Connections(context.Background())
	if err != nil || len(connections) != 1 {
		t.Fatalf("Connections() = %#v, %v", connections, err)
	}
	connection := connections[0]
	if connection.Source != "192.168.69.42:54321" || connection.SourceHostname != "phone.home." || connection.SourceIP != "192.168.69.42" {
		t.Fatalf("named connection = %#v", connection)
	}
}

func TestSafeConnectionHostnameRejectsDisplayControlValues(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"", "*", "192.168.69.1", "bad host", "bad\nname", string([]byte{0xff})} {
		if got := safeConnectionHostname(value); got != "" {
			t.Fatalf("safeConnectionHostname(%q) = %q", value, got)
		}
	}
	if got := safeConnectionHostname("printer.lan."); got != "printer.lan." {
		t.Fatalf("safeConnectionHostname(FQDN) = %q", got)
	}
}
