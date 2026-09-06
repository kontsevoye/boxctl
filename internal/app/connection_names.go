package app

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	defaultConnectionNameRefreshInterval = 5 * time.Second
	defaultConnectionNamePTRTimeout      = 750 * time.Millisecond
	defaultConnectionNamePositiveTTL     = 10 * time.Minute
	defaultConnectionNameNegativeTTL     = 30 * time.Second
	defaultConnectionNamePTRLookups      = 8
	maximumConnectionNameServers         = 4
	maximumConnectionNameFiles           = 64
	maximumConnectionNameCacheEntries    = 4_096
	maximumConnectionNameFileBytes       = int64(2 << 20)
	maximumConnectionNameLineBytes       = 64 << 10
)

var (
	defaultConnectionLeaseFiles = []string{
		"/tmp/dhcp.leases",
		"/var/lib/misc/dnsmasq.leases",
	}
	defaultConnectionHostFiles = []string{
		"/etc/hosts",
		"/opt/etc/hosts",
		"/tmp/hosts/odhcpd",
	}
	defaultConnectionHostGlobs = []string{
		"/tmp/hosts/dhcp.cfg*",
		"/tmp/hosts/dhcp.*",
	}
	defaultConnectionResolvFiles = []string{
		"/tmp/resolv.conf.d/resolv.conf.auto",
		"/tmp/resolv.conf.auto",
		"/etc/resolv.conf",
	}
)

// ConnectionNameResolver enriches untrusted core connection metadata with
// advisory local names. Implementations must remain bounded because this path
// feeds both one-shot requests and a live stream.
type ConnectionNameResolver interface {
	Resolve(context.Context, []string) map[string]string
}

type connectionNameLookup func(context.Context, netip.Addr, []netip.Addr) string

type connectionNameResolverOptions struct {
	LeaseFiles      []string
	HostFiles       []string
	HostGlobs       []string
	ResolvFiles     []string
	RefreshInterval time.Duration
	PTRTimeout      time.Duration
	PositiveTTL     time.Duration
	NegativeTTL     time.Duration
	MaxPTRLookups   int
	Now             func() time.Time
	LookupPTR       connectionNameLookup
	LocalAddresses  func() map[netip.Addr]struct{}
}

type localConnectionNameResolver struct {
	leaseFiles      []string
	hostFiles       []string
	hostGlobs       []string
	resolvFiles     []string
	refreshInterval time.Duration
	ptrTimeout      time.Duration
	positiveTTL     time.Duration
	negativeTTL     time.Duration
	maxPTRLookups   int
	now             func() time.Time
	lookupPTR       connectionNameLookup
	localAddresses  func() map[netip.Addr]struct{}

	mu             sync.Mutex
	localNames     map[netip.Addr]string
	nameServers    []netip.Addr
	localRefreshed time.Time
	ptrCache       map[netip.Addr]connectionNameCacheEntry
	ptrInflight    map[netip.Addr]*connectionNameInflight
	ptrSlots       chan struct{}
}

type connectionNameCacheEntry struct {
	name    string
	expires time.Time
}

type connectionNameInflight struct {
	done chan struct{}
	name string
}

func newConnectionNameResolver(options connectionNameResolverOptions) *localConnectionNameResolver {
	resolver := &localConnectionNameResolver{
		leaseFiles:      defaultStringSlice(options.LeaseFiles, defaultConnectionLeaseFiles),
		hostFiles:       defaultStringSlice(options.HostFiles, defaultConnectionHostFiles),
		hostGlobs:       defaultStringSlice(options.HostGlobs, defaultConnectionHostGlobs),
		resolvFiles:     defaultStringSlice(options.ResolvFiles, defaultConnectionResolvFiles),
		refreshInterval: options.RefreshInterval,
		ptrTimeout:      options.PTRTimeout,
		positiveTTL:     options.PositiveTTL,
		negativeTTL:     options.NegativeTTL,
		maxPTRLookups:   options.MaxPTRLookups,
		now:             options.Now,
		lookupPTR:       options.LookupPTR,
		localAddresses:  options.LocalAddresses,
		ptrCache:        make(map[netip.Addr]connectionNameCacheEntry),
	}
	if resolver.refreshInterval <= 0 {
		resolver.refreshInterval = defaultConnectionNameRefreshInterval
	}
	if resolver.ptrTimeout <= 0 {
		resolver.ptrTimeout = defaultConnectionNamePTRTimeout
	}
	if resolver.positiveTTL <= 0 {
		resolver.positiveTTL = defaultConnectionNamePositiveTTL
	}
	if resolver.negativeTTL <= 0 {
		resolver.negativeTTL = defaultConnectionNameNegativeTTL
	}
	if resolver.maxPTRLookups <= 0 {
		resolver.maxPTRLookups = defaultConnectionNamePTRLookups
	}
	if resolver.now == nil {
		resolver.now = time.Now
	}
	if resolver.lookupPTR == nil {
		resolver.lookupPTR = lookupConnectionPTR
	}
	if resolver.localAddresses == nil {
		resolver.localAddresses = connectionLocalAddresses
	}
	resolver.ptrInflight = make(map[netip.Addr]*connectionNameInflight)
	resolver.ptrSlots = make(chan struct{}, resolver.maxPTRLookups)
	return resolver
}

func defaultStringSlice(value, fallback []string) []string {
	if value == nil {
		value = fallback
	}
	return append([]string(nil), value...)
}

// Resolve consults local ownership data first, then performs at most a small
// number of concurrent PTR queries against WAN-provided resolvers. Only RFC1918
// and ULA source addresses are eligible, so arbitrary controller metadata
// cannot turn boxctl into a general reverse-DNS scanner.
func (resolver *localConnectionNameResolver) Resolve(ctx context.Context, sourceIPs []string) map[string]string {
	result := make(map[string]string)
	if resolver == nil || len(sourceIPs) == 0 {
		return result
	}
	now := resolver.now()
	localNames, nameServers := resolver.sources(now)
	requested := make(map[netip.Addr][]string)
	ordered := make([]netip.Addr, 0, len(sourceIPs))
	for _, raw := range sourceIPs {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if !addr.IsPrivate() {
			continue
		}
		_, seen := requested[addr]
		requested[addr] = append(requested[addr], raw)
		if name := localNames[addr]; name != "" {
			result[raw] = name
			continue
		}
		if seen {
			continue
		}
		ordered = append(ordered, addr)
	}

	type pendingLookup struct {
		addr   netip.Addr
		flight *connectionNameInflight
	}
	pending := make([]pendingLookup, 0, min(len(ordered), resolver.maxPTRLookups))
	resolver.mu.Lock()
	resolver.prunePTRCache(now)
	for _, addr := range ordered {
		entry, cached := resolver.ptrCache[addr]
		if cached && now.Before(entry.expires) {
			if entry.name != "" {
				for _, raw := range requested[addr] {
					result[raw] = entry.name
				}
			}
			continue
		}
		delete(resolver.ptrCache, addr)
		if len(pending) >= resolver.maxPTRLookups {
			continue
		}
		flight := resolver.ptrInflight[addr]
		if flight == nil && len(nameServers) > 0 && ctx.Err() == nil {
			select {
			case resolver.ptrSlots <- struct{}{}:
				flight = &connectionNameInflight{done: make(chan struct{})}
				resolver.ptrInflight[addr] = flight
				go resolver.runPTRLookup(addr, nameServers, flight)
			default:
				// Other authenticated streams already own all global PTR slots.
			}
		}
		if flight != nil {
			pending = append(pending, pendingLookup{addr: addr, flight: flight})
		}
	}
	resolver.mu.Unlock()
	for _, lookup := range pending {
		select {
		case <-lookup.flight.done:
			if lookup.flight.name != "" {
				for _, raw := range requested[lookup.addr] {
					result[raw] = lookup.flight.name
				}
			}
		case <-ctx.Done():
			return result
		}
	}
	return result
}

func (resolver *localConnectionNameResolver) runPTRLookup(addr netip.Addr, nameServers []netip.Addr, flight *connectionNameInflight) {
	lookupContext, cancel := context.WithTimeout(context.Background(), resolver.ptrTimeout)
	name := safeConnectionHostname(resolver.lookupPTR(lookupContext, addr, nameServers))
	cancel()

	now := resolver.now()
	ttl := resolver.positiveTTL
	if name == "" {
		ttl = resolver.negativeTTL
	}
	resolver.mu.Lock()
	resolver.cachePTR(addr, connectionNameCacheEntry{name: name, expires: now.Add(ttl)})
	flight.name = name
	delete(resolver.ptrInflight, addr)
	close(flight.done)
	resolver.mu.Unlock()
	<-resolver.ptrSlots
}

func (resolver *localConnectionNameResolver) prunePTRCache(now time.Time) {
	for addr, entry := range resolver.ptrCache {
		if !now.Before(entry.expires) {
			delete(resolver.ptrCache, addr)
		}
	}
}

func (resolver *localConnectionNameResolver) cachePTR(addr netip.Addr, entry connectionNameCacheEntry) {
	if _, exists := resolver.ptrCache[addr]; !exists && len(resolver.ptrCache) >= maximumConnectionNameCacheEntries {
		var oldestAddr netip.Addr
		var oldestExpiry time.Time
		for candidate, cached := range resolver.ptrCache {
			if oldestExpiry.IsZero() || cached.expires.Before(oldestExpiry) {
				oldestAddr = candidate
				oldestExpiry = cached.expires
			}
		}
		delete(resolver.ptrCache, oldestAddr)
	}
	resolver.ptrCache[addr] = entry
}

func (resolver *localConnectionNameResolver) sources(now time.Time) (map[netip.Addr]string, []netip.Addr) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.localNames == nil || now.Before(resolver.localRefreshed) || now.Sub(resolver.localRefreshed) >= resolver.refreshInterval {
		resolver.localNames = readConnectionLocalNames(resolver.hostFiles, resolver.hostGlobs, resolver.leaseFiles)
		resolver.nameServers = readConnectionNameServers(resolver.resolvFiles, resolver.localAddresses())
		resolver.localRefreshed = now
	}
	return resolver.localNames, append([]netip.Addr(nil), resolver.nameServers...)
}

func readConnectionLocalNames(hostFiles, hostGlobs, leaseFiles []string) map[netip.Addr]string {
	result := make(map[netip.Addr]string)
	files := append([]string(nil), hostFiles...)
	for _, pattern := range hostGlobs {
		matches, _ := filepath.Glob(pattern)
		sort.Strings(matches)
		remaining := maximumConnectionNameFiles - len(files)
		if remaining <= 0 {
			break
		}
		if len(matches) > remaining {
			matches = matches[:remaining]
		}
		files = append(files, matches...)
	}
	seen := make(map[string]struct{}, len(files))
	for index, filename := range files {
		if index >= maximumConnectionNameFiles {
			break
		}
		filename = filepath.Clean(filename)
		if _, duplicate := seen[filename]; duplicate {
			continue
		}
		seen[filename] = struct{}{}
		readConnectionNameFile(filename, func(fields []string) {
			addr, name, ok := parseConnectionHostFields(fields)
			if ok {
				setConnectionLocalName(result, addr, name)
			}
		})
	}
	remaining := maximumConnectionNameFiles - len(seen)
	for index, filename := range leaseFiles {
		if index >= remaining {
			break
		}
		readConnectionNameFile(filename, func(fields []string) {
			addr, name, ok := parseConnectionLeaseFields(fields)
			if ok {
				setConnectionLocalName(result, addr, name)
			}
		})
	}
	return result
}

func readConnectionNameFile(filename string, consume func([]string)) {
	info, err := os.Stat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximumConnectionNameFileBytes {
		return
	}
	// #nosec G304 -- callers supply only fixed, administrator-owned host,
	// lease, and resolver paths; the options are package-private test hooks.
	file, err := os.Open(filename)
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, maximumConnectionNameFileBytes))
	scanner.Buffer(make([]byte, 4<<10), maximumConnectionNameLineBytes)
	for scanner.Scan() {
		line := scanner.Text()
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = line[:comment]
		}
		if fields := strings.Fields(line); len(fields) > 0 {
			consume(fields)
		}
	}
}

func parseConnectionHostFields(fields []string) (netip.Addr, string, bool) {
	if len(fields) < 2 {
		return netip.Addr{}, "", false
	}
	addr, err := netip.ParseAddr(fields[0])
	if err != nil {
		return netip.Addr{}, "", false
	}
	for _, candidate := range fields[1:] {
		if name := safeConnectionHostname(candidate); name != "" {
			return addr.Unmap(), name, true
		}
	}
	return netip.Addr{}, "", false
}

func parseConnectionLeaseFields(fields []string) (netip.Addr, string, bool) {
	if len(fields) < 4 {
		return netip.Addr{}, "", false
	}
	addr, err := netip.ParseAddr(fields[2])
	name := safeConnectionHostname(fields[3])
	if err != nil || name == "" {
		return netip.Addr{}, "", false
	}
	return addr.Unmap(), name, true
}

func setConnectionLocalName(names map[netip.Addr]string, addr netip.Addr, name string) {
	if !addr.IsValid() || !addr.IsPrivate() || name == "" {
		return
	}
	if _, exists := names[addr]; !exists {
		names[addr] = name
	}
}

func safeConnectionHostname(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "*" || len(value) > 253 || !utf8.ValidString(value) {
		return ""
	}
	if addr, err := netip.ParseAddr(strings.TrimSuffix(value, ".")); err == nil && addr.IsValid() {
		return ""
	}
	if strings.IndexFunc(value, func(character rune) bool {
		return unicode.IsControl(character) || unicode.IsSpace(character)
	}) >= 0 {
		return ""
	}
	return value
}

func readConnectionNameServers(files []string, local map[netip.Addr]struct{}) []netip.Addr {
	result := make([]netip.Addr, 0, maximumConnectionNameServers)
	seen := make(map[netip.Addr]struct{})
	for index, filename := range files {
		if index >= maximumConnectionNameFiles {
			break
		}
		readConnectionNameFile(filename, func(fields []string) {
			if len(result) >= maximumConnectionNameServers || len(fields) < 2 || !strings.EqualFold(fields[0], "nameserver") {
				return
			}
			addr, err := netip.ParseAddr(fields[1])
			if err != nil {
				return
			}
			addr = addr.Unmap()
			if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() {
				return
			}
			if _, isLocal := local[addr]; isLocal {
				return
			}
			if _, duplicate := seen[addr]; duplicate {
				return
			}
			seen[addr] = struct{}{}
			result = append(result, addr)
		})
		if len(result) >= maximumConnectionNameServers {
			break
		}
	}
	return result
}

func connectionLocalAddresses() map[netip.Addr]struct{} {
	result := make(map[netip.Addr]struct{})
	addresses, _ := net.InterfaceAddrs()
	for _, value := range addresses {
		prefix, err := netip.ParsePrefix(value.String())
		if err == nil {
			result[prefix.Addr().Unmap()] = struct{}{}
		}
	}
	return result
}

func lookupConnectionPTR(ctx context.Context, addr netip.Addr, servers []netip.Addr) string {
	for _, server := range servers {
		server := server
		dialer := &net.Dialer{}
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(dialContext context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(dialContext, network, net.JoinHostPort(server.String(), "53"))
			},
		}
		names, err := resolver.LookupAddr(ctx, addr.String())
		if err != nil {
			if ctx.Err() != nil {
				return ""
			}
			continue
		}
		for _, candidate := range names {
			if name := safeConnectionHostname(candidate); name != "" {
				return name
			}
		}
	}
	return ""
}

var _ ConnectionNameResolver = (*localConnectionNameResolver)(nil)
