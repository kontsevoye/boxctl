package app

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/bits"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	configpkg "github.com/kontsevoye/boxctl/internal/config"
	"github.com/kontsevoye/boxctl/internal/fakeip"
	"github.com/kontsevoye/boxctl/internal/state"
	"go.yaml.in/yaml/v3"
)

const maxRuleProviderBytes = 16 << 20

var errFakeIPModeNotApplicable = errors.New("fake-IP destination pool is not applicable")

var errRuleProviderPathEscape = errors.New("rule-provider path escapes trusted cache roots")

// FakeIPCaptureManager builds the destination allowlist without changing the
// user-owned Mihomo configuration. Generated state lives in
// local-rules/fakeip-whitelist-ipcidr.txt.
type FakeIPCaptureManager struct {
	Layout state.Layout
	Store  *fakeip.Store
	Now    func() time.Time

	// TrustedProviderCacheRoots contains manager-owned cache directories outside
	// the persistent state root. The production constructor permits only the
	// private tmpfs directory used by runtime rule-provider relocation.
	TrustedProviderCacheRoots []string

	mu           sync.RWMutex
	lastWarnings []string
}

// FakeIPCaptureOptions controls which referenced provider sources may extend
// the generated destination pool. The zero value deliberately includes only
// user-managed inline and local-rules providers.
type FakeIPCaptureOptions struct {
	// IncludeExternalIPProviders also consumes non-local file providers and local
	// caches of referenced HTTP providers, including MRS caches.
	IncludeExternalIPProviders bool
}

type fakeIPCapturePolicy struct {
	Document     fakeip.Document
	FakeIPRanges []netip.Prefix
	Effective    []netip.Prefix
	FilterMode   string
	Applicable   bool
	Selective    bool
	Warnings     []string
}

func NewFakeIPCaptureManager(layout state.Layout) *FakeIPCaptureManager {
	return &FakeIPCaptureManager{
		Layout:                    layout,
		Store:                     &fakeip.Store{Directory: layout.LocalRulesDir},
		Now:                       time.Now,
		TrustedProviderCacheRoots: []string{tmpfsRuleProviderPath()},
	}
}

// Prepare resolves the immutable policy used for one core/firewall generation.
// AUTO regeneration happens only for whitelist/rule mode; blacklist still
// captures the fake-IP range but deliberately ignores the additional file.
func (manager *FakeIPCaptureManager) Prepare(source []byte, auto bool) (fakeIPCapturePolicy, error) {
	return manager.PrepareWithOptions(source, auto, FakeIPCaptureOptions{})
}

// PrepareWithOptions is Prepare with an explicit provider-source policy.
func (manager *FakeIPCaptureManager) PrepareWithOptions(source []byte, auto bool, options FakeIPCaptureOptions) (fakeIPCapturePolicy, error) {
	return manager.prepareWithOptions(source, auto, options, true)
}

// PreviewWithOptions computes the same candidate policy as PrepareWithOptions
// without publishing an AUTO block or changing the manager's shared warning
// state. Explicit profile preparation uses this before its surrounding switch
// transaction has a durable journal.
func (manager *FakeIPCaptureManager) PreviewWithOptions(source []byte, auto bool, options FakeIPCaptureOptions) (fakeIPCapturePolicy, error) {
	return manager.prepareWithOptions(source, auto, options, false)
}

func (manager *FakeIPCaptureManager) prepareWithOptions(source []byte, auto bool, options FakeIPCaptureOptions, persist bool) (fakeIPCapturePolicy, error) {
	routing, policy, err := manager.parsePolicy(source)
	if err != nil || !policy.Applicable {
		if err == nil && persist {
			manager.setWarnings(nil)
		}
		return policy, err
	}
	document, err := manager.store().Read()
	if err != nil {
		return fakeIPCapturePolicy{}, fmt.Errorf("read fake-IP destination pool: %w", err)
	}
	if auto {
		document, policy.Warnings, err = manager.regenerate(routing, document, document.Revision, options, persist)
		if persist {
			manager.setWarnings(policy.Warnings)
		}
		if err != nil {
			return fakeIPCapturePolicy{}, err
		}
	} else if persist {
		manager.setWarnings(nil)
	}
	return finalizeFakeIPPolicy(policy, document), nil
}

// Inspect returns current file/config state without regenerating or writing it.
func (manager *FakeIPCaptureManager) Inspect(source []byte) (fakeIPCapturePolicy, error) {
	_, policy, err := manager.parsePolicy(source)
	if err != nil {
		return fakeIPCapturePolicy{}, err
	}
	document, err := manager.store().Read()
	if err != nil {
		return fakeIPCapturePolicy{}, fmt.Errorf("read fake-IP destination pool: %w", err)
	}
	policy.Warnings = manager.warnings()
	return finalizeFakeIPPolicy(policy, document), nil
}

// Regenerate replaces only the AUTO block using an optimistic revision.
func (manager *FakeIPCaptureManager) Regenerate(source []byte, revision string) (fakeIPCapturePolicy, error) {
	return manager.RegenerateWithOptions(source, revision, FakeIPCaptureOptions{})
}

// RegenerateWithOptions is Regenerate with an explicit provider-source policy.
func (manager *FakeIPCaptureManager) RegenerateWithOptions(source []byte, revision string, options FakeIPCaptureOptions) (fakeIPCapturePolicy, error) {
	routing, policy, err := manager.parsePolicy(source)
	if err != nil {
		return fakeIPCapturePolicy{}, err
	}
	if !policy.Applicable {
		return fakeIPCapturePolicy{}, errFakeIPModeNotApplicable
	}
	document, err := manager.store().Read()
	if err != nil {
		return fakeIPCapturePolicy{}, fmt.Errorf("read fake-IP destination pool: %w", err)
	}
	document, policy.Warnings, err = manager.regenerate(routing, document, revision, options, true)
	manager.setWarnings(policy.Warnings)
	if err != nil {
		return fakeIPCapturePolicy{}, err
	}
	return finalizeFakeIPPolicy(policy, document), nil
}

func (manager *FakeIPCaptureManager) parsePolicy(source []byte) (configpkg.MihomoRouting, fakeIPCapturePolicy, error) {
	routing, err := configpkg.ParseMihomoRouting(source)
	if err != nil {
		return configpkg.MihomoRouting{}, fakeIPCapturePolicy{}, fmt.Errorf("inspect Mihomo routing policy: %w", err)
	}
	policy := fakeIPCapturePolicy{}
	if routing.DNS.FakeIPFilterMode != nil {
		policy.FilterMode = strings.ToLower(strings.TrimSpace(*routing.DNS.FakeIPFilterMode))
	}
	dnsEnabled := routing.DNS.Enabled != nil && *routing.DNS.Enabled
	fakeIP := dnsEnabled && routing.DNS.EnhancedMode != nil && strings.EqualFold(strings.TrimSpace(*routing.DNS.EnhancedMode), "fake-ip")
	if !fakeIP {
		return routing, policy, nil
	}
	fakeRange := defaultMihomoFakeIPRange
	if routing.DNS.FakeIPRange != nil && strings.TrimSpace(*routing.DNS.FakeIPRange) != "" {
		fakeRange = strings.TrimSpace(*routing.DNS.FakeIPRange)
	}
	prefix, err := parseCaptureIPv4Prefix(fakeRange)
	if err != nil {
		return configpkg.MihomoRouting{}, fakeIPCapturePolicy{}, fmt.Errorf("parse Mihomo fake-IP range: %w", err)
	}
	policy.Selective = true
	policy.FakeIPRanges = []netip.Prefix{prefix}
	policy.Applicable = policy.FilterMode == "whitelist" || policy.FilterMode == "rule"
	policy.Effective = append([]netip.Prefix(nil), policy.FakeIPRanges...)
	return routing, policy, nil
}

func finalizeFakeIPPolicy(policy fakeIPCapturePolicy, document fakeip.Document) fakeIPCapturePolicy {
	policy.Document = document
	effective := append([]netip.Prefix(nil), policy.FakeIPRanges...)
	if policy.Applicable {
		effective = append(effective, document.Effective...)
	}
	policy.Effective = normalizeNetPrefixes(effective)
	policy.Warnings = slices.Compact(policy.Warnings)
	return policy
}

func (manager *FakeIPCaptureManager) regenerate(routing configpkg.MihomoRouting, current fakeip.Document, revision string, options FakeIPCaptureOptions, persist bool) (fakeip.Document, []string, error) {
	// Regeneration is an optimistic mutation even when one of the providers is
	// unavailable and the safe outcome is either a compatible LKG or a
	// scope-narrowed partial block. Never turn either fallback into a way to
	// accept a stale browser revision.
	if revision == "" || revision != current.Revision {
		return fakeip.Document{}, nil, fakeip.ErrConflict
	}
	generated, warnings, complete, err := manager.generate(routing, options)
	if err != nil {
		return fakeip.Document{}, nil, fmt.Errorf("generate fake-IP destination pool: %w", err)
	}
	targetScope := fakeIPCaptureAutoScope(options)
	if !complete {
		if fakeIPCaptureScopeCompatible(current.GeneratedScope, targetScope) && current.HasGenerated {
			warnings = append(warnings, "AUTO generation was incomplete; retained the last-known-good generated pool")
			return current, warnings, nil
		}
		if !current.HasGenerated {
			return fakeip.Document{}, warnings, errors.New("AUTO fake-IP destination pool is incomplete and has no last-known-good block")
		}
		// A local-only run must never retain a legacy or all-providers block:
		// that would keep remote CIDRs active after the user opts out. Publish
		// only the successfully collected inputs for the requested scope. The
		// store keeps the optimistic revision check and atomic rename semantics.
		warnings = append(warnings, fmt.Sprintf("AUTO generation was incomplete; replaced the incompatible %s generated pool with currently available %s inputs", fakeIPCaptureScopeLabel(current.GeneratedScope), targetScope))
	}
	generatedAt := time.Now().UTC()
	if manager != nil && manager.Now != nil {
		generatedAt = manager.Now().UTC()
	}
	var document fakeip.Document
	if persist {
		document, err = manager.store().ReplaceGeneratedWithScope(generated, revision, generatedAt, targetScope)
	} else {
		document, err = manager.store().PreviewReplaceGeneratedWithScope(generated, revision, generatedAt, targetScope)
	}
	if err != nil {
		return fakeip.Document{}, warnings, err
	}
	return document, warnings, nil
}

func fakeIPCaptureAutoScope(options FakeIPCaptureOptions) string {
	if options.IncludeExternalIPProviders {
		return fakeip.AutoScopeAllProviders
	}
	return fakeip.AutoScopeLocalOnly
}

func fakeIPCaptureScopeCompatible(current, target string) bool {
	if current == target {
		return true
	}
	// Before scope provenance existed AUTO generation consumed all referenced
	// providers. A legacy block is therefore compatible only with an explicit
	// all-providers request, never with the local-only default.
	return current == "" && target == fakeip.AutoScopeAllProviders
}

func fakeIPCaptureScopeLabel(scope string) string {
	if scope == "" {
		return "legacy/unknown-scope"
	}
	return scope
}

func (manager *FakeIPCaptureManager) generate(routing configpkg.MihomoRouting, options FakeIPCaptureOptions) ([]netip.Prefix, []string, bool, error) {
	inputs, err := configpkg.CollectMihomoAutoInputs(routing.Rules, fakeip.MaxEntries)
	if err != nil {
		if errors.Is(err, configpkg.ErrMihomoAutoInputsTooLarge) {
			return nil, nil, false, fakeip.ErrTooManyEntries
		}
		return nil, nil, false, err
	}
	providerNames, err := fakeIPFilterProviderNames(routing.DNS, inputs.ProviderNames, fakeip.MaxEntries)
	if err != nil {
		return nil, nil, false, err
	}
	result := make([]netip.Prefix, 0, len(inputs.InlineIPv4))
	seen := make(map[netip.Prefix]struct{}, len(inputs.InlineIPv4))
	if err := appendBoundedCapturePrefixes(&result, seen, inputs.InlineIPv4, fakeip.MaxEntries); err != nil {
		return nil, nil, false, err
	}
	warnings := make([]string, 0)
	complete := true
	for _, name := range providerNames {
		provider, exists := routing.RuleProviders[name]
		if !exists {
			warnings = append(warnings, fmt.Sprintf("rule-provider %q is unavailable", name))
			complete = false
			continue
		}
		if !manager.includeAutoProvider(provider, options) {
			continue
		}
		// HTTP providers are consumed only through their configured local cache;
		// this routine never performs a network fetch while building a firewall
		// allowlist. Inline payload remains explicit local configuration.
		providerType := strings.ToLower(strings.TrimSpace(provider.Type))
		if providerType != "file" && providerType != "inline" && providerType != "http" {
			continue
		}
		prefixes, loadErr := manager.providerPrefixes(provider)
		if loadErr != nil {
			warnings = append(warnings, fmt.Sprintf("rule-provider %q could not provide IPv4 CIDRs", name))
			complete = false
			continue
		}
		if err := appendBoundedCapturePrefixes(&result, seen, prefixes, fakeip.MaxEntries); err != nil {
			return nil, warnings, false, err
		}
	}
	return normalizeNetPrefixes(result), warnings, complete, nil
}

func (manager *FakeIPCaptureManager) includeAutoProvider(provider configpkg.MihomoRuleProvider, options FakeIPCaptureOptions) bool {
	if options.IncludeExternalIPProviders {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(provider.Type)) {
	case "inline":
		return true
	case "file":
		return manager.providerPathIsInLocalRules(provider.Path)
	default:
		return false
	}
}

func (manager *FakeIPCaptureManager) providerPathIsInLocalRules(pathValue string) bool {
	pathValue = strings.TrimSpace(pathValue)
	if pathValue == "" || strings.TrimSpace(manager.Layout.Root) == "" || strings.TrimSpace(manager.Layout.LocalRulesDir) == "" {
		return false
	}
	candidate := pathValue
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(manager.Layout.Root, candidate)
	}
	candidate, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	localRulesRoot, err := filepath.Abs(manager.Layout.LocalRulesDir)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(localRulesRoot, candidate)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func fakeIPFilterProviderNames(dns configpkg.MihomoRoutingDNS, ruleProviders []string, maxEntries int) ([]string, error) {
	if maxEntries <= 0 {
		return nil, fakeip.ErrTooManyEntries
	}
	result := make([]string, 0, min(len(ruleProviders), maxEntries))
	seen := make(map[string]struct{}, min(len(ruleProviders), maxEntries))
	appendName := func(name string) error {
		if _, exists := seen[name]; exists {
			return nil
		}
		if len(result) >= maxEntries {
			return fakeip.ErrTooManyEntries
		}
		seen[name] = struct{}{}
		result = append(result, name)
		return nil
	}
	for _, name := range ruleProviders {
		if err := appendName(name); err != nil {
			return nil, err
		}
	}
	mode := ""
	if dns.FakeIPFilterMode != nil {
		mode = strings.ToLower(strings.TrimSpace(*dns.FakeIPFilterMode))
	}
	for _, raw := range dns.FakeIPFilter {
		name := ""
		switch mode {
		case "whitelist":
			trimmed := strings.TrimSpace(raw)
			if len(trimmed) > len("rule-set:") && strings.EqualFold(trimmed[:len("rule-set:")], "rule-set:") {
				name = strings.TrimSpace(trimmed[len("rule-set:"):])
			}
		case "rule":
			rule, err := configpkg.ParseMihomoRule(raw)
			if err != nil {
				return nil, fmt.Errorf("parse dns.fake-ip-filter rule: %w", err)
			}
			if rule.Type == "RULE-SET" && len(rule.Arguments) == 1 && strings.EqualFold(strings.TrimSpace(rule.Action), "fake-ip") {
				name = strings.TrimSpace(rule.Arguments[0])
			}
		}
		if name == "" {
			continue
		}
		if err := appendName(name); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func appendBoundedCapturePrefixes(result *[]netip.Prefix, seen map[netip.Prefix]struct{}, values []netip.Prefix, maxEntries int) error {
	if maxEntries <= 0 {
		return fakeip.ErrTooManyEntries
	}
	for _, prefix := range values {
		if !prefix.IsValid() {
			continue
		}
		prefix = prefix.Masked()
		if _, exists := seen[prefix]; exists {
			continue
		}
		if len(*result) >= maxEntries {
			return fakeip.ErrTooManyEntries
		}
		seen[prefix] = struct{}{}
		*result = append(*result, prefix)
	}
	return nil
}

func (manager *FakeIPCaptureManager) providerPrefixes(provider configpkg.MihomoRuleProvider) ([]netip.Prefix, error) {
	behavior := strings.ToLower(strings.TrimSpace(provider.Behavior))
	if behavior == "domain" {
		return []netip.Prefix{}, nil
	}
	if behavior != "ipcidr" && behavior != "classical" {
		return nil, errors.New("unsupported rule-provider behavior")
	}
	items := provider.Payload
	if items == nil {
		pathOnDisk, format, err := manager.providerPath(provider)
		if err != nil {
			return nil, err
		}
		if format == "mrs" {
			content, err := readBoundedRegular(pathOnDisk, maxRuleProviderBytes)
			if err != nil {
				return nil, err
			}
			return decodeMRSIPv4Prefixes(content)
		}
		content, err := readBoundedRegular(pathOnDisk, maxRuleProviderBytes)
		if err != nil {
			return nil, err
		}
		switch format {
		case "text":
			items = providerTextItems(content)
		case "yaml", "yml", "":
			var document struct {
				Payload []string `yaml:"payload"`
			}
			if err := yaml.Unmarshal(content, &document); err != nil || document.Payload == nil {
				return nil, errors.New("invalid YAML rule-provider")
			}
			items = document.Payload
		default:
			return nil, errors.New("unsupported rule-provider format")
		}
	}
	result := make([]netip.Prefix, 0, min(len(items), fakeip.MaxEntries))
	seen := make(map[netip.Prefix]struct{}, min(len(items), fakeip.MaxEntries))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || strings.HasPrefix(item, "#") || strings.HasPrefix(item, "//") {
			continue
		}
		candidate := item
		if behavior == "classical" {
			kind, rest, found := strings.Cut(item, ",")
			if !found || !strings.EqualFold(strings.TrimSpace(kind), "IP-CIDR") {
				continue
			}
			candidate, _, _ = strings.Cut(rest, ",")
		}
		prefix, include, err := parseProviderIPv4Prefix(candidate)
		if err != nil {
			return nil, err
		}
		if !include {
			continue
		}
		prefix = prefix.Masked()
		if _, exists := seen[prefix]; exists {
			continue
		}
		if len(result) >= fakeip.MaxEntries {
			return nil, fakeip.ErrTooManyEntries
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix)
	}
	return normalizeNetPrefixes(result), nil
}

func decodeMRSIPv4Prefixes(content []byte) ([]netip.Prefix, error) {
	decoder, err := zstd.NewReader(bytes.NewReader(content), zstd.WithDecoderMaxMemory(64<<20))
	if err != nil {
		return nil, errors.New("invalid MRS compression")
	}
	defer decoder.Close()
	reader := io.LimitReader(decoder, 64<<20)

	var magic [4]byte
	if _, err := io.ReadFull(reader, magic[:]); err != nil || magic != [4]byte{'M', 'R', 'S', 1} {
		return nil, errors.New("invalid MRS header")
	}
	var behavior [1]byte
	if _, err := io.ReadFull(reader, behavior[:]); err != nil || behavior[0] != 1 {
		return nil, errors.New("MRS provider is not ipcidr")
	}
	var ruleCount int64
	if err := binary.Read(reader, binary.BigEndian, &ruleCount); err != nil || ruleCount < 0 {
		return nil, errors.New("invalid MRS rule count")
	}
	var extraLength int64
	if err := binary.Read(reader, binary.BigEndian, &extraLength); err != nil || extraLength < 0 || extraLength > maxRuleProviderBytes {
		return nil, errors.New("invalid MRS extra data")
	}
	if extraLength > 0 {
		if _, err := io.CopyN(io.Discard, reader, extraLength); err != nil {
			return nil, errors.New("truncated MRS extra data")
		}
	}
	var version [1]byte
	if _, err := io.ReadFull(reader, version[:]); err != nil || version[0] != 1 {
		return nil, errors.New("unsupported MRS CIDR version")
	}
	var rangeCount int64
	if err := binary.Read(reader, binary.BigEndian, &rangeCount); err != nil || rangeCount < 1 || rangeCount > fakeip.MaxEntries {
		return nil, errors.New("invalid MRS CIDR range count")
	}

	result := make([]netip.Prefix, 0, min(int(rangeCount), fakeip.MaxEntries))
	for range rangeCount {
		var fromBytes, toBytes [16]byte
		if err := binary.Read(reader, binary.BigEndian, &fromBytes); err != nil {
			return nil, errors.New("truncated MRS CIDR range")
		}
		if err := binary.Read(reader, binary.BigEndian, &toBytes); err != nil {
			return nil, errors.New("truncated MRS CIDR range")
		}
		from := netip.AddrFrom16(fromBytes).Unmap()
		to := netip.AddrFrom16(toBytes).Unmap()
		if from.BitLen() != to.BitLen() || from.Compare(to) > 0 {
			return nil, errors.New("invalid MRS CIDR range")
		}
		if !from.Is4() {
			continue
		}
		prefixes, err := ipv4RangePrefixes(from, to, fakeip.MaxEntries-len(result))
		if err != nil {
			return nil, err
		}
		result = append(result, prefixes...)
	}
	return normalizeNetPrefixes(result), nil
}

func ipv4RangePrefixes(from, to netip.Addr, limit int) ([]netip.Prefix, error) {
	if !from.Is4() || !to.Is4() || from.Compare(to) > 0 || limit <= 0 {
		return nil, errors.New("invalid IPv4 range")
	}
	from4, to4 := from.As4(), to.As4()
	start := uint64(binary.BigEndian.Uint32(from4[:]))
	end := uint64(binary.BigEndian.Uint32(to4[:]))
	result := make([]netip.Prefix, 0)
	for start <= end {
		alignmentBits := 32
		if start != 0 {
			alignmentBits = min(bits.TrailingZeros64(start), 32)
		}
		remainingBits := bits.Len64(end-start+1) - 1
		hostBits := min(alignmentBits, remainingBits)
		encodedAddress := [8]byte{}
		binary.BigEndian.PutUint64(encodedAddress[:], start)
		addressBytes := [4]byte{}
		copy(addressBytes[:], encodedAddress[4:])
		result = append(result, netip.PrefixFrom(netip.AddrFrom4(addressBytes), 32-hostBits))
		if len(result) > limit {
			return nil, fakeip.ErrTooManyEntries
		}
		start += uint64(1) << hostBits
	}
	return result, nil
}

// parseProviderIPv4Prefix distinguishes a valid IPv6 provider entry (which is
// outside the current IPv4-only gateway contract) from malformed provider
// content. A mixed ipcidr provider must keep contributing its IPv4 entries.
func parseProviderIPv4Prefix(value string) (netip.Prefix, bool, error) {
	value = strings.TrimSpace(value)
	if address, err := netip.ParseAddr(value); err == nil {
		if !address.Is4() {
			return netip.Prefix{}, false, nil
		}
		return netip.PrefixFrom(address, 32), true, nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, false, errors.New("invalid IP destination prefix")
	}
	if !prefix.Addr().Is4() {
		return netip.Prefix{}, false, nil
	}
	return prefix.Masked(), true, nil
}

func (manager *FakeIPCaptureManager) providerPath(provider configpkg.MihomoRuleProvider) (string, string, error) {
	root := manager.Layout.Root
	if strings.TrimSpace(root) == "" {
		return "", "", errors.New("state root is unavailable")
	}
	format := strings.ToLower(strings.TrimSpace(provider.Format))
	candidates := make([]string, 0, 3)
	if pathValue := strings.TrimSpace(provider.Path); pathValue != "" {
		if filepath.IsAbs(pathValue) {
			candidates = append(candidates, pathValue)
		} else {
			candidates = append(candidates, filepath.Join(root, pathValue))
		}
	}
	if len(candidates) == 0 && strings.EqualFold(strings.TrimSpace(provider.Type), "http") {
		if sourceURL := strings.TrimSpace(provider.URL); sourceURL != "" {
			candidates = append(candidates, mihomoHashedProviderCachePath(root, "rules", sourceURL))
		}
	}
	if len(candidates) == 0 {
		return "", "", errors.New("rule-provider has no local payload")
	}
	roots := make([]string, 0, 1+len(manager.TrustedProviderCacheRoots))
	roots = append(roots, root)
	for _, trustedRoot := range manager.TrustedProviderCacheRoots {
		trustedRoot = strings.TrimSpace(trustedRoot)
		if trustedRoot != "" && !slices.Contains(roots, trustedRoot) {
			roots = append(roots, trustedRoot)
		}
	}
	var lastErr error
	for _, candidate := range candidates {
		matchedRoot := false
		for _, trustedRoot := range roots {
			pathOnDisk, err := secureProviderPath(trustedRoot, candidate)
			if errors.Is(err, errRuleProviderPathEscape) {
				continue
			}
			matchedRoot = true
			if err != nil {
				lastErr = err
				continue
			}
			if _, err := os.Lstat(pathOnDisk); err != nil {
				lastErr = err
				continue
			}
			if format == "" {
				switch strings.ToLower(filepath.Ext(pathOnDisk)) {
				case ".txt", ".text":
					format = "text"
				case ".mrs":
					format = "mrs"
				default:
					format = "yaml"
				}
			}
			return pathOnDisk, format, nil
		}
		if !matchedRoot {
			lastErr = errRuleProviderPathEscape
		}
	}
	if lastErr == nil {
		lastErr = fs.ErrNotExist
	}
	return "", "", lastErr
}

func secureProviderPath(root, candidate string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", errRuleProviderPathEscape
	}
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			return "", statErr
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return "", errors.New("rule-provider path contains a symbolic link")
		}
	}
	info, err := os.Lstat(candidate)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("rule-provider is not a regular file")
	}
	return candidate, nil
}

func providerTextItems(content []byte) []string {
	contentText := strings.ReplaceAll(string(content), "\r\n", "\n")
	contentText = strings.ReplaceAll(contentText, "\r", "\n")
	return strings.Split(contentText, "\n")
}

func parseCaptureIPv4Prefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if address, err := netip.ParseAddr(value); err == nil {
		if !address.Is4() {
			return netip.Prefix{}, errors.New("destination is not IPv4")
		}
		return netip.PrefixFrom(address, 32), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() {
		return netip.Prefix{}, errors.New("invalid IPv4 destination prefix")
	}
	return prefix.Masked(), nil
}

func (manager *FakeIPCaptureManager) store() *fakeip.Store {
	if manager.Store != nil {
		return manager.Store
	}
	return &fakeip.Store{Directory: manager.Layout.LocalRulesDir}
}

func (manager *FakeIPCaptureManager) setWarnings(warnings []string) {
	if manager == nil {
		return
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.lastWarnings = append([]string(nil), warnings...)
}

func (manager *FakeIPCaptureManager) warnings() []string {
	if manager == nil {
		return nil
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return append([]string(nil), manager.lastWarnings...)
}
