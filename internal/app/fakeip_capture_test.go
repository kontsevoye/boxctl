package app

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	configpkg "github.com/kontsevoye/boxctl/internal/config"
	"github.com/kontsevoye/boxctl/internal/fakeip"
	"github.com/kontsevoye/boxctl/internal/state"
)

func TestFakeIPCapturePolicyModeMatrix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		dns            string
		filterMode     string
		applicable     bool
		selective      bool
		fakeIPRanges   []string
		effectiveCIDRs []string
	}{
		{
			name:           "whitelist uses Mihomo default range",
			dns:            "enable: true\n  enhanced-mode: fake-ip\n  fake-ip-filter-mode: whitelist",
			filterMode:     "whitelist",
			applicable:     true,
			selective:      true,
			fakeIPRanges:   []string{"198.18.0.0/15"},
			effectiveCIDRs: []string{"198.18.0.0/15"},
		},
		{
			name:           "rule normalizes mode and custom range",
			dns:            "enable: true\n  enhanced-mode: FAKE-IP\n  fake-ip-filter-mode: ' Rule '\n  fake-ip-range: 198.19.7.9/15",
			filterMode:     "rule",
			applicable:     true,
			selective:      true,
			fakeIPRanges:   []string{"198.18.0.0/15"},
			effectiveCIDRs: []string{"198.18.0.0/15"},
		},
		{
			name:           "blacklist captures only fake range",
			dns:            "enable: true\n  enhanced-mode: fake-ip\n  fake-ip-filter-mode: blacklist",
			filterMode:     "blacklist",
			selective:      true,
			fakeIPRanges:   []string{"198.18.0.0/15"},
			effectiveCIDRs: []string{"198.18.0.0/15"},
		},
		{
			name:           "missing filter mode captures only fake range",
			dns:            "enable: true\n  enhanced-mode: fake-ip",
			selective:      true,
			fakeIPRanges:   []string{"198.18.0.0/15"},
			effectiveCIDRs: []string{"198.18.0.0/15"},
		},
		{
			name:       "disabled DNS is not a fake-IP policy",
			dns:        "enable: false\n  enhanced-mode: fake-ip\n  fake-ip-filter-mode: whitelist",
			filterMode: "whitelist",
		},
		{
			name:       "missing DNS enable is disabled",
			dns:        "enhanced-mode: fake-ip\n  fake-ip-filter-mode: whitelist",
			filterMode: "whitelist",
		},
		{
			name:       "redir-host is not a fake-IP policy",
			dns:        "enable: true\n  enhanced-mode: redir-host\n  fake-ip-filter-mode: whitelist",
			filterMode: "whitelist",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			manager := &FakeIPCaptureManager{}
			_, policy, err := manager.parsePolicy([]byte("dns:\n  " + test.dns + "\nrules: []\n"))
			if err != nil {
				t.Fatal(err)
			}
			if policy.FilterMode != test.filterMode || policy.Applicable != test.applicable || policy.Selective != test.selective {
				t.Fatalf("policy flags = mode %q applicable=%t selective=%t", policy.FilterMode, policy.Applicable, policy.Selective)
			}
			if got := fakeIPCapturePrefixStrings(policy.FakeIPRanges); !slices.Equal(got, test.fakeIPRanges) {
				t.Fatalf("fake-IP ranges = %v, want %v", got, test.fakeIPRanges)
			}
			if got := fakeIPCapturePrefixStrings(policy.Effective); !slices.Equal(got, test.effectiveCIDRs) {
				t.Fatalf("effective CIDRs = %v, want %v", got, test.effectiveCIDRs)
			}
		})
	}
}

func TestFakeIPCaptureRejectsInvalidFakeRange(t *testing.T) {
	t.Parallel()
	for _, fakeRange := range []string{"2001:db8::/32", "not-an-address"} {
		fakeRange := fakeRange
		t.Run(fakeRange, func(t *testing.T) {
			t.Parallel()
			manager := &FakeIPCaptureManager{}
			source := fmt.Sprintf("dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-filter-mode: whitelist\n  fake-ip-range: %q\n", fakeRange)
			if _, _, err := manager.parsePolicy([]byte(source)); err == nil {
				t.Fatal("invalid fake-IP range was accepted")
			}
		})
	}
}

func TestFakeIPCapturePrepareAutoOffUsesCurrentMarkerDocument(t *testing.T) {
	t.Parallel()
	manager, layout := fakeIPCaptureTestManager(t)
	if err := os.MkdirAll(layout.LocalRulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	before := "# manual before\n203.0.113.7\n"
	generated := fakeip.AutoBeginMarker + "\n# Generated: 2026-01-02T03:04:05Z\n100.64.0.0/10\n" + fakeip.AutoEndMarker + "\n"
	after := "# manual after\n198.51.100.9/32\n"
	original := before + generated + after
	pathOnDisk := filepath.Join(layout.LocalRulesDir, fakeip.FileName)
	if err := os.WriteFile(pathOnDisk, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	current, err := manager.Store.Read()
	if err != nil {
		t.Fatal(err)
	}

	policy, err := manager.Prepare([]byte(`
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
rules:
  - IP-CIDR,192.0.2.0/24,PROXY
`), false)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Document.Revision != current.Revision || policy.Document.Content != original {
		t.Fatal("AUTO-off Prepare changed the current document")
	}
	if policy.Document.ManualContent != before+after {
		t.Fatalf("manual content = %q, want %q", policy.Document.ManualContent, before+after)
	}
	want := []string{"100.64.0.0/10", "198.18.0.0/15", "198.51.100.9/32", "203.0.113.7/32"}
	if got := fakeIPCapturePrefixStrings(policy.Effective); !reflect.DeepEqual(got, want) {
		t.Fatalf("effective = %v, want %v", got, want)
	}
	content, err := os.ReadFile(pathOnDisk)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != original {
		t.Fatal("AUTO-off Prepare wrote the file")
	}
}

func TestFakeIPCapturePrepareGeneratesFromInlineAndLocalProviders(t *testing.T) {
	t.Parallel()
	manager, layout := fakeIPCaptureTestManager(t)
	if err := os.MkdirAll(layout.LocalRulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fakeIPCaptureWriteFile(t, filepath.Join(layout.LocalRulesDir, "ip.yaml"), `payload:
  - 198.51.100.99/24
  - 198.51.100.7
`)
	fakeIPCaptureWriteFile(t, filepath.Join(layout.LocalRulesDir, "classical.yaml"), `payload:
  - DOMAIN-SUFFIX,example.invalid
  - IP-CIDR,100.64.9.8/10
  - IP-CIDR,100.64.0.0/10
  - SRC-IP-CIDR,192.168.0.0/16
  - IP-CIDR6,2001:db8::/32
`)
	fakeIPCaptureWriteFile(t, filepath.Join(layout.LocalRulesDir, "dns.txt"), "# comment\r\n9.9.9.9\r\n9.9.9.9/32\r\n")

	const source = `
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
  fake-ip-filter:
    - rule-set:dns-text
    - +.example.invalid
rules:
  - IP-CIDR,203.0.113.99/24,PROXY,no-resolve
  - IP-CIDR,203.0.113.0/24,SECOND-PROXY
  - IP-CIDR,192.0.2.0/24,DIRECT
  - IP-CIDR,2001:db8::/32,PROXY
  - IP-CIDR6,2001:db8::/32,PROXY
  - SRC-IP-CIDR,10.0.0.0/8,PROXY
  - RULE-SET,ip-yaml,PROXY
  - RULE-SET,classical,PROXY
  - RULE-SET,domain-only,PROXY
  - RULE-SET,missing-direct,DIRECT
rule-providers:
  ip-yaml:
    type: file
    behavior: ipcidr
    format: yaml
    path: ./local-rules/ip.yaml
  classical:
    type: file
    behavior: classical
    format: yaml
    path: ./local-rules/classical.yaml
  dns-text:
    type: file
    behavior: ipcidr
    format: text
    path: ./local-rules/dns.txt
  domain-only:
    type: inline
    behavior: domain
    payload:
      - +.example.invalid
`
	policy, err := manager.Prepare([]byte(source), true)
	if err != nil {
		t.Fatal(err)
	}
	wantGenerated := []string{
		"100.64.0.0/10",
		"198.51.100.0/24",
		"198.51.100.7/32",
		"203.0.113.0/24",
		"9.9.9.9/32",
	}
	if got := fakeIPCapturePrefixStrings(policy.Document.Generated); !reflect.DeepEqual(got, wantGenerated) {
		t.Fatalf("generated = %v, want %v", got, wantGenerated)
	}
	wantEffective := []string{
		"100.64.0.0/10",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"198.51.100.7/32",
		"203.0.113.0/24",
		"9.9.9.9/32",
	}
	if got := fakeIPCapturePrefixStrings(policy.Effective); !reflect.DeepEqual(got, wantEffective) {
		t.Fatalf("effective = %v, want %v", got, wantEffective)
	}
	if len(policy.Warnings) != 0 {
		t.Fatalf("warnings = %v", policy.Warnings)
	}
	if policy.Document.GeneratedScope != fakeip.AutoScopeLocalOnly {
		t.Fatalf("generated scope = %q, want %q", policy.Document.GeneratedScope, fakeip.AutoScopeLocalOnly)
	}
	if !policy.Document.GeneratedAt.Equal(manager.Now()) {
		t.Fatalf("generated at = %v, want %v", policy.Document.GeneratedAt, manager.Now())
	}
	if !strings.Contains(policy.Document.Content, fakeip.AutoBeginMarker) || !strings.Contains(policy.Document.Content, fakeip.AutoEndMarker) {
		t.Fatalf("generated document has no AUTO block: %q", policy.Document.Content)
	}
}

func TestFakeIPCaptureDefaultLocalProviderSymlinkCannotEscapeTrustedRoot(t *testing.T) {
	t.Parallel()
	manager, layout := fakeIPCaptureTestManager(t)
	current := fakeIPCaptureSeedDocument(t, manager, "", []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),
	})

	outside := filepath.Join(t.TempDir(), "outside.yaml")
	fakeIPCaptureWriteFile(t, outside, "payload:\n  - 192.0.2.0/24\n")
	if err := os.MkdirAll(layout.LocalRulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(layout.LocalRulesDir, "linked.yaml")); err != nil {
		t.Fatal(err)
	}

	const source = `
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
rules:
  - RULE-SET,linked,PROXY
rule-providers:
  linked:
    type: file
    behavior: ipcidr
    format: yaml
    path: ./local-rules/linked.yaml
`
	policy, err := manager.Prepare([]byte(source), true)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Document.Revision == current.Revision || policy.Document.Content == current.Content {
		t.Fatal("local-only generation retained an unknown-scope last-known-good block")
	}
	if got := fakeIPCapturePrefixStrings(policy.Document.Generated); len(got) != 0 {
		t.Fatalf("generated = %v, want fail-small empty pool", got)
	}
	if policy.Document.GeneratedScope != fakeip.AutoScopeLocalOnly {
		t.Fatalf("generated scope = %q, want %q", policy.Document.GeneratedScope, fakeip.AutoScopeLocalOnly)
	}
	if !fakeIPCaptureContainsWarning(policy.Warnings, `rule-provider "linked" could not provide IPv4 CIDRs`) ||
		!fakeIPCaptureContainsWarning(policy.Warnings, "replaced the incompatible legacy/unknown-scope") {
		t.Fatalf("warnings = %v", policy.Warnings)
	}
}

func TestFakeIPCaptureOptOutDoesNotRetainBroadPoolWhenLocalProviderIsUnavailable(t *testing.T) {
	t.Parallel()
	manager, layout := fakeIPCaptureTestManager(t)
	remotePath := filepath.Join(layout.RuleProvidersDir, "remote.yaml")
	localPath := filepath.Join(layout.LocalRulesDir, "local.yaml")
	fakeIPCaptureWriteFile(t, remotePath, "payload:\n  - 100.64.0.0/10\n")
	fakeIPCaptureWriteFile(t, localPath, "payload:\n  - 198.51.100.0/24\n")

	const source = `
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
rules:
  - IP-CIDR,203.0.113.0/24,PROXY
  - RULE-SET,remote,PROXY
  - RULE-SET,local,PROXY
rule-providers:
  remote:
    type: file
    behavior: ipcidr
    format: yaml
    path: ./rule-providers/remote.yaml
  local:
    type: file
    behavior: ipcidr
    format: yaml
    path: ./local-rules/local.yaml
`
	broad, err := manager.PrepareWithOptions([]byte(source), true, FakeIPCaptureOptions{IncludeExternalIPProviders: true})
	if err != nil {
		t.Fatal(err)
	}
	if broad.Document.GeneratedScope != fakeip.AutoScopeAllProviders {
		t.Fatalf("broad generated scope = %q", broad.Document.GeneratedScope)
	}
	if got := fakeIPCapturePrefixStrings(broad.Document.Generated); !reflect.DeepEqual(got, []string{"100.64.0.0/10", "198.51.100.0/24", "203.0.113.0/24"}) {
		t.Fatalf("broad generated = %v", got)
	}
	if err := os.Remove(localPath); err != nil {
		t.Fatal(err)
	}

	local, err := manager.Prepare([]byte(source), true)
	if err != nil {
		t.Fatal(err)
	}
	if local.Document.Revision == broad.Document.Revision || local.Document.Content == broad.Document.Content {
		t.Fatal("true-to-false transition retained the all-providers AUTO block")
	}
	if local.Document.GeneratedScope != fakeip.AutoScopeLocalOnly {
		t.Fatalf("local generated scope = %q, want %q", local.Document.GeneratedScope, fakeip.AutoScopeLocalOnly)
	}
	if got := fakeIPCapturePrefixStrings(local.Document.Generated); !reflect.DeepEqual(got, []string{"203.0.113.0/24"}) {
		t.Fatalf("local generated = %v, want only available inline inputs", got)
	}
	if strings.Contains(local.Document.Content, "100.64.0.0/10") || strings.Contains(local.Document.Content, "198.51.100.0/24") {
		t.Fatalf("local AUTO block retained broad or unavailable prefixes: %q", local.Document.Content)
	}
	if !fakeIPCaptureContainsWarning(local.Warnings, `rule-provider "local" could not provide IPv4 CIDRs`) ||
		!fakeIPCaptureContainsWarning(local.Warnings, "replaced the incompatible all-providers") ||
		fakeIPCaptureContainsWarning(local.Warnings, "retained the last-known-good") {
		t.Fatalf("warnings = %v", local.Warnings)
	}
}

func TestFakeIPCaptureExternalIPProviderOptionControlsNonLocalFileProvider(t *testing.T) {
	t.Parallel()
	manager, layout := fakeIPCaptureTestManager(t)
	fakeIPCaptureWriteFile(t, filepath.Join(layout.RuleProvidersDir, "remote.yaml"), `payload:
  - 198.51.100.99/24
`)
	const source = `
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
rules:
  - IP-CIDR,203.0.113.0/24,PROXY
  - RULE-SET,non-local-file,PROXY
rule-providers:
  non-local-file:
    type: file
    behavior: ipcidr
    format: yaml
    path: ./rule-providers/remote.yaml
`
	policy, err := manager.Prepare([]byte(source), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := fakeIPCapturePrefixStrings(policy.Document.Generated); !reflect.DeepEqual(got, []string{"203.0.113.0/24"}) {
		t.Fatalf("default generated = %v", got)
	}
	if len(policy.Warnings) != 0 {
		t.Fatalf("excluded non-local file caused warnings: %v", policy.Warnings)
	}

	policy, err = manager.PrepareWithOptions([]byte(source), true, FakeIPCaptureOptions{IncludeExternalIPProviders: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := fakeIPCapturePrefixStrings(policy.Document.Generated); !reflect.DeepEqual(got, []string{"198.51.100.0/24", "203.0.113.0/24"}) {
		t.Fatalf("external provider generated = %v", got)
	}
}

func TestFakeIPCaptureExternalIPProviderOptionControlsConfiguredHTTPCache(t *testing.T) {
	t.Parallel()
	manager, layout := fakeIPCaptureTestManager(t)
	fakeIPCaptureWriteFile(t, filepath.Join(layout.RuleProvidersDir, "remote.yaml"), `payload:
  - 198.51.100.99/24
`)
	const source = `
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
rules:
  - IP-CIDR,203.0.113.0/24,PROXY
  - RULE-SET,remote-ip,PROXY
rule-providers:
  remote-ip:
    type: http
    behavior: ipcidr
    format: yaml
    url: https://rules.example.invalid/private-token.yaml
    path: ./rule-providers/remote.yaml
`
	policy, err := manager.Prepare([]byte(source), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := fakeIPCapturePrefixStrings(policy.Document.Generated); !reflect.DeepEqual(got, []string{"203.0.113.0/24"}) {
		t.Fatalf("default generated = %v", got)
	}
	if len(policy.Warnings) != 0 {
		t.Fatalf("excluded HTTP cache caused warnings: %v", policy.Warnings)
	}

	policy, err = manager.PrepareWithOptions([]byte(source), true, FakeIPCaptureOptions{IncludeExternalIPProviders: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := fakeIPCapturePrefixStrings(policy.Document.Generated); !reflect.DeepEqual(got, []string{"198.51.100.0/24", "203.0.113.0/24"}) {
		t.Fatalf("external provider generated = %v", got)
	}
	if len(policy.Warnings) != 0 {
		t.Fatalf("opted-in HTTP cache caused warnings: %v", policy.Warnings)
	}
}

func TestFakeIPCaptureExternalIPProviderOptionControlsMihomoDefaultHTTPMRSCachePath(t *testing.T) {
	t.Parallel()
	manager, layout := fakeIPCaptureTestManager(t)
	const sourceURL = "https://rules.example.invalid/pathless.mrs"
	// Mihomo stores a pathless HTTP rule-provider under rules/md5(url).
	pathOnDisk := filepath.Join(layout.Root, "rules", "0857365cfa0b31600c252957043a67ad")
	if err := os.MkdirAll(filepath.Dir(pathOnDisk), 0o700); err != nil {
		t.Fatal(err)
	}
	content := fakeIPCaptureMRS(t, [][2]netip.Addr{{
		netip.MustParseAddr("198.51.100.0"), netip.MustParseAddr("198.51.100.255"),
	}})
	if err := os.WriteFile(pathOnDisk, content, 0o600); err != nil {
		t.Fatal(err)
	}

	const source = `
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
rules:
  - RULE-SET,pathless-mrs,PROXY
rule-providers:
  pathless-mrs:
    type: http
    behavior: ipcidr
    format: mrs
    url: ` + sourceURL + `
`
	policy, err := manager.Prepare([]byte(source), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := fakeIPCapturePrefixStrings(policy.Document.Generated); len(got) != 0 {
		t.Fatalf("default generated = %v, want no remote MRS entries", got)
	}
	if len(policy.Warnings) != 0 {
		t.Fatalf("excluded pathless HTTP MRS cache caused warnings: %v", policy.Warnings)
	}

	policy, err = manager.PrepareWithOptions([]byte(source), true, FakeIPCaptureOptions{IncludeExternalIPProviders: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := fakeIPCapturePrefixStrings(policy.Document.Generated); !reflect.DeepEqual(got, []string{"198.51.100.0/24"}) {
		t.Fatalf("external provider generated = %v", got)
	}
	if len(policy.Warnings) != 0 {
		t.Fatalf("opted-in pathless HTTP MRS cache caused warnings: %v", policy.Warnings)
	}
}

func TestFakeIPCaptureUsesOnlyTrustedExternalCacheRoots(t *testing.T) {
	t.Parallel()
	manager, _ := fakeIPCaptureTestManager(t)
	trustedRoot := t.TempDir()
	manager.TrustedProviderCacheRoots = []string{trustedRoot}
	trustedPath := filepath.Join(trustedRoot, "runtime.yaml")
	fakeIPCaptureWriteFile(t, trustedPath, "payload:\n  - 198.51.100.99/24\n")

	trustedSource := fmt.Sprintf(`
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
rules:
  - RULE-SET,runtime-ip,PROXY
rule-providers:
  runtime-ip:
    type: http
    behavior: ipcidr
    format: yaml
    path: %q
`, trustedPath)
	policy, err := manager.Prepare([]byte(trustedSource), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := fakeIPCapturePrefixStrings(policy.Document.Generated); len(got) != 0 {
		t.Fatalf("default generated from non-local trusted cache = %v", got)
	}

	policy, err = manager.PrepareWithOptions([]byte(trustedSource), true, FakeIPCaptureOptions{IncludeExternalIPProviders: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := fakeIPCapturePrefixStrings(policy.Document.Generated); !reflect.DeepEqual(got, []string{"198.51.100.0/24"}) {
		t.Fatalf("external provider generated from trusted cache = %v", got)
	}

	untrustedPath := filepath.Join(t.TempDir(), "untrusted.yaml")
	fakeIPCaptureWriteFile(t, untrustedPath, "payload:\n  - 203.0.113.0/24\n")
	_, _, err = manager.providerPath(configpkg.MihomoRuleProvider{Path: untrustedPath, Format: "yaml"})
	if !errors.Is(err, errRuleProviderPathEscape) {
		t.Fatalf("untrusted external cache error = %v, want trusted-root rejection", err)
	}
}

func TestFakeIPCaptureDecodesHTTPMRSCaches(t *testing.T) {
	t.Parallel()
	manager, layout := fakeIPCaptureTestManager(t)
	pathOnDisk := filepath.Join(layout.RuleProvidersDir, "remote.mrs")
	if err := os.MkdirAll(filepath.Dir(pathOnDisk), 0o700); err != nil {
		t.Fatal(err)
	}
	content := fakeIPCaptureMRS(t, [][2]netip.Addr{
		{netip.MustParseAddr("198.51.100.0"), netip.MustParseAddr("198.51.100.255")},
		{netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("203.0.113.9")},
		{netip.MustParseAddr("2001:db8::"), netip.MustParseAddr("2001:db8::ffff")},
	})
	if err := os.WriteFile(pathOnDisk, content, 0o600); err != nil {
		t.Fatal(err)
	}

	const source = `
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
rules:
  - RULE-SET,remote-mrs,PROXY
rule-providers:
  remote-mrs:
    type: http
    behavior: ipcidr
    format: mrs
    url: https://rules.example.invalid/private-token.mrs
    path: ./rule-providers/remote.mrs
`
	policy, err := manager.Prepare([]byte(source), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := fakeIPCapturePrefixStrings(policy.Document.Generated); len(got) != 0 {
		t.Fatalf("default generated = %v, want no remote MRS entries", got)
	}

	policy, err = manager.PrepareWithOptions([]byte(source), true, FakeIPCaptureOptions{IncludeExternalIPProviders: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.0/24", "203.0.113.9/32"}
	if got := fakeIPCapturePrefixStrings(policy.Document.Generated); !reflect.DeepEqual(got, want) {
		t.Fatalf("generated = %v, want %v", got, want)
	}
	if len(policy.Warnings) != 0 {
		t.Fatalf("MRS cache caused warnings: %v", policy.Warnings)
	}
}

func TestFakeIPCaptureRejectsEmptyMRSCIDRSet(t *testing.T) {
	t.Parallel()
	if _, err := decodeMRSIPv4Prefixes(fakeIPCaptureMRS(t, nil)); err == nil || !strings.Contains(err.Error(), "range count") {
		t.Fatalf("empty MRS error = %v", err)
	}
}

func TestFakeIPCaptureRuleModeIncludesOnlyFakeIPFilterProviders(t *testing.T) {
	t.Parallel()
	manager, _ := fakeIPCaptureTestManager(t)
	const source = `
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: rule
  fake-ip-filter:
    - RULE-SET,dns-real,real-ip
    - RULE-SET,dns-fake,fake-ip
    - DOMAIN-SUFFIX,example.invalid,real-ip
rules: []
rule-providers:
  dns-fake:
    type: inline
    behavior: ipcidr
    payload:
      - 192.0.2.9/24
`
	policy, err := manager.Prepare([]byte(source), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := fakeIPCapturePrefixStrings(policy.Document.Generated); !reflect.DeepEqual(got, []string{"192.0.2.0/24"}) {
		t.Fatalf("generated = %v", got)
	}
	if len(policy.Warnings) != 0 {
		t.Fatalf("excluded real-ip provider caused warnings: %v", policy.Warnings)
	}
}

func TestFakeIPCaptureProviderIPv6EntriesAreExcluded(t *testing.T) {
	t.Parallel()
	manager, _ := fakeIPCaptureTestManager(t)
	const source = `
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
rules:
  - RULE-SET,mixed-ip,PROXY
rule-providers:
  mixed-ip:
    type: inline
    behavior: ipcidr
    payload:
      - 2001:db8::/32
      - 192.0.2.9/24
`
	policy, err := manager.Prepare([]byte(source), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := fakeIPCapturePrefixStrings(policy.Document.Generated); !reflect.DeepEqual(got, []string{"192.0.2.0/24"}) {
		t.Fatalf("generated = %v", got)
	}
}

func TestFakeIPCaptureUnsafeOrUnavailableProviderRetainsLastKnownGood(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		prepare  func(t *testing.T, layout state.Layout) string
		provider string
	}{
		{
			name: "path escapes root",
			prepare: func(t *testing.T, _ state.Layout) string {
				outside := filepath.Join(t.TempDir(), "outside.txt")
				fakeIPCaptureWriteFile(t, outside, "192.0.2.0/24\n")
				return fmt.Sprintf("  bad:\n    type: file\n    behavior: ipcidr\n    format: text\n    path: %q\n", outside)
			},
			provider: "bad",
		},
		{
			name: "symlink",
			prepare: func(t *testing.T, layout state.Layout) string {
				if err := os.MkdirAll(layout.RuleProvidersDir, 0o700); err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(layout.Root, "real-provider.txt")
				fakeIPCaptureWriteFile(t, outside, "192.0.2.0/24\n")
				link := filepath.Join(layout.RuleProvidersDir, "linked.txt")
				if err := os.Symlink(outside, link); err != nil {
					t.Fatal(err)
				}
				return "  bad:\n    type: file\n    behavior: ipcidr\n    format: text\n    path: ./rule-providers/linked.txt\n"
			},
			provider: "bad",
		},
		{
			name: "MRS",
			prepare: func(t *testing.T, layout state.Layout) string {
				path := filepath.Join(layout.RuleProvidersDir, "provider.mrs")
				fakeIPCaptureWriteFile(t, path, "not-an-mrs-fixture")
				return "  bad:\n    type: file\n    behavior: ipcidr\n    format: mrs\n    path: ./rule-providers/provider.mrs\n"
			},
			provider: "bad",
		},
		{
			name: "missing file",
			prepare: func(_ *testing.T, _ state.Layout) string {
				return "  bad:\n    type: file\n    behavior: ipcidr\n    format: text\n    path: ./rule-providers/missing.txt\n"
			},
			provider: "bad",
		},
		{
			name:     "missing definition",
			prepare:  func(_ *testing.T, _ state.Layout) string { return "" },
			provider: "missing-provider",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			manager, layout := fakeIPCaptureTestManager(t)
			current := fakeIPCaptureSeedDocument(t, manager,
				"# manual\n203.0.113.8\n",
				[]netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
			)
			providers := test.prepare(t, layout)
			source := fmt.Sprintf(`
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
rules:
  - RULE-SET,%s,PROXY
rule-providers:
%s`, test.provider, providers)
			policy, err := manager.PrepareWithOptions([]byte(source), true, FakeIPCaptureOptions{IncludeExternalIPProviders: true})
			if err != nil {
				t.Fatal(err)
			}
			if policy.Document.Revision != current.Revision || policy.Document.Content != current.Content {
				t.Fatal("incomplete generation replaced last-known-good content")
			}
			if got := fakeIPCapturePrefixStrings(policy.Document.Generated); !reflect.DeepEqual(got, []string{"100.64.0.0/10"}) {
				t.Fatalf("generated = %v", got)
			}
			if len(policy.Warnings) < 2 || !fakeIPCaptureContainsWarning(policy.Warnings, "retained the last-known-good") {
				t.Fatalf("warnings = %v", policy.Warnings)
			}
			wantEffective := []string{"100.64.0.0/10", "198.18.0.0/15", "203.0.113.8/32"}
			if got := fakeIPCapturePrefixStrings(policy.Effective); !reflect.DeepEqual(got, wantEffective) {
				t.Fatalf("effective = %v, want %v", got, wantEffective)
			}
		})
	}
}

func TestFakeIPCaptureIncompleteGenerationWithoutLastKnownGoodFailsClosed(t *testing.T) {
	t.Parallel()
	manager, layout := fakeIPCaptureTestManager(t)
	const source = `
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
rules:
  - RULE-SET,missing-provider,PROXY
`
	if _, err := manager.Prepare([]byte(source), true); err == nil || !strings.Contains(err.Error(), "no last-known-good") {
		t.Fatalf("Prepare error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(layout.LocalRulesDir, fakeip.FileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed generation wrote a document: %v", err)
	}
	policy, err := manager.Inspect([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	if !fakeIPCaptureContainsWarning(policy.Warnings, "unavailable") {
		t.Fatalf("Inspect did not retain generation warning: %v", policy.Warnings)
	}
}

func TestFakeIPCaptureIncompleteGenerationStillRejectsStaleRevision(t *testing.T) {
	t.Parallel()
	manager, _ := fakeIPCaptureTestManager(t)
	current := fakeIPCaptureSeedDocument(t, manager, "", []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),
	})
	const source = `
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
rules:
  - RULE-SET,missing-provider,PROXY
`
	if _, err := manager.Regenerate([]byte(source), "stale"); !errors.Is(err, fakeip.ErrConflict) {
		t.Fatalf("Regenerate error = %v, want ErrConflict", err)
	}
	after, err := manager.Store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != current.Revision || after.Content != current.Content {
		t.Fatal("stale incomplete regeneration changed the LKG document")
	}
}

func TestFakeIPCaptureRegenerateHonorsRevision(t *testing.T) {
	t.Parallel()
	manager, _ := fakeIPCaptureTestManager(t)
	const source = `
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
rules:
  - IP-CIDR,192.0.2.0/24,PROXY
`
	if _, err := manager.Regenerate([]byte(source), "stale"); !errors.Is(err, fakeip.ErrConflict) {
		t.Fatalf("Regenerate error = %v, want ErrConflict", err)
	}
	current, err := manager.Store.Read()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := manager.Regenerate([]byte(source), current.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if got := fakeIPCapturePrefixStrings(policy.Document.Generated); !reflect.DeepEqual(got, []string{"192.0.2.0/24"}) {
		t.Fatalf("generated = %v", got)
	}
}

func TestAppendBoundedCapturePrefixesEnforcesGlobalUniqueLimit(t *testing.T) {
	t.Parallel()
	result := []netip.Prefix{}
	seen := map[netip.Prefix]struct{}{}
	first := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.9/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
	}
	if err := appendBoundedCapturePrefixes(&result, seen, first, 2); err != nil {
		t.Fatal(err)
	}
	if want := []string{"192.0.2.0/24", "198.51.100.0/24"}; !reflect.DeepEqual(fakeIPCapturePrefixStrings(result), want) {
		t.Fatalf("result = %v, want %v", result, want)
	}
	if err := appendBoundedCapturePrefixes(&result, seen, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, 2); !errors.Is(err, fakeip.ErrTooManyEntries) {
		t.Fatalf("third unique prefix error = %v, want ErrTooManyEntries", err)
	}
	if len(result) != 2 {
		t.Fatalf("overflow changed result length to %d", len(result))
	}
	if err := appendBoundedCapturePrefixes(&result, seen, nil, 0); !errors.Is(err, fakeip.ErrTooManyEntries) {
		t.Fatalf("zero limit error = %v, want ErrTooManyEntries", err)
	}
}

func TestFakeIPFilterProviderNamesEnforcesBound(t *testing.T) {
	t.Parallel()
	mode := "whitelist"
	dns := configpkg.MihomoRoutingDNS{
		FakeIPFilterMode: &mode,
		FakeIPFilter:     []string{"rule-set:two"},
	}
	if _, err := fakeIPFilterProviderNames(dns, []string{"one"}, 1); !errors.Is(err, fakeip.ErrTooManyEntries) {
		t.Fatalf("provider-name overflow error = %v, want ErrTooManyEntries", err)
	}
}

func fakeIPCaptureTestManager(t *testing.T) (*FakeIPCaptureManager, state.Layout) {
	t.Helper()
	layout, err := state.NewLayout(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := NewFakeIPCaptureManager(layout)
	fixed := time.Date(2026, time.August, 25, 19, 46, 20, 0, time.UTC)
	manager.Now = func() time.Time { return fixed }
	return manager, layout
}

func fakeIPCaptureSeedDocument(t *testing.T, manager *FakeIPCaptureManager, manual string, generated []netip.Prefix) fakeip.Document {
	t.Helper()
	document, err := manager.Store.Read()
	if err != nil {
		t.Fatal(err)
	}
	document, err = manager.Store.SaveManual(manual, document.Revision)
	if err != nil {
		t.Fatal(err)
	}
	document, err = manager.Store.ReplaceGenerated(generated, document.Revision, manager.Now())
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func fakeIPCaptureWriteFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func fakeIPCaptureMRS(t *testing.T, ranges [][2]netip.Addr) []byte {
	t.Helper()
	var document bytes.Buffer
	document.Write([]byte{'M', 'R', 'S', 1})
	document.WriteByte(1) // IPCIDR behavior.
	if err := binary.Write(&document, binary.BigEndian, int64(len(ranges))); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&document, binary.BigEndian, int64(0)); err != nil {
		t.Fatal(err)
	}
	document.WriteByte(1) // IpCidrSet binary version.
	if err := binary.Write(&document, binary.BigEndian, int64(len(ranges))); err != nil {
		t.Fatal(err)
	}
	for _, addressRange := range ranges {
		if err := binary.Write(&document, binary.BigEndian, addressRange[0].As16()); err != nil {
			t.Fatal(err)
		}
		if err := binary.Write(&document, binary.BigEndian, addressRange[1].As16()); err != nil {
			t.Fatal(err)
		}
	}
	var compressed bytes.Buffer
	encoder, err := zstd.NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encoder.Write(document.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func fakeIPCapturePrefixStrings(prefixes []netip.Prefix) []string {
	result := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		result[index] = prefix.String()
	}
	return result
}

func fakeIPCaptureContainsWarning(warnings []string, fragment string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, fragment) {
			return true
		}
	}
	return false
}
