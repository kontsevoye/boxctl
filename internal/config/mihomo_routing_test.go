package config

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestParseMihomoRoutingExtractsResolvedNonSecretModel(t *testing.T) {
	t.Parallel()
	const source = `
secret: never-expose-this-controller-secret
dns-defaults: &dns-defaults
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter-mode: rule
dns:
  <<: *dns-defaults
  fake-ip-filter:
    - "+.lan"
    - "rule-set:private-domain"
provider-defaults: &provider-defaults
  type: http
  behavior: ipcidr
  format: mrs
  url: https://rules.example.invalid/provider.mrs
  path: ./rule-providers/provider.mrs
rules:
  - IP-CIDR,203.0.113.0/24,PROXY,no-resolve
  - RULE-SET,remote-ip,PROXY
rule-providers:
  remote-ip:
    <<: *provider-defaults
  inline-classical:
    type: inline
    behavior: classical
    format: yaml
    payload:
      - DOMAIN-SUFFIX,example.com
      - IP-CIDR,192.0.2.0/24
unrelated: {preserved-by-native-config: true}
`

	routing, err := ParseMihomoRouting([]byte(source))
	if err != nil {
		t.Fatalf("ParseMihomoRouting() error = %v", err)
	}
	assertBoolPointer(t, "dns.enable", routing.DNS.Enabled, true)
	assertStringPointer(t, "dns.enhanced-mode", routing.DNS.EnhancedMode, "fake-ip")
	assertStringPointer(t, "dns.fake-ip-range", routing.DNS.FakeIPRange, "198.18.0.1/16")
	assertStringPointer(t, "dns.fake-ip-filter-mode", routing.DNS.FakeIPFilterMode, "rule")
	if want := []string{"+.lan", "rule-set:private-domain"}; !reflect.DeepEqual(routing.DNS.FakeIPFilter, want) {
		t.Fatalf("dns.fake-ip-filter = %#v, want %#v", routing.DNS.FakeIPFilter, want)
	}
	if want := []string{"IP-CIDR,203.0.113.0/24,PROXY,no-resolve", "RULE-SET,remote-ip,PROXY"}; !reflect.DeepEqual(routing.Rules, want) {
		t.Fatalf("rules = %#v, want %#v", routing.Rules, want)
	}

	remote := routing.RuleProviders["remote-ip"]
	if remote.Type != "http" || remote.Behavior != "ipcidr" || remote.Format != "mrs" ||
		remote.URL != "https://rules.example.invalid/provider.mrs" || remote.Path != "./rule-providers/provider.mrs" {
		t.Fatalf("resolved remote provider = %#v", remote)
	}
	inline := routing.RuleProviders["inline-classical"]
	if want := []string{"DOMAIN-SUFFIX,example.com", "IP-CIDR,192.0.2.0/24"}; !reflect.DeepEqual(inline.Payload, want) {
		t.Fatalf("inline payload = %#v, want %#v", inline.Payload, want)
	}
}

func TestParseMihomoRoutingAbsentCollectionsAreUsable(t *testing.T) {
	t.Parallel()
	routing, err := ParseMihomoRouting([]byte("mode: rule\n"))
	if err != nil {
		t.Fatalf("ParseMihomoRouting() error = %v", err)
	}
	if routing.Rules == nil || routing.RuleProviders == nil || routing.DNS.FakeIPFilter == nil {
		t.Fatalf("nil collections in routing model: %#v", routing)
	}
	if routing.DNS.Enabled != nil || routing.DNS.EnhancedMode != nil || routing.DNS.FakeIPRange != nil || routing.DNS.FakeIPFilterMode != nil {
		t.Fatalf("absent DNS scalars reported as present: %#v", routing.DNS)
	}
}

func TestParseMihomoRoutingRejectsAmbiguousDocumentsWithoutLeakingValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		source string
	}{
		{name: "empty", source: ""},
		{name: "sequence root", source: "- mode\n- rule\n"},
		{name: "multiple documents", source: "mode: rule\n---\nmode: direct\n"},
		{name: "duplicate routing key", source: "rules: []\nrules: []\n"},
		{name: "wrong DNS scalar type", source: "dns:\n  enable: [never-expose-this-controller-secret]\n"},
		{name: "wrong rule type", source: "rules:\n  - {secret: never-expose-this-controller-secret}\n"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseMihomoRouting([]byte(test.source))
			if !errors.Is(err, ErrInvalidMihomoRouting) {
				t.Fatalf("ParseMihomoRouting() error = %v, want ErrInvalidMihomoRouting", err)
			}
			if strings.Contains(err.Error(), "never-expose-this-controller-secret") {
				t.Fatalf("routing error leaked a document value: %v", err)
			}
		})
	}
}

func TestParseMihomoRuleKeepsNestedAndQuotedCommas(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
		want MihomoRule
	}{
		{
			name: "CIDR with option",
			raw:  " IP-CIDR , 203.0.113.0/24 , Proxy Group , no-resolve ",
			want: MihomoRule{Type: "IP-CIDR", Arguments: []string{"203.0.113.0/24"}, Action: "Proxy Group", Options: []string{"no-resolve"}},
		},
		{
			name: "logical rule",
			raw:  "AND,((DOMAIN-SUFFIX,example.com),(NETWORK,TCP)),PROXY",
			want: MihomoRule{Type: "AND", Arguments: []string{"((DOMAIN-SUFFIX,example.com),(NETWORK,TCP))"}, Action: "PROXY", Options: []string{}},
		},
		{
			name: "quoted provider",
			raw:  `RULE-SET,"provider,one",PROXY`,
			want: MihomoRule{Type: "RULE-SET", Arguments: []string{"provider,one"}, Action: "PROXY", Options: []string{}},
		},
		{
			name: "apostrophe in action",
			raw:  `RULE-SET,'provider,one',John's Proxy`,
			want: MihomoRule{Type: "RULE-SET", Arguments: []string{"provider,one"}, Action: "John's Proxy", Options: []string{}},
		},
		{
			name: "regex delimiters",
			raw:  `DOMAIN-REGEX,^foo[0-9,]+(bar,baz){1,3}$,PROXY`,
			want: MihomoRule{Type: "DOMAIN-REGEX", Arguments: []string{`^foo[0-9,]+(bar,baz){1,3}$`}, Action: "PROXY", Options: []string{}},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseMihomoRule(test.raw)
			if err != nil {
				t.Fatalf("ParseMihomoRule() error = %v", err)
			}
			got.Raw = ""
			if got.Options == nil {
				got.Options = []string{}
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("ParseMihomoRule() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestParseMihomoRuleRejectsMalformedCSV(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"",
		"MATCH",
		"RULE-SET,,PROXY",
		`RULE-SET,"unterminated,PROXY`,
		"AND,((DOMAIN,example.com),PROXY",
		"DOMAIN-REGEX,[a,b),PROXY",
	} {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseMihomoRule(raw); !errors.Is(err, ErrInvalidMihomoRule) {
				t.Fatalf("ParseMihomoRule(%q) error = %v, want ErrInvalidMihomoRule", raw, err)
			}
		})
	}
}

func TestCollectMihomoAutoInputs(t *testing.T) {
	t.Parallel()
	rules := []string{
		"IP-CIDR,203.0.113.7/24,PROXY",
		"IP-CIDR,203.0.113.0/24,SECOND-PROXY,no-resolve",
		"IP-CIDR,192.0.2.9,DIRECT",
		"IP-CIDR,198.51.100.7,REJECT",
		"IP-CIDR,2001:db8::/32,PROXY",
		"IP-CIDR6,2001:db8::/32,PROXY",
		"SRC-IP-CIDR,10.0.0.0/8,PROXY",
		"RULE-SET,remote-ip,PROXY",
		"RULE-SET,remote-ip,SECOND-PROXY",
		"RULE-SET,direct-ip,direct",
		`RULE-SET,"provider,with-comma",REJECT`,
		"MATCH,DIRECT",
	}

	inputs, err := CollectMihomoAutoInputs(rules, 100)
	if err != nil {
		t.Fatalf("CollectMihomoAutoInputs() error = %v", err)
	}
	wantPrefixes := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("198.51.100.7/32"),
	}
	if !reflect.DeepEqual(inputs.InlineIPv4, wantPrefixes) {
		t.Fatalf("inline IPv4 = %v, want %v", inputs.InlineIPv4, wantPrefixes)
	}
	if want := []string{"remote-ip", "provider,with-comma"}; !reflect.DeepEqual(inputs.ProviderNames, want) {
		t.Fatalf("provider names = %#v, want %#v", inputs.ProviderNames, want)
	}
}

func TestCollectMihomoAutoInputsRejectsMalformedRelevantRules(t *testing.T) {
	t.Parallel()
	for _, rules := range [][]string{
		{"IP-CIDR,not-a-prefix,PROXY"},
		{"IP-CIDR,192.0.2.0/24,extra,PROXY"},
		{"RULE-SET,one,two,PROXY"},
	} {
		if _, err := CollectMihomoAutoInputs(rules, 100); !errors.Is(err, ErrInvalidMihomoRule) {
			t.Fatalf("CollectMihomoAutoInputs(%q) error = %v, want ErrInvalidMihomoRule", rules, err)
		}
	}
}

func TestCollectMihomoAutoInputsEnforcesBoundsWhileCollecting(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		rules []string
	}{
		{
			name: "inline destinations",
			rules: []string{
				"IP-CIDR,192.0.2.0/24,PROXY",
				"IP-CIDR,198.51.100.0/24,PROXY",
			},
		},
		{
			name: "provider references",
			rules: []string{
				"RULE-SET,one,PROXY",
				"RULE-SET,two,PROXY",
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := CollectMihomoAutoInputs(test.rules, 1); !errors.Is(err, ErrMihomoAutoInputsTooLarge) {
				t.Fatalf("CollectMihomoAutoInputs() error = %v, want ErrMihomoAutoInputsTooLarge", err)
			}
		})
	}
	if _, err := CollectMihomoAutoInputs([]string{"IP-CIDR,192.0.2.0/24,PROXY"}, 0); !errors.Is(err, ErrMihomoAutoInputsTooLarge) {
		t.Fatalf("zero limit error = %v, want ErrMihomoAutoInputsTooLarge", err)
	}
}

func assertBoolPointer(t *testing.T, name string, got *bool, want bool) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("%s = %v, want %t", name, got, want)
	}
}
