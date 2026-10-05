package ruleconvert

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDomainBoundaries(t *testing.T) {
	for _, tt := range []struct{ input, kind, value string }{{"example.org", "domain", "example.org"}, {"+.example.org", "domain_suffix", "example.org"}, {".example.org", "domain_suffix", ".example.org"}, {"*.*.example.org", "domain_regex", `^[^.]+\.[^.]+\.example\.org$`}} {
		p, err := domainPattern(tt.input)
		if err != nil || p.Kind != tt.kind || p.Value != tt.value {
			t.Fatalf("%s: %+v %v", tt.input, p, err)
		}
	}
	p, _ := domainPattern(".example.org")
	text, err := classical(p)
	if err != nil || text != "AND,((DOMAIN-SUFFIX,example.org),(NOT,((DOMAIN,example.org))))" {
		t.Fatalf("subdomain boundary lost: %s %v", text, err)
	}
}
func TestFormatsAndOptimalBehavior(t *testing.T) {
	for _, tt := range []struct{ name, input, hint, want string }{
		{"yaml-domain", "payload:\n - '+.example.org'\n - '.example.net'\n", "", "domain"},
		{"text-ip", "# comment\n192.0.2.99/24\n2001:db8::1\n", "", "ipcidr"},
		{"classical", "DOMAIN,example.org\nDOMAIN-SUFFIX,example.net\n", "", "domain"},
		{"mixed", "DOMAIN,example.org\nIP-CIDR,192.0.2.0/24\n", "", "classical"},
		{"regex", "DOMAIN-REGEX,^ads\\..+$\n", "", "classical"},
		{"logic", "AND,((DOMAIN,example.org),(DST-PORT,443))\n", "classical", "classical"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := parseText([]byte(tt.input), tt.hint)
			if err != nil {
				t.Fatal(err)
			}
			if got := outputBehavior(rules); got != tt.want {
				t.Fatalf("%s != %s", got, tt.want)
			}
			source, err := encodeSing(rules)
			if err != nil {
				t.Fatal(err)
			}
			back, err := parseSing(source)
			if err != nil {
				t.Fatal(err)
			}
			if outputBehavior(back) != tt.want {
				t.Fatalf("round trip: %s", source)
			}
		})
	}
}
func TestSingLogicalGrouping(t *testing.T) {
	input := []byte(`{"version":3,"rules":[{"domain":["example.org"],"ip_cidr":["192.0.2.0/24"],"port":[443],"invert":true}]}`)
	rules, err := parseSing(input)
	if err != nil {
		t.Fatal(err)
	}
	text, err := mihomoText(rules, "classical")
	if err != nil {
		t.Fatal(err)
	}
	want := "NOT,((AND,((OR,((DOMAIN,example.org),(IP-CIDR,192.0.2.0/24))),(DST-PORT,443))))\n"
	if string(text) != want {
		t.Fatalf("lost grouping:\n%s\nwant:\n%s", text, want)
	}
	back, err := parseText(text, "classical")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(rules)
	b, _ := json.Marshal(back)
	if string(a) != string(b) {
		t.Fatalf("round trip: %s != %s", a, b)
	}
}
func TestUnsupportedNeverDropped(t *testing.T) {
	for _, input := range []string{"GEOIP,CN", "IP-CIDR,192.0.2.0/24,no-resolve", "DOMAIN,example.org\nINVALID,anything", "payload:\n - 23\n", "<html>server error</html>", "MATCH", ""} {
		if _, err := parseText([]byte(input), ""); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
	for _, field := range []string{"wifi_ssid", "query_type", "future_field"} {
		_, err := parseSing([]byte(`{"version":3,"rules":[{"domain":"example.org","` + field + `":"bad"}]}`))
		if err == nil || !strings.Contains(err.Error(), field) {
			t.Fatalf("field %s silently lost: %v", field, err)
		}
	}
}
func TestPortsAndMatch(t *testing.T) {
	rules, err := parseText([]byte("OR,((SRC-PORT,1000-2000),(DST-PORT,443/8443))\n"), "classical")
	if err != nil {
		t.Fatal(err)
	}
	rules = append(rules, predicate{Kind: "true"})
	source, err := encodeSing(rules)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), `"invert":true`) {
		t.Fatalf("MATCH missing complement: %s", source)
	}
}

func TestRegexCaseAndIncompatibleSyntax(t *testing.T) {
	rules, err := parseText([]byte("DOMAIN-REGEX,^EXAMPLE\\.ORG$\n"), "classical")
	if err != nil {
		t.Fatal(err)
	}
	if rules[0].Value != "(?i:^EXAMPLE\\.ORG$)" {
		t.Fatalf("Mihomo case folding lost: %+v", rules)
	}
	rules, err = parseSing([]byte(`{"version":3,"rules":[{"domain_regex":"^EXAMPLE\\.ORG$"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	text, err := mihomoText(rules, "classical")
	if err != nil || !strings.Contains(string(text), "(?-i:") {
		t.Fatalf("sing-box case folding lost: %s %v", text, err)
	}
	for _, pattern := range []string{`\w+`, `(?U)a.*`, `(?imU:a.*)`, `\Qtext\E`, `a(?=b)`, `[[:alpha:]]`, `\123`} {
		if portableRegex(pattern, "domain_regex") == nil {
			t.Errorf("accepted incompatible %s", pattern)
		}
	}
}
func TestNativeJSONCommentsAndYAMLHeader(t *testing.T) {
	source := []byte("// header\n{\"version\":3,\"rules\":[{\"domain_regex\":\"^http://example\",},],}\n")
	if _, err := nativeSingSource(source); err != nil {
		t.Fatal(err)
	}
	if _, err := parseSing(source); err != nil {
		t.Fatal(err)
	}
	if _, err := nativeSingSource(append(source, []byte(` {}`)...)); err == nil {
		t.Fatal("accepted trailing JSON document")
	}
	for _, input := range []string{"# header\npayload:\n - '+.example.org'\n", `{"payload":["+.example.org"]}`} {
		rules, err := parseText([]byte(input), "")
		if err != nil || outputBehavior(rules) != "domain" {
			t.Fatalf("%s: %v", input, err)
		}
	}
}

func TestProcessCaseAndNativeTypes(t *testing.T) {
	rules, err := parseText([]byte(`PROCESS-PATH,/usr/bin/Example`), "classical")
	if err != nil || rules[0].Value != `(?i:\A/usr/bin/Example\z)` {
		t.Fatalf("Mihomo process case folding lost: %+v %v", rules, err)
	}
	for _, field := range []string{"process_name", "process_path", "process_path_regex"} {
		source, _ := json.Marshal(map[string]any{"version": 5, "rules": []any{map[string]any{field: "/usr/bin/Example"}}})
		rules, err = parseSing(source)
		if err != nil {
			t.Fatal(err)
		}
		text, err := mihomoText(rules, "classical")
		if err != nil || !strings.Contains(string(text), "(?-i:") {
			t.Fatalf("sing-box process case sensitivity lost: %q %v", text, err)
		}
	}
	for _, input := range []string{"PROCESS-NAME,Example", "PROCESS-PATH-WILDCARD,*/Example?"} {
		if _, err := parseText([]byte(input), "classical"); err == nil {
			t.Fatalf("accepted incompatible process semantics: %s", input)
		}
	}
	if _, err := parseSing([]byte(`{"version":5,"rules":[{"domain":123}]}`)); err == nil {
		t.Fatal("accepted a number as a domain")
	}
}
