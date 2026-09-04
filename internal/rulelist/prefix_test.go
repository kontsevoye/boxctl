package rulelist

import (
	"strings"
	"testing"
)

func TestAutoPrefixContentUsesFilenameConvention(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{name: "telegram-ip", want: "IP-CIDR,149.154.160.0/20\n"},
		{name: "clients-src-ip", want: "SRC-IP-CIDR,192.168.1.10/32\n"},
		{name: "video-domain.txt", want: "DOMAIN-SUFFIX,example.com\n"},
		{name: "search-keyword", want: "DOMAIN-KEYWORD,example\n"},
		{name: "country-geoip", want: "GEOIP,RU\n"},
		{name: "sites-geosite", want: "GEOSITE,youtube\n"},
		{name: "untyped", want: "example.com\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := test.want
			if comma := strings.IndexByte(input, ','); comma >= 0 {
				input = input[comma+1:]
			}
			if got := AutoPrefixContent(test.name, input); got != test.want {
				t.Fatalf("AutoPrefixContent() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestAutoPrefixContentPreservesCommentsIndentAndExistingRules(t *testing.T) {
	input := "# heading\n  1.1.1.0/24\n// note\n; disabled\nIP-CIDR,8.8.8.8/32\n\n"
	want := "# heading\n  IP-CIDR,1.1.1.0/24\n// note\n; disabled\nIP-CIDR,8.8.8.8/32\n\n"
	if got := AutoPrefixContent("dns-ip", input); got != want {
		t.Fatalf("AutoPrefixContent() = %q, want %q", got, want)
	}
}
