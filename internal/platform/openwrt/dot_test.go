package openwrt

import (
	"strings"
	"testing"
)

func TestRenderDoTPolicyBeforeCapture(t *testing.T) {
	t.Parallel()
	for _, mode := range []Mode{ModeTPROXY, ModeHYBRID, ModeTUN, ModeMIXED, ModeMIXED2} {
		for _, dns := range []DNSMode{DNSUpstream, DNSRedirect} {
			t.Run(string(mode)+"/"+string(dns), func(t *testing.T) {
				plan := goldenGatewayPlan(mode)
				plan.BlockDoT = true
				plan.DNSMode = dns
				// Even explicit port bypass/filter and narrow destination capture
				// must not let DoT evade DNS policy.
				plan.BypassTCPPorts = []uint16{853}
				plan.BypassUDPPorts = []uint16{853}
				plan.ProxyOnlyTCPPorts = []uint16{443}
				plan.ProxyOnlyUDPPorts = []uint16{443}
				rendered, err := Render(plan)
				if err != nil {
					t.Fatal(err)
				}
				start := strings.Index(rendered, "\tchain dot_block {\n")
				if start < 0 {
					t.Fatal("missing DoT chain")
				}
				chain := strings.SplitN(rendered[start:], "\t}\n", 2)[0]
				for _, fragment := range []string{
					"type filter hook prerouting priority -160; policy accept;",
					`iifname != { "br-lan", "lan2" } return`,
					`iifname { "wan" } return`,
					"ip saddr @source_bypass4 return",
					"fib daddr type local return",
					"meta mark 0x00000002 return",
					"meta nfproto ipv4 tcp dport 853 drop",
					"meta nfproto ipv4 udp dport 853 drop",
				} {
					if !strings.Contains(chain, fragment) {
						t.Fatalf("DoT chain missing %q:\n%s", fragment, chain)
					}
				}
				firstDrop := strings.Index(chain, "tcp dport 853 drop")
				if strings.LastIndex(chain, "return") > firstDrop {
					t.Fatal("DoT bypass after blocking rule")
				}
				for _, unexpected := range []string{"@capture4", "@bypass4", "@proxy_servers4", "dport {", "dport !=", "hook output", "redirect to", "tproxy"} {
					if strings.Contains(chain, unexpected) {
						t.Fatalf("DoT chain unexpectedly depends on %q", unexpected)
					}
				}
				if strings.Count(rendered, "dport 853 drop") != 2 {
					t.Fatal("DoT blocking leaked into another chain")
				}
				if start > strings.Index(rendered, "chain mark_traffic") {
					t.Fatal("DoT filter rendered after capture")
				}
			})
		}
	}
}

func TestDoTDisabledAndDNSRequirement(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTPROXY)
	for _, dns := range []DNSMode{DNSDisabled, DNSUpstream, DNSRedirect} {
		plan.DNSMode = dns
		rendered, err := Render(plan)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(rendered, "dot_block") || strings.Contains(rendered, "853 drop") {
			t.Fatal("disabled DoT blocks traffic")
		}
	}
	plan.DNSMode = DNSDisabled
	plan.BlockDoT = true
	if _, err := Render(plan); err == nil {
		t.Fatal("DoT blocking accepted disabled DNS")
	}
	plan.DNSMode = DNSUpstream
	withDoT := planDigest(normalizedPlan(plan))
	plan.BlockDoT = false
	if withDoT == planDigest(normalizedPlan(plan)) {
		t.Fatal("DoT setting omitted from reconciliation digest")
	}
}
