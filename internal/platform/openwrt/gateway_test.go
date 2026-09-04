package openwrt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDefaultReservedCIDRs(t *testing.T) {
	t.Parallel()
	want := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
	}
	if got := DefaultGatewayPlan(ModeTPROXY).BypassCIDRs; !slices.Equal(got, want) {
		t.Fatalf("reserved defaults = %v, want %v", got, want)
	}
}

func TestPlanDigestIncludesRendererRevision(t *testing.T) {
	t.Parallel()
	plan := normalizedPlan(DefaultGatewayPlan(ModeTPROXY))
	legacyJSON, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	legacySum := sha256.Sum256(legacyJSON)
	if planDigest(plan) == hex.EncodeToString(legacySum[:]) {
		t.Fatal("plan digest omitted the renderer revision")
	}
}

func TestRenderGoldenModes(t *testing.T) {
	t.Parallel()
	for _, mode := range []Mode{ModeTPROXY, ModeHYBRID, ModeTUN, ModeMIXED, ModeMIXED2} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			plan := goldenGatewayPlan(mode)
			got, err := Render(plan)
			if err != nil {
				t.Fatal(err)
			}
			goldenPath := filepath.Join("testdata", string(mode)+".nft")
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Fatalf("render differs from %s\n--- got ---\n%s\n--- want ---\n%s", goldenPath, got, want)
			}
		})
	}
}

func goldenGatewayPlan(mode Mode) GatewayPlan {
	plan := DefaultGatewayPlan(mode)
	plan.DNSMode = DNSRedirect
	plan.CaptureCIDRs = []string{"198.18.1.9", "198.18.0.0/16"}
	plan.BypassCIDRs = append(plan.BypassCIDRs, "203.0.113.7")
	plan.SourceBypassCIDRs = []string{"192.0.2.32/28"}
	plan.ProxyServerCIDRs = []string{"9.9.9.9", "1.1.1.1/32"}
	plan.IncludeInterfaces = []string{"lan2", "br-lan"}
	plan.ExcludeInterfaces = []string{"wan"}
	plan.BypassUIDs = []uint32{65534, 99, 99}
	plan.ProxyOnlyTCPPorts = []uint16{8443, 443}
	plan.ProxyOnlyUDPPorts = []uint16{443}
	plan.InterceptOutput = true
	plan.RejectQUIC = true
	return plan
}

func TestRenderModeSemantics(t *testing.T) {
	t.Parallel()
	tests := []struct {
		mode       Mode
		contains   []string
		notContain []string
	}{
		{ModeTPROXY,
			[]string{"tcp tproxy ip to 127.0.0.1:7894", "udp tproxy ip to 127.0.0.1:7894"},
			[]string{"redirect to :7893", "chain tun_forward"}},
		{ModeHYBRID,
			[]string{"udp tproxy ip to 127.0.0.1:7894", "tcp redirect to :7893"},
			[]string{"tcp tproxy ip to", "chain tun_forward"}},
		{ModeTUN,
			[]string{"tcp meta mark set 0x00000003", "udp meta mark set 0x00000003", "chain tun_forward"},
			[]string{"tproxy ip to", "redirect to :7893"}},
		{ModeMIXED,
			[]string{"tcp meta mark set 0x00000001", "udp meta mark set 0x00000003", "tcp tproxy ip to", "chain tun_forward"},
			[]string{"udp tproxy ip to", "redirect to :7893"}},
		{ModeMIXED2,
			[]string{"tcp redirect to :7893", "udp meta mark set 0x00000003", "chain tun_forward"},
			[]string{"tproxy ip to"}},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.mode), func(t *testing.T) {
			t.Parallel()
			got, err := Render(DefaultGatewayPlan(test.mode))
			if err != nil {
				t.Fatal(err)
			}
			for _, fragment := range test.contains {
				if !strings.Contains(got, fragment) {
					t.Errorf("missing %q", fragment)
				}
			}
			for _, fragment := range test.notContain {
				if strings.Contains(got, fragment) {
					t.Errorf("unexpected %q", fragment)
				}
			}
			if !strings.Contains(got, "udp sport 67 udp dport 68 return") || !strings.Contains(got, "udp sport 68 udp dport 67 return") {
				t.Error("DHCP bypass is absent")
			}
		})
	}
}

func TestRenderCompatibilityAndOrdering(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeHYBRID)
	plan.CaptureCIDRs = []string{"198.18.0.0/16"}
	plan.SourceBypassCIDRs = []string{"192.0.2.0/24"}
	plan.ProxyOnlyTCPPorts = []uint16{80, 443}
	plan.ProxyOnlyUDPPorts = []uint16{53, 443}
	plan.InterceptOutput = true
	rendered, err := Render(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"table inet clash {",
		"meta mark 0x00000002 return",
		"meta mark & 0x0000ff00 != 0x00000000 return",
		"fib daddr type local return",
		"tcp dport { 7890, 7891, 7892, 7893, 7894 } return",
		"udp dport { 7890, 7891, 7892, 7893, 7894 } return",
		"tcp sport { 7890, 7891, 7892, 7893, 7894 } return",
		"udp sport { 7890, 7891, 7892, 7893, 7894 } return",
		"ip saddr @source_bypass4 return",
		"tcp dport != { 80, 443 } return",
		"udp dport != { 53, 443 } return",
		"ip daddr @capture4 meta l4proto tcp redirect to :7893",
	} {
		if !strings.Contains(rendered, fragment) {
			t.Errorf("missing compatibility fragment %q", fragment)
		}
	}
	if strings.Index(rendered, "tcp dport { 7890") > strings.Index(rendered, "tcp dport != { 80") {
		t.Error("unconditional bypass must precede proxy-only filtering")
	}
}

func TestRenderOutputInterceptionDoesNotApplyIngressInterfaceFilter(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTPROXY)
	plan.ExcludeInterfaces = []string{"eth1"}
	plan.InterceptOutput = true
	plan.RejectQUIC = true
	rendered, err := Render(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered, `iifname { "eth1" } return`) {
		t.Fatal("prerouting WAN exclusion is absent")
	}
	if strings.Contains(rendered, `oifname { "eth1" } return`) {
		t.Fatal("ingress WAN exclusion incorrectly disables router-output interception")
	}
	if strings.Count(rendered, "fib daddr type local return") != 1 {
		t.Fatal("local-destination FIB bypass must apply only to prerouting")
	}
	if strings.Count(rendered, "udp dport 443 reject") != 1 {
		t.Fatal("QUIC rejection must apply exactly once in the prerouting mark chain")
	}
	if strings.Index(rendered, "udp dport 443 reject") > strings.Index(rendered, "ip daddr @bypass4 return") {
		t.Fatal("QUIC rejection must precede destination bypass rules")
	}
}

func TestSelectiveCaptureCIDRsOverrideReservedButNotProxyEndpointBypass(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTPROXY)
	plan.CaptureCIDRs = []string{"10.0.0.0/8", "203.0.113.7/32"}
	plan.ProxyServerCIDRs = []string{"203.0.113.7/32"}
	rendered, err := Render(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"ip daddr @capture4 meta l4proto tcp meta mark set",
		"ip daddr @capture4 meta l4proto udp meta mark set",
	} {
		if !strings.Contains(rendered, fragment) {
			t.Errorf("selective capture is missing %q", fragment)
		}
	}
	if !strings.Contains(rendered, "ip daddr @proxy_servers4 return") {
		t.Fatal("selective capture does not unconditionally bypass its proxy endpoint")
	}
	if strings.Contains(rendered, "ip daddr @bypass4 return") {
		t.Fatal("destination explicitly selected for capture is still cancelled by the broad reserved set")
	}
	if strings.Index(rendered, "ip daddr @proxy_servers4 return") > strings.Index(rendered, "ip daddr @capture4 meta l4proto tcp meta mark set") {
		t.Fatal("proxy endpoint bypass must run before selective capture marking")
	}
}

func TestExplicitEmptyBypassListsDisableDefaults(t *testing.T) {
	t.Parallel()
	plan := GatewayPlan{
		Mode:                  ModeTPROXY,
		BypassCIDRs:           []string{},
		BypassCIDRsConfigured: true,
		BypassTCPPorts:        []uint16{},
		BypassUDPPorts:        []uint16{},
	}
	rendered, err := Render(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"set bypass4", "tcp dport { 7890", "udp dport { 7890"} {
		if strings.Contains(rendered, fragment) {
			t.Errorf("explicit empty list unexpectedly restored default %q", fragment)
		}
	}
}

func TestValidateRejectsUnsafePlans(t *testing.T) {
	t.Parallel()
	tests := []GatewayPlan{
		{Mode: "unknown"},
		{Mode: ModeTPROXY, Table: "clash; flush ruleset"},
		{Mode: ModeTPROXY, TProxyMark: 3, TUNMark: 3},
		{Mode: ModeTPROXY, LoopMark: 1},
		{Mode: ModeTPROXY, CaptureCIDRs: []string{"::1"}},
		{Mode: ModeTPROXY, CaptureCIDRsConfigured: true, CaptureCIDRs: []string{}},
		{Mode: ModeTPROXY, IncludeInterfaces: []string{"br-lan"}, ExcludeInterfaces: []string{"br-lan"}},
		{Mode: ModeTPROXY, ProxyOnlyTCPPorts: []uint16{0}},
	}
	for _, plan := range tests {
		if err := Validate(plan); err == nil {
			t.Errorf("Validate(%+v) succeeded", plan)
		}
	}
}

type runnerStep struct {
	result Result
	err    error
}

type recordingRunner struct {
	steps    []runnerStep
	commands []Command
}

func (runner *recordingRunner) Run(_ context.Context, command Command) (Result, error) {
	runner.commands = append(runner.commands, command)
	if len(runner.steps) == 0 {
		return Result{}, errors.New("unexpected command")
	}
	step := runner.steps[0]
	runner.steps = runner.steps[1:]
	return step.result, step.err
}

func tableJSON(plan GatewayPlan, comment string) []byte {
	value := map[string]any{"nftables": []any{map[string]any{"table": map[string]any{
		"family": "inet", "name": normalizedPlan(plan).Table, "comment": comment,
	}}}}
	data, _ := json.Marshal(value)
	return data
}

func firewallJSON(plan GatewayPlan) []byte {
	comments := expectedFirewallComments(plan)
	objects := make([]any, 0, len(comments))
	for index, comment := range comments {
		chain := "forward"
		if index == 0 {
			chain = "input"
		}
		objects = append(objects, map[string]any{"rule": map[string]any{
			"family": "inet", "table": "fw4", "chain": chain, "handle": index + 10, "comment": comment,
		}})
	}
	data, _ := json.Marshal(map[string]any{"nftables": objects})
	return data
}

func TestApplyRefusesForeignTable(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTPROXY)
	runner := &recordingRunner{steps: []runnerStep{{result: Result{Stdout: tableJSON(plan, "managed-by=someone-else plan-sha256=bad")}}}}
	err := Apply(context.Background(), runner, plan)
	if err == nil || !strings.Contains(err.Error(), "foreign") {
		t.Fatalf("Apply error = %v", err)
	}
	if len(runner.commands) != 1 || runner.commands[0].Name != "nft" {
		t.Fatalf("commands = %+v", runner.commands)
	}
}

func TestApplyReplacesOwnedTableWithLegacyPlanOnlyDigest(t *testing.T) {
	t.Parallel()
	plan := normalizedPlan(DefaultGatewayPlan(ModeTPROXY))
	legacyJSON, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	legacySum := sha256.Sum256(legacyJSON)
	legacyComment := ownerPrefix(plan) + "plan-sha256=" + hex.EncodeToString(legacySum[:])
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: tableJSON(plan, legacyComment)}},
		{result: Result{Stdout: []byte(`{"nftables":[]}`)}},
		{result: Result{}},
		{result: Result{Stdout: []byte(ownedTPROXYRule)}},
		{result: Result{Stdout: []byte("local default dev lo proto 196\n")}},
		{result: Result{}},
		{result: Result{Stdout: []byte("local default dev lo table 100 proto 196\n")}},
		{result: Result{}},
	}}
	if err := Apply(context.Background(), runner, plan); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 8 {
		t.Fatalf("commands = %+v", runner.commands)
	}
	for _, index := range []int{2, 7} {
		transaction := string(runner.commands[index].Stdin)
		if !strings.Contains(transaction, "delete table inet "+plan.Table+"\n") {
			t.Errorf("transaction %d does not replace the legacy table:\n%s", index, transaction)
		}
		if !strings.Contains(transaction, ownershipComment(plan)) {
			t.Errorf("transaction %d lacks the renderer-revision digest:\n%s", index, transaction)
		}
	}
}

func TestCheckOwnedPlanAndRoutes(t *testing.T) {
	t.Parallel()
	plan := normalizedPlan(DefaultGatewayPlan(ModeMIXED))
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: tableJSON(plan, ownershipComment(plan))}},
		{result: Result{Stdout: []byte(ownedTPROXYRule + ownedTUNRule)}},
		{result: Result{Stdout: []byte("local default dev lo proto 196\n")}},
		{result: Result{Stdout: []byte("default dev clash-tun proto 196\n")}},
		{result: Result{Stdout: []byte("local default dev lo table 100 proto 196\ndefault dev clash-tun table 101 proto 196\n")}},
		{result: Result{Stdout: firewallJSON(plan)}},
	}}
	result, err := Check(context.Background(), runner, plan)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Exists || !result.Owned || !result.PlanMatches || !result.PolicyMatches || !result.FirewallMatches {
		t.Fatalf("unexpected check result: %+v", result)
	}
}

func TestCleanupMissingNftStateRemovesProtocolOwnedPolicyTuples(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTPROXY)
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{ExitCode: 1, Stderr: []byte("No such file or directory")}},
		{result: Result{ExitCode: 1, Stderr: []byte("No such file or directory")}},
		{result: Result{Stdout: []byte(ownedTPROXYRule)}},
		{result: Result{Stdout: []byte("local default dev lo proto 196\n")}},
		{result: Result{ExitCode: 2, Stderr: []byte("FIB table does not exist")}},
		{result: Result{}},
		{result: Result{}},
	}}
	if err := Cleanup(context.Background(), runner, plan); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 7 {
		t.Fatalf("unexpected commands: %+v", runner.commands)
	}
	if got := strings.Join(runner.commands[5].Args, " "); got != "-4 rule del pref 1000 protocol 196 fwmark 0x1 lookup 100" {
		t.Fatalf("policy rule cleanup = %q", got)
	}
	if got := strings.Join(runner.commands[6].Args, " "); got != "-4 route flush table 100 proto 196" {
		t.Fatalf("policy route cleanup = %q", got)
	}
}

func TestCleanupGatewayInspectionFailureStillRemovesProtocolOwnedPolicy(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTPROXY)
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{ExitCode: 2, Stderr: []byte("operation not supported")}},
		{result: Result{ExitCode: 1, Stderr: []byte("No such file or directory")}},
		{result: Result{Stdout: []byte(ownedTPROXYRule)}},
		{result: Result{Stdout: []byte("local default dev lo proto 196\n")}},
		{result: Result{Stdout: []byte("default dev clash-tun proto 196\n")}},
		{},
		{},
		{},
	}}
	err := Cleanup(context.Background(), runner, plan)
	if err == nil || !strings.Contains(err.Error(), "inspect nft table") {
		t.Fatalf("Cleanup() error = %v, want nft inspection failure", err)
	}
	if len(runner.commands) != 8 {
		t.Fatalf("cleanup stopped before independently-owned policy state: %+v", runner.commands)
	}
	if got := strings.Join(runner.commands[5].Args, " "); got != "-4 rule del pref 1000 protocol 196 fwmark 0x1 lookup 100" {
		t.Fatalf("policy rule cleanup = %q", got)
	}
	for index, table := range []string{"100", "101"} {
		if got := strings.Join(runner.commands[6+index].Args, " "); got != "-4 route flush table "+table+" proto 196" {
			t.Fatalf("policy table %s cleanup = %q", table, got)
		}
	}
}

func TestFirewallReconcileIsOwnershipScoped(t *testing.T) {
	t.Parallel()
	plan := normalizedPlan(DefaultGatewayPlan(ModeTUN))
	current := firewallState{Exists: true, OwnedRules: []firewallRule{
		{Chain: "forward", Handle: 41, Comment: "managed-by=boxctl/v1 stale"},
		{Chain: "input", Handle: 12, Comment: "managed-by=boxctl/v1 stale"},
	}}
	var transaction strings.Builder
	if err := renderFirewallReconcile(&transaction, plan, current); err != nil {
		t.Fatal(err)
	}
	got := transaction.String()
	for _, fragment := range []string{
		"delete rule inet fw4 forward handle 41",
		"delete rule inet fw4 input handle 12",
		"insert rule inet fw4 input iifname \"clash-tun\" counter accept comment \"managed-by=boxctl/v1",
		"role=tun-forward-input",
		"role=tun-forward-output",
	} {
		if !strings.Contains(got, fragment) {
			t.Errorf("transaction lacks %q:\n%s", fragment, got)
		}
	}
	if strings.Contains(got, "flush") || strings.Contains(got, "delete table inet fw4") {
		t.Fatalf("reconcile exceeds owned rule scope:\n%s", got)
	}
}

func TestTUNFirewallReconcileRequiresFW4(t *testing.T) {
	t.Parallel()
	plan := normalizedPlan(DefaultGatewayPlan(ModeTUN))
	var transaction strings.Builder
	if err := renderFirewallReconcile(&transaction, plan, firewallState{}); err == nil {
		t.Fatal("TUN reconcile without fw4 succeeded")
	}
}
