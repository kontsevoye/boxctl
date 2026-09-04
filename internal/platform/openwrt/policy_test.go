package openwrt

import (
	"context"
	"strings"
	"testing"
)

const (
	ownedTPROXYRule = "1000: from all fwmark 0x1 lookup 100 proto 196\n"
	ownedTUNRule    = "1001: from all fwmark 0x3 lookup 101 proto 196\n"
)

func TestManagedRouteLineRequiresOwnershipProtocolAndExactShape(t *testing.T) {
	t.Parallel()
	tests := []struct {
		line   string
		route  []string
		wanted bool
	}{
		{"local default dev lo proto 196", []string{"local", "default", "dev", "lo"}, true},
		{"local default dev lo scope host proto 196", []string{"local", "default", "dev", "lo"}, true},
		{"local default dev lo proto 196 scope 254", []string{"local", "default", "dev", "lo"}, true},
		{"2 default dev lo proto 196 scope 254", []string{"local", "default", "dev", "lo"}, true},
		{"default dev clash-tun proto 196 scope link", []string{"default", "dev", "clash-tun"}, true},
		{"default dev clash-tun proto 196 scope 253", []string{"default", "dev", "clash-tun"}, true},
		{"1 default dev clash-tun proto 196 scope 253", []string{"default", "dev", "clash-tun"}, true},
		{"default dev clash-tun scope link proto 196 linkdown", []string{"default", "dev", "clash-tun"}, true},
		{"local default dev lo proto 196 scope 253", []string{"local", "default", "dev", "lo"}, true},
		{"default dev clash-tun proto 196 scope 254", []string{"default", "dev", "clash-tun"}, true},
		{"local default dev lo proto 196 scope 252", []string{"local", "default", "dev", "lo"}, false},
		{"1 default dev lo proto 196 scope 254", []string{"local", "default", "dev", "lo"}, false},
		{"2 default dev clash-tun proto 196 scope 253", []string{"default", "dev", "clash-tun"}, false},
		{"3 default dev clash-tun proto 196 scope 253", []string{"default", "dev", "clash-tun"}, false},
		{"default dev clash-tun scope link proto static", []string{"default", "dev", "clash-tun"}, false},
		{"default dev clash-tun", []string{"default", "dev", "clash-tun"}, false},
		{"default dev clash-tun proto 196 metric 100", []string{"default", "dev", "clash-tun"}, false},
		{"default via 192.0.2.1 dev clash-tun proto 196", []string{"default", "dev", "clash-tun"}, false},
		{"local default dev eth0 scope host proto 196", []string{"local", "default", "dev", "lo"}, false},
	}
	for _, test := range tests {
		if got := isManagedRouteLine(test.line, test.route); got != test.wanted {
			t.Errorf("isManagedRouteLine(%q) = %v, want %v", test.line, got, test.wanted)
		}
	}
}

func TestParsePolicyRuleDistinguishesOwnedExactRule(t *testing.T) {
	t.Parallel()
	tests := []struct {
		line  string
		owned bool
		exact bool
	}{
		{"1000: from all fwmark 0x1 lookup 100 proto 196", true, true},
		{"1000: from all fwmark 0x1/0xffffffff lookup 100 protocol 196", true, true},
		{"1000: from all fwmark 0x1/0xff lookup 100 proto 196", true, false},
		{"1000: from all fwmark 0x1 lookup 100 proto 196 iif br-lan", true, false},
		{"1000: from all to 192.0.2.1 fwmark 0x1 lookup 100 proto 196", true, false},
		{"1000: from all fwmark 0x1 lookup 100 proto 197", false, false},
		{"1000: from all fwmark 0x1 lookup 100", false, false},
	}
	for _, test := range tests {
		rule, ok := parsePolicyRule(test.line)
		if !ok {
			t.Fatalf("parsePolicyRule(%q) failed", test.line)
		}
		if rule.Owned != test.owned || rule.Exact != test.exact || rule.Priority != 1000 || rule.Mark != 1 || rule.Table != 100 {
			t.Errorf("parsePolicyRule(%q) = %+v", test.line, rule)
		}
	}
}

func TestReconcilePolicyRoutesRefusesForeignPriorityBeforeMutation(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTPROXY)
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: []byte("1000: from all fwmark 0x1 lookup 100\n")}},
		{result: Result{ExitCode: 2, Stderr: []byte("FIB table does not exist")}},
		{},
		{},
	}}
	err := reconcilePolicyRoutes(context.Background(), runner, plan)
	if err == nil || !strings.Contains(err.Error(), "foreign rule at reserved priority 1000") {
		t.Fatalf("reconcile error = %v", err)
	}
	assertOnlyPolicyInspectionCommands(t, runner.commands, 4)
}

func TestReconcilePolicyRoutesRefusesForeignRuleUsingTable(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTPROXY)
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: []byte("900: from all fwmark 0x9 lookup 100 proto 99\n")}},
		{result: Result{}},
		{},
		{},
	}}
	err := reconcilePolicyRoutes(context.Background(), runner, plan)
	if err == nil || !strings.Contains(err.Error(), "foreign rule using reserved policy table 100") {
		t.Fatalf("reconcile error = %v", err)
	}
	assertOnlyPolicyInspectionCommands(t, runner.commands, 4)
}

func TestReconcilePolicyRoutesRefusesEarlierRuleOverlappingManagedMark(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTUN)
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: []byte("500: from all fwmark 0x3/0xff lookup 222 proto 99\n")}},
		{},
		{result: Result{ExitCode: 2, Stderr: []byte("FIB table does not exist")}},
		{},
	}}
	err := reconcilePolicyRoutes(context.Background(), runner, plan)
	if err == nil || !strings.Contains(err.Error(), "priority 500 overlapping managed mark 0x3") {
		t.Fatalf("reconcile error = %v", err)
	}
	assertOnlyPolicyInspectionCommands(t, runner.commands, 4)
}

func TestReconcilePolicyRoutesRefusesForeignRouteBeforeMutation(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTPROXY)
	runner := &recordingRunner{steps: []runnerStep{
		{},
		{result: Result{Stdout: []byte("local default dev lo proto static\n")}},
		{},
		{},
	}}
	err := reconcilePolicyRoutes(context.Background(), runner, plan)
	if err == nil || !strings.Contains(err.Error(), "foreign route in reserved policy table 100") {
		t.Fatalf("reconcile error = %v", err)
	}
	assertOnlyPolicyInspectionCommands(t, runner.commands, 4)
}

func TestReconcilePolicyRoutesPreflightsEveryDesiredTableBeforeMutation(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeMIXED)
	runner := &recordingRunner{steps: []runnerStep{
		{},
		{result: Result{ExitCode: 2, Stderr: []byte("FIB table does not exist")}},
		{result: Result{Stdout: []byte("default dev foreign-tun proto static\n")}},
		{},
	}}
	err := reconcilePolicyRoutes(context.Background(), runner, plan)
	if err == nil || !strings.Contains(err.Error(), "foreign route in reserved policy table 101") {
		t.Fatalf("reconcile error = %v", err)
	}
	assertOnlyPolicyInspectionCommands(t, runner.commands, 4)
}

func TestReconcilePolicyRoutesLeavesHealthyOwnedStateUntouched(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeMIXED)
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: []byte(ownedTPROXYRule + ownedTUNRule)}},
		{result: Result{Stdout: []byte("2 default dev lo proto 196 scope 254\n")}},
		{result: Result{Stdout: []byte("1 default dev clash-tun proto 196 scope 253\n")}},
		{result: Result{Stdout: []byte("2 default dev lo table 100 proto 196 scope 254\n1 default dev clash-tun table 101 proto 196 scope 253\n")}},
	}}
	if err := reconcilePolicyRoutes(context.Background(), runner, plan); err != nil {
		t.Fatal(err)
	}
	assertOnlyPolicyInspectionCommands(t, runner.commands, 4)
}

func TestReconcilePolicyRoutesRefusesUnknownProtocolRouteInReservedTable(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTUN)
	plan.TUNDevice = "new-tun"
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: []byte(ownedTUNRule)}},
		{result: Result{}},
		{result: Result{Stdout: []byte("default dev old-tun proto 196\n")}},
		{result: Result{Stdout: []byte("default dev old-tun table 101 proto 196\n")}},
	}}
	err := reconcilePolicyRoutes(context.Background(), runner, plan)
	if err == nil || !strings.Contains(err.Error(), "foreign route in reserved policy table 101") {
		t.Fatalf("reconcile error = %v", err)
	}
	assertOnlyPolicyInspectionCommands(t, runner.commands, 4)
}

func TestPolicyRoutesPreserveFiveModes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		mode       Mode
		wantTPROXY bool
		wantTUN    bool
	}{
		{ModeTPROXY, true, false},
		{ModeHYBRID, true, false},
		{ModeTUN, false, true},
		{ModeMIXED, true, true},
		{ModeMIXED2, false, true},
	}
	for _, test := range tests {
		routes := policyRoutes(DefaultGatewayPlan(test.mode))
		if len(routes) != 2 || routes[0].Desired != test.wantTPROXY || routes[1].Desired != test.wantTUN {
			t.Errorf("policyRoutes(%s) = %+v", test.mode, routes)
		}
	}
}

func TestReconcilePolicyRoutesCreatesMissingRouteBeforeRule(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTPROXY)
	runner := &recordingRunner{steps: []runnerStep{
		{},
		{result: Result{ExitCode: 2, Stderr: []byte("Error: ipv4: FIB table does not exist.")}},
		{},
		{},
		{},
		{},
	}}
	if err := reconcilePolicyRoutes(context.Background(), runner, plan); err != nil {
		t.Fatal(err)
	}
	if got := commandText(runner.commands[4]); got != "ip -4 route add local default dev lo table 100 proto 196" {
		t.Fatalf("route command = %q", got)
	}
	if got := commandText(runner.commands[5]); got != "ip -4 rule add pref 1000 protocol 196 fwmark 0x1 lookup 100" {
		t.Fatalf("rule command = %q", got)
	}
}

func TestReconcilePolicyRoutesPreservesUnknownProtocolOrphan(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTUN)
	plan.TUNTable = 150
	plan.TUNPriority = 1150
	plan.TUNDevice = "new-tun"
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: []byte("1400: from all fwmark 0x3 lookup 222 proto 196\n")}},
		{result: Result{ExitCode: 2, Stderr: []byte("routing table does not exist")}},
		{result: Result{ExitCode: 2, Stderr: []byte("routing table does not exist")}},
		{result: Result{Stdout: []byte("default dev old-tun table 222 proto 196\n")}},
		{},
		{},
	}}
	if err := reconcilePolicyRoutes(context.Background(), runner, plan); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip -4 route add default dev new-tun table 150 proto 196",
		"ip -4 rule add pref 1150 protocol 196 fwmark 0x3 lookup 150",
	}
	for index, command := range runner.commands[4:] {
		if got := commandText(command); got != want[index] {
			t.Errorf("command %d = %q, want %q", index+4, got, want[index])
		}
	}
}

func TestReconcilePolicyRoutesPreservesUnknownProtocolRouteInInactiveKnownTable(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTPROXY)
	runner := &recordingRunner{steps: []runnerStep{
		{},
		{result: Result{ExitCode: 2, Stderr: []byte("FIB table does not exist")}},
		{result: Result{Stdout: []byte("default dev someone-else proto 196\n")}},
		{result: Result{Stdout: []byte("default dev someone-else table 101 proto 196\n")}},
		{},
		{},
	}}
	if err := reconcilePolicyRoutes(context.Background(), runner, plan); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip -4 route add local default dev lo table 100 proto 196",
		"ip -4 rule add pref 1000 protocol 196 fwmark 0x1 lookup 100",
	}
	for index, command := range runner.commands[4:] {
		if got := commandText(command); got != want[index] {
			t.Errorf("command %d = %q, want %q", index+4, got, want[index])
		}
	}
}

func TestCleanupPolicyRoutesPreservesUnknownProtocolOrphans(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTPROXY)
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: []byte(ownedTPROXYRule + "1400: from all fwmark 0x3 lookup 222 proto 196\n")}},
		{result: Result{Stdout: []byte("local default dev lo proto 196\n")}},
		{result: Result{ExitCode: 2, Stderr: []byte("FIB table does not exist")}},
		{},
		{},
	}}
	if err := cleanupPolicyRoutes(context.Background(), runner, plan); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip -N -4 rule show",
		"ip -N -4 route show table 100",
		"ip -N -4 route show table 101",
		"ip -4 rule del pref 1000 protocol 196 fwmark 0x1 lookup 100",
		"ip -4 route flush table 100 proto 196",
	}
	if len(runner.commands) != len(want) {
		t.Fatalf("commands = %+v", runner.commands)
	}
	for index, command := range runner.commands {
		if got := commandText(command); got != want[index] {
			t.Errorf("command %d = %q, want %q", index, got, want[index])
		}
	}
}

func TestCleanupPolicyRoutesRefusesUnknownProtocolRouteInKnownTable(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTPROXY)
	runner := &recordingRunner{steps: []runnerStep{
		{},
		{result: Result{ExitCode: 2, Stderr: []byte("FIB table does not exist")}},
		{result: Result{Stdout: []byte("default dev someone-else proto 196\n")}},
	}}
	err := cleanupPolicyRoutes(context.Background(), runner, plan)
	if err == nil || !strings.Contains(err.Error(), "refusing unknown protocol 196 route in policy table 101") {
		t.Fatalf("cleanup error = %v", err)
	}
	assertOnlyPolicyInspectionCommands(t, runner.commands, 3)
}

func TestCheckPolicyRoutesTreatsMissingDesiredTableAsMismatch(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTPROXY)
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: []byte(ownedTPROXYRule)}},
		{result: Result{ExitCode: 2, Stderr: []byte("Error: ipv4: FIB table does not exist.")}},
		{},
	}}
	matches, err := checkPolicyRoutes(context.Background(), runner, plan)
	if err != nil {
		t.Fatal(err)
	}
	if matches {
		t.Fatal("missing desired route table was accepted")
	}
}

func TestCheckPolicyRoutesAcceptsForeignStateInUnusedTable(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTPROXY)
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: []byte(ownedTPROXYRule + "1001: from all fwmark 0x9 lookup 101 proto 99\n")}},
		{result: Result{Stdout: []byte("local default dev lo proto 196\n")}},
		{result: Result{Stdout: []byte("local default dev lo table 100 proto 196\n")}},
	}}
	matches, err := checkPolicyRoutes(context.Background(), runner, plan)
	if err != nil {
		t.Fatal(err)
	}
	if !matches {
		t.Fatal("foreign state in unused table was rejected")
	}
}

func TestCheckPolicyRoutesRejectsEarlierRuleOverlappingManagedMark(t *testing.T) {
	t.Parallel()
	plan := DefaultGatewayPlan(ModeTUN)
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: []byte(ownedTUNRule + "500: from all fwmark 0x3/0xff lookup 222 proto 99\n")}},
		{result: Result{Stdout: []byte("default dev clash-tun proto 196\n")}},
		{result: Result{Stdout: []byte("default dev clash-tun table 101 proto 196\n")}},
	}}
	matches, err := checkPolicyRoutes(context.Background(), runner, plan)
	if err != nil {
		t.Fatal(err)
	}
	if matches {
		t.Fatal("earlier overlapping policy rule was accepted")
	}
}

func assertOnlyPolicyInspectionCommands(t *testing.T, commands []Command, count int) {
	t.Helper()
	if len(commands) != count {
		t.Fatalf("commands = %+v", commands)
	}
	for _, command := range commands {
		text := commandText(command)
		if strings.Contains(text, " add ") || strings.Contains(text, " del ") || strings.Contains(text, " flush ") || strings.Contains(text, " replace ") {
			t.Fatalf("mutation executed before ownership preflight: %q", text)
		}
	}
}

func commandText(command Command) string {
	return strings.TrimSpace(command.Name + " " + strings.Join(command.Args, " "))
}
