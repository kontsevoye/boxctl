package openwrt

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

const originalUCI = `package dhcp

config dnsmasq
	option domainneeded '1'
	list server '1.1.1.1'
	list server '8.8.8.8'
	option noresolv '0'

config dhcp 'lan'
	option interface 'lan'
`

const managedUCI = `package dhcp

config dnsmasq
	list server '127.0.0.1#7874'
	option noresolv '1'
	option cachesize '0'
`

func originalDNSBackup(t *testing.T) DNSBackup {
	t.Helper()
	options, err := parseFirstUCISection(originalUCI, "dnsmasq", managedDNSOptions)
	if err != nil {
		t.Fatal(err)
	}
	return DNSBackup{Version: dnsBackupVersion, Package: "dhcp", Section: "@dnsmasq[0]", Options: options}
}

func TestParseUCIOptionPresenceAndKind(t *testing.T) {
	t.Parallel()
	backup := originalDNSBackup(t)
	server := backup.Options["server"]
	if !server.Present || server.Kind != UCIList || !reflect.DeepEqual(server.Values, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Fatalf("server = %+v", server)
	}
	if backup.Options["cachesize"].Present {
		t.Fatalf("cachesize presence was lost: %+v", backup.Options["cachesize"])
	}
	if got := backup.Options["noresolv"]; !got.Present || got.Kind != UCIOption || !reflect.DeepEqual(got.Values, []string{"0"}) {
		t.Fatalf("noresolv = %+v", got)
	}
}

func TestDNSApplyUpstreamUsesAtomicBatch(t *testing.T) {
	t.Parallel()
	backup := originalDNSBackup(t)
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: []byte(originalUCI)}},
		{result: Result{}},
		{result: Result{}},
	}}
	manager := NewDNSManager(runner)
	plan := DefaultGatewayPlan(ModeTPROXY)
	plan.DNSMode = DNSUpstream
	if err := manager.Apply(context.Background(), plan, backup); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 3 {
		t.Fatalf("commands = %+v", runner.commands)
	}
	batch := string(runner.commands[1].Stdin)
	for _, fragment := range []string{
		"set dhcp.@dnsmasq[0].cachesize='0'",
		"delete dhcp.@dnsmasq[0].noresolv",
		"set dhcp.@dnsmasq[0].noresolv='1'",
		"delete dhcp.@dnsmasq[0].server",
		"add_list dhcp.@dnsmasq[0].server='127.0.0.1#7874'",
		"commit dhcp",
	} {
		if !strings.Contains(batch, fragment) {
			t.Errorf("batch lacks %q:\n%s", fragment, batch)
		}
	}
	if strings.Contains(batch, "delete dhcp.@dnsmasq[0].cachesize") {
		t.Errorf("absent option must not be deleted:\n%s", batch)
	}
	if runner.commands[2].Name != "/etc/init.d/dnsmasq" {
		t.Fatalf("restart command = %+v", runner.commands[2])
	}
}

func TestDNSReconcileAlreadyDesiredIsReadOnly(t *testing.T) {
	t.Parallel()
	backup := originalDNSBackup(t)
	runner := &recordingRunner{steps: []runnerStep{{result: Result{Stdout: []byte(managedUCI)}}}}
	plan := DefaultGatewayPlan(ModeTPROXY)
	plan.DNSMode = DNSUpstream
	if err := NewDNSManager(runner).Reconcile(context.Background(), plan, backup); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 || runner.commands[0].Name != "uci" {
		t.Fatalf("unexpected commands: %+v", runner.commands)
	}
}

func TestDNSReconcileConvertsScalarServerToList(t *testing.T) {
	t.Parallel()
	scalarManagedUCI := strings.Replace(managedUCI, "list server", "option server", 1)
	backup := originalDNSBackup(t)
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: []byte(scalarManagedUCI)}},
		{result: Result{Stdout: []byte(scalarManagedUCI)}},
		{result: Result{}},
		{result: Result{}},
	}}
	plan := DefaultGatewayPlan(ModeTPROXY)
	plan.DNSMode = DNSUpstream
	if err := NewDNSManager(runner).Reconcile(context.Background(), plan, backup); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 4 {
		t.Fatalf("commands = %+v", runner.commands)
	}
	batch := string(runner.commands[2].Stdin)
	for _, fragment := range []string{
		"delete dhcp.@dnsmasq[0].server",
		"add_list dhcp.@dnsmasq[0].server='127.0.0.1#7874'",
	} {
		if !strings.Contains(batch, fragment) {
			t.Errorf("batch lacks %q:\n%s", fragment, batch)
		}
	}
	if strings.Contains(batch, "set dhcp.@dnsmasq[0].server=") {
		t.Errorf("server was reconciled as a scalar option:\n%s", batch)
	}
}

func TestDNSRestorePreservesListAndAbsence(t *testing.T) {
	t.Parallel()
	backup := originalDNSBackup(t)
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: []byte(managedUCI)}},
		{result: Result{}},
		{result: Result{}},
	}}
	if err := NewDNSManager(runner).Restore(context.Background(), backup); err != nil {
		t.Fatal(err)
	}
	batch := string(runner.commands[1].Stdin)
	for _, fragment := range []string{
		"delete dhcp.@dnsmasq[0].cachesize",
		"delete dhcp.@dnsmasq[0].noresolv",
		"set dhcp.@dnsmasq[0].noresolv='0'",
		"delete dhcp.@dnsmasq[0].server",
		"add_list dhcp.@dnsmasq[0].server='1.1.1.1'",
		"add_list dhcp.@dnsmasq[0].server='8.8.8.8'",
	} {
		if !strings.Contains(batch, fragment) {
			t.Errorf("restore batch lacks %q:\n%s", fragment, batch)
		}
	}
}

func TestDNSRestoreRetriesRuntimeRestartAfterUCICommit(t *testing.T) {
	t.Parallel()
	backup := originalDNSBackup(t)
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: []byte(managedUCI)}},
		{result: Result{}},
		{result: Result{ExitCode: 1, Stderr: []byte("restart failed")}},
		{result: Result{Stdout: []byte(originalUCI)}},
		{result: Result{}},
	}}
	manager := NewDNSManager(runner)
	if err := manager.Restore(context.Background(), backup); err == nil || !strings.Contains(err.Error(), "restart dnsmasq") {
		t.Fatalf("first Restore() error = %v, want restart failure", err)
	}
	if err := manager.Restore(context.Background(), backup); err != nil {
		t.Fatalf("retry Restore() error = %v", err)
	}
	if len(runner.commands) != 5 {
		t.Fatalf("commands = %+v", runner.commands)
	}
	wantNames := []string{"uci", "uci", "/etc/init.d/dnsmasq", "uci", "/etc/init.d/dnsmasq"}
	for index, name := range wantNames {
		if runner.commands[index].Name != name {
			t.Fatalf("command %d = %+v, want %s", index, runner.commands[index], name)
		}
	}
	if len(runner.commands[4].Stdin) != 0 {
		t.Fatalf("retry restart unexpectedly wrote a second UCI batch: %+v", runner.commands[4])
	}
}

func TestParseUCIWordsDoesNotEvaluateShell(t *testing.T) {
	t.Parallel()
	words, err := parseUCIWords(`option server '$(touch /tmp/never)'`)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(words, []string{"option", "server", "$(touch /tmp/never)"}) {
		t.Fatalf("words = %#v", words)
	}
}

func TestDNSManagerRejectsAlternateOrInjectedUCITarget(t *testing.T) {
	t.Parallel()
	runner := &recordingRunner{}
	manager := NewDNSManager(runner)
	manager.Package = "dhcp\ncommit firewall"
	if _, err := manager.Backup(context.Background()); err == nil {
		t.Fatal("unsafe UCI package accepted")
	}
	if len(runner.commands) != 0 {
		t.Fatalf("unsafe target executed commands: %+v", runner.commands)
	}
}
