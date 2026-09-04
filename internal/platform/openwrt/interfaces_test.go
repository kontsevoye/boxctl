package openwrt

import (
	"context"
	"reflect"
	"testing"
)

const networkUCI = `package network
config interface 'loopback'
	option device 'lo'
config interface 'lan'
	option device 'br-lan'
config interface 'guest'
	option device 'br-guest'
config interface 'wan'
	option device 'eth1'
config interface 'wan6'
	option device '@wan'
`

const firewallUCI = `package firewall
config zone
	option name 'lan'
	list network 'lan'
	list network 'guest'
config zone
	option name 'wan'
	list network 'wan'
	list network 'wan6'
`

func TestDetectInterfacesFromUBus(t *testing.T) {
	t.Parallel()
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: []byte(networkUCI)}},
		{result: Result{Stdout: []byte(firewallUCI)}},
		{result: Result{Stdout: []byte(`{"interface":[{"interface":"lan","l3_device":"br-lan"},{"interface":"guest","l3_device":"br-guest"},{"interface":"wan","l3_device":"pppoe-wan"},{"interface":"wan6","l3_device":"pppoe-wan"}]}`)}},
		{result: Result{Stdout: []byte(`[{"ifname":"lo"},{"ifname":"br-lan"},{"ifname":"br-guest"},{"ifname":"eth0"},{"ifname":"lan1"},{"ifname":"pppoe-wan"}]`)}},
	}}
	got, err := DetectInterfaces(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != "ubus" || !reflect.DeepEqual(got.LANInterfaces, []string{"br-guest", "br-lan"}) || !reflect.DeepEqual(got.WANInterfaces, []string{"pppoe-wan"}) {
		t.Fatalf("discovery = %+v", got)
	}
	if !reflect.DeepEqual(got.AllInterfaces, []string{"br-guest", "br-lan", "eth0", "eth1", "lan1", "pppoe-wan", "wan"}) {
		t.Fatalf("all interfaces = %v", got.AllInterfaces)
	}
	if len(runner.commands) != 4 || runner.commands[0].Name != "uci" || runner.commands[2].Name != "ubus" || runner.commands[3].Name != "ip" {
		t.Fatalf("commands = %+v", runner.commands)
	}
}

func TestDetectInterfacesFallsBackToReadOnlyIPJSON(t *testing.T) {
	t.Parallel()
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: []byte(networkUCI)}},
		{result: Result{Stdout: []byte(firewallUCI)}},
		{result: Result{ExitCode: 1, Stderr: []byte("ubus unavailable")}},
		{result: Result{Stdout: []byte(`[{"dst":"default","dev":"eth1"}]`)}},
		{result: Result{Stdout: []byte(`[{"ifname":"lo"},{"ifname":"br-lan"},{"ifname":"br-guest"},{"ifname":"eth1"}]`)}},
	}}
	got, err := DetectInterfaces(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != "ip" || !reflect.DeepEqual(got.LANInterfaces, []string{"br-guest", "br-lan"}) || !reflect.DeepEqual(got.WANInterfaces, []string{"eth1"}) {
		t.Fatalf("discovery = %+v", got)
	}
	if !reflect.DeepEqual(got.AllInterfaces, []string{"br-guest", "br-lan", "eth1"}) {
		t.Fatalf("all interfaces = %v", got.AllInterfaces)
	}
	for _, command := range runner.commands {
		if command.Name != "uci" && command.Name != "ubus" && command.Name != "ip" {
			t.Fatalf("mutating/unexpected command: %+v", command)
		}
	}
}

func TestDetectInterfacesFailsClosedOnAmbiguousZones(t *testing.T) {
	t.Parallel()
	badFirewall := `package firewall
config zone
	option name 'lan'
	list network 'lan'
config zone
	option name 'wan'
	list network 'lan'
`
	runner := &recordingRunner{steps: []runnerStep{
		{result: Result{Stdout: []byte(networkUCI)}},
		{result: Result{Stdout: []byte(badFirewall)}},
	}}
	if _, err := DetectInterfaces(context.Background(), runner); err == nil {
		t.Fatal("ambiguous topology succeeded")
	}
	if len(runner.commands) != 2 {
		t.Fatalf("commands after failed topology validation = %+v", runner.commands)
	}
}
