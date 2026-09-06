package openwrt

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func guardTestPlan() RestartGuardPlan {
	return RestartGuardPlan{Protected: []string{"br-lan"}, Trusted: []string{"br-lan", "br-local"}}
}

func guardTableJSON(comment string) []byte {
	data, _ := json.Marshal(map[string]any{"nftables": []any{map[string]any{"table": map[string]any{"family": "inet", "name": RestartGuardTable, "comment": comment}}}})
	return data
}

func missingGuardStep() runnerStep {
	return runnerStep{result: Result{ExitCode: 1, Stderr: []byte("No such file or directory")}}
}

func TestRestartGuardBoundaryAndLease(t *testing.T) {
	plan := guardTestPlan()
	body, err := RenderRestartGuard(plan, RestartGuardMaxLease)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"table inet boxctl_guard", "type ifname", "flags timeout", "timeout 300s", "priority -10", "iifname @protected_lan oifname != @trusted_local counter drop"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in %s", want, body)
		}
	}
	for _, forbidden := range []string{"hook input", "hook output", "ip saddr", "ip6 saddr", "ct state established accept", "wan"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("unexpected %q in %s", forbidden, body)
		}
	}
	for _, lease := range []time.Duration{0, time.Millisecond, RestartGuardMaxLease + time.Second} {
		if _, err := RenderRestartGuard(plan, lease); err == nil {
			t.Errorf("accepted lease %s", lease)
		}
	}
	for _, name := range []string{"", "lo", "br-lan\"; drop", "interface-name-too-long"} {
		bad := guardTestPlan()
		bad.Protected = []string{name}
		if _, err := RenderRestartGuard(bad, time.Second); err == nil {
			t.Errorf("accepted interface %q", name)
		}
	}
}

func TestRestartGuardAtomicInstallAndNonRenewingIdempotence(t *testing.T) {
	plan := guardTestPlan()
	owned := runnerStep{result: Result{Stdout: guardTableJSON(plan.comment())}}
	runner := &recordingRunner{steps: []runnerStep{missingGuardStep(), {}, {}, owned, owned}}
	for range 2 {
		if err := ApplyRestartGuard(context.Background(), runner, plan, RestartGuardMaxLease); err != nil {
			t.Fatal(err)
		}
	}
	if len(runner.commands) != 5 {
		t.Fatalf("commands = %+v", runner.commands)
	}
	if strings.Join(runner.commands[1].Args, " ") != "-c -f -" || strings.Join(runner.commands[2].Args, " ") != "-f -" || string(runner.commands[1].Stdin) != string(runner.commands[2].Stdin) {
		t.Fatal("install was not preflighted as one atomic transaction")
	}
}

func TestRestartGuardRejectsForeignAndFailedPreflight(t *testing.T) {
	for _, remove := range []bool{false, true} {
		runner := &recordingRunner{steps: []runnerStep{{result: Result{Stdout: guardTableJSON("owned by someone else")}}}}
		var err error
		if remove {
			err = RemoveRestartGuard(context.Background(), runner)
		} else {
			err = ApplyRestartGuard(context.Background(), runner, guardTestPlan(), time.Minute)
		}
		if err == nil || !strings.Contains(err.Error(), "foreign") || len(runner.commands) != 1 {
			t.Fatalf("foreign table modified: %v %+v", err, runner.commands)
		}
	}
	runner := &recordingRunner{steps: []runnerStep{missingGuardStep(), {result: Result{ExitCode: 1, Stderr: []byte("unsupported timeout")}}}}
	if err := ApplyRestartGuard(context.Background(), runner, guardTestPlan(), time.Minute); err == nil || len(runner.commands) != 2 {
		t.Fatalf("failed preflight committed: %v %+v", err, runner.commands)
	}
}

func TestRestartGuardVerifiedRemoval(t *testing.T) {
	owned := runnerStep{result: Result{Stdout: guardTableJSON(guardTestPlan().comment())}}
	for _, remains := range []bool{false, true} {
		last := missingGuardStep()
		if remains {
			last = owned
		}
		runner := &recordingRunner{steps: []runnerStep{owned, {}, {}, last}}
		err := RemoveRestartGuard(context.Background(), runner)
		if (err != nil) != remains {
			t.Fatalf("remains=%v err=%v", remains, err)
		}
	}
	runner := &recordingRunner{steps: []runnerStep{missingGuardStep()}}
	if err := RemoveRestartGuard(context.Background(), runner); err != nil || len(runner.commands) != 1 {
		t.Fatalf("absent cleanup: %v", err)
	}
}

func TestRestartGuardRejectsConfiguredAndLiveOffload(t *testing.T) {
	for _, key := range []string{"flow_offloading", "flow_offloading_hw"} {
		runner := &recordingRunner{steps: []runnerStep{{result: Result{Stdout: []byte("config defaults\n option " + key + " '1'\n")}}}}
		if err := CheckRestartGuardSupport(context.Background(), runner); err == nil || len(runner.commands) != 1 {
			t.Fatalf("accepted %s: %v", key, err)
		}
	}
	for _, live := range []bool{false, true} {
		listing := `{"nftables":[]}`
		if live {
			listing = `{"nftables":[{"flowtable":{"family":"inet","table":"custom","name":"fast"}}]}`
		}
		runner := &recordingRunner{steps: []runnerStep{{result: Result{Stdout: []byte("config defaults\n option flow_offloading '0'\n option flow_offloading_hw '0'\n")}}, {result: Result{Stdout: []byte(listing)}}}}
		if err := CheckRestartGuardSupport(context.Background(), runner); (err != nil) != live {
			t.Fatalf("live=%v err=%v", live, err)
		}
	}
}
