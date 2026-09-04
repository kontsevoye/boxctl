package openwrt

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

type firewallRule struct {
	Chain   string
	Handle  uint64
	Comment string
}

type firewallState struct {
	Exists      bool
	OwnedRules  []firewallRule
	PlanMatches bool
}

type firewallListing struct {
	NFTables []struct {
		Rule *struct {
			Family  string `json:"family"`
			Table   string `json:"table"`
			Chain   string `json:"chain"`
			Handle  uint64 `json:"handle"`
			Comment string `json:"comment"`
		} `json:"rule,omitempty"`
	} `json:"nftables"`
}

func inspectFirewallRules(ctx context.Context, runner Runner, plan GatewayPlan) (firewallState, error) {
	result, err := runner.Run(ctx, Command{Name: "nft", Args: []string{"-j", "-a", "list", "table", "inet", "fw4"}})
	if err != nil {
		return firewallState{}, err
	}
	if result.ExitCode != 0 {
		if nftObjectMissing(result.Stderr) {
			state := firewallState{}
			state.PlanMatches = len(expectedFirewallComments(plan)) == 0
			return state, nil
		}
		return firewallState{}, fmt.Errorf("openwrt: inspect fw4 rules: exit %d: %s", result.ExitCode, strings.TrimSpace(string(result.Stderr)))
	}
	var listing firewallListing
	if err := json.Unmarshal(result.Stdout, &listing); err != nil {
		return firewallState{}, fmt.Errorf("openwrt: parse fw4 JSON: %w", err)
	}
	state := firewallState{Exists: true}
	actualComments := make([]string, 0, 3)
	for _, object := range listing.NFTables {
		rule := object.Rule
		if rule == nil || rule.Family != "inet" || rule.Table != "fw4" || !hasOwnerPrefix(rule.Comment, plan) {
			continue
		}
		if rule.Chain != "input" && rule.Chain != "forward" {
			return firewallState{}, fmt.Errorf("openwrt: owned fw4 rule is in unexpected chain %q", rule.Chain)
		}
		if rule.Handle == 0 {
			return firewallState{}, fmt.Errorf("openwrt: owned fw4 rule lacks a handle")
		}
		state.OwnedRules = append(state.OwnedRules, firewallRule{Chain: rule.Chain, Handle: rule.Handle, Comment: rule.Comment})
		actualComments = append(actualComments, rule.Comment)
	}
	slices.Sort(actualComments)
	wanted := expectedFirewallComments(plan)
	slices.Sort(wanted)
	state.PlanMatches = slices.Equal(actualComments, wanted)
	return state, nil
}

func expectedFirewallComments(plan GatewayPlan) []string {
	if !usesTUN(plan.Mode) {
		return nil
	}
	base := ownershipComment(plan)
	return []string{
		base + " role=tun-input",
		base + " role=tun-forward-input",
		base + " role=tun-forward-output",
	}
}

func renderFirewallReconcile(builder *strings.Builder, plan GatewayPlan, current firewallState) error {
	for _, rule := range current.OwnedRules {
		fmt.Fprintf(builder, "delete rule inet fw4 %s handle %d\n", rule.Chain, rule.Handle)
	}
	if !usesTUN(plan.Mode) {
		return nil
	}
	if !current.Exists {
		return fmt.Errorf("openwrt: inet fw4 is required for TUN forwarding")
	}
	comments := expectedFirewallComments(plan)
	fmt.Fprintf(builder, "insert rule inet fw4 input iifname %s counter accept comment %s\n", strconv.Quote(plan.TUNDevice), strconv.Quote(comments[0]))
	fmt.Fprintf(builder, "insert rule inet fw4 forward iifname %s counter accept comment %s\n", strconv.Quote(plan.TUNDevice), strconv.Quote(comments[1]))
	fmt.Fprintf(builder, "insert rule inet fw4 forward oifname %s counter accept comment %s\n", strconv.Quote(plan.TUNDevice), strconv.Quote(comments[2]))
	return nil
}
