package openwrt

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// PolicyProtocol marks boxctl policy rules and routes. Ownership additionally
// requires the exact plan tuple and object shape; a numeric protocol alone is
// not sufficient because the kernel namespace is shared with other software.
const PolicyProtocol = 196

const policyProtocol = PolicyProtocol

type policyRoute struct {
	Mark     uint32
	Table    int
	Priority int
	Route    []string
	Desired  bool
}

type observedPolicyRule struct {
	Priority int
	Mark     uint32
	MarkSpec string
	Table    int
	Owned    bool
	Exact    bool
}

type policyTableState struct {
	OwnedCount      int
	ExactCount      int
	Foreign         bool
	UnknownProtocol bool
}

var (
	rulePriorityPattern = regexp.MustCompile(`^(\d+):(?:\s|$)`)
	ruleMarkPattern     = regexp.MustCompile(`(?:^|\s)fwmark\s+(0x[0-9a-fA-F]+|[0-9]+)(/[0-9a-fA-Fx]+)?(?:\s|$)`)
	ruleTablePattern    = regexp.MustCompile(`(?:^|\s)(?:lookup|table)\s+(\d+)(?:\s|$)`)
	protocolPattern     = regexp.MustCompile(`(?:^|\s)(?:proto|protocol)\s+` + strconv.Itoa(policyProtocol) + `(?:\s|$)`)
	routeTablePattern   = regexp.MustCompile(`(?:^|\s)table\s+(\d+)(?:\s|$)`)
)

func policyRoutes(plan GatewayPlan) []policyRoute {
	tproxy := policyRoute{
		Mark: plan.TProxyMark, Table: plan.TProxyTable, Priority: plan.TProxyPriority,
		Route:   []string{"local", "default", "dev", "lo"},
		Desired: usesTProxyTCP(plan.Mode) || usesTProxyUDP(plan.Mode),
	}
	tun := policyRoute{
		Mark: plan.TUNMark, Table: plan.TUNTable, Priority: plan.TUNPriority,
		Route:   []string{"default", "dev", plan.TUNDevice},
		Desired: usesTUN(plan.Mode),
	}
	return []policyRoute{tproxy, tun}
}

func reconcilePolicyRoutes(ctx context.Context, runner Runner, plan GatewayPlan) error {
	rules, err := inspectPolicyRules(ctx, runner)
	if err != nil {
		return err
	}
	routes := policyRoutes(plan)
	tableStates := make(map[int]policyTableState, len(routes))
	for _, route := range routes {
		state, err := inspectPolicyTable(ctx, runner, route)
		if err != nil {
			return err
		}
		tableStates[route.Table] = state
	}
	orphanTables, err := inspectOwnedRouteTables(ctx, runner, routes)
	if err != nil {
		return err
	}
	if err := preflightPolicyOwnership(rules, routes, tableStates); err != nil {
		return err
	}

	// Delete stale rules before changing their routes. A healthy desired rule is
	// retained only when its route is healthy too; otherwise it is recreated
	// after the route, avoiding a rule that temporarily points at an empty table.
	retainedRules := make(map[int]bool, len(routes))
	var joined error
	for _, group := range groupOwnedRules(rules, routes) {
		desired, wanted := desiredRouteAtPriority(routes, group[0].Priority)
		state := tableStates[desired.Table]
		keep := wanted && state.ExactCount == 1 && state.OwnedCount == 1 && len(group) == 1 && ruleMatchesRoute(group[0], desired)
		if keep {
			retainedRules[desired.Priority] = true
			continue
		}
		for _, rule := range group {
			if _, err := runOK(ctx, runner, deleteObservedRuleCommand(rule)); err != nil {
				joined = errors.Join(joined, err)
			}
		}
	}
	if joined != nil {
		return joined
	}

	desiredTables := make(map[int]bool, len(routes))
	for _, route := range routes {
		if !route.Desired {
			continue
		}
		desiredTables[route.Table] = true
		state := tableStates[route.Table]
		if state.ExactCount == 1 && state.OwnedCount == 1 {
			continue
		}
		if state.OwnedCount > 0 {
			if err := flushOwnedRouteTable(ctx, runner, route.Table); err != nil {
				return err
			}
		}
		if _, err := runOK(ctx, runner, addRouteCommand(route)); err != nil {
			return err
		}
	}
	for _, table := range orphanTables {
		if desiredTables[table] {
			continue
		}
		if tableStates[table].UnknownProtocol {
			// A matching numeric protocol outside boxctl's exact route shape is
			// not ownership proof. Leave it untouched.
			continue
		}
		if err := flushOwnedRouteTable(ctx, runner, table); err != nil {
			return err
		}
	}
	for _, route := range routes {
		if !route.Desired || retainedRules[route.Priority] {
			continue
		}
		if _, err := runOK(ctx, runner, addRuleCommand(route)); err != nil {
			return err
		}
	}
	return nil
}

func cleanupPolicyRoutes(ctx context.Context, runner Runner, plan GatewayPlan) error {
	rules, rulesErr := inspectPolicyRules(ctx, runner)
	routes := policyRoutes(plan)
	tableStates := make(map[int]policyTableState, len(routes))
	var tableErrs error
	for _, route := range routes {
		state, err := inspectPolicyTable(ctx, runner, route)
		if err != nil {
			tableErrs = errors.Join(tableErrs, err)
			continue
		}
		tableStates[route.Table] = state
	}

	joined := errors.Join(rulesErr, tableErrs)
	for _, rule := range rules {
		if !managedPolicyRule(rule, routes) {
			continue
		}
		if _, err := runOK(ctx, runner, deleteObservedRuleCommand(rule)); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	for _, route := range routes {
		state, inspected := tableStates[route.Table]
		if !inspected || state.OwnedCount == 0 {
			continue
		}
		if state.UnknownProtocol {
			joined = errors.Join(joined, fmt.Errorf("openwrt: refusing unknown protocol %d route in policy table %d", policyProtocol, route.Table))
			continue
		}
		if err := flushOwnedRouteTable(ctx, runner, route.Table); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	return joined
}

func checkPolicyRoutes(ctx context.Context, runner Runner, plan GatewayPlan) (bool, error) {
	rules, err := inspectPolicyRules(ctx, runner)
	if err != nil {
		return false, err
	}
	routes := policyRoutes(plan)
	tableStates := make(map[int]policyTableState, len(routes))
	for _, route := range routes {
		if !route.Desired {
			continue
		}
		state, err := inspectPolicyTable(ctx, runner, route)
		if err != nil {
			return false, err
		}
		tableStates[route.Table] = state
	}
	ownedTables, err := inspectOwnedRouteTables(ctx, runner, routes)
	if err != nil {
		return false, err
	}
	if policyOwnershipConflicts(rules, routes, tableStates) {
		return false, nil
	}

	desiredRules := 0
	desiredTables := make(map[int]bool, len(routes))
	for _, route := range routes {
		if !route.Desired {
			continue
		}
		desiredRules++
		desiredTables[route.Table] = true
		state := tableStates[route.Table]
		if state.ExactCount != 1 || state.OwnedCount != 1 {
			return false, nil
		}
		matches := 0
		for _, rule := range rules {
			if rule.Owned && ruleMatchesRoute(rule, route) {
				matches++
			}
		}
		if matches != 1 {
			return false, nil
		}
	}
	ownedRules := 0
	for _, rule := range rules {
		if managedPolicyRule(rule, routes) {
			ownedRules++
		}
	}
	if ownedRules != desiredRules {
		return false, nil
	}
	for _, table := range ownedTables {
		if !desiredTables[table] {
			return false, nil
		}
	}
	return true, nil
}

func inspectPolicyRules(ctx context.Context, runner Runner) ([]observedPolicyRule, error) {
	result, err := runOK(ctx, runner, Command{Name: "ip", Args: []string{"-N", "-4", "rule", "show"}})
	if err != nil {
		return nil, err
	}
	var rules []observedPolicyRule
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		rule, ok := parsePolicyRule(line)
		if ok {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func parsePolicyRule(line string) (observedPolicyRule, bool) {
	priorityMatch := rulePriorityPattern.FindStringSubmatch(strings.TrimSpace(line))
	if len(priorityMatch) != 2 {
		return observedPolicyRule{}, false
	}
	priority, err := strconv.Atoi(priorityMatch[1])
	if err != nil {
		return observedPolicyRule{}, false
	}
	rule := observedPolicyRule{Priority: priority, Owned: protocolPattern.MatchString(line)}
	tableMatch := ruleTablePattern.FindStringSubmatch(line)
	if len(tableMatch) == 2 {
		rule.Table, _ = strconv.Atoi(tableMatch[1])
	}
	markMatch := ruleMarkPattern.FindStringSubmatch(line)
	if len(markMatch) >= 2 {
		mark, parseErr := strconv.ParseUint(markMatch[1], 0, 32)
		if parseErr == nil {
			rule.Mark = uint32(mark)
			rule.MarkSpec = markMatch[1]
			if len(markMatch) == 3 {
				rule.MarkSpec += markMatch[2]
			}
			rule.Exact = markMaskIsExact(markMatch) && policyRuleShapeIsExact(line)
		}
	}
	return rule, true
}

func policyRuleShapeIsExact(line string) bool {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 1 || !strings.HasSuffix(fields[0], ":") {
		return false
	}
	fields = fields[1:]
	seen := make(map[string]bool, 4)
	for index := 0; index < len(fields); {
		key := fields[index]
		if index+1 >= len(fields) || seen[key] {
			return false
		}
		value := fields[index+1]
		switch key {
		case "from":
			if value != "all" {
				return false
			}
		case "fwmark":
			// The value and optional exact mask are validated separately by
			// parsePolicyRule and markMaskIsExact.
		case "lookup", "table":
			if seen["lookup"] || seen["table"] {
				return false
			}
		case "proto", "protocol":
			if (seen["proto"] || seen["protocol"]) || value != strconv.Itoa(policyProtocol) {
				return false
			}
		default:
			return false
		}
		seen[key] = true
		index += 2
	}
	return seen["from"] && seen["fwmark"] && (seen["lookup"] || seen["table"]) && (seen["proto"] || seen["protocol"])
}

func markMaskIsExact(matches []string) bool {
	if len(matches) < 3 || matches[2] == "" {
		return true
	}
	mask, err := strconv.ParseUint(strings.TrimPrefix(matches[2], "/"), 0, 32)
	return err == nil && mask == uint64(^uint32(0))
}

func inspectPolicyTable(ctx context.Context, runner Runner, route policyRoute) (policyTableState, error) {
	result, err := runner.Run(ctx, Command{Name: "ip", Args: []string{"-N", "-4", "route", "show", "table", strconv.Itoa(route.Table)}})
	if err != nil {
		return policyTableState{}, err
	}
	if result.ExitCode != 0 {
		if isMissingRouteTable(result) {
			return policyTableState{}, nil
		}
		return policyTableState{}, fmt.Errorf("openwrt: inspect route table %d: %s", route.Table, strings.TrimSpace(string(result.Stderr)))
	}
	var state policyTableState
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !protocolPattern.MatchString(line) {
			state.Foreign = true
			continue
		}
		state.OwnedCount++
		if isManagedRouteLine(line, route.Route) {
			state.ExactCount++
		} else {
			state.Foreign = true
			state.UnknownProtocol = true
		}
	}
	return state, nil
}

func inspectOwnedRouteTables(ctx context.Context, runner Runner, routes []policyRoute) ([]int, error) {
	result, err := runOK(ctx, runner, Command{Name: "ip", Args: []string{
		"-N", "-4", "route", "show", "table", "all", "proto", strconv.Itoa(policyProtocol),
	}})
	if err != nil {
		return nil, err
	}
	var tables []int
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		if strings.TrimSpace(line) == "" || !protocolPattern.MatchString(line) {
			continue
		}
		table := 254 // ip omits "table main" even when table all is requested.
		match := routeTablePattern.FindStringSubmatch(line)
		if len(match) == 2 {
			table, _ = strconv.Atoi(match[1])
		}
		if table > 0 && policyTableIsKnown(table, routes) && !slices.Contains(tables, table) {
			tables = append(tables, table)
		}
	}
	slices.Sort(tables)
	return tables, nil
}

func policyTableIsKnown(table int, routes []policyRoute) bool {
	for _, route := range routes {
		if route.Table == table {
			return true
		}
	}
	return false
}

func preflightPolicyOwnership(rules []observedPolicyRule, routes []policyRoute, tables map[int]policyTableState) error {
	for _, route := range routes {
		if !route.Desired {
			continue
		}
		if tables[route.Table].Foreign {
			return fmt.Errorf("openwrt: refusing foreign route in reserved policy table %d", route.Table)
		}
		for _, rule := range rules {
			if managedPolicyRule(rule, routes) {
				continue
			}
			if rule.Priority < route.Priority && policyRuleMatchesMark(rule, route.Mark) {
				return fmt.Errorf("openwrt: refusing foreign rule at priority %d overlapping managed mark 0x%x", rule.Priority, route.Mark)
			}
			if rule.Priority == route.Priority {
				return fmt.Errorf("openwrt: refusing foreign rule at reserved priority %d", route.Priority)
			}
			if rule.Table == route.Table {
				return fmt.Errorf("openwrt: refusing foreign rule using reserved policy table %d", route.Table)
			}
		}
	}
	return nil
}

func policyRuleMatchesMark(rule observedPolicyRule, mark uint32) bool {
	if rule.MarkSpec == "" {
		return false
	}
	mask := uint64(^uint32(0))
	if separator := strings.IndexByte(rule.MarkSpec, '/'); separator >= 0 {
		parsed, err := strconv.ParseUint(rule.MarkSpec[separator+1:], 0, 32)
		if err != nil {
			return false
		}
		mask = parsed
	}
	return uint64(mark)&mask == uint64(rule.Mark)&mask
}

func policyOwnershipConflicts(rules []observedPolicyRule, routes []policyRoute, tables map[int]policyTableState) bool {
	return preflightPolicyOwnership(rules, routes, tables) != nil
}

func groupOwnedRules(rules []observedPolicyRule, routes []policyRoute) [][]observedPolicyRule {
	byPriority := make(map[int][]observedPolicyRule)
	var priorities []int
	for _, rule := range rules {
		if !managedPolicyRule(rule, routes) {
			continue
		}
		if _, found := byPriority[rule.Priority]; !found {
			priorities = append(priorities, rule.Priority)
		}
		byPriority[rule.Priority] = append(byPriority[rule.Priority], rule)
	}
	slices.Sort(priorities)
	groups := make([][]observedPolicyRule, 0, len(priorities))
	for _, priority := range priorities {
		groups = append(groups, byPriority[priority])
	}
	return groups
}

func managedPolicyRule(rule observedPolicyRule, routes []policyRoute) bool {
	for _, route := range routes {
		if ruleMatchesRoute(rule, route) {
			return true
		}
	}
	return false
}

func desiredRouteAtPriority(routes []policyRoute, priority int) (policyRoute, bool) {
	for _, route := range routes {
		if route.Desired && route.Priority == priority {
			return route, true
		}
	}
	return policyRoute{}, false
}

func ruleMatchesRoute(rule observedPolicyRule, route policyRoute) bool {
	return rule.Owned && rule.Exact && rule.Priority == route.Priority && rule.Mark == route.Mark && rule.Table == route.Table
}

func addRuleCommand(route policyRoute) Command {
	return Command{Name: "ip", Args: []string{
		"-4", "rule", "add", "pref", strconv.Itoa(route.Priority),
		"protocol", strconv.Itoa(policyProtocol),
		"fwmark", fmt.Sprintf("0x%x", route.Mark), "lookup", strconv.Itoa(route.Table),
	}}
}

func deleteObservedRuleCommand(rule observedPolicyRule) Command {
	args := []string{"-4", "rule", "del", "pref", strconv.Itoa(rule.Priority), "protocol", strconv.Itoa(policyProtocol)}
	if rule.MarkSpec != "" {
		args = append(args, "fwmark", rule.MarkSpec)
	}
	if rule.Table > 0 {
		args = append(args, "lookup", strconv.Itoa(rule.Table))
	}
	return Command{Name: "ip", Args: args}
}

func addRouteCommand(route policyRoute) Command {
	args := []string{"-4", "route", "add"}
	args = append(args, route.Route...)
	args = append(args, "table", strconv.Itoa(route.Table), "proto", strconv.Itoa(policyProtocol))
	return Command{Name: "ip", Args: args}
}

func flushOwnedRouteTable(ctx context.Context, runner Runner, table int) error {
	result, err := runner.Run(ctx, Command{Name: "ip", Args: []string{
		"-4", "route", "flush", "table", strconv.Itoa(table), "proto", strconv.Itoa(policyProtocol),
	}})
	if err != nil {
		return err
	}
	if result.ExitCode == 0 || isMissingRouteTable(result) {
		return nil
	}
	return fmt.Errorf("openwrt: flush owned routes from table %d: %s", table, strings.TrimSpace(string(result.Stderr)))
}

func isMissingRouteTable(result Result) bool {
	if result.ExitCode == 0 {
		return false
	}
	message := strings.ToLower(string(result.Stderr) + "\n" + string(result.Stdout))
	return strings.Contains(message, "fib table does not exist") ||
		strings.Contains(message, "routing table does not exist")
}

func isManagedRouteLine(line string, wanted []string) bool {
	fields := strings.Fields(line)
	if len(wanted) == 0 {
		return false
	}
	// With -N, iproute2 may render route types numerically: RTN_UNICAST (1)
	// is an otherwise implicit prefix, while RTN_LOCAL (2) replaces "local".
	if len(fields) > 0 && fields[0] == "1" && wanted[0] != "local" {
		fields = fields[1:]
	}
	if len(fields) < len(wanted) {
		return false
	}
	for index, token := range wanted {
		if fields[index] != token && (index != 0 || token != "local" || fields[index] != "2") {
			return false
		}
	}
	// The numeric protocol is one part of the ownership proof. Known display-only
	// attributes may vary by kernel, but metrics/nexthops remain foreign.
	owned := false
	remainder := fields[len(wanted):]
	for len(remainder) > 0 {
		if remainder[0] == "linkdown" {
			remainder = remainder[1:]
			continue
		}
		if len(remainder) < 2 {
			return false
		}
		switch remainder[0] {
		case "scope":
			if remainder[1] != "host" && remainder[1] != "254" &&
				remainder[1] != "link" && remainder[1] != "253" {
				return false
			}
		case "proto":
			if remainder[1] != strconv.Itoa(policyProtocol) {
				return false
			}
			owned = true
		default:
			return false
		}
		remainder = remainder[2:]
	}
	return owned
}
