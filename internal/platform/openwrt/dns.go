package openwrt

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

const dnsBackupVersion = 1

type UCIOptionKind string

const (
	UCIOption UCIOptionKind = "option"
	UCIList   UCIOptionKind = "list"
)

type UCIOptionState struct {
	Present bool          `json:"present"`
	Kind    UCIOptionKind `json:"kind,omitempty"`
	Values  []string      `json:"values,omitempty"`
}

// DNSBackup preserves both option values and absence. It must be stored before
// the first DNS apply and reused until Restore succeeds.
type DNSBackup struct {
	Version int                       `json:"version"`
	Package string                    `json:"package"`
	Section string                    `json:"section"`
	Options map[string]UCIOptionState `json:"options"`
}

// DNSManager owns only three dnsmasq options. DNS redirect rules remain part
// of the ownership-marked GatewayPlan nft table.
type DNSManager struct {
	Runner  Runner
	Package string
	Section string
}

func NewDNSManager(runner Runner) DNSManager {
	return DNSManager{Runner: runner, Package: "dhcp", Section: "@dnsmasq[0]"}
}

var managedDNSOptions = []string{"cachesize", "noresolv", "server"}

func (manager DNSManager) normalized() DNSManager {
	if manager.Package == "" {
		manager.Package = "dhcp"
	}
	if manager.Section == "" {
		manager.Section = "@dnsmasq[0]"
	}
	return manager
}

// The compatibility contract currently owns only the first dnsmasq section.
// Reject alternate UCI paths instead of labelling data from one section as a
// backup of another or allowing control characters into a batch transaction.
func (manager DNSManager) validateTarget() error {
	if manager.Package != "dhcp" || manager.Section != "@dnsmasq[0]" {
		return fmt.Errorf("openwrt: unsupported DNS UCI target %q.%q", manager.Package, manager.Section)
	}
	return nil
}

// Backup reads UCI export output so a one-element list remains distinguishable
// from an option. No UCI transaction is performed.
func (manager DNSManager) Backup(ctx context.Context) (DNSBackup, error) {
	manager = manager.normalized()
	if manager.Runner == nil {
		return DNSBackup{}, errors.New("openwrt: nil DNS runner")
	}
	if err := manager.validateTarget(); err != nil {
		return DNSBackup{}, err
	}
	result, err := runOK(ctx, manager.Runner, Command{Name: "uci", Args: []string{"-q", "export", manager.Package}})
	if err != nil {
		return DNSBackup{}, err
	}
	options, err := parseFirstUCISection(string(result.Stdout), "dnsmasq", managedDNSOptions)
	if err != nil {
		return DNSBackup{}, err
	}
	return DNSBackup{
		Version: dnsBackupVersion,
		Package: manager.Package,
		Section: manager.Section,
		Options: options,
	}, nil
}

// Apply applies the requested UCI side of a DNS mode. DNSUpstream owns the
// upstream options; DNSRedirect and DNSDisabled restore their exact backup.
func (manager DNSManager) Apply(ctx context.Context, plan GatewayPlan, backup DNSBackup) error {
	manager = manager.normalized()
	if err := manager.validateTarget(); err != nil {
		return err
	}
	plan = normalizedPlan(plan)
	if err := Validate(plan); err != nil {
		return err
	}
	if err := validateDNSBackup(backup, manager); err != nil {
		return err
	}
	switch plan.DNSMode {
	case DNSUpstream:
		return manager.applyOptions(ctx, desiredUpstreamOptions(plan), false)
	case DNSRedirect, DNSDisabled:
		return manager.applyOptions(ctx, backup.Options, false)
	default:
		return fmt.Errorf("openwrt: unsupported DNS mode %q", plan.DNSMode)
	}
}

// Reconcile is idempotent: dnsmasq is restarted only when the managed option
// states differ from the requested state.
func (manager DNSManager) Reconcile(ctx context.Context, plan GatewayPlan, backup DNSBackup) error {
	manager = manager.normalized()
	if err := manager.validateTarget(); err != nil {
		return err
	}
	plan = normalizedPlan(plan)
	if err := Validate(plan); err != nil {
		return err
	}
	if err := validateDNSBackup(backup, manager); err != nil {
		return err
	}
	current, err := manager.Backup(ctx)
	if err != nil {
		return err
	}
	desired := backup.Options
	if plan.DNSMode == DNSUpstream {
		desired = desiredUpstreamOptions(plan)
	}
	if equalOptionStates(current.Options, desired) {
		return nil
	}
	return manager.applyOptions(ctx, desired, false)
}

// Restore reinstates scalar/list values and deletes options which were absent.
// It always restarts dnsmasq: matching UCI state can mean a previous restore
// committed successfully but its runtime restart failed. Callers must retain
// the durable backup until this method returns success.
func (manager DNSManager) Restore(ctx context.Context, backup DNSBackup) error {
	manager = manager.normalized()
	if err := manager.validateTarget(); err != nil {
		return err
	}
	if err := validateDNSBackup(backup, manager); err != nil {
		return err
	}
	return manager.applyOptions(ctx, backup.Options, true)
}

func desiredUpstreamOptions(plan GatewayPlan) map[string]UCIOptionState {
	return map[string]UCIOptionState{
		"server": {
			Present: true,
			Kind:    UCIList,
			Values:  []string{fmt.Sprintf("127.0.0.1#%d", plan.DNSPort)},
		},
		"noresolv":  {Present: true, Kind: UCIOption, Values: []string{"1"}},
		"cachesize": {Present: true, Kind: UCIOption, Values: []string{"0"}},
	}
}

func validateDNSBackup(backup DNSBackup, manager DNSManager) error {
	if backup.Version != dnsBackupVersion {
		return fmt.Errorf("openwrt: unsupported DNS backup version %d", backup.Version)
	}
	if backup.Package != manager.Package || backup.Section != manager.Section {
		return errors.New("openwrt: DNS backup belongs to another UCI section")
	}
	for _, name := range managedDNSOptions {
		state, ok := backup.Options[name]
		if !ok {
			return fmt.Errorf("openwrt: DNS backup lacks %s presence metadata", name)
		}
		if !state.Present {
			if state.Kind != "" || len(state.Values) != 0 {
				return fmt.Errorf("openwrt: absent DNS option %s contains data", name)
			}
			continue
		}
		if state.Kind != UCIOption && state.Kind != UCIList {
			return fmt.Errorf("openwrt: invalid UCI kind for %s", name)
		}
		if len(state.Values) == 0 || (state.Kind == UCIOption && len(state.Values) != 1) {
			return fmt.Errorf("openwrt: invalid values for %s", name)
		}
	}
	return nil
}

func (manager DNSManager) applyOptions(ctx context.Context, options map[string]UCIOptionState, restartIfUnchanged bool) error {
	current, err := manager.Backup(ctx)
	if err != nil {
		return err
	}
	unchanged := equalOptionStates(current.Options, options)
	if unchanged && !restartIfUnchanged {
		return nil
	}
	if !unchanged {
		var batch strings.Builder
		for _, name := range managedDNSOptions {
			state, ok := options[name]
			if !ok {
				return fmt.Errorf("openwrt: requested DNS state lacks %s", name)
			}
			path := manager.Package + "." + manager.Section + "." + name
			if current.Options[name].Present {
				fmt.Fprintf(&batch, "delete %s\n", path)
			}
			if !state.Present {
				continue
			}
			switch state.Kind {
			case UCIOption:
				fmt.Fprintf(&batch, "set %s=%s\n", path, quoteUCI(state.Values[0]))
			case UCIList:
				for _, value := range state.Values {
					fmt.Fprintf(&batch, "add_list %s=%s\n", path, quoteUCI(value))
				}
			default:
				return fmt.Errorf("openwrt: invalid UCI kind for %s", name)
			}
		}
		fmt.Fprintf(&batch, "commit %s\n", manager.Package)
		if _, err := runOK(ctx, manager.Runner, Command{Name: "uci", Args: []string{"-q", "batch"}, Stdin: []byte(batch.String())}); err != nil {
			return fmt.Errorf("openwrt: apply dnsmasq UCI: %w", err)
		}
	}
	if _, err := runOK(ctx, manager.Runner, Command{Name: "/etc/init.d/dnsmasq", Args: []string{"restart"}}); err != nil {
		return fmt.Errorf("openwrt: restart dnsmasq: %w", err)
	}
	return nil
}

func equalOptionStates(left, right map[string]UCIOptionState) bool {
	for _, name := range managedDNSOptions {
		a, aOK := left[name]
		b, bOK := right[name]
		if !aOK || !bOK || a.Present != b.Present || a.Kind != b.Kind || !slices.Equal(a.Values, b.Values) {
			return false
		}
	}
	return true
}

func quoteUCI(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func parseFirstUCISection(input, sectionType string, wanted []string) (map[string]UCIOptionState, error) {
	result := make(map[string]UCIOptionState, len(wanted))
	for _, name := range wanted {
		result[name] = UCIOptionState{}
	}
	inSection := false
	found := false
	for lineNumber, raw := range strings.Split(input, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "package ") {
			continue
		}
		words, err := parseUCIWords(line)
		if err != nil {
			return nil, fmt.Errorf("openwrt: parse UCI export line %d: %w", lineNumber+1, err)
		}
		if len(words) == 0 {
			continue
		}
		if words[0] == "config" {
			if inSection {
				break
			}
			inSection = len(words) >= 2 && words[1] == sectionType
			found = found || inSection
			continue
		}
		if !inSection || len(words) != 3 || (words[0] != string(UCIOption) && words[0] != string(UCIList)) || !slices.Contains(wanted, words[1]) {
			continue
		}
		name := words[1]
		kind := UCIOptionKind(words[0])
		state := result[name]
		if kind == UCIOption {
			if state.Present {
				return nil, fmt.Errorf("openwrt: duplicate UCI option %s", name)
			}
			result[name] = UCIOptionState{Present: true, Kind: kind, Values: []string{words[2]}}
			continue
		}
		if state.Present && state.Kind != UCIList {
			return nil, fmt.Errorf("openwrt: mixed option/list UCI state for %s", name)
		}
		state.Present = true
		state.Kind = UCIList
		state.Values = append(state.Values, words[2])
		result[name] = state
	}
	if !found {
		return nil, fmt.Errorf("openwrt: no config %s section in UCI export", sectionType)
	}
	return result, nil
}

// parseUCIWords implements the shell-like quoting emitted by `uci export`
// without evaluating substitutions or escapes in a shell.
func parseUCIWords(line string) ([]string, error) {
	var words []string
	var word strings.Builder
	quote := rune(0)
	escaped := false
	haveWord := false
	flush := func() {
		if haveWord {
			words = append(words, word.String())
			word.Reset()
			haveWord = false
		}
	}
	for _, current := range line {
		if escaped {
			word.WriteRune(current)
			haveWord = true
			escaped = false
			continue
		}
		if quote != 0 {
			if current == quote {
				quote = 0
				continue
			}
			if quote == '"' && current == '\\' {
				escaped = true
				continue
			}
			word.WriteRune(current)
			haveWord = true
			continue
		}
		switch {
		case current == '\'' || current == '"':
			quote = current
			haveWord = true
		case current == '\\':
			escaped = true
			haveWord = true
		case unicode.IsSpace(current):
			flush()
		default:
			word.WriteRune(current)
			haveWord = true
		}
	}
	if escaped || quote != 0 {
		return nil, errors.New("unterminated UCI quote or escape")
	}
	flush()
	return words, nil
}
