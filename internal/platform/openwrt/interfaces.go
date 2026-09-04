package openwrt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// InterfaceDiscovery maps OpenWrt logical firewall networks to concrete nft
// interface names. All commands used by DetectInterfaces are read-only.
type InterfaceDiscovery struct {
	LANNetworks   []string
	WANNetworks   []string
	LANInterfaces []string
	WANInterfaces []string
	AllInterfaces []string
	Source        string
}

// DetectInterfaces reads UCI network/firewall topology and resolves concrete
// devices with ubus. If ubus is unavailable it falls back to JSON ip output.
// Ambiguous topology is rejected instead of silently capturing a WAN device.
func DetectInterfaces(ctx context.Context, runner Runner) (InterfaceDiscovery, error) {
	if runner == nil {
		return InterfaceDiscovery{}, errors.New("openwrt: nil interface runner")
	}
	networkResult, err := runOK(ctx, runner, Command{Name: "uci", Args: []string{"-q", "export", "network"}})
	if err != nil {
		return InterfaceDiscovery{}, fmt.Errorf("openwrt: read network topology: %w", err)
	}
	firewallResult, err := runOK(ctx, runner, Command{Name: "uci", Args: []string{"-q", "export", "firewall"}})
	if err != nil {
		return InterfaceDiscovery{}, fmt.Errorf("openwrt: read firewall topology: %w", err)
	}
	devices, err := parseNetworkDevices(string(networkResult.Stdout))
	if err != nil {
		return InterfaceDiscovery{}, err
	}
	lanNetworks, wanNetworks, err := parseFirewallNetworks(string(firewallResult.Stdout))
	if err != nil {
		return InterfaceDiscovery{}, err
	}

	ubusResult, ubusErr := runner.Run(ctx, Command{Name: "ubus", Args: []string{"call", "network.interface", "dump"}})
	if ubusErr == nil && ubusResult.ExitCode == 0 {
		resolved, err := resolveUBusInterfaces(ubusResult.Stdout, lanNetworks, wanNetworks, devices)
		if err == nil {
			if links, linkErr := listIPLinks(ctx, runner); linkErr == nil {
				resolved.AllInterfaces = normalizeStrings(append(resolved.AllInterfaces, links...))
			}
			resolved.Source = "ubus"
			return resolved, nil
		}
		ubusErr = err
	} else if ubusErr == nil {
		ubusErr = fmt.Errorf("ubus exited with %d: %s", ubusResult.ExitCode, strings.TrimSpace(string(ubusResult.Stderr)))
	}

	resolved, fallbackErr := resolveIPInterfaces(ctx, runner, lanNetworks, wanNetworks, devices)
	if fallbackErr != nil {
		return InterfaceDiscovery{}, errors.Join(fmt.Errorf("openwrt: ubus interface discovery: %w", ubusErr), fallbackErr)
	}
	resolved.Source = "ip"
	return resolved, nil
}

type uciSection struct {
	sectionType string
	name        string
	options     map[string][]string
}

func parseUCISections(input string) ([]uciSection, error) {
	var sections []uciSection
	var current *uciSection
	for lineNumber, raw := range strings.Split(input, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "package ") {
			continue
		}
		words, err := parseUCIWords(line)
		if err != nil {
			return nil, fmt.Errorf("openwrt: parse UCI topology line %d: %w", lineNumber+1, err)
		}
		switch {
		case len(words) >= 2 && words[0] == "config":
			section := uciSection{sectionType: words[1], options: make(map[string][]string)}
			if len(words) >= 3 {
				section.name = words[2]
			}
			sections = append(sections, section)
			current = &sections[len(sections)-1]
		case current != nil && len(words) == 3 && (words[0] == "option" || words[0] == "list"):
			if words[0] == "option" {
				current.options[words[1]] = strings.Fields(words[2])
			} else {
				current.options[words[1]] = append(current.options[words[1]], words[2])
			}
		}
	}
	return sections, nil
}

func parseNetworkDevices(input string) (map[string]string, error) {
	sections, err := parseUCISections(input)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string)
	for _, section := range sections {
		if section.sectionType != "interface" || section.name == "" {
			continue
		}
		for _, key := range []string{"device", "ifname"} {
			if values := section.options[key]; len(values) > 0 && values[0] != "" {
				result[section.name] = strings.TrimPrefix(values[0], "@")
				break
			}
		}
	}
	return result, nil
}

func parseFirewallNetworks(input string) (lan, wan []string, returnErr error) {
	sections, err := parseUCISections(input)
	if err != nil {
		return nil, nil, err
	}
	for _, section := range sections {
		if section.sectionType != "zone" {
			continue
		}
		zoneNames := section.options["name"]
		if len(zoneNames) != 1 {
			continue
		}
		networks := section.options["network"]
		switch strings.ToLower(zoneNames[0]) {
		case "lan":
			lan = append(lan, networks...)
		case "wan":
			wan = append(wan, networks...)
		}
	}
	lan = normalizeStrings(lan)
	wan = normalizeStrings(wan)
	if len(lan) == 0 || len(wan) == 0 {
		return nil, nil, errors.New("openwrt: firewall must identify non-empty lan and wan networks")
	}
	for _, network := range lan {
		if slices.Contains(wan, network) {
			return nil, nil, fmt.Errorf("openwrt: network %q belongs to both lan and wan zones", network)
		}
	}
	return lan, wan, nil
}

type ubusInterfaceDump struct {
	Interfaces []struct {
		Name     string `json:"interface"`
		Device   string `json:"device"`
		L3Device string `json:"l3_device"`
	} `json:"interface"`
}

func resolveUBusInterfaces(data []byte, lanNetworks, wanNetworks []string, configured map[string]string) (InterfaceDiscovery, error) {
	var dump ubusInterfaceDump
	if err := json.Unmarshal(data, &dump); err != nil {
		return InterfaceDiscovery{}, fmt.Errorf("openwrt: parse ubus interface dump: %w", err)
	}
	resolved := make(map[string]string, len(dump.Interfaces)+len(configured))
	all := make([]string, 0, len(dump.Interfaces)+len(configured))
	for name, device := range configured {
		resolved[name] = device
		all = append(all, device)
	}
	for _, candidate := range dump.Interfaces {
		device := candidate.L3Device
		if device == "" {
			device = candidate.Device
		}
		if candidate.Name != "" && device != "" {
			resolved[candidate.Name] = device
			all = append(all, device)
		}
	}
	result, err := buildInterfaceDiscovery(lanNetworks, wanNetworks, resolved)
	result.AllInterfaces = normalizeInterfaceNames(all)
	return result, err
}

func buildInterfaceDiscovery(lanNetworks, wanNetworks []string, devices map[string]string) (InterfaceDiscovery, error) {
	result := InterfaceDiscovery{
		LANNetworks: append([]string(nil), lanNetworks...),
		WANNetworks: append([]string(nil), wanNetworks...),
	}
	for _, network := range lanNetworks {
		if device := devices[network]; device != "" {
			result.LANInterfaces = append(result.LANInterfaces, device)
		}
	}
	for _, network := range wanNetworks {
		if device := devices[network]; device != "" {
			result.WANInterfaces = append(result.WANInterfaces, device)
		}
	}
	result.LANInterfaces = normalizeStrings(result.LANInterfaces)
	result.WANInterfaces = normalizeStrings(result.WANInterfaces)
	if len(result.LANInterfaces) == 0 || len(result.WANInterfaces) == 0 {
		return InterfaceDiscovery{}, errors.New("openwrt: unable to resolve concrete lan and wan interfaces")
	}
	for _, device := range result.LANInterfaces {
		if slices.Contains(result.WANInterfaces, device) {
			return InterfaceDiscovery{}, fmt.Errorf("openwrt: device %q resolves as both lan and wan", device)
		}
	}
	return result, nil
}

type ipRoute struct {
	Destination string `json:"dst"`
	Device      string `json:"dev"`
}

type ipLink struct {
	Name string `json:"ifname"`
}

func resolveIPInterfaces(ctx context.Context, runner Runner, lanNetworks, wanNetworks []string, configured map[string]string) (InterfaceDiscovery, error) {
	routeResult, err := runOK(ctx, runner, Command{Name: "ip", Args: []string{"-j", "-4", "route", "show"}})
	if err != nil {
		return InterfaceDiscovery{}, fmt.Errorf("openwrt: fallback route discovery: %w", err)
	}
	linkResult, err := runOK(ctx, runner, Command{Name: "ip", Args: []string{"-j", "link", "show"}})
	if err != nil {
		return InterfaceDiscovery{}, fmt.Errorf("openwrt: fallback link discovery: %w", err)
	}
	var routes []ipRoute
	var links []ipLink
	if err := json.Unmarshal(routeResult.Stdout, &routes); err != nil {
		return InterfaceDiscovery{}, fmt.Errorf("openwrt: parse route JSON: %w", err)
	}
	if err := json.Unmarshal(linkResult.Stdout, &links); err != nil {
		return InterfaceDiscovery{}, fmt.Errorf("openwrt: parse link JSON: %w", err)
	}
	known := make(map[string]bool, len(links))
	for _, link := range links {
		known[link.Name] = true
	}
	resolved := make(map[string]string, len(configured))
	for network, device := range configured {
		if known[device] {
			resolved[network] = device
		}
	}
	for _, route := range routes {
		if route.Destination != "default" || !known[route.Device] {
			continue
		}
		for _, network := range wanNetworks {
			resolved[network] = route.Device
		}
		break
	}
	result, err := buildInterfaceDiscovery(lanNetworks, wanNetworks, resolved)
	all := make([]string, 0, len(links))
	for _, link := range links {
		all = append(all, link.Name)
	}
	result.AllInterfaces = normalizeInterfaceNames(all)
	return result, err
}

func listIPLinks(ctx context.Context, runner Runner) ([]string, error) {
	result, err := runOK(ctx, runner, Command{Name: "ip", Args: []string{"-j", "link", "show"}})
	if err != nil {
		return nil, err
	}
	var links []ipLink
	if err := json.Unmarshal(result.Stdout, &links); err != nil {
		return nil, fmt.Errorf("openwrt: parse link JSON: %w", err)
	}
	names := make([]string, 0, len(links))
	for _, link := range links {
		names = append(names, link.Name)
	}
	return normalizeInterfaceNames(names), nil
}

func normalizeInterfaceNames(values []string) []string {
	filtered := values[:0]
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || value == "lo" || strings.HasPrefix(value, "@") {
			continue
		}
		filtered = append(filtered, value)
	}
	return normalizeStrings(filtered)
}
