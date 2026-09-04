package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kontsevoye/boxctl/internal/state"
)

const (
	SingBoxEngineName = "sing-box"

	SingBoxManagedTagPrefix           = "boxctl-"
	SingBoxTPROXYInboundTag           = "boxctl-tproxy-in"
	SingBoxTPROXYTCPInboundTag        = "boxctl-tproxy-tcp-in"
	SingBoxTPROXYUDPInboundTag        = "boxctl-tproxy-udp-in"
	SingBoxRedirectInboundTag         = "boxctl-redirect-in"
	SingBoxTUNInboundTag              = "boxctl-tun-in"
	SingBoxDNSInboundTag              = "boxctl-dns-in"
	SingBoxDefaultTUNAddress          = "172.19.0.1/30"
	SingBoxDefaultTUNMTU       uint32 = 1500
)

// SingBoxOptions controls native preparation, supervision and Clash API
// behavior. ClashAPIAllowedOrigins must contain exact http(s) origins; wildcard
// origins are rejected. The loopback origin default keeps the core controller
// private when boxctl proxies dashboard requests.
type SingBoxOptions struct {
	HTTPClient             *http.Client
	StopTimeout            time.Duration
	LogBuffer              int
	ProcessStatePath       string
	ClashAPIAllowedOrigins []string
}

// SingBoxDriver implements Config, Runtime and Control for a native sing-box
// profile. The user source is never rewritten: candidate sing-box normalizes
// JSONC into a private runtime document before boxctl applies its owned patch.
type SingBoxDriver struct {
	httpClient     *http.Client
	allowedOrigins []string
	supervisor     *externalProcessSupervisor
}

func NewSingBoxDriver(options SingBoxOptions) *SingBoxDriver {
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	driver := &SingBoxDriver{
		httpClient:     httpClient,
		allowedOrigins: append([]string(nil), options.ClashAPIAllowedOrigins...),
	}
	driver.supervisor = newExternalProcessSupervisor(externalProcessSupervisorOptions{
		Engine: SingBoxEngineName, DisplayName: "sing-box",
		ProcessStatePath: options.ProcessStatePath, StopTimeout: options.StopTimeout, LogBuffer: options.LogBuffer,
		DefaultArgs: func(prepared PreparedCore) []string {
			return []string{"run", "-D", prepared.HomeDir, "-c", prepared.RuntimeConfigPath}
		},
		Validate: driver.Validate, ValidatePrepared: validatePreparedSingBox,
		Cleanup: CleanupPreparedRuntime, LogPump: driver.controllerLogPump,
	})
	return driver
}

func (d *SingBoxDriver) Capabilities() Capabilities { return singBoxCapabilities }

func (d *SingBoxDriver) Prepare(ctx context.Context, request PrepareRequest) (PreparedCore, error) {
	if err := ctx.Err(); err != nil {
		return PreparedCore{}, err
	}
	if err := verifyExecutable(request.BinaryPath); err != nil {
		return PreparedCore{}, err
	}
	if request.SourceConfigPath == "" {
		return PreparedCore{}, errors.New("sing-box source config path is required")
	}
	if request.RuntimeDir == "" {
		return PreparedCore{}, errors.New("sing-box runtime base directory is required")
	}
	sourcePath, err := filepath.Abs(request.SourceConfigPath)
	if err != nil {
		return PreparedCore{}, fmt.Errorf("resolve sing-box source config: %w", err)
	}
	if err := validateRegularFile(sourcePath, "sing-box source config"); err != nil {
		return PreparedCore{}, err
	}
	runtimeBase, err := filepath.Abs(request.RuntimeDir)
	if err != nil {
		return PreparedCore{}, fmt.Errorf("resolve sing-box runtime base directory: %w", err)
	}
	if err := validateExistingDirectory(runtimeBase, "sing-box runtime base"); err != nil {
		return PreparedCore{}, err
	}
	if err := request.Capture.Validate(); err != nil {
		return PreparedCore{}, fmt.Errorf("invalid sing-box capture plan: %w", err)
	}

	request.Capture.Capabilities = singBoxCapabilities
	if request.Capture.LoopMark == 0 {
		request.Capture.LoopMark = 2
	}
	usesTUN := request.Capture.TCP.Method == CaptureTUN || request.Capture.UDP.Method == CaptureTUN
	if usesTUN {
		if request.Capture.TUNStack == "" {
			request.Capture.TUNStack = "system"
		}
		if len(request.Capture.TUNAddresses) == 0 {
			request.Capture.TUNAddresses = []netip.Prefix{netip.MustParsePrefix(SingBoxDefaultTUNAddress)}
		}
		if request.Capture.TUNMTU == 0 {
			request.Capture.TUNMTU = SingBoxDefaultTUNMTU
		}
	}
	home := request.HomeDir
	if home == "" {
		home = filepath.Dir(sourcePath)
	}
	home, err = filepath.Abs(home)
	if err != nil {
		return PreparedCore{}, fmt.Errorf("resolve sing-box working directory: %w", err)
	}
	if err := validateExistingDirectory(home, "sing-box working directory"); err != nil {
		return PreparedCore{}, err
	}
	controller, err := normalizeSingBoxController(request.Controller)
	if err != nil {
		return PreparedCore{}, err
	}
	allowedOrigins, err := normalizeSingBoxAllowedOrigins(d.allowedOrigins)
	if err != nil {
		return PreparedCore{}, err
	}

	runtimeRoot, err := createSingBoxRuntimeRoot(runtimeBase)
	if err != nil {
		return PreparedCore{}, err
	}
	runtimePath := filepath.Join(runtimeRoot, "sing-box-runtime.json")
	prepared := PreparedCore{
		Engine: SingBoxEngineName, BinaryPath: request.BinaryPath,
		SourceConfigPath: sourcePath, RuntimeConfigPath: runtimePath, HomeDir: home,
		Args:    []string{"run", "-D", home, "-c", runtimePath},
		Capture: request.Capture, Controller: controller, Capabilities: singBoxCapabilities,
		runtimeConfigRoot: runtimeRoot, runtimeConfigOwnedPath: runtimePath,
	}
	if err := precreatePrivateRuntime(runtimePath); err != nil {
		CleanupPreparedRuntime(prepared)
		return PreparedCore{}, err
	}
	mergeArgs := []string{"merge", runtimePath, "-D", home, "-c", sourcePath}
	output, err := runCommandGroup(ctx, request.BinaryPath, mergeArgs, prepared.Env)
	if err != nil {
		CleanupPreparedRuntime(prepared)
		return PreparedCore{}, fmt.Errorf("sing-box config merge failed: %w: %s", err, strings.TrimSpace(output))
	}
	if err := validatePrivateRuntimeFile(runtimePath); err != nil {
		CleanupPreparedRuntime(prepared)
		return PreparedCore{}, err
	}
	document, err := decodeSingBoxRuntime(runtimePath)
	if err != nil {
		CleanupPreparedRuntime(prepared)
		return PreparedCore{}, err
	}
	if err := patchSingBoxRuntime(document, request.Capture, controller, allowedOrigins); err != nil {
		CleanupPreparedRuntime(prepared)
		return PreparedCore{}, err
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		CleanupPreparedRuntime(prepared)
		return PreparedCore{}, fmt.Errorf("encode managed sing-box runtime: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := state.WriteFileAtomic(runtimePath, encoded, 0o600); err != nil {
		CleanupPreparedRuntime(prepared)
		return PreparedCore{}, fmt.Errorf("write managed sing-box runtime: %w", err)
	}
	if err := d.Validate(ctx, prepared); err != nil {
		CleanupPreparedRuntime(prepared)
		return PreparedCore{}, err
	}
	return prepared, nil
}

func (d *SingBoxDriver) Validate(ctx context.Context, prepared PreparedCore) error {
	if err := validatePreparedSingBox(prepared); err != nil {
		return err
	}
	args := []string{"check", "-D", prepared.HomeDir, "-c", prepared.RuntimeConfigPath}
	output, err := runCommandGroup(ctx, prepared.BinaryPath, args, prepared.Env)
	if err != nil {
		return fmt.Errorf("sing-box config validation failed: %w: %s", err, strings.TrimSpace(output))
	}
	return nil
}

func validatePreparedSingBox(prepared PreparedCore) error {
	if prepared.Engine != SingBoxEngineName {
		return fmt.Errorf("prepared core is %q, not sing-box", prepared.Engine)
	}
	if err := verifyExecutable(prepared.BinaryPath); err != nil {
		return err
	}
	if prepared.RuntimeConfigPath == "" || prepared.HomeDir == "" {
		return errors.New("prepared sing-box core lacks runtime config or working directory")
	}
	if !runtimeFileOwnedBy(prepared, "sing-box-", ".json") {
		return errors.New("prepared sing-box runtime config lacks private ownership")
	}
	rootInfo, err := os.Lstat(prepared.runtimeConfigRoot)
	if err != nil {
		return fmt.Errorf("stat sing-box runtime root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o700 {
		return errors.New("sing-box runtime root is not a private directory")
	}
	return validatePrivateRuntimeFile(prepared.RuntimeConfigPath)
}

func createSingBoxRuntimeRoot(base string) (string, error) {
	root, err := os.MkdirTemp(base, "boxctl-sing-box-")
	if err != nil {
		return "", fmt.Errorf("create private sing-box runtime directory: %w", err)
	}
	//nolint:gosec // 0700 is intentionally required for owner-only directory traversal
	if err := os.Chmod(root, 0o700); err != nil {
		_ = os.Remove(root)
		return "", fmt.Errorf("protect sing-box runtime directory: %w", err)
	}
	return root, nil
}

func precreatePrivateRuntime(path string) error {
	//nolint:gosec // path is inside a fresh manager-owned 0700 runtime root
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("precreate private sing-box runtime: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close private sing-box runtime: %w", err)
	}
	return nil
}

func validatePrivateRuntimeFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat sing-box runtime config: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("sing-box runtime config is not a private regular file")
	}
	return nil
}

func validateRegularFile(path, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular non-symlink file", label)
	}
	return nil
}

func validateExistingDirectory(path, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s must be an existing non-symlink directory", label)
	}
	return nil
}

func decodeSingBoxRuntime(path string) (map[string]any, error) {
	//nolint:gosec // path is the exact manager-owned runtime produced by candidate merge
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open normalized sing-box runtime: %w", err)
	}
	defer file.Close()
	limited := io.LimitReader(file, maxControllerResponse+1)
	content, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read normalized sing-box runtime: %w", err)
	}
	if len(content) > maxControllerResponse {
		return nil, errors.New("normalized sing-box runtime exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode normalized sing-box runtime: %w", err)
	}
	if document == nil {
		return nil, errors.New("normalized sing-box runtime must be a JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode normalized sing-box runtime: trailing data")
	}
	return document, nil
}

func normalizeSingBoxController(endpoint ControllerEndpoint) (ControllerEndpoint, error) {
	if endpoint.Listen == "" {
		endpoint.Listen = "127.0.0.1:9090"
	}
	if strings.ContainsAny(endpoint.Listen, "\r\n") || strings.ContainsAny(endpoint.Secret, "\r\n") {
		return ControllerEndpoint{}, errors.New("sing-box controller settings contain a newline")
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(endpoint.Listen))
	if err != nil {
		return ControllerEndpoint{}, fmt.Errorf("parse sing-box controller listen address: %w", err)
	}
	if _, err := parsePort(port); err != nil {
		return ControllerEndpoint{}, fmt.Errorf("parse sing-box controller listen port: %w", err)
	}
	endpoint.Listen = net.JoinHostPort("127.0.0.1", port)
	if endpoint.BaseURL == "" {
		endpoint.BaseURL = "http://" + endpoint.Listen
	}
	if _, err := NewSingBoxController(endpoint, nil); err != nil {
		return ControllerEndpoint{}, err
	}
	return endpoint, nil
}

func normalizeSingBoxAllowedOrigins(origins []string) ([]string, error) {
	if len(origins) == 0 {
		origins = []string{"http://127.0.0.1"}
	}
	seen := make(map[string]struct{}, len(origins))
	result := make([]string, 0, len(origins))
	for _, raw := range origins {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.ContainsAny(raw, "*\r\n") {
			return nil, fmt.Errorf("invalid sing-box Clash API origin %q", raw)
		}
		parsed, err := url.Parse(raw)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
			parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("invalid sing-box Clash API origin %q", raw)
		}
		normalized := strings.ToLower(parsed.Scheme) + "://" + parsed.Host
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	sort.Strings(result)
	return result, nil
}

func patchSingBoxRuntime(document map[string]any, capture CapturePlan, controller ControllerEndpoint, allowedOrigins []string) error {
	managedInbounds, err := singBoxManagedInbounds(capture)
	if err != nil {
		return err
	}
	if err := validateSingBoxCollisions(document, managedInbounds, capture, controller); err != nil {
		return err
	}

	existingInbounds, err := optionalObjectArray(document, "inbounds", "sing-box inbounds")
	if err != nil {
		return err
	}
	for _, inbound := range managedInbounds {
		existingInbounds = append(existingInbounds, inbound)
	}
	document["inbounds"] = existingInbounds

	route, err := optionalObject(document, "route", "sing-box route")
	if err != nil {
		return err
	}
	route["default_mark"] = fmt.Sprintf("0x%x", capture.LoopMark)
	if capture.DNS.Enabled {
		rules, err := optionalObjectArray(route, "rules", "sing-box route rules")
		if err != nil {
			return err
		}
		dnsRule := map[string]any{
			"inbound": []any{SingBoxDNSInboundTag},
			"action":  "hijack-dns",
		}
		route["rules"] = append([]any{dnsRule}, rules...)
	}
	document["route"] = route

	experimental, err := optionalObject(document, "experimental", "sing-box experimental config")
	if err != nil {
		return err
	}
	experimental["clash_api"] = map[string]any{
		"external_controller":                  controller.Listen,
		"secret":                               controller.Secret,
		"access_control_allow_origin":          stringSliceAsAny(allowedOrigins),
		"access_control_allow_private_network": false,
	}
	document["experimental"] = experimental
	return nil
}

func singBoxManagedInbounds(capture CapturePlan) ([]map[string]any, error) {
	listenInbound := func(kind, tag, network string, port uint16) map[string]any {
		inbound := map[string]any{
			"type": kind, "tag": tag, "listen": "0.0.0.0", "listen_port": port,
		}
		if network != "" {
			inbound["network"] = network
		}
		return inbound
	}
	var inbounds []map[string]any
	switch {
	case capture.TCP.Method == CaptureTPROXY && capture.UDP.Method == CaptureTPROXY:
		if capture.TCP.Port == capture.UDP.Port {
			inbounds = append(inbounds, listenInbound("tproxy", SingBoxTPROXYInboundTag, "", capture.TCP.Port))
		} else {
			inbounds = append(inbounds,
				listenInbound("tproxy", SingBoxTPROXYTCPInboundTag, "tcp", capture.TCP.Port),
				listenInbound("tproxy", SingBoxTPROXYUDPInboundTag, "udp", capture.UDP.Port),
			)
		}
	case capture.TCP.Method == CaptureRedirect && capture.UDP.Method == CaptureTPROXY:
		inbounds = append(inbounds,
			listenInbound("redirect", SingBoxRedirectInboundTag, "", capture.TCP.Port),
			listenInbound("tproxy", SingBoxTPROXYUDPInboundTag, "udp", capture.UDP.Port),
		)
	case capture.TCP.Method == CaptureTUN && capture.UDP.Method == CaptureTUN:
		inbounds = append(inbounds, singBoxTUNInbound(capture))
	case capture.TCP.Method == CaptureTPROXY && capture.UDP.Method == CaptureTUN:
		inbounds = append(inbounds,
			listenInbound("tproxy", SingBoxTPROXYTCPInboundTag, "tcp", capture.TCP.Port),
			singBoxTUNInbound(capture),
		)
	case capture.TCP.Method == CaptureRedirect && capture.UDP.Method == CaptureTUN:
		inbounds = append(inbounds,
			listenInbound("redirect", SingBoxRedirectInboundTag, "", capture.TCP.Port),
			singBoxTUNInbound(capture),
		)
	default:
		return nil, fmt.Errorf("%w: sing-box does not support TCP=%s UDP=%s", ErrUnsupported, capture.TCP.Method, capture.UDP.Method)
	}
	if capture.DNS.Enabled {
		host := capture.DNS.Host
		if host == "" {
			host = "0.0.0.0"
		}
		inbounds = append(inbounds, map[string]any{
			"type": "direct", "tag": SingBoxDNSInboundTag,
			"listen": host, "listen_port": capture.DNS.Port,
		})
	}
	return inbounds, nil
}

func singBoxTUNInbound(capture CapturePlan) map[string]any {
	addresses := make([]any, 0, len(capture.TUNAddresses))
	for _, prefix := range capture.TUNAddresses {
		addresses = append(addresses, prefix.String())
	}
	return map[string]any{
		"type": "tun", "tag": SingBoxTUNInboundTag,
		"interface_name": capture.TUNDevice,
		"address":        addresses,
		"mtu":            capture.TUNMTU,
		"stack":          capture.TUNStack,
		"dns_mode":       "disabled",
		"auto_route":     false,
		"auto_redirect":  false,
	}
}

func validateSingBoxCollisions(document map[string]any, managed []map[string]any, capture CapturePlan, controller ControllerEndpoint) error {
	managerPorts := make(map[uint16]string)
	controllerPort, err := controllerListenPort(controller.Listen)
	if err != nil {
		return err
	}
	managerPorts[controllerPort] = "Clash API controller"
	for _, inbound := range managed {
		port, present, err := objectPort(inbound, "listen_port")
		if err != nil {
			return err
		}
		if !present {
			continue
		}
		tag, _ := inbound["tag"].(string)
		if previous, exists := managerPorts[port]; exists {
			return fmt.Errorf("sing-box manager listener port %d is shared by %s and %s", port, previous, tag)
		}
		managerPorts[port] = tag
	}

	inbounds, err := optionalObjectArray(document, "inbounds", "sing-box inbounds")
	if err != nil {
		return err
	}
	if err := rejectReservedTags(inbounds, "inbound"); err != nil {
		return err
	}
	for index, value := range inbounds {
		inbound, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("sing-box inbound %d is not an object", index)
		}
		kind, _ := inbound["type"].(string)
		switch strings.ToLower(kind) {
		case "tproxy", "redirect", "tun":
			return fmt.Errorf("sing-box profile inbound %d uses manager-owned capture type %q", index, kind)
		}
		port, present, err := objectPort(inbound, "listen_port")
		if err != nil {
			return fmt.Errorf("sing-box inbound %d: %w", index, err)
		}
		if present {
			if owner, collision := managerPorts[port]; collision {
				return fmt.Errorf("sing-box profile inbound %d collides with managed %s on port %d", index, owner, port)
			}
		}
	}

	for _, collection := range []struct {
		container map[string]any
		key       string
		label     string
	}{
		{document, "outbounds", "outbound"},
		{document, "endpoints", "endpoint"},
	} {
		items, err := optionalObjectArray(collection.container, collection.key, "sing-box "+collection.key)
		if err != nil {
			return err
		}
		if err := rejectReservedTags(items, collection.label); err != nil {
			return err
		}
	}

	route, err := optionalObject(document, "route", "sing-box route")
	if err != nil {
		return err
	}
	if _, exists := route["default_mark"]; exists {
		return errors.New("sing-box profile route.default_mark is manager-owned")
	}
	ruleSets, err := optionalObjectArray(route, "rule_set", "sing-box route rule_set")
	if err != nil {
		return err
	}
	if err := rejectReservedTags(ruleSets, "rule set"); err != nil {
		return err
	}

	dns, err := optionalObject(document, "dns", "sing-box DNS config")
	if err != nil {
		return err
	}
	dnsServers, err := optionalObjectArray(dns, "servers", "sing-box DNS servers")
	if err != nil {
		return err
	}
	if err := rejectReservedTags(dnsServers, "DNS server"); err != nil {
		return err
	}
	// DialerOptions are embedded in many sing-box 1.14 objects, including
	// nested HTTP clients. Any explicit routing_mark overrides route.default_mark,
	// so every occurrence must obey the manager's loop-prevention contract.
	if err := validateSingBoxRoutingMarks(document, "config", capture.LoopMark); err != nil {
		return err
	}

	experimental, err := optionalObject(document, "experimental", "sing-box experimental config")
	if err != nil {
		return err
	}
	if _, exists := experimental["clash_api"]; exists {
		return errors.New("sing-box profile experimental.clash_api is manager-owned")
	}
	return nil
}

func validateSingBoxRoutingMarks(value any, path string, loopMark uint32) error {
	switch typed := value.(type) {
	case map[string]any:
		if rawMark, exists := typed["routing_mark"]; exists {
			markPath := path + ".routing_mark"
			mark, err := parseFirewallMark(rawMark)
			if err != nil {
				return fmt.Errorf("sing-box %s: %w", markPath, err)
			}
			if mark != loopMark {
				return fmt.Errorf("sing-box %s %#x conflicts with managed default_mark %#x", markPath, mark, loopMark)
			}
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			if key != "routing_mark" {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			if err := validateSingBoxRoutingMarks(typed[key], path+"."+key, loopMark); err != nil {
				return err
			}
		}
	case []any:
		for index, item := range typed {
			if err := validateSingBoxRoutingMarks(item, fmt.Sprintf("%s[%d]", path, index), loopMark); err != nil {
				return err
			}
		}
	}
	return nil
}

func optionalObject(container map[string]any, key, label string) (map[string]any, error) {
	value, exists := container[key]
	if !exists || value == nil {
		return make(map[string]any), nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	return object, nil
}

func optionalObjectArray(container map[string]any, key, label string) ([]any, error) {
	value, exists := container[key]
	if !exists || value == nil {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", label)
	}
	return append([]any(nil), items...), nil
}

func rejectReservedTags(items []any, label string) error {
	for index, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("sing-box %s %d is not an object", label, index)
		}
		tag, _ := object["tag"].(string)
		if strings.HasPrefix(tag, SingBoxManagedTagPrefix) {
			return fmt.Errorf("sing-box %s tag %q uses reserved prefix %q", label, tag, SingBoxManagedTagPrefix)
		}
	}
	return nil
}

func objectPort(object map[string]any, key string) (uint16, bool, error) {
	value, exists := object[key]
	if !exists || value == nil {
		return 0, false, nil
	}
	switch typed := value.(type) {
	case json.Number:
		port, err := parsePort(typed.String())
		return port, true, err
	case uint16:
		if typed == 0 {
			return 0, true, errors.New("listener port must be positive")
		}
		return typed, true, nil
	case uint32:
		if typed == 0 || typed > 65535 {
			return 0, true, errors.New("listener port is out of range")
		}
		return uint16(typed), true, nil
	case int:
		return portFromInt64(int64(typed))
	case float64:
		if typed != float64(int64(typed)) {
			return 0, true, errors.New("listener port must be an integer")
		}
		return portFromInt64(int64(typed))
	default:
		return 0, true, errors.New("listener port must be a number")
	}
}

func portFromInt64(value int64) (uint16, bool, error) {
	if value <= 0 || value > 65535 {
		return 0, true, errors.New("listener port is out of range")
	}
	return uint16(value), true, nil
}

func parsePort(value string) (uint16, error) {
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil || parsed == 0 {
		return 0, errors.New("listener port is out of range")
	}
	return uint16(parsed), nil
}

func controllerListenPort(listen string) (uint16, error) {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return 0, fmt.Errorf("parse managed sing-box controller: %w", err)
	}
	return parsePort(port)
}

func parseFirewallMark(value any) (uint32, error) {
	var raw string
	switch typed := value.(type) {
	case json.Number:
		raw = typed.String()
	case string:
		raw = typed
	case uint32:
		return typed, nil
	case int:
		if typed < 0 || uint64(typed) > uint64(^uint32(0)) {
			return 0, errors.New("mark must be unsigned")
		}
		return uint32(typed), nil
	default:
		return 0, errors.New("mark must be a number or string")
	}
	parsed, err := strconv.ParseUint(raw, 0, 32)
	if err != nil {
		return 0, errors.New("mark is invalid")
	}
	return uint32(parsed), nil
}

func stringSliceAsAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func (d *SingBoxDriver) Start(ctx context.Context, prepared PreparedCore) error {
	return d.supervisor.Start(ctx, prepared)
}

func (d *SingBoxDriver) Stop(ctx context.Context) error { return d.supervisor.Stop(ctx) }

func (d *SingBoxDriver) Reload(context.Context, PreparedCore) error {
	return unsupported(CapabilityHotReload)
}

func (d *SingBoxDriver) Adopt(ctx context.Context) (PreparedCore, HealthStatus, error) {
	prepared, err := d.supervisor.Adopt(ctx)
	if err != nil {
		return PreparedCore{}, HealthStatus{}, err
	}
	health, healthErr := d.Health(ctx)
	if healthErr != nil {
		d.supervisor.emitLog("supervisor", "adopted sing-box readiness check: "+healthErr.Error())
	}
	return prepared, health, nil
}

func (d *SingBoxDriver) Health(ctx context.Context) (HealthStatus, error) {
	now := time.Now().UTC()
	pid, identity, prepared, startedAt, lastExit := d.supervisor.snapshot()
	status := HealthStatus{CheckedAt: now, StartedAt: startedAt, LastExitError: lastExit}
	if pid == 0 || (identity != "" && !persistedProcessAlive(pid, identity)) {
		return status, nil
	}
	status.Running = true
	status.PID = pid
	controller, err := NewSingBoxController(prepared.Controller, d.httpClient)
	if err != nil {
		return status, err
	}
	version, err := controller.Version(ctx)
	if err != nil {
		return status, err
	}
	status.ControllerReady = true
	status.Version = version
	if prepared.Capture.DNS.Enabled {
		if err := ProbeDNS(ctx, prepared.Capture.DNS); err != nil {
			return status, fmt.Errorf("probe sing-box DNS listener: %w", err)
		}
		status.DNSReady = true
	}
	return status, nil
}

func (d *SingBoxDriver) Version(ctx context.Context, binaryPath string) (string, error) {
	if err := verifyExecutable(binaryPath); err != nil {
		return "", err
	}
	output, err := runCommandGroup(ctx, binaryPath, []string{"version"}, nil)
	if err != nil {
		return "", fmt.Errorf("read sing-box version: %w: %s", err, strings.TrimSpace(output))
	}
	version := strings.TrimSpace(output)
	if version == "" {
		return "", errors.New("sing-box returned an empty version")
	}
	return version, nil
}

func (d *SingBoxDriver) Logs() <-chan LogEntry { return d.supervisor.Logs() }

func (d *SingBoxDriver) controllerLogPump(ctx context.Context, prepared PreparedCore, emit func(string, string)) {
	for {
		if ctx.Err() != nil {
			return
		}
		controller, err := NewSingBoxController(prepared.Controller, d.httpClient)
		if err == nil {
			var stream <-chan SingBoxLog
			stream, err = controller.StreamLogs(ctx)
			if err == nil {
				for entry := range stream {
					emitControllerLog(ctx, entry, emit)
					if ctx.Err() != nil {
						return
					}
				}
			}
		}
		if !waitLogReconnect(ctx) {
			return
		}
	}
}

func (d *SingBoxDriver) controller(capability Capability) (*SingBoxController, error) {
	pid, _, prepared, _, _ := d.supervisor.snapshot()
	if pid == 0 {
		return nil, ErrNotRunning
	}
	if !prepared.Capabilities.Supports(capability) {
		return nil, unsupported(capability)
	}
	return NewSingBoxController(prepared.Controller, d.httpClient)
}

func (d *SingBoxDriver) ActiveControllerEndpoint() (ControllerEndpoint, error) {
	return d.supervisor.ActiveControllerEndpoint()
}

func (d *SingBoxDriver) Proxies(ctx context.Context) ([]Proxy, error) {
	controller, err := d.controller(CapabilityProxies)
	if err != nil {
		return nil, err
	}
	return controller.Proxies(ctx)
}

func (d *SingBoxDriver) Groups(ctx context.Context) ([]ProxyGroup, error) {
	controller, err := d.controller(CapabilityGroups)
	if err != nil {
		return nil, err
	}
	return controller.Groups(ctx)
}

func (d *SingBoxDriver) Select(ctx context.Context, group, proxy string) error {
	controller, err := d.controller(CapabilitySelection)
	if err != nil {
		return err
	}
	return controller.Select(ctx, group, proxy)
}

func (d *SingBoxDriver) Delay(ctx context.Context, proxy, testURL string, timeout time.Duration) (time.Duration, error) {
	controller, err := d.controller(CapabilityDelay)
	if err != nil {
		return 0, err
	}
	return controller.Delay(ctx, proxy, testURL, timeout)
}

func (d *SingBoxDriver) Providers(_ context.Context, kind ProviderKind) ([]Provider, error) {
	return nil, unsupported(providerCapability(kind))
}

func (d *SingBoxDriver) UpdateProvider(_ context.Context, kind ProviderKind, _ string) error {
	return unsupported(providerCapability(kind))
}

func (d *SingBoxDriver) Rules(ctx context.Context) ([]Rule, error) {
	controller, err := d.controller(CapabilityRules)
	if err != nil {
		return nil, err
	}
	return controller.Rules(ctx)
}

func (d *SingBoxDriver) Connections(ctx context.Context) (ConnectionsSnapshot, error) {
	controller, err := d.controller(CapabilityConnections)
	if err != nil {
		return ConnectionsSnapshot{}, err
	}
	return controller.Connections(ctx)
}

func (d *SingBoxDriver) StreamConnections(ctx context.Context, interval time.Duration) (<-chan ConnectionsSnapshot, error) {
	controller, err := d.controller(CapabilityConnections)
	if err != nil {
		return nil, err
	}
	return controller.StreamConnections(ctx, interval)
}

func (d *SingBoxDriver) CloseConnection(ctx context.Context, id string) error {
	controller, err := d.controller(CapabilityCloseConnection)
	if err != nil {
		return err
	}
	return controller.CloseConnection(ctx, id)
}

func (d *SingBoxDriver) CloseAllConnections(ctx context.Context) error {
	controller, err := d.controller(CapabilityCloseAllConnections)
	if err != nil {
		return err
	}
	return controller.CloseAllConnections(ctx)
}

func (*SingBoxDriver) RoutingMode(context.Context) (RoutingMode, error) {
	return "", unsupported(CapabilityRoutingMode)
}

func (*SingBoxDriver) SetRoutingMode(context.Context, RoutingMode) error {
	return unsupported(CapabilityRoutingMode)
}

func (d *SingBoxDriver) StreamTraffic(ctx context.Context) (<-chan TrafficSnapshot, error) {
	controller, err := d.controller(CapabilityTrafficStream)
	if err != nil {
		return nil, err
	}
	return controller.StreamTraffic(ctx)
}

var (
	_ Config  = (*SingBoxDriver)(nil)
	_ Runtime = (*SingBoxDriver)(nil)
	_ Control = (*SingBoxDriver)(nil)
)
