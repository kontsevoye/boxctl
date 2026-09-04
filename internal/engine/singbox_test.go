package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSingBoxPrepareUsesCandidateMergeAndAppliesPrivateManagerPatch(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	normalized := `{
  "log": {"level": "warn"},
  "inbounds": [{"type":"mixed","tag":"user-in","listen":"127.0.0.1","listen_port":8080}],
  "outbounds": [{"type":"direct","tag":"direct","routing_mark":"0x2"}],
  "route": {"rules":[{"action":"route","outbound":"direct"}]}
}`
	binary, commandRecord := writeFakeSingBox(t, directory, normalized)
	sourcePath := filepath.Join(directory, "profile.json")
	source := "{\n  // accepted by sing-box extended JSON\n  \"outbounds\": []\n}\n"
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	runtimeBase := filepath.Join(directory, "runtime")
	if err := os.Mkdir(runtimeBase, 0o700); err != nil {
		t.Fatal(err)
	}
	driver := NewSingBoxDriver(SingBoxOptions{
		ClashAPIAllowedOrigins: []string{"https://dashboard.test/", "http://127.0.0.1"},
	})
	prepared, err := driver.Prepare(context.Background(), PrepareRequest{
		BinaryPath: binary, SourceConfigPath: sourcePath, RuntimeDir: runtimeBase,
		Capture: CapturePlan{
			TCP:       ProtocolCapture{Method: CaptureRedirect, Port: 7893},
			UDP:       ProtocolCapture{Method: CaptureTUN},
			DNS:       DNSEndpoint{Enabled: true, Host: "0.0.0.0", Port: 7874},
			TUNDevice: "clash-tun", TUNStack: "system",
			TUNAddresses: []netip.Prefix{netip.MustParsePrefix("172.31.255.1/30")}, TUNMTU: 1400,
			LoopMark: 2,
		},
		Controller: ControllerEndpoint{Listen: "0.0.0.0:9090", Secret: "manager-secret"},
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	t.Cleanup(func() { CleanupPreparedRuntime(prepared) })
	if prepared.Engine != SingBoxEngineName || prepared.SourceConfigPath != sourcePath || prepared.RuntimeConfigPath == sourcePath {
		t.Fatalf("prepared core = %#v", prepared)
	}
	if prepared.Controller.Listen != "127.0.0.1:9090" || prepared.Controller.BaseURL != "http://127.0.0.1:9090" {
		t.Fatalf("controller = %#v", prepared.Controller)
	}
	if prepared.Capabilities.HotReload || prepared.Capabilities.ProxyProviders || prepared.Capabilities.RuleProviders || prepared.Capabilities.RoutingMode || !prepared.Capabilities.Connections {
		t.Fatalf("capabilities = %#v", prepared.Capabilities)
	}
	if got := prepared.Args; len(got) != 5 || got[0] != "run" || got[2] != prepared.HomeDir || got[4] != prepared.RuntimeConfigPath {
		t.Fatalf("launch args = %#v", got)
	}
	rootInfo, err := os.Lstat(filepath.Dir(prepared.RuntimeConfigPath))
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o700 || rootInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("runtime root info = %v, %v", rootInfo, err)
	}
	runtimeInfo, err := os.Lstat(prepared.RuntimeConfigPath)
	if err != nil || !runtimeInfo.Mode().IsRegular() || runtimeInfo.Mode().Perm() != 0o600 || runtimeInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("runtime info = %v, %v", runtimeInfo, err)
	}
	document, err := decodeSingBoxRuntime(prepared.RuntimeConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	route := document["route"].(map[string]any)
	if route["default_mark"] != "0x2" {
		t.Fatalf("route.default_mark = %#v", route["default_mark"])
	}
	rules := route["rules"].([]any)
	firstRule := rules[0].(map[string]any)
	if firstRule["action"] != "hijack-dns" || len(rules) != 2 {
		t.Fatalf("route rules = %#v", rules)
	}
	inbounds := indexObjectsByTag(t, document["inbounds"].([]any))
	if len(inbounds) != 4 || inbounds["user-in"]["type"] != "mixed" {
		t.Fatalf("inbounds = %#v", inbounds)
	}
	tun := inbounds[SingBoxTUNInboundTag]
	if tun["auto_route"] != false || tun["auto_redirect"] != false || tun["dns_mode"] != "disabled" || tun["stack"] != "system" {
		t.Fatalf("managed TUN = %#v", tun)
	}
	if got := tun["address"].([]any); len(got) != 1 || got[0] != "172.31.255.1/30" {
		t.Fatalf("managed TUN addresses = %#v", got)
	}
	clashAPI := document["experimental"].(map[string]any)["clash_api"].(map[string]any)
	if clashAPI["external_controller"] != "127.0.0.1:9090" || clashAPI["secret"] != "manager-secret" || clashAPI["access_control_allow_private_network"] != false {
		t.Fatalf("managed Clash API = %#v", clashAPI)
	}
	origins := clashAPI["access_control_allow_origin"].([]any)
	if fmt.Sprint(origins) != "[http://127.0.0.1 https://dashboard.test]" {
		t.Fatalf("managed origins = %#v", origins)
	}
	unchanged, err := os.ReadFile(sourcePath)
	if err != nil || string(unchanged) != source {
		t.Fatalf("source changed: %q, %v", unchanged, err)
	}
	record, err := os.ReadFile(commandRecord)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(record), "merge "+prepared.RuntimeConfigPath) || !strings.Contains(string(record), "-c "+sourcePath) ||
		!strings.Contains(string(record), "check -D "+prepared.HomeDir+" -c "+prepared.RuntimeConfigPath) {
		t.Fatalf("candidate commands were not used:\n%s", record)
	}
}

func TestDecodeSingBoxRuntimeUsesNumbersAndRejectsTrailingJSON(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "runtime.json")
	if err := os.WriteFile(path, []byte(`{"large":9007199254740993}`), 0o600); err != nil {
		t.Fatal(err)
	}
	document, err := decodeSingBoxRuntime(path)
	if err != nil {
		t.Fatal(err)
	}
	value, ok := document["large"].(json.Number)
	if !ok || value.String() != "9007199254740993" {
		t.Fatalf("large number = %#v", document["large"])
	}
	if err := os.WriteFile(path, []byte(`{} {}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeSingBoxRuntime(path); err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("trailing JSON error = %v", err)
	}
}

func TestSingBoxPrepareCleansPrivateRuntimeAfterNativeFailure(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		script string
		want   string
	}{
		{
			name: "merge",
			script: `#!/bin/sh
if [ "$1" = merge ]; then echo merge-rejected >&2; exit 41; fi
exit 0
`,
			want: "merge-rejected",
		},
		{
			name: "check",
			script: `#!/bin/sh
if [ "$1" = merge ]; then printf '{}\n' > "$2"; exit 0; fi
if [ "$1" = check ]; then echo check-rejected >&2; exit 42; fi
exit 0
`,
			want: "check-rejected",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			directory := t.TempDir()
			binary := filepath.Join(directory, "sing-box")
			if err := os.WriteFile(binary, []byte(test.script), 0o700); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(directory, "profile.json")
			if err := os.WriteFile(source, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			runtimeBase := filepath.Join(directory, "runtime")
			if err := os.Mkdir(runtimeBase, 0o700); err != nil {
				t.Fatal(err)
			}
			driver := NewSingBoxDriver(SingBoxOptions{})
			_, err := driver.Prepare(context.Background(), PrepareRequest{
				BinaryPath: binary, SourceConfigPath: source, RuntimeDir: runtimeBase,
				Capture: CapturePlan{
					TCP: ProtocolCapture{Method: CaptureTPROXY, Port: 7894},
					UDP: ProtocolCapture{Method: CaptureTPROXY, Port: 7894},
				},
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Prepare() error = %v", err)
			}
			entries, readErr := os.ReadDir(runtimeBase)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("failed preparation left runtime entries: %#v", entries)
			}
		})
	}
}

func TestSingBoxCaptureModeMappings(t *testing.T) {
	t.Parallel()
	tun := func(tcp, udp ProtocolCapture) CapturePlan {
		return CapturePlan{
			TCP: tcp, UDP: udp, TUNDevice: "clash-tun", TUNStack: "system",
			TUNAddresses: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")}, TUNMTU: 1500,
		}
	}
	tests := []struct {
		name string
		plan CapturePlan
		want map[string]string
	}{
		{"tproxy", tun(ProtocolCapture{Method: CaptureTPROXY, Port: 7894}, ProtocolCapture{Method: CaptureTPROXY, Port: 7894}), map[string]string{SingBoxTPROXYInboundTag: "tproxy:"}},
		{"tproxy-split", tun(ProtocolCapture{Method: CaptureTPROXY, Port: 7893}, ProtocolCapture{Method: CaptureTPROXY, Port: 7894}), map[string]string{SingBoxTPROXYTCPInboundTag: "tproxy:tcp", SingBoxTPROXYUDPInboundTag: "tproxy:udp"}},
		{"hybrid", tun(ProtocolCapture{Method: CaptureRedirect, Port: 7893}, ProtocolCapture{Method: CaptureTPROXY, Port: 7894}), map[string]string{SingBoxRedirectInboundTag: "redirect:", SingBoxTPROXYUDPInboundTag: "tproxy:udp"}},
		{"tun", tun(ProtocolCapture{Method: CaptureTUN}, ProtocolCapture{Method: CaptureTUN}), map[string]string{SingBoxTUNInboundTag: "tun:"}},
		{"mixed", tun(ProtocolCapture{Method: CaptureTPROXY, Port: 7894}, ProtocolCapture{Method: CaptureTUN}), map[string]string{SingBoxTPROXYTCPInboundTag: "tproxy:tcp", SingBoxTUNInboundTag: "tun:"}},
		{"mixed2", tun(ProtocolCapture{Method: CaptureRedirect, Port: 7893}, ProtocolCapture{Method: CaptureTUN}), map[string]string{SingBoxRedirectInboundTag: "redirect:", SingBoxTUNInboundTag: "tun:"}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			inbounds, err := singBoxManagedInbounds(test.plan)
			if err != nil {
				t.Fatal(err)
			}
			if len(inbounds) != len(test.want) {
				t.Fatalf("inbounds = %#v", inbounds)
			}
			for _, inbound := range inbounds {
				tag := inbound["tag"].(string)
				got := inbound["type"].(string) + ":"
				if network, _ := inbound["network"].(string); network != "" {
					got += network
				}
				if want, ok := test.want[tag]; !ok || got != want {
					t.Fatalf("inbound %q = %q, want %#v", tag, got, test.want)
				}
			}
		})
	}
}

func TestSingBoxPatchRejectsOwnershipAndListenerCollisions(t *testing.T) {
	t.Parallel()
	basePlan := CapturePlan{
		TCP: ProtocolCapture{Method: CaptureTPROXY, Port: 7894},
		UDP: ProtocolCapture{Method: CaptureTPROXY, Port: 7894}, LoopMark: 2,
	}
	controller := ControllerEndpoint{Listen: "127.0.0.1:9090"}
	tests := []struct {
		name     string
		document map[string]any
		plan     CapturePlan
		contains string
	}{
		{"reserved-tag", map[string]any{"outbounds": []any{map[string]any{"type": "direct", "tag": "boxctl-user"}}}, basePlan, "reserved prefix"},
		{"capture-type", map[string]any{"inbounds": []any{map[string]any{"type": "tun", "tag": "user"}}}, basePlan, "manager-owned capture"},
		{"listener-port", map[string]any{"inbounds": []any{map[string]any{"type": "mixed", "tag": "user", "listen_port": json.Number("7894")}}}, basePlan, "collides"},
		{"controller", map[string]any{"experimental": map[string]any{"clash_api": map[string]any{}}}, basePlan, "manager-owned"},
		{"default-mark", map[string]any{"route": map[string]any{"default_mark": "0x2"}}, basePlan, "manager-owned"},
		{"outbound-mark", map[string]any{"outbounds": []any{map[string]any{"type": "direct", "tag": "direct", "routing_mark": "0x3"}}}, basePlan, "conflicts"},
		{"dns-server-mark", map[string]any{"dns": map[string]any{"servers": []any{map[string]any{"type": "udp", "tag": "dns", "server": "1.1.1.1", "routing_mark": "0x3"}}}}, basePlan, "conflicts"},
		{"http-client-mark", map[string]any{"http_clients": []any{map[string]any{"tag": "rules", "routing_mark": "0x3"}}}, basePlan, "config.http_clients[0].routing_mark"},
		{"nested-rule-set-http-client-mark", map[string]any{"route": map[string]any{"rule_set": []any{map[string]any{"type": "remote", "tag": "rules", "http_client": map[string]any{"routing_mark": json.Number("3")}}}}}, basePlan, "config.route.rule_set[0].http_client.routing_mark"},
		{"manager-port", map[string]any{}, CapturePlan{TCP: ProtocolCapture{Method: CaptureTPROXY, Port: 9090}, UDP: ProtocolCapture{Method: CaptureTPROXY, Port: 9090}, LoopMark: 2}, "shared"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := patchSingBoxRuntime(test.document, test.plan, controller, []string{"http://127.0.0.1"})
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("patch error = %v, want substring %q", err, test.contains)
			}
		})
	}
}

func TestSingBoxPatchAcceptsManagedRoutingMarkAtEveryDepth(t *testing.T) {
	t.Parallel()
	document := map[string]any{
		"http_clients": []any{map[string]any{"tag": "shared", "routing_mark": "0x2"}},
		"route": map[string]any{"rule_set": []any{map[string]any{
			"type": "remote", "tag": "rules",
			"http_client": map[string]any{"routing_mark": json.Number("2")},
		}}},
	}
	plan := CapturePlan{
		TCP: ProtocolCapture{Method: CaptureTPROXY, Port: 7894},
		UDP: ProtocolCapture{Method: CaptureTPROXY, Port: 7894}, LoopMark: 2,
	}
	if err := patchSingBoxRuntime(document, plan, ControllerEndpoint{Listen: "127.0.0.1:9090"}, nil); err != nil {
		t.Fatalf("patch error = %v", err)
	}
}

func TestSingBoxControllerCapabilitiesAndClashAPI(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer secret" {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch request.URL.Path {
		case "/version":
			_, _ = io.WriteString(writer, `{"version":"1.14.0"}`)
		case "/proxies":
			_, _ = io.WriteString(writer, `{"proxies":{"direct":{"name":"direct","type":"Direct"}}}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	controller, err := NewSingBoxController(ControllerEndpoint{BaseURL: server.URL, Secret: "secret"}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	capabilities := controller.Capabilities()
	if capabilities.HotReload || capabilities.ProxyProviders || capabilities.RuleProviders || capabilities.RoutingMode || !capabilities.Proxies || !capabilities.Connections {
		t.Fatalf("capabilities = %#v", capabilities)
	}
	version, err := controller.Version(context.Background())
	if err != nil || version != "1.14.0" {
		t.Fatalf("Version() = %q, %v", version, err)
	}
	proxies, err := controller.Proxies(context.Background())
	if err != nil || len(proxies) != 1 || proxies[0].Name != "direct" {
		t.Fatalf("Proxies() = %#v, %v", proxies, err)
	}
	if _, err := controller.Providers(context.Background(), ProviderProxy); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Providers() error = %v", err)
	}
	if err := controller.Reload(context.Background(), "/tmp/runtime.json"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Reload() error = %v", err)
	}
	if _, err := controller.RoutingMode(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("RoutingMode() error = %v", err)
	}
	if err := controller.SetRoutingMode(context.Background(), RoutingModeDirect); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("SetRoutingMode() error = %v", err)
	}
	driver := NewSingBoxDriver(SingBoxOptions{})
	if _, err := driver.RoutingMode(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("driver RoutingMode() error = %v", err)
	}
	if err := driver.SetRoutingMode(context.Background(), RoutingModeDirect); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("driver SetRoutingMode() error = %v", err)
	}
}

func TestSingBoxLifecycleHealthControlLogsAndCleanup(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	binary, _ := writeFakeSingBox(t, directory, `{"outbounds":[{"type":"direct","tag":"direct"}]}`)
	sourcePath := filepath.Join(directory, "profile.json")
	if err := os.WriteFile(sourcePath, []byte(`{"outbounds":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var requestMu sync.Mutex
	versionRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer lifecycle-secret" || request.URL.Path != "/version" {
			http.Error(writer, "unexpected", http.StatusBadRequest)
			return
		}
		requestMu.Lock()
		versionRequests++
		requestMu.Unlock()
		_, _ = io.WriteString(writer, `{"version":"controller-1.14.0"}`)
	}))
	defer server.Close()
	driver := NewSingBoxDriver(SingBoxOptions{HTTPClient: server.Client(), StopTimeout: 2 * time.Second, LogBuffer: 32})
	prepared, err := driver.Prepare(context.Background(), PrepareRequest{
		BinaryPath: binary, SourceConfigPath: sourcePath, RuntimeDir: directory,
		Capture: CapturePlan{
			TCP: ProtocolCapture{Method: CaptureTPROXY, Port: 7894},
			UDP: ProtocolCapture{Method: CaptureTPROXY, Port: 7894},
		},
		Controller: ControllerEndpoint{Listen: "127.0.0.1:9090", BaseURL: server.URL, Secret: "lifecycle-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Start(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = driver.Stop(context.Background()) })
	if err := driver.Start(context.Background(), prepared); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second Start() error = %v", err)
	}
	status, err := driver.Health(context.Background())
	if err != nil || !status.Running || !status.ControllerReady || status.Version != "controller-1.14.0" || status.PID <= 1 {
		t.Fatalf("Health() = %#v, %v", status, err)
	}
	if err := driver.Reload(context.Background(), prepared); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Reload() error = %v", err)
	}
	wantLogs := map[string]bool{"fake sing-box ready": false, "fake sing-box warning": false}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for remaining := len(wantLogs); remaining > 0; {
		select {
		case entry := <-driver.Logs():
			if seen, exists := wantLogs[entry.Message]; exists && !seen {
				wantLogs[entry.Message] = true
				remaining--
			}
		case <-deadline.C:
			t.Fatalf("timed out waiting for logs: %#v", wantLogs)
		}
	}
	if err := driver.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status, err := driver.Health(context.Background()); err != nil || status.Running {
		t.Fatalf("health after stop = %#v, %v", status, err)
	}
	if _, err := os.Stat(prepared.RuntimeConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime survived stop: %v", err)
	}
	requestMu.Lock()
	defer requestMu.Unlock()
	if versionRequests == 0 {
		t.Fatal("controller was not probed")
	}
}

func indexObjectsByTag(t *testing.T, values []any) map[string]map[string]any {
	t.Helper()
	result := make(map[string]map[string]any, len(values))
	for _, value := range values {
		object, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("object list contains %#v", value)
		}
		tag, _ := object["tag"].(string)
		result[tag] = object
	}
	return result
}

func writeFakeSingBox(t *testing.T, directory, normalized string) (string, string) {
	t.Helper()
	normalizedPath := filepath.Join(directory, "normalized.json")
	if err := os.WriteFile(normalizedPath, []byte(normalized), 0o600); err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(directory, "commands.log")
	binaryPath := filepath.Join(directory, "sing-box")
	script := fmt.Sprintf(`#!/bin/sh
set -eu
echo "$*" >> %s
command="$1"
shift
case "$command" in
  merge)
    output="$1"
    cat %s > "$output"
    ;;
  check)
    ;;
  version)
    echo "sing-box version 1.14.0"
    ;;
  run)
    echo "fake sing-box ready"
    echo "fake sing-box warning" >&2
    trap 'exit 0' TERM INT
    while :; do sleep 1 & wait $!; done
    ;;
  *)
    echo "unexpected command: $command" >&2
    exit 64
    ;;
esac
`, shellQuote(recordPath), shellQuote(normalizedPath))
	if err := os.WriteFile(binaryPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return binaryPath, recordPath
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
