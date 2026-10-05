package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/ruleconvert"
)

// This test is run in the OpenWrt VM with both actual core binaries. Local
// listeners prove rule application without depending on external services.
func TestNativeConvertedRuleRefresh(t *testing.T) {
	binaries := ruleconvert.Binaries{SingBox: os.Getenv("BOXCTL_TEST_SING_BOX"), Mihomo: os.Getenv("BOXCTL_TEST_MIHOMO")}
	if binaries.SingBox == "" || binaries.Mihomo == "" {
		t.Skip("requires both native core test binaries")
	}
	for _, scenario := range []struct {
		target  string
		bridge  bool
		complex bool
	}{{"sing-box", false, false}, {"mihomo", false, false}, {"sing-box", true, false}, {"mihomo", true, false}, {"sing-box", false, true}, {"mihomo", false, true}} {
		target := scenario.target
		t.Run(fmt.Sprintf("%s/bridge=%t/complex=%t", target, scenario.bridge, scenario.complex), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			root := t.TempDir()
			runtimeDir := t.TempDir()
			service := ruleconvert.New(root)
			if err := service.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = service.Close() })
			other := "mihomo"
			if target == other {
				other = "sing-box"
			}
			codec := ruleconvert.Codec{Binaries: binaries}
			initialText, replacementText := "127.0.0.1/32\n", "192.0.2.0/24\n"
			if scenario.complex {
				initialText = "AND,((IP-CIDR,127.0.0.1/32),(NETWORK,tcp))\n"
				replacementText = "AND,((IP-CIDR,192.0.2.0/24),(NETWORK,tcp))\n"
			}
			initial, err := codec.Convert(ctx, []byte(initialText), other, "")
			if err != nil {
				t.Fatal(err)
			}
			replacement, err := codec.Convert(ctx, []byte(replacementText), other, "")
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			body := initial.Data
			bad := false
			requests := 0
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				requests++
				if bad {
					w.WriteHeader(503)
					return
				}
				_, _ = w.Write(body)
			}))
			defer upstream.Close()
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "conversion-routing-ok") }))
			defer origin.Close()
			proxyAddress := testFreeAddress(t)
			_, proxyPort, _ := net.SplitHostPort(proxyAddress)
			control := testFreeAddress(t)
			_, capturePortText, _ := net.SplitHostPort(testFreeAddress(t))
			capturePort, _ := strconv.ParseUint(capturePortText, 10, 16)
			var driver interface {
				Config
				Runtime
			}
			codecs := func() ruleconvert.Binaries { return binaries }
			var source string
			binary := binaries.SingBox
			if target == "sing-box" {
				driver = NewSingBoxDriver(SingBoxOptions{RuleConverter: service, RuleCodecs: codecs})
				source = fmt.Sprintf(`{"inbounds":[{"type":"mixed","tag":"probe","listen":"127.0.0.1","listen_port":%s}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rule_set":[{"type":"remote","tag":"converted","format":"binary","url":"convert:%s","update_interval":"1s","http_client":{"detour":"direct"}}],"rules":[{"rule_set":"converted","action":"reject"}],"final":"direct"}}`, proxyPort, upstream.URL)
			} else {
				binary = binaries.Mihomo
				driver = NewMihomoDriver(MihomoOptions{RuleConverter: service, RuleCodecs: codecs})
				source = fmt.Sprintf("mixed-port: %s\nallow-lan: false\nmode: rule\nrule-providers:\n  converted:\n    type: http\n    url: convert:%s\n    interval: 1\n    behavior: classical\n    format: yaml\nrules:\n  - RULE-SET,converted,REJECT\n  - MATCH,DIRECT\n", proxyPort, upstream.URL)
			}
			if scenario.bridge {
				seed, err := codec.Convert(ctx, []byte("127.0.0.1/32\n"), target, "")
				if err != nil {
					t.Fatal(err)
				}
				seedPath := filepath.Join(root, "seed.rules")
				if err = os.WriteFile(seedPath, seed.Data, 0o600); err != nil {
					t.Fatal(err)
				}
				if target == "sing-box" {
					var doc map[string]any
					if err = json.Unmarshal([]byte(source), &doc); err != nil {
						t.Fatal(err)
					}
					outbounds := doc["outbounds"].([]any)
					doc["outbounds"] = append(outbounds, map[string]any{"type": "selector", "tag": "download-proxy", "outbounds": []string{"direct"}})
					route := doc["route"].(map[string]any)
					provider := route["rule_set"].([]any)[0].(map[string]any)
					provider["initial_path"] = seedPath
					provider["http_client"] = map[string]any{"detour": "download-proxy"}
					encoded, _ := json.Marshal(doc)
					source = string(encoded)
				} else {
					source = strings.Replace(source, "    interval: 1", "    proxy: download-proxy\n    path: "+seedPath+"\n    interval: 1", 1)
					source += "proxy-groups:\n  - name: download-proxy\n    type: select\n    proxies: [DIRECT]\n"
				}
			}
			sourcePath := filepath.Join(root, "profile")
			if err = os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			prepared, err := driver.Prepare(ctx, PrepareRequest{BinaryPath: binary, SourceConfigPath: sourcePath, HomeDir: root, RuntimeDir: runtimeDir, Controller: ControllerEndpoint{Listen: control, Secret: "fixture-secret"}, Capture: CapturePlan{TCP: ProtocolCapture{Method: CaptureTPROXY, Port: uint16(capturePort)}, UDP: ProtocolCapture{Method: CaptureTPROXY, Port: uint16(capturePort)}}})
			if err != nil {
				t.Fatal(err)
			}
			if err = driver.Start(ctx, prepared); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = driver.Stop(context.Background()) }()
			proxy, _ := url.Parse("http://" + proxyAddress)
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.Proxy = http.ProxyURL(proxy)
			transport.DisableKeepAlives = true
			defer transport.CloseIdleConnections()
			client := http.Client{Transport: transport, Timeout: time.Second}
			probe := func() bool {
				resp, e := client.Get(origin.URL)
				if e != nil {
					return false
				}
				defer resp.Body.Close()
				data, _ := io.ReadAll(resp.Body)
				return resp.StatusCode == 200 && string(data) == "conversion-routing-ok"
			}
			// Establish the proxy listener before asserting an intentional reject.
			deadline := time.Now().Add(5 * time.Second)
			for {
				conn, e := net.DialTimeout("tcp", proxyAddress, time.Second)
				if e == nil {
					_ = conn.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("core proxy listener did not start")
				}
				time.Sleep(50 * time.Millisecond)
			}
			if probe() {
				t.Fatal("initial converted rule failed to reject the matching address")
			}
			mu.Lock()
			body = replacement.Data
			mu.Unlock()
			eventuallyNative(t, ctx, probe, "core did not apply its scheduled converted update")
			// A manager-only restart rebinds the persisted endpoint; the running core
			// must still be able to update, without any rewritten runtime URL.
			if err = service.Close(); err != nil {
				t.Fatal(err)
			}
			service = ruleconvert.New(root)
			if err = service.Start(); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			body = initial.Data
			mu.Unlock()
			eventuallyNative(t, ctx, func() bool { return !probe() }, "core lost converter after manager restart")
			mu.Lock()
			bad = true
			before := requests
			mu.Unlock()
			eventuallyNative(t, ctx, func() bool { mu.Lock(); defer mu.Unlock(); return requests > before }, "core stopped requesting updates")
			if probe() {
				t.Fatal("failed upstream update discarded the last good rejection rule")
			}
			content, err := os.ReadFile(sourcePath)
			if err != nil || string(content) != source {
				t.Fatal("saved source profile was rewritten")
			}
		})
	}
}
func testFreeAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	_ = l.Close()
	return address
}
func eventuallyNative(t *testing.T, ctx context.Context, check func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for {
		if check() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(message)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(150 * time.Millisecond):
		}
	}
}
