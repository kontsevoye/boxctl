package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func TestMihomoControllerControlPlane(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	requests := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "Bearer top-secret" {
			http.Error(writer, "bad auth", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		requests[request.Method+" "+request.URL.EscapedPath()]++
		mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/version":
			_, _ = io.WriteString(writer, `{"version":"v1.19.99","meta":true}`)
		case request.Method == http.MethodGet && request.URL.Path == "/proxies":
			_, _ = io.WriteString(writer, `{"proxies":{"DIRECT":{"name":"DIRECT","type":"Direct","icon":"https://icons.example/direct.png","udp":true,"alive":true,"history":[{"time":"now","delay":9}]},"Hidden":{"name":"Hidden","type":"Selector","icon":"https://icons.example/group.png","now":"DIRECT","all":["DIRECT"],"history":[{"time":"now","delay":12}]}}}`)
		case request.Method == http.MethodPut && strings.HasPrefix(request.URL.Path, "/proxies/"):
			var payload struct {
				Name string `json:"name"`
			}
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil || payload.Name != "DIRECT" {
				http.Error(writer, "bad selection", http.StatusBadRequest)
				return
			}
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/delay"):
			if request.URL.Query().Get("url") != "https://example.test/a?b=c" || request.URL.Query().Get("timeout") != "2500" {
				http.Error(writer, "bad delay query", http.StatusBadRequest)
				return
			}
			_, _ = io.WriteString(writer, `{"delay":37}`)
		case request.Method == http.MethodGet && request.URL.Path == "/providers/proxies":
			_, _ = io.WriteString(writer, `{"providers":{"Sub B":{"name":"Sub B","type":"Proxy","vehicleType":"HTTP","updatedAt":"later","proxies":[{"name":"one"},{"name":"two"}],"subscriptionInfo":{"upload":1,"download":2,"total":3,"expire":4},"healthCheck":{"enable":true,"interval":300,"lazy":true}},"Sub A":{"type":"Proxy","vehicleType":"File","path":"./a.yaml"}}}`)
		case request.Method == http.MethodGet && request.URL.Path == "/providers/rules":
			_, _ = io.WriteString(writer, `{"providers":{"Rules":{"name":"Rules","type":"Rule","vehicleType":"HTTP","ruleCount":42,"behavior":"domain","format":"mrs"}}}`)
		case request.Method == http.MethodPut && strings.HasPrefix(request.URL.Path, "/providers/"):
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodGet && request.URL.Path == "/rules":
			_, _ = io.WriteString(writer, `{"rules":[{"type":"DOMAIN-SUFFIX","payload":"example.com","proxy":"DIRECT","size":1}]}`)
		case request.Method == http.MethodGet && request.URL.Path == "/connections":
			_, _ = io.WriteString(writer, `{"downloadTotal":11,"uploadTotal":22,"memory":33,"connections":[{"id":"conn/1","metadata":{"network":"tcp","sourceIP":"192.0.2.1"},"upload":3,"download":4,"chains":["DIRECT"]}]}`)
		case request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, "/connections/"):
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodDelete && request.URL.Path == "/connections":
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodGet && request.URL.Path == "/configs":
			_, _ = io.WriteString(writer, `{"mode":"Rule"}`)
		case request.Method == http.MethodPatch && request.URL.Path == "/configs":
			var payload struct {
				Mode RoutingMode `json:"mode"`
			}
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil || payload.Mode != RoutingModeDirect {
				http.Error(writer, "bad routing mode", http.StatusBadRequest)
				return
			}
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodPut && request.URL.Path == "/configs":
			if request.URL.Query().Get("force") != "true" {
				http.Error(writer, "missing force", http.StatusBadRequest)
				return
			}
			var payload struct {
				Path string `json:"path"`
			}
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil || payload.Path != "/runtime/config.yaml" {
				http.Error(writer, "bad reload path", http.StatusBadRequest)
				return
			}
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.Error(writer, fmt.Sprintf("unexpected %s %s", request.Method, request.URL.String()), http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewMihomoController(ControllerEndpoint{BaseURL: server.URL, Secret: "top-secret"}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	version, err := client.Version(ctx)
	if err != nil || version != "v1.19.99" {
		t.Fatalf("Version() = %q, %v", version, err)
	}
	proxies, err := client.Proxies(ctx)
	if err != nil || len(proxies) != 2 || proxies[0].Name != "DIRECT" || proxies[1].Name != "Hidden" {
		t.Fatalf("Proxies() = %#v, %v", proxies, err)
	}
	groups, err := client.Groups(ctx)
	if err != nil || len(groups) != 1 || groups[0].Name != "Hidden" || groups[0].Icon != "https://icons.example/group.png" || groups[0].Now != "DIRECT" || len(groups[0].Options) != 1 || groups[0].Options[0].Icon != "https://icons.example/direct.png" || groups[0].Options[0].Type != "Direct" || groups[0].Options[0].Alive == nil || !*groups[0].Options[0].Alive {
		t.Fatalf("Groups() = %#v, %v", groups, err)
	}
	if err := client.Select(ctx, "group/😀", "DIRECT"); err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	delay, err := client.Delay(ctx, "Hidden", "https://example.test/a?b=c", 2500*time.Millisecond)
	if err != nil || delay != 37*time.Millisecond {
		t.Fatalf("Delay() = %s, %v", delay, err)
	}
	providers, err := client.Providers(ctx, ProviderProxy)
	if err != nil || len(providers) != 2 || providers[0].Name != "Sub A" || providers[1].Name != "Sub B" {
		t.Fatalf("Providers(proxy) = %#v, %v", providers, err)
	}
	if providers[1].ProxyCount != 2 || providers[1].SubscriptionInfo == nil || providers[1].SubscriptionInfo.Total != 3 || !providers[1].HealthCheck.Enabled {
		t.Fatalf("Providers(proxy) metadata = %#v", providers[1])
	}
	ruleProviders, err := client.Providers(ctx, ProviderRule)
	if err != nil || len(ruleProviders) != 1 || ruleProviders[0].Name != "Rules" || ruleProviders[0].RuleCount != 42 || ruleProviders[0].Format != "mrs" {
		t.Fatalf("Providers(rule) = %#v, %v", ruleProviders, err)
	}
	if err := client.UpdateProvider(ctx, ProviderProxy, "Sub A"); err != nil {
		t.Fatalf("UpdateProvider() error = %v", err)
	}
	rules, err := client.Rules(ctx)
	if err != nil || len(rules) != 1 || rules[0].Payload != "example.com" {
		t.Fatalf("Rules() = %#v, %v", rules, err)
	}
	connections, err := client.Connections(ctx)
	if err != nil || len(connections.Connections) != 1 || connections.DownloadTotal != 11 {
		t.Fatalf("Connections() = %#v, %v", connections, err)
	}
	if err := client.CloseConnection(ctx, "conn/1"); err != nil {
		t.Fatalf("CloseConnection() error = %v", err)
	}
	if err := client.CloseAllConnections(ctx); err != nil {
		t.Fatalf("CloseAllConnections() error = %v", err)
	}
	mode, err := client.RoutingMode(ctx)
	if err != nil || mode != RoutingModeRule {
		t.Fatalf("RoutingMode() = %q, %v", mode, err)
	}
	if err := client.SetRoutingMode(ctx, RoutingModeDirect); err != nil {
		t.Fatalf("SetRoutingMode() error = %v", err)
	}
	if err := client.SetRoutingMode(ctx, RoutingMode("script")); err == nil {
		t.Fatal("SetRoutingMode() accepted unsupported mode")
	}
	if err := client.Reload(ctx, "/runtime/config.yaml"); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if requests[http.MethodPut+" /proxies/group%2F%F0%9F%98%80"] != 1 {
		t.Errorf("selection path was not escaped: %#v", requests)
	}
	if requests[http.MethodDelete+" /connections/conn%2F1"] != 1 {
		t.Errorf("connection path was not escaped: %#v", requests)
	}
	if requests[http.MethodDelete+" /connections"] != 1 {
		t.Errorf("close-all path was not requested: %#v", requests)
	}
}

func TestMihomoControllerStreamsTrafficOverWebSocket(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/traffic" || request.Header.Get("Authorization") != "Bearer stream-secret" {
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		connection, err := websocket.Accept(writer, request, nil)
		if err != nil {
			return
		}
		defer func() { _ = connection.CloseNow() }()
		_ = wsjson.Write(request.Context(), connection, TrafficSnapshot{UploadRateBytes: 12, DownloadRateBytes: 34})
	}))
	defer server.Close()

	client, err := NewMihomoController(ControllerEndpoint{BaseURL: server.URL, Secret: "stream-secret"}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.StreamTraffic(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, ok := <-stream
	if !ok || snapshot.UploadRateBytes != 12 || snapshot.DownloadRateBytes != 34 || snapshot.CapturedAt.IsZero() {
		t.Fatalf("traffic snapshot = %#v, open=%t", snapshot, ok)
	}
}

func TestMihomoControllerStreamsLogsOverWebSocket(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/logs" || request.Header.Get("Authorization") != "Bearer stream-secret" {
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		connection, err := websocket.Accept(writer, request, nil)
		if err != nil {
			return
		}
		defer func() { _ = connection.CloseNow() }()
		_ = wsjson.Write(request.Context(), connection, MihomoLog{Level: "warning", Message: "provider is stale"})
	}))
	defer server.Close()

	client, err := NewMihomoController(ControllerEndpoint{BaseURL: server.URL, Secret: "stream-secret"}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.StreamLogs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := <-stream
	if !ok || entry.Level != "warning" || entry.Message != "provider is stale" {
		t.Fatalf("log entry = %#v, open=%t", entry, ok)
	}
}

func TestMihomoControllerStreamsConnectionsOverWebSocket(t *testing.T) {
	t.Parallel()
	intervals := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer stream-secret" {
			http.Error(writer, "bad auth", http.StatusUnauthorized)
			return
		}
		if request.URL.Path != "/connections" {
			http.NotFound(writer, request)
			return
		}
		intervals <- request.URL.Query().Get("interval")
		connection, err := websocket.Accept(writer, request, nil)
		if err != nil {
			return
		}
		defer func() { _ = connection.CloseNow() }()
		for _, snapshot := range []ConnectionsSnapshot{
			{Connections: []Connection{{ID: "one", Upload: 10, Download: 20}}},
			{Connections: []Connection{{ID: "one", Upload: 30, Download: 50}}},
		} {
			if err := wsjson.Write(request.Context(), connection, snapshot); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	client, err := NewMihomoController(
		ControllerEndpoint{BaseURL: server.URL, Secret: "stream-secret"},
		server.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.StreamConnections(ctx, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	first, ok := <-stream
	if !ok || len(first.Connections) != 1 || first.Connections[0].Upload != 10 || first.CapturedAt.IsZero() {
		t.Fatalf("first streamed snapshot = %#v, open=%t", first, ok)
	}
	second, ok := <-stream
	if !ok || second.Connections[0].Download != 50 || second.CapturedAt.Before(first.CapturedAt) {
		t.Fatalf("second streamed snapshot = %#v, open=%t", second, ok)
	}
	if interval := <-intervals; interval != "250" {
		t.Fatalf("bounded stream interval = %q, want 250", interval)
	}
}

func TestMihomoControllerConnectionStreamSetupIsBounded(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()

	httpClient := *server.Client()
	httpClient.Timeout = 50 * time.Millisecond
	client, err := NewMihomoController(ControllerEndpoint{BaseURL: server.URL}, &httpClient)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := client.StreamConnections(context.Background(), time.Second); err == nil {
		t.Fatal("StreamConnections accepted a stalled WebSocket handshake")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("stalled WebSocket handshake took %s", elapsed)
	}
}

func TestMihomoControllerConnectionStreamClosesWhenUpstreamIsSilent(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request, nil)
		if err != nil {
			return
		}
		defer func() { _ = connection.CloseNow() }()
		<-release
	}))
	defer server.Close()
	defer close(release)

	client, err := NewMihomoController(ControllerEndpoint{BaseURL: server.URL}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.StreamConnections(ctx, minimumConnectionsInterval)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case _, open := <-stream:
		if open {
			t.Fatal("silent connection stream produced a snapshot")
		}
	case <-ctx.Done():
		t.Fatal("silent connection stream did not close before request context")
	}
}

func TestMihomoControllerHonorsContextAndErrors(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/version" {
			http.Error(writer, "controller unavailable", http.StatusServiceUnavailable)
			return
		}
		<-request.Context().Done()
	}))
	defer server.Close()
	client, err := NewMihomoController(ControllerEndpoint{BaseURL: server.URL}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Version(context.Background())
	if err == nil || !strings.Contains(err.Error(), "503") || !strings.Contains(err.Error(), "controller unavailable") {
		t.Fatalf("Version() error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.Proxies(cancelled)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Proxies(cancelled) error = %v, want context.Canceled", err)
	}
}

func TestMihomoControllerRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	if _, err := NewMihomoController(ControllerEndpoint{BaseURL: "file:///tmp/controller"}, nil); err == nil {
		t.Fatal("NewMihomoController accepted file URL")
	}
	client, err := NewMihomoController(ControllerEndpoint{BaseURL: "http://127.0.0.1:1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Delay(context.Background(), "proxy", "url", 0); err == nil {
		t.Fatal("Delay accepted zero timeout")
	}
	if _, err := client.Providers(context.Background(), ProviderKind("bad")); err == nil {
		t.Fatal("Providers accepted invalid kind")
	}
}
