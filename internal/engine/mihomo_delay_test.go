package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestMihomoProviderNodeMetadataAndDelay(t *testing.T) {
	t.Parallel()
	const node = "[d3] 🇳🇱 NL / [AnyTLS]"
	const provider = "diaff/3"
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.EscapedPath())
		if r.Header.Get("Authorization") != "Bearer test-secret" {
			t.Error("missing controller authentication")
		}
		switch r.URL.EscapedPath() {
		case "/proxies":
			_ = json.NewEncoder(w).Encode(map[string]any{"proxies": map[string]any{"DIAFF-FAST": map[string]any{"type": "URLTest", "now": node, "all": []string{node}}}})
		case "/providers/proxies":
			_ = json.NewEncoder(w).Encode(map[string]any{"providers": map[string]any{provider: map[string]any{"proxies": []any{map[string]any{"name": node, "type": "AnyTLS", "udp": true, "alive": true, "history": []any{map[string]any{"time": "now", "delay": 52}}}}}}})
		case "/providers/proxies/" + url.PathEscape(provider) + "/" + url.PathEscape(node) + "/healthcheck":
			if r.Method != http.MethodGet || r.URL.Query().Get("timeout") != "5000" || r.URL.Query().Get("url") != "https://example.test/generate_204?token=private" {
				t.Error("incorrect delay request")
			}
			_, _ = w.Write([]byte(`{"delay":57}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Resource not found"}`))
		}
	}))
	defer server.Close()
	client, err := NewMihomoController(ControllerEndpoint{BaseURL: server.URL, Secret: "test-secret"}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	groups, err := client.Groups(context.Background())
	if err != nil || len(groups) != 1 || len(groups[0].Options) != 1 {
		t.Fatalf("Groups = %#v, %v", groups, err)
	}
	option := groups[0].Options[0]
	if option.Name != node || option.Provider != provider || option.Type != "AnyTLS" || !option.UDP || option.Alive == nil || !*option.Alive || len(option.History) != 1 || option.History[0].Delay != 52 {
		t.Fatalf("provider metadata missing: %#v", option)
	}
	for _, identity := range []string{provider, ""} {
		delay, err := client.Delay(context.Background(), node, identity, "https://example.test/generate_204?token=private", 5*time.Second)
		if err != nil || delay != 57*time.Millisecond {
			t.Fatalf("Delay(provider=%q) = %v, %v", identity, delay, err)
		}
	}
	for _, path := range paths {
		if strings.HasPrefix(path, "/group/") {
			t.Fatalf("test must not clear automatic group pin: %s", path)
		}
	}
}

func TestMihomoDelayFailuresAndProviderIdentity(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, provider string
		status         int
		duplicates     bool
		want           error
		healthChecks   int
	}{
		{"missing", "", 404, false, ErrProxyNotFound, 0},
		{"explicit missing", "chosen", 404, false, ErrProxyNotFound, 1},
		{"timeout", "", 504, false, ErrDelayTimeout, 0},
		{"failed", "", 503, false, ErrDelayFailed, 0},
		{"duplicate", "", 404, true, ErrProxyAmbiguous, 0},
		{"explicit duplicate", "chosen", 200, true, nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookups, checks := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/providers/proxies" {
					lookups++
					_ = json.NewEncoder(w).Encode(map[string]any{"providers": map[string]any{"chosen": map[string]any{"proxies": []any{map[string]any{"name": "duplicate"}}}, "other": map[string]any{"proxies": []any{map[string]any{"name": "duplicate"}}}}})
					return
				}
				if strings.Contains(r.URL.Path, "/healthcheck") {
					checks++
					if !strings.HasPrefix(r.URL.Path, "/providers/proxies/chosen/") {
						t.Error("wrong provider")
					}
				}
				w.WriteHeader(tc.status)
				if tc.status == 200 {
					_, _ = w.Write([]byte(`{"delay":10}`))
				} else {
					_, _ = w.Write([]byte(`{"message":"private upstream detail"}`))
				}
			}))
			defer server.Close()
			client, _ := NewMihomoController(ControllerEndpoint{BaseURL: server.URL}, server.Client())
			name := "missing"
			if tc.duplicates {
				name = "duplicate"
			}
			_, err := client.Delay(context.Background(), name, tc.provider, "https://example.test", time.Second)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if checks != tc.healthChecks {
				t.Fatalf("provider calls = %d", checks)
			}
			if tc.status != 404 || tc.provider != "" {
				if lookups != 0 {
					t.Fatal("must not discover providers after a non-404 or explicit-provider failure")
				}
			}
		})
	}
	if err := classifyDelayError(context.DeadlineExceeded); !errors.Is(err, ErrDelayTimeout) {
		t.Fatalf("deadline = %v", err)
	}
	if err := classifyDelayError(context.Canceled); !errors.Is(err, context.Canceled) || errors.Is(err, ErrDelayFailed) {
		t.Fatalf("cancellation = %v", err)
	}
}

func TestSingBoxDelayNeverDiscoversProviders(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/providers") {
			t.Error("sing-box must not use provider API")
		}
		if r.URL.Path == "/proxies" {
			_, _ = w.Write([]byte(`{"proxies":{"auto":{"type":"URLTest","all":["missing"]}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	client, _ := NewSingBoxController(ControllerEndpoint{BaseURL: server.URL}, server.Client())
	if _, err := client.Groups(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Delay(context.Background(), "missing", "", "https://example.test", time.Second); !errors.Is(err, ErrProxyNotFound) {
		t.Fatalf("Delay = %v", err)
	}
	if _, err := client.Delay(context.Background(), "missing", "provider", "https://example.test", time.Second); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("provider Delay = %v", err)
	}
}
