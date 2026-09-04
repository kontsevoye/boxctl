package config

import (
	"strings"
	"testing"
	"time"
)

func TestInjectMihomoProxyProvidersPreservesSourceAndAddsPrivateRuntimeEntries(t *testing.T) {
	source := []byte("# owned by user\nmode: rule\nproxy-providers:\n  existing:\n    type: file\n    path: ./existing.yaml\nproxy-groups: [{name: PROXY, type: select, use: [existing]}]\n")
	result, err := InjectMihomoProxyProviders(source, []MihomoProxyProvider{{
		Name: "boxctl-abc123", URL: "https://example.test/sub?token=secret",
		Path: "./proxy-providers/boxctl-abc123.yaml", Interval: 6 * time.Hour,
		Headers: map[string]string{"User-Agent": "private-agent"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	text := string(result)
	for _, want := range []string{
		"# owned by user", "  existing:", "  boxctl-abc123:", "    type: http",
		`    url: "https://example.test/sub?token=secret"`, "    interval: 21600", `      "User-Agent":`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("result missing %q:\n%s", want, text)
		}
	}
	if !strings.HasPrefix(text, "# owned by user\nmode: rule\n") {
		t.Fatalf("unmanaged prefix changed:\n%s", text)
	}
}

func TestInjectMihomoProxyProvidersRefusesNameCollision(t *testing.T) {
	_, err := InjectMihomoProxyProviders([]byte("proxy-providers:\n  boxctl-abc:\n    type: file\n"), []MihomoProxyProvider{{
		Name: "boxctl-abc", Local: true, Path: "./cache.yaml", Interval: time.Hour,
	}})
	if err == nil {
		t.Fatal("provider collision was accepted")
	}
}

func TestInjectMihomoLocalProxyProviderHasNoRemoteOnlyFields(t *testing.T) {
	result, err := InjectMihomoProxyProviders([]byte("mode: rule\n"), []MihomoProxyProvider{{
		Name: "boxctl-local", Local: true, Path: "./proxy-providers/boxctl-local.yaml", Interval: 24 * time.Hour,
		Headers: map[string]string{"X-HWID": "must-not-be-rendered"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	text := string(result)
	if !strings.Contains(text, "  type: file") || strings.Contains(text, "interval:") || strings.Contains(text, "header:") || strings.Contains(text, "url:") {
		t.Fatalf("local provider contains remote-only fields:\n%s", text)
	}
}
