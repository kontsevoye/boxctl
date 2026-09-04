package config

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestInjectMihomoProxyProviderHeadersChangesRuntimeOnly(t *testing.T) {
	source := []byte(`# user comment
proxy-providers:
  subscribed:
    type: http
    url: https://secret.example/sub/token
    header:
      Authorization:
        - keep-me
      user-agent:
        - old
      x-hwid:
        - explicit-device
  local:
    type: file
    path: ./proxy-providers/local.yaml
rules: []
`)
	updated, err := InjectMihomoProxyProviderHeaders(source, map[string]string{
		"User-Agent": "boxctl/1", "x-hwid": "device-id", "x-device-os": "OpenWrt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updated), "Authorization:") || !strings.Contains(string(updated), "- old") || !strings.Contains(string(updated), "x-hwid:") {
		t.Fatalf("unexpected runtime config:\n%s", updated)
	}
	if strings.Count(string(updated), "x-hwid:") != 1 {
		t.Fatalf("device headers were injected into a local provider:\n%s", updated)
	}
	if !strings.Contains(string(updated), "explicit-device") || strings.Contains(string(updated), "device-id") {
		t.Fatalf("generated headers overrode an explicit subscription header:\n%s", updated)
	}
	if !strings.Contains(string(source), "- old") {
		t.Fatal("source document was modified")
	}
	var decoded map[string]any
	if err := yaml.Unmarshal(updated, &decoded); err != nil {
		t.Fatal(err)
	}
}

func TestRelocateMihomoHTTPRuleProviders(t *testing.T) {
	source := []byte(`rule-providers:
  telegram:
    type: http
    behavior: ipcidr
    format: mrs
    url: https://secret.example/rules/token
    path: ./rule-providers/telegram.mrs
  local:
    type: file
    path: ./local-rules/local.txt
rules: []
`)
	updated, relocations, err := RelocateMihomoHTTPRuleProviders(source, "/tmp/boxctl-rules-private")
	if err != nil {
		t.Fatal(err)
	}
	if len(relocations) != 1 || relocations[0].Name != "telegram" || relocations[0].ConfiguredPath != "./rule-providers/telegram.mrs" || !strings.HasSuffix(relocations[0].RuntimePath, ".mrs") {
		t.Fatalf("relocations = %+v", relocations)
	}
	text := string(updated)
	if !strings.Contains(text, "path: /tmp/boxctl-rules-private/") || !strings.Contains(text, "path: ./local-rules/local.txt") {
		t.Fatalf("unexpected runtime config:\n%s", text)
	}
	if strings.Contains(strings.Join([]string{relocations[0].Name, relocations[0].ConfiguredPath, relocations[0].RuntimePath}, " "), "secret") {
		t.Fatal("relocation metadata exposed URL credentials")
	}
}

func TestRelocateMihomoPathlessHTTPRuleProviderReturnsCredentialSafeCacheName(t *testing.T) {
	source := []byte(`rule-providers:
  pathless:
    type: http
    behavior: ipcidr
    url: https://secret.example/rules?token=private
rules: []
`)
	_, relocations, err := RelocateMihomoHTTPRuleProviders(source, "/tmp/boxctl-rules-private")
	if err != nil {
		t.Fatal(err)
	}
	if len(relocations) != 1 || len(relocations[0].MihomoCacheName) != 32 || relocations[0].ConfiguredPath != "" {
		t.Fatalf("relocations = %+v", relocations)
	}
	metadata := strings.Join([]string{relocations[0].Name, relocations[0].MihomoCacheName, relocations[0].RuntimePath}, " ")
	if strings.Contains(metadata, "secret.example") || strings.Contains(metadata, "token=") {
		t.Fatal("relocation metadata exposed URL credentials")
	}
}

func TestRelocateMihomoHTTPRuleProviderBindsRuntimePathToSourceIdentity(t *testing.T) {
	first := []byte("rule-providers:\n  shared-name:\n    type: http\n    url: https://rules.example.invalid/first?token=one\nrules: []\n")
	second := []byte("rule-providers:\n  shared-name:\n    type: http\n    url: https://rules.example.invalid/second?token=two\nrules: []\n")
	_, firstRelocations, err := RelocateMihomoHTTPRuleProviders(first, "/tmp/boxctl-rules-private")
	if err != nil {
		t.Fatal(err)
	}
	_, secondRelocations, err := RelocateMihomoHTTPRuleProviders(second, "/tmp/boxctl-rules-private")
	if err != nil {
		t.Fatal(err)
	}
	if len(firstRelocations) != 1 || len(secondRelocations) != 1 {
		t.Fatalf("relocations = %+v, %+v", firstRelocations, secondRelocations)
	}
	if firstRelocations[0].RuntimePath == secondRelocations[0].RuntimePath {
		t.Fatalf("different provider sources share runtime path %q", firstRelocations[0].RuntimePath)
	}
	paths := firstRelocations[0].RuntimePath + " " + secondRelocations[0].RuntimePath
	if strings.Contains(paths, "token=") || strings.Contains(paths, "example.invalid") {
		t.Fatalf("runtime path exposed source credentials: %s", paths)
	}
}
