package config

import (
	"errors"
	"strings"
	"testing"
)

func TestInspectLocalRuleListBinding(t *testing.T) {
	source := []byte(`mode: rule
rule-providers:
  local-telegram-ip:
    type: file
    behavior: classical
    format: text
    path: ./local-rules/telegram-ip.txt
rules:
  - RULE-SET,local-telegram-ip,TELEGRAM
  - MATCH,DIRECT
`)
	binding, err := InspectLocalRuleListBinding(source, "telegram-ip")
	if err != nil {
		t.Fatal(err)
	}
	if binding.ProviderName != "local-telegram-ip" || !binding.InConfig || binding.ConfigNameTaken || !binding.InUse {
		t.Fatalf("unexpected binding: %+v", binding)
	}
}

func TestInsertLocalRuleProviderPreservesNativeDocument(t *testing.T) {
	source := []byte(`# native comment
mode: rule
rule-providers:
  remote:
    type: http
    url: https://user:secret@example.invalid/rules.txt
rules:
  - MATCH,DIRECT
`)
	updated, binding, err := InsertLocalRuleProvider(source, "telegram-ip")
	if err != nil {
		t.Fatal(err)
	}
	text := string(updated)
	for _, fragment := range []string{
		"# native comment", "https://user:secret@example.invalid/rules.txt",
		"  local-telegram-ip:\n", "    behavior: classical\n", "    path: ./local-rules/telegram-ip.txt\n",
		"rules:\n  - MATCH,DIRECT\n",
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("updated config is missing %q:\n%s", fragment, text)
		}
	}
	if !binding.InConfig {
		t.Fatalf("unexpected binding: %+v", binding)
	}
	second, _, err := InsertLocalRuleProvider(updated, "telegram-ip")
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != string(updated) {
		t.Fatal("idempotent insert changed the document")
	}
}

func TestInsertLocalRuleProviderCreatesSection(t *testing.T) {
	updated, _, err := InsertLocalRuleProvider([]byte("mode: rule\nrules:\n  - MATCH,DIRECT\n"), "video-domain")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updated), "rule-providers:\n  local-video-domain:\n") {
		t.Fatalf("missing provider section:\n%s", updated)
	}
	if _, err := ParseMihomoRouting(updated); err != nil {
		t.Fatalf("mutated YAML is invalid: %v", err)
	}
}

func TestInsertLocalRuleProviderRefusesUnrelatedName(t *testing.T) {
	source := []byte(`rule-providers:
  local-telegram-ip:
    type: http
    url: https://example.invalid/rules
rules: []
`)
	_, binding, err := InsertLocalRuleProvider(source, "telegram-ip")
	if !errors.Is(err, ErrLocalRuleProviderConflict) {
		t.Fatalf("error = %v", err)
	}
	if !binding.ConfigNameTaken || binding.InConfig {
		t.Fatalf("unexpected binding: %+v", binding)
	}
}

func TestRemoveLocalRuleProviderPreservesOtherProviders(t *testing.T) {
	source := []byte(`rule-providers:
  local-telegram-ip:
    type: file
    behavior: classical
    format: text
    path: ./local-rules/telegram-ip.txt
  remote:
    type: http
    url: https://example.invalid/rules
rules:
  - RULE-SET,local-telegram-ip,PROXY
`)
	updated, binding, err := RemoveLocalRuleProvider(source, "telegram-ip")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(updated), "local-telegram-ip:") || !strings.Contains(string(updated), "  remote:\n") {
		t.Fatalf("unexpected config:\n%s", updated)
	}
	if binding.InConfig || !binding.InUse {
		t.Fatalf("unexpected binding after removal: %+v", binding)
	}
}

func TestRemoveOnlyLocalRuleProviderLeavesEmptyMapping(t *testing.T) {
	source := []byte(`rule-providers:
  local-telegram-ip:
    type: file
    path: ./local-rules/telegram-ip.txt
rules: []
`)
	updated, _, err := RemoveLocalRuleProvider(source, "telegram-ip")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(updated), "rule-providers: {}\nrules: []\n") {
		t.Fatalf("unexpected config:\n%s", updated)
	}
	if _, err := ParseMihomoRouting(updated); err != nil {
		t.Fatalf("mutated YAML is invalid: %v", err)
	}
}
