package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

const maxMihomoRoutingConfigBytes = 32 << 20

var (
	// ErrInvalidMihomoRouting reports that a native Mihomo document cannot be
	// represented by the narrow, read-only routing model. The parser deliberately
	// does not include the offending YAML value in the returned error because the
	// same document may also contain controller and provider credentials.
	ErrInvalidMihomoRouting = errors.New("invalid Mihomo routing configuration")
	// ErrInvalidMihomoRule reports malformed top-level Mihomo CSV rule syntax.
	ErrInvalidMihomoRule = errors.New("invalid Mihomo rule")
	// ErrMihomoAutoInputsTooLarge reports that the bounded AUTO collector would
	// have to retain more unique inline destinations or provider references than
	// its caller permits.
	ErrMihomoAutoInputsTooLarge = errors.New("mihomo AUTO inputs exceed entry limit")
)

// MihomoRouting is the non-secret subset of a Mihomo document needed to build
// a firewall destination policy. It is read-only: parsing never rewrites the
// source document and ignores all unrelated native options.
type MihomoRouting struct {
	DNS           MihomoRoutingDNS              `yaml:"dns"`
	Rules         []string                      `yaml:"rules"`
	RuleProviders map[string]MihomoRuleProvider `yaml:"rule-providers"`
}

// MihomoRoutingDNS keeps pointers for scalars whose absence has different
// native-default semantics from an explicitly empty or false value.
type MihomoRoutingDNS struct {
	Enabled          *bool    `yaml:"enable"`
	EnhancedMode     *string  `yaml:"enhanced-mode"`
	FakeIPRange      *string  `yaml:"fake-ip-range"`
	FakeIPFilterMode *string  `yaml:"fake-ip-filter-mode"`
	FakeIPFilter     []string `yaml:"fake-ip-filter"`
}

// MihomoRuleProvider is the generator-facing subset of one rule-provider.
// Path is only metadata here; this package never opens provider files or URLs.
type MihomoRuleProvider struct {
	Type     string   `yaml:"type"`
	Behavior string   `yaml:"behavior"`
	Format   string   `yaml:"format"`
	URL      string   `yaml:"url"`
	Path     string   `yaml:"path"`
	Payload  []string `yaml:"payload"`
}

// ParseMihomoRouting resolves ordinary YAML anchors and merge keys into a
// narrow routing model. It rejects multiple documents and non-mapping roots so
// callers cannot accidentally construct a partial allow-list from an
// ambiguous native configuration.
func ParseMihomoRouting(source []byte) (MihomoRouting, error) {
	if len(source) == 0 {
		return MihomoRouting{}, fmt.Errorf("%w: empty document", ErrInvalidMihomoRouting)
	}
	if len(source) > maxMihomoRoutingConfigBytes {
		return MihomoRouting{}, fmt.Errorf("%w: document exceeds %d bytes", ErrInvalidMihomoRouting, maxMihomoRoutingConfigBytes)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(source))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return MihomoRouting{}, fmt.Errorf("%w: YAML cannot be decoded", ErrInvalidMihomoRouting)
	}
	if len(document.Content) != 1 {
		return MihomoRouting{}, fmt.Errorf("%w: document has no root mapping", ErrInvalidMihomoRouting)
	}
	root, ok := resolvedYAMLNode(document.Content[0])
	if !ok || root.Kind != yaml.MappingNode {
		return MihomoRouting{}, fmt.Errorf("%w: root is not a mapping", ErrInvalidMihomoRouting)
	}

	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return MihomoRouting{}, fmt.Errorf("%w: multiple YAML documents are not supported", ErrInvalidMihomoRouting)
		}
		return MihomoRouting{}, fmt.Errorf("%w: trailing YAML cannot be decoded", ErrInvalidMihomoRouting)
	}

	var result MihomoRouting
	if err := document.Decode(&result); err != nil {
		return MihomoRouting{}, fmt.Errorf("%w: routing fields have an incompatible type", ErrInvalidMihomoRouting)
	}
	if result.Rules == nil {
		result.Rules = []string{}
	}
	if result.RuleProviders == nil {
		result.RuleProviders = map[string]MihomoRuleProvider{}
	}
	if result.DNS.FakeIPFilter == nil {
		result.DNS.FakeIPFilter = []string{}
	}
	return result, nil
}

func resolvedYAMLNode(node *yaml.Node) (*yaml.Node, bool) {
	seen := make(map[*yaml.Node]struct{})
	for node != nil && node.Kind == yaml.AliasNode {
		if _, exists := seen[node]; exists {
			return nil, false
		}
		seen[node] = struct{}{}
		node = node.Alias
	}
	return node, node != nil
}

// MihomoRule is a parsed top-level CSV rule. Arguments excludes the rule type,
// outbound action and recognized trailing options such as no-resolve. Logical
// sub-rules remain intact as one argument.
type MihomoRule struct {
	Raw       string
	Type      string
	Arguments []string
	Action    string
	Options   []string
}

// ParseMihomoRule parses commas only at the top level. Commas inside balanced
// parentheses/brackets/braces, quoted fields, and escaped characters are left
// inside the field, which is required for logical and regular-expression rules.
func ParseMihomoRule(raw string) (MihomoRule, error) {
	fields, err := splitMihomoRuleFields(raw)
	if err != nil {
		return MihomoRule{}, err
	}
	if len(fields) < 2 {
		return MihomoRule{}, fmt.Errorf("%w: rule has no action", ErrInvalidMihomoRule)
	}

	actionIndex := len(fields) - 1
	for actionIndex > 0 && isMihomoRuleOption(fields[actionIndex]) {
		actionIndex--
	}
	if actionIndex == 0 || fields[actionIndex] == "" {
		return MihomoRule{}, fmt.Errorf("%w: rule has no action", ErrInvalidMihomoRule)
	}
	typeName := strings.ToUpper(strings.TrimSpace(fields[0]))
	if typeName == "" {
		return MihomoRule{}, fmt.Errorf("%w: rule has no type", ErrInvalidMihomoRule)
	}

	return MihomoRule{
		Raw:       raw,
		Type:      typeName,
		Arguments: append([]string(nil), fields[1:actionIndex]...),
		Action:    fields[actionIndex],
		Options:   append([]string(nil), fields[actionIndex+1:]...),
	}, nil
}

// MihomoAutoInputs contains only information available directly from rules.
// Provider content is intentionally left for a separate bounded reader.
type MihomoAutoInputs struct {
	InlineIPv4    []netip.Prefix
	ProviderNames []string
}

// CollectMihomoAutoInputs returns top-level, non-DIRECT IP-CIDR destinations
// and provider names referenced by top-level, non-DIRECT RULE-SET rules.
// Results are de-duplicated while preserving first appearance order. Each
// collection is bounded independently so a large config cannot allocate an
// unbounded intermediate result before provider content is inspected.
func CollectMihomoAutoInputs(rules []string, maxEntries int) (MihomoAutoInputs, error) {
	if maxEntries <= 0 {
		return MihomoAutoInputs{}, ErrMihomoAutoInputsTooLarge
	}
	result := MihomoAutoInputs{
		InlineIPv4:    []netip.Prefix{},
		ProviderNames: []string{},
	}
	seenPrefixes := make(map[netip.Prefix]struct{})
	seenProviders := make(map[string]struct{})

	for _, raw := range rules {
		rule, err := ParseMihomoRule(raw)
		if err != nil {
			return MihomoAutoInputs{}, err
		}
		switch rule.Type {
		case "IP-CIDR":
			if len(rule.Arguments) != 1 {
				return MihomoAutoInputs{}, fmt.Errorf("%w: IP-CIDR requires one destination", ErrInvalidMihomoRule)
			}
			prefix, err := parseMihomoIPv4Prefix(rule.Arguments[0])
			if err != nil {
				return MihomoAutoInputs{}, err
			}
			if strings.EqualFold(rule.Action, "DIRECT") || !prefix.IsValid() {
				continue
			}
			prefix = prefix.Masked()
			if _, exists := seenPrefixes[prefix]; !exists {
				if len(result.InlineIPv4) >= maxEntries {
					return MihomoAutoInputs{}, ErrMihomoAutoInputsTooLarge
				}
				seenPrefixes[prefix] = struct{}{}
				result.InlineIPv4 = append(result.InlineIPv4, prefix)
			}
		case "RULE-SET":
			if len(rule.Arguments) != 1 {
				return MihomoAutoInputs{}, fmt.Errorf("%w: RULE-SET requires one provider name", ErrInvalidMihomoRule)
			}
			if strings.EqualFold(rule.Action, "DIRECT") {
				continue
			}
			name := strings.TrimSpace(rule.Arguments[0])
			if name == "" {
				return MihomoAutoInputs{}, fmt.Errorf("%w: RULE-SET provider name is empty", ErrInvalidMihomoRule)
			}
			if _, exists := seenProviders[name]; !exists {
				if len(result.ProviderNames) >= maxEntries {
					return MihomoAutoInputs{}, ErrMihomoAutoInputsTooLarge
				}
				seenProviders[name] = struct{}{}
				result.ProviderNames = append(result.ProviderNames, name)
			}
		}
	}
	return result, nil
}

func parseMihomoIPv4Prefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	prefix, err := netip.ParsePrefix(value)
	if err == nil {
		if !prefix.Addr().Is4() {
			return netip.Prefix{}, nil
		}
		return prefix.Masked(), nil
	}
	address, addressErr := netip.ParseAddr(value)
	if addressErr == nil {
		if !address.Is4() {
			return netip.Prefix{}, nil
		}
		return netip.PrefixFrom(address, 32), nil
	}
	return netip.Prefix{}, fmt.Errorf("%w: IP-CIDR destination is not an IP prefix", ErrInvalidMihomoRule)
}

func isMihomoRuleOption(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "no-resolve")
}

func splitMihomoRuleFields(raw string) ([]string, error) {
	if !utf8.ValidString(raw) {
		return nil, fmt.Errorf("%w: rule is not UTF-8", ErrInvalidMihomoRule)
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%w: rule is empty", ErrInvalidMihomoRule)
	}

	fields := make([]string, 0, 4)
	stack := make([]rune, 0, 4)
	start := 0
	var quote rune
	escaped := false
	tokenStart := true
	for index, current := range raw {
		if escaped {
			escaped = false
			continue
		}
		if current == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if current == quote {
				if quote == '\'' && index+1 < len(raw) && raw[index+1] == '\'' {
					escaped = true
					continue
				}
				quote = 0
			}
			continue
		}
		if (current == '\'' || current == '"') && tokenStart {
			quote = current
			tokenStart = false
			continue
		}
		switch current {
		case '(', '[', '{':
			stack = append(stack, current)
			tokenStart = true
		case ')', ']', '}':
			if len(stack) == 0 || !matchingMihomoDelimiter(stack[len(stack)-1], current) {
				return nil, fmt.Errorf("%w: rule delimiters are unbalanced", ErrInvalidMihomoRule)
			}
			stack = stack[:len(stack)-1]
			tokenStart = false
		case ',':
			if len(stack) == 0 {
				field, err := normalizeMihomoRuleField(raw[start:index])
				if err != nil {
					return nil, err
				}
				fields = append(fields, field)
				start = index + 1
			}
			tokenStart = true
		default:
			if current != ' ' && current != '\t' && current != '\r' && current != '\n' {
				tokenStart = false
			}
		}
	}
	if escaped || quote != 0 || len(stack) != 0 {
		return nil, fmt.Errorf("%w: rule quoting or delimiters are unbalanced", ErrInvalidMihomoRule)
	}
	field, err := normalizeMihomoRuleField(raw[start:])
	if err != nil {
		return nil, err
	}
	fields = append(fields, field)
	for _, field := range fields {
		if field == "" {
			return nil, fmt.Errorf("%w: rule contains an empty field", ErrInvalidMihomoRule)
		}
	}
	return fields, nil
}

func matchingMihomoDelimiter(open, close rune) bool {
	return open == '(' && close == ')' || open == '[' && close == ']' || open == '{' && close == '}'
}

func normalizeMihomoRuleField(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) < 2 {
		return value, nil
	}
	if value[0] == '"' && value[len(value)-1] == '"' {
		unquoted, err := strconv.Unquote(value)
		if err != nil {
			return "", fmt.Errorf("%w: quoted field is invalid", ErrInvalidMihomoRule)
		}
		return strings.TrimSpace(unquoted), nil
	}
	if value[0] == '\'' && value[len(value)-1] == '\'' {
		return strings.TrimSpace(strings.ReplaceAll(value[1:len(value)-1], "''", "'")), nil
	}
	return value, nil
}
