package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	pathpkg "path"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

var (
	ErrLocalRuleProviderConflict  = errors.New("local rule provider name is already used")
	ErrUnsupportedYAMLSurgery     = errors.New("configuration layout cannot be edited safely")
	validLocalRuleListBindingName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

// LocalRuleListBinding describes how a user-owned local list is represented in
// the active Mihomo configuration. ConfigNameTaken distinguishes a managed
// local provider from an unrelated provider that happens to use the same name.
type LocalRuleListBinding struct {
	ProviderName    string
	InConfig        bool
	ConfigNameTaken bool
	InUse           bool
}

// LocalRuleProviderName is the stable name used by local lists in
// rule-providers and RULE-SET rules.
func LocalRuleProviderName(listName string) (string, error) {
	listName = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(listName, ".txt")))
	if !validLocalRuleListBindingName.MatchString(listName) {
		return "", fmt.Errorf("invalid local rule list name %q", listName)
	}
	return "local-" + listName, nil
}

// InspectLocalRuleListBinding reads only the rule-provider and rules sections;
// it never exposes or rewrites unrelated native configuration fields.
func InspectLocalRuleListBinding(source []byte, listName string) (LocalRuleListBinding, error) {
	providerName, err := LocalRuleProviderName(listName)
	if err != nil {
		return LocalRuleListBinding{}, err
	}
	routing, err := ParseMihomoRouting(source)
	if err != nil {
		return LocalRuleListBinding{}, err
	}
	binding := LocalRuleListBinding{ProviderName: providerName}
	if provider, exists := routing.RuleProviders[providerName]; exists {
		binding.InConfig = isManagedLocalRuleProvider(provider, listName)
		binding.ConfigNameTaken = !binding.InConfig
	}
	for _, raw := range routing.Rules {
		rule, parseErr := ParseMihomoRule(raw)
		if parseErr != nil {
			return LocalRuleListBinding{}, parseErr
		}
		if rule.Type == "RULE-SET" && len(rule.Arguments) == 1 && rule.Arguments[0] == providerName {
			binding.InUse = true
			break
		}
	}
	return binding, nil
}

// InsertLocalRuleProvider adds a classical text provider without re-encoding
// the user's YAML. The surgical edit preserves comments, ordering, anchors and
// all secret-bearing sections. Exotic flow/alias layouts fail closed.
func InsertLocalRuleProvider(source []byte, listName string) ([]byte, LocalRuleListBinding, error) {
	binding, err := InspectLocalRuleListBinding(source, listName)
	if err != nil {
		return nil, LocalRuleListBinding{}, err
	}
	if binding.InConfig {
		return append([]byte(nil), source...), binding, nil
	}
	if binding.ConfigNameTaken {
		return nil, binding, ErrLocalRuleProviderConflict
	}

	root, err := localRuleYAMLRoot(source)
	if err != nil {
		return nil, binding, err
	}
	key, providers, pairIndex := mappingEntry(root, "rule-providers")
	eol := sourceLineEnding(source)
	providerBlock := renderLocalRuleProvider(binding.ProviderName, strings.TrimSuffix(listName, ".txt"), 2, eol)
	if key == nil {
		result := append([]byte(nil), source...)
		if len(result) > 0 && !bytes.HasSuffix(result, []byte("\n")) {
			result = append(result, eol...)
		}
		if len(bytes.TrimSpace(result)) > 0 {
			result = append(result, eol...)
		}
		result = append(result, []byte("rule-providers:")...)
		result = append(result, eol...)
		result = append(result, providerBlock...)
		binding.InConfig = true
		return result, binding, nil
	}
	if providers == nil || providers.Kind != yaml.MappingNode || providers.Style&yaml.FlowStyle != 0 || providers.Alias != nil {
		return nil, binding, ErrUnsupportedYAMLSurgery
	}

	indent := key.Column - 1 + 2
	if len(providers.Content) > 0 {
		indent = providers.Content[0].Column - 1
	}
	providerBlock = renderLocalRuleProvider(binding.ProviderName, strings.TrimSuffix(listName, ".txt"), indent, eol)
	beforeLine := lineCount(source) + 1
	if pairIndex+2 < len(root.Content) {
		beforeLine = root.Content[pairIndex+2].Line
	}
	offset, ok := offsetAtLine(source, beforeLine)
	if !ok {
		return nil, binding, ErrUnsupportedYAMLSurgery
	}
	result := make([]byte, 0, len(source)+len(providerBlock))
	result = append(result, source[:offset]...)
	result = append(result, providerBlock...)
	result = append(result, source[offset:]...)
	binding.InConfig = true
	return result, binding, nil
}

// RemoveLocalRuleProvider removes only a provider proven to point at this
// local list. An unrelated provider with the same name is deliberately left
// untouched. RULE-SET references are reported through binding.InUse and remain
// user-owned and are reported to the caller.
func RemoveLocalRuleProvider(source []byte, listName string) ([]byte, LocalRuleListBinding, error) {
	binding, err := InspectLocalRuleListBinding(source, listName)
	if err != nil {
		return nil, LocalRuleListBinding{}, err
	}
	if !binding.InConfig {
		return append([]byte(nil), source...), binding, nil
	}
	root, err := localRuleYAMLRoot(source)
	if err != nil {
		return nil, binding, err
	}
	key, providers, pairIndex := mappingEntry(root, "rule-providers")
	if key == nil || providers == nil || providers.Kind != yaml.MappingNode || providers.Style&yaml.FlowStyle != 0 || providers.Alias != nil {
		return nil, binding, ErrUnsupportedYAMLSurgery
	}
	providerKey, _, providerIndex := mappingEntry(providers, binding.ProviderName)
	if providerKey == nil || providerIndex < 0 {
		return nil, binding, ErrUnsupportedYAMLSurgery
	}

	if len(providers.Content) == 2 {
		keyLineEnd := lineContentEnd(source, key.Line)
		endLine := lineCount(source) + 1
		if pairIndex+2 < len(root.Content) {
			endLine = root.Content[pairIndex+2].Line
		}
		endOffset, ok := offsetAtLine(source, endLine)
		if keyLineEnd < 0 || !ok || keyLineEnd > endOffset {
			return nil, binding, ErrUnsupportedYAMLSurgery
		}
		eol := sourceLineEnding(source)
		replacement := append([]byte(" {}"), eol...)
		result := make([]byte, 0, len(source)-(endOffset-keyLineEnd)+len(replacement))
		result = append(result, source[:keyLineEnd]...)
		result = append(result, replacement...)
		result = append(result, source[endOffset:]...)
		binding.InConfig = false
		return result, binding, nil
	}

	startOffset, ok := offsetAtLine(source, providerKey.Line)
	if !ok {
		return nil, binding, ErrUnsupportedYAMLSurgery
	}
	endLine := lineCount(source) + 1
	if providerIndex+2 < len(providers.Content) {
		endLine = providers.Content[providerIndex+2].Line
	} else if pairIndex+2 < len(root.Content) {
		endLine = root.Content[pairIndex+2].Line
	}
	endOffset, ok := offsetAtLine(source, endLine)
	if !ok || endOffset < startOffset {
		return nil, binding, ErrUnsupportedYAMLSurgery
	}
	result := make([]byte, 0, len(source)-(endOffset-startOffset))
	result = append(result, source[:startOffset]...)
	result = append(result, source[endOffset:]...)
	binding.InConfig = false
	return result, binding, nil
}

func isManagedLocalRuleProvider(provider MihomoRuleProvider, listName string) bool {
	if !strings.EqualFold(strings.TrimSpace(provider.Type), "file") {
		return false
	}
	configured := strings.TrimPrefix(pathpkg.Clean(strings.TrimSpace(provider.Path)), "./")
	want := pathpkg.Join("local-rules", strings.TrimSuffix(strings.TrimSpace(listName), ".txt")+".txt")
	return configured == want
}

func localRuleYAMLRoot(source []byte) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(source))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || len(document.Content) != 1 {
		return nil, ErrUnsupportedYAMLSurgery
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrUnsupportedYAMLSurgery
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode || root.Alias != nil || root.Style&yaml.FlowStyle != 0 {
		return nil, ErrUnsupportedYAMLSurgery
	}
	return root, nil
}

func mappingEntry(mapping *yaml.Node, name string) (key, value *yaml.Node, index int) {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil, nil, -1
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		candidate := mapping.Content[index]
		if candidate.Kind == yaml.ScalarNode && candidate.Value == name {
			return candidate, mapping.Content[index+1], index
		}
	}
	return nil, nil, -1
}

func renderLocalRuleProvider(providerName, listName string, indent int, eol []byte) []byte {
	outer := strings.Repeat(" ", indent)
	inner := strings.Repeat(" ", indent+2)
	lines := []string{
		outer + providerName + ":",
		inner + "type: file",
		inner + "behavior: classical",
		inner + "format: text",
		inner + "path: ./local-rules/" + listName + ".txt",
	}
	return []byte(strings.Join(lines, string(eol)) + string(eol))
}

func sourceLineEnding(source []byte) []byte {
	if bytes.Contains(source, []byte("\r\n")) {
		return []byte("\r\n")
	}
	return []byte("\n")
}

func lineCount(source []byte) int {
	if len(source) == 0 {
		return 0
	}
	count := bytes.Count(source, []byte("\n"))
	if !bytes.HasSuffix(source, []byte("\n")) {
		count++
	}
	return count
}

func offsetAtLine(source []byte, oneBased int) (int, bool) {
	if oneBased <= 0 {
		return 0, false
	}
	if oneBased == 1 {
		return 0, true
	}
	line := 1
	for index, character := range source {
		if character != '\n' {
			continue
		}
		line++
		if line == oneBased {
			return index + 1, true
		}
	}
	if oneBased == line+1 {
		return len(source), true
	}
	return 0, false
}

func lineContentEnd(source []byte, oneBased int) int {
	start, ok := offsetAtLine(source, oneBased)
	if !ok {
		return -1
	}
	end := bytes.IndexByte(source[start:], '\n')
	if end < 0 {
		end = len(source) - start
	}
	end += start
	if end > start && source[end-1] == '\r' {
		end--
	}
	return end
}
