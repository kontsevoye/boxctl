package config

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

var safeProviderCachePart = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// RuleProviderRelocation contains cache paths only. It deliberately omits the
// remote provider URL so it is safe to pass through runtime preparation and
// diagnostic errors without leaking subscription credentials.
type RuleProviderRelocation struct {
	Name            string
	ConfiguredPath  string
	MihomoCacheName string
	RuntimePath     string
}

// InjectMihomoProxyProviderHeaders adds device-identification headers to the
// private runtime document. The user-owned profile is never rewritten. Only
// HTTP providers receive headers, and an explicit per-provider value wins over
// the generated device default (matched case-insensitively).
func InjectMihomoProxyProviderHeaders(source []byte, headers map[string]string) ([]byte, error) {
	if len(headers) == 0 {
		return bytes.Clone(source), nil
	}
	document, root, err := mutableMihomoDocument(source)
	if err != nil {
		return nil, err
	}
	_, providers, _ := mappingEntry(root, "proxy-providers")
	if providers == nil {
		return bytes.Clone(source), nil
	}
	providers, ok := resolvedYAMLNode(providers)
	if !ok || providers.Kind != yaml.MappingNode {
		return nil, ErrUnsafeYAML
	}
	names := make([]string, 0, len(headers))
	for name, value := range headers {
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, "\r\n:") || strings.ContainsAny(value, "\r\n\x00") {
			return nil, errors.New("invalid proxy-provider runtime header")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for index := 0; index+1 < len(providers.Content); index += 2 {
		provider, resolved := resolvedYAMLNode(providers.Content[index+1])
		if !resolved || provider.Kind != yaml.MappingNode {
			return nil, ErrUnsafeYAML
		}
		if !strings.EqualFold(strings.TrimSpace(mappingScalar(provider, "type")), "http") {
			continue
		}
		_, headerMap, _ := mappingEntry(provider, "header")
		if headerMap == nil {
			headerMap = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			provider.Content = append(provider.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "header"},
				headerMap,
			)
		} else {
			headerMap, resolved = resolvedYAMLNode(headerMap)
			if !resolved || headerMap.Kind != yaml.MappingNode {
				return nil, ErrUnsafeYAML
			}
		}
		for _, name := range names {
			setHTTPHeaderNodeIfMissing(headerMap, name, headers[name])
		}
	}
	return encodeMutableMihomoDocument(document)
}

// RelocateMihomoHTTPRuleProviders points HTTP provider caches at a private
// runtime directory (normally under /tmp on OpenWrt). Existing configured
// paths are returned only as copy hints; this function performs no filesystem
// access and never follows user-controlled paths.
func RelocateMihomoHTTPRuleProviders(source []byte, runtimeDirectory string) ([]byte, []RuleProviderRelocation, error) {
	runtimeDirectory = strings.TrimRight(strings.TrimSpace(runtimeDirectory), "/")
	if runtimeDirectory == "" || !strings.HasPrefix(runtimeDirectory, "/") || strings.ContainsAny(runtimeDirectory, "\r\n\x00") {
		return nil, nil, errors.New("invalid rule-provider runtime directory")
	}
	document, root, err := mutableMihomoDocument(source)
	if err != nil {
		return nil, nil, err
	}
	_, providers, _ := mappingEntry(root, "rule-providers")
	if providers == nil {
		return bytes.Clone(source), []RuleProviderRelocation{}, nil
	}
	providers, ok := resolvedYAMLNode(providers)
	if !ok || providers.Kind != yaml.MappingNode {
		return nil, nil, ErrUnsafeYAML
	}
	relocations := make([]RuleProviderRelocation, 0)
	for index := 0; index+1 < len(providers.Content); index += 2 {
		nameNode := providers.Content[index]
		provider, resolved := resolvedYAMLNode(providers.Content[index+1])
		if nameNode.Kind != yaml.ScalarNode || !resolved || provider.Kind != yaml.MappingNode {
			return nil, nil, ErrUnsafeYAML
		}
		providerType := mappingScalar(provider, "type")
		if !strings.EqualFold(strings.TrimSpace(providerType), "http") {
			continue
		}
		format := strings.ToLower(strings.TrimSpace(mappingScalar(provider, "format")))
		extension := ".yaml"
		if format == "mrs" {
			extension = ".mrs"
		}
		configuredPath := mappingScalar(provider, "path")
		sourceURL := strings.TrimSpace(mappingScalar(provider, "url"))
		runtimePath := runtimeDirectory + "/" + providerRuntimeFileName(nameNode.Value, configuredPath, sourceURL, extension)
		cacheName := ""
		if strings.TrimSpace(configuredPath) == "" {
			if sourceURL != "" {
				//nolint:gosec // Compatibility with Mihomo's GetPathByHash cache layout.
				digest := md5.Sum([]byte(sourceURL))
				cacheName = hex.EncodeToString(digest[:])
			}
		}
		setMappingScalar(provider, "path", runtimePath)
		relocations = append(relocations, RuleProviderRelocation{
			Name: nameNode.Value, ConfiguredPath: configuredPath, MihomoCacheName: cacheName, RuntimePath: runtimePath,
		})
	}
	if len(relocations) == 0 {
		return bytes.Clone(source), relocations, nil
	}
	updated, err := encodeMutableMihomoDocument(document)
	return updated, relocations, err
}

func mutableMihomoDocument(source []byte) (*yaml.Node, *yaml.Node, error) {
	if len(source) == 0 || len(source) > maxMihomoRoutingConfigBytes {
		return nil, nil, ErrUnsafeYAML
	}
	decoder := yaml.NewDecoder(bytes.NewReader(source))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || len(document.Content) != 1 {
		return nil, nil, ErrUnsafeYAML
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, nil, ErrUnsafeYAML
	}
	root, ok := resolvedYAMLNode(document.Content[0])
	if !ok || root.Kind != yaml.MappingNode {
		return nil, nil, ErrUnsafeYAML
	}
	return &document, root, nil
}

func encodeMutableMihomoDocument(document *yaml.Node) ([]byte, error) {
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(document); err != nil {
		return nil, fmt.Errorf("encode Mihomo runtime document: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("close Mihomo runtime encoder: %w", err)
	}
	return output.Bytes(), nil
}

func setHTTPHeaderNodeIfMissing(mapping *yaml.Node, name, value string) {
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if strings.EqualFold(mapping.Content[index].Value, name) {
			return
		}
	}
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name},
		stringSequenceNode(value),
	)
}

func stringSequenceNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}}}
}

func mappingScalar(mapping *yaml.Node, name string) string {
	_, value, _ := mappingEntry(mapping, name)
	if value == nil || value.Kind != yaml.ScalarNode {
		return ""
	}
	return value.Value
}

func setMappingScalar(mapping *yaml.Node, name, value string) {
	_, current, _ := mappingEntry(mapping, name)
	if current != nil {
		*current = yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
		return
	}
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value},
	)
}

func providerRuntimeFileName(name, configuredPath, sourceURL, extension string) string {
	// The remote URL can contain credentials, so keep it out of the readable
	// portion while still binding the runtime cache to its exact source. This
	// prevents a provider renamed in place (same name, new URL/path) from
	// inheriting bytes fetched for the previous source.
	digest := sha256.Sum256([]byte(name + "\x00" + configuredPath + "\x00" + sourceURL))
	clean := strings.Trim(safeProviderCachePart.ReplaceAllString(name, "-"), ".-_")
	if clean == "" {
		clean = "provider"
	}
	if len(clean) > 48 {
		clean = clean[:48]
	}
	return clean + "-" + hex.EncodeToString(digest[:8]) + extension
}
