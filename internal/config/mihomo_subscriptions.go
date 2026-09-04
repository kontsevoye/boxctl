package config

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// MihomoProxyProvider is one runtime-only boxctl-managed provider. URL and
// header values are written only to Mihomo's private mode-0600 runtime copy.
type MihomoProxyProvider struct {
	Name     string
	URL      string
	Path     string
	Interval time.Duration
	Headers  map[string]string
	Local    bool
}

// InjectMihomoProxyProviders appends isolated provider entries without
// serializing the rest of the user's YAML. Existing entries are never
// overwritten; ambiguous/flow mappings fail closed.
func InjectMihomoProxyProviders(source []byte, providers []MihomoProxyProvider) ([]byte, error) {
	if len(providers) == 0 {
		return append([]byte(nil), source...), nil
	}
	doc, err := parseDocument(source)
	if err != nil {
		return nil, err
	}
	if err := doc.requireBlockMappingRoot(); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(providers))
	seen := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		if err := validateMihomoProxyProvider(provider); err != nil {
			return nil, err
		}
		if _, duplicate := seen[provider.Name]; duplicate {
			return nil, fmt.Errorf("duplicate managed proxy provider %q", provider.Name)
		}
		seen[provider.Name] = struct{}{}
		names = append(names, provider.Name)
	}
	if _, err := doc.inspectNestedScope("proxy-providers", names); err != nil {
		return nil, err
	}
	parents := doc.mappingIndices("proxy-providers", 0, 0, len(doc.lines))
	if len(parents) > 1 {
		return nil, fmt.Errorf("%w: duplicate top-level mapping %q", ErrUnsafeYAML, "proxy-providers")
	}
	var parentIndex int
	childIndent := 2
	if len(parents) == 0 {
		parentIndex = doc.documentEnd()
		doc.insert(parentIndex, "proxy-providers:")
	} else {
		parentIndex = parents[0]
		parent, _ := parseMappingLine(doc.lines[parentIndex])
		if parent.value != "" {
			return nil, fmt.Errorf("%w: proxy-providers is not a block mapping", ErrUnsafeYAML)
		}
		end := doc.blockEnd(parentIndex, parent.indent)
		if existing := doc.directChildIndent(parentIndex+1, end, parent.indent); existing >= 0 {
			childIndent = existing
		} else {
			childIndent = parent.indent + 2
		}
	}
	for _, provider := range providers {
		end := doc.blockEnd(parentIndex, 0)
		if indices := doc.mappingIndices(provider.Name, childIndent, parentIndex+1, end); len(indices) != 0 {
			return nil, fmt.Errorf("%w: proxy provider %q already exists", ErrUnsafeYAML, provider.Name)
		}
		lines := renderMihomoProxyProvider(provider, childIndent)
		doc.insert(end, lines...)
	}
	return doc.bytes(), nil
}

func validateMihomoProxyProvider(provider MihomoProxyProvider) error {
	if !strings.HasPrefix(provider.Name, "boxctl-") || len(provider.Name) > 64 {
		return errors.New("managed proxy provider name is invalid")
	}
	for _, r := range provider.Name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return errors.New("managed proxy provider name is invalid")
	}
	if provider.Path == "" || strings.ContainsAny(provider.Path, "\r\n") {
		return errors.New("managed proxy provider path is invalid")
	}
	if provider.Interval < time.Hour || provider.Interval > 168*time.Hour {
		return errors.New("managed proxy provider interval is invalid")
	}
	if provider.Local {
		if provider.URL != "" {
			return errors.New("local managed proxy provider has a URL")
		}
		return nil
	}
	parsed, err := url.Parse(provider.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("managed proxy provider URL is invalid")
	}
	return nil
}

func renderMihomoProxyProvider(provider MihomoProxyProvider, indent int) []string {
	prefix := strings.Repeat(" ", indent)
	child := prefix + "  "
	lines := []string{prefix + provider.Name + ":"}
	if provider.Local {
		lines = append(lines, child+"type: file")
	} else {
		lines = append(lines, child+"type: http", child+"url: "+yamlString(provider.URL))
	}
	lines = append(lines, child+"path: "+yamlString(provider.Path))
	if !provider.Local {
		lines = append(lines, child+"interval: "+fmt.Sprintf("%d", int64(provider.Interval/time.Second)))
	}
	if len(provider.Headers) > 0 && !provider.Local {
		lines = append(lines, child+"header:")
		names := make([]string, 0, len(provider.Headers))
		for name := range provider.Headers {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			lines = append(lines, child+"  "+yamlString(name)+":", child+"    - "+yamlString(provider.Headers[name]))
		}
	}
	return lines
}
