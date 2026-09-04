package rulelist

import "strings"

// AutoPrefixContent applies the local-rule filename convention. Plain entries
// are converted to classical Mihomo rules while
// comments, empty lines and entries that already contain a rule prefix are
// preserved verbatim.
func AutoPrefixContent(name, content string) string {
	prefix := autoPrefixForName(name)
	if prefix == "" {
		return content
	}

	lines := strings.Split(content, "\n")
	for index, line := range lines {
		leading := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, ";") || strings.Contains(trimmed, ",") {
			continue
		}
		lines[index] = leading + prefix + "," + trimmed
	}
	return strings.Join(lines, "\n")
}

func autoPrefixForName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, ".txt")
	for _, candidate := range []struct {
		suffix string
		prefix string
	}{
		{suffix: "-src-ip", prefix: "SRC-IP-CIDR"},
		{suffix: "-domain", prefix: "DOMAIN-SUFFIX"},
		{suffix: "-keyword", prefix: "DOMAIN-KEYWORD"},
		{suffix: "-geosite", prefix: "GEOSITE"},
		{suffix: "-geoip", prefix: "GEOIP"},
		{suffix: "-ip", prefix: "IP-CIDR"},
	} {
		if strings.HasSuffix(name, candidate.suffix) {
			return candidate.prefix
		}
	}
	return ""
}
