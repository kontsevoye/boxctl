// Package ruleconvert translates remote rule sets without silently dropping
// conditions. Native core commands own binary serialization.
package ruleconvert

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

const MaxBytes = 32 << 20
const maxDepth = 64

type predicate struct {
	Kind, Value string
	Children    []predicate
}

func logical(kind string, children []predicate) predicate {
	if len(children) == 1 && kind != "not" {
		return children[0]
	}
	return predicate{Kind: kind, Children: children}
}

// parseText recognizes the native provider grammar, not the file extension.
func parseText(data []byte, behavior string) ([]predicate, error) {
	if len(data) > MaxBytes {
		return nil, errors.New("rule set exceeds size limit")
	}
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, []byte{239, 187, 191}))
	var lines []string
	probe := trimmed
	for bytes.HasPrefix(probe, []byte("#")) {
		_, rest, found := bytes.Cut(probe, []byte("\n"))
		if !found {
			break
		}
		probe = bytes.TrimSpace(rest)
	}
	if bytes.HasPrefix(probe, []byte("payload:")) || bytes.HasPrefix(probe, []byte("---")) || bytes.HasPrefix(probe, []byte("{")) {
		var doc struct {
			Payload []yaml.Node `yaml:"payload"`
		}
		dec := yaml.NewDecoder(bytes.NewReader(trimmed))
		dec.KnownFields(true)
		if err := dec.Decode(&doc); err != nil {
			return nil, errors.New("invalid Mihomo YAML payload")
		}
		var extra any
		if !errors.Is(dec.Decode(&extra), io.EOF) {
			return nil, errors.New("multiple YAML documents are unsupported")
		}
		for _, item := range doc.Payload {
			if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
				return nil, errors.New("mihomo payload entries must be strings")
			}
			lines = append(lines, item.Value)
		}
	} else {
		scanner := bufio.NewScanner(bytes.NewReader(trimmed))
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil, errors.New("rule line exceeds size limit")
		}
	}
	var rules []predicate
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		var p predicate
		var err error
		switch behavior {
		case "domain":
			p, err = domainPattern(line)
		case "ipcidr":
			p, err = cidrPredicate("ip_cidr", line)
		case "classical":
			p, err = parseClassical(line, 0)
		case "", "auto":
			if strings.Contains(line, ",") || line == "MATCH" {
				p, err = parseClassical(line, 0)
			} else if prefix, e := cidrPredicate("ip_cidr", line); e == nil {
				p = prefix
			} else {
				p, err = domainPattern(line)
			}
		default:
			return nil, errors.New("source behavior must be auto, domain, ipcidr or classical")
		}
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		rules = append(rules, p)
	}
	if len(rules) == 0 {
		return nil, errors.New("empty rule set")
	}
	return rules, nil
}
func cidrPredicate(kind, value string) (predicate, error) {
	var prefix netip.Prefix
	var err error
	if strings.Contains(value, "/") {
		prefix, err = netip.ParsePrefix(value)
	} else {
		var a netip.Addr
		a, err = netip.ParseAddr(value)
		if err == nil {
			prefix = netip.PrefixFrom(a, a.BitLen())
		}
	}
	if err != nil || !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
		return predicate{}, errors.New("invalid IP address or CIDR")
	}
	return predicate{Kind: kind, Value: prefix.Masked().String()}, nil
}
func domainPattern(value string) (predicate, error) {
	value = strings.ToLower(value)
	if strings.HasPrefix(value, "+.") && !strings.ContainsAny(value[2:], "*+") {
		if err := validDomain(value[2:]); err != nil {
			return predicate{}, err
		}
		return predicate{Kind: "domain_suffix", Value: value[2:]}, nil
	}
	if strings.HasPrefix(value, ".") && !strings.ContainsAny(value[1:], "*+") {
		if err := validDomain(value[1:]); err != nil {
			return predicate{}, err
		}
		return predicate{Kind: "domain_suffix", Value: value}, nil
	}
	if !strings.Contains(value, "*") {
		if err := validDomain(value); err != nil {
			return predicate{}, err
		}
		return predicate{Kind: "domain", Value: value}, nil
	}
	parts := strings.Split(value, ".")
	for i, part := range parts {
		if part != "*" {
			if err := validDomain(part); err != nil {
				return predicate{}, err
			}
			parts[i] = regexp.QuoteMeta(part)
		} else {
			parts[i] = "[^.]+"
		}
	}
	return predicate{Kind: "domain_regex", Value: "^" + strings.Join(parts, `\.`) + "$"}, nil
}
func validDomain(value string) error {
	if value == "" || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") || strings.ContainsAny(value, " \t\r\n/:,+*?()[]{}|\\\"'<>=#") {
		return errors.New("invalid or ambiguous domain; specify a native rule syntax")
	}
	return nil
}

var classicalFields = map[string]string{
	"DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix", "DOMAIN-KEYWORD": "domain_keyword", "DOMAIN-REGEX": "domain_regex",
	"IP-CIDR": "ip_cidr", "IP-CIDR6": "ip_cidr", "SRC-IP-CIDR": "source_ip_cidr", "DST-PORT": "port", "SRC-PORT": "source_port",
	"PROCESS-NAME": "process_name", "PROCESS-PATH": "process_path", "PROCESS-PATH-REGEX": "process_path_regex", "NETWORK": "network",
}

func parseClassical(text string, depth int) (predicate, error) {
	if depth > maxDepth {
		return predicate{}, errors.New("logical nesting exceeds limit")
	}
	kind, tail, has := strings.Cut(text, ",")
	kind = strings.ToUpper(strings.TrimSpace(kind))
	tail = strings.TrimSpace(tail)
	if kind == "MATCH" && !has {
		return predicate{}, errors.New("MATCH is not supported in native Mihomo rule providers")
	}
	if kind == "AND" || kind == "OR" || kind == "NOT" {
		if !strings.HasPrefix(tail, "(") || !strings.HasSuffix(tail, ")") {
			return predicate{}, errors.New("invalid logical rule")
		}
		items, err := splitLogical(tail[1 : len(tail)-1])
		if err != nil {
			return predicate{}, err
		}
		var children []predicate
		for _, item := range items {
			child, e := parseClassical(item, depth+1)
			if e != nil {
				return predicate{}, e
			}
			children = append(children, child)
		}
		if len(children) == 0 || (kind == "NOT" && len(children) != 1) {
			return predicate{}, errors.New("invalid logical operands")
		}
		return logical(strings.ToLower(kind), children), nil
	}
	if !has || tail == "" {
		return predicate{}, errors.New("invalid classical rule")
	}
	// no-resolve changes DNS evaluation, not just the set of addresses. It cannot
	// be encoded by a standalone sing-box headless rule and must not be discarded.
	if strings.HasSuffix(tail, ",no-resolve") {
		return predicate{}, errors.New("no-resolve requires routing/DNS configuration; cannot translate this rule set losslessly")
	}
	if kind == "PROCESS-NAME" || kind == "PROCESS-PATH-WILDCARD" {
		return predicate{}, errors.New("process name case folding or byte wildcard semantics have no portable sing-box equivalent")
	}
	if kind == "PROCESS-PATH" {
		return predicate{Kind: "process_path_regex", Value: `(?i:\A` + regexp.QuoteMeta(tail) + `\z)`}, nil
	}
	if kind == "DOMAIN-WILDCARD" {
		expression := regexp.QuoteMeta(strings.ToLower(tail))
		expression = strings.ReplaceAll(expression, `\*`, ".*")
		expression = strings.ReplaceAll(expression, `\?`, ".")
		return predicate{Kind: "domain_regex", Value: "^" + expression + "$"}, nil
	}
	field, ok := classicalFields[kind]
	if !ok {
		return predicate{}, fmt.Errorf("%.64s has no supported standalone target equivalent", kind)
	}
	if field == "domain_keyword" {
		tail = strings.ToLower(tail)
	}
	if field == "ip_cidr" || field == "source_ip_cidr" {
		return cidrPredicate(field, tail)
	}
	if field == "domain_suffix" {
		tail = strings.TrimPrefix(tail, ".")
	}
	if field == "domain" || field == "domain_suffix" {
		if err := validDomain(tail); err != nil {
			return predicate{}, err
		}
		tail = strings.ToLower(tail)
	}
	if strings.Contains(field, "regex") {
		if err := portableRegex(tail, field); err != nil {
			return predicate{}, err
		}
		tail = "(?i:" + tail + ")"
		if _, err := regexp.Compile(tail); err != nil {
			return predicate{}, errors.New("invalid regular expression")
		}
	}
	if field == "network" {
		tail = strings.ToLower(tail)
		if tail != "tcp" && tail != "udp" {
			return predicate{}, errors.New("unsupported network")
		}
	}
	if field == "port" || field == "source_port" {
		var children []predicate
		for _, part := range strings.Split(tail, "/") {
			p, err := portPredicate(field, strings.ReplaceAll(part, "-", ":"))
			if err != nil {
				return predicate{}, err
			}
			children = append(children, p)
		}
		return logical("or", children), nil
	}
	return predicate{Kind: field, Value: tail}, nil
}
func splitLogical(text string) ([]string, error) {
	var items []string
	for text != "" {
		if text[0] != '(' {
			return nil, errors.New("invalid logical operand")
		}
		level, end := 0, -1
		for i, c := range text {
			if c == '(' {
				level++
			}
			if c == ')' {
				level--
				if level == 0 {
					end = i
					break
				}
			}
		}
		if end < 0 {
			return nil, errors.New("unclosed logical operand")
		}
		items = append(items, text[1:end])
		text = text[end+1:]
		if text != "" {
			if text[0] != ',' {
				return nil, errors.New("invalid logical separator")
			}
			text = text[1:]
			if text == "" {
				return nil, errors.New("empty logical operand")
			}
		}
	}
	return items, nil
}
func portPredicate(kind, value string) (predicate, error) {
	if a, b, ok := strings.Cut(value, ":"); ok {
		low, high := 0, 65535
		var err error
		if a != "" {
			low, err = strconv.Atoi(a)
			if err != nil {
				return predicate{}, errors.New("invalid port range")
			}
		}
		if b != "" {
			high, err = strconv.Atoi(b)
			if err != nil {
				return predicate{}, errors.New("invalid port range")
			}
		}
		if low < 0 || high > 65535 || low > high {
			return predicate{}, errors.New("invalid port range")
		}
		return predicate{Kind: kind + "_range", Value: fmt.Sprintf("%d:%d", low, high)}, nil
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 0 || port > 65535 {
		return predicate{}, errors.New("invalid port")
	}
	return predicate{Kind: kind, Value: strconv.Itoa(port)}, nil
}

type singDocument struct {
	Version int                          `json:"version"`
	Rules   []map[string]json.RawMessage `json:"rules"`
}

func parseSing(data []byte) ([]predicate, error) {
	var doc singDocument
	cleaned, err := cleanJSON(data)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(cleaned))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, errors.New("invalid sing-box source JSON")
	}
	var extra any
	if !errors.Is(dec.Decode(&extra), io.EOF) {
		return nil, errors.New("trailing JSON data")
	}
	if doc.Version < 1 || doc.Version > 5 {
		return nil, errors.New("unsupported sing-box rule-set version")
	}
	var rules []predicate
	for i, r := range doc.Rules {
		p, err := singPredicate(r, 0)
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		rules = append(rules, p)
	}
	if len(rules) == 0 {
		return nil, errors.New("empty rule set")
	}
	return rules, nil
}
func singPredicate(raw map[string]json.RawMessage, depth int) (predicate, error) {
	if depth > maxDepth {
		return predicate{}, errors.New("logical nesting exceeds limit")
	}
	var typ string
	var invert bool
	if b, ok := raw["type"]; ok {
		if json.Unmarshal(b, &typ) != nil {
			return predicate{}, errors.New("invalid rule type")
		}
	}
	if b, ok := raw["invert"]; ok {
		if json.Unmarshal(b, &invert) != nil {
			return predicate{}, errors.New("invalid invert")
		}
	}
	var p predicate
	if typ == "logical" {
		for key := range raw {
			if key != "type" && key != "mode" && key != "rules" && key != "invert" {
				return p, fmt.Errorf("unsupported logical field %s", key)
			}
		}
		var mode string
		var children []map[string]json.RawMessage
		if json.Unmarshal(raw["mode"], &mode) != nil || (mode != "and" && mode != "or") || json.Unmarshal(raw["rules"], &children) != nil || len(children) == 0 {
			return p, errors.New("invalid logical rule")
		}
		var ps []predicate
		for _, child := range children {
			c, err := singPredicate(child, depth+1)
			if err != nil {
				return p, err
			}
			ps = append(ps, c)
		}
		p = logical(mode, ps)
	} else {
		if typ != "" && typ != "default" {
			return p, errors.New("unsupported rule type")
		}
		groups := map[string][]predicate{}
		keys := make([]string, 0, len(raw))
		for key := range raw {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if key == "type" || key == "invert" {
				continue
			}
			switch key {
			case "domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "source_ip_cidr", "port", "port_range", "source_port", "source_port_range", "network", "process_name", "process_path", "process_path_regex":
			default:
				return p, fmt.Errorf("field %s has no supported Mihomo rule-provider equivalent", key)
			}
			values, err := stringValues(raw[key], key == "port" || key == "source_port")
			if err != nil {
				return p, fmt.Errorf("invalid %s", key)
			}
			group := key
			switch key {
			case "domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr":
				group = "destination"
			case "port", "port_range":
				group = "port"
			case "source_port", "source_port_range":
				group = "source_port"
			}
			for _, value := range values {
				q := predicate{Kind: key, Value: value}
				if key == "ip_cidr" || key == "source_ip_cidr" {
					q, err = cidrPredicate(key, value)
				}
				if key == "port" || key == "source_port" {
					q, err = portPredicate(key, value)
				}
				if key == "port_range" || key == "source_port_range" {
					q, err = portPredicate(strings.TrimSuffix(key, "_range"), value)
				}
				if strings.Contains(key, "regex") {
					err = portableRegex(value, key)
				}
				if key == "domain" || key == "domain_suffix" {
					err = validDomain(strings.TrimPrefix(value, "."))
					q.Value = strings.ToLower(value)
				}
				if key == "network" && value != "tcp" && value != "udp" {
					err = errors.New("invalid network")
				}
				if err != nil {
					return p, fmt.Errorf("invalid %s", key)
				}
				groups[group] = append(groups[group], q)
			}
		}
		names := make([]string, 0, len(groups))
		for name := range groups {
			names = append(names, name)
		}
		sort.Strings(names)
		var ps []predicate
		for _, name := range names {
			ps = append(ps, logical("or", groups[name]))
		}
		if len(ps) == 0 {
			return p, errors.New("empty rule")
		}
		p = logical("and", ps)
	}
	if invert {
		p = logical("not", []predicate{p})
	}
	return p, nil
}
func stringValues(raw []byte, numeric bool) ([]string, error) {
	var values []any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if list, ok := v.([]any); ok {
		values = list
	} else {
		values = []any{v}
	}
	result := make([]string, 0, len(values))
	for _, v := range values {
		switch value := v.(type) {
		case string:
			result = append(result, value)
		case json.Number:
			if !numeric {
				return nil, errors.New("expected string")
			}
			result = append(result, value.String())
		default:
			return nil, errors.New("expected string or number")
		}
	}
	return result, nil
}
func singRule(p predicate) map[string]any {
	switch p.Kind {
	case "true":
		return map[string]any{"type": "logical", "mode": "or", "rules": []any{map[string]any{"network": "tcp"}, map[string]any{"network": "tcp", "invert": true}}}
	case "and", "or", "not":
		if p.Kind == "not" {
			result := singRule(p.Children[0])
			v, _ := result["invert"].(bool)
			result["invert"] = !v
			return result
		}
		children := make([]map[string]any, 0, len(p.Children))
		for _, c := range p.Children {
			children = append(children, singRule(c))
		}
		return map[string]any{"type": "logical", "mode": p.Kind, "rules": children}
	default:
		if p.Kind == "port" || p.Kind == "source_port" {
			value, _ := strconv.Atoi(p.Value)
			return map[string]any{p.Kind: []int{value}}
		}
		return map[string]any{p.Kind: []string{p.Value}}
	}
}
func encodeSing(rules []predicate) ([]byte, error) {
	// Group independent OR leaves into one native rule per field. Large domain/IP
	// lists must not become tens of thousands of separate logical objects.
	grouped := map[string][]string{}
	var result []map[string]any
	for _, p := range rules {
		if p.Kind == "true" {
			result = append(result, singRule(p))
			continue
		}
		if len(p.Children) == 0 && p.Kind != "port" && p.Kind != "source_port" {
			grouped[p.Kind] = append(grouped[p.Kind], p.Value)
		} else {
			result = append(result, singRule(p))
		}
	}
	keys := make([]string, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		result = append(result, map[string]any{key: grouped[key]})
	}
	return json.Marshal(map[string]any{"version": 3, "rules": result})
}
func outputBehavior(rules []predicate) string {
	behavior := ""
	var visit func(predicate) bool
	visit = func(p predicate) bool {
		if p.Kind == "or" {
			for _, c := range p.Children {
				if !visit(c) {
					return false
				}
			}
			return true
		}
		b := ""
		switch p.Kind {
		case "domain", "domain_suffix":
			b = "domain"
		case "ip_cidr":
			b = "ipcidr"
		default:
			return false
		}
		if behavior != "" && behavior != b {
			return false
		}
		behavior = b
		return true
	}
	for _, p := range rules {
		if !visit(p) {
			return "classical"
		}
	}
	return behavior
}
func mihomoText(rules []predicate, behavior string) ([]byte, error) {
	var lines []string
	var emit func(predicate) error
	emit = func(p predicate) error {
		if p.Kind == "or" {
			for _, c := range p.Children {
				if err := emit(c); err != nil {
					return err
				}
			}
			return nil
		}
		if behavior != "classical" {
			v := p.Value
			if p.Kind == "domain_suffix" && !strings.HasPrefix(v, ".") {
				v = "+." + v
			}
			lines = append(lines, v)
			return nil
		}
		line, err := classical(p)
		if err != nil {
			return err
		}
		lines = append(lines, line)
		return nil
	}
	for _, p := range rules {
		if err := emit(p); err != nil {
			return nil, err
		}
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}
func classical(p predicate) (string, error) {
	if p.Kind == "true" {
		return "OR,((NETWORK,tcp),(NOT,((NETWORK,tcp))))", nil
	}
	if len(p.Children) > 0 {
		var children []string
		for _, c := range p.Children {
			line, err := classical(c)
			if err != nil {
				return "", err
			}
			children = append(children, "("+line+")")
		}
		return strings.ToUpper(p.Kind) + ",(" + strings.Join(children, ",") + ")", nil
	}
	if p.Kind == "domain_suffix" && strings.HasPrefix(p.Value, ".") {
		v := strings.TrimPrefix(p.Value, ".")
		return "AND,((DOMAIN-SUFFIX," + v + "),(NOT,((DOMAIN," + v + "))))", nil
	}
	if p.Value != strings.TrimSpace(p.Value) {
		return "", errors.New("mihomo trims whitespace in rule values; cannot convert losslessly")
	}
	if strings.ContainsAny(p.Value, "\r\n") {
		return "", errors.New("mihomo text cannot represent newlines in rule values")
	}
	if p.Kind == "domain_regex" || p.Kind == "process_path_regex" {
		key := "DOMAIN-REGEX"
		if p.Kind == "process_path_regex" {
			key = "PROCESS-PATH-REGEX"
		}
		return key + ",(?-i:" + p.Value + ")", nil
	}
	if p.Kind == "process_name" || p.Kind == "process_path" {
		key := "PROCESS-NAME-REGEX"
		if p.Kind == "process_path" {
			key = "PROCESS-PATH-REGEX"
		}
		return key + `,(?-i:\A` + regexp.QuoteMeta(p.Value) + `\z)`, nil
	}
	if p.Kind == "domain_keyword" && (p.Value != strings.ToLower(p.Value) || strings.Contains(p.Value, ",")) {
		return "DOMAIN-REGEX,(?-i:" + regexp.QuoteMeta(p.Value) + ")", nil
	}
	if !strings.Contains(p.Kind, "regex") && strings.Contains(p.Value, ",") {
		return "", errors.New("mihomo cannot represent a comma in this rule value")
	}
	if p.Kind == "port_range" || p.Kind == "source_port_range" {
		key := "DST-PORT"
		if p.Kind == "source_port_range" {
			key = "SRC-PORT"
		}
		return key + "," + strings.ReplaceAll(p.Value, ":", "-"), nil
	}
	for native, kind := range classicalFields {
		if kind == p.Kind && native != "IP-CIDR6" {
			return native + "," + p.Value, nil
		}
	}
	return "", fmt.Errorf("unsupported predicate %s", p.Kind)
}

// The two cores use different regular-expression engines. This first converter
// accepts their common ASCII subset, preserving case explicitly. Constructs
// with different Unicode/boundary semantics are errors, never approximations.
func portableRegex(value, field string) error {
	if _, err := regexp.Compile(value); err != nil {
		return errors.New("regex is not supported by both engines")
	}
	if strings.Contains(value, "(?P<") || strings.Contains(value, "(?U") || strings.Contains(value, "(?-U") || strings.Contains(value, `\x{`) {
		return errors.New("regex syntax differs between engines")
	}
	if strings.Contains(value, "[:") {
		return errors.New("POSIX regex classes cannot be translated losslessly")
	}
	for _, c := range value {
		if c > 127 {
			return errors.New("non-ASCII regex requires engine-specific Unicode semantics")
		}
	}
	for i := 0; i < len(value); i++ {
		if value[i] == '(' && i+1 < len(value) && value[i+1] == '?' {
			for j := i + 2; j < len(value) && strings.ContainsRune("imsU-", rune(value[j])); j++ {
				if value[j] == 'U' {
					return errors.New("regex ungreedy flag differs between engines")
				}
			}
		}
		if value[i] == '\\' && i+1 < len(value) {
			i++
			if (value[i] >= '0' && value[i] <= '9') || ((value[i] >= 'A' && value[i] <= 'Z') || (value[i] >= 'a' && value[i] <= 'z')) && !strings.ContainsRune("nrtfavxAz", rune(value[i])) {
				return errors.New("regex character class or boundary has engine-specific semantics")
			}
		}
	}
	if field == "process_path_regex" && strings.Contains(value, "$") {
		return errors.New("process regex end-anchor semantics differ between engines")
	}
	return nil
}
