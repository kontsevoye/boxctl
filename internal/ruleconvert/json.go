package ruleconvert

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// JSON rule sets accept the comments and trailing commas supported by native
// sing-box. Removing them must never modify quoted patterns or URLs.
func cleanJSON(data []byte) ([]byte, error) {
	result := append([]byte(nil), data...)
	quoted, escaped := false, false
	for i := 0; i < len(result); i++ {
		b := result[i]
		if quoted {
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				quoted = false
			}
			continue
		}
		if b == '"' {
			quoted = true
			continue
		}
		if b != '/' || i+1 >= len(result) {
			continue
		}
		if result[i+1] == '/' {
			result[i] = ' '
			i++
			for i < len(result) && result[i] != '\n' {
				result[i] = ' '
				i++
			}
			continue
		}
		if result[i+1] == '*' {
			result[i] = ' '
			i++
			result[i] = ' '
			closed := false
			for i++; i < len(result); i++ {
				if result[i] == '*' && i+1 < len(result) && result[i+1] == '/' {
					result[i] = ' '
					i++
					result[i] = ' '
					closed = true
					break
				}
				if result[i] != '\n' {
					result[i] = ' '
				}
			}
			if !closed {
				return nil, errors.New("unterminated JSON comment")
			}
		}
	}
	quoted, escaped = false, false
	for i, b := range result {
		if quoted {
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				quoted = false
			}
			continue
		}
		if b == '"' {
			quoted = true
			continue
		}
		if b == ',' {
			tail := bytes.TrimSpace(result[i+1:])
			if len(tail) > 0 && (tail[0] == ']' || tail[0] == '}') {
				result[i] = ' '
			}
		}
	}
	return result, nil
}
func nativeSingSource(data []byte) (singDocument, error) {
	cleaned, err := cleanJSON(data)
	if err != nil {
		return singDocument{}, err
	}
	var doc singDocument
	decoder := json.NewDecoder(bytes.NewReader(cleaned))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&doc); err != nil {
		return doc, errors.New("invalid sing-box source JSON")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return doc, errors.New("unexpected content after sing-box source JSON")
	}
	if doc.Version < 1 || doc.Version > 5 || len(doc.Rules) == 0 {
		return doc, errors.New("invalid sing-box rule-set version or empty rules")
	}
	allowed := map[string]bool{}
	for _, key := range []string{"type", "mode", "rules", "invert", "query_type", "network", "domain", "domain_suffix", "domain_keyword", "domain_regex", "source_ip_cidr", "ip_cidr", "source_port", "source_port_range", "port", "port_range", "process_name", "process_path", "process_path_regex", "package_name", "package_name_regex", "network_type", "network_is_expensive", "network_is_constrained", "network_interface_address", "default_interface_address", "wifi_ssid", "wifi_bssid"} {
		allowed[key] = true
	}
	var validate func(map[string]json.RawMessage, int) error
	validate = func(rule map[string]json.RawMessage, depth int) error {
		if depth > maxDepth {
			return errors.New("logical nesting exceeds limit")
		}
		for key := range rule {
			if !allowed[key] {
				return errors.New("unknown sing-box headless rule field: " + key)
			}
		}
		if nested, ok := rule["rules"]; ok {
			var children []map[string]json.RawMessage
			if json.Unmarshal(nested, &children) != nil {
				return errors.New("invalid nested rules")
			}
			for _, child := range children {
				if err := validate(child, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, rule := range doc.Rules {
		if err = validate(rule, 0); err != nil {
			return doc, err
		}
	}
	return doc, nil
}
