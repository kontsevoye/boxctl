package ruleconvert

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kontsevoye/boxctl/internal/state"
)

// ProfileOptions describes a native runtime, never the saved source profile.
type ProfileOptions struct {
	Target, Home string
	Binaries     Binaries
	LoopMark     uint32
}

func conversionURL(value string) (source, hint string, ok bool, err error) {
	if !strings.HasPrefix(value, "convert:") {
		return "", "", false, nil
	}
	source = strings.TrimPrefix(value, "convert:")
	for _, behavior := range []string{"domain", "ipcidr", "classical"} {
		if strings.HasPrefix(source, behavior+":") {
			hint = behavior
			source = strings.TrimPrefix(source, behavior+":")
			break
		}
	}
	_, err = parseURL(source)
	return source, hint, true, err
}

// Patch keeps the source URL extension private to boxctl and leaves intervals
// with the native cores. It registers persistent, format-pinned HTTP resources.
func (s *Service) Patch(ctx context.Context, document map[string]any, options ProfileOptions) error {
	var providers []map[string]any
	switch options.Target {
	case "sing-box":
		route, _ := document["route"].(map[string]any)
		list, _ := route["rule_set"].([]any)
		for _, raw := range list {
			p, _ := raw.(map[string]any)
			if p != nil {
				providers = append(providers, p)
			}
		}
	case "mihomo":
		all, _ := document["rule-providers"].(map[string]any)
		for _, raw := range all {
			p, _ := raw.(map[string]any)
			if p != nil {
				providers = append(providers, p)
			}
		}
	default:
		return errors.New("unknown profile engine")
	}
	count := 0
	for _, p := range providers {
		raw, _ := p["url"].(string)
		sourceURL, hint, convert, err := conversionURL(raw)
		if err != nil {
			return err
		}
		if !convert {
			continue
		}
		count++
		if count > 128 {
			return errors.New("too many converted rule sets")
		}
		source := Source{URL: sourceURL, Target: options.Target, Hint: hint, Binaries: options.Binaries, LoopMark: options.LoopMark}
		detour := ""
		if options.Target == "sing-box" {
			if p["type"] != "remote" {
				return errors.New("convert: requires a remote sing-box rule set")
			}
			if _, ok := p["tag"].(string); !ok {
				return errors.New("convert: currently requires a single rule-set tag")
			}
			client, err := singHTTPClient(document, p)
			if err != nil {
				return err
			}
			for key, value := range client {
				switch key {
				case "engine", "type":
					if value != "go" && value != "" {
						return errors.New("convert: only the go HTTP client is supported")
					}
				case "tag":
				case "version":
					if fmt.Sprint(value) != "2" && fmt.Sprint(value) != "1" {
						return errors.New("convert: HTTP versions other than 1.1 and 2 are unsupported")
					}
					source.HTTPVersion = fmt.Sprint(value)
				case "detour":
					detour, _ = value.(string)
				case "headers":
					source.Headers, err = readHeaders(value)
					if err != nil {
						return err
					}
				case "disable_version_fallback":
					if value != false {
						return errors.New("convert: disabling HTTP version fallback is unsupported")
					}
				case "routing_mark": // manager-owned loop-prevention mark
				default:
					return fmt.Errorf("convert: HTTP client field %s cannot be preserved by the downloader", key)
				}
			}
			if legacy, ok := p["download_detour"].(string); ok && legacy != "" {
				if detour != "" {
					return errors.New("conflicting download detours")
				}
				detour = legacy
			}
			if detour == "" {
				route, _ := document["route"].(map[string]any)
				detour, _ = route["final"].(string)
				if detour == "" {
					outbounds, _ := document["outbounds"].([]any)
					if len(outbounds) > 0 {
						first, _ := outbounds[0].(map[string]any)
						detour, _ = first["tag"].(string)
					}
				}
			}
		} else {
			if p["type"] != "http" {
				return errors.New("convert: requires a Mihomo HTTP rule-provider")
			}
			detour, _ = p["proxy"].(string)
			if headers, ok := p["header"]; ok {
				source.Headers, err = readHeaders(headers)
				if err != nil {
					return err
				}
			}
		}
		if !directDetour(document, options.Target, detour) {
			source.ProxyURL, err = s.addBridge(document, options, detour)
			if err != nil {
				return err
			}
		}
		initial, _ := p["initial_path"].(string)
		if options.Target == "mihomo" {
			initial, _ = p["path"].(string)
		}
		if initial != "" && !filepath.IsAbs(initial) {
			initial = filepath.Join(options.Home, initial)
		}
		record, err := s.Prepare(ctx, source, initial)
		if err != nil {
			return fmt.Errorf("convert: %w", err)
		}
		p["url"] = s.URL(record)
		if options.Target == "sing-box" {
			p["format"] = "binary"
			p["initial_path"] = s.InitialPath(record)
			delete(p, "download_detour")
			// A loopback download must never follow the remote download detour.
			p["http_client"] = map[string]any{"detour": ensureDirect(document, options.LoopMark)}
		} else {
			p["format"] = record.Format
			p["behavior"] = record.Behavior
			p["proxy"] = "DIRECT"
			delete(p, "header")
			cache := filepath.Join(options.Home, "rule-providers", "boxctl-convert-"+record.ID+"."+extension(record.Format))
			content, err := s.artifact(record)
			if err != nil {
				return err
			}
			if err = os.MkdirAll(filepath.Dir(cache), 0o700); err != nil {
				return err
			}
			if err = state.WriteFileAtomic(cache, content, 0o600); err != nil {
				return err
			}
			p["path"] = cache
		}
	}
	return nil
}
func singHTTPClient(document, p map[string]any) (map[string]any, error) {
	selected := p["http_client"]
	if selected == nil {
		selected = document["default_http_client"]
	}
	if object, ok := selected.(map[string]any); ok {
		return object, nil
	}
	name, _ := selected.(string)
	clients, _ := document["http_clients"].([]any)
	for i, raw := range clients {
		client, _ := raw.(map[string]any)
		if client["tag"] == name || (name == "" && i == 0) {
			return client, nil
		}
	}
	if name != "" {
		return nil, errors.New("unknown rule-set HTTP client")
	}
	return map[string]any{}, nil
}
func readHeaders(raw any) (http.Header, error) {
	object, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("invalid download headers")
	}
	headers := make(http.Header)
	for key, v := range object {
		if key == "" || strings.ContainsAny(key, "\r\n :") {
			return nil, errors.New("invalid download header name")
		}
		var values []string
		switch value := v.(type) {
		case string:
			values = []string{value}
		case []any:
			for _, item := range value {
				text, ok := item.(string)
				if !ok {
					return nil, errors.New("invalid download header value")
				}
				values = append(values, text)
			}
		default:
			return nil, errors.New("invalid download header value")
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				return nil, errors.New("invalid download header value")
			}
			headers.Add(key, value)
		}
	}
	return headers, nil
}
func directDetour(document map[string]any, target, tag string) bool {
	if target == "mihomo" {
		return tag == "" || tag == "DIRECT"
	}
	outbounds, _ := document["outbounds"].([]any)
	for _, raw := range outbounds {
		outbound, _ := raw.(map[string]any)
		if outbound["tag"] == tag && outbound["type"] == "direct" {
			// Direct outbounds with custom interface/address/resolver settings must use
			// the native bridge too; treating them as the manager network loses policy.
			for key := range outbound {
				if key != "tag" && key != "type" && key != "routing_mark" {
					return false
				}
			}
			return true
		}
	}
	return false
}
func ensureDirect(document map[string]any, mark uint32) string {
	const tag = "boxctl-rule-converter-direct"
	outbounds, _ := document["outbounds"].([]any)
	for _, raw := range outbounds {
		outbound, _ := raw.(map[string]any)
		if outbound["tag"] == tag {
			return tag
		}
	}
	document["outbounds"] = append(outbounds, map[string]any{"type": "direct", "tag": tag, "routing_mark": mark})
	return tag
}
func (s *Service) addBridge(document map[string]any, options ProfileOptions, detour string) (string, error) {
	if detour == "" {
		return "", errors.New("convert: could not determine the source download outbound")
	}
	if err := s.initialize(); err != nil {
		return "", err
	}
	h := hmac.New(sha256.New, []byte(s.listener.Secret))
	_, _ = h.Write([]byte(options.Target + ":" + detour))
	token := hex.EncodeToString(h.Sum(nil))
	username := "boxctl-rule-" + token[:16]
	password := token[16:]
	address := s.listener.BridgeAddress
	if options.Target == "mihomo" {
		var err error
		address, err = s.mihomoBridge(username)
		if err != nil {
			return "", err
		}
	}
	_, portText, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portText)
	name := "boxctl-rule-download-bridge"
	if options.Target == "mihomo" {
		name += "-" + token[:16]
	}
	if options.Target == "sing-box" {
		list, _ := document["inbounds"].([]any)
		var bridge map[string]any
		for _, raw := range list {
			item, _ := raw.(map[string]any)
			if item["tag"] == name {
				bridge = item
			}
		}
		if bridge == nil {
			bridge = map[string]any{"type": "mixed", "tag": name, "listen": "127.0.0.1", "listen_port": port}
			document["inbounds"] = append(list, bridge)
		}
		users, _ := bridge["users"].([]any)
		for _, raw := range users {
			user, _ := raw.(map[string]any)
			if user["username"] == username {
				return (&url.URL{Scheme: "http", Host: address, User: url.UserPassword(username, password)}).String(), nil
			}
		}
		users = append(users, map[string]any{"username": username, "password": password})
		bridge["users"] = users
		route, _ := document["route"].(map[string]any)
		rules, _ := route["rules"].([]any)
		route["rules"] = append([]any{map[string]any{"inbound": name, "auth_user": username, "action": "route", "outbound": detour}}, rules...)
	} else {
		list, _ := document["listeners"].([]any)
		var bridge map[string]any
		for _, raw := range list {
			item, _ := raw.(map[string]any)
			if item["name"] == name {
				bridge = item
			}
		}
		if bridge == nil {
			bridge = map[string]any{"type": "mixed", "name": name, "listen": "127.0.0.1", "port": port, "udp": false, "proxy": detour}
			document["listeners"] = append(list, bridge)
		}
		users, _ := bridge["users"].([]any)
		for _, raw := range users {
			user, _ := raw.(map[string]any)
			if user["username"] == username {
				return (&url.URL{Scheme: "http", Host: address, User: url.UserPassword(username, password)}).String(), nil
			}
		}
		bridge["users"] = append(users, map[string]any{"username": username, "password": password})

	}
	u := url.URL{Scheme: "http", Host: address, User: url.UserPassword(username, password)}
	return u.String(), nil
}

// IDsInRuntime reads only converter URLs belonging to this installation; the
// panel must never present inactive validation candidates as applied rules.
func (s *Service) IDsInRuntime(document map[string]any) []string {
	var ids []string
	var walk func(any)
	walk = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			for key, item := range v {
				if key == "url" {
					if raw, ok := item.(string); ok {
						prefix := "http://" + s.listener.Address + endpointPrefix
						if strings.HasPrefix(raw, prefix) {
							id, _, _ := strings.Cut(strings.TrimPrefix(raw, prefix), "/")
							if validID(id) {
								ids = append(ids, id)
							}
						}
					}
				}
				walk(item)
			}
		case []any:
			for _, item := range v {
				walk(item)
			}
		}
	}
	walk(document)
	return ids
}

func (s *Service) RuntimeStatus(document map[string]any) []Status {
	statuses := s.Status(s.IDsInRuntime(document))
	names := map[string][]string{}
	add := func(name string, p map[string]any) {
		raw, _ := p["url"].(string)
		for _, status := range statuses {
			if strings.Contains(raw, endpointPrefix+status.ID+"/") {
				names[status.ID] = append(names[status.ID], name)
			}
		}
	}
	route, _ := document["route"].(map[string]any)
	rules, _ := route["rule_set"].([]any)
	for _, raw := range rules {
		p, _ := raw.(map[string]any)
		tag, _ := p["tag"].(string)
		add(tag, p)
	}
	providers, _ := document["rule-providers"].(map[string]any)
	for name, raw := range providers {
		p, _ := raw.(map[string]any)
		add(name, p)
	}
	for i := range statuses {
		statuses[i].Name = strings.Join(names[statuses[i].ID], ", ")
	}
	return statuses
}
