// Package config prepares engine-specific runtime configurations without
// modifying user-owned source files.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrUnsafeYAML is returned when a managed value cannot be changed without a
// risk of changing unrelated YAML semantics. Callers must not fall back to a
// best-effort rewrite when this error is returned.
var ErrUnsafeYAML = errors.New("managed YAML cannot be patched safely")

// MihomoCaptureMode describes the five capture layouts understood by Mihomo.
type MihomoCaptureMode string

const (
	MihomoCaptureTPROXY MihomoCaptureMode = "tproxy"
	MihomoCaptureHybrid MihomoCaptureMode = "hybrid"
	MihomoCaptureTUN    MihomoCaptureMode = "tun"
	MihomoCaptureMixed  MihomoCaptureMode = "mixed"
	MihomoCaptureMixed2 MihomoCaptureMode = "mixed2"
)

// MihomoCapture contains the small subset of capture-related configuration
// that boxctl owns. Zero ports use boxctl's established defaults.
type MihomoCapture struct {
	Mode         MihomoCaptureMode
	TProxyPort   uint16
	RedirectPort uint16
	TUNDevice    string
	TUNStack     string
}

// MihomoPatch is deliberately narrow. All fields outside this list remain
// byte-for-byte identical to the source configuration.
type MihomoPatch struct {
	Capture            *MihomoCapture
	ExternalController *string
	Secret             *string
	DNSEnabled         *bool
	DNSListen          *string
	RoutingMark        *uint32
}

// SensitiveString holds a secret read from a user profile. Its default text,
// Go-syntax, JSON and text representations are redacted; callers must opt in
// explicitly through Reveal when they need to pass the value to Mihomo.
type SensitiveString struct {
	value string
}

// Reveal returns the underlying value. Keep the result out of logs, errors and
// serialized state.
func (s SensitiveString) Reveal() string {
	return s.value
}

// Empty reports whether the underlying secret is empty.
func (s SensitiveString) Empty() bool {
	return s.value == ""
}

func (SensitiveString) String() string {
	return "[REDACTED]"
}

func (SensitiveString) GoString() string {
	return "[REDACTED]"
}

func (SensitiveString) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED]"`), nil
}

func (SensitiveString) MarshalText() ([]byte, error) {
	return []byte("[REDACTED]"), nil
}

// MihomoManagedValues is the read-side view of values boxctl may need during
// a runtime patch. Pointers distinguish an absent key from an explicit
// zero/false/empty value. Secret is deliberately excluded from struct JSON.
type MihomoManagedValues struct {
	ExternalController  *string          `json:"externalController,omitempty"`
	Secret              *SensitiveString `json:"-"`
	RoutingMark         *uint32          `json:"routingMark,omitempty"`
	TProxyPort          *uint16          `json:"tproxyPort,omitempty"`
	RedirectPort        *uint16          `json:"redirectPort,omitempty"`
	DNSEnabled          *bool            `json:"dnsEnabled,omitempty"`
	DNSListen           *string          `json:"dnsListen,omitempty"`
	DNSEnhancedMode     *string          `json:"dnsEnhancedMode,omitempty"`
	DNSFakeIPRange      *string          `json:"dnsFakeIPRange,omitempty"`
	DNSFakeIPFilterMode *string          `json:"dnsFakeIPFilterMode,omitempty"`
	TUNEnabled          *bool            `json:"tunEnabled,omitempty"`
	TUNDevice           *string          `json:"tunDevice,omitempty"`
	TUNStack            *string          `json:"tunStack,omitempty"`
}

func (v MihomoManagedValues) String() string {
	return fmt.Sprintf(
		"MihomoManagedValues{externalController:%s secret:%s routingMark:%s tproxyPort:%s redirectPort:%s dnsEnabled:%s dnsListen:%s dnsEnhancedMode:%s dnsFakeIPRange:%s dnsFakeIPFilterMode:%s tunEnabled:%s tunDevice:%s tunStack:%s}",
		presence(v.ExternalController), secretPresence(v.Secret), presence(v.RoutingMark), presence(v.TProxyPort),
		presence(v.RedirectPort), presence(v.DNSEnabled), presence(v.DNSListen), presence(v.DNSEnhancedMode), presence(v.DNSFakeIPRange), presence(v.DNSFakeIPFilterMode),
		presence(v.TUNEnabled), presence(v.TUNDevice), presence(v.TUNStack),
	)
}

func (v MihomoManagedValues) GoString() string {
	return v.String()
}

func presence[T any](value *T) string {
	if value == nil {
		return "absent"
	}
	return "set"
}

func secretPresence(value *SensitiveString) string {
	if value == nil {
		return "absent"
	}
	return "[REDACTED]"
}

type patchAction uint8

const (
	patchSet patchAction = iota + 1
	patchDelete
)

type scalarPatch struct {
	key            string
	action         patchAction
	value          string
	onlyIfExisting bool
}

type nestedPatch struct {
	parent         string
	key            string
	action         patchAction
	value          string
	createParent   bool
	onlyIfExisting bool
}

// PatchMihomo returns a runtime configuration with only boxctl-managed keys
// changed. It is a surgical YAML editor rather than a serializer: comments,
// ordering, quoting and all unowned values are preserved.
func PatchMihomo(source []byte, patch MihomoPatch) ([]byte, error) {
	doc, err := parseDocument(source)
	if err != nil {
		return nil, err
	}

	top, nested, err := buildMihomoPatches(patch)
	if err != nil {
		return nil, err
	}
	if len(top) == 0 && len(nested) == 0 {
		return bytes.Clone(source), nil
	}
	if err := doc.requireBlockMappingRoot(); err != nil {
		return nil, err
	}
	if err := doc.validatePatchScopes(top, nested); err != nil {
		return nil, err
	}

	for _, op := range top {
		if err := doc.applyTopLevel(op); err != nil {
			return nil, err
		}
	}
	for _, op := range nested {
		if err := doc.applyNested(op); err != nil {
			return nil, err
		}
	}

	return doc.bytes(), nil
}

// InspectMihomo extracts only the managed controller, capture and DNS values
// from a profile. It shares PatchMihomo's conservative parser and fails closed
// on YAML constructs (merges, complex keys, flow mappings, aliases or block
// scalars) whose effective managed value cannot be proven without a full YAML
// resolver.
func InspectMihomo(source []byte) (MihomoManagedValues, error) {
	doc, err := parseDocument(source)
	if err != nil {
		return MihomoManagedValues{}, err
	}
	if err := doc.requireBlockMappingRoot(); err != nil {
		return MihomoManagedValues{}, err
	}

	topKeys := []string{"external-controller", "secret", "routing-mark", "tproxy-port", "redir-port"}
	top, err := doc.inspectTopScope(topKeys)
	if err != nil {
		return MihomoManagedValues{}, err
	}
	dns, err := doc.inspectNestedScope("dns", []string{"enable", "listen", "enhanced-mode", "fake-ip-range", "fake-ip-filter-mode"})
	if err != nil {
		return MihomoManagedValues{}, err
	}
	tun, err := doc.inspectNestedScope("tun", []string{"enable", "device", "stack"})
	if err != nil {
		return MihomoManagedValues{}, err
	}

	result := MihomoManagedValues{}
	if result.ExternalController, err = top.stringValue("external-controller"); err != nil {
		return MihomoManagedValues{}, err
	}
	secret, err := top.stringValue("secret")
	if err != nil {
		return MihomoManagedValues{}, err
	}
	if secret != nil {
		result.Secret = &SensitiveString{value: *secret}
	}
	if result.RoutingMark, err = top.uint32Value("routing-mark"); err != nil {
		return MihomoManagedValues{}, err
	}
	if result.TProxyPort, err = top.uint16Value("tproxy-port"); err != nil {
		return MihomoManagedValues{}, err
	}
	if result.RedirectPort, err = top.uint16Value("redir-port"); err != nil {
		return MihomoManagedValues{}, err
	}
	if result.DNSEnabled, err = dns.boolValue("enable"); err != nil {
		return MihomoManagedValues{}, err
	}
	if result.DNSListen, err = dns.stringValue("listen"); err != nil {
		return MihomoManagedValues{}, err
	}
	if result.DNSEnhancedMode, err = dns.stringValue("enhanced-mode"); err != nil {
		return MihomoManagedValues{}, err
	}
	if result.DNSFakeIPRange, err = dns.stringValue("fake-ip-range"); err != nil {
		return MihomoManagedValues{}, err
	}
	if result.DNSFakeIPFilterMode, err = dns.stringValue("fake-ip-filter-mode"); err != nil {
		return MihomoManagedValues{}, err
	}
	if result.TUNEnabled, err = tun.boolValue("enable"); err != nil {
		return MihomoManagedValues{}, err
	}
	if result.TUNDevice, err = tun.stringValue("device"); err != nil {
		return MihomoManagedValues{}, err
	}
	if result.TUNStack, err = tun.stringValue("stack"); err != nil {
		return MihomoManagedValues{}, err
	}
	return result, nil
}

// WriteMihomoRuntime writes a private, atomic runtime copy. sourcePath and
// destinationPath must be different so a caller can never mutate the user's
// profile accidentally.
func WriteMihomoRuntime(sourcePath, destinationPath string, patch MihomoPatch) error {
	sourceAbs, err := filepath.Abs(sourcePath)
	if err != nil {
		return fmt.Errorf("resolve source config: %w", err)
	}
	destinationAbs, err := filepath.Abs(destinationPath)
	if err != nil {
		return fmt.Errorf("resolve runtime config: %w", err)
	}
	if filepath.Clean(sourceAbs) == filepath.Clean(destinationAbs) {
		return errors.New("runtime config must not replace source config")
	}

	info, err := os.Stat(sourcePath)
	if err != nil {
		return fmt.Errorf("stat source config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("source config is not a regular file")
	}

	const maxConfigSize = 32 << 20
	if info.Size() > maxConfigSize {
		return fmt.Errorf("source config exceeds %d bytes", maxConfigSize)
	}
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("read source config: %w", err)
	}
	if len(source) > maxConfigSize {
		return fmt.Errorf("source config exceeds %d bytes", maxConfigSize)
	}
	runtimeConfig, err := PatchMihomo(source, patch)
	if err != nil {
		return err
	}

	dir := filepath.Dir(destinationPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create runtime config directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".mihomo-config-*")
	if err != nil {
		return fmt.Errorf("create temporary runtime config: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("protect temporary runtime config: %w", err)
	}
	if _, err := tmp.Write(runtimeConfig); err != nil {
		return fmt.Errorf("write temporary runtime config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary runtime config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary runtime config: %w", err)
	}
	if err := os.Rename(tmpName, destinationPath); err != nil {
		return fmt.Errorf("install runtime config: %w", err)
	}
	committed = true
	return nil
}

func buildMihomoPatches(patch MihomoPatch) ([]scalarPatch, []nestedPatch, error) {
	var top []scalarPatch
	var nested []nestedPatch
	if patch.ExternalController != nil {
		if err := validateSingleLine("external controller", *patch.ExternalController); err != nil {
			return nil, nil, err
		}
		top = append(top, scalarPatch{key: "external-controller", action: patchSet, value: yamlString(*patch.ExternalController)})
	}
	if patch.Secret != nil {
		if err := validateSingleLine("controller secret", *patch.Secret); err != nil {
			return nil, nil, err
		}
		top = append(top, scalarPatch{key: "secret", action: patchSet, value: yamlString(*patch.Secret)})
	}
	if patch.RoutingMark != nil {
		if *patch.RoutingMark == 0 {
			return nil, nil, errors.New("routing mark must be non-zero")
		}
		top = append(top, scalarPatch{key: "routing-mark", action: patchSet, value: strconv.FormatUint(uint64(*patch.RoutingMark), 10)})
	}
	if patch.DNSEnabled != nil {
		nested = append(nested, nestedPatch{parent: "dns", key: "enable", action: patchSet, value: strconv.FormatBool(*patch.DNSEnabled), createParent: true})
	}
	if patch.DNSListen != nil {
		if err := validateSingleLine("DNS listen address", *patch.DNSListen); err != nil {
			return nil, nil, err
		}
		nested = append(nested, nestedPatch{parent: "dns", key: "listen", action: patchSet, value: yamlString(*patch.DNSListen), createParent: true})
	}

	if patch.Capture == nil {
		return top, nested, nil
	}
	capture := *patch.Capture
	if capture.TProxyPort == 0 {
		capture.TProxyPort = 7894
	}
	if capture.RedirectPort == 0 {
		capture.RedirectPort = 7893
	}
	if capture.TUNDevice == "" {
		capture.TUNDevice = "clash-tun"
	}
	if capture.TUNStack == "" {
		capture.TUNStack = "system"
	}
	if !validTUNDevice(capture.TUNDevice) {
		return nil, nil, fmt.Errorf("invalid TUN device %q", capture.TUNDevice)
	}
	switch capture.TUNStack {
	case "system", "gvisor", "mixed":
	default:
		return nil, nil, fmt.Errorf("unsupported Mihomo TUN stack %q", capture.TUNStack)
	}

	setTProxy := func() {
		top = append(top, scalarPatch{key: "tproxy-port", action: patchSet, value: strconv.Itoa(int(capture.TProxyPort))})
	}
	setRedirect := func() {
		top = append(top, scalarPatch{key: "redir-port", action: patchSet, value: strconv.Itoa(int(capture.RedirectPort))})
	}
	deleteTProxy := func() {
		top = append(top, scalarPatch{key: "tproxy-port", action: patchDelete, onlyIfExisting: true})
	}
	deleteRedirect := func() {
		top = append(top, scalarPatch{key: "redir-port", action: patchDelete, onlyIfExisting: true})
	}
	setTUN := func(enabled bool, create bool) {
		nested = append(nested, nestedPatch{parent: "tun", key: "enable", action: patchSet, value: strconv.FormatBool(enabled), createParent: create})
		if !enabled {
			return
		}
		nested = append(nested,
			nestedPatch{parent: "tun", key: "device", action: patchSet, value: yamlString(capture.TUNDevice), createParent: true},
			nestedPatch{parent: "tun", key: "stack", action: patchSet, value: yamlString(capture.TUNStack), createParent: true},
			nestedPatch{parent: "tun", key: "auto-route", action: patchSet, value: "false", createParent: true},
			nestedPatch{parent: "tun", key: "auto-redirect", action: patchSet, value: "false", createParent: true},
			nestedPatch{parent: "tun", key: "auto-detect-interface", action: patchSet, value: "false", createParent: true},
		)
	}

	switch capture.Mode {
	case MihomoCaptureTPROXY:
		setTProxy()
		deleteRedirect()
		setTUN(false, false)
	case MihomoCaptureHybrid:
		setTProxy()
		setRedirect()
		setTUN(false, false)
	case MihomoCaptureTUN:
		deleteTProxy()
		deleteRedirect()
		setTUN(true, true)
	case MihomoCaptureMixed:
		setTProxy()
		deleteRedirect()
		setTUN(true, true)
	case MihomoCaptureMixed2:
		deleteTProxy()
		setRedirect()
		setTUN(true, true)
	default:
		return nil, nil, fmt.Errorf("unsupported Mihomo capture mode %q", capture.Mode)
	}
	return top, nested, nil
}

func validateSingleLine(label, value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("%s contains a newline", label)
	}
	return nil
}

func validTUNDevice(value string) bool {
	if len(value) == 0 || len(value) > 15 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

// JSON string syntax is a valid YAML double-quoted scalar and avoids all YAML
// plain-scalar ambiguities (comments, booleans, anchors and tags).
func yamlString(value string) string {
	return strconv.Quote(value)
}

type yamlDocument struct {
	lines        []string
	newline      string
	finalNewline bool
}

func parseDocument(source []byte) (*yamlDocument, error) {
	if bytes.HasPrefix(source, []byte{0xef, 0xbb, 0xbf}) {
		return nil, fmt.Errorf("%w: UTF-8 BOM is not supported", ErrUnsafeYAML)
	}
	newline := "\n"
	if bytes.Contains(source, []byte("\r\n")) {
		newline = "\r\n"
		withoutCRLF := bytes.ReplaceAll(source, []byte("\r\n"), nil)
		if bytes.ContainsRune(withoutCRLF, '\r') || bytes.ContainsRune(withoutCRLF, '\n') {
			return nil, fmt.Errorf("%w: mixed newline styles", ErrUnsafeYAML)
		}
	} else if bytes.ContainsRune(source, '\r') {
		return nil, fmt.Errorf("%w: bare carriage returns", ErrUnsafeYAML)
	}

	raw := string(source)
	finalNewline := strings.HasSuffix(raw, newline)
	if finalNewline {
		raw = strings.TrimSuffix(raw, newline)
	}
	var lines []string
	if raw != "" {
		lines = strings.Split(raw, newline)
	}
	for index, line := range lines {
		prefix := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		if strings.ContainsRune(prefix, '\t') {
			return nil, fmt.Errorf("%w: tab indentation on line %d", ErrUnsafeYAML, index+1)
		}
	}
	return &yamlDocument{lines: lines, newline: newline, finalNewline: finalNewline}, nil
}

func (d *yamlDocument) bytes() []byte {
	result := strings.Join(d.lines, d.newline)
	if d.finalNewline {
		result += d.newline
	}
	return []byte(result)
}

func (d *yamlDocument) requireBlockMappingRoot() error {
	docStarted := false
	seenContent := false
	docEnded := false
	for _, line := range d.lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "%") {
			continue
		}
		if line == "---" {
			if docStarted || seenContent || docEnded {
				return fmt.Errorf("%w: multiple YAML documents", ErrUnsafeYAML)
			}
			docStarted = true
			continue
		}
		if line == "..." {
			if docEnded {
				return fmt.Errorf("%w: multiple YAML document terminators", ErrUnsafeYAML)
			}
			docEnded = true
			continue
		}
		if docEnded {
			return fmt.Errorf("%w: content after YAML document terminator", ErrUnsafeYAML)
		}
		if strings.HasPrefix(line, "{") || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "?") {
			return fmt.Errorf("%w: root must be a block mapping", ErrUnsafeYAML)
		}
		seenContent = true
	}
	return nil
}

type mappingLine struct {
	key       string
	indent    int
	colon     int
	value     string
	commentAt int
}

func parseMappingLine(line string) (mappingLine, bool) {
	indent := len(line) - len(strings.TrimLeft(line, " "))
	rest := line[indent:]
	if rest == "" || strings.HasPrefix(rest, "#") || strings.HasPrefix(rest, "-") || strings.HasPrefix(rest, "?") {
		return mappingLine{}, false
	}

	colon := mappingColon(rest)
	if colon < 0 {
		return mappingLine{}, false
	}
	rawKey := strings.TrimSpace(rest[:colon])
	key, ok := decodeSimpleYAMLKey(rawKey)
	if !ok {
		return mappingLine{}, false
	}
	valuePart := rest[colon+1:]
	commentAt := yamlCommentIndex(valuePart)
	valueOnly := valuePart
	if commentAt >= 0 {
		valueOnly = valuePart[:commentAt]
	}
	return mappingLine{
		key:       key,
		indent:    indent,
		colon:     indent + colon,
		value:     strings.TrimSpace(valueOnly),
		commentAt: commentAt,
	}, true
}

func mappingColon(value string) int {
	inSingle := false
	inDouble := false
	escaped := false
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if inDouble {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		if inSingle {
			if ch == '\'' {
				if i+1 < len(value) && value[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
			continue
		}
		switch ch {
		case '"':
			inDouble = true
		case '\'':
			inSingle = true
		case ':':
			if i+1 == len(value) || value[i+1] == ' ' || value[i+1] == '\t' || value[i+1] == '#' {
				return i
			}
		}
	}
	return -1
}

func decodeSimpleYAMLKey(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	if raw == "<<" {
		return raw, true
	}
	if raw[0] == '"' {
		decoded, err := strconv.Unquote(raw)
		return decoded, err == nil
	}
	if raw[0] == '\'' {
		if len(raw) < 2 || raw[len(raw)-1] != '\'' {
			return "", false
		}
		return strings.ReplaceAll(raw[1:len(raw)-1], "''", "'"), true
	}
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return "", false
	}
	return raw, true
}

func yamlCommentIndex(value string) int {
	inSingle := false
	inDouble := false
	escaped := false
	depth := 0
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if inDouble {
			if escaped {
				escaped = false
				continue
			}
			switch ch {
			case '\\':
				escaped = true
			case '"':
				inDouble = false
			}
			continue
		}
		if inSingle {
			if ch == '\'' {
				if i+1 < len(value) && value[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
			continue
		}
		switch ch {
		case '"':
			inDouble = true
		case '\'':
			inSingle = true
		case '[', '{':
			depth++
		case ']', '}':
			if depth > 0 {
				depth--
			}
		case '#':
			if depth == 0 && (i == 0 || value[i-1] == ' ' || value[i-1] == '\t') {
				return i
			}
		}
	}
	return -1
}

func unsafeManagedScalar(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return true
	}
	switch trimmed[0] {
	case '|', '>', '{', '[', '&', '*', '!':
		return true
	default:
		return false
	}
}

type inspectScope struct {
	doc    *yamlDocument
	label  string
	start  int
	end    int
	indent int
}

func (d *yamlDocument) validatePatchScopes(top []scalarPatch, nested []nestedPatch) error {
	if len(top) > 0 {
		keys := make([]string, 0, len(top))
		for _, operation := range top {
			keys = append(keys, operation.key)
		}
		if _, err := d.inspectTopScope(keys); err != nil {
			return err
		}
	}
	parents := make(map[string][]string)
	for _, operation := range nested {
		parents[operation.parent] = append(parents[operation.parent], operation.key)
	}
	for parent, keys := range parents {
		if _, err := d.inspectNestedScope(parent, keys); err != nil {
			return err
		}
	}
	return nil
}

func (d *yamlDocument) inspectTopScope(keys []string) (inspectScope, error) {
	scope := inspectScope{doc: d, label: "top level", start: 0, end: len(d.lines), indent: 0}
	if err := scope.validateKeys(keys); err != nil {
		return inspectScope{}, err
	}
	return scope, nil
}

func (d *yamlDocument) inspectNestedScope(parent string, keys []string) (inspectScope, error) {
	top, err := d.inspectTopScope([]string{parent})
	if err != nil {
		return inspectScope{}, err
	}
	parents := d.mappingIndices(parent, top.indent, top.start, top.end)
	if len(parents) == 0 {
		return inspectScope{}, nil
	}
	parentIndex := parents[0]
	parsed, _ := parseMappingLine(d.lines[parentIndex])
	if parsed.value != "" {
		return inspectScope{}, fmt.Errorf("%w: managed mapping %q is not a block mapping", ErrUnsafeYAML, parent)
	}
	end := d.blockEnd(parentIndex, parsed.indent)
	childIndent := d.directChildIndent(parentIndex+1, end, parsed.indent)
	if childIndent < 0 {
		return inspectScope{}, nil
	}
	scope := inspectScope{
		doc:    d,
		label:  fmt.Sprintf("mapping %q", parent),
		start:  parentIndex + 1,
		end:    end,
		indent: childIndent,
	}
	if err := scope.validateKeys(keys); err != nil {
		return inspectScope{}, err
	}
	return scope, nil
}

func (s inspectScope) validateKeys(keys []string) error {
	if s.doc == nil {
		return nil
	}
	watched := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		watched[key] = struct{}{}
	}
	counts := make(map[string]int, len(keys))
	for index := s.start; index < s.end; index++ {
		line := s.doc.lines[index]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || trimmed == "---" || trimmed == "..." || strings.HasPrefix(trimmed, "%") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent != s.indent {
			continue
		}
		parsed, ok := parseMappingLine(line)
		if ok {
			if parsed.key == "<<" {
				return fmt.Errorf("%w: YAML merge in %s", ErrUnsafeYAML, s.label)
			}
			if _, watchedKey := watched[parsed.key]; watchedKey {
				counts[parsed.key]++
			}
			continue
		}

		// A sequence or complex/tagged/aliased key at a managed mapping
		// level can hide a semantically equivalent managed key. Without a
		// resolver, absence or uniqueness cannot be proven.
		rest := strings.TrimSpace(line)
		if rest == "" {
			continue
		}
		if strings.ContainsRune("-?!&*[{", rune(rest[0])) {
			return fmt.Errorf("%w: complex YAML entry in %s on line %d", ErrUnsafeYAML, s.label, index+1)
		}
		colon := mappingColon(rest)
		if colon < 0 {
			return fmt.Errorf("%w: non-mapping YAML entry in %s on line %d", ErrUnsafeYAML, s.label, index+1)
		}
		rawKey := strings.TrimSpace(rest[:colon])
		for key := range watched {
			if strings.Contains(rawKey, key) {
				return fmt.Errorf("%w: ambiguous key for %q in %s", ErrUnsafeYAML, key, s.label)
			}
		}
	}
	for key, count := range counts {
		if count > 1 {
			return fmt.Errorf("%w: duplicate key %q in %s", ErrUnsafeYAML, key, s.label)
		}
	}
	return nil
}

func (s inspectScope) rawValue(key string) (*string, error) {
	if s.doc == nil {
		return nil, nil
	}
	indices := s.doc.mappingIndices(key, s.indent, s.start, s.end)
	if len(indices) == 0 {
		return nil, nil
	}
	if len(indices) > 1 {
		return nil, fmt.Errorf("%w: duplicate key %q in %s", ErrUnsafeYAML, key, s.label)
	}
	index := indices[0]
	parsed, _ := parseMappingLine(s.doc.lines[index])
	if unsafeManagedScalar(parsed.value) || s.doc.hasIndentedContinuation(index, parsed.indent) {
		return nil, fmt.Errorf("%w: key %q in %s is not a simple scalar", ErrUnsafeYAML, key, s.label)
	}
	value, ok := decodeSimpleYAMLScalar(parsed.value)
	if !ok {
		return nil, fmt.Errorf("%w: key %q in %s has an ambiguous scalar", ErrUnsafeYAML, key, s.label)
	}
	return &value, nil
}

func (s inspectScope) stringValue(key string) (*string, error) {
	return s.rawValue(key)
}

func (s inspectScope) uint16Value(key string) (*uint16, error) {
	raw, err := s.rawValue(key)
	if err != nil || raw == nil {
		return nil, err
	}
	value, parseErr := strconv.ParseUint(*raw, 0, 16)
	if parseErr != nil {
		return nil, fmt.Errorf("%w: key %q in %s is not an unsigned 16-bit integer", ErrUnsafeYAML, key, s.label)
	}
	result := uint16(value)
	return &result, nil
}

func (s inspectScope) uint32Value(key string) (*uint32, error) {
	raw, err := s.rawValue(key)
	if err != nil || raw == nil {
		return nil, err
	}
	value, parseErr := strconv.ParseUint(*raw, 0, 32)
	if parseErr != nil {
		return nil, fmt.Errorf("%w: key %q in %s is not an unsigned 32-bit integer", ErrUnsafeYAML, key, s.label)
	}
	result := uint32(value)
	return &result, nil
}

func (s inspectScope) boolValue(key string) (*bool, error) {
	raw, err := s.rawValue(key)
	if err != nil || raw == nil {
		return nil, err
	}
	var result bool
	switch strings.ToLower(*raw) {
	case "true":
		result = true
	case "false":
		result = false
	default:
		return nil, fmt.Errorf("%w: key %q in %s is not a boolean", ErrUnsafeYAML, key, s.label)
	}
	return &result, nil
}

func decodeSimpleYAMLScalar(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", false
	}
	switch value[0] {
	case '"':
		decoded, err := strconv.Unquote(value)
		if err != nil {
			return "", false
		}
		return decoded, true
	case '\'':
		if len(value) < 2 || value[len(value)-1] != '\'' {
			return "", false
		}
		var decoded strings.Builder
		for index := 1; index < len(value)-1; index++ {
			if value[index] != '\'' {
				decoded.WriteByte(value[index])
				continue
			}
			if index+1 >= len(value)-1 || value[index+1] != '\'' {
				return "", false
			}
			decoded.WriteByte('\'')
			index++
		}
		return decoded.String(), true
	default:
		lower := strings.ToLower(value)
		if lower == "null" || value == "~" || unsafeManagedScalar(value) {
			return "", false
		}
		return value, true
	}
}

func (d *yamlDocument) applyTopLevel(op scalarPatch) error {
	indices := d.mappingIndices(op.key, 0, 0, len(d.lines))
	if len(indices) > 1 {
		return fmt.Errorf("%w: duplicate top-level key %q", ErrUnsafeYAML, op.key)
	}
	if len(indices) == 0 {
		if op.action == patchDelete || op.onlyIfExisting {
			return nil
		}
		d.insert(d.documentEnd(), op.key+": "+op.value)
		return nil
	}
	index := indices[0]
	parsed, _ := parseMappingLine(d.lines[index])
	if unsafeManagedScalar(parsed.value) || d.hasIndentedContinuation(index, parsed.indent) {
		return fmt.Errorf("%w: top-level key %q is not a simple scalar", ErrUnsafeYAML, op.key)
	}
	if op.action == patchDelete {
		d.lines = append(d.lines[:index], d.lines[index+1:]...)
		return nil
	}
	d.lines[index] = replaceScalar(d.lines[index], parsed, op.value)
	return nil
}

func (d *yamlDocument) applyNested(op nestedPatch) error {
	parents := d.mappingIndices(op.parent, 0, 0, len(d.lines))
	if len(parents) > 1 {
		return fmt.Errorf("%w: duplicate top-level mapping %q", ErrUnsafeYAML, op.parent)
	}
	if len(parents) == 0 {
		if !op.createParent || op.onlyIfExisting || op.action == patchDelete {
			return nil
		}
		at := d.documentEnd()
		d.insert(at, op.parent+":", "  "+op.key+": "+op.value)
		return nil
	}

	parentIndex := parents[0]
	parent, _ := parseMappingLine(d.lines[parentIndex])
	if parent.value != "" {
		return fmt.Errorf("%w: managed mapping %q uses flow/alias/scalar syntax", ErrUnsafeYAML, op.parent)
	}
	end := d.blockEnd(parentIndex, parent.indent)
	childIndent := d.directChildIndent(parentIndex+1, end, parent.indent)
	if childIndent < 0 {
		childIndent = parent.indent + 2
	}
	indices := d.mappingIndices(op.key, childIndent, parentIndex+1, end)
	if len(indices) > 1 {
		return fmt.Errorf("%w: duplicate key %q inside %q", ErrUnsafeYAML, op.key, op.parent)
	}
	if len(indices) == 0 {
		if op.action == patchDelete || op.onlyIfExisting {
			return nil
		}
		d.insert(end, strings.Repeat(" ", childIndent)+op.key+": "+op.value)
		return nil
	}
	index := indices[0]
	parsed, _ := parseMappingLine(d.lines[index])
	if unsafeManagedScalar(parsed.value) || d.hasIndentedContinuation(index, parsed.indent) {
		return fmt.Errorf("%w: key %q inside %q is not a simple scalar", ErrUnsafeYAML, op.key, op.parent)
	}
	if op.action == patchDelete {
		d.lines = append(d.lines[:index], d.lines[index+1:]...)
		return nil
	}
	d.lines[index] = replaceScalar(d.lines[index], parsed, op.value)
	return nil
}

func replaceScalar(line string, parsed mappingLine, value string) string {
	afterColon := line[parsed.colon+1:]
	leadingLen := len(afterColon) - len(strings.TrimLeft(afterColon, " \t"))
	leading := afterColon[:leadingLen]
	if leading == "" {
		leading = " "
	}
	suffix := ""
	if parsed.commentAt >= 0 {
		commentStart := parsed.commentAt
		for commentStart > 0 && (afterColon[commentStart-1] == ' ' || afterColon[commentStart-1] == '\t') {
			commentStart--
		}
		suffix = afterColon[commentStart:]
	} else {
		trimmedRight := strings.TrimRight(afterColon, " \t")
		suffix = afterColon[len(trimmedRight):]
	}
	return line[:parsed.colon+1] + leading + value + suffix
}

func (d *yamlDocument) mappingIndices(key string, indent, start, end int) []int {
	var result []int
	for i := start; i < end; i++ {
		parsed, ok := parseMappingLine(d.lines[i])
		if ok && parsed.indent == indent && parsed.key == key {
			result = append(result, i)
		}
	}
	return result
}

func (d *yamlDocument) hasIndentedContinuation(index, indent int) bool {
	for i := index + 1; i < len(d.lines); i++ {
		trimmed := strings.TrimSpace(d.lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lineIndent := len(d.lines[i]) - len(strings.TrimLeft(d.lines[i], " "))
		return lineIndent > indent
	}
	return false
}

func (d *yamlDocument) blockEnd(parentIndex, parentIndent int) int {
	for i := parentIndex + 1; i < len(d.lines); i++ {
		trimmed := strings.TrimSpace(d.lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(d.lines[i]) - len(strings.TrimLeft(d.lines[i], " "))
		if indent <= parentIndent {
			return i
		}
	}
	return len(d.lines)
}

func (d *yamlDocument) directChildIndent(start, end, parentIndent int) int {
	minimum := -1
	for i := start; i < end; i++ {
		trimmed := strings.TrimSpace(d.lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(d.lines[i]) - len(strings.TrimLeft(d.lines[i], " "))
		if indent > parentIndent && (minimum < 0 || indent < minimum) {
			minimum = indent
		}
	}
	return minimum
}

func (d *yamlDocument) documentEnd() int {
	for i, line := range d.lines {
		if line == "..." {
			return i
		}
	}
	return len(d.lines)
}

func (d *yamlDocument) insert(index int, lines ...string) {
	d.lines = append(d.lines, make([]string, len(lines))...)
	copy(d.lines[index+len(lines):], d.lines[index:len(d.lines)-len(lines)])
	copy(d.lines[index:index+len(lines)], lines)
}
