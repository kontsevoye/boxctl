// Package fakeip manages the generated fake-IP destination allowlist.
package fakeip

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	// FileName is the stable name of the firewall allowlist.
	FileName = "fakeip-whitelist-ipcidr.txt"

	// AutoBeginMarker and AutoEndMarker delimit content owned by the generator.
	AutoBeginMarker = "# AUTO-BEGIN: generated from rule-providers — do not edit between markers"
	AutoEndMarker   = "# AUTO-END"
	AutoScopeMarker = "# Source scope: "

	// AutoScopeLocalOnly and AutoScopeAllProviders identify the source policy
	// used to build an AUTO block. Older blocks have an empty scope.
	AutoScopeLocalOnly    = "local-only"
	AutoScopeAllProviders = "all-providers"

	// MaxDocumentBytes bounds reads and writes on resource-constrained routers.
	MaxDocumentBytes = 4 << 20
	// MaxEntries prevents a valid but pathologically large list from consuming
	// excessive memory while it is parsed and installed into the firewall.
	MaxEntries = 65_536
)

var (
	ErrConflict         = errors.New("fake-IP whitelist revision conflict")
	ErrInvalidManual    = errors.New("invalid fake-IP whitelist manual content")
	ErrMalformedMarkers = errors.New("malformed fake-IP whitelist AUTO markers")
	ErrTooLarge         = errors.New("fake-IP whitelist exceeds size limit")
	ErrTooManyEntries   = errors.New("fake-IP whitelist exceeds entry limit")
	ErrUnsafePath       = errors.New("unsafe fake-IP whitelist path")
)

// Document is a parsed view of fakeip-whitelist-ipcidr.txt.
//
// Content and ManualContent retain the file's text. Prefix collections contain
// canonical, exactly de-duplicated IPv4 prefixes in lexical order. Contained
// subnets are deliberately not collapsed.
type Document struct {
	Content        string
	ManualContent  string
	Manual         []netip.Prefix
	Generated      []netip.Prefix
	Effective      []netip.Prefix
	Count          int
	ManualCount    int
	GeneratedCount int
	EffectiveCount int
	Revision       string
	GeneratedAt    time.Time
	GeneratedScope string
	HasGenerated   bool
}

// Store manages one fake-IP whitelist below Directory. A Store must not be
// copied after first use.
type Store struct {
	Directory string
	mu        sync.RWMutex
}

// Read returns the current document. A missing file is represented by an empty
// document with the revision of empty content.
func (s *Store) Read() (Document, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.readUnlocked()
}

// SaveManual replaces user-owned content while retaining an existing generated
// AUTO block byte-for-byte. The block is kept first so ManualContent remains a
// single editable value. revision must match the document returned by Read.
func (s *Store) SaveManual(content, revision string) (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, err := s.readUnlocked()
	if err != nil {
		return Document{}, err
	}
	if revision == "" || revision != current.Revision {
		return Document{}, ErrConflict
	}

	manual, _, err := validateManual(content)
	if err != nil {
		return Document{}, err
	}
	sections, err := splitSections(current.Content)
	if err != nil {
		return Document{}, err
	}

	next := manual
	if sections.hasGenerated {
		next = sections.generatedBlock
		if manual != "" {
			if !endsInLineBreak(next) {
				next += "\n"
			}
			next += manual
		}
	}
	return s.commitUnlocked(next, current.Revision)
}

// ReplaceGenerated atomically replaces the generated AUTO block. Manual text
// before and after an existing block is preserved byte-for-byte. If no block
// exists, the new block is prepended to the manual document. revision must
// match the document returned by Read. A zero generatedAt uses the current UTC
// time.
func (s *Store) ReplaceGenerated(prefixes []netip.Prefix, revision string, generatedAt time.Time) (Document, error) {
	return s.ReplaceGeneratedWithScope(prefixes, revision, generatedAt, "")
}

// ReplaceGeneratedWithScope is ReplaceGenerated with provenance for the
// generated inputs. The scope is stored as a comment inside the AUTO block so
// older readers continue to consume the file unchanged.
func (s *Store) ReplaceGeneratedWithScope(prefixes []netip.Prefix, revision string, generatedAt time.Time, scope string) (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, err := s.readUnlocked()
	if err != nil {
		return Document{}, err
	}
	if revision == "" || revision != current.Revision {
		return Document{}, ErrConflict
	}
	next, err := replacedGeneratedDocument(current, prefixes, generatedAt, scope)
	if err != nil {
		return Document{}, err
	}
	return s.commitUnlocked(next.Content, current.Revision)
}

// PreviewReplaceGeneratedWithScope computes the exact document which a
// ReplaceGeneratedWithScope call would publish, without changing the shared
// whitelist. It is used by runtime preflight paths which need the candidate
// capture policy before a surrounding transaction is durable.
func (s *Store) PreviewReplaceGeneratedWithScope(prefixes []netip.Prefix, revision string, generatedAt time.Time, scope string) (Document, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	current, err := s.readUnlocked()
	if err != nil {
		return Document{}, err
	}
	if revision == "" || revision != current.Revision {
		return Document{}, ErrConflict
	}
	return replacedGeneratedDocument(current, prefixes, generatedAt, scope)
}

func replacedGeneratedDocument(current Document, prefixes []netip.Prefix, generatedAt time.Time, scope string) (Document, error) {
	if len(prefixes) > MaxEntries {
		return Document{}, ErrTooManyEntries
	}
	if !validAutoScope(scope) {
		return Document{}, fmt.Errorf("invalid fake-IP whitelist AUTO source scope %q", scope)
	}
	generated, err := canonicalPrefixes(prefixes)
	if err != nil {
		return Document{}, err
	}
	if generatedAt.IsZero() {
		generatedAt = time.Now()
	}
	block := renderGeneratedBlock(generated, generatedAt, scope)

	sections, err := splitSections(current.Content)
	if err != nil {
		return Document{}, err
	}
	next := block + current.Content
	if sections.hasGenerated {
		next = sections.before + block + sections.after
	}
	return parseDocument(next)
}

func (s *Store) readUnlocked() (Document, error) {
	pathOnDisk, err := s.path()
	if err != nil {
		return Document{}, err
	}
	content, err := readFile(pathOnDisk)
	if errors.Is(err, os.ErrNotExist) {
		return parseDocument("")
	}
	if err != nil {
		return Document{}, err
	}
	return parseDocument(content)
}

func (s *Store) commitUnlocked(content, expectedRevision string) (Document, error) {
	if len(content) > MaxDocumentBytes {
		return Document{}, ErrTooLarge
	}
	if !utf8.ValidString(content) || strings.IndexByte(content, 0) >= 0 {
		return Document{}, fmt.Errorf("%w: content is not valid UTF-8 text", ErrInvalidManual)
	}
	next, err := parseDocument(content)
	if err != nil {
		return Document{}, err
	}

	pathOnDisk, err := s.path()
	if err != nil {
		return Document{}, err
	}
	directory := filepath.Dir(pathOnDisk)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return Document{}, fmt.Errorf("create fake-IP whitelist directory: %w", err)
	}
	if err := inspectDirectory(directory); err != nil {
		return Document{}, err
	}
	if err := checkRevision(pathOnDisk, expectedRevision); err != nil {
		return Document{}, err
	}

	temporary, err := os.CreateTemp(directory, ".fakeip-whitelist-*")
	if err != nil {
		return Document{}, fmt.Errorf("create fake-IP whitelist temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return Document{}, fmt.Errorf("protect fake-IP whitelist temporary file: %w", err)
	}
	if _, err := io.WriteString(temporary, content); err != nil {
		return Document{}, fmt.Errorf("write fake-IP whitelist temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return Document{}, fmt.Errorf("sync fake-IP whitelist temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return Document{}, fmt.Errorf("close fake-IP whitelist temporary file: %w", err)
	}
	// Recheck after the potentially slow write so another process cannot silently
	// replace data observed by the caller before this rename.
	if err := checkRevision(pathOnDisk, expectedRevision); err != nil {
		return Document{}, err
	}
	if err := os.Rename(temporaryPath, pathOnDisk); err != nil {
		return Document{}, fmt.Errorf("publish fake-IP whitelist: %w", err)
	}
	committed = true
	if err := syncDirectory(directory); err != nil {
		return Document{}, fmt.Errorf("sync fake-IP whitelist directory: %w", err)
	}
	return next, nil
}

func (s *Store) path() (string, error) {
	if strings.TrimSpace(s.Directory) == "" {
		return "", fmt.Errorf("%w: directory is empty", ErrUnsafePath)
	}
	directory, err := filepath.Abs(s.Directory)
	if err != nil || directory == string(filepath.Separator) || directory == "." {
		return "", fmt.Errorf("%w: invalid directory", ErrUnsafePath)
	}
	if err := inspectDirectoryIfPresent(directory); err != nil {
		return "", err
	}
	return filepath.Join(directory, FileName), nil
}

func readFile(pathOnDisk string) (string, error) {
	info, err := os.Lstat(pathOnDisk)
	if err != nil {
		return "", err
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w: whitelist is not a regular file", ErrUnsafePath)
	}
	if info.Size() > MaxDocumentBytes {
		return "", ErrTooLarge
	}
	file, err := os.Open(pathOnDisk)
	if err != nil {
		return "", fmt.Errorf("open fake-IP whitelist: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxDocumentBytes+1))
	if err != nil {
		return "", fmt.Errorf("read fake-IP whitelist: %w", err)
	}
	if len(data) > MaxDocumentBytes {
		return "", ErrTooLarge
	}
	if !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
		return "", errors.New("fake-IP whitelist is not valid UTF-8 text")
	}
	return string(data), nil
}

func checkRevision(pathOnDisk, expected string) error {
	content, err := readFile(pathOnDisk)
	if errors.Is(err, os.ErrNotExist) {
		content = ""
	} else if err != nil {
		return err
	}
	if revision([]byte(content)) != expected {
		return ErrConflict
	}
	return nil
}

func inspectDirectoryIfPresent(directory string) error {
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect fake-IP whitelist directory: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: directory must be a real directory", ErrUnsafePath)
	}
	return nil
}

func inspectDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect fake-IP whitelist directory: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: directory must be a real directory", ErrUnsafePath)
	}
	return nil
}

type documentSections struct {
	before         string
	generatedBody  string
	generatedBlock string
	after          string
	hasGenerated   bool
}

type sourceLine struct {
	start int
	end   int
	text  string
}

func splitSections(content string) (documentSections, error) {
	lines := sourceLines(content)
	begin := -1
	end := -1
	for index, line := range lines {
		switch line.text {
		case AutoBeginMarker:
			if begin >= 0 || end >= 0 {
				return documentSections{}, ErrMalformedMarkers
			}
			begin = index
		case AutoEndMarker:
			if begin < 0 || end >= 0 {
				return documentSections{}, ErrMalformedMarkers
			}
			end = index
		}
	}
	if begin < 0 && end < 0 {
		return documentSections{before: content}, nil
	}
	if begin < 0 || end < 0 || end <= begin {
		return documentSections{}, ErrMalformedMarkers
	}
	beginLine, endLine := lines[begin], lines[end]
	return documentSections{
		before:         content[:beginLine.start],
		generatedBody:  content[beginLine.end:endLine.start],
		generatedBlock: content[beginLine.start:endLine.end],
		after:          content[endLine.end:],
		hasGenerated:   true,
	}, nil
}

func sourceLines(content string) []sourceLine {
	if content == "" {
		return nil
	}
	lines := make([]sourceLine, 0, strings.Count(content, "\n")+1)
	for start := 0; start < len(content); {
		relativeEnd := strings.IndexByte(content[start:], '\n')
		end := len(content)
		textEnd := end
		if relativeEnd >= 0 {
			textEnd = start + relativeEnd
			end = textEnd + 1
		}
		text := content[start:textEnd]
		text = strings.TrimSuffix(text, "\r")
		lines = append(lines, sourceLine{start: start, end: end, text: text})
		start = end
	}
	return lines
}

func parseDocument(content string) (Document, error) {
	if len(content) > MaxDocumentBytes {
		return Document{}, ErrTooLarge
	}
	if !utf8.ValidString(content) || strings.IndexByte(content, 0) >= 0 {
		return Document{}, errors.New("fake-IP whitelist is not valid UTF-8 text")
	}
	sections, err := splitSections(content)
	if err != nil {
		return Document{}, err
	}
	manualContent := sections.before + sections.after
	manual, _, err := parsePrefixText(manualContent, false)
	if err != nil {
		return Document{}, err
	}
	generated, generatedAt, err := parsePrefixText(sections.generatedBody, false)
	if err != nil {
		return Document{}, err
	}
	effectiveInput := make([]netip.Prefix, 0, len(manual)+len(generated))
	effectiveInput = append(effectiveInput, manual...)
	effectiveInput = append(effectiveInput, generated...)
	effective, err := canonicalPrefixes(effectiveInput)
	if err != nil {
		return Document{}, err
	}
	if len(manual) > MaxEntries || len(generated) > MaxEntries || len(effective) > MaxEntries {
		return Document{}, ErrTooManyEntries
	}
	return Document{
		Content:        content,
		ManualContent:  manualContent,
		Manual:         manual,
		Generated:      generated,
		Effective:      effective,
		Count:          len(effective),
		ManualCount:    len(manual),
		GeneratedCount: len(generated),
		EffectiveCount: len(effective),
		Revision:       revision([]byte(content)),
		GeneratedAt:    generatedAt,
		GeneratedScope: parseAutoScope(sections.generatedBody),
		HasGenerated:   sections.hasGenerated,
	}, nil
}

func validateManual(content string) (string, []netip.Prefix, error) {
	if len(content) > MaxDocumentBytes {
		return "", nil, ErrTooLarge
	}
	if !utf8.ValidString(content) || strings.IndexByte(content, 0) >= 0 {
		return "", nil, fmt.Errorf("%w: content is not valid UTF-8 text", ErrInvalidManual)
	}
	content = normalizeLineEndings(content)
	prefixes, _, err := parsePrefixText(content, true)
	if err != nil {
		return "", nil, err
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if len(content) > MaxDocumentBytes {
		return "", nil, ErrTooLarge
	}
	return content, prefixes, nil
}

func parsePrefixText(content string, strict bool) ([]netip.Prefix, time.Time, error) {
	prefixes := make([]netip.Prefix, 0)
	var generatedAt time.Time
	for lineNumber, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if strict && (line == AutoBeginMarker || line == AutoEndMarker) {
				return nil, time.Time{}, fmt.Errorf("%w at line %d: AUTO markers are reserved", ErrInvalidManual, lineNumber+1)
			}
			const timestampPrefix = "# Generated: "
			if strings.HasPrefix(line, timestampPrefix) {
				if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(strings.TrimPrefix(line, timestampPrefix))); err == nil {
					generatedAt = parsed
				}
			}
			continue
		}
		prefix, err := parseIPv4Prefix(line)
		if err != nil {
			if strict {
				return nil, time.Time{}, fmt.Errorf("%w at line %d: %q", ErrInvalidManual, lineNumber+1, line)
			}
			continue
		}
		prefixes = append(prefixes, prefix)
		if len(prefixes) > MaxEntries {
			return nil, time.Time{}, ErrTooManyEntries
		}
	}
	canonical, err := canonicalPrefixes(prefixes)
	if err != nil {
		return nil, time.Time{}, err
	}
	return canonical, generatedAt, nil
}

func parseIPv4Prefix(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() {
			return netip.Prefix{}, errors.New("not an IPv4 prefix")
		}
		return prefix.Masked(), nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() {
		return netip.Prefix{}, errors.New("not an IPv4 address")
	}
	return netip.PrefixFrom(address, 32), nil
}

func canonicalPrefixes(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	if len(prefixes) > MaxEntries {
		return nil, ErrTooManyEntries
	}
	values := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() || !prefix.Addr().Is4() {
			return nil, errors.New("fake-IP whitelist contains a non-IPv4 prefix")
		}
		values = append(values, prefix.Masked().String())
	}
	sort.Strings(values)
	result := make([]netip.Prefix, 0, len(values))
	previous := ""
	for _, value := range values {
		if value == previous {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, err
		}
		result = append(result, prefix)
		previous = value
	}
	return result, nil
}

func renderGeneratedBlock(prefixes []netip.Prefix, generatedAt time.Time, scope string) string {
	var builder strings.Builder
	builder.WriteString(AutoBeginMarker)
	builder.WriteByte('\n')
	builder.WriteString("# Generated: ")
	builder.WriteString(generatedAt.UTC().Format(time.RFC3339))
	builder.WriteByte('\n')
	if scope != "" {
		builder.WriteString(AutoScopeMarker)
		builder.WriteString(scope)
		builder.WriteByte('\n')
	}
	for _, prefix := range prefixes {
		builder.WriteString(prefix.String())
		builder.WriteByte('\n')
	}
	builder.WriteString(AutoEndMarker)
	builder.WriteByte('\n')
	return builder.String()
}

func validAutoScope(scope string) bool {
	return scope == "" || scope == AutoScopeLocalOnly || scope == AutoScopeAllProviders
}

func parseAutoScope(content string) string {
	scope := ""
	seen := false
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if !strings.HasPrefix(line, AutoScopeMarker) {
			continue
		}
		if seen {
			return ""
		}
		seen = true
		candidate := strings.TrimSpace(strings.TrimPrefix(line, AutoScopeMarker))
		if !validAutoScope(candidate) || candidate == "" {
			return ""
		}
		scope = candidate
	}
	return scope
}

func normalizeLineEndings(content string) string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	return strings.ReplaceAll(content, "\r", "\n")
}

func endsInLineBreak(content string) bool {
	return strings.HasSuffix(content, "\n") || strings.HasSuffix(content, "\r")
}

func revision(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
