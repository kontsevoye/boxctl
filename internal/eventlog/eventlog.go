// Package eventlog provides a bounded, process-local structured log stream.
package eventlog

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	secretAssignmentPattern = regexp.MustCompile(`(?i)(password|passwd|secret|token|authorization|cookie|credential|api[_-]?key|private[_-]?key|source[_-]?url|subscription(?:[_-]?url)?|external[_-]?controller)(\s*[:=]\s*)[^\s,;]+`)
	authorizationPattern    = regexp.MustCompile(`(?i)\b(Bearer|Basic)(\s+)[^\s,;]+`)
	urlPattern              = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s<>"',;]+`)
	secretPathPattern       = regexp.MustCompile(`(?i)(/(?:token|secret|subscription|subscribe|controller|auth|api[-_]?key)/)[^/\s?#]+`)
	privateRuntimePattern   = regexp.MustCompile(`(?i)(^|[\s"'=])(/[^\s"',;]*(?:/runtime/|mihomo-[^/\s]*\.ya?ml)[^\s"',;]*)`)
)

// Entry is safe to expose through the authenticated system-log API.
type Entry struct {
	Sequence  uint64         `json:"sequence"`
	Timestamp time.Time      `json:"timestamp"`
	Level     string         `json:"level"`
	Component string         `json:"component,omitempty"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// Ring stores recent entries and broadcasts new entries to bounded subscribers.
// Slow subscribers are disconnected instead of blocking the supervisor.
type Ring struct {
	mu          sync.Mutex
	entries     []Entry
	capacity    int
	next        uint64
	subscribers map[uint64]chan Entry
	nextSub     uint64
}

// New creates a ring. Capacities below one are promoted to one.
func New(capacity int) *Ring {
	if capacity < 1 {
		capacity = 1
	}
	return &Ring{capacity: capacity, subscribers: make(map[uint64]chan Entry)}
}

// Append records an entry after removing fields that are unsafe to expose.
func (r *Ring) Append(entry Entry) Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next++
	entry.Sequence = r.next
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	} else {
		entry.Timestamp = entry.Timestamp.UTC()
	}
	entry.Message = RedactText(entry.Message)
	entry.Fields = redactFields(entry.Fields)
	if len(r.entries) == r.capacity {
		copy(r.entries, r.entries[1:])
		r.entries[len(r.entries)-1] = entry
	} else {
		r.entries = append(r.entries, entry)
	}
	for id, subscriber := range r.subscribers {
		select {
		case subscriber <- entry:
		default:
			close(subscriber)
			delete(r.subscribers, id)
		}
	}
	return entry
}

// Snapshot returns entries after sequence, up to limit. A non-positive limit
// returns all retained entries.
func (r *Ring) Snapshot(after uint64, limit int) []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]Entry, 0, len(r.entries))
	for _, entry := range r.entries {
		if entry.Sequence > after {
			result = append(result, cloneEntry(entry))
		}
	}
	if limit > 0 && len(result) > limit {
		result = result[len(result)-limit:]
	}
	return result
}

// Subscribe returns a snapshot followed by live entries. Cancel must always be
// called; cancellation is also automatic when ctx ends.
func (r *Ring) Subscribe(ctx context.Context, after uint64) ([]Entry, <-chan Entry, func()) {
	r.mu.Lock()
	snapshot := make([]Entry, 0, len(r.entries))
	for _, entry := range r.entries {
		if entry.Sequence > after {
			snapshot = append(snapshot, cloneEntry(entry))
		}
	}
	r.nextSub++
	id := r.nextSub
	stream := make(chan Entry, 64)
	r.subscribers[id] = stream
	r.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			r.mu.Lock()
			if subscriber, ok := r.subscribers[id]; ok {
				delete(r.subscribers, id)
				close(subscriber)
			}
			r.mu.Unlock()
		})
	}
	go func() {
		<-ctx.Done()
		cancel()
	}()
	return snapshot, stream, cancel
}

// Handler returns an slog handler that writes JSON-safe records into the ring.
func (r *Ring) Handler(level slog.Leveler) slog.Handler {
	if level == nil {
		level = slog.LevelInfo
	}
	return &handler{ring: r, level: level}
}

type handler struct {
	ring      *Ring
	level     slog.Leveler
	attrs     []slog.Attr
	component string
}

func (h *handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *handler) Handle(_ context.Context, record slog.Record) error {
	fields := make(map[string]any, record.NumAttrs()+len(h.attrs))
	for _, attribute := range h.attrs {
		appendAttr(fields, attribute)
	}
	record.Attrs(func(attribute slog.Attr) bool {
		appendAttr(fields, attribute)
		return true
	})
	h.ring.Append(Entry{
		Timestamp: record.Time,
		Level:     record.Level.String(),
		Component: h.component,
		Message:   record.Message,
		Fields:    fields,
	})
	return nil
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &clone
}

func (h *handler) WithGroup(name string) slog.Handler {
	clone := *h
	if clone.component == "" {
		clone.component = name
	} else if name != "" {
		clone.component += "." + name
	}
	return &clone
}

func appendAttr(fields map[string]any, attribute slog.Attr) {
	attribute.Value = attribute.Value.Resolve()
	if attribute.Equal(slog.Attr{}) {
		return
	}
	if attribute.Value.Kind() == slog.KindGroup {
		group := make(map[string]any)
		for _, child := range attribute.Value.Group() {
			appendAttr(group, child)
		}
		fields[attribute.Key] = group
		return
	}
	fields[attribute.Key] = attribute.Value.Any()
}

func cloneEntry(entry Entry) Entry {
	clone := entry
	if entry.Fields != nil {
		clone.Fields = make(map[string]any, len(entry.Fields))
		for key, value := range entry.Fields {
			clone.Fields[key] = value
		}
	}
	return clone
}

func redactFields(fields map[string]any) map[string]any {
	if len(fields) == 0 {
		return nil
	}
	result := make(map[string]any, len(fields))
	for key, value := range fields {
		if sensitiveField(key) {
			result[key] = "[REDACTED]"
			continue
		}
		switch typed := value.(type) {
		case map[string]any:
			result[key] = redactFields(typed)
		case string:
			result[key] = RedactText(typed)
		case []any:
			values := make([]any, len(typed))
			for index, item := range typed {
				switch item := item.(type) {
				case string:
					values[index] = RedactText(item)
				case map[string]any:
					values[index] = redactFields(item)
				default:
					values[index] = item
				}
			}
			result[key] = values
		case []string:
			values := make([]string, len(typed))
			for index, item := range typed {
				values[index] = RedactText(item)
			}
			result[key] = values
		case map[string]string:
			values := make(map[string]any, len(typed))
			for itemKey, item := range typed {
				if sensitiveField(itemKey) {
					values[itemKey] = "[REDACTED]"
				} else {
					values[itemKey] = RedactText(item)
				}
			}
			result[key] = values
		case error:
			result[key] = RedactText(typed.Error())
		default:
			result[key] = value
		}
	}
	return result
}

func sensitiveField(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(key))
	for _, part := range []string{
		"password", "passwd", "secret", "token", "authorization", "cookie", "credential", "private",
		"apikey", "url", "uri", "path", "controller", "subscription",
	} {
		if strings.Contains(normalized, part) {
			return true
		}
	}
	return false
}

// RedactText removes common credentials and private locations from arbitrary
// diagnostic text. It deliberately strips every URL path, query, and fragment:
// subscription credentials are commonly encoded in otherwise unnamed path
// segments or query parameters, so a key-name allow-list is not sufficient.
func RedactText(value string) string {
	value = authorizationPattern.ReplaceAllString(value, `${1}${2}[REDACTED]`)
	value = urlPattern.ReplaceAllStringFunc(value, redactURL)
	value = secretPathPattern.ReplaceAllString(value, `${1}[REDACTED]`)
	value = privateRuntimePattern.ReplaceAllString(value, `${1}[REDACTED_PATH]`)
	value = secretAssignmentPattern.ReplaceAllString(value, `${1}${2}[REDACTED]`)
	return value
}

func redactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" {
		return "[REDACTED_URL]"
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "ws", "wss":
	default:
		return parsed.Scheme + "://[REDACTED]"
	}
	if parsed.Host == "" {
		return parsed.Scheme + "://[REDACTED]"
	}
	result := parsed.Scheme + "://"
	if parsed.User != nil {
		result += "[REDACTED]@"
	}
	result += parsed.Host
	if parsed.EscapedPath() != "" && parsed.EscapedPath() != "/" {
		result += "/[REDACTED]"
	} else if parsed.EscapedPath() == "/" {
		result += "/"
	}
	if parsed.RawQuery != "" {
		result += "?[REDACTED]"
	}
	if parsed.Fragment != "" {
		result += "#[REDACTED]"
	}
	return result
}

// MarshalEntry provides a stable JSON encoding for stream adapters.
func MarshalEntry(entry Entry) ([]byte, error) {
	return json.Marshal(entry)
}
