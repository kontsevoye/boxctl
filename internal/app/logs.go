package app

import (
	"context"
	"strings"

	"github.com/kontsevoye/boxctl/internal/eventlog"
	"github.com/kontsevoye/boxctl/internal/web"
)

// SystemLogs exposes the redacted in-process ring through web's neutral API.
type SystemLogs struct {
	Ring *eventlog.Ring
}

func (logs SystemLogs) SystemLogs(_ context.Context, query web.LogQuery) ([]web.LogEntry, error) {
	if logs.Ring == nil {
		return []web.LogEntry{}, nil
	}
	entries := logs.Ring.Snapshot(0, normalizedLogLimit(query.Limit))
	result := make([]web.LogEntry, 0, len(entries))
	for _, entry := range entries {
		if query.Level != "" && !strings.EqualFold(entry.Level, query.Level) {
			continue
		}
		result = append(result, toWebLog(entry))
	}
	return result, nil
}

func (logs SystemLogs) StreamSystemLogs(ctx context.Context, query web.LogQuery) (<-chan web.LogEntry, error) {
	if logs.Ring == nil {
		result := make(chan web.LogEntry)
		close(result)
		return result, nil
	}
	snapshot, stream, cancel := logs.Ring.Subscribe(ctx, 0)
	limit := normalizedLogLimit(query.Limit)
	if len(snapshot) > limit {
		snapshot = snapshot[len(snapshot)-limit:]
	}
	result := make(chan web.LogEntry, len(snapshot)+64)
	go func() {
		defer close(result)
		defer cancel()
		for _, entry := range snapshot {
			if query.Level == "" || strings.EqualFold(entry.Level, query.Level) {
				select {
				case result <- toWebLog(entry):
				case <-ctx.Done():
					return
				}
			}
		}
		for {
			select {
			case <-ctx.Done():
				return
			case entry, ok := <-stream:
				if !ok {
					return
				}
				if query.Level != "" && !strings.EqualFold(entry.Level, query.Level) {
					continue
				}
				select {
				case result <- toWebLog(entry):
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return result, nil
}

func toWebLog(entry eventlog.Entry) web.LogEntry {
	return web.LogEntry{Time: entry.Timestamp, Level: strings.ToLower(strings.TrimSpace(entry.Level)), Component: entry.Component, Message: entry.Message, Fields: entry.Fields}
}

func normalizedLogLimit(value int) int {
	if value <= 0 {
		return 500
	}
	if value > 5000 {
		return 5000
	}
	return value
}
