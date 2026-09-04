package app

import (
	"context"
	"testing"

	"github.com/kontsevoye/boxctl/internal/eventlog"
	"github.com/kontsevoye/boxctl/internal/web"
)

func TestSystemLogStreamBoundsInitialSnapshot(t *testing.T) {
	t.Parallel()
	ring := eventlog.New(8)
	for _, message := range []string{"first", "second", "third"} {
		ring.Append(eventlog.Entry{Level: "info", Message: message})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := (SystemLogs{Ring: ring}).StreamSystemLogs(ctx, web.LogQuery{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	first := <-stream
	second := <-stream
	if first.Message != "second" || second.Message != "third" {
		t.Fatalf("bounded stream snapshot = %q, %q", first.Message, second.Message)
	}
}

func TestSystemLogsNormalizeSlogLevelsAndFilterCaseInsensitively(t *testing.T) {
	t.Parallel()
	ring := eventlog.New(8)
	ring.Append(eventlog.Entry{Level: "INFO", Message: "visible"})
	ring.Append(eventlog.Entry{Level: "ERROR", Message: "hidden"})

	entries, err := (SystemLogs{Ring: ring}).SystemLogs(context.Background(), web.LogQuery{Level: "info"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Level != "info" || entries[0].Message != "visible" {
		t.Fatalf("normalized system logs = %#v", entries)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := (SystemLogs{Ring: ring}).StreamSystemLogs(ctx, web.LogQuery{Level: "error"})
	if err != nil {
		t.Fatal(err)
	}
	entry := <-stream
	if entry.Level != "error" || entry.Message != "hidden" {
		t.Fatalf("normalized system log stream entry = %#v", entry)
	}
}
