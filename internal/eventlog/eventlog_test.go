package eventlog

import (
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestRingBoundsAndRedacts(t *testing.T) {
	t.Parallel()
	ring := New(2)
	ring.Append(Entry{Message: "Authorization: Bearer abc123", Fields: map[string]any{"token": "abc", "ok": "value"}})
	ring.Append(Entry{Message: "second"})
	ring.Append(Entry{Message: "third"})
	entries := ring.Snapshot(0, 0)
	if len(entries) != 2 || entries[0].Message != "second" || entries[1].Message != "third" {
		t.Fatalf("unexpected snapshot %#v", entries)
	}
	redacted := ring.Append(Entry{Message: "Bearer secret", Fields: map[string]any{"password": "secret", "visible": "yes"}})
	if redacted.Message != "Bearer [REDACTED]" || redacted.Fields["password"] != "[REDACTED]" {
		t.Fatalf("entry was not redacted: %#v", redacted)
	}
}

func TestRingRedactsURLsSecretSegmentsAndPrivateRuntimePaths(t *testing.T) {
	t.Parallel()
	const (
		userSecret    = "user-secret"
		querySecret   = "query-secret"
		pathSecret    = "path-secret"
		runtimeSecret = "mihomo-private-123.yaml"
	)
	ring := New(1)
	entry := ring.Append(Entry{
		Message: "fetch https://admin:" + userSecret + "@example.test/subscriptions/" + pathSecret + "?opaque=" + querySecret +
			" via /controller/" + pathSecret + " using /tmp/boxctl-mihomo-123456789/" + runtimeSecret + " vmess://payload-secret",
		Fields: map[string]any{
			"subscription_url": "https://example.test/" + pathSecret + "?id=" + querySecret,
			"runtimePath":      "/tmp/boxctl-mihomo-123456789/" + runtimeSecret,
			"nested": map[string]any{
				"items": []string{"https://example.test/" + pathSecret + "?id=" + querySecret},
			},
		},
	})
	encoded, err := MarshalEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{userSecret, querySecret, pathSecret, runtimeSecret, "payload-secret"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("redacted entry leaked %q: %s", secret, encoded)
		}
	}
	if !strings.Contains(entry.Message, "https://[REDACTED]@example.test/[REDACTED]?[REDACTED]") {
		t.Fatalf("URL was not usefully redacted: %q", entry.Message)
	}
	if entry.Fields["subscription_url"] != "[REDACTED]" || entry.Fields["runtimePath"] != "[REDACTED]" {
		t.Fatalf("sensitive fields were exposed: %#v", entry.Fields)
	}
}

func TestSubscribeAndSlogHandler(t *testing.T) {
	t.Parallel()
	ring := New(10)
	logger := slog.New(ring.Handler(slog.LevelDebug)).WithGroup("supervisor")
	logger.Info("ready", "secret", "nope", "port", 9091)
	ctx, cancelContext := context.WithCancel(context.Background())
	snapshot, stream, cancel := ring.Subscribe(ctx, 0)
	defer cancel()
	if len(snapshot) != 1 || snapshot[0].Component != "supervisor" || snapshot[0].Fields["secret"] != "[REDACTED]" {
		t.Fatalf("unexpected snapshot %#v", snapshot)
	}
	ring.Append(Entry{Message: "live"})
	select {
	case entry := <-stream:
		if entry.Message != "live" {
			t.Fatalf("unexpected entry %#v", entry)
		}
	default:
		t.Fatal("live entry was not delivered")
	}
	cancelContext()
}
