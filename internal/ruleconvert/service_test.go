package ruleconvert

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func fakeConvert(_ context.Context, raw []byte, source Source) (Artifact, error) {
	if string(raw) == "broken" {
		return Artifact{}, errors.New("invalid fixture")
	}
	rules, err := parseText(raw, "")
	if err != nil {
		return Artifact{}, err
	}
	behavior := outputBehavior(rules)
	format := "mrs"
	if behavior == "classical" {
		format = "text"
	}
	if source.Target == "sing-box" {
		format = "binary"
		behavior = ""
	}
	return Artifact{Data: append([]byte("compiled:"), raw...), Format: format, Behavior: behavior, Count: len(rules)}, nil
}
func TestHTTPConversionLifecycle(t *testing.T) {
	var mu sync.Mutex
	body, etag := "192.0.2.0/24\n", `"one"`
	hits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		hits++
		if r.Header.Get("Authorization") != "Bearer fixture" {
			t.Error("lost source header")
		}
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(304)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	defer upstream.Close()
	root := t.TempDir()
	service := New(root)
	service.Convert = fakeConvert
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	source := Source{URL: upstream.URL, Target: "sing-box", Headers: http.Header{"Authorization": []string{"Bearer fixture"}}}
	record, err := service.Prepare(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := service.URL(record)
	fetch := func(etag string) (int, string, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, endpoint, nil)
		req.Header.Set("If-None-Match", etag)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(data), resp.Header.Get("ETag")
	}
	status, data, outputETag := fetch("")
	if status != 200 || data != "compiled:"+body {
		t.Fatalf("%d %s", status, data)
	}
	status, _, _ = fetch(outputETag)
	if status != 304 {
		t.Fatalf("unchanged %d", status)
	}
	mu.Lock()
	body = "198.51.100.0/24\n"
	etag = `"two"`
	mu.Unlock()
	status, data, newETag := fetch(outputETag)
	if status != 200 || !strings.Contains(data, "198.51.100") || newETag == outputETag {
		t.Fatalf("update %d %s", status, data)
	}
	mu.Lock()
	body = "broken"
	etag = `"broken"`
	mu.Unlock()
	status, _, _ = fetch(newETag)
	if status != 502 {
		t.Fatalf("bad update %d", status)
	}
	record, err = service.Prepare(t.Context(), source)
	if err != nil {
		t.Fatal("offline last good", err)
	}
	cached, err := service.artifact(record)
	if err != nil || !strings.Contains(string(cached), "198.51.100") {
		t.Fatalf("last good lost: %s %v", cached, err)
	}
	statuses := service.Status([]string{record.ID})
	if len(statuses) != 1 || statuses[0].LastError == "" {
		t.Fatal("missing stale status")
	}
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	service = New(root)
	service.Convert = fakeConvert
	if err = service.Start(); err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if service.URL(record) != endpoint {
		t.Fatal("endpoint changed after manager restart")
	}
	mu.Lock()
	body = "203.0.113.0/24\n"
	etag = `"three"`
	mu.Unlock()
	status, data, _ = fetch("")
	if status != 200 || !strings.Contains(data, "203.0.113") {
		t.Fatalf("restart %d %s", status, data)
	}
}
func TestFormatChangeGetsNewEndpoint(t *testing.T) {
	body := "192.0.2.0/24\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
	defer upstream.Close()
	s := New(t.TempDir())
	s.Convert = fakeConvert
	source := Source{URL: upstream.URL, Target: "mihomo"}
	first, err := s.Prepare(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	body = "DOMAIN,example.org\nIP-CIDR,192.0.2.0/24\n"
	second, err := s.Prepare(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID || first.Format != "mrs" || second.Format != "text" {
		t.Fatalf("bad format transition: %+v %+v", first, second)
	}
	old, _ := s.load(first.ID)
	if old.Format != "mrs" || old.LastError == "" {
		t.Fatal("old endpoint contract changed")
	}
}
func TestConverterAccess(t *testing.T) {
	s := New(t.TempDir())
	for _, remote := range []string{"192.0.2.1:5000", "bad", "[::ffff:192.0.2.1]:5000"} {
		r := httptest.NewRequest("GET", "http://localhost/internal/rules/"+strings.Repeat("a", 64)+"/rules.mrs", nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Errorf("remote %s got %d", remote, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "http://localhost/internal/rules/x", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
	for _, u := range []string{"file:///etc/passwd", "https://u:p@example.org/x", "https://example.org/x#y"} {
		if _, e := s.Prepare(t.Context(), Source{URL: u, Target: "sing-box"}); e == nil {
			t.Fatal("accepted", u)
		}
	}
}
func TestNativeCodecs(t *testing.T) {
	binaries := testBinaries(t)
	codec := Codec{Binaries: binaries}
	t.Run("native-only-predicates", func(t *testing.T) {
		source := []byte(`{"version":5,"rules":[{"wifi_ssid":["fixture-network"]}]}`)
		artifact, err := codec.Convert(t.Context(), source, "sing-box", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = codec.Convert(t.Context(), artifact.Data, "sing-box", ""); err != nil {
			t.Fatalf("native SRS predicate lost: %v", err)
		}
		if _, err = codec.Convert(t.Context(), artifact.Data, "mihomo", ""); err == nil {
			t.Fatal("silently accepted native-only predicate in Mihomo")
		}
	})
	for _, input := range []string{"+.example.org\n.example.net\n", "192.0.2.0/24\n2001:db8::/32\n", "AND,((DOMAIN-SUFFIX,example.org),(DST-PORT,443))\n", "PROCESS-PATH,/usr/bin/Example\n"} {
		t.Run(fmt.Sprintf("%x", input[:4]), func(t *testing.T) {
			a, err := codec.Convert(t.Context(), []byte(input), "sing-box", "")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(string(a.Data), "SRS") {
				t.Fatal("not SRS")
			}
			b, err := codec.Convert(t.Context(), a.Data, "mihomo", "")
			if err != nil {
				t.Fatal(err)
			}
			c, err := codec.Convert(t.Context(), b.Data, "sing-box", "")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(string(c.Data), "SRS") {
				t.Fatal("round trip not SRS")
			}
		})
	}
}

func TestArtifactRetention(t *testing.T) {
	service := New(t.TempDir())
	if err := service.initialize(); err != nil {
		t.Fatal(err)
	}
	record := Record{Source: Source{URL: "https://example.org/rules", Target: "sing-box"}}
	var err error
	for i := range 4 {
		record, err = service.publish(record, Artifact{Data: []byte(fmt.Sprint(i)), Format: "binary"}, "", "")
		if err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(service.root, record.ID))
	if err != nil {
		t.Fatal(err)
	}
	blobs := 0
	for _, entry := range entries {
		if validID(entry.Name()) {
			blobs++
		}
	}
	if blobs != 2 {
		t.Fatalf("retained %d blobs, want current and previous", blobs)
	}
	if data, err := service.artifact(record); err != nil || string(data) != "3" {
		t.Fatalf("current artifact lost: %q %v", data, err)
	}
}
