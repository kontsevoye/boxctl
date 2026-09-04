package engine

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGitHubReleaseSourceLatestAndOpen(t *testing.T) {
	t.Parallel()
	const assetBody = "fake-mihomo-archive"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("User-Agent") != "boxctl-test" {
			http.Error(writer, "missing user agent", http.StatusBadRequest)
			return
		}
		switch request.URL.Path {
		case "/latest":
			if request.Header.Get("Accept") != "application/vnd.github+json" {
				http.Error(writer, "bad accept", http.StatusBadRequest)
				return
			}
			_, _ = io.WriteString(writer, `{"tag_name":"v1.20.0","name":"Mihomo v1.20.0","published_at":"2026-08-24T12:00:00Z","assets":[{"name":"mihomo-linux-arm64.tar.gz","browser_download_url":"`+serverURLFromRequest(request)+`/asset","size":19,"content_type":"application/gzip"}]}`)
		case "/asset":
			if request.Header.Get("Accept") != "application/octet-stream" {
				http.Error(writer, "bad asset accept", http.StatusBadRequest)
				return
			}
			_, _ = io.WriteString(writer, assetBody)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	source, err := NewMihomoReleaseSource(GitHubReleaseOptions{
		APIURL:            server.URL + "/latest",
		HTTPClient:        server.Client(),
		UserAgent:         "boxctl-test",
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	release, err := source.Latest(ctx)
	if err != nil {
		t.Fatalf("Latest() error = %v", err)
	}
	if release.Tag != "v1.20.0" || release.Name != "Mihomo v1.20.0" || !release.PublishedAt.Equal(time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("Latest() = %#v", release)
	}
	asset, err := FindReleaseAsset(release, "mihomo-linux-arm64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := source.Open(ctx, asset)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	data, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || string(data) != assetBody {
		t.Fatalf("asset read = %q, %v, close=%v", data, readErr, closeErr)
	}
}

func serverURLFromRequest(request *http.Request) string {
	return "http://" + request.Host
}

func TestGitHubReleaseSourceSafetyAndContext(t *testing.T) {
	t.Parallel()
	if _, err := NewMihomoReleaseSource(GitHubReleaseOptions{APIURL: "http://example.test/latest"}); err == nil {
		t.Fatal("NewMihomoReleaseSource accepted insecure HTTP")
	}
	if _, err := NewMihomoReleaseSource(GitHubReleaseOptions{APIURL: "https://user:pass@example.test/latest"}); err == nil {
		t.Fatal("NewMihomoReleaseSource accepted URL credentials")
	}
	source, err := NewMihomoReleaseSource(GitHubReleaseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Latest(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Latest(cancelled) error = %v, want context.Canceled", err)
	}
	if _, err := source.Open(context.Background(), ReleaseAsset{URL: "file:///tmp/mihomo"}); err == nil {
		t.Fatal("Open accepted file URL")
	}
	if _, err := source.Open(context.Background(), ReleaseAsset{URL: "https://example.test/mihomo", Size: maxReleaseAsset + 1}); err == nil {
		t.Fatal("Open accepted oversized declared asset")
	}
}

func TestFindReleaseAssetRequiresUniqueExactName(t *testing.T) {
	t.Parallel()
	release := Release{Assets: []ReleaseAsset{{Name: "mihomo"}, {Name: "mihomo"}, {Name: "mihomo.gz"}}}
	if _, err := FindReleaseAsset(release, "mihomo"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("FindReleaseAsset(duplicate) error = %v", err)
	}
	if _, err := FindReleaseAsset(release, "missing"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("FindReleaseAsset(missing) error = %v", err)
	}
}

func TestBoundedReleaseReaderReportsOverflow(t *testing.T) {
	t.Parallel()
	reader := &boundedReadCloser{
		reader:    strings.NewReader("12345"),
		closer:    io.NopCloser(strings.NewReader("")),
		remaining: 4,
	}
	data, err := io.ReadAll(reader)
	if string(data) != "1234" || err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("bounded read = %q, %v", data, err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
}
