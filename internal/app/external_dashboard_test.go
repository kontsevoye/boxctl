package app

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/update"
)

func TestExternalDashboardInstallIsVerifiedVersionedAndIdempotent(t *testing.T) {
	archive := dashboardArchive(t, map[string]string{
		"dist/index.html":           `<!doctype html><title>zashboard</title><script src="./assets/app.js"></script>`,
		"dist/assets/app.js":        "console.log('zashboard')",
		"dist/manifest.webmanifest": `{"name":"zashboard"}`,
	})
	assetURL := "https://github.com/Zephyruso/zashboard/releases/download/v3.23.0/dist-no-fonts.zip"
	asset := update.Asset{Name: externalDashboardAsset, URL: assetURL, Digest: dashboardDigest(archive), Size: int64(len(archive))}
	source := &dashboardSourceStub{release: update.Release{Tag: "v3.23.0", Assets: []update.Asset{asset}}}
	var downloads atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		downloads.Add(1)
		return dashboardResponse(request, archive), nil
	})}
	manager := dashboardTestManager(t, source, client)
	manager.Now = func() time.Time { return time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC) }

	result, err := manager.InstallExternalDashboard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || !result.Installed || result.CurrentVersion != "v3.23.0" || result.LatestVersion != "v3.23.0" {
		t.Fatalf("install result = %#v", result)
	}
	content, err := os.ReadFile(filepath.Join(manager.Layout.DashboardDir, "assets", "app.js"))
	if err != nil || string(content) != "console.log('zashboard')" {
		t.Fatalf("installed asset = %q err=%v", content, err)
	}
	metadata, err := readExternalDashboardMetadata(filepath.Join(manager.Layout.DashboardDir, externalDashboardMetadataName))
	if err != nil || metadata.Version != "v3.23.0" || metadata.Digest != asset.Digest || !metadata.InstalledAt.Equal(manager.Now()) {
		t.Fatalf("metadata = %#v err=%v", metadata, err)
	}

	again, err := manager.InstallExternalDashboard(context.Background())
	if err != nil || again.Changed || downloads.Load() != 1 {
		t.Fatalf("second install = %#v downloads=%d err=%v", again, downloads.Load(), err)
	}
	open, err := manager.OpenExternalDashboard(context.Background())
	if err != nil || open.Path != externalDashboardPublicPath || open.ControllerPath != externalDashboardControllerPath {
		t.Fatalf("open = %#v err=%v", open, err)
	}
}

func TestExternalDashboardFailedUpdatePreservesInstalledVersion(t *testing.T) {
	good := dashboardArchive(t, map[string]string{
		"dist/index.html":    `<!doctype html><title>zashboard v1</title><script src="./assets/app.js"></script>`,
		"dist/assets/app.js": "v1",
	})
	bad := dashboardArchive(t, map[string]string{
		"dist/index.html": `<!doctype html><title>zashboard v2</title><script src="./assets/app.js"></script>`,
		"../escaped":      "no",
	})
	assetURL := func(version string) string {
		return "https://github.com/Zephyruso/zashboard/releases/download/" + version + "/dist-no-fonts.zip"
	}
	source := &dashboardSourceStub{}
	currentArchive := good
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return dashboardResponse(request, currentArchive), nil
	})}
	manager := dashboardTestManager(t, source, client)
	source.release = update.Release{Tag: "v3.22.0", Assets: []update.Asset{{
		Name: externalDashboardAsset, URL: assetURL("v3.22.0"), Digest: dashboardDigest(good), Size: int64(len(good)),
	}}}
	if _, err := manager.InstallExternalDashboard(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldIndex, err := os.ReadFile(filepath.Join(manager.Layout.DashboardDir, "index.html"))
	if err != nil {
		t.Fatal(err)
	}

	currentArchive = bad
	source.release = update.Release{Tag: "v3.23.0", Assets: []update.Asset{{
		Name: externalDashboardAsset, URL: assetURL("v3.23.0"), Digest: dashboardDigest(bad), Size: int64(len(bad)),
	}}}
	if _, err := manager.UpdateExternalDashboard(context.Background()); err == nil {
		t.Fatal("unsafe update succeeded")
	}
	index, err := os.ReadFile(filepath.Join(manager.Layout.DashboardDir, "index.html"))
	if err != nil || !bytes.Equal(index, oldIndex) {
		t.Fatalf("installed index changed after failed update: err=%v index=%q", err, index)
	}
	status, err := manager.ExternalDashboardStatus(context.Background(), false)
	if err != nil || status.CurrentVersion != "v3.22.0" {
		t.Fatalf("status after failed update = %#v err=%v", status, err)
	}
}

func TestExternalDashboardStatusReportsCorruptMetadata(t *testing.T) {
	manager := dashboardTestManager(t, &dashboardSourceStub{}, http.DefaultClient)
	if err := os.MkdirAll(manager.Layout.DashboardDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manager.Layout.DashboardDir, "index.html"), []byte("zashboard ./assets/"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manager.Layout.DashboardDir, externalDashboardMetadataName), []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ExternalDashboardStatus(context.Background(), false); err == nil || !strings.Contains(err.Error(), "metadata") {
		t.Fatalf("status error = %v", err)
	}
}

func TestExternalDashboardStatusKeepsInstalledDashboardUsableWhenUpdateCheckFails(t *testing.T) {
	archive := dashboardArchive(t, map[string]string{
		"dist/index.html":    `<!doctype html><title>zashboard</title><script src="./assets/app.js"></script>`,
		"dist/assets/app.js": "installed",
	})
	assetURL := "https://github.com/Zephyruso/zashboard/releases/download/v3.23.0/dist-no-fonts.zip"
	source := &dashboardSourceStub{release: update.Release{Tag: "v3.23.0", Assets: []update.Asset{{
		Name: externalDashboardAsset, URL: assetURL, Digest: dashboardDigest(archive), Size: int64(len(archive)),
	}}}}
	manager := dashboardTestManager(t, source, &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return dashboardResponse(request, archive), nil
	})})
	if _, err := manager.InstallExternalDashboard(context.Background()); err != nil {
		t.Fatal(err)
	}
	source.err = errors.New("upstream unavailable")

	status, err := manager.ExternalDashboardStatus(context.Background(), true)
	if err != nil || !status.Installed || status.CurrentVersion != "v3.23.0" || !status.UpdateCheckFailed {
		t.Fatalf("offline status = %#v err=%v", status, err)
	}
	if _, err := manager.OpenExternalDashboard(context.Background()); err != nil {
		t.Fatalf("open installed dashboard: %v", err)
	}
}

func TestExternalDashboardReleaseRejectsUnattestedOrUnexpectedAssets(t *testing.T) {
	manager := dashboardTestManager(t, &dashboardSourceStub{release: update.Release{
		Tag: "v3.23.0",
		Assets: []update.Asset{{
			Name: externalDashboardAsset, URL: "https://attacker.example/dist-no-fonts.zip", Digest: "sha256:" + strings.Repeat("0", 64), Size: 1,
		}},
	}}, &http.Client{})
	if _, _, err := manager.latest(context.Background()); err == nil {
		t.Fatal("non-GitHub dashboard asset was accepted")
	}
	manager.Source = &dashboardSourceStub{release: update.Release{Tag: "latest", Assets: []update.Asset{}}}
	if _, _, err := manager.latest(context.Background()); err == nil {
		t.Fatal("unsafe dashboard release tag was accepted")
	}
	duplicate := update.Asset{
		Name:   externalDashboardAsset,
		URL:    "https://github.com/Zephyruso/zashboard/releases/download/v3.23.0/dist-no-fonts.zip",
		Digest: "sha256:" + strings.Repeat("0", 64),
		Size:   1,
	}
	manager.Source = &dashboardSourceStub{release: update.Release{Tag: "v3.23.0", Assets: []update.Asset{duplicate, duplicate}}}
	if _, _, err := manager.latest(context.Background()); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate dashboard assets error = %v", err)
	}
}

func TestExternalDashboardServesOnlySafeFilesWithScopedCSP(t *testing.T) {
	manager := dashboardTestManager(t, &dashboardSourceStub{}, &http.Client{})
	if err := os.MkdirAll(filepath.Join(manager.Layout.DashboardDir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manager.Layout.DashboardDir, "index.html"), []byte(`<!doctype html><link rel="manifest" href="./manifest.webmanifest"><script src="./assets/app.js"></script>`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manager.Layout.DashboardDir, "assets", "app.js"), []byte("asset"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manager.Layout.DashboardDir, externalDashboardMetadataName), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}

	index := httptest.NewRecorder()
	manager.ServeHTTP(index, httptest.NewRequest(http.MethodGet, externalDashboardPublicPath, nil))
	if index.Code != http.StatusOK || !strings.Contains(index.Body.String(), `rel="manifest" href="./manifest.webmanifest" crossorigin="use-credentials"`) || !strings.Contains(index.Body.String(), "./assets/app.js") {
		t.Fatalf("index = %d %s", index.Code, index.Body.String())
	}
	csp := index.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "connect-src 'self' https://api.github.com") || !strings.Contains(csp, "img-src 'self' data: blob: https:") || !strings.Contains(csp, "worker-src 'self' blob:") || strings.Contains(csp, "default-src *") {
		t.Fatalf("external dashboard CSP = %q", csp)
	}
	asset := httptest.NewRecorder()
	manager.ServeHTTP(asset, httptest.NewRequest(http.MethodGet, externalDashboardPublicPath+"assets/app.js", nil))
	if asset.Code != http.StatusOK || asset.Body.String() != "asset" || !strings.Contains(asset.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("asset = %d headers=%v body=%s", asset.Code, asset.Header(), asset.Body.String())
	}
	metadata := httptest.NewRecorder()
	manager.ServeHTTP(metadata, httptest.NewRequest(http.MethodGet, externalDashboardPublicPath+externalDashboardMetadataName, nil))
	if metadata.Code != http.StatusNotFound || strings.Contains(metadata.Body.String(), "private") {
		t.Fatalf("metadata leaked = %d %s", metadata.Code, metadata.Body.String())
	}

	outside := filepath.Join(manager.Layout.Root, "outside.js")
	if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(manager.Layout.DashboardDir, "assets", "escape.js")); err != nil {
		t.Fatal(err)
	}
	escape := httptest.NewRecorder()
	manager.ServeHTTP(escape, httptest.NewRequest(http.MethodGet, externalDashboardPublicPath+"assets/escape.js", nil))
	if escape.Code != http.StatusNotFound || strings.Contains(escape.Body.String(), "outside") {
		t.Fatalf("symlink escaped = %d %s", escape.Code, escape.Body.String())
	}
}

func TestAddDashboardManifestCredentialsIsIdempotent(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		in   string
		want string
	}{
		{name: "double quotes", in: `<link rel="manifest" href="./manifest.webmanifest">`, want: `<link rel="manifest" href="./manifest.webmanifest" crossorigin="use-credentials">`},
		{name: "single quotes and self closing", in: `<link href='./manifest.webmanifest' rel='manifest'/>`, want: `<link href='./manifest.webmanifest' rel='manifest' crossorigin="use-credentials"/>`},
		{name: "already credentialed", in: `<link rel="manifest" crossorigin="use-credentials" href="manifest.webmanifest">`, want: `<link rel="manifest" crossorigin="use-credentials" href="manifest.webmanifest">`},
		{name: "unrelated link", in: `<link rel="stylesheet" href="app.css">`, want: `<link rel="stylesheet" href="app.css">`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := string(addDashboardManifestCredentials([]byte(test.in))); got != test.want {
				t.Fatalf("addDashboardManifestCredentials() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestExternalDashboardControllerProxyInjectsSecretWithoutLeakingBrowserState(t *testing.T) {
	const secret = "controller-secret-never-leak"
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/version" || request.URL.RawQuery != "detail=1" {
			t.Errorf("upstream URL = %s", request.URL.String())
		}
		if request.Header.Get("Authorization") != "Bearer "+secret {
			t.Errorf("upstream authorization = %q", request.Header.Get("Authorization"))
		}
		for _, header := range []string{"Cookie", "Origin", "Referer", "X-CSRF-Token", "X-Forwarded-For"} {
			if got := request.Header.Get(header); got != "" {
				t.Errorf("upstream %s leaked: %q", header, got)
			}
		}
		response.Header().Set("Set-Cookie", "mihomo=secret")
		_, _ = io.WriteString(response, `{"version":"test"}`)
	}))
	defer upstream.Close()
	manager := dashboardTestManager(t, &dashboardSourceStub{}, upstream.Client())
	manager.ControllerTarget = func() (engine.ControllerEndpoint, error) {
		return engine.ControllerEndpoint{BaseURL: upstream.URL, Secret: secret}, nil
	}
	request := httptest.NewRequest(http.MethodGet, externalDashboardControllerPath+"/version?detail=1", nil)
	request.Header.Set("Authorization", "Bearer browser-value")
	request.Header.Set("Cookie", "boxctl_session=browser")
	request.Header.Set("Origin", "http://router.example")
	response := httptest.NewRecorder()
	manager.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != `{"version":"test"}` {
		t.Fatalf("proxy response = %d %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Set-Cookie") != "" || strings.Contains(response.Body.String(), secret) || strings.Contains(response.Header().Get("Location"), secret) {
		t.Fatalf("controller secret/state leaked: headers=%v body=%s", response.Header(), response.Body.String())
	}
}

func TestExternalDashboardControllerProxiesWebSockets(t *testing.T) {
	const secret = "websocket-secret"
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+secret || request.Header.Get("Cookie") != "" || request.Header.Get("Origin") != "" {
			t.Errorf("websocket headers = %v", request.Header)
		}
		connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer func() { _ = connection.CloseNow() }()
		_ = wsjson.Write(request.Context(), connection, map[string]int{"up": 42})
	}))
	defer upstream.Close()
	manager := dashboardTestManager(t, &dashboardSourceStub{}, upstream.Client())
	manager.ControllerTarget = func() (engine.ControllerEndpoint, error) {
		return engine.ControllerEndpoint{BaseURL: upstream.URL, Secret: secret}, nil
	}
	proxy := httptest.NewServer(manager)
	defer proxy.Close()
	requestHeaders := http.Header{"Origin": []string{proxy.URL}}
	// coder/websocket owns and closes the handshake response body.
	connection, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(proxy.URL, "http")+externalDashboardControllerPath+"/traffic", &websocket.DialOptions{HTTPHeader: requestHeaders}) //nolint:bodyclose
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.CloseNow() }()
	var payload map[string]int
	if err := wsjson.Read(context.Background(), connection, &payload); err != nil || payload["up"] != 42 {
		t.Fatalf("websocket payload = %#v err=%v", payload, err)
	}
}

func TestExternalDashboardWebSocketDetectionRequiresCompleteHandshake(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodGet, externalDashboardControllerPath+"/traffic", nil)
	request.Header.Set("Upgrade", "websocket")
	if isWebSocketRequest(request) {
		t.Fatal("Upgrade header without Connection token bypassed the proxy body limit")
	}
	request.Header.Set("Connection", "keep-alive, Upgrade")
	if !isWebSocketRequest(request) {
		t.Fatal("valid WebSocket upgrade was not detected")
	}
}

type dashboardSourceStub struct {
	release update.Release
	err     error
}

func (source *dashboardSourceStub) Latest(context.Context, update.Channel) (update.Release, error) {
	return source.release, source.err
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func dashboardResponse(request *http.Request, body []byte) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       request,
	}
}

func dashboardTestManager(t *testing.T, source externalDashboardReleaseSource, client *http.Client) *ExternalDashboardManager {
	t.Helper()
	layout, err := state.NewLayout(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &ExternalDashboardManager{Layout: layout, Source: source, Client: client}
}

func dashboardArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for name, content := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(entry, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
