package engine

import (
	"context"
	encodingbinary "encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestMihomoPrepareValidateAndVersion(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	binary, validationRecord, _ := writeFakeMihomo(t, dir)
	sourcePath := filepath.Join(dir, "config.yaml")
	const source = "mode: rule\nproxy-groups: [{name: USER, type: select, proxies: [DIRECT]}]\n"
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	driver := NewMihomoDriver(MihomoOptions{})
	runtimeBase := t.TempDir()
	prepared, err := driver.Prepare(context.Background(), PrepareRequest{
		BinaryPath:       binary,
		SourceConfigPath: sourcePath,
		RuntimeDir:       runtimeBase,
		Capture: CapturePlan{
			TCP:       ProtocolCapture{Method: CaptureRedirect, Port: 7893},
			UDP:       ProtocolCapture{Method: CaptureTUN},
			DNS:       DNSEndpoint{Enabled: true, Host: "0.0.0.0", Port: 7874},
			TUNDevice: "clash-tun",
			LoopMark:  2,
		},
		Controller: ControllerEndpoint{Listen: "0.0.0.0:9090", BaseURL: "http://127.0.0.1:9090", Secret: "secret"},
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if prepared.Engine != "mihomo" || prepared.RuntimeConfigPath == sourcePath {
		t.Fatalf("Prepare() returned invalid paths: %#v", prepared)
	}
	if !prepared.Capabilities.HotReload || !prepared.Capture.Capabilities.Connections {
		t.Fatalf("Prepare() omitted capabilities: %#v", prepared)
	}
	if prepared.Capture.TUNStack != "system" {
		t.Fatalf("Prepare() did not expose effective TUN stack: %q", prepared.Capture.TUNStack)
	}
	runtimeInfo, err := os.Stat(prepared.RuntimeConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeInfo.Mode().Perm() != 0o600 {
		t.Fatalf("runtime config mode = %o, want 600", runtimeInfo.Mode().Perm())
	}
	runtimeRoot := filepath.Dir(prepared.RuntimeConfigPath)
	runtimeRootInfo, err := os.Lstat(runtimeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(runtimeRoot) != runtimeBase || runtimeRootInfo.Mode().Perm() != 0o700 || !runtimeRootInfo.IsDir() || runtimeRootInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("runtime root = %q mode=%v, want private child of %q", runtimeRoot, runtimeRootInfo.Mode(), runtimeBase)
	}
	runtimeConfig, err := os.ReadFile(prepared.RuntimeConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"redir-port: 7893",
		"dns:\n  enable: true\n  listen: \"0.0.0.0:7874\"",
		"tun:\n  enable: true",
		"  device: \"clash-tun\"",
		"external-controller: \"127.0.0.1:9090\"",
		"secret: \"secret\"",
		"routing-mark: 2",
		"proxy-groups: [{name: USER, type: select, proxies: [DIRECT]}]",
	} {
		if !strings.Contains(string(runtimeConfig), expected) {
			t.Errorf("runtime config missing %q:\n%s", expected, runtimeConfig)
		}
	}
	unchanged, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != source {
		t.Fatalf("source config changed: %s", unchanged)
	}
	record, err := os.ReadFile(validationRecord)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(record), "-t") || !strings.Contains(string(record), prepared.RuntimeConfigPath) || !strings.Contains(string(record), "-d "+dir) {
		t.Fatalf("native validation arguments were not used: %s", record)
	}
	version, err := driver.Version(context.Background(), binary)
	if err != nil || version != "Mihomo Meta v-test" {
		t.Fatalf("Version() = %q, %v", version, err)
	}
}

func TestMihomoPrepareRejectsNativeValidationFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	binary, _, _ := writeFakeMihomo(t, dir)
	sourcePath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(sourcePath, []byte("mode: rule\nreject-validation: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.Mkdir(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	driver := NewMihomoDriver(MihomoOptions{})
	_, err := driver.Prepare(context.Background(), PrepareRequest{
		BinaryPath:       binary,
		SourceConfigPath: sourcePath,
		RuntimeDir:       runtimeDir,
		Capture: CapturePlan{
			TCP: ProtocolCapture{Method: CaptureTPROXY, Port: 7894},
			UDP: ProtocolCapture{Method: CaptureTPROXY, Port: 7894},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "native validation rejected config") {
		t.Fatalf("Prepare() error = %v", err)
	}
	entries, readErr := os.ReadDir(runtimeDir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("failed validation left runtime files: %#v", entries)
	}
}

func TestCleanupPreparedRuntimeRequiresExactPrivateOwnership(t *testing.T) {
	t.Parallel()
	outsideRoot := t.TempDir()
	makeOwned := func() (PreparedCore, string) {
		t.Helper()
		runtimeRoot := t.TempDir()
		sourcePath := filepath.Join(outsideRoot, "source.yaml")
		ownedPath := filepath.Join(runtimeRoot, "mihomo-runtime.yaml")
		if err := os.WriteFile(ownedPath, []byte("runtime\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return PreparedCore{
			SourceConfigPath:       sourcePath,
			RuntimeConfigPath:      ownedPath,
			runtimeConfigRoot:      runtimeRoot,
			runtimeConfigOwnedPath: ownedPath,
		}, runtimeRoot
	}

	owned, ownedRoot := makeOwned()
	CleanupPreparedRuntime(owned)
	if _, err := os.Stat(ownedRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact owned runtime root survived cleanup: %v", err)
	}

	changedPath, changedRoot := makeOwned()
	outsidePath := filepath.Join(outsideRoot, "mihomo-outside.yaml")
	if err := os.WriteFile(outsidePath, []byte("outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changedPath.RuntimeConfigPath = outsidePath
	CleanupPreparedRuntime(changedPath)
	if _, err := os.Stat(outsidePath); err != nil {
		t.Fatalf("out-of-root runtime was removed: %v", err)
	}
	if _, err := os.Stat(changedRoot); err != nil {
		t.Fatalf("root with changed path was removed: %v", err)
	}

	changedPath, changedRoot = makeOwned()
	siblingPath := filepath.Join(changedRoot, "mihomo-sibling.yaml")
	if err := os.WriteFile(siblingPath, []byte("sibling\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changedPath.RuntimeConfigPath = siblingPath
	CleanupPreparedRuntime(changedPath)
	if _, err := os.Stat(siblingPath); err != nil {
		t.Fatalf("unowned sibling runtime was removed: %v", err)
	}

	unmarkedRoot := t.TempDir()
	unmarkedPath := filepath.Join(unmarkedRoot, "mihomo-unmarked.yaml")
	if err := os.WriteFile(unmarkedPath, []byte("unmarked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	CleanupPreparedRuntime(PreparedCore{SourceConfigPath: filepath.Join(outsideRoot, "source.yaml"), RuntimeConfigPath: unmarkedPath})
	if _, err := os.Stat(unmarkedPath); err != nil {
		t.Fatalf("runtime without private ownership was removed: %v", err)
	}

	symlinked, symlinkedRoot := makeOwned()
	if err := os.Remove(symlinked.RuntimeConfigPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsidePath, symlinked.RuntimeConfigPath); err != nil {
		t.Fatal(err)
	}
	CleanupPreparedRuntime(symlinked)
	if _, err := os.Lstat(symlinked.RuntimeConfigPath); err != nil {
		t.Fatalf("symlink substitution was followed or removed: %v", err)
	}
	if _, err := os.Stat(symlinkedRoot); err != nil {
		t.Fatalf("root with symlink substitution was removed: %v", err)
	}
}

func TestMihomoPrepareResistsPrecreatedAndSymlinkRuntimePaths(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	binary, _, _ := writeFakeMihomo(t, dir)
	sourcePath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(sourcePath, []byte("mode: rule\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runtimeBase := t.TempDir()
	outside := t.TempDir()
	preexistingPath := filepath.Join(runtimeBase, "boxctl")
	if err := os.Symlink(outside, preexistingPath); err != nil {
		t.Fatal(err)
	}
	precreatedPath := filepath.Join(runtimeBase, "mihomo-runtime.yaml")
	if err := os.Symlink(filepath.Join(outside, "attacker.yaml"), precreatedPath); err != nil {
		t.Fatal(err)
	}

	driver := NewMihomoDriver(MihomoOptions{})
	prepared, err := driver.Prepare(context.Background(), PrepareRequest{
		BinaryPath: binary, SourceConfigPath: sourcePath, RuntimeDir: runtimeBase,
		Capture: CapturePlan{
			TCP: ProtocolCapture{Method: CaptureTPROXY, Port: 7894},
			UDP: ProtocolCapture{Method: CaptureTPROXY, Port: 7894},
		},
		Controller: ControllerEndpoint{Listen: "192.168.8.1:19090", Secret: "secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer CleanupPreparedRuntime(prepared)
	if filepath.Dir(filepath.Dir(prepared.RuntimeConfigPath)) != runtimeBase || filepath.Dir(prepared.RuntimeConfigPath) == preexistingPath {
		t.Fatalf("runtime path %q is not in a fresh private root", prepared.RuntimeConfigPath)
	}
	if prepared.Controller.Listen != "127.0.0.1:19090" || prepared.Controller.Secret != "secret" {
		t.Fatalf("controller = %+v", prepared.Controller)
	}
	content, err := os.ReadFile(prepared.RuntimeConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `external-controller: "127.0.0.1:19090"`) {
		t.Fatalf("runtime controller was not loopback-only:\n%s", content)
	}
	if _, err := os.Lstat(preexistingPath); err != nil {
		t.Fatalf("precreated symlink was modified: %v", err)
	}
	if _, err := os.Lstat(precreatedPath); err != nil {
		t.Fatalf("precreated config symlink was modified: %v", err)
	}

	symlinkBase := filepath.Join(dir, "runtime-link")
	if err := os.Symlink(outside, symlinkBase); err != nil {
		t.Fatal(err)
	}
	_, err = driver.Prepare(context.Background(), PrepareRequest{
		BinaryPath: binary, SourceConfigPath: sourcePath, RuntimeDir: symlinkBase,
		Capture: CapturePlan{
			TCP: ProtocolCapture{Method: CaptureTPROXY, Port: 7894},
			UDP: ProtocolCapture{Method: CaptureTPROXY, Port: 7894},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "non-symlink directory") {
		t.Fatalf("Prepare(symlink base) error = %v", err)
	}
}

func TestNormalizeControllerForcesExplicitLANListenToLoopback(t *testing.T) {
	t.Parallel()
	for _, secret := range []string{"", "keep-me"} {
		endpoint, err := normalizeController(ControllerEndpoint{Listen: "192.168.8.1:19090", Secret: secret})
		if err != nil {
			t.Fatal(err)
		}
		if endpoint.Listen != "127.0.0.1:19090" || endpoint.BaseURL != "http://127.0.0.1:19090" || endpoint.Secret != secret {
			t.Fatalf("normalizeController(secret=%q) = %+v", secret, endpoint)
		}
	}
}

func TestMihomoLifecycleReloadHealthLogsAndProcessGroup(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	binary, _, childPIDPath := writeFakeMihomo(t, dir)
	sourcePath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(sourcePath, []byte("mode: rule\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	reloadPaths := make([]string, 0)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer lifecycle-secret" {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/version":
			_, _ = io.WriteString(writer, `{"version":"controller-test"}`)
		case request.Method == http.MethodPut && request.URL.Path == "/configs":
			var payload struct {
				Path string `json:"path"`
			}
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}
			mu.Lock()
			reloadPaths = append(reloadPaths, payload.Path)
			mu.Unlock()
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.Error(writer, "unexpected", http.StatusNotFound)
		}
	}))
	defer server.Close()

	driver := NewMihomoDriver(MihomoOptions{HTTPClient: server.Client(), StopTimeout: 2 * time.Second, LogBuffer: 64})
	dnsEndpoint := startFakeDNSResponder(t, func(query []byte) []byte {
		response := append([]byte(nil), query...)
		encodingbinary.BigEndian.PutUint16(response[2:4], 0x8180)
		return response
	})
	request := PrepareRequest{
		BinaryPath:       binary,
		SourceConfigPath: sourcePath,
		RuntimeDir:       dir,
		Capture: CapturePlan{
			TCP: ProtocolCapture{Method: CaptureTPROXY, Port: 7894},
			UDP: ProtocolCapture{Method: CaptureTPROXY, Port: 7894},
			DNS: dnsEndpoint,
		},
		Controller: ControllerEndpoint{Listen: "0.0.0.0:9090", BaseURL: server.URL, Secret: "lifecycle-secret"},
	}
	prepared, err := driver.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Start(context.Background(), prepared); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = driver.Stop(context.Background()) })
	if err := driver.Start(context.Background(), prepared); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second Start() error = %v, want ErrAlreadyRunning", err)
	}

	childPID := waitForChildPID(t, childPIDPath)
	status, err := driver.Health(context.Background())
	if err != nil || !status.Running || !status.ControllerReady || !status.DNSReady || status.Version != "controller-test" || status.PID <= 1 {
		t.Fatalf("Health() = %#v, %v", status, err)
	}
	wantLogs := map[string]bool{"fake stdout ready": false, "fake stderr ready": false}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for remaining := len(wantLogs); remaining > 0; {
		select {
		case entry := <-driver.Logs():
			if seen, ok := wantLogs[entry.Message]; ok && !seen {
				wantLogs[entry.Message] = true
				remaining--
			}
		case <-deadline.C:
			t.Fatalf("timed out waiting for process logs: %#v", wantLogs)
		}
	}

	second, err := driver.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if second.RuntimeConfigPath == prepared.RuntimeConfigPath {
		t.Fatal("Prepare reused mutable runtime config path")
	}
	if err := driver.Reload(context.Background(), second); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if _, err := os.Stat(prepared.RuntimeConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old runtime config survived reload: %v", err)
	}
	mu.Lock()
	if len(reloadPaths) != 1 || reloadPaths[0] != second.RuntimeConfigPath {
		t.Fatalf("reload paths = %#v", reloadPaths)
	}
	mu.Unlock()

	if err := driver.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if _, err := os.Stat(second.RuntimeConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active runtime config survived stop: %v", err)
	}
	if err := driver.Stop(context.Background()); err != nil {
		t.Fatalf("idempotent Stop() error = %v", err)
	}
	if processExists(childPID) {
		deadline := time.Now().Add(2 * time.Second)
		for processExists(childPID) && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if processExists(childPID) {
		t.Fatalf("child process %d survived process-group stop", childPID)
	}
	status, err = driver.Health(context.Background())
	if err != nil || status.Running {
		t.Fatalf("Health() after Stop = %#v, %v", status, err)
	}
}

func TestMihomoUnsupportedAndContextCancellation(t *testing.T) {
	t.Parallel()
	driver := NewMihomoDriver(MihomoOptions{})
	prepared := PreparedCore{Capabilities: Capabilities{HotReload: false}}
	if err := driver.Reload(context.Background(), prepared); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Reload() error = %v, want ErrUnsupported", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := driver.Start(ctx, PreparedCore{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start(cancelled) error = %v", err)
	}
	if _, err := driver.Proxies(context.Background()); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Proxies() error = %v, want ErrNotRunning", err)
	}
}

func TestCapturePlanValidation(t *testing.T) {
	t.Parallel()
	valid := CapturePlan{
		TCP:       ProtocolCapture{Method: CaptureRedirect, Port: 7893},
		UDP:       ProtocolCapture{Method: CaptureTUN},
		TUNDevice: "clash-tun",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid plan rejected: %v", err)
	}
	invalid := valid
	invalid.TCP.Port = 0
	if err := invalid.Validate(); err == nil {
		t.Fatal("redirect plan without port accepted")
	}
	invalid = valid
	invalid.TUNDevice = ""
	if err := invalid.Validate(); err == nil {
		t.Fatal("TUN plan without device accepted")
	}
}

func TestMihomoRejectsDifferentTCPAndUDPTProxyPorts(t *testing.T) {
	t.Parallel()
	_, err := mihomoCaptureFromPlan(CapturePlan{
		TCP: ProtocolCapture{Method: CaptureTPROXY, Port: 7894},
		UDP: ProtocolCapture{Method: CaptureTPROXY, Port: 7895},
	})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("mihomoCaptureFromPlan() error = %v, want ErrUnsupported", err)
	}
}

func writeFakeMihomo(t *testing.T, dir string) (binaryPath, validationRecord, childPIDPath string) {
	t.Helper()
	validationRecord = filepath.Join(dir, "validation-args")
	childPIDPath = filepath.Join(dir, "child-pid")
	binaryPath = filepath.Join(dir, "mihomo-fake")
	script := fmt.Sprintf(`#!/bin/sh
original_args="$*"
if [ "$1" = "-v" ]; then
  echo "Mihomo Meta v-test"
  exit 0
fi
test_mode=0
config=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -t) test_mode=1 ;;
    -f) shift; config="$1" ;;
  esac
  shift
done
if [ "$test_mode" = "1" ]; then
  printf '%%s\n' "$original_args" >> %s
  if grep -q '^reject-validation: true' "$config"; then
    echo "native validation rejected config" >&2
    exit 42
  fi
  echo "configuration is valid"
  exit 0
fi
echo "fake stdout ready"
echo "fake stderr ready" >&2
sleep 300 &
child=$!
printf '%%s\n' "$child" > %s
trap 'exit 0' TERM INT
while :; do sleep 1; done
`, shellQuoteForTest(validationRecord), shellQuoteForTest(childPIDPath))
	if err := os.WriteFile(binaryPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return binaryPath, validationRecord, childPIDPath
}

func shellQuoteForTest(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func waitForChildPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data)))
			if parseErr == nil && pid > 1 {
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for fake Mihomo child PID at %s", path)
	return 0
}

func processExists(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
