package engine

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClonePreparedRuntimePreservesExactGenerationForBothEngines(t *testing.T) {
	t.Parallel()
	tests := []struct {
		engine   string
		filename string
		args     func(string) []string
	}{
		{mihomoEngineName, "mihomo-runtime.yaml", func(path string) []string { return []string{"-d", "/state", "-f", path} }},
		{SingBoxEngineName, "sing-box-runtime.json", func(path string) []string { return []string{"run", "-D", "/state", "-c", path} }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.engine, func(t *testing.T) {
			t.Parallel()
			base := t.TempDir()
			root := filepath.Join(base, "boxctl-"+test.engine+"-live")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, test.filename)
			content := []byte("exact-applied-runtime\nsecret=value\n")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			prepared := PreparedCore{
				Engine: test.engine, BinaryPath: "/opt/core", SourceConfigPath: "/profiles/source",
				SourceRevision: "sha256:old-applied", RuntimeConfigPath: path, HomeDir: "/state",
				Args: test.args(path), Env: []string{"A=B"},
				Capture: CapturePlan{
					TCP: ProtocolCapture{Method: CaptureTUN}, UDP: ProtocolCapture{Method: CaptureTUN},
					TUNDevice: "clash-tun", TUNAddresses: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
					EndpointBypassCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")},
				},
				Controller:        ControllerEndpoint{Listen: "127.0.0.1:9090", Secret: "secret"},
				runtimeConfigRoot: root, runtimeConfigOwnedPath: path,
			}
			cloned, err := ClonePreparedRuntime(prepared)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { CleanupPreparedRuntime(cloned) })
			if cloned.RuntimeConfigPath == path || cloned.runtimeConfigRoot == root || filepath.Dir(cloned.runtimeConfigRoot) != base {
				t.Fatalf("clone paths = %#v", cloned)
			}
			if cloned.Engine != prepared.Engine || cloned.BinaryPath != prepared.BinaryPath || cloned.SourceConfigPath != prepared.SourceConfigPath ||
				cloned.SourceRevision != prepared.SourceRevision || cloned.HomeDir != prepared.HomeDir || cloned.Controller != prepared.Controller ||
				len(cloned.Env) != 1 || cloned.Env[0] != "A=B" {
				t.Fatalf("clone metadata changed: %#v", cloned)
			}
			for _, argument := range cloned.Args {
				if strings.Contains(argument, path) {
					t.Fatalf("old runtime path survived in args: %#v", cloned.Args)
				}
			}
			if cloned.Args[len(cloned.Args)-1] != cloned.RuntimeConfigPath {
				t.Fatalf("clone args = %#v", cloned.Args)
			}
			cloneContent, err := os.ReadFile(cloned.RuntimeConfigPath)
			if err != nil || string(cloneContent) != string(content) {
				t.Fatalf("clone content = %q, %v", cloneContent, err)
			}
			rootInfo, err := os.Lstat(cloned.runtimeConfigRoot)
			if err != nil || rootInfo.Mode().Perm() != 0o700 || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
				t.Fatalf("clone root = %v, %v", rootInfo, err)
			}
			fileInfo, err := os.Lstat(cloned.RuntimeConfigPath)
			if err != nil || fileInfo.Mode().Perm() != 0o600 || !fileInfo.Mode().IsRegular() || fileInfo.Mode()&os.ModeSymlink != 0 {
				t.Fatalf("clone file = %v, %v", fileInfo, err)
			}
			cloned.Env[0] = "changed"
			cloned.Capture.TUNAddresses[0] = netip.MustParsePrefix("172.20.0.1/30")
			if prepared.Env[0] != "A=B" || prepared.Capture.TUNAddresses[0].String() != "172.19.0.1/30" {
				t.Fatal("clone aliases mutable slices from live generation")
			}
			CleanupPreparedRuntime(cloned)
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("clone cleanup removed live runtime: %v", err)
			}
		})
	}
}

func TestClonePreparedRuntimeRejectsUnownedAndSubstitutedFiles(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "mihomo-runtime.yaml")
	if err := os.WriteFile(path, []byte("runtime\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ClonePreparedRuntime(PreparedCore{Engine: mihomoEngineName, RuntimeConfigPath: path}); err == nil || !strings.Contains(err.Error(), "private ownership") {
		t.Fatalf("unowned clone error = %v", err)
	}

	root := filepath.Join(directory, "boxctl-mihomo-live")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "mihomo-runtime.yaml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	prepared := PreparedCore{
		Engine: mihomoEngineName, RuntimeConfigPath: link, Args: []string{"-f", link},
		runtimeConfigRoot: root, runtimeConfigOwnedPath: link,
	}
	if _, err := ClonePreparedRuntime(prepared); err == nil || !strings.Contains(err.Error(), "private regular file") {
		t.Fatalf("symlink clone error = %v", err)
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		t.Fatal("clone followed and removed symlink target")
	}
}
