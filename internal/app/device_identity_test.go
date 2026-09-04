package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontsevoye/boxctl/internal/state"
)

func TestDeviceIdentityIsStableAndUsesOpenWrtMetadata(t *testing.T) {
	root := t.TempDir()
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(root, "openwrt_release")
	model := filepath.Join(root, "model")
	if err := os.WriteFile(release, []byte("DISTRIB_RELEASE='24.10.2'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(model, []byte("Example Router\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity := &DeviceIdentity{
		State: store, ReleasePath: release, ModelPath: model,
		Random: strings.NewReader("0123456789abcdef"),
	}
	first, err := identity.Headers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := identity.Headers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first["x-hwid"] == "" || first["x-hwid"] != second["x-hwid"] || !validHWID.MatchString(first["x-hwid"]) {
		t.Fatalf("unstable HWID: first=%q second=%q", first["x-hwid"], second["x-hwid"])
	}
	if first["x-device-os"] != "OpenWrt" || first["x-ver-os"] != "24.10.2" || first["x-device-model"] != "Example Router" || !strings.Contains(first["User-Agent"], "Example Router") {
		t.Fatalf("headers = %#v", first)
	}
	info, err := os.Stat(filepath.Join(root, hwidRelativePath))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("HWID state mode = %v, err=%v", info, err)
	}
}
