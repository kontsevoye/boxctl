package app

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
)

type recordingSingBoxConfig struct {
	request engine.PrepareRequest
}

func (config *recordingSingBoxConfig) Prepare(_ context.Context, request engine.PrepareRequest) (engine.PreparedCore, error) {
	config.request = request
	content, err := os.ReadFile(request.SourceConfigPath)
	if err != nil {
		return engine.PreparedCore{}, err
	}
	runtime, err := os.CreateTemp(request.RuntimeDir, "recording-sing-box-runtime-*.json")
	if err != nil {
		return engine.PreparedCore{}, err
	}
	if _, err := runtime.Write(content); err != nil {
		_ = runtime.Close()
		return engine.PreparedCore{}, err
	}
	if err := runtime.Close(); err != nil {
		return engine.PreparedCore{}, err
	}
	return engine.PreparedCore{
		Engine: state.EngineSingBox, SourceConfigPath: request.SourceConfigPath,
		RuntimeConfigPath: runtime.Name(), Capture: request.Capture, Controller: request.Controller,
	}, nil
}

func (*recordingSingBoxConfig) Validate(context.Context, engine.PreparedCore) error { return nil }

func TestActiveSingBoxPreparerAppliesManagerOwnedTUNSettingsOnlyForTUNCapture(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{"engines/sing-box", ".boxctl", "configs"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(root, "engines", "sing-box", "sing-box")
	if err := os.WriteFile(binary, []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	profiles, err := state.NewProfileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	profile := state.ActiveProfile{Name: "native", Engine: state.EngineSingBox}
	if err := profiles.Create(context.Background(), profile, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Activate(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSettings(settingsRelativePath, state.Settings{
		"PROXY_MODE":          "tun",
		"ENABLE_DNS_UPSTREAM": "false",
		"SINGBOX_TUN_ADDRESS": "172.30.255.1/30",
		"SINGBOX_TUN_MTU":     "1400",
	}); err != nil {
		t.Fatal(err)
	}
	recorder := &recordingSingBoxConfig{}
	preparer, err := NewActiveSingBoxPreparer(root, recorder)
	if err != nil {
		t.Fatal(err)
	}
	preparer.RuntimeDir = t.TempDir()
	prepared, err := preparer.PrepareActive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(prepared.RuntimeConfigPath)
	wantAddress := netip.MustParsePrefix("172.30.255.1/30")
	if len(recorder.request.Capture.TUNAddresses) != 1 || recorder.request.Capture.TUNAddresses[0] != wantAddress || recorder.request.Capture.TUNMTU != 1400 {
		t.Fatalf("sing-box capture = %+v", recorder.request.Capture)
	}
}

func TestValidateSingBoxUpstreamDNSRejectsResolverCycles(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{name: "missing", content: `{}`, wantErr: true},
		{name: "empty", content: `{"dns":{"servers":[]}}`, wantErr: true},
		{name: "implicit local", content: `{"dns":{"servers":[{"type":"local","tag":"system"}]}}`, wantErr: true},
		{name: "resolved service", content: `{"dns":{"servers":[{"type":"resolved","tag":"system","service":"resolved"}]}}`, wantErr: true},
		{name: "loopback dnsmasq", content: `{"dns":{"servers":[{"type":"udp","tag":"dnsmasq","server":"127.0.0.1"}]}}`, wantErr: true},
		{name: "managed listener", content: `{"dns":{"servers":[{"type":"udp","tag":"self","server":"::1","server_port":7874}]}}`, wantErr: true},
		{name: "hosts only", content: `{"dns":{"servers":[{"type":"hosts","tag":"hosts","predefined":{"router.lan":"192.168.1.1"}}],"final":"hosts"}}`, wantErr: true},
		{name: "mdns default before upstream", content: `{"dns":{"servers":[{"type":"mdns","tag":"mdns"},{"type":"udp","tag":"upstream","server":"1.1.1.1"}]}}`, wantErr: true},
		{name: "fakeip final", content: `{"dns":{"servers":[{"type":"udp","tag":"upstream","server":"1.1.1.1"},{"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15"}],"final":"fake"}}`, wantErr: true},
		{name: "tailscale without defaults", content: `{"dns":{"servers":[{"type":"tailscale","tag":"ts","endpoint":"ts-ep"}],"final":"ts"}}`, wantErr: true},
		{name: "missing final tag", content: `{"dns":{"servers":[{"type":"udp","tag":"upstream","server":"1.1.1.1"}],"final":"missing"}}`, wantErr: true},
		{name: "hosts auxiliary", content: `{"dns":{"servers":[{"type":"udp","tag":"upstream","server":"1.1.1.1"},{"type":"hosts","tag":"hosts"}],"final":"upstream"}}`},
		{name: "tailscale with defaults", content: `{"dns":{"servers":[{"type":"tailscale","tag":"ts","endpoint":"ts-ep","accept_default_resolvers":true}],"final":"ts"}}`},
		{name: "literal upstream", content: `{"dns":{"servers":[{"type":"udp","tag":"upstream","server":"1.1.1.1"}],"final":"upstream"}}`},
		{name: "separate local service", content: `{"dns":{"servers":[{"type":"udp","tag":"stub","server":"127.0.0.1","server_port":5353}],"final":"stub"}}`},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateSingBoxUpstreamDNS([]byte(test.content), 7874)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateSingBoxUpstreamDNS() error = %v, wantErr=%t", err, test.wantErr)
			}
		})
	}
}
