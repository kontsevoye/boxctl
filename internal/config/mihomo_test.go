package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectMihomoManagedValuesAndSecretRedaction(t *testing.T) {
	t.Parallel()
	const rawSecret = "never-leak-this-controller-secret"
	source := []byte("" +
		"mode: rule\n" +
		"external-controller: \"0.0.0.0:9090\" # controller\n" +
		"secret: 'never-leak-this-controller-secret'\n" +
		"routing-mark: 0x2\n" +
		"tproxy-port: 7894\n" +
		"redir-port: \"7893\"\n" +
		"dns:\n" +
		"  enable: true\n" +
		"  listen: ':7874'\n" +
		"  enhanced-mode: fake-ip\n" +
		"  fake-ip-range: 198.18.0.1/16\n" +
		"  fake-ip-filter-mode: rule\n" +
		"  nameserver: [https://1.1.1.1/dns-query]\n" +
		"tun:\n" +
		"  enable: true\n" +
		"  device: mihomo-tun\n" +
		"  stack: system\n" +
		"proxy-groups: [{name: USER, type: select, proxies: [DIRECT]}]\n")

	values, err := InspectMihomo(source)
	if err != nil {
		t.Fatalf("InspectMihomo() error = %v", err)
	}
	assertStringPointer(t, "external-controller", values.ExternalController, "0.0.0.0:9090")
	assertUint32Pointer(t, "routing-mark", values.RoutingMark, 2)
	assertUint16Pointer(t, "tproxy-port", values.TProxyPort, 7894)
	assertUint16Pointer(t, "redir-port", values.RedirectPort, 7893)
	if values.DNSEnabled == nil || !*values.DNSEnabled {
		t.Fatalf("dns.enable = %v, want true", values.DNSEnabled)
	}
	assertStringPointer(t, "dns.listen", values.DNSListen, ":7874")
	assertStringPointer(t, "dns.enhanced-mode", values.DNSEnhancedMode, "fake-ip")
	assertStringPointer(t, "dns.fake-ip-range", values.DNSFakeIPRange, "198.18.0.1/16")
	assertStringPointer(t, "dns.fake-ip-filter-mode", values.DNSFakeIPFilterMode, "rule")
	if values.TUNEnabled == nil || !*values.TUNEnabled {
		t.Fatalf("tun.enable = %v, want true", values.TUNEnabled)
	}
	assertStringPointer(t, "tun.device", values.TUNDevice, "mihomo-tun")
	assertStringPointer(t, "tun.stack", values.TUNStack, "system")
	if values.Secret == nil || values.Secret.Reveal() != rawSecret {
		t.Fatalf("secret was not imported through explicit Reveal")
	}

	jsonValues, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	jsonSecret, err := json.Marshal(values.Secret)
	if err != nil {
		t.Fatal(err)
	}
	textSecret, err := values.Secret.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	representations := []string{
		fmt.Sprint(values),
		fmt.Sprintf("%+v", values),
		fmt.Sprintf("%#v", values),
		fmt.Sprint(values.Secret),
		fmt.Sprintf("%#v", values.Secret),
		string(jsonValues),
		string(jsonSecret),
		string(textSecret),
	}
	for _, representation := range representations {
		if strings.Contains(representation, rawSecret) {
			t.Fatalf("secret leaked through representation %q", representation)
		}
	}
	if strings.Contains(string(jsonValues), "secret") || strings.Contains(string(jsonValues), "Secret") {
		t.Fatalf("managed values JSON contains a secret field: %s", jsonValues)
	}
}

func TestInspectMihomoAbsentValues(t *testing.T) {
	t.Parallel()
	values, err := InspectMihomo([]byte("mode: rule\ncustom.key: {arbitrary: yaml}\n"))
	if err != nil {
		t.Fatalf("InspectMihomo() error = %v", err)
	}
	if values.ExternalController != nil || values.Secret != nil || values.DNSEnabled != nil || values.DNSListen != nil || values.TUNEnabled != nil {
		t.Fatalf("absent values were reported as present: %s", values)
	}
}

func TestInspectMihomoFailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		source string
	}{
		{name: "duplicate managed key", source: "secret: one\n\"secret\": two\n"},
		{name: "top-level merge", source: "defaults: &defaults {secret: inherited}\n<<: *defaults\n"},
		{name: "nested merge", source: "dns:\n  <<: *dns-defaults\n  listen: :53\n"},
		{name: "flow managed mapping", source: "dns: {listen: ':53'}\n"},
		{name: "aliased managed scalar", source: "secret: *controller-secret\n"},
		{name: "block managed scalar", source: "secret: |\n  value\n"},
		{name: "tagged managed key", source: "!!str secret: value\n"},
		{name: "bad routing mark", source: "routing-mark: negative\n"},
		{name: "overflow port", source: "tproxy-port: 70000\n"},
		{name: "ambiguous boolean", source: "tun:\n  enable: yes\n"},
		{name: "managed parent sequence", source: "tun:\n  - enable: true\n"},
		{name: "multiple documents", source: "mode: rule\n---\nmode: direct\n"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := InspectMihomo([]byte(test.source))
			if !errors.Is(err, ErrUnsafeYAML) {
				t.Fatalf("InspectMihomo() error = %v, want ErrUnsafeYAML", err)
			}
			if strings.Contains(fmt.Sprint(err), "never-leak") {
				t.Fatal("InspectMihomo error leaked a secret")
			}
		})
	}
}

func assertStringPointer(t *testing.T, name string, got *string, want string) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("%s = %v, want %q", name, got, want)
	}
}

func assertUint16Pointer(t *testing.T, name string, got *uint16, want uint16) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("%s = %v, want %d", name, got, want)
	}
}

func assertUint32Pointer(t *testing.T, name string, got *uint32, want uint32) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("%s = %v, want %d", name, got, want)
	}
}

func TestPatchMihomoPreservesUnmanagedYAML(t *testing.T) {
	t.Parallel()
	source := strings.Join([]string{
		"# user header",
		"mode: rule",
		"tproxy-port: 9999 # managed comment",
		"external-controller: 127.0.0.1:1",
		"secret: old",
		"routing-mark: 99",
		"dns:",
		"    enable: true",
		"    listen: 127.0.0.1:1 # dns comment",
		"    nameserver: [https://1.1.1.1/dns-query]",
		"tun:",
		"  enable: false",
		"  custom-option: &custom {answer: 42}",
		"proxy-groups: [{name: '# untouched', type: select, proxies: [DIRECT]}]",
		"rules:",
		"  - MATCH,DIRECT",
		"",
	}, "\r\n")
	original := []byte(source)
	controller := "0.0.0.0:9090"
	secret := "value # : & * must be quoted"
	dns := "0.0.0.0:7874"
	dnsEnabled := true
	mark := uint32(2)

	result, err := PatchMihomo(original, MihomoPatch{
		Capture: &MihomoCapture{
			Mode:         MihomoCaptureMixed2,
			RedirectPort: 7893,
			TUNDevice:    "clash-tun",
			TUNStack:     "gvisor",
		},
		ExternalController: &controller,
		Secret:             &secret,
		DNSEnabled:         &dnsEnabled,
		DNSListen:          &dns,
		RoutingMark:        &mark,
	})
	if err != nil {
		t.Fatalf("PatchMihomo() error = %v", err)
	}
	if string(original) != source {
		t.Fatal("PatchMihomo modified its input buffer")
	}
	got := string(result)
	for _, unchanged := range []string{
		"# user header\r\n",
		"mode: rule\r\n",
		"    nameserver: [https://1.1.1.1/dns-query]\r\n",
		"  custom-option: &custom {answer: 42}\r\n",
		"proxy-groups: [{name: '# untouched', type: select, proxies: [DIRECT]}]\r\n",
		"rules:\r\n  - MATCH,DIRECT\r\n",
	} {
		if !strings.Contains(got, unchanged) {
			t.Errorf("unmanaged YAML was not preserved; missing %q\n%s", unchanged, got)
		}
	}
	for _, managed := range []string{
		"external-controller: \"0.0.0.0:9090\"",
		"secret: \"value # : & * must be quoted\"",
		"routing-mark: 2",
		"    enable: true",
		"    listen: \"0.0.0.0:7874\" # dns comment",
		"  enable: true",
		"  device: \"clash-tun\"",
		"  stack: \"gvisor\"",
		"  auto-route: false",
		"  auto-redirect: false",
		"  auto-detect-interface: false",
		"redir-port: 7893",
	} {
		if !strings.Contains(got, managed) {
			t.Errorf("managed YAML missing %q\n%s", managed, got)
		}
	}
	if strings.Contains(got, "tproxy-port:") {
		t.Errorf("MIXED2 retained tproxy-port:\n%s", got)
	}
	if strings.Contains(strings.ReplaceAll(got, "\r\n", ""), "\n") {
		t.Fatal("PatchMihomo changed CRLF newline style")
	}
}

func TestPatchMihomoCaptureModes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		mode     MihomoCaptureMode
		contains []string
		excludes []string
	}{
		{name: "tproxy", mode: MihomoCaptureTPROXY, contains: []string{"tproxy-port: 7894", "  enable: false"}, excludes: []string{"redir-port:"}},
		{name: "hybrid", mode: MihomoCaptureHybrid, contains: []string{"tproxy-port: 7894", "redir-port: 7893", "  enable: false"}},
		{name: "tun", mode: MihomoCaptureTUN, contains: []string{"  enable: true", "  device: \"clash-tun\""}, excludes: []string{"tproxy-port:", "redir-port:"}},
		{name: "mixed", mode: MihomoCaptureMixed, contains: []string{"tproxy-port: 7894", "  enable: true"}, excludes: []string{"redir-port:"}},
		{name: "mixed2", mode: MihomoCaptureMixed2, contains: []string{"redir-port: 7893", "  enable: true"}, excludes: []string{"tproxy-port:"}},
	}
	const source = "mode: rule\ntproxy-port: 1111\nredir-port: 2222\ntun:\n  enable: true\n  unknown: keep\n"
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := PatchMihomo([]byte(source), MihomoPatch{Capture: &MihomoCapture{Mode: test.mode}})
			if err != nil {
				t.Fatalf("PatchMihomo() error = %v", err)
			}
			got := string(result)
			if !strings.Contains(got, "  unknown: keep") {
				t.Fatalf("unknown nested key was lost:\n%s", got)
			}
			for _, value := range test.contains {
				if !strings.Contains(got, value) {
					t.Errorf("result does not contain %q:\n%s", value, got)
				}
			}
			for _, value := range test.excludes {
				if strings.Contains(got, value) {
					t.Errorf("result unexpectedly contains %q:\n%s", value, got)
				}
			}
		})
	}
}

func TestPatchMihomoCreatesManagedMappings(t *testing.T) {
	t.Parallel()
	dns := "0.0.0.0:7874"
	dnsEnabled := true
	result, err := PatchMihomo([]byte("---\nmode: rule\n...\n"), MihomoPatch{
		Capture:    &MihomoCapture{Mode: MihomoCaptureTUN},
		DNSEnabled: &dnsEnabled,
		DNSListen:  &dns,
	})
	if err != nil {
		t.Fatalf("PatchMihomo() error = %v", err)
	}
	got := string(result)
	terminator := strings.Index(got, "...")
	for _, value := range []string{"dns:\n  enable: true\n  listen: \"0.0.0.0:7874\"", "tun:\n  enable: true"} {
		index := strings.Index(got, value)
		if index < 0 || index > terminator {
			t.Errorf("managed mapping %q not inserted before document terminator:\n%s", value, got)
		}
	}
}

func TestPatchMihomoLeavesDNSBlockUntouchedWhenDNSIsUnmanaged(t *testing.T) {
	t.Parallel()
	const source = "mode: rule\ndns:\n  enable: false # user choice\n  listen: 127.0.0.1:5353\n  nameserver: [system]\ntun:\n  enable: false\n"
	result, err := PatchMihomo([]byte(source), MihomoPatch{Capture: &MihomoCapture{Mode: MihomoCaptureTPROXY}})
	if err != nil {
		t.Fatalf("PatchMihomo() error = %v", err)
	}
	const dnsBlock = "dns:\n  enable: false # user choice\n  listen: 127.0.0.1:5353\n  nameserver: [system]\n"
	if !strings.Contains(string(result), dnsBlock) {
		t.Fatalf("DNS block changed while DNS management was disabled:\n%s", result)
	}
}

func TestPatchMihomoFailsClosed(t *testing.T) {
	t.Parallel()
	controller := "0.0.0.0:9090"
	stackPatch := MihomoPatch{Capture: &MihomoCapture{Mode: MihomoCaptureTUN}}
	tests := []struct {
		name   string
		source string
		patch  MihomoPatch
	}{
		{name: "flow managed mapping", source: "mode: rule\ntun: {enable: true}\n", patch: stackPatch},
		{name: "duplicate managed key", source: "external-controller: a\n'external-controller': b\n", patch: MihomoPatch{ExternalController: &controller}},
		{name: "block scalar", source: "secret: |\n  value\n", patch: MihomoPatch{Secret: &controller}},
		{name: "second document", source: "mode: rule\n---\nmode: direct\n", patch: MihomoPatch{ExternalController: &controller}},
		{name: "flow root", source: "{mode: rule}\n", patch: MihomoPatch{ExternalController: &controller}},
		{name: "tab indentation", source: "dns:\n\tlisten: :53\n", patch: stackPatch},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := PatchMihomo([]byte(test.source), test.patch)
			if !errors.Is(err, ErrUnsafeYAML) {
				t.Fatalf("PatchMihomo() error = %v, want ErrUnsafeYAML", err)
			}
		})
	}
}

func TestPatchMihomoNoopIsExactCopy(t *testing.T) {
	t.Parallel()
	source := []byte("{flow: [style, stays], merge: *whatever}\n")
	result, err := PatchMihomo(source, MihomoPatch{})
	if err != nil {
		t.Fatalf("PatchMihomo() error = %v", err)
	}
	if string(result) != string(source) {
		t.Fatalf("no-op changed input: %q != %q", result, source)
	}
	if len(result) > 0 {
		result[0] = 'X'
		if source[0] == 'X' {
			t.Fatal("no-op result aliases source buffer")
		}
	}
}

func TestWriteMihomoRuntimeIsPrivateAndDoesNotModifySource(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "config.yaml")
	runtimePath := filepath.Join(dir, "runtime", "mihomo.yaml")
	const source = "mode: rule\nsecret: user-owned\n"
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	secret := "runtime-only"
	if err := WriteMihomoRuntime(sourcePath, runtimePath, MihomoPatch{Secret: &secret}); err != nil {
		t.Fatalf("WriteMihomoRuntime() error = %v", err)
	}
	unchanged, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != source {
		t.Fatalf("source changed to %q", unchanged)
	}
	runtimeInfo, err := os.Stat(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeInfo.Mode().Perm() != 0o600 {
		t.Fatalf("runtime mode = %o, want 600", runtimeInfo.Mode().Perm())
	}
	runtimeConfig, err := os.ReadFile(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(runtimeConfig), `secret: "runtime-only"`) {
		t.Fatalf("runtime config was not patched: %s", runtimeConfig)
	}
	if err := WriteMihomoRuntime(sourcePath, sourcePath, MihomoPatch{}); err == nil {
		t.Fatal("WriteMihomoRuntime allowed source replacement")
	}
}
