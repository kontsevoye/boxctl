package openwrt_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func projectRoot(t *testing.T) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
}

func readProjectFile(t *testing.T, relative string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(projectRoot(t), filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestShellScriptsParse(t *testing.T) {
	t.Parallel()
	for _, relative := range []string{
		"scripts/calver.sh",
		"scripts/validate-calver.sh",
		"scripts/test-calver.sh",
		"packaging/openwrt/install.sh",
		"packaging/openwrt/files/etc/init.d/boxctl",
		"packaging/openwrt/files/etc/hotplug.d/iface/40-boxctl",
		"packaging/openwrt/files/etc/hotplug.d/net/99-boxctl-tun",
		"scripts/deploy-openwrt.sh",
		"scripts/test-deploy-openwrt.sh",
	} {
		relative := relative
		t.Run(relative, func(t *testing.T) {
			command := exec.Command("sh", "-n", filepath.Join(projectRoot(t), relative))
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("sh -n: %v\n%s", err, output)
			}
		})
	}
}

func TestInitScriptReexecsManagerWithoutStoppingCore(t *testing.T) {
	t.Parallel()
	text := readProjectFile(t, "packaging/openwrt/files/etc/init.d/boxctl")
	for _, required := range []string{
		`HANDOFF_MARKER="${BOXCTL_ROOT}/.boxctl/manager-handoff.json"`,
		`EXTRA_COMMANDS="manager_handoff"`,
		`procd_send_signal boxctl '*' 12`,
		`self-update handoff: preserving Mihomo and active dataplane`,
	} {
		if !strings.Contains(text, required) {
			t.Errorf("boxctl init script is missing %q", required)
		}
	}
}

func TestCalVerReleaseWorkflowPublishesVerifiedArtifacts(t *testing.T) {
	t.Parallel()
	tagWorkflow := readProjectFile(t, ".github/workflows/release-tag.yml")
	for _, required := range []string{
		"workflow_dispatch:",
		"./scripts/calver.sh",
		"./scripts/validate-calver.sh",
		`printf 'tag=v%s\n' "$calver"`,
		"go test -race ./...",
		`gh release create "$TAG"`,
		`--target "$GITHUB_SHA"`,
		`dist/boxctl-linux-arm64-$VERSION.sha256`,
		`dist/boxctl-openwrt-linux-arm64-$VERSION.tar.gz`,
		`dist/boxctl-openwrt-linux-arm64-$VERSION.tar.gz.sha256`,
		`dist/boxctl-openwrt-25.12-mediatek-filogic-$VERSION.apk.sha256`,
		"            LICENSE \\",
	} {
		if !strings.Contains(tagWorkflow, required) {
			t.Errorf("release tag workflow is missing %q", required)
		}
	}
}

func TestNativePackageUsesOpenWrtBuildSystem(t *testing.T) {
	t.Parallel()
	packageMakefile := readProjectFile(t, "packaging/openwrt/Makefile")
	for _, required := range []string{
		"include $(INCLUDE_DIR)/package.mk",
		"BOXCTL_RUNTIME_DEPENDS:=+ca-bundle +dnsmasq +firewall4 +ip-full +kmod-nft-tproxy +kmod-tun +nftables-json +procd +ubus +uci",
		"BOXCTL_RUNTIME_EXTRA_DEPENDS:=ca-bundle (>=0), dnsmasq (>=0), firewall4 (>=0), ip-full (>=0), kmod-nft-tproxy (>=0), kmod-tun (>=0), nftables-json (>=0), procd (>=0), ubus (>=0), uci (>=0)",
		"ifeq ($(BOXCTL_PREBUILT),1)",
		"define Package/boxctl/preinst",
		`[ -e "$${root}/bin/boxctl" ] || fresh=1`,
		`start-stopped-until-first-success`,
		`"$${root}/configs"`,
		`$(1)/opt/boxctl/configs`,
		`chmod 0700 $(1)/opt/boxctl $(1)/opt/boxctl/.boxctl $(1)/opt/boxctl/.install`,
		"$(INSTALL_BIN) $(BOXCTL_BINARY) $(1)/opt/boxctl/bin/boxctl",
		"define Package/boxctl/conffiles",
		"/etc/config/boxctl",
		"$(INSTALL_CONF) ./files/etc/config/boxctl $(1)/etc/config/boxctl",
		"$(INSTALL_DIR) $(1)/usr/share/licenses/boxctl",
		"$(INSTALL_DATA) $(BOXCTL_LEGAL_DIR)/LICENSE $(1)/usr/share/licenses/boxctl/LICENSE",
		"$(eval $(call BuildPackage,boxctl))",
	} {
		if !strings.Contains(packageMakefile, required) {
			t.Errorf("OpenWrt package Makefile is missing %q", required)
		}
	}
	if strings.Contains(packageMakefile, `/opt/boxctl/profiles`) {
		t.Error("OpenWrt package Makefile creates the obsolete profiles directory")
	}

	buildScript := readProjectFile(t, "scripts/build-openwrt-apk.sh")
	for _, required := range []string{
		`OPENWRT_VERSION="25.12.5"`,
		`VERSION must use YYYY.MM.N`,
		`OPENWRT_TARGET="mediatek"`,
		`OPENWRT_SUBTARGET="filogic"`,
		`SDK_SHA256="ff4a38a397caa2cfe1c39e18f84ddede14878221b3593c3f2c4cfe24e3ec4c25"`,
		`"${SDK_ROOT}/scripts/feeds" update base`,
		`# CONFIG_ALL is not set`,
		`# CONFIG_ALL_KMODS is not set`,
		`CONFIG_PACKAGE_boxctl=m`,
		`BOXCTL_PREBUILT=1`,
		`BOXCTL_LEGAL_DIR="$REPOSITORY_ROOT"`,
		"package/boxctl/compile",
		"adbdump --format json",
		`"/usr/share/licenses/boxctl/LICENSE": 0o644`,
		`"/etc/config/boxctl": 0o600`,
	} {
		if !strings.Contains(buildScript, required) {
			t.Errorf("SDK build script is missing %q", required)
		}
	}
}

func TestLocalCheckCoversAllValidationLayers(t *testing.T) {
	t.Parallel()
	makefile := readProjectFile(t, "Makefile")
	for _, required := range []string{
		"check: test lint lint-linux shellcheck",
		"npm --prefix frontend test",
		"golangci-lint run ./...",
		"CGO_ENABLED=0 GOOS=linux golangci-lint run ./...",
		"shellcheck $(SHELL_SCRIPTS)",
		"tests/integration/fetch-openwrt.sh",
		"tests/integration/guest/run.sh",
		"packaging/openwrt/files/etc/init.d/boxctl",
	} {
		if !strings.Contains(makefile, required) {
			t.Errorf("local check contract is missing %q", required)
		}
	}
}

func TestIntegrationRunnerUsesPortableTemporaryDirectory(t *testing.T) {
	t.Parallel()
	runner := readProjectFile(t, "tests/integration/run.sh")
	if strings.Contains(runner, "/private/tmp") {
		t.Error("integration runner contains a macOS-only temporary path")
	}
	if !strings.Contains(runner, `${TMPDIR:-/tmp}`) {
		t.Error("integration runner does not honor TMPDIR with a portable fallback")
	}
}

func TestInstallerSupportsFreshInstallAndUpdate(t *testing.T) {
	t.Parallel()
	text := readProjectFile(t, "packaging/openwrt/install.sh")
	for _, required := range []string{
		`"$SOURCE_BINARY" version`,
		`SOURCE_BINARY=$SOURCE_DIRECTORY/$SOURCE_BASENAME`,
		`ip -N -4 rule show`,
		`--prefer-seamless) PREFER_SEAMLESS=1`,
		`integration_files_match`,
		`settingsSchemaVersion`,
		`captureInjectorVersion`,
		`self-update install --file "$SOURCE_BINARY" --sha256 "$digest"`,
		`refusing to continue with a full reinstall`,
		`ROOT_WAS_PRESENT=1`,
		`backup_file binary`,
		`backup_file config "$CONFIG"`,
		`if service_running; then`,
		`install_atomic "$SOURCE_BINARY"`,
		`start-stopped-until-first-success`,
		`wait_service_running`,
		`rollback_on_error`,
	} {
		if !strings.Contains(text, required) {
			t.Errorf("installer is missing %q", required)
		}
	}
	if strings.Index(text, `"$SOURCE_BINARY" version`) > strings.Index(text, `if service_running; then`) {
		t.Fatal("binary preflight runs after the service is stopped")
	}
	if strings.Index(text, `ip -N -4 rule show`) > strings.Index(text, `if service_running; then`) {
		t.Fatal("ip-full preflight runs after the service is stopped")
	}
	if strings.Index(text, `self-update install --file "$SOURCE_BINARY"`) > strings.Index(text, `if service_running; then`) {
		t.Fatal("seamless update runs after the service is stopped")
	}
}

func TestServiceUsesProcdAndOwnedCleanup(t *testing.T) {
	t.Parallel()
	text := readProjectFile(t, "packaging/openwrt/files/etc/init.d/boxctl")
	for _, required := range []string{
		"USE_PROCD=1",
		`procd_set_param command "$BOXCTL_BIN" serve`,
		`procd_set_param respawn`,
		`config_load boxctl`,
		`procd_append_param env BOXCTL_ALLOWED_HOSTS="$allowed_hosts"`,
		`procd_append_param env BOXCTL_PUBLIC_ORIGIN="$public_origin"`,
		`procd_append_param env BOXCTL_ENABLE_UNSAFE_EXTERNAL_DASHBOARD=1`,
		`procd_append_param env BOXCTL_TLS="$tls_certificate,$tls_key"`,
		`"$BOXCTL_BIN" cleanup`,
		`procd_add_reload_trigger "network" "firewall"`,
	} {
		if !strings.Contains(text, required) {
			t.Errorf("init script is missing %q", required)
		}
	}
}

func TestBundleContainsOnlyCurrentInstaller(t *testing.T) {
	t.Parallel()
	text := readProjectFile(t, "Makefile")
	for _, required := range []string{
		"OPENWRT_INTEGRATION_FILES :=",
		"packaging/openwrt/files/etc/apk/protected_paths.d/boxctl.list",
		"packaging/openwrt/files/etc/config/boxctl",
		"packaging/openwrt/files/etc/hotplug.d/iface/40-boxctl",
		"packaging/openwrt/files/etc/hotplug.d/net/99-boxctl-tun",
		"packaging/openwrt/files/etc/init.d/boxctl",
		"packaging/openwrt/files/lib/upgrade/keep.d/boxctl",
		`install -m 0755 packaging/openwrt/install.sh`,
		`install -m 0644 LICENSE`,
		`for source in $(OPENWRT_INTEGRATION_FILES)`,
		`target="$$bundle_root/$${source#packaging/openwrt/}"`,
		`tar --format=ustar`,
	} {
		if !strings.Contains(text, required) {
			t.Errorf("bundle recipe is missing %q", required)
		}
	}
	if strings.Contains(text, "cp -Rp packaging/openwrt/files") {
		t.Error("bundle recipe recursively copies untracked packaging files")
	}
}

func TestUpgradePersistenceFilesCoverBoxctl(t *testing.T) {
	t.Parallel()
	protected := readProjectFile(t, "packaging/openwrt/files/etc/apk/protected_paths.d/boxctl.list")
	keep := readProjectFile(t, "packaging/openwrt/files/lib/upgrade/keep.d/boxctl")
	for _, expected := range []struct{ protected, keep string }{
		{"!opt/boxctl/", "/opt/boxctl/"},
		{"!etc/init.d/boxctl", "/etc/init.d/boxctl"},
		{"!etc/config/boxctl", "/etc/config/boxctl"},
		{"!etc/hotplug.d/iface/40-boxctl", "/etc/hotplug.d/iface/40-boxctl"},
		{"!etc/hotplug.d/net/99-boxctl-tun", "/etc/hotplug.d/net/99-boxctl-tun"},
	} {
		if !strings.Contains(protected, expected.protected) || !strings.Contains(keep, expected.keep) {
			t.Errorf("upgrade persistence is missing %s", expected.keep)
		}
	}
}
