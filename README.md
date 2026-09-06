# boxctl

`boxctl` is a transparent-routing manager for current OpenWrt releases. It
starts and supervises a proxy core, generates its configuration, and manages
only the `nftables`, policy-routing, and DNS state owned by boxctl.

Profiles and managed engine artifacts carry an explicit engine identity.
Mihomo remains the established core; sing-box support targets the reviewed
`>=1.14.0,<1.15.0` compatibility window without changing ownership of the
OpenWrt dataplane.

## Features

- built-in English and Russian web interface with password authentication;
- engine-aware start, stop, restart, health, and capability contracts;
- TPROXY, hybrid, TUN, mixed, and mixed2 capture modes;
- validated engine-native Mihomo YAML and sing-box JSON profiles;
- remote profiles for both engines, plus Mihomo proxy subscriptions and
  rule/proxy providers;
- verified engine updates with size, SHA-256, Linux/AArch64 ELF, static-link,
  upstream version, and build-tag checks where applicable;
- verified boxctl self-updates from GitHub Releases or an offline local file,
  with an atomic swap, procd restart check, and automatic rollback;
- export and restore of portable boxctl state;
- fail-open cleanup that removes boxctl-owned routing state and restores DNS
  settings when the core stops;
- separate traffic, connection, CPU, and memory metrics for boxctl and the
  active proxy core.

boxctl targets OpenWrt systems using `firewall4`, `procd`, `nftables`, and
`ip-full`. The installer does not import another routing manager's state. A
fresh installation creates an isolated `/opt/boxctl` root; rerunning the
installer upgrades that installation while preserving its state.
`kmod-inet-diag` is installed for process-aware sing-box routing rules;
`kmod-nft-queue` is intentionally not required because boxctl keeps sing-box
`auto_redirect` disabled and remains the sole nftables owner.

The selected profile is the only persisted engine selector. Profile names may
be reused across engines because identity is the pair `engine:name`; the UI
filters profiles and managed resources by that identity. Existing untagged
profiles and resources migrate as Mihomo. Switching a running selection always
requires confirmation and performs target preflight before stopping the live
generation. Runtime, gateway, metadata, and applied revision are committed as
one rollback-capable transition; a durable journal reconciles an interrupted
switch against the exact adopted runtime revision on the next start.

sing-box does not expose Mihomo's proxy-provider or rule-provider management
semantics. boxctl therefore keeps proxy subscriptions, local rule-list surgery,
and fake-IP list generation explicitly Mihomo-only instead of presenting
operations that cannot affect a sing-box runtime. Native
sing-box `outbounds` and `route.rule_set` remain editable in its JSON profile;
the integrated proxies, rules, connections, traffic, and log pages use its
loopback Clash API adapter. The optional Zashboard proxy follows the running
engine and is available for both Mihomo and sing-box, but sing-box dashboard
panels that depend on providers, hot reload, or mutable routing mode remain
unsupported. Remote sing-box profile refreshes are staged as pending changes
and never restart the core in the background.

Connections enrich private LAN source addresses from OpenWrt/Entware host and
lease data (`/etc/hosts`, `/opt/etc/hosts`, `/tmp/hosts/*`, and
`/tmp/dhcp.leases`). Missing private addresses receive a bounded, cached PTR
lookup through WAN resolver files such as
`/tmp/resolv.conf.d/resolv.conf.auto`; loopback and addresses owned by the
boxctl host are skipped to avoid querying the managed local DNS path. The raw
source IP remains present in the API and UI alongside the resolved name.

OpenWrt DNS `upstream` mode requires the native sing-box profile to define an
independent `dns.servers` chain. Implicit or explicit `local`/`resolved`
resolution is rejected because dnsmasq itself is pointed at sing-box in this
mode and would form a resolver loop. The default/final server must provide
general recursive resolution; scoped or synthetic `hosts`, `mdns`, `fakeip`,
or MagicDNS-only servers may be used only as auxiliary rule targets. For
example, a literal upstream uses
`{"dns":{"servers":[{"type":"udp","tag":"upstream","server":"1.1.1.1"}],"final":"upstream"}}`.
After applying the dnsmasq/firewall generation, boxctl performs a fresh query
below the reserved `.invalid` TLD and rolls the whole activation back on DNS
failure; `SERVFAIL` and `REFUSED` do not count as readiness.

## Requirements

The reproducible development environment is provided by Nix. Enter it before
running build or test commands:

```sh
nix develop
```

The frontend uses Node.js and npm, while the manager is written in Go. The Nix
development shell supplies both toolchains and the utilities required by the
OpenWrt integration test.

## Build and test

Run the standard local checks (the QEMU integration test is separate):

```sh
npm --prefix frontend ci
make check
```

Frontend dependency installation is explicit: `make check` uses the locked
packages already present under `frontend/node_modules` and does not run
`npm install` or `npm ci` for you. Go may still populate an empty module or
toolchain cache.

Build a Linux/AArch64 binary and a portable OpenWrt bundle with explicit build
metadata:

```sh
make bundle-openwrt-arm64 \
  VERSION=dev \
  COMMIT="$(git rev-parse --short HEAD)" \
  DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

The binary is written to `dist/boxctl-linux-arm64`; the bundle is written to
`dist/boxctl-openwrt-linux-arm64.tar.gz`.

### OpenWrt integration test

The integration suite installs one boxctl instance with Mihomo and sing-box in
a clean OpenWrt VM. It checks engine-tagged profile selection, live
Mihomo-to-sing-box-to-Mihomo cutover, exact process/listener identity, the
`procd` lifecycle, real `nftables` and policy-routing rules, TPROXY traffic
through both engines, a direct neighbouring Mihomo flow, and shutdown cleanup:

```sh
nix develop --command tests/integration/run.sh \
  --manager dist/boxctl-linux-arm64 \
  --mihomo /path/to/mihomo-linux-arm64 \
  --sing-box /path/to/sing-box-linux-arm64
```

The test downloads the pinned OpenWrt 25.12.5 image from the official mirror
and verifies its SHA-256 checksum. The VM receives a separate network interface
only while installing packages; that interface is removed in the guest and
disabled through QEMU QMP before the test payload is transferred.

### Release parity tests

The parity suite compares a separately verified official release manager
with the current manager under the same Mihomo binary and hermetic OpenWrt
scenario. Before running it, verify the release asset against the checksum
published with that release. Both manager artifacts must then be supplied with
their expected SHA-256 digest, version, and full commit; these values pin the
exact inputs during the run but do not independently establish GitHub
provenance:

```sh
nix develop --command tests/integration/parity-mihomo-run.sh \
  --release-manager /path/to/release/boxctl-linux-arm64 \
  --release-sha256 RELEASE_SHA256 \
  --release-version RELEASE_VERSION \
  --release-commit RELEASE_COMMIT \
  --current-manager /path/to/current/boxctl-linux-arm64 \
  --current-sha256 CURRENT_SHA256 \
  --current-version CURRENT_VERSION \
  --current-commit CURRENT_COMMIT \
  --mihomo /path/to/mihomo-linux-arm64 \
  --output /path/to/new/mihomo-result
```

The command runs two clean VMs and requires their normalized observable
contracts to be byte-identical. The contract covers fake-IP and ordinary DNS,
captured data transfer, local and remote rule providers, local and remote proxy
providers, reserved-address bypass, rejection, listeners, nftables ownership,
and policy routing. Only the concrete fake-IP allocation is normalized.

After that comparison passes, run the current manager with sing-box and bind
the semantic comparison to the complete Mihomo result directory:

```sh
nix develop --command tests/integration/parity-singbox-run.sh \
  --manager /path/to/current/boxctl-linux-arm64 \
  --manager-sha256 CURRENT_SHA256 \
  --manager-version CURRENT_VERSION \
  --manager-commit CURRENT_COMMIT \
  --sing-box /path/to/sing-box-linux-arm64 \
  --mihomo-result /path/to/mihomo-result \
  --output /path/to/new/singbox-result
```

This second comparison uses identical network stimuli and checks semantic
invariants rather than requiring engine-specific JSON to match byte for byte.
Mihomo's native dynamic proxy-provider is intentionally recorded as an engine
difference: the sing-box scenario verifies the supported equivalents, an
inline selector for the local proxy and an HTTPS remote profile for the remote
proxy. Each result directory retains manifests, exact input hashes, version
evidence, controller snapshots, packet-policy evidence, and the generated
contract or cross-engine matrix for audit.

## Deploy to OpenWrt

Build and deploy over SSH:

```sh
./scripts/deploy-openwrt.sh --target root@router.lan
```

The deployment script builds the Linux/AArch64 binary and bundle locally,
verifies the bundle checksum after upload, installs required OpenWrt packages,
and exposes the web interface on port `9091`. Its default build version is the
current Git revision (plus a timestamp for a dirty tree), so repeated local
builds cannot be mistaken for the same `dev` binary. When a compatible boxctl
installation is already running and its OpenWrt integration files are current,
deployment uses the local binary as an offline self-update and re-executes only
the manager; the active core, connections, DNS, nftables, and policy routing stay
in place. Otherwise it falls back to the transactional installer. On a fresh
installation, the selected core remains stopped until an administrator reviews the
configuration and selects **Start**.

Run `./scripts/deploy-openwrt.sh --help` for SSH, version, and dry-run options.

For a manual installation, unpack the bundle and run its installer:

```sh
mkdir boxctl-bundle
tar -xzf boxctl-openwrt-linux-arm64.tar.gz -C boxctl-bundle
cd boxctl-bundle
./install.sh ./boxctl-linux-arm64
```

The web interface is intended for a trusted LAN or loopback. Configure HTTPS
explicitly before exposing it to an untrusted network. See
[SECURITY.md](SECURITY.md) for the security model and deployment guidance.

The unauthenticated first-run setup accepts literal IP hosts, `localhost`, and
the address to which boxctl is bound. If the setup page is reached through an
additional DNS name, add it to the comma-separated `BOXCTL_ALLOWED_HOSTS`
environment variable. For a TLS-terminating reverse proxy, set the exact
external origin in `BOXCTL_PUBLIC_ORIGIN` and preserve the original `Host`
header; its hostname is allowed automatically and HTTPS also enables Secure
session cookies. These checks prevent a DNS-rebinding page from claiming a
fresh instance.

The packaged OpenWrt service persists the corresponding settings in UCI. For
example:

```sh
uci set boxctl.main.public_origin='https://router.example'
uci set boxctl.main.allowed_hosts='router.home'
uci set boxctl.main.enable_unsafe_external_dashboard='1'
# For TLS served directly by boxctl, set both absolute paths instead:
# uci set boxctl.main.tls_certificate='/etc/ssl/boxctl.crt'
# uci set boxctl.main.tls_key='/etc/ssl/private/boxctl.key'
uci commit boxctl
service boxctl restart
```

### Optional external dashboard

Zashboard is not bundled with boxctl and its integration is disabled by
default. Set `BOXCTL_ENABLE_UNSAFE_EXTERNAL_DASHBOARD=1` before a direct
`boxctl serve`, or use the UCI option above, to expose the explicit install
control. If an administrator then chooses to install it, boxctl downloads
`dist-no-fonts.zip` from a tagged
`Zephyruso/zashboard` GitHub Release, requires GitHub's size and SHA-256 digest,
checks archive paths and extraction limits, and publishes it atomically. The
digest verifies the downloaded release asset; it is not a reproducible-build
or source-code audit. Zashboard is third-party browser code with access to the
proxied API of the running Clash-compatible core, so review its upstream source
and license before enabling it. Controller credentials remain server-side and
are added only to requests proxied by boxctl.

## Known limitations

- Official binaries are Linux/AArch64; the native APK is built specifically
  for OpenWrt 25.12 mediatek/filogic. Other firewall4-based OpenWrt targets may
  work with a compatible build, but are not release targets.
- Gateway and capture management are IPv4-only. IPv6 traffic is not routed
  through the managed capture plan.
- The management UI uses plain HTTP by default and must remain on a trusted LAN
  or loopback unless HTTPS is configured explicitly.
- Engine binaries are installed separately and must be validated before traffic
  can be captured. Managed sing-box artifacts are intentionally restricted to
  upstream-compatible 1.14.x static ARM64-musl archives.
- In DNS `upstream` mode, sing-box profiles must carry a non-system recursive
  DNS transport; profiles without explicit `dns.servers` can instead use
  `redirect` or `disabled` mode when the native resolver design requires it.
- Zashboard can use sing-box's Clash API for proxies, selectors, delay tests,
  rules, connections, traffic, and logs. Provider management, hot reload, and
  mutable routing mode are not advertised for sing-box because its API does not
  implement the corresponding Mihomo behavior.

## CLI

```text
boxctl serve [--root PATH] [--listen ADDRESS] [--start-stopped]
boxctl setpass
boxctl config validate [--engine mihomo|sing-box] [--file PATH]
boxctl engine install sing-box --file /tmp/sing-box-1.14.0-linux-arm64-musl.tar.gz [--sha256 HEX] [--root PATH]
boxctl fw start|update|diagnose|stop
boxctl doctor [--root PATH] [--json]
boxctl self-update check [--repo OWNER/REPO] [--root PATH]
boxctl self-update install [--repo OWNER/REPO] [--no-restart|--full-restart] [--root PATH]
boxctl self-update install --file /tmp/boxctl-linux-arm64 [--sha256 HEX] [--no-restart|--full-restart]
boxctl self-update rollback [--no-restart|--full-restart] [--root PATH]
boxctl cleanup
boxctl version
```

## Self-update and releases

`boxctl self-update install` discovers the latest stable release in
`kontsevoye/boxctl`. The selected release must use a canonical
`vYYYY.MM.N` tag and contain a raw `boxctl-linux-arm64-YYYY.MM.N` asset with
GitHub SHA-256 digest
metadata. The candidate is size-bounded, checked as a Linux/AArch64 ELF,
executed only for `boxctl version`, and required to report the release version.

The binary is staged beside `/opt/boxctl/bin/boxctl`, atomically swapped into
place, and retained as `boxctl.prev`. Each binary reports an internal settings
schema version and capture-injector version. When both match, the default
activation re-executes only the manager/web image in place: the exact active-core process is
verified and adopted by the new manager while active connections, nftables,
policy routing, and DNS stay in place. A compatibility change requires an
interactive confirmation because it restarts the active core and interrupts active
connections. `--full-restart` forces that path and acts as non-interactive
approval; `--no-restart` only swaps the binary. The CLI requires the new
manager to remain running and restores the previous binary if verification
fails. Configuration and state under `/opt/boxctl` are not replaced.

For an offline update, copy the raw binary and its generated `.sha256` file to
the router:

```sh
boxctl self-update install --file /tmp/boxctl-linux-arm64-2025.01.15
```

The updater reads `FILE.sha256` automatically. An explicit 64-character digest
may instead be provided with `--sha256`. Local files without either checksum
are rejected. `boxctl self-update rollback` restores the one retained previous
binary.

## sing-box engine artifacts

The managed sing-box installer accepts the official
`sing-box-VERSION-linux-arm64-musl.tar.gz` archive for stable 1.14.x releases.
It rejects the generic arm64 build because that artifact uses a glibc dynamic
loader, and it does not install the upstream OpenWrt package because that
package brings a separate init service and configuration owner. Archives are
size- and SHA-256-bounded and may contain only their canonical top-level
directory plus regular `sing-box` and `LICENSE` files. The candidate must be a
static Linux/AArch64 ELF, report the exact archive version, and include
`with_musl`, `with_clash_api`, and `with_gvisor` build tags.

Verified versions are published under
`/opt/boxctl/engines/sing-box/versions/VERSION/`. An atomic `current.json`
registry retains the immediately previous version for pointer rollback. A
local `--file` installation requires an explicit checksum or a bounded regular
`FILE.sha256` companion and is recorded as custom with automatic updates
disabled. Validation executes the staged binary only for its `version` output;
an operator-supplied checksum detects replacement or corruption but does not
make an untrusted custom binary trustworthy.

OpenWrt sysupgrade persistence retains the entire `/opt/boxctl` tree. Capacity
planning must therefore include the current and previous approximately 86 MB
sing-box binaries, temporary staging space, and the resulting sysupgrade
archive; engine binaries remain excluded from boxctl application backups.
Backup schema 2 includes both `config.yaml` and `config.json`, engine-native
profiles, and portable registries, while recording required engine
version/digest metadata separately. Restore still reads schema 1 archives and
checks any exact managed-engine requirement before replacing current state;
runtime, process, transition, lock, and controller-secret state is never
restored.

sing-box is a separate upstream program and is not bundled with boxctl. Its
downloaded `LICENSE` is retained beside each installed binary together with
the upstream URL, release tag, archive and binary digests, build tags, and a
no-affiliation marker. sing-box 1.14 is distributed upstream under
GPL-3.0-or-later with additional upstream terms; see the
[upstream license](https://github.com/SagerNet/sing-box/blob/v1.14.0/LICENSE).
Installing or redistributing sing-box does not change boxctl's own MIT license.

Every push to `master` runs the checks, builds the release artifacts once, and
then creates a tag-backed GitHub Release. The workflow finds the highest
`vYYYY.MM.N` tag for the current UTC month and increments its monthly release
number (`v2025.01.15` becomes `v2025.01.16`). The release title is the tag
itself, and its notes list every commit since the previous CalVer release with
links to the commits and the full comparison. A rerun for an already tagged
commit performs the checks without rebuilding or republishing release assets.
Each new release contains:

- the raw static Linux/AArch64 binary and SHA-256 file;
- a portable OpenWrt bundle and SHA-256 file;
- the native OpenWrt 25.12 mediatek/filogic APK and SHA-256 file;
- `LICENSE` for binary recipients.

## Project origin

boxctl is an independent implementation, not a modification or a complete
rewrite of SSClash-Go. During early development, the separately licensed
SSClash-Go v6.2.1 distribution was used as an external reference for public
documentation, observable configuration and state contracts, and migration
compatibility. No SSClash-Go source code or executable is included, linked, or
redistributed by the current repository or its releases. SSClash-Go remains
copyrighted by its respective owner and governed by its own license; boxctl
does not claim full feature parity with it.

## Repository layout

- `cmd/boxctl` contains the command-line entry point.
- `internal/app` coordinates configuration, lifecycle, updates, and status.
- `internal/platform/openwrt` owns OpenWrt networking integration.
- `frontend` contains the React web interface and its tests.
- `packaging/openwrt` contains the package filesystem and install scripts.
- `tests/integration` contains the QEMU-based OpenWrt integration suite.

## License

This project is distributed under the terms in [LICENSE](LICENSE).
