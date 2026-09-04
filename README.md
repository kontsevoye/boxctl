# boxctl

`boxctl` is a transparent-routing manager for current OpenWrt releases. It
starts and supervises a proxy core, generates its configuration, and manages
only the `nftables`, policy-routing, and DNS state owned by boxctl.

Mihomo is currently supported. A sing-box driver is planned; the core and
configuration contracts are already separated so another engine can be added
without replacing the web interface or the OpenWrt integration.

## Features

- built-in English and Russian web interface with password authentication;
- Mihomo start, stop, restart, and reload operations through `procd`;
- TPROXY, hybrid, TUN, mixed, and mixed2 capture modes;
- validated editing of Mihomo YAML and local rule lists;
- remote profiles, proxy subscriptions, and rule/proxy providers;
- verified Mihomo updates with size, SHA-256, and Linux/AArch64 ELF checks;
- verified boxctl self-updates from GitHub Releases or an offline local file,
  with an atomic swap, procd restart check, and automatic rollback;
- export and restore of portable boxctl state;
- fail-open cleanup that removes boxctl-owned routing state and restores DNS
  settings when the core stops;
- separate traffic, connection, CPU, and memory metrics for boxctl and Mihomo.

boxctl targets OpenWrt systems using `firewall4`, `procd`, `nftables`, and
`ip-full`. The installer does not import another routing manager's state. A
fresh installation creates an isolated `/opt/boxctl` root; rerunning the
installer upgrades that installation while preserving its state.

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

The integration suite installs one boxctl instance in a clean OpenWrt VM and
checks the `procd` lifecycle, real `nftables` and policy-routing rules, TPROXY
marking for test LAN traffic, a direct neighbouring flow, and shutdown cleanup:

```sh
nix develop --command tests/integration/run.sh \
  --manager dist/boxctl-linux-arm64 \
  --core /path/to/mihomo-linux-arm64
```

The test downloads the pinned OpenWrt 25.12.5 image from the official mirror
and verifies its SHA-256 checksum. The VM receives a separate network interface
only while installing packages; that interface is removed in the guest and
disabled through QEMU QMP before the test payload is transferred.

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
the manager; Mihomo, active connections, DNS, nftables, and policy routing stay
in place. Otherwise it falls back to the transactional installer. On a fresh
installation, Mihomo remains stopped until an administrator reviews the
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
proxied Mihomo API, so review its upstream source and license before enabling
it. Controller credentials remain server-side and are added only to requests
proxied by boxctl.

## Known limitations

- Official binaries are Linux/AArch64; the native APK is built specifically
  for OpenWrt 25.12 mediatek/filogic. Other firewall4-based OpenWrt targets may
  work with a compatible build, but are not release targets.
- Gateway and capture management are IPv4-only. IPv6 traffic is not routed
  through the managed capture plan.
- The management UI uses plain HTTP by default and must remain on a trusted LAN
  or loopback unless HTTPS is configured explicitly.
- Mihomo is installed separately and must be configured before traffic can be
  captured. A sing-box driver is not implemented.

## CLI

```text
boxctl serve [--root PATH] [--listen ADDRESS] [--start-stopped]
boxctl setpass
boxctl config validate [--file PATH]
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
activation re-executes only the manager/web image in place: the exact Mihomo process is
verified and adopted by the new manager while active connections, nftables,
policy routing, and DNS stay in place. A compatibility change requires an
interactive confirmation because it restarts Mihomo and interrupts active
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

Releases are deliberate and tag-backed. Run the `release-tag` workflow on
`main`; it finds the highest `vYYYY.MM.N` tag for the current UTC month and
increments its monthly release number (`v2025.01.15` becomes `v2025.01.16`).
It then reruns all checks, builds the artifacts, and creates the `v<CalVer>` tag
together with its GitHub Release containing:

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
