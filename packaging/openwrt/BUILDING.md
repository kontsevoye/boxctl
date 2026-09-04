# OpenWrt package build

Main-branch CI builds `boxctl` as a native OpenWrt 25.12 APK for the
`mediatek/filogic` target used by the BPI-R4. The build uses the official
OpenWrt 25.12.5 SDK rather
than assembling or renaming an archive:

- SDK: `openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64.tar.zst`
- SHA-256: `ff4a38a397caa2cfe1c39e18f84ddede14878221b3593c3f2c4cfe24e3ec4c25`
- Source: <https://downloads.openwrt.org/releases/25.12.5/targets/mediatek/filogic/>

The resulting APK architecture is `aarch64_cortex-a53`, matching the official
25.12.5 BPI-R4 image. APK architecture names are enforced by the package
manager, so this package intentionally is not labelled `aarch64_generic`.

The package installs the manager at `/opt/boxctl/bin/boxctl`, its `procd`
service, both hotplug handlers, and the APK/sysupgrade persistence lists. Its
runtime dependencies describe the OpenWrt commands and kernel support used by
the manager. Empty `/opt/boxctl/engines/mihomo` and
`/opt/boxctl/engines/sing-box` directories are created for separately managed
core artifacts; no third-party proxy-core binary or license is embedded in the
boxctl package.

To reproduce a package build on Linux x86-64, first build the static arm64
binary and then invoke the SDK wrapper:

```sh
npm --prefix frontend ci
make cross-arm64 \
  VERSION=2026.08.15 \
  COMMIT="$(git rev-parse HEAD)" \
  DATE="$(git show -s --format=%cI HEAD)"
VERSION=2026.08.15 \
  BINARY="$PWD/dist/boxctl-linux-arm64" \
  ./scripts/build-openwrt-apk.sh
```

CI publishes the APK together with a SHA-256 file. Verify that checksum before
copying the package to a router. A standalone package built outside the
official OpenWrt repositories is not trusted by the router's official keys, so
a one-off manual install must explicitly use APK's untrusted-package flow. A
managed package feed should instead sign its APK index and distribute that
feed's public key to clients.

```sh
sha256sum -c boxctl-openwrt-25.12-mediatek-filogic-<version>.apk.sha256
apk --allow-untrusted add ./boxctl-openwrt-25.12-mediatek-filogic-<version>.apk
```
