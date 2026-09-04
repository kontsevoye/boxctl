# Security policy

## Reporting

Please report vulnerabilities privately through GitHub Security Advisories.
Do not include real profile URLs, controller secrets, passwords, WireGuard
keys, router backups, or unredacted configuration files in a public issue.

## Security boundaries

- The daemon runs as root on OpenWrt because it owns nftables, policy routing,
  dnsmasq integration, and the supervised core process.
- The management API is not intended for WAN exposure. Bind it to a trusted LAN
  address or loopback and use HTTPS when the network is not fully trusted. The
  packaged default is plaintext HTTP and its session cookie is not `Secure`;
  credentials, raw configuration, and backups are then visible to an on-path
  LAN attacker.
- First-run administrator setup validates both the browser origin and request
  host. Literal IP hosts, `localhost`, and the listener address are accepted;
  deployments behind additional DNS names must explicitly list hostnames in
  `BOXCTL_ALLOWED_HOSTS`. A TLS-terminating reverse proxy should instead set an
  exact `BOXCTL_PUBLIC_ORIGIN` and preserve the original `Host` header.
- Profile and backup files contain credentials. New files are mode `0600`, and
  backup/session directories are mode `0700`.
- Ordinary profile DTOs, errors, and mutation results never return the Mihomo
  controller secret or subscription URL. The authenticated raw editor and
  backup export intentionally can return secret-bearing state.
- Core updates require an official GitHub release-asset SHA-256 digest, a size
  match, a valid Linux/AArch64 ELF, native core validation, and an atomic swap
  retaining the previous binary.
- Manager self-updates are CLI-only and require OpenWrt. GitHub updates accept
  only canonical boxctl CalVer releases and digest-attested Linux/AArch64
  assets; offline files require an explicit or companion SHA-256. The manager
  binary is atomically replaced, procd must remain running after restart, and a
  failed restart restores the retained previous binary. Self-update never
  replaces configuration or state.
- Restore rejects absolute paths, traversal, links, duplicate entries,
  oversized payloads, and files outside the documented state allow-list.
- The optional Zashboard integration is disabled unless
  `BOXCTL_ENABLE_UNSAFE_EXTERNAL_DASHBOARD=1` is set at daemon startup. Its
  downloaded JavaScript is served from the authenticated boxctl origin and can
  therefore act with administrator authority; a release digest proves asset
  integrity, not source trust or reproducibility.

## Backup boundary

Portable backups always include the portable parts of `.boxctl`, `cache.db`,
`config.yaml`, `configs`, `local-rules`, and `subscriptions` when present.
Administrator password, downloaded `proxy-providers`/`rule-providers`, and the
external `ui` dashboard are separate opt-in export groups. They exclude core
binaries, nested backups, runtime/import/lock/DNS transaction state, process
ownership and manager-handoff records, and session secrets. Restore preserves
the current administrator password when the archive does not contain one.

Production limits are 10,000 files, 32 MiB per file, 128 MiB expanded data,
and 32 MiB for the compressed archive or upload. When selective routing was
running, import stops it before the atomic state swap and starts it again after
the restore lock is released; a previously stopped core remains stopped. A
successful restore replaces the complete in-memory and persisted session
signing-key set and clears the importing browser cookie, invalidating every
existing browser session without requiring a daemon restart.

The project deliberately fails open for packet forwarding when its managed
core becomes unavailable: capture is removed and the previous dnsmasq options
are restored. This availability choice does not bypass management API auth.
