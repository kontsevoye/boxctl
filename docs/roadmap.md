# Planned features

## Local device aliases

Status: planned; not implemented.

- Manage custom names for local devices in Settings, for example `Work MacBook`
  or `My phone`. Create, edit, and remove aliases through the GUI.
- Show aliases alongside actual source IPs in active/closed connections, the
  source-device selector, connection details, and system/core log viewers.
  Display priority: custom alias, discovered DNS/DHCP hostname, then IP.
- Preserve original IPs and native log messages for troubleshooting. Resolve
  aliases in structured source fields or in the presentation layer rather than
  blindly replacing text in log messages.
- Prefer DHCP/MAC identity when available so aliases can follow address changes;
  support explicit IP mappings for static devices. Define collision handling
  and IPv4/IPv6 associations before implementation.
- Persist aliases in boxctl-owned settings and include them in backup/restore.
  Applying an alias refreshes the UI without reloading/restarting the core or
  changing DNS responses on the network.

Acceptance: a phone alias appears in connections, the device filter, and
relevant log entries; editing/removing it updates those views, and aliases
survive panel restarts and backup restoration.
