# Core downtime traffic guard

Status: design proposal. This document does not change the current fail-open
runtime behaviour.

## Goal

Optionally stop forwarded LAN traffic from escaping directly while the boxctl
manager is available but the selected proxy core is not healthy. The router's
management UI, DHCP, DNS service and LAN-local traffic must stay reachable so
the failure can be repaired.

The guard is not the normal transparent-proxy ruleset. It must live in a
separate, ownership-marked nftables table so removing or replacing the active
Mihomo/sing-box generation cannot create an unguarded gap.

## User-visible modes

`off`

: Keep today's fail-open behaviour. Stopping the core restores dnsmasq and
  removes boxctl capture state, so clients use the router's normal path.

`transitions`

: Guard only planned restart, reload-with-restart, profile switch and engine
  switch operations. Install it before deactivating the old dataplane and
  remove it only after the target generation passes its post-activation health
  probe. If both the target and rollback generation fail, remove the guard and
  retain today's fail-open recovery behaviour. Manual Stop remains fail-open.

`strict`

: Guard whenever no healthy selected core owns the dataplane, including boot,
  manual Stop, failed start and a detected core crash. The guard survives an
  unexpected manager exit and is removed only after a healthy dataplane is
  committed or the user explicitly disables strict mode. This is the actual
  kill-switch behaviour.

Recommended mode: `strict`, opt-in and off by default. A boolean cannot safely
represent the difference between a short transition guard and a persistent
kill switch, so the Settings UI should use a three-value choice.

## Packet boundary

The first implementation should block forwarded client traffic, for IPv4 and
IPv6, from the discovered/included LAN interfaces toward discovered WAN
interfaces. It should not change the `input` path, so clients can still reach
the router and boxctl. It should not initially block router-originated `output`:
the manager and replacement core need WAN access to resolve endpoints and
recover, and both currently run without a distinct service UID or cgroup that
would let nftables separate them safely from other router processes.

Existing forwarded connections stop carrying packets immediately when the
guard is installed. Deleting conntrack entries is unnecessary for enforcement
and would add a new runtime dependency.

Suggested ownership contract:

- dedicated table: `inet boxctl_guard`;
- deterministic owner and plan-digest comments;
- `forward` base chain with an explicit LAN-to-WAN drop rule;
- atomic `nft -c -f -` preflight followed by `nft -f -`;
- refuse to replace or delete a same-named foreign table;
- serialize with the existing host-global `gateway-dns` lock;
- hotplug reconciliation must update interface sets without opening a gap.

## Lifecycle ordering

For a planned transition:

1. Resolve and atomically install the guard.
2. Restore DNS/remove the old capture dataplane.
3. Stop the old core.
4. Start and probe the new core.
5. Activate capture and DNS.
6. Run the existing post-activation health probe.
7. Atomically remove the guard.

For `strict` startup, reconcile the guard before stale capture cleanup or core
preparation. For a monitor-detected crash, install/reconcile it before removing
capture. A failed guard installation must abort a planned transition: claiming
fail-closed while continuing without the guard would be worse than reporting a
clear error.

## Settings and recovery safety

Persist an enum such as `CORE_DOWNTIME_POLICY=off|transitions|strict`. Enabling
`strict` should be transactional:

- when the core is healthy, save the setting and leave the guard absent;
- when the core is stopped, require an explicit confirmation because saving
  immediately cuts client internet access;
- reject or prominently warn about `START_ON_BOOT=false` with `strict`;
- expose guard state and the last reconciliation error in `/status`;
- provide a local recovery command that disables the policy and removes only a
  verified boxctl-owned guard table.

The fresh-install/start-stopped marker must continue to be fail-open until the
administrator opts in. An install must never unexpectedly isolate a router
before a valid profile has completed its first successful start.

## Required verification

- nft render, ownership-conflict, idempotence and cleanup unit tests;
- lifecycle ordering tests for restart, engine switch, target failure,
  successful rollback, double failure, manual Stop and monitor crash;
- OpenWrt VM dataplane probes for IPv4 and IPv6 during an intentionally slow
  restart and a killed core;
- prove UI/DHCP/router DNS remain reachable while forwarding is blocked;
- prove the guard is removed after successful recovery and explicit disable;
- power-loss/SIGKILL recovery and WAN/LAN hotplug tests.
