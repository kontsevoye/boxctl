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
  committed or the user explicitly disables strict mode. This is the intended
  kill-switch policy, but it must not be described as a complete kill switch
  until the early-boot, firewall-reload and flow-offload requirements below are
  implemented and verified.

Recommended delivery: ship `transitions` first, only on routers where software
and hardware flow offload are disabled, then add `strict` after early-boot and
reload reconciliation is available. `strict` remains opt-in and `off` remains
the default. A boolean cannot safely represent the difference between a short
transition guard and a persistent kill switch, so the Settings UI should use a
three-value choice. The UI should call `transitions` restart/switch gap
protection, not a kill switch.

## Packet boundary

The first implementation should protect configured LAN ingress for both IPv4
and IPv6. It should default-deny forwarding from protected LAN interfaces to
any interface not in an explicit trusted-local set, rather than enumerate only
currently discovered WAN interfaces. Otherwise a newly appearing PPPoE, WWAN,
VPN or mwan interface can fail open before hotplug reconciliation. The
protected and trusted interface sets must be visible in status and diagnostics.

The guard should not change the `input` path, so clients can still reach the
router and boxctl. It should not initially block router-originated `output`:
the manager and replacement core need WAN access to resolve endpoints and
recover, and both currently run without a distinct service UID or cgroup that
would let nftables separate them safely from other router processes. This means
a router-local relay or proxy remains outside the guard's threat boundary.

An nftables forward hook does not necessarily see an already offloaded flow.
The first implementation must detect OpenWrt software and hardware flow
offloading and reject enabling the guard while either is active. Supporting
offload later requires an explicit ingress/offload-flush design and tests; a
conntrack-only assumption is insufficient.

Suggested ownership contract:

- dedicated table: `inet boxctl_guard`;
- deterministic owner and plan-digest comments;
- `forward` base chain with an explicit LAN-to-WAN drop rule;
- forward hook priority `-10`, before the target OpenWrt fw4 `filter` priority
  `0`; verify this ordering against the live ruleset and do not rely on
  undefined ordering at the same priority;
- atomic `nft -c -f -` preflight followed by `nft -f -`;
- refuse to replace or delete a same-named foreign table;
- serialize with the existing host-global `gateway-dns` lock;
- hotplug reconciliation must update interface sets without opening a gap.

The nft table is otherwise RAM-only. `strict` therefore also requires an
early-boot fw4/procd integration that installs the guard before ordinary client
forwarding is possible, plus independent reconciliation across `fw4 reload`,
network reload, hotplug and a manager crash. Starting boxctl at `START=21` by
itself is not sufficient.

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

Lifecycle calls need an explicit reason/scope so restart, profile/engine switch,
manual Stop, service shutdown, crash recovery, install and uninstall do not all
collapse into the current generic `Stop` path. Cleanup must remove or retain the
guard according to that reason and the selected policy; an incidental rollback
or cleanup error must never silently remove it.

Guard removal requires the complete committed gateway state: healthy core and
controller, owned capture/firewall and policy routing, and the expected DNS
state. The existing process/controller readiness probe alone is insufficient.
If the target is healthy but guard removal fails, keep the healthy core and the
guard, report a distinct `running-guarded` degraded state, and retry verified
removal. Do not stop or roll back the healthy target merely because removal
failed. The crash monitor also needs an explicit threshold: process death can
engage immediately, while transient controller probe failures should use a
bounded failure policy.

## Settings and recovery safety

Persist an enum such as `CORE_DOWNTIME_POLICY=off|transitions|strict`. Enabling
`strict` should be transactional:

- when the core is healthy, save the setting and leave the guard absent;
- when the core is stopped, require an explicit confirmation because saving
  immediately cuts client internet access;
- reject `START_ON_BOOT=false` with `strict`;
- reject guard modes in server/no-gateway operation;
- expose guard state and the last reconciliation error in `/status`;
- provide a local recovery command that disables the policy and removes only a
  verified boxctl-owned guard table.

The fresh-install/start-stopped marker must continue to be fail-open until the
administrator opts in. An install must never unexpectedly isolate a router
before a valid profile has completed its first successful start.

Upgrade, uninstall and emergency recovery must be explicit. Enabling a policy
is a transactional install/reconcile/save operation; disabling it is a
transactional verified remove/save operation. Package removal must not strand a
guard without leaving a documented local recovery command. When implemented,
README and SECURITY must replace the current unconditional fail-open wording
with the exact per-mode availability and recovery trade-offs.

The current managed capture path is IPv4-only. An `inet` guard can block both
IPv4 and IPv6 during downtime, but after a healthy core is restored IPv6 can
still use the router's normal path. Strict downtime protection must not be
marketed as all-time IPv6 tunnelling.

## Required verification

- nft render, ownership-conflict, idempotence and cleanup unit tests;
- lifecycle ordering tests for restart, engine switch, target failure,
  successful rollback, double failure, manual Stop and monitor crash;
- flow-offload detection/refusal tests and, before any future offload support,
  software and hardware offload dataplane tests;
- OpenWrt VM dataplane probes for IPv4 and IPv6 during an intentionally slow
  restart and a killed core;
- cold-boot, manager crash, firewall reload, network reload and new-egress
  hotplug tests with no forwarding window;
- prove UI/DHCP/router DNS remain reachable while forwarding is blocked;
- prove the guard is removed after successful recovery and explicit disable;
- prove a guard-removal failure leaves the healthy core running in the
  `running-guarded` state and is retried;
- power-loss/SIGKILL recovery and WAN/LAN hotplug tests.
