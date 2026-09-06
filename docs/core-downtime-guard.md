# Panel restart traffic guard

Status: implemented, off by default. The setting is available in the panel's
Settings page as **Blackhole during restart** / **Blackhole при перезапуске**.

## Goal

Optionally stop forwarded LAN traffic from escaping directly during an explicit
user-requested restart of a running core from the boxctl panel, for example to
apply a new configuration. Block only the restart gap, from immediately before
deactivating the old dataplane until the replacement or rollback is healthy.
The router's management UI, DHCP, DNS service and LAN-local traffic must stay
reachable throughout the operation.

Opening the panel or starting the manager while the core has not started must
leave traffic fail-open. Core unavailability alone must never engage the guard.

The guard is not the normal transparent-proxy ruleset. It must live in a
separate, ownership-marked nftables table so removing or replacing the active
Mihomo/sing-box generation cannot create an unguarded gap.

## User-visible behaviour

Use a single optional setting, "Blackhole during restart", off by
default. There is no persistent `strict` mode or boot-time kill switch in this
plan. Enabling the setting only changes how subsequent eligible restarts run;
saving it never installs the guard immediately.

| Operation | Engage the guard? |
| --- | --- |
| Panel **Restart**, while the core is running | Yes, just before dataplane teardown |
| **Save & restart** of the active configuration, while the core is running | Yes |
| Panel profile/engine switch or apply action with an explicit restart confirmation | Yes, only if it actually restarts a running core |
| Open/reload the panel, start the manager, router boot or first installation | No |
| **Start** of a stopped core, including a failed start | No |
| Restart request received when the core is already stopped or failed | No; any resulting start is an ordinary unguarded start |
| Save without restart, edit an inactive profile, or hot reload without dataplane teardown | No |
| Manual **Stop**, service shutdown, standalone core crash or health-check failure | No |
| Scheduled maintenance, automatic updates, CLI/service restarts or manager handoff | No |

Eligibility depends on explicit user intent and the running state checked under
the lifecycle operation lock, not on the name of a shared `Restart`/`Stop`
method. Background jobs must not inherit guard eligibility just because they
use the same lifecycle helpers. A reload that requires restart must obtain the
user's explicit restart confirmation before becoming eligible.

If the target fails, retain the guard through a bounded rollback attempt. Once
recovery succeeds, or the restart and recovery attempts end in failure,
remove it. A failed operation must return to today's fail-open recovery
behaviour, rather than leave clients blocked while the core remains stopped.

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
- interface sets are resolved before each restart and remain fixed through its
  rollback. New egress names are blocked without WAN discovery/reconciliation.

Reconciliation across firewall/network reload and hotplug may maintain a guard
only while its restart transaction is active. It must never create a guard
merely because the core is absent. There is no early-boot guard installation.
Normal fw4 reload affects `inet fw4` and preserves the independent guard table.
A global `nft flush ruleset`, changing protected LAN device names, or enabling
offload externally during the transaction is outside the supported boundary.

## Lifecycle ordering

For an eligible panel restart:

1. Acquire the lifecycle operation lock and recheck explicit restart intent,
   policy, running core and owned gateway state. If already stopped, follow
   the ordinary unguarded start/apply path.
2. Prepare and validate the target and rollback material while the old
   dataplane is still active. A validation failure must not engage the guard.
3. Resolve and atomically install the guard with a bounded transaction lease,
   immediately before the first disruptive step. Arm expiry recovery before
   teardown so a manager crash cannot leave an indefinite blackhole.
4. Restore DNS/remove the old capture dataplane.
5. Stop the old core.
6. Start and probe the new core.
7. Activate capture and DNS.
8. Run the existing post-activation health probe and verify committed gateway
   state. On target failure, keep the same guard through rollback and verify
   the recovered generation instead.
9. Atomically remove the guard after success, or after terminal failure and
   bounded cleanup. Report a failed restart even when fail-open cleanup works.

A failed guard installation must abort the protected restart before touching
the old dataplane. Cancellation or an incidental rollback/cleanup error must
enter transaction finalization; it must not skip guard removal or remove the
guard midway through an active rollback. Closing the browser must not strand
the guard or cancel required recovery.

Lifecycle calls need an explicit reason/scope propagated from panel restart and
confirmed apply actions. In particular, `LifecycleService.Restart`, config
save/apply callbacks and profile switching must carry that scope into the same
transaction; generic `Start`, `Stop`, monitor cleanup and automatic updates must
not install a guard. Keep the guard separate from capture cleanup so the stop,
target activation and rollback steps cannot remove it accidentally.

Successful recovery requires the complete committed gateway state: healthy
core and controller, owned capture/firewall and policy routing, and the expected
DNS state. The existing process/controller readiness probe alone is
insufficient. Terminal failure removes the guard without claiming recovery.
If the target is healthy but guard removal fails, keep the healthy core, report
a distinct `running-guarded` degraded state, and retry verified removal within
the lease deadline. Do not stop or roll back the healthy target merely because
removal failed. Expiry must still restore fail-open forwarding if retries fail.

## Settings and recovery safety

Persist a boolean such as `CORE_RESTART_GUARD=false|true`:

- validate gateway support and disabled flow offload before enabling it;
- save the setting without installing a guard, whether the core is running or
  stopped; `START_ON_BOOT=false` remains a valid combination;
- reject enabling it in server/no-gateway operation;
- serialize policy changes with lifecycle operations; disabling must verify
  removal of any owned guard before reporting success;
- expose guard state, restart reason, lease deadline and last cleanup error in
  `/status`;
- provide a local recovery command that disables the setting and removes only
  a verified boxctl-owned guard table.

The fresh-install/start-stopped marker, ordinary startup and failed initial
start remain fail-open even when restart protection is enabled. Starting the
panel never waits for a healthy core before allowing normal forwarding.

Bound the entire guarded transaction, including rollback and cleanup. Define a
maximum lease and an expiry mechanism that works without the manager, such as
an nftables timeout. The implementation uses timed `ifname` set elements with a
five-minute lifetime; expiry makes the drop rule inert without a userspace
watchdog. Applying the same plan never renews its timeout. The target operation
has a two-minute budget, with bounded rollback and cleanup inside that lease.
See the upstream [nftables set timeout contract](https://netfilter.org/projects/nftables/manpage.html).

After an interrupted transaction, manager startup removes only verified stale
owned guard state before serving normal lifecycle operations; it must not wait
for the core to start or recreate the guard. Ordinary shutdown and uninstall
also finalize/remove owned guards. Recovery must remain bounded even after
SIGKILL without a subsequent manager restart. README and SECURITY describe the
temporary restart window, expiry and fail-open failure recovery.

Local emergency recovery is `boxctl fw guard-off` with `BOXCTL_ROOT` set to the
managed root. This removes a verified owned table and saves
`CORE_RESTART_GUARD=false`. Normal daemon startup, Stop, shutdown and package
cleanup also remove owned guard state; none install a startup guard.

The settings page also offers **Network recovery → Stop core and clean firewall**
(`POST /api/v1/firewall/cleanup`, authenticated and CSRF-protected). It restores
the saved DNS options and removes owned capture/policy state before stopping the
core, then removes any verified owned restart guard. It forces reinspection even
when the in-memory lifecycle already says stopped and knows of no guard. It does
not change the saved restart-protection setting or start the core again. An
in-progress lifecycle operation returns a conflict instead of racing cleanup.
Once accepted, cleanup has a bounded context independent of a browser disconnect.
Failures are reported rather than hidden; capture/DNS removal failure keeps the
core alive for retry, while guard removal is still attempted independently.

On startup the stale guard is removed before normal lifecycle operations. Without
a live adopted core, both regular Start and management-only `--start-stopped`
reconcile stale capture/policy/DNS before exposing the panel. A verified live
generation retained through manager recovery preserves its working dataplane.
Private runtime files and a persisted process record are also discarded when
the runtime passes ownership validation and the recorded PID no longer exists.
Live or reused PIDs and unverified runtime paths do not qualify for this cleanup.
All cleanup uses ownership markers and saved DNS state, never a global firewall
flush or a guessed resolver reset.

The current managed capture path is IPv4-only. An `inet` guard can block both
IPv4 and IPv6 during downtime, but after a healthy core is restored IPv6 can
still use the router's normal path. Restart protection must not be marketed as
all-time IPv6 tunnelling or a persistent kill switch.

## Verification

The implementation is covered by `make check` and focused Go race tests for
restart ordering, rollback, policy persistence, cancellation and a restart
queued behind Stop. `tests/integration/guest/restart-guard.sh` runs inside the
existing disposable OpenWrt VM suite and checks the real panel settings and
restart APIs, IPv4/IPv6 forwarding, router reachability, fw4 reload, a renamed
egress, successful recovery, explicit disable and kernel timeout expiry. The
VM suite also exercises subsequent engine switches, manager crash recovery,
Stop, second startup, procd reload, panel firewall cleanup from running/stopped
states, and startup after SIGKILL of both manager and core with stale guard,
capture, policy and DNS state. Recovery must preserve a foreign sentinel table.

The guard's five-minute production lease is shortened to three seconds only
when replaying its rendered nftables rule for the isolated expiry test. This
tests kernel expiry without waiting for or invoking manager cleanup. No
production-router rollout or rendered-browser verification is implied by
these checks.

Regression requirements and additional platform coverage:

- nft render, ownership-conflict, idempotence and cleanup unit tests;
- lifecycle ordering tests for panel restart, save-and-restart, confirmed
  profile/engine switch, target failure, successful rollback and double failure;
- prove no guard is installed on panel/manager startup, cold boot, first start,
  failed start, manual Stop, monitor crash, hot reload, save-only, background
  maintenance or automatic updates, including with protection enabled;
- prove a restart queued behind Stop rechecks state under the operation lock
  and does not guard an ordinary start;
- guard-install failure must leave the old dataplane running; preparation and
  validation failures must not install the guard;
- flow-offload detection/refusal tests and, before any future offload support,
  software and hardware offload dataplane tests;
- OpenWrt VM dataplane probes for IPv4 and IPv6 during an intentionally slow
  panel restart and rollback, plus unguarded startup and standalone core crash;
- firewall reload and new-egress tests with no forwarding window during an
  active guarded transaction, and no guard installation outside one; network
  reload coverage must preserve the configured protected LAN device names;
- prove UI/DHCP/router DNS remain reachable while forwarding is blocked;
- prove the guard is removed after successful recovery, terminal failure,
  cancellation, explicit disable, shutdown and uninstall;
- prove a guard-removal failure leaves the healthy core running in the
  `running-guarded` state and is retried, with fail-open expiry still bounded;
- browser disconnect, manager SIGKILL without restart, interrupted-transaction
  startup cleanup and power-loss recovery tests; none may leave or recreate a
  persistent blackhole while waiting for a stopped core.
