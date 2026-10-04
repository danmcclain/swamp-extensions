# @dmc/patch

Agentless fleet patch management for Proxmox VMs, Proxmox CTs (LXC), bare-metal
hosts, and VPSs — scan for pending updates, apply them safely (snapshot-guarded,
health-checked, with automatic rollback where reversible), and keep an auditable
history. No agent runs on the fleet; everything is driven over SSH (and `pct` for
containers) through a single `@swamp/ssh` model.

> Built to replace an agent-based patch monitor with a pull-based swamp
> workflow, avoiding the agent's WebSocket-leak failure mode.

---

## Table of contents

- [Concepts](#concepts)
- [Dependencies](#dependencies)
- [The fleet model — `@dmc/patch/fleet`](#the-fleet-model--dmcpatchfleet)
  - [Machine decorations](#machine-decorations)
  - [Health checks](#health-checks)
- [Methods](#methods)
- [Resources (data)](#resources-data)
- [Reports](#reports)
- [Workflows](#workflows)
- [The collector](#the-collector)
- [Snapshot & image retention lifecycle](#snapshot--image-retention-lifecycle)
- [Typical usage](#typical-usage)
- [Design notes & gotchas](#design-notes--gotchas)
- [Installing](#installing)

---

## Concepts

`@dmc/patch` is one **fleet** model whose instance holds a list of decorated
**machines**. Each machine declares *what it is* and *how to reach it*, and the
model's methods act on it:

| Layer | What it patches | Owned by |
| ----- | --------------- | -------- |
| **OS packages** | apt / dnf / apk inside the host or container | `@dmc/patch` (`ct` / `vm` / bare-metal path) |
| **App version** | a versioned app inside a CT (e.g. Forgejo, a cache server) | a `source` updater (e.g. `@dmc/proxmox/community-script`) |
| **Docker images** | running compose containers | `@dmc/patch` (`docker` path) |

The three layers are complementary — an app updater bumps the app binary, but the
container's OS packages (`bash`, `curl`, `openssl`, …) still need patching, and
that's the fleet's job.

Everything an operation produces (what changed, snapshots taken, health verdicts,
prunes) is written as **versioned model data**, so reports and `swamp data query`
give a full, queryable history.

---

## Dependencies

- **`@swamp/ssh`** (required) — the transport. The fleet takes an `sshModel`
  (an `@swamp/ssh` instance name, e.g. `my-ssh`) and reaches every host by
  delegating `swamp model method run <sshModel> exec/script`. Consumers point
  `sshModel` at their own fleet.
- **`@keeb/proxmox/node`** (for VMs) — snapshot / rollback API for Proxmox VMs
  (`snapshotVm` / `rollbackVm` / `listVmSnapshots` / `deleteVmSnapshot`).
- **`@dmc/proxmox/community-script`** (optional, for CT app updates) — the
  `source` app updater referenced by a CT.

CTs are snapshot-guarded via `pct` directly (no node-model method needed).

---

## The fleet model — `@dmc/patch/fleet`

Global arguments:

```yaml
type: '@dmc/patch/fleet'
name: fleet
globalArguments:
  sshModel: my-ssh        # required: an @swamp/ssh instance
  proxmoxNodes:              # optional: node models for VM/CT discovery in `import`
    - proxmox-node
  machines:                  # the decorated fleet (below)
    - host: node1
    - host: app-ct
      # …decorations…
```

### Machine decorations

Every machine has a `host` (a host name in `sshModel`). The rest is optional and
declares its nature:

```yaml
- host: my-app
  os: true                    # collect OS package status (default true; false = skip OS)
  reach: ssh | pct            # transport hint; unset = ssh, fall back to pct for CTs

  # --- location (pick the one that applies) ---
  vm:                         # a Proxmox VM — snapshot-guarded OS update via the node model
    proxmoxNode: proxmox-node # a @keeb/proxmox/node model name (for snapshot API)
    vmid: 300
  ct:                         # a Proxmox CT — OS update via pct, snapshot via pct
    proxmoxNode: node1        # the ssh HOST that runs pct (not the node model!)
    ctid: 701
  # (a plain host / VPS needs neither vm nor ct)

  # --- optional app updater on top of the OS lifecycle ---
  source:
    type: community-script    # currently the only type
    model: my-app             # a @dmc/proxmox/community-script instance

  # --- optional docker inspection / update ---
  docker:
    composePath: /home/me/my-app
    service: my-app           # optional; omit to target the whole compose project
    healthUrl: https://…      # probed after a docker update
    healthExpectStatus: 200

  # --- optional health checks (below) ---
  health:
    - type: http
      url: https://my-app.example.net/healthz
```

Notes:

- **`vm.proxmoxNode`** is a **node *model*** name (used for the snapshot API).
  **`ct.proxmoxNode`** is the **ssh *host*** that runs `pct` (e.g. `node1`). They
  are different kinds of reference.
- A **plain CT** needs only `ct` — it gets scan + OS-patch-with-capture + reboot,
  no `source` required.
- **`source`** is what triggers app-update delegation — *being a CT does not*.
- The deprecated **`proxmox: { model }`** is a legacy field that supplied both a
  CT's location and its app updater from one reference; still honoured as a
  fallback, but prefer `ct` + `source`.

### Health checks

`health` is an array of checks; the machine is **healthy only when every check
passes**. An empty/absent array falls back to reachability. Works on any machine —
the transport is chosen automatically (HTTP from the swamp host; `service` /
`command` via ssh or `pct`).

```yaml
health:
  - type: http
    label: API responding          # optional; shown in logs & reports
    url: https://app.example/healthz
    expectStatus: 200              # default 200
    timeoutSec: 10
  - type: service
    label: app service active
    name: my-app                   # systemctl is-active (or OpenRC rc-service on Alpine)
  - type: command
    label: self-check
    run: /usr/local/bin/my-app --selfcheck   # exit 0 = healthy
    timeoutSec: 30
```

Where checks are used:

- **`scan`** evaluates them and stores a verdict in `inventory.health`, rendered
  as ✅ / ❌ in the reports.
- **Before** `safeOsUpdate` / `safeUpdate`, the `baseline-healthy`
  [pre-flight check](#pre-flight-checks) evaluates them: an already-broken app
  blocks the update instead of being "fixed" and then rolled back. Bypass it with
  `--skip-check baseline-healthy`.
- **After** the update, `safeOsUpdate` evaluates them again; that **post-update**
  verdict drives the automatic rollback. It runs inside the method and is never
  skipped. It has a **grace window** (`healthGraceSec`, below).
- **`reboot`** runs them *after* the host returns — **detection only** (a reboot
  can't be rolled back; recovery is the explicit `rollback` method). It has the
  same grace window.

**Grace window (`healthGraceSec`).** A `docker-ce` upgrade restarts every
container, so a check made right after the update can read unhealthy for a good
update. `safeOsUpdate` and `reboot` take `healthGraceSec` (integer, `>= 0`,
default `120`). While the post-update (or post-reboot) health is unhealthy, the
method checks again every 10 seconds, until the machine is healthy or
`healthGraceSec` seconds have passed. Each failed attempt is logged at `info`
with the failing check labels. `healthGraceSec: 0` checks exactly once. The
window applies to both the CT path and the VM / bare-metal path of
`safeOsUpdate`. It never applies to the `baseline-healthy` pre-flight check,
which is immediate. A machine with no health checks keeps the reachability
fallback, with no wait.

**Secrets:** reference an on-host credential file in a `command`; the secret is
read at check time and never enters the config, git, or logs. Example (a cache server):

```yaml
- type: command
  label: cache PING
  run: 'cache-cli -a "$(cat /root/app.creds)" ping 2>/dev/null | grep -q PONG'
```

**Deriving from a `source`:** a `source: community-script` CT with no explicit
`health` derives `[http(healthUrl), service(service)]` from its updater model, so
existing setups work without extra config, and you can override anytime.

---

## Methods

| Method | Purpose |
| ------ | ------- |
| `scan` | Fan out over the fleet: collect OS package status + docker image drift per machine, evaluate health, and refresh `source` app-update checks. Per-machine (resilient — one unreachable host can't sink the run). |
| `import` | Emit a suggested `machines:` block seeded from the `sshModel` host list and Proxmox guest discovery (VMs → `vm`, CTs → `ct` + commented `source`). Paste into `globalArguments` and decorate. |
| `safeOsUpdate` | Snapshot-guarded OS update for one machine (see below). |
| `safeUpdate` | Health-checked, rollback-capable **docker** update: record image ids → pull + `up -d` → wait for health → roll back to the prior image on failure. Replaced images are retained for `retentionHours` (pruned by `pruneImages`). |
| `reboot` | Graceful reboot: `systemctl reboot` (ssh, scheduled via `systemd-run` so the call returns before the link drops) or `pct reboot` (CT). Guarded on `needsReboot` unless `force`; waits for return; runs health as **detection** (with the `healthGraceSec` grace window, default 120 s). |
| `rollback` | Deliberately revert a machine to its newest retained pre-update snapshot (VM snapshot rollback / `pct rollback`), or a named one. The recovery for a reboot/update that left a host unhealthy. |
| `pruneSnapshots` | Delete retained pre-update snapshots past their retention window that are health-confirmed, reboot-confirmed (when a reboot was needed), and pass a fresh healthcheck. `dryRun` to preview. VM → node-model delete; CT → `pct delsnapshot`. |
| `pruneImages` | Delete retained previous docker images past their retention window (via `docker rmi`, which refuses if still in use). `dryRun` to preview. |

### `safeOsUpdate` in detail

Arguments: `host`, `mode` (`safe` = `apt upgrade` / `full` = `apt full-upgrade`;
dnf/apk always upgrade), `retentionHours` (default 168 = 7 days),
`rollbackOnFailure` (default true), `healthGraceSec` (default 120, see
[Health checks](#health-checks)).

Before the method runs, its [pre-flight checks](#pre-flight-checks) gate it:
`host-in-fleet`, `host-reachable`, `baseline-healthy` (health checks pass now) and
`snapshot-target-resolves`. To update an app that is already unhealthy, bypass the
baseline gate on purpose:

```bash
swamp model method run fleet safeOsUpdate --input host=node1 --skip-check baseline-healthy
```

Flow, per machine type:

1. **Snapshot** — VM via the node model; CT via `pct snapshot`; bare-metal none.
2. **Upgrade** — apt/dnf/apk, over ssh (VM/bare) or `pct exec` (CT), capturing an
   installed-package **before/after diff** (`{name, from, to}`).
3. **App update** (CTs with a `source`) — delegate to the `source` updater on top
   of the OS update. **One snapshot guards both**: the method calls the source's
   `safeUpdate` with `{ snapshot: false }`, so the updater takes no snapshot of
   its own. This needs `@dmc/proxmox` >= 2026.10.01.1. An older `@dmc/proxmox`
   rejects the argument; the method then retries once with no arguments and logs
   a `warn`. That older updater takes its own extra, untracked snapshot (the
   old behavior). Any other failure of the source is not retried.
4. **Post-update health** — `healthyAfter` from the `health` checks (or
   reachability when none), with the `healthGraceSec` grace window. Unhealthy
   after the window → **roll back** the snapshot (VM / `pct`); healthy →
   **retain** it with the retention window.
5. **Reboot is never automatic** — `needsReboot` is reported; you call `reboot`.

### Pre-flight checks

swamp runs these checks **before** a method starts. A failed check stops the
run before anything changes. Each check is cheap and read-only. `scan` and
`import` have no checks.

| Check | Label | Runs before | Verifies |
| ----- | ----- | ----------- | -------- |
| `host-in-fleet` | `policy` | `safeUpdate`, `safeOsUpdate`, `reboot`, `rollback`, `pruneSnapshots`, `pruneImages` | The `host` argument names a machine in `globalArguments.machines`. A prune method with no `host` filter passes. |
| `docker-configured` | `policy` | `safeUpdate` | The machine has a `docker` block. |
| `host-reachable` | `live` | `safeUpdate`, `safeOsUpdate`, `reboot` | The machine answers: ssh `true` through the `sshModel`, or `pct status <ctid>` on the node for a CT. Not run for `rollback`, because a broken host is the reason to roll back. |
| `baseline-healthy` | `live` | `safeUpdate`, `safeOsUpdate` | The machine's [health checks](#health-checks) pass now. The failing labels are named. A machine with no health checks passes. |
| `snapshot-target-resolves` | `live` | `safeOsUpdate`, `rollback`, `pruneSnapshots` | The VM or CT location resolves and its Proxmox node answers. For `rollback`, a snapshot also exists (the named one, if you pass `snapshot`). A machine with no `vm` or `ct` passes. |

The prune methods keep their per-host skip behavior. Only `host-in-fleet`
(and, with a `host` filter, `snapshot-target-resolves`) checks them.

Skip checks with the standard swamp flags:

```bash
swamp model method run fleet safeOsUpdate --input host=my-host --skip-check host-reachable
swamp model method run fleet safeOsUpdate --input host=my-host --skip-check-label live
swamp model method run fleet safeOsUpdate --input host=my-host --skip-checks
```

To run the checks without the method, use
`swamp model validate fleet --method safeOsUpdate --label live`. This command
takes no method arguments, so the checks that need a `host` pass without a
target. Run the method to test a real host.

---

## Resources (data)

All are versioned model data (`swamp data list fleet`, `swamp data query`).

| Spec | Written by | Contents |
| ---- | ---------- | -------- |
| `inventory` | scan / safeOsUpdate | Per-host OS status, docker engine + image drift, reachMethod, **health** verdict. Keyed by host (latest = current). |
| `run` | every mutating method | Append-only audit row (`run-<action>-<host>-<ts>`): action, outcome, before/after counts, **package** and **image** diffs, snapshot, rolledBack, needsReboot. |
| `snapshot` | safeOsUpdate | Lifecycle of a retained snapshot (`kind` vm/ct, retainUntil, healthConfirmed, rebootConfirmed, status). |
| `image` | safeUpdate | A retained previous docker image (rollback point) with a retention window. |
| `osUpdate` / `update` / `reboot` | the respective method | Latest result per host for that operation. |
| `prune` | pruneSnapshots / pruneImages | What each prune run retired vs kept (and why). |
| `seed` | import | A suggested `machines:` block. |

Example queries:

```bash
swamp data list fleet
swamp data query 'modelName == "fleet" && content.action == "osUpdate"' \
  --select '{"host":content.host,"out":content.outcome,"pkgs":content.packagesChanged}' --json
```

---

## Reports

Model-scoped (attached to the fleet model); fetch with
`swamp report get <name> --model fleet --markdown`.

- **`@dmc/patch-status`** — one holistic fleet table: per node its **health**,
  OS updates, security, community-script **app** version, reboot, docker engine +
  container count; plus **Docker containers**, **Unhealthy**, and
  **Reboot required** sections.
- **`@dmc/patch-history`** — per-host detail: current status (OS, location, app,
  docker, health) followed by that host's **run history** with collapsible
  package / image `from → to` diffs. Every host gets a section, even with no runs.
- **`@dmc/patch-prune-history`** — chronological snapshot/image prune runs
  (retired vs kept, with reasons).

Model-scope reports regenerate when a fleet method runs; there is no
`swamp report run`, so trigger a cheap method (e.g. `pruneImages --input dryRun=true`)
to refresh, or run the `patch-scan` workflow.

---

## Workflows

- **`patch-scan`** — `fleet scan` → community-script `checkUpdate` per app →
  renders the reports. Read-only. Schedule this for a recurring inventory.
- **`patch-prune`** — `pruneSnapshots` → `pruneImages` (sequential, to avoid
  fleet-model lock contention). Real prune, but self-gated on retention + health,
  so it's safe to schedule.

```bash
swamp workflow run patch-scan
swamp workflow run patch-prune
```

A gated `patch-apply` workflow (orchestrating `safeOsUpdate` / `reboot` across the
fleet) is a planned addition.

---

## The collector

The collector is a self-contained, OS-detecting bash script (apt / dnf / apk)
bundled inside the extension — consumers do not need to provide it. It prints **one** `{"_kind":"patch-inventory",…}` JSON line:
pending updates, security updates, held-back / dist-upgrade (apt), total packages,
`needsReboot` (running-vs-installed kernel + `needs-restarting -r` / apt
`reboot-required`), and per-container docker image drift. It runs over ssh, or is
shipped base64-encoded through `pct exec` for CTs. It reads no stdin
(`main </dev/null`) because the ssh model pipes it on stdin.

---

## Snapshot & image retention lifecycle

Rollback points are **never auto-deleted** — they're retained so you have time to
catch a late-surfacing problem (a bad kernel only shows up on the reboot):

1. `safeOsUpdate` takes a snapshot and, on success, **retains** it with
   `retainUntil = now + retentionHours` (default 7 days). `safeUpdate` retains the
   replaced docker image the same way.
2. `reboot` confirms a snapshot once the host returns healthy after a reboot.
3. `pruneSnapshots` / `pruneImages` delete only what is **past retention**,
   **health-confirmed**, **reboot-confirmed** (when required), and **healthy on a
   fresh check** — and CT snapshots refuse via `pct`/`docker rmi` if still needed.
4. `rollback` reverts a host to its retained snapshot when you decide to.

---

## Typical usage

```bash
# 1. Seed the fleet (then paste + decorate the output into globalArguments.machines)
swamp model method run fleet import

# 2. Scan and view status
swamp workflow run patch-scan
swamp report get @dmc/patch-status  --model fleet --markdown
swamp report get @dmc/patch-history --model fleet --markdown

# 3. Patch a host (snapshot-guarded, health-checked, package diff captured)
swamp model method run fleet safeOsUpdate --input host=app-ct

# 4. Reboot when needed (health is detected, not auto-rolled-back)
swamp model method run fleet reboot --input host=app-ct

# 5. If something's wrong, revert deliberately
swamp model method run fleet rollback --input host=app-ct

# 6. Clean up old rollback points on schedule
swamp workflow run patch-prune
```

---

## Design notes & gotchas

- **`ct.proxmoxNode` = ssh host, `vm.proxmoxNode` = node model.** Different refs.
- **Shipping shell into a CT** must go through `runScript` (`pct exec … -- bash -c
  "echo '<b64>' | base64 -d | bash"`), not `exec` with `sh -c "…"` — nested double
  quotes break through the exec wrapper (`rc 127`).
- **`DEBIAN_FRONTEND`** is exported on its own line, never inlined as
  `$SUDO VAR=val cmd` (which breaks when `$SUDO` is non-empty).
- **A reboot can't be rolled back** (the disk is unchanged); reboot health is
  detection, and recovery is the explicit `rollback` to the pre-update snapshot.
- **Community-script CTs take ONE snapshot** — the fleet's guarding snapshot. The
  app step calls the updater with `snapshot: false` (needs `@dmc/proxmox` >=
  2026.10.01.1; an older one takes its own extra snapshot and a `warn` is logged).
- **Health checks share a definition** with `@dmc/proxmox/community-script`
  (a shared contract, since swamp extensions bundle independently).

---

## Installing

```bash
swamp extension pull @dmc/patch
```

Then create a `@dmc/patch/fleet` model instance, point `sshModel` at your own
`@swamp/ssh` instance, and list your machines. The `patch-scan` and
`patch-prune` workflows shown above are small YAML definitions you author in your
own repo: `patch-scan` runs `fleet scan` (plus any `checkUpdate` on your
community-script CTs), and `patch-prune` runs `pruneSnapshots` then
`pruneImages`.
