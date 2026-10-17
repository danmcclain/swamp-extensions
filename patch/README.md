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
- [How `@dmc/patch` reaches other models](#how-dmcpatch-reaches-other-models)
- [The fleet model — `@dmc/patch/fleet`](#the-fleet-model--dmcpatchfleet)
  - [Machine decorations](#machine-decorations)
  - [Health checks](#health-checks)
- [Extending `@dmc/patch` — your own updater and snapshotter](#extending-dmcpatch--your-own-updater-and-snapshotter)
  - [Updater contract (`source`)](#updater-contract-source)
  - [Snapshotter contract (`snapshotter`)](#snapshotter-contract-snapshotter)
  - [Example](#example)
- [Methods](#methods)
  - [Retired machines and `clearRetired`](#retired-machines-and-clearretired)
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
| **App version** | a versioned app on the machine (e.g. Forgejo in a CT, a binary on a VM) | a `source` updater (e.g. `@dmc/proxmox/community-script`, or [your own](#extending-dmcpatch--your-own-updater-and-snapshotter)) |
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
  (an `@swamp/ssh` instance name, e.g. `my-ssh`) and reaches every host through
  its `exec` and `script` methods (see
  [How `@dmc/patch` reaches other models](#how-dmcpatch-reaches-other-models)).
  Consumers point `sshModel` at their own fleet.
- **`@keeb/proxmox/node`** (for VMs) — snapshot / rollback API for Proxmox VMs
  (`snapshotVm` / `rollbackVm` / `listVmSnapshots` / `deleteVmSnapshot`).
- **`@dmc/proxmox/community-script`** (optional, for CT app updates) — the
  `source` app updater referenced by a CT.

CTs are snapshot-guarded via `pct` directly (no node-model method needed).

None of these is required for a mechanism you bring yourself: an app updater or a
snapshotter can be any model that implements the contract — see
[Extending `@dmc/patch`](#extending-dmcpatch--your-own-updater-and-snapshotter).

---

## How `@dmc/patch` reaches other models

The fleet does no ssh or Proxmox work itself. It calls the methods of other
models: `<sshModel> exec` / `script`, the `vm.proxmoxNode` model
(`snapshotVm`, `rollbackVm`, `listVmSnapshots`, `deleteVmSnapshot`), the
`proxmoxNodes` models (`listGuests`, for `import`), the `source` updater
(`checkUpdate`, `safeUpdate`), and the `snapshotter` model (`snapshot`,
`rollback`, `deleteSnapshot`, `listSnapshots`). Updaters and snapshotters are
reached by instance name; their type does not matter.

**Methods** use swamp's in-process API. They never start the swamp CLI:

- `context.runModel` runs another model's method. The fleet reads the
  attributes of the resources that method wrote.
- `context.readModelData` reads another model's data. The fleet uses it for one
  case only: when an `<sshModel> script` call fails because one host exits
  non-zero, `runModel` returns no resources, but the ssh model has already
  written one `runResult` record per host (`run-script-<host>`). The fleet reads
  those records back, keeps only the requested hosts, and keeps only records
  that started at or after the call. So a result of an earlier run is never
  used. (A second run of the same method on the same host, through the same ssh
  model, at the same time, could still write a record that is read instead.)
- `context.definitionRepository` reads another model's `globalArguments`: a
  legacy `proxmox.model` CT location, the `healthUrl` / `service` of a `source`,
  and the `hosts` list of the `sshModel` (for `import`).

The fleet reads its **own** records by model id (`dataRepository`), never with
`readModelData`.

**Pre-flight checks** get no `runModel` from swamp. Three `live` checks must
still reach hosts, so they start the swamp CLI as a subprocess:

```bash
swamp model method run <model> <method> --json --quiet --repo-dir <repoDir> --input …
```

| Check | Model and method it runs |
| ----- | ------------------------ |
| `host-reachable` | `<sshModel> exec` (`true` on the host, or `pct status <ctid>` on the node of a CT) |
| `baseline-healthy` | `<sshModel> script` (the machine's batched health checks; on the node through `pct exec` for a CT) |
| `snapshot-target-resolves` | `<snapshotter.model> listSnapshots` when a `snapshotter` is set; else `<vm.proxmoxNode> listVmSnapshots` for a VM, or `<sshModel> exec` (`pct listsnapshot <ctid>` on the node) for a CT |

- The model names come from the fleet's own `globalArguments` (`sshModel`,
  `machines[].vm.proxmoxNode`, `machines[].snapshotter.model`). They are
  zod-validated strings.
- Every value is passed as a separate argv element (a string as `k=<v>`, any
  other value as `k:json=<JSON>`). No shell is involved.
- No secret is passed. The arguments are host names, ids, timeouts and the
  command text: fixed commands and your own health-check commands. Keep secrets
  on the host (see [Health checks](#health-checks)), because a command line is
  visible in the local process list.
- The checks read definitions in-process from `definitionRepository`, not
  through the CLI.

### The scan call budget

swamp allows at most **100** `runModel` calls in one method run. `scan`
batches its calls to stay well below that:

```text
calls = 1                                  one ssh `script` call: the collector on every ssh host
      + nodes with CTs on the pct path     one call per Proxmox node: the collector in each of its CTs in turn
      + machines with service/command checks   one health call per machine
      + app sources                        one `checkUpdate` per `source`
```

`http` checks run from the swamp host and cost no call. A machine with no
`service` / `command` check and no `source` costs no call of its own. So with a
shell health check on every machine and two or three Proxmox nodes, about 95
machines fit; with a `source` on every machine too, about 48 fit. When the cap
is reached, the later calls fail, every machine still gets its inventory record
(an error record when nothing worked), and `scan` logs **one** warning that names
the cap and the machine count. Split a larger fleet over more fleet models.

A failing host or node does not affect the others: each host keeps its own
result or error, and each node's call is separate.

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

  # --- optional app updater on top of the OS lifecycle (any machine kind) ---
  source:
    type: community-script    # optional label for readers; the fleet does not read it
    model: my-app             # ANY model that implements the updater contract,
                              # e.g. a @dmc/proxmox/community-script instance

  # --- optional pluggable snapshot guard (overrides the built-in VM/CT snapshot) ---
  snapshotter:
    model: my-snapshots       # ANY model that implements the snapshotter contract

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
- **`source`** is what triggers app-update delegation — *being a CT does not*. It
  works on every machine kind (VM, CT, bare metal), and the model can be any
  updater you write ([updater contract](#updater-contract-source)).
- **`snapshotter`** replaces the built-in snapshot guard (VM node model / CT
  `pct`) with any model you write, and lets a bare-metal machine be
  snapshot-guarded ([snapshotter contract](#snapshotter-contract-snapshotter)).
- The deprecated **`proxmox: { model }`** is a legacy field that supplied both a
  CT's location and its app updater from one reference; still honoured as a
  fallback, but prefer `ct` + `source`.

### Health checks

`health` is an array of checks; the machine is **healthy only when every check
passes**. An empty/absent array falls back to reachability. Works on any machine —
the transport is chosen automatically (HTTP from the swamp host; `service` /
`command` via ssh or `pct`). All `service` and `command` checks of one machine run in
**one** shell call on it. Each check runs in its own subshell (with stdin and
output on `/dev/null`), so a bare `exit` in one check ends only that check; only
its exit code counts. The call's timeout is the sum of the `command` checks'
`timeoutSec` plus 30 s per `service` check. A check with no result in the
output fails with the detail `no result`.

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

**Deriving from a `source`:** a machine with a `source` and no explicit `health`
derives `[http(healthUrl), service(service)]` from the updater model's
`healthUrl` / `healthExpectStatus` / `service` globalArguments (a
community-script instance has them; your own updater may too), so existing setups
work without extra config, and you can override anytime.

---

## Extending `@dmc/patch` — your own updater and snapshotter

`@dmc/patch` has two extension points. Each one is a **contract**: you name a
model instance on a machine, and the fleet calls that model's methods **by name**
(through `runModel`). The fleet never needs the model's type. So you can add your
own update or snapshot mechanism in your own repo, without changing or
upstreaming anything to `@dmc/patch`.

| Decoration | What it plugs in | Contract (methods your model exposes) |
| ---------- | ---------------- | ------------------------------------- |
| `source: { model }` | The app-update step, on top of the OS update | `checkUpdate`, `safeUpdate({ snapshot? })` |
| `snapshotter: { model }` | The snapshot guard: snapshot → rollback → cleanup | `snapshot`, `rollback`, `deleteSnapshot`, `listSnapshots` |

The built-in behavior is the same code path: the Proxmox VM and CT snapshots are
two snapshotter implementations inside the fleet, and
`@dmc/proxmox/community-script` is one updater.

### Updater contract (`source`)

| Method | Arguments | Called by | Your model must |
| ------ | --------- | --------- | --------------- |
| `checkUpdate` | none | `scan`, for every machine with a `source` | Record whether an update is available. Best-effort: a failure only logs a warning. |
| `safeUpdate` | `snapshot?: boolean` | `safeOsUpdate`, after the OS upgrade, on any machine kind | Apply the update. A failed method run counts as a failed update. |

The `snapshot` argument tells the updater who guards the machine:

- **`snapshot: false`** — `@dmc/patch` already took a snapshot (the machine has a
  `vm`, a `ct`, or a `snapshotter`). That one snapshot guards the OS update **and**
  the app update, so take no snapshot of your own. If the machine is unhealthy
  after the update, `@dmc/patch` rolls the whole machine back to it.
- **no argument** — the machine is unguarded (bare metal with no `snapshotter`).
  Guard yourself if you can.
- Declare `snapshot` as an optional boolean. An updater that does not declare it
  is retried once with no arguments (and a warning is logged), so it still works.

Optional globalArguments: `healthUrl`, `healthExpectStatus`, `service`. A machine
with a `source` and no `health` checks derives its health checks from them (see
[Health checks](#health-checks)).

`source.type` is an optional free-text label for readers (for example
`community-script` or `swamp-binary`). The fleet does not read it.

### Snapshotter contract (`snapshotter`)

A snapshot, its rollback and its cleanup act on one artifact. So they are **one
contract**: the implementation that takes a snapshot must also roll it back and
delete it.

| Method | Arguments | Called by | Your model must |
| ------ | --------- | --------- | --------------- |
| `snapshot` | `host`, `name` | `safeOsUpdate`, before the upgrade | Take a snapshot of `host` called `name`. A failed run **aborts the update** before anything changes. |
| `rollback` | `host`, `name` | `safeOsUpdate` (unhealthy after the update, with `rollbackOnFailure`), and the `rollback` method | Revert `host` to snapshot `name`. |
| `deleteSnapshot` | `host`, `name` | `pruneSnapshots` (past retention, health- and reboot-confirmed, healthy now) | Remove snapshot `name`. A failed run keeps the record (reason `delete call failed`). |
| `listSnapshots` | `host` | the `snapshot-target-resolves` pre-flight check | Write one resource whose attributes hold `snapshots: [{ name }]`. |

Rules:

- **`@dmc/patch` chooses every snapshot name** (`preupdate-<timestamp>`). Your
  model must find a snapshot again by that name — for example, store it as a tag
  on a cloud snapshot.
- **`host`** is the machine's host, so one snapshotter instance can serve many
  machines.
- **Success is the method run succeeding.** Report a failure by failing the run.

Which snapshotter a machine uses, in order:

1. **`snapshotter: { model }`** — always wins. It overrides the built-in VM/CT
   snapshot.
2. **`vm`** — built-in **proxmox-vm**: the node model's `snapshotVm`,
   `rollbackVm`, `deleteVmSnapshot` and `listVmSnapshots`.
3. **a CT** (`ct`) — built-in **proxmox-ct**: `pct snapshot | rollback |
   delsnapshot | listsnapshot` on the node.
4. **none** — the update is unguarded (bare metal). Add a `snapshotter` to guard
   bare metal.

**Each snapshot record remembers its snapshotter.** A `snapshot` record stores
the snapshotter that took it (`snapshotter: { kind: proxmox-vm | proxmox-ct |
model, … }`). `rollback` and `pruneSnapshots` dispatch from the **record**, not
from the machine's current decorations. So when you change a machine's
snapshotter, its older snapshots are still rolled back and deleted by the
implementation that took them. Records written before this release have no
`snapshotter` field; they map from `kind` / `vmid` / `proxmoxNode`.

### Example

A machine that updates its own app binary on a VM, guarded by your own
snapshotter:

```yaml
machines:
  - host: app-vm
    vm: { proxmoxNode: proxmox-node, vmid: 310 }  # location: scan, reboot
    snapshotter:
      model: zfs-snapshots     # your model — overrides the built-in VM snapshot
    source:
      type: app-binary         # label only
      model: app-updater       # your model
    health:
      - type: http
        url: https://app.example.net/health
```

A snapshotter is an ordinary swamp model. A minimal outline (add your own
backend calls where the comments are):

```ts
import { z } from "npm:zod@4";

const Target = z.object({ host: z.string(), name: z.string() });
const done = { dataHandles: [] };

export const model = {
  type: "@you/zfs-snapshots",
  version: "2026.10.16.1",
  globalArguments: z.object({ dataset: z.string() }),
  resources: {
    snapshots: {
      description: "Snapshot names of a host",
      schema: z.object({ snapshots: z.array(z.object({ name: z.string() })) }),
      lifetime: "infinite" as const,
      garbageCollection: 5,
    },
  },
  methods: {
    snapshot: {
      description: "Take snapshot `name` of `host`",
      arguments: Target,
      execute: async (a, ctx) => done, // e.g. zfs snapshot <dataset>@<name>
    },
    rollback: {
      description: "Revert `host` to snapshot `name`",
      arguments: Target,
      execute: async (a, ctx) => done, // e.g. zfs rollback -r <dataset>@<name>
    },
    deleteSnapshot: {
      description: "Remove snapshot `name` of `host`",
      arguments: Target,
      execute: async (a, ctx) => done, // e.g. zfs destroy <dataset>@<name>
    },
    listSnapshots: {
      description: "List the snapshots of `host`",
      arguments: z.object({ host: z.string() }),
      execute: async (a, ctx) => {
        const names: string[] = []; // e.g. from zfs list -t snapshot
        const h = await ctx.writeResource("snapshots", a.host, {
          snapshots: names.map((name) => ({ name })),
        });
        return { dataHandles: [h] };
      },
    },
  },
};
```

An updater needs only two methods:

```ts
methods: {
  checkUpdate: {
    description: "Record whether a newer version is available",
    arguments: z.object({}),
    execute: async (_a, ctx) => ({ dataHandles: [/* a version record */] }),
  },
  safeUpdate: {
    description: "Apply the update",
    arguments: z.object({ snapshot: z.boolean().optional() }),
    // snapshot === false → @dmc/patch owns the snapshot; take none of your own.
    execute: async (a, ctx) => ({ dataHandles: [] }),
  },
},
```

---

## Methods

| Method | Purpose |
| ------ | ------- |
| `scan` | Fan out over the fleet: collect OS package status + docker image drift per machine, evaluate health, and refresh `source` app-update checks. Batched (one ssh call for all ssh hosts, one call per Proxmox node for its CTs, one health call per machine) and resilient: one unreachable host or node can't sink the run. See the [scan call budget](#the-scan-call-budget). |
| `import` | Emit a suggested `machines:` block seeded from the `sshModel` host list and Proxmox guest discovery (VMs → `vm`, CTs → `ct` + commented `source`). Paste into `globalArguments` and decorate. |
| `safeOsUpdate` | Snapshot-guarded OS update for one machine (see below). |
| `safeUpdate` | Health-checked, rollback-capable **docker** update: record image ids → pull + `up -d` → wait for health → roll back to the prior image on failure. Replaced images are retained for `retentionHours` (pruned by `pruneImages`). |
| `reboot` | Graceful reboot: `systemctl reboot` (ssh, scheduled via `systemd-run` so the call returns before the link drops) or `pct reboot` (CT). Guarded on `needsReboot` unless `force`; waits for return; runs health as **detection** (with the `healthGraceSec` grace window, default 120 s). |
| `rollback` | Deliberately revert a machine to its newest retained pre-update snapshot, or a named one, through the snapshotter that took it (VM snapshot rollback / `pct rollback` / your `snapshotter`'s `rollback`). The recovery for a reboot/update that left a host unhealthy. |
| `pruneSnapshots` | Delete retained pre-update snapshots past their retention window that are health-confirmed, reboot-confirmed (when a reboot was needed), and pass a fresh check: the host answers a scan (over `pct` on its node for a CT, over ssh otherwise) and has no reboot pending. A snapshot of a host that is no longer in the fleet is kept. `dryRun` to preview. Each snapshot is deleted by the snapshotter that took it: VM → node-model delete; CT → `pct delsnapshot`; your `snapshotter` → `deleteSnapshot`. |
| `pruneImages` | Delete retained previous docker images past their retention window (via `docker rmi`, which refuses if still in use). `dryRun` to preview. |
| `clearRetired` | Delete the stored records of **retired machines** (hosts with records that are no longer in `globalArguments.machines`). **A bare run is a preview** (`dryRun` defaults to `true`). See [Retired machines and `clearRetired`](#retired-machines-and-clearretired). |

### `safeOsUpdate` in detail

Arguments: `host`, `mode` (`safe` = `apt upgrade` / `full` = `apt full-upgrade`;
dnf/apk always upgrade), `retentionHours` (default 168 = 7 days),
`rollbackOnFailure` (default true; applies to every machine kind with a snapshot
guard), `healthGraceSec` (default 120, see [Health checks](#health-checks)).

Before the method runs, its [pre-flight checks](#pre-flight-checks) gate it:
`host-in-fleet`, `host-reachable`, `baseline-healthy` (health checks pass now) and
`snapshot-target-resolves`. To update an app that is already unhealthy, bypass the
baseline gate on purpose:

```bash
swamp model method run fleet safeOsUpdate --input host=node1 --skip-check baseline-healthy
```

Flow, per machine type:

1. **Snapshot** — through the machine's snapshotter: your `snapshotter` model
   when set; else a VM via the node model, a CT via `pct snapshot`; bare metal
   none. A failed snapshot aborts the update.
2. **Upgrade** — apt/dnf/apk, over ssh (VM/bare) or `pct exec` (CT), capturing an
   installed-package **before/after diff** (`{name, from, to}`).
3. **App update** (any machine with a `source`) — delegate to the `source`
   updater on top of the OS update. **One snapshot guards both**: when the
   fleet took a snapshot, it calls the source's `safeUpdate` with
   `{ snapshot: false }`, so the updater takes no snapshot of its own (an
   unguarded machine calls it with no arguments). A community-script source needs
   `@dmc/proxmox` >= 2026.10.01.1 for this. An updater that rejects the argument
   is retried once with no arguments and a `warn` is logged; such an updater may
   take its own extra, untracked snapshot. Any other failure of the source is not
   retried.
4. **Post-update health** — `healthyAfter` from the `health` checks (or
   reachability when none), with the `healthGraceSec` grace window. Then the
   outcome, **health first**, the same for every machine kind (VM, CT, bare
   metal):

   | After the update | Action | `outcome` |
   | ---------------- | ------ | --------- |
   | Unhealthy, has a snapshot, `rollbackOnFailure` (default) | Roll back through the same snapshotter | `rolled-back` |
   | Unhealthy, otherwise (`rollbackOnFailure: false`, or no snapshot guard) | Keep the machine as-is | `failed` |
   | Healthy, but the upgrade command failed | No rollback | `failed` |
   | Healthy | Keep | `updated` / `no-change` |

   An unhealthy machine is rolled back whatever the upgrade's exit code. The
   snapshot record is written in every case — also after a rollback, because a
   rollback reverts to the snapshot but does not delete it. `pruneSnapshots`
   deletes it later (only once it is health-confirmed).
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
| `host-retired` | `policy` | `clearRetired` | The `host` argument is **not** in `globalArguments.machines` (the opposite of `host-in-fleet`). Without a `host`, it passes. |
| `snapshot-target-resolves` | `live` | `safeOsUpdate`, `rollback`, `pruneSnapshots` | The machine's snapshotter answers a list: your `snapshotter`'s `listSnapshots`, or the VM/CT location resolves and its Proxmox node answers. For `rollback`, a snapshot also exists (the named one, if you pass `snapshot`). A machine with no `snapshotter`, `vm` or `ct` passes. |

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

### Retired machines and `clearRetired`

A *retired machine* is a host that has stored records but is not in
`globalArguments.machines`. The `inventory` record never expires, so a machine
that you remove from the fleet would otherwise stay in the reports for ever, with
frozen numbers.

The reports handle this for you:

- `@dmc/patch-status` counts **current machines only** in the node table and in
  all totals (updates, security, dist-upgrade, reboot, LXC apps, container
  images, retained snapshots and images). A section **Retired machines** lists
  each retired host with `Last scanned`, `Records` (all stored records of the
  host) and `Active retention` (active snapshot and image records). The section
  does not appear when there are no retired hosts.
- `@dmc/patch-history` gives detail sections to current machines only. Its
  **Retired machines** section shows the last status line and the run history
  (collapsed) of each retired host, until you clear it.
- If `globalArguments.machines` is missing or empty, the reports show every host
  and have no Retired section. A broken context never hides the whole fleet.
- An LXC app (community-script `updateCheck`) whose name matches a retired host
  is left out of the LXC totals.

`clearRetired` removes the records:

| Argument | Default | Meaning |
| -------- | ------- | ------- |
| `host` | all retired hosts | Clear one retired host only. |
| `dryRun` | **`true`** | Only report what would happen. Nothing is deleted. |
| `keepHistory` | `false` | Keep the `run` records and the **pruned** snapshot/image records. Delete only the status records, so the host leaves `patch-status` but its history stays under Retired in `patch-history`. |
| `force` | `false` | Also delete **active** snapshot and image records. |

What it does for each retired host:

- Status records (`inventory`, last `update`, `osUpdate` and `reboot` results):
  deleted.
- `run` records and pruned snapshot/image records: deleted, unless `keepHistory`.
- **Active** snapshot and image records: kept, with a reason, unless `force`.
  They track snapshots and images that can still exist on the Proxmox node or on
  the docker host. If you delete the record, the real snapshot or image has no
  record any more. Prune them first, or use `force` when you know they are gone.
- Never touched: `prune-*` and `report-*` records, `seed`, and every record of
  another host. A host is matched by its exact name (`node` never matches `node2`).

Safety:

- `dryRun` deletes nothing. It writes a `prune` record
  (`prune-retired-<timestamp>`, kind `retired`, `dryRun: true`) that lists
  exactly what a real run would delete (`pruned`) and keep (`kept`, with reasons).
  `@dmc/patch-prune-history` shows it.
- If you pass `host` and the host is in the fleet, or has no records, the method
  stops with an error and deletes nothing.
- The pre-flight check `host-retired` (label `policy`) fails the run before it
  starts when `host` is in the fleet. Skip it with `--skip-check host-retired`.
  (`host-in-fleet` does not apply to `clearRetired`; it would mean the opposite.)
- If `globalArguments.machines` is empty, the method refuses to run, because every
  host would look retired.

Example: preview first, then delete.

```bash
# 1. Preview: nothing is deleted
swamp model method run fleet clearRetired

# 2. Read the prune record, then delete for real
swamp model method run fleet clearRetired --input dryRun=false

# One host only, and keep its run history
swamp model method run fleet clearRetired --input host=old-host --input keepHistory=true --input dryRun=false
```

---

## Resources (data)

All are versioned model data (`swamp data list fleet`, `swamp data query`).

| Spec | Written by | Contents |
| ---- | ---------- | -------- |
| `inventory` | scan / safeOsUpdate | Per-host OS status, docker engine + image drift, reachMethod, **health** verdict. Keyed by host (latest = current). |
| `run` | every mutating method | Append-only audit row (`run-<action>-<host>-<ts>`): action, outcome, before/after counts, **package** and **image** diffs, snapshot, rolledBack, needsReboot. |
| `snapshot` | safeOsUpdate | Lifecycle of a retained snapshot (`snapshotter` that took it, `kind` vm/ct/model, retainUntil, healthConfirmed, rebootConfirmed, status). |
| `image` | safeUpdate | A retained previous docker image (rollback point) with a retention window. |
| `osUpdate` / `update` / `reboot` | the respective method | Latest result per host for that operation. |
| `prune` | pruneSnapshots / pruneImages / clearRetired | What each prune run retired vs kept (and why). Kind `retired` = records deleted by `clearRetired`. |
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
  **Reboot required** sections. Current machines only; hosts that left the fleet
  appear under **Retired machines**.
- **`@dmc/patch-history`** — per-host detail: current status (OS, location, app,
  docker, health) followed by that host's **run history** with collapsible
  package / image `from → to` diffs. Every current host gets a section, even with
  no runs. Retired hosts get a **Retired machines** block with their last status
  and run history.
- **`@dmc/patch-prune-history`** — chronological snapshot/image prune runs
  (retired vs kept, with reasons), including `clearRetired` runs.

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
   Each snapshot is deleted by the snapshotter that took it.
4. `rollback` reverts a host to its retained snapshot when you decide to, through
   the snapshotter that took it.

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

# 7. After you remove a machine from the fleet: preview, then clear its records
swamp model method run fleet clearRetired
swamp model method run fleet clearRetired --input dryRun=false
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
- **One snapshot guards the OS and the app** — the fleet's guarding snapshot. The
  app step calls the updater with `snapshot: false` (a community-script updater
  needs `@dmc/proxmox` >= 2026.10.01.1; an updater that rejects the argument takes
  its own extra snapshot and a `warn` is logged).
- **Snapshot, rollback and cleanup are one contract.** Only the implementation
  that took a snapshot can roll it back or delete it, so the `snapshot` record
  stores its snapshotter and `rollback` / `pruneSnapshots` dispatch from the
  record. Changing a machine's `snapshotter` never orphans its older snapshots.
- **Both extension points are reached by name, never by type**, so a consumer
  adds an updater or snapshotter in their own repo without upstreaming it.
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
