# @dmc/proxmox

Proxmox VE extensions for swamp, with API-token auth: node status and guest
discovery, VM snapshot guarding, full QEMU VM and LXC lifecycle (provisioning
from cloud images, snapshots, disk and node migration, container control), cloud
image storage, and safe updates for community-scripts LXCs.

`@dmc/proxmox/node` and `@dmc/proxmox/vm` replace `@keeb/proxmox/node` and
`@keeb/proxmox/vm`. Since 2026.11.07.1 this package no longer extends
`@keeb/proxmox/vm` and takes API tokens only — see
[Upgrading to 2026.11.07.1](#upgrading-to-202611071) and
[Moving from @keeb/proxmox](#moving-from-keebproxmox).

## Models

### `@dmc/proxmox/node`

Node-level operations. The guest methods keep the names and shapes `@dmc/patch`
expects, so a `proxmoxNodes` / `proxmoxNode` entry can point at a definition of
this type.

- `status` — node memory, CPU and uptime (`status` resource).
- `clusterHealth` — judge one node (default: the configured `node`) from
  `/cluster/status`. The node is healthy when the cluster lists it online and,
  in a cluster, the cluster is quorate and lists as many nodes as it says it
  has. An unhealthy node is a result, not an error. A failed call, or an answer
  that does not parse, is an error. Needs `Sys.Audit` on `/` (see
  [A limited token for snapshots and health](#a-limited-token-for-snapshots-and-health)).
- `listGuests` — every VM and CT on the cluster with type, vmid, name, status,
  node and IPv4 (`guests` resource).
- `snapshotVm` / `rollbackVm` / `deleteVmSnapshot` / `listVmSnapshots`, and
  `snapshotCt` / `rollbackCt` / `deleteCtSnapshot` / `listCtSnapshots` — run the
  snapshot task and wait for it (`snapshot` resource, `snapshot-<vmid>`, with
  the guest's type and node). Each one first finds the guest in
  `/cluster/resources` and acts on the node the guest runs on now, so one model
  reaches every guest in the cluster, also after a migration. It stops before
  any change when the guest is not listed (it does not exist, or the token has
  no `VM.Audit` on it), is listed twice, or is the other kind (a CT id for a VM
  method). `rollbackCt` starts the CT again (Proxmox stops a CT to roll it
  back), which needs `VM.PowerMgmt`. Snapshot names must start with a letter and
  use letters, digits, `_` or `-`.
- `permissions` — read-only: the effective privileges of the calling token or
  user, or of another `userid`, optionally for one ACL `path`, with their
  propagate flags.
- `ensureSnapshotAccess` — make a least-privilege API token for snapshots and,
  optionally, cluster health. See
  [A limited token for snapshots and health](#a-limited-token-for-snapshots-and-health).

**Global arguments:** `apiUrl`, `node`, `skipTlsVerify`, `caCert`, and auth (see
[Authentication](#authentication) and [TLS](#tls)).

**Checks:** `valid-connection` (policy), `node-reachable` (live). The
`node-reachable` check reads `/version`, which every valid token can read, so a
limited token passes it.

### `@dmc/proxmox/vm`

QEMU VM (and LXC) lifecycle: `lookup`, `start`, `stop`, `create`, `delete`,
`setBootOrder`, `setConfig`, `sync` (adapted from `@keeb/proxmox`, MIT; no
`spiceConnect`), plus every method and check listed under
[the VM/LXC methods](#vmlxc-methods) below.

**Global arguments:** `apiUrl`, `node`, `skipTlsVerify`, `caCert`, and auth (see
[Authentication](#authentication) and [TLS](#tls)).

Each method description lists the Proxmox privileges it needs.

### `@dmc/proxmox/storage`

Downloads cloud images directly into Proxmox storage via the Proxmox
download-url API. Proxmox fetches the image server-side — no local bandwidth
required. The resulting `storageRef` can be passed directly to
`createFromImage`.

**Global arguments:** `apiUrl`, `node`, `storage`, `skipTlsVerify`, `caCert`,
and auth (`tokenId`/`tokenSecret` — see [Authentication](#authentication) and
[TLS](#tls)).

**Checks:**

- `storage-target-exists` (`live`) — verifies the target storage exists and is
  active on the node before `downloadImage` runs (skip with
  `--skip-check storage-target-exists`)

**Methods:**

- `downloadImage` — fetch a cloud image URL into Proxmox storage and record its
  `volid` for use in `import-from`. Idempotent: skips the download and reuses
  the existing `volid` if a file with the same name is already in storage.

### `@dmc/proxmox/community-script`

Safely updates a Proxmox VE
[community-scripts](https://community-scripts.github.io/ProxmoxVE/) LXC
container: snapshot the container, run its in-container `update` helper
(forced-silent, so it never prompts), validate that the app comes back healthy,
and **roll back to the snapshot automatically** if it does not. One model
instance == one container.

The Proxmox API cannot run a command _inside_ an LXC, so this model runs its
commands through a [`@swamp/ssh`](https://swamp.club/extensions/@swamp/ssh)
instance (named by `sshModel`, required) and does not open its own connection —
it shells out to `swamp model method run <sshModel> exec`. This requires the
`swamp` binary on PATH (override with `SWAMP_BIN`). `reach` sets which host that
instance connects to:

- `reach: pct` (default) — the ssh instance reaches the PVE node (`node`), and
  every command runs as root through `pct exec`. The ssh instance's host list
  must include the node.
- `reach: ssh` — the ssh instance reaches the container itself (`ctHost`) as a
  non-root login. Health, version and package probes run as that login. The
  update runs as one exact argv through `sudo -n`, so one sudoers entry can
  grant it (see `privileges`). Snapshots, rollbacks and deletes go only through
  `nodeModel`, a `@dmc/proxmox/node` model with a limited snapshot token (see
  [A limited token for snapshots and health](#a-limited-token-for-snapshots-and-health)).
  Without `nodeModel`, a step that needs a snapshot stops before it runs a
  command. `install` needs `reach: pct`.

With `reach: ssh`, `updateCommand` is not run by a shell. It must have the form
`[NAME=value ...] /absolute/bin [args]` (values use `A-Za-z0-9._/:=+-`), and env
pairs go through `env`. The default, `PHS_SILENT=1 /usr/bin/update`, becomes
`sudo -n env PHS_SILENT=1 /usr/bin/update`.

`nodeModel` also works with `reach: pct`. Snapshots then go through the API in
place of `pct snapshot`.

**Key global arguments:** `node` (PVE host), `ctid` (LXC id), `service` (systemd
unit to health-check; `serviceActiveCommand` for OpenRC), `reach`, `ctHost` and
`nodeModel` (see above), optional `versionCommand` /`releaseApiUrl` (enable
update detection), optional `healthUrl` (end-to-end HTTP readiness probe).

**Methods:**

- `install` — provision a **new** community-scripts LXC headlessly at `ctid`
  (`PHS_SILENT=1 mode=default`, `var_ctid` pinned, `installVars` as env), then
  verify it comes up healthy. **LXC only** — community-scripts VM (`vm/*.sh`)
  scripts are interactive-only, so use `@dmc/proxmox/vm` `createFromImage` for
  VMs.
- `previewInstall` — read-only: inspect the app's `ct/<app>.sh` +
  `install/<app>-install.sh` and summarize what installing it will do
  (provisioning defaults, narrated steps, packages, release downloads, services,
  exposed port) — run before `install`. `install` also records this summary in
  its log.
- `discoverApp` — read-only: parse the app's `ct/<app>.sh` for its default
  `var_*` settings and `build.func` for the recognized `var_*` names + a `vars`
  array of `{name, default, description, group}` (descriptions/groups parsed
  from build.func's `default.vars` template; `null` where the source documents
  none) — to help compose `installVars`
- `status` — report running state, service health, version, snapshots, and (when
  `releaseApiUrl` is set) whether an update is available
- `checkUpdate` — read-only: compare the installed version against the latest
  upstream release tag; sets `updateAvailable`
- `safeUpdate` — snapshot → update → validate → auto-rollback on failure.
  Refuses to run on an already-unhealthy container unless `force: true`. With
  `reach: ssh`, two more checks run before the snapshot, as the login and
  without root:
  - The update's bin must start with `#!` or be an ELF file. The
    community-scripts `/usr/bin/update` can have no `#!` line, and busybox `env`
    on musl (Alpine) cannot run such a file ("Exec format error"). The error
    gives the fix.
  - Each http(s) URL that the update script fetches (on `curl` and `wget` lines,
    with `$NAME`, `${NAME}` and `${NAME:-default}` expanded from the script's
    own literal assignments) must answer 2xx from `ctHost`. The check refuses a
    script it cannot read or that is over 64 KiB, a URL with unsafe characters,
    more than 8 URLs, a missing `curl`, and output it cannot parse. A URL that
    it cannot resolve is logged as not checked.

  With either reach, the update output is also checked. A `curl: (NN)` line, or
  the helper saying that the app script was removed or that no update script
  exists, is a failed update even when the update exits 0. The run then rolls
  back (or, with `snapshot: false`, records `failed`), because an empty script
  that "succeeds" is not an up-to-date app. Arguments:
  - `force` (default `false`) — proceed even if the container is unhealthy
    before the update.
  - `keepSnapshot` (default `true`) — keep the `preupdate-*` snapshot after a
    successful update; `false` deletes it. Ignored when `snapshot` is `false`.
  - `snapshot` (default `true`) — `false` takes no snapshot and never rolls
    back. Use it when the caller already holds its own snapshot and owns the
    rollback (for example `@dmc/patch` `safeOsUpdate` snapshots before the OS
    upgrade, so a second untracked `preupdate-*` snapshot only piles up on the
    node). The baseline health gate, the update, and the post-update health
    check still run. If the app is unhealthy afterwards, the method records
    `outcome: "failed"` (`snapshot: null`, `snapshotTaken: false`,
    `rolledBack: false`) and throws, so the caller can roll back.
- `rollback` — roll back to a named snapshot, or the most recent `preupdate-*`
  one
- `privileges` — read-only, runs nothing: declares the root commands that the
  update needs, for the `@dmc/patch` plug-in contract. With `reach: ssh` it
  declares the one `sudo` argv, with `remoteCode: true` and
  `remoteSources: ["community-scripts/ProxmoxVE@main", "community-scripts/core@main"]`
  (the helper fetches and runs code from both repositories as root). With
  `reach: pct` it refuses: `pct` runs every command as root on the node, and no
  sudo grant can limit that.

**Pre-flight checks** (run before the mutating methods; `status`, `discoverApp`,
`previewInstall` and `checkUpdate` have none):

| Check                 | Label    | Methods                             | Verifies                                                                                                                                                                                   |
| --------------------- | -------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `manage-args-present` | `policy` | `install`, `safeUpdate`, `rollback` | `node`, `ctid` and `service` are set                                                                                                                                                       |
| `install-app-present` | `policy` | `install`                           | `app` is set                                                                                                                                                                               |
| `reach-ssh-ready`     | `policy` | `install`, `safeUpdate`, `rollback` | with `reach: ssh`: `updateCommand` is an exact argv that sudo can grant, a `nodeModel` is set when the method needs a snapshot, and the method is not `install` (passes with `reach: pct`) |
| `node-reachable`      | `live`   | `install`, `safeUpdate`, `rollback` | `reach: pct`: the node answers over the ssh model and has `pct`. `reach: ssh` with a `nodeModel`: the node model lists the CT's snapshots                                                  |
| `ctid-free`           | `live`   | `install`                           | no container or VM uses the ctid in the cluster (passes with `force=true`)                                                                                                                 |
| `container-exists`    | `live`   | `safeUpdate`                        | `reach: pct`: `pct status` answers for the ctid. `reach: ssh`: the container answers over ssh on `ctHost`. The app need not be healthy                                                     |
| `snapshot-available`  | `live`   | `rollback`                          | the named snapshot, or at least one `preupdate-*` snapshot, exists                                                                                                                         |

The `rollback` checks never need the container to be running or healthy: a
broken container is the reason to roll back. Skip checks with
`--skip-check <name>`, `--skip-check-label <policy|live>` or `--skip-checks`.

`install-app-present`, `ctid-free` and `snapshot-available` test a precondition
of one specific method that a managed container normally fails (its ctid is
taken, it has no `app`, it may have no retained snapshot). They are evaluated
only when their method is selected — a real run, or
`swamp model validate <name> --method <method>` — and pass under a plain
`swamp model validate <name>`.

### VM/LXC methods

Provisioning, snapshot, disk/node migration, and LXC container control. These
are methods of `@dmc/proxmox/vm`.

**VM provisioning:**

- `createFromImage` — create a VM by importing a cloud image disk, attaching a
  cloud-init drive, and configuring user/keys/IP in one step. The disk is
  `virtio0` and the NIC is `virtio`. Every hardware setting is an input with a
  default — nothing is fixed in code:

  | Input           | Default                 | Notes                                                                                                                                     |
  | --------------- | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
  | `memory`        | `2048`                  | MB                                                                                                                                        |
  | `cores`         | `2`                     |                                                                                                                                           |
  | `sockets`       | `1`                     |                                                                                                                                           |
  | `cpu`           | `Broadwell-noTSX`       | QEMU CPU model. `-noTSX` runs on hosts without TSX and can live-migrate between them; use `Broadwell` only if every possible host has TSX |
  | `ostype`        | `l26`                   | Proxmox guest OS type                                                                                                                     |
  | `agent`         | `true`                  | QEMU guest agent (`start` waits for its IP)                                                                                               |
  | `serialConsole` | `true`                  | adds `serial0: socket`; cloud images log boot output there                                                                                |
  | `diskOptions`   | `iothread=1,discard=on` | extra options for `virtio0`                                                                                                               |
  | `diskSize`      | the image's size        | GiB. `import-from` copies the image at its own size; when set, the disk grows to this size before the first boot. Cannot shrink.          |
  | `networkBridge` | `vmbr0`                 |                                                                                                                                           |
  | `ipConfig`      | `ip=dhcp`               |                                                                                                                                           |

  If a step after the VM is created fails (the disk resize or cloud-init),
  `createFromImage` deletes that new, never-started VM with its disks, so a
  re-run is not blocked by `vmid-free`. The error says whether the removal
  worked; if it did not, delete the VM before re-running.

- `configureCloudInit` — update cloud-init settings on an existing VM

**Snapshots:**

- `snapshot` — create a named VM snapshot
- `deleteSnapshot` — delete a named VM snapshot
- `listSnapshots` — list all snapshots for a VM

**Disk management:**

- `moveDisk` — migrate a VM disk to a different storage pool
- `lxcMoveVolume` — migrate an LXC volume (rootfs or mount point) to a different
  storage pool

**Node migration:**

- `migrate` — live-migrate a VM to another Proxmox node over shared storage
  (state transfer only, no disk copy); accepts an optional `sourceNode` override
  when the VM has already moved off the model's default node
  - pre-flight check `cluster-has-migration-target` (`live`) — verifies the node
    is part of a multi-node cluster before migrating. It does not validate the
    specific `target` node name or that it shares storage with the VM — those
    failures still surface from the Proxmox API call itself.

**LXC lifecycle:**

- `lxcStop` — stop an LXC container (idempotent)
- `lxcStart` — start an LXC container (idempotent)

**Inspection:**

- `getConfig` — read raw config for a QEMU VM or LXC container

**Pre-flight checks** (`listSnapshots` and `getConfig` are read-only and have
none). Checks read the raw per-call args from swamp's `unresolvedMethodArgs`; if
an arg is absent or still an unresolved expression, the check passes and the
method's own validation decides.

| Check                          | Label    | Methods                                                                                                           | Verifies                                                      |
| ------------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `guest-exists`                 | `live`   | `configureCloudInit`, `snapshot`, `deleteSnapshot`, `moveDisk`, `migrate`, `lxcStop`, `lxcStart`, `lxcMoveVolume` | the VM or LXC exists on the node (`sourceNode` for `migrate`) |
| `vmid-free`                    | `live`   | `createFromImage`                                                                                                 | an explicit `vmid` is unused in the cluster                   |
| `target-storage-exists`        | `live`   | `createFromImage`, `moveDisk`, `lxcMoveVolume`                                                                    | the target storage exists and is active on the node           |
| `disk-size-fits-image`         | `live`   | `createFromImage`                                                                                                 | `diskSize` is not smaller than the image's virtual size       |
| `snapshot-name-valid`          | `policy` | `snapshot`                                                                                                        | the name follows the Proxmox rule and is not `current`        |
| `snapshot-name-free`           | `live`   | `snapshot`                                                                                                        | the VM has no snapshot with this name                         |
| `snapshot-exists`              | `live`   | `deleteSnapshot`                                                                                                  | the snapshot to delete exists                                 |
| `cluster-has-migration-target` | `live`   | `migrate`                                                                                                         | the node is in a multi-node cluster                           |

Skip checks with `--skip-check <name>`, `--skip-check-label <policy|live>` or
`--skip-checks`. `vmid-free`, `disk-size-fits-image` and
`cluster-has-migration-target` are evaluated only when their method is selected
(a real run or `validate --method`); a plain `swamp model validate <name>`
passes them, since an existing VM's own vmid is taken and a standalone node has
no migration target.

## Usage

### Provision a VM from a Rocky Linux cloud image

```yaml
steps:
  - name: download-image
    model: proxmox-storage
    method: downloadImage
    args:
      url: https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2
      filename: Rocky-9-GenericCloud-Base.latest.x86_64.qcow2

  - name: create-vm
    model: my-proxmox-vm
    method: createFromImage
    args:
      vmName: my-rocky-vm
      importFrom: ${{ data.latest("proxmox-storage", "Rocky-9-GenericCloud-Base.latest.x86_64.qcow2").attributes.storageRef }}
      diskStorage: local-lvm
      diskSize: 32
      ciUser: rocky
      sshKeys: ${{ vault.my-keys.SSH_PUBLIC_KEY }}
```

### Snapshot before a risky change

```bash
swamp model method run my-proxmox-vm snapshot \
  --snapname pre_upgrade \
  --description "Before kernel upgrade"

# ... make changes ...

swamp model method run my-proxmox-vm deleteSnapshot \
  --snapname pre_upgrade
```

### Move an LXC container's rootfs to a different storage pool

```bash
swamp model method run my-proxmox-vm lxcStop --ctName my-container
swamp model method run my-proxmox-vm lxcMoveVolume \
  --ctName my-container \
  --volume rootfs \
  --targetStorage fast-ssd
swamp model method run my-proxmox-vm lxcStart --ctName my-container
```

### Safely update a community-scripts LXC (snapshot + auto-rollback)

```bash
# Detect first (read-only)
swamp model method run forgejo checkUpdate
# { installedVersion: "15.0.0", latestVersion: "16.0.4", updateAvailable: true }

# Snapshot → update → validate → roll back if it comes back unhealthy
swamp model method run forgejo safeUpdate

# Caller already holds its own snapshot and owns the rollback: take none here
swamp model method run forgejo safeUpdate --input snapshot:json=false
```

### Provision a new community-scripts LXC (headless)

```bash
# Configure the instance: app slug + the ctid you want + provisioning vars
swamp model create @dmc/proxmox/community-script my-forgejo \
  --global-arg sshModel=my-ssh --global-arg node=pve1 --global-arg ctid=610 \
  --global-arg app=forgejo --global-arg service=forgejo \
  --global-arg 'installVars={"var_cpu":"2","var_ram":"2048","var_disk":"10"}'

# Preview what the install will do BEFORE running it
swamp model method run my-forgejo previewInstall
# → summary: "Provisions a debian 13, unprivileged LXC, 2 CPU / 2048MB RAM / 10GB disk
#   and installs forgejo. Steps: …; Fetches: forgejo/forgejo (codeberg); Listens on port 3000."

# See which var_* you can override (optional)
swamp model method run my-forgejo discoverApp

# Create it (PHS_SILENT=1 mode=default, var_ctid pinned), then verify health
swamp model method run my-forgejo install
```

The community-scripts site shows customization as `var_*` env assignments
prefixed onto the standard script command, e.g.:

```
var_cpu="3" var_ram="1536" var_disk="8" var_os='debian' bash -c "$(curl -fsSL .../ct/valkey.sh)"
```

That maps 1:1 onto this model: the URL is always `<ctScriptBaseUrl>/ct/<app>.sh`
(so you give `app`, not a URL), and every `var_*` prefix goes into
`installVars`. `install` adds only the headless bits
(`PHS_SILENT=1 mode=default`) and `var_ctid` to pin the ID. Alpine, where a
script supports it, is just `installVars: {"var_os": "alpine"}` (the script then
applies its Alpine defaults).

## Authentication

Every API call goes through one auth layer (`lib/proxmox.ts`), and it takes an
API token only: `tokenId` (`user@realm!tokenname`) and `tokenSecret`. Requests
carry `Authorization: PVEAPIToken=<tokenId>=<tokenSecret>` and no CSRF token.
There is no login call, no 2-hour ticket expiry, and no ticket is stored as
data. A method or live check with no token, or a malformed one, fails before it
calls the API. Password and ticket login were removed in 2026.11.07.1.

Keep `tokenSecret` in a vault:

```yaml
globalArguments:
  tokenId: swamp@pve!automation
  tokenSecret: ${{ vault.get(infra, PROXMOX_TOKEN_SECRET) }}
```

Request headers (the token secret) and request bodies (for example cloud-init
passwords) go to curl in 0600 temp files (`-K` and `--data-binary @file`), so
they do not show on the command line. curl runs on the swamp host, not on the
node.

Token args are available on `@dmc/proxmox/node`, `@dmc/proxmox/vm` and
`@dmc/proxmox/storage`.

Live checks pass when the auth args are still unresolved `${{ }}` expressions
(as under `swamp model validate`); a method run resolves them and runs the
checks for real.

### TLS

Every API call sends the token to `apiUrl`, so verify the API certificate:

- **A publicly trusted certificate** (for example Tailscale Serve or a reverse
  proxy with a Let's Encrypt certificate in front of port 8006): set
  `skipTlsVerify: false`. curl then checks the certificate and the host name
  against the system roots.
- **The self-signed Proxmox certificate** (port 8006 directly): set `caCert` to
  the PEM CA that signs it (for a cluster, `/etc/pve/pve-root-ca.pem`). curl
  then gets `--cacert` and never `-k`, whatever `skipTlsVerify` says. Linux curl
  then trusts this CA only. Apple's `/usr/bin/curl` also keeps trusting the
  macOS system roots, so on macOS `caCert` is not an exclusive pin. A `caCert`
  that is not a PEM certificate bundle, or is still an unresolved expression,
  stops the call before curl runs.
- `skipTlsVerify: true` with no `caCert` turns all certificate checks off
  (`curl -k`). Anyone on the network path to the API can then read the token. It
  is the default only so that existing definitions keep working.

curl gets `-q` first, so a `~/.curlrc` on the swamp host cannot turn
verification off.

```yaml
globalArguments:
  apiUrl: https://pve1.example.net:8006/api2/json
  skipTlsVerify: false
  caCert: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
```

### A limited token for snapshots and health

`@dmc/patch` (or any automation that only snapshots guests) does not need an
admin token. `ensureSnapshotAccess` on a `@dmc/proxmox/node` model with an admin
token makes a token that may only audit, snapshot, roll back and power the
guests in one pool. With the default arguments (`role`, `auditRole`, `user`,
`tokenName` and `pool` change the names) it makes:

- role `SwampPatch` with exactly `VM.Audit`, `VM.PowerMgmt`, `VM.Snapshot` and
  `VM.Snapshot.Rollback` (`VM.PowerMgmt` because a CT rollback with start checks
  it);
- user `swamp-patch@pve`, pool `patch` with the `members` you list, ACLs on
  `/pool/patch` with propagate 0, and a privilege-separated token `patch`.

With `clusterAudit: true` it also adds role `SwampPatchAudit` with exactly
`Sys.Audit`, granted on `/` with propagate 0 to the user and the token, so the
token can run `clusterHealth`. `Sys.Audit` on `/` also reads cluster-level
status and configuration (HA status, cluster options, firewall rules, backup and
replication jobs). It gives no right on a node, guest, pool or storage path, and
no write.

It is a dry run by default (`dryRun: false` to write). It reads the roles,
users, ACLs, pools and guests, and the caller's own privileges, first. It writes
nothing when anything is off: a role with other privileges, a user in a group, a
token without privilege separation, any other grant for the user, token or role,
a propagated grant, a guest in another pool, or a missing caller privilege. It
creates only what is missing, and never changes or removes an existing object.
The new token secret is stored only as a sensitive output (vault key
`snapshot-token`), before any other step, and never in data, logs or errors. A
live run then checks that the token holds exactly the expected privileges on
each path.

```bash
# Plan (dry run), then apply
swamp model method run proxmox-admin ensureSnapshotAccess \
  --input clusterAudit=true --input 'members:json=[100,101,200]'
swamp model method run proxmox-admin ensureSnapshotAccess \
  --input clusterAudit=true --input 'members:json=[100,101,200]' \
  --input dryRun=false
```

Point a second `@dmc/proxmox/node` model at that token
(`tokenId: swamp-patch@pve!patch`), and use it as the `nodeModel` of a
community-script, or as a `@dmc/patch` snapshot or health-check model.

## Upgrading to 2026.11.07.1

This release has breaking changes for `@dmc/proxmox/node`, `@dmc/proxmox/vm` and
`@dmc/proxmox/storage`:

- **API tokens are the only auth.** The upgrade removes the `ticket`,
  `csrfToken`, `username`, `password` and `realm` global arguments from each
  definition. A definition that used them needs `tokenId` and `tokenSecret` (see
  [Authentication](#authentication) and
  [A limited token for snapshots and health](#a-limited-token-for-snapshots-and-health)).
  Until then its methods fail before they call the API.
- **The `@keeb/proxmox/vm` extension is removed.** Definitions of that type no
  longer get the VM/LXC methods from this package. Move them to
  `@dmc/proxmox/vm` (below).
- Old `auth` data that `@keeb/proxmox/node` wrote is no longer read. You can
  delete it with `swamp data` when nothing else uses it.

Set `skipTlsVerify: false` or `caCert` too, so the token is not sent to an
unverified server (see [TLS](#tls)).

## Moving from @keeb/proxmox

A definition can change type in place: keep its `id` and `name`, so
`data.latest("<name>", ...)` references keep resolving to the data it already
wrote.

1. Set `type: '@dmc/proxmox/vm'` (or `'@dmc/proxmox/node'`) and the current
   `typeVersion`.
2. Replace `ticket` / `csrfToken` (or `username` / `password`) with `tokenId` /
   `tokenSecret` vault references.
3. Drop workflow steps that only ran `@keeb/proxmox/node` `auth`.
4. For `@dmc/patch`, keep the node definition's name; `listGuests` and the VM
   snapshot methods are built into `@dmc/proxmox/node`.

## Requirements

- Proxmox VE 7+ (download-url API required for `@dmc/proxmox/storage`)
- `curl` on the swamp host (API calls run there)
- A Proxmox API token — see [Authentication](#authentication)
- For `@dmc/proxmox/community-script`:
  [`@swamp/ssh`](https://swamp.club/extensions/@swamp/ssh) installed with an
  instance reaching the PVE node (`reach: pct`) or the container (`reach: ssh`),
  the `swamp` binary on PATH, and an LXC created by the Proxmox VE
  community-scripts project

## License

MIT
