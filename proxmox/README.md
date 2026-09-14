# @dmc/proxmox

Proxmox VE extensions for swamp — VM/LXC lifecycle operations and cloud image
storage management. Extends the `@keeb/proxmox` family with methods for
provisioning VMs from cloud images, snapshotting, disk and node migration, and
LXC container control.

## Models

### `@dmc/proxmox/storage`

Downloads cloud images directly into Proxmox storage via the Proxmox
download-url API. Proxmox fetches the image server-side — no local bandwidth
required. The resulting `storageRef` can be passed directly to
`createFromImage`.

**Global arguments:** `apiUrl`, `node`, `storage`, `skipTlsVerify`, and auth
(`ticket`/`csrfToken` or `username`/`password`/`realm`).

**Checks:**

- `storage-target-exists` (`live`) — verifies the target storage exists and is
  active on the node before `downloadImage` runs

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

Because the Proxmox API cannot run a command _inside_ an LXC, this model reaches
the hypervisor node's shell through a
[`@swamp/ssh`](https://swamp.club/extensions/@swamp/ssh) instance (named by
`sshModel`, default `infra-ssh`) rather than opening its own connection — it
shells out to `swamp model method run <sshModel> exec`. This requires the
`swamp` binary on PATH (override with `SWAMP_BIN`) and a configured `@swamp/ssh`
instance whose host list includes the PVE node.

**Key global arguments:** `node` (PVE host), `ctid` (LXC id), `service` (systemd
unit to health-check), optional `versionCommand` /`releaseApiUrl` (enable update
detection), optional `healthUrl` (end-to-end HTTP readiness probe).

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
  Refuses to run on an already-unhealthy container unless `force: true`.
- `rollback` — roll back to a named snapshot, or the most recent `preupdate-*`
  one

### `@keeb/proxmox/vm` extension

Extends `@keeb/proxmox/vm`, the base QEMU VM model from `@keeb/proxmox`, with
provisioning, snapshot, disk/node migration, and LXC container control.

**VM provisioning:**

- `createFromImage` — create a VM by importing a cloud image disk, attaching a
  cloud-init drive, and configuring user/keys/IP in one step
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
    is part of a multi-node cluster before migrating. Checks only see global
    connection args, not per-call arguments, so this cannot validate the
    specific `target` node name or that it shares storage with the VM — those
    failures still surface from the Proxmox API call itself.

**LXC lifecycle:**

- `lxcStop` — stop an LXC container (idempotent)
- `lxcStart` — start an LXC container (idempotent)

**Inspection:**

- `getConfig` — read raw config for a QEMU VM or LXC container

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
```

### Provision a new community-scripts LXC (headless)

```bash
# Configure the instance: app slug + the ctid you want + provisioning vars
swamp model create @dmc/proxmox/community-script my-forgejo \
  --global-arg node=fort --global-arg ctid=610 \
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

## Requirements

- [`@keeb/proxmox`](https://swamp.club/extensions/@keeb/proxmox) installed and
  configured
- Proxmox VE 7+ (download-url API required for `@dmc/proxmox/storage`)
- Auth via ticket/CSRF token (from `@keeb/proxmox/node` `auth` method) or
  `username`/`password` global args
- For `@dmc/proxmox/community-script`:
  [`@swamp/ssh`](https://swamp.club/extensions/@swamp/ssh) installed with an
  instance reaching the PVE node, the `swamp` binary on PATH, and an LXC created
  by the Proxmox VE community-scripts project

## License

MIT
