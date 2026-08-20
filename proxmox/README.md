# @dmc/proxmox

Proxmox VE extensions for swamp — VM/LXC lifecycle operations and cloud image
storage management. Extends the `@keeb/proxmox` family with methods for
provisioning VMs from cloud images, snapshotting, disk and node migration, and
LXC container control.

## Models

### `@dmc/proxmox/storage`

Downloads cloud images directly into Proxmox storage via the Proxmox
download-url API. Proxmox fetches the image server-side — no local bandwidth
required. The resulting `storageRef` can be passed directly to `createFromImage`.

**Global arguments:** `apiUrl`, `node`, `storage`, `skipTlsVerify`, and auth
(`ticket`/`csrfToken` or `username`/`password`/`realm`).

**Checks:**

- `storage-target-exists` (`live`) — verifies the target storage exists and is
  active on the node before `downloadImage` runs

**Methods:**

- `downloadImage` — fetch a cloud image URL into Proxmox storage and record its
  `volid` for use in `import-from`. Idempotent: skips the download and reuses
  the existing `volid` if a file with the same name is already in storage.

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
- `lxcMoveVolume` — migrate an LXC volume (rootfs or mount point) to a
  different storage pool

**Node migration:**

- `migrate` — live-migrate a VM to another Proxmox node over shared storage
  (state transfer only, no disk copy); accepts an optional `sourceNode`
  override when the VM has already moved off the model's default node
  - pre-flight check `cluster-has-migration-target` (`live`) — verifies the
    node is part of a multi-node cluster before migrating. Checks only see
    global connection args, not per-call arguments, so this cannot validate
    the specific `target` node name or that it shares storage with the VM —
    those failures still surface from the Proxmox API call itself.

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

## Requirements

- [`@keeb/proxmox`](https://swamp.club/extensions/@keeb/proxmox) installed and
  configured
- Proxmox VE 7+ (download-url API required for `@dmc/proxmox/storage`)
- Auth via ticket/CSRF token (from `@keeb/proxmox/node` `auth` method) or
  `username`/`password` global args

## License

MIT
