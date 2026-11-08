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
- [Secure patching (restricted access)](#secure-patching-restricted-access)
  - [The layers](#the-layers)
  - [Setup](#setup)
  - [Root commands (sudo)](#root-commands-sudo)
  - [OS update policy](#os-update-policy)
  - [Accepted risks](#accepted-risks)
  - [Auditing access](#auditing-access)
  - [Recommended setup](#recommended-setup)
  - [Upgrading from 2026.10.25.1 and earlier (breaking)](#upgrading-from-202610251-and-earlier-breaking)
- [Dependencies](#dependencies)
- [How `@dmc/patch` reaches other models](#how-dmcpatch-reaches-other-models)
- [The fleet model — `@dmc/patch/fleet`](#the-fleet-model--dmcpatchfleet)
  - [Machine decorations](#machine-decorations)
  - [Health checks](#health-checks)
- [Extending `@dmc/patch` — your own updater, snapshotter and OS updater](#extending-dmcpatch--your-own-updater-snapshotter-and-os-updater)
  - [Updater contract (`source`)](#updater-contract-source)
  - [Snapshotter contract (`snapshotter`)](#snapshotter-contract-snapshotter)
  - [OS updater contract (`osUpdater`)](#os-updater-contract-osupdater)
  - [Plug-in privileges (`privileges`)](#plug-in-privileges-privileges)
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
| **OS packages** | apt / dnf / apk / pacman inside the host or container | `@dmc/patch` (`ct` / `vm` / bare-metal path), or an `osUpdater` model ([your own](#os-updater-contract-osupdater)) |
| **App version** | a versioned app on the machine (e.g. Forgejo in a CT, a binary on a VM) | a `source` updater (e.g. `@dmc/proxmox/community-script`, or [your own](#extending-dmcpatch--your-own-updater-snapshotter-and-os-updater)) |
| **Docker images** | running compose containers | `@dmc/patch` (`docker` path) |

The three layers are complementary — an app updater bumps the app binary, but the
container's OS packages (`bash`, `curl`, `openssl`, …) still need patching, and
that's the fleet's job.

Everything an operation produces (what changed, snapshots taken, health verdicts,
prunes) is written as **versioned model data**, so reports and `swamp data query`
give a full, queryable history.

---

## Secure patching (restricted access)

A patch tool that logs in everywhere as root is the most valuable key in the
fleet. `@dmc/patch` is built so the key it uses for routine work is nearly
worthless to anyone who steals it:

- **Scans need no root and no sudo.** They run as an unprivileged login
  (`swamp-patch` by default) that can read package state and nothing more.
- **Every root command is an exact sudoers entry.** The upgrade, the reboot,
  the docker helper, and the commands a plug-in declares are each granted as one
  fixed argv. A stolen key can start the normal update or reboot, and cannot
  choose a command (see [Root commands](#root-commands-sudo)).
- **Root paths are opt-in, per machine, with a reason and an expiry.** Root over
  ssh, `pct exec` into a container, and similar shortcuts are refused unless the
  machine carries an *acceptance record* (see [Accepted risks](#accepted-risks)).
  There is never a silent fallback from a safe path to a root path.
- **The login that patches cannot change its own access.** A separate,
  root-capable ssh model provisions and audits the login; the patch login can
  never write its key, its sudoers file or its helpers.
- **Nothing logs in to the Proxmox nodes as root.** Container snapshots go
  through the Proxmox API with a token that can only audit, snapshot and roll
  back the guests in one pool. Node health comes from the cluster API too. The
  nodes get no root key and no helper for snapshots or health.
- **Access is audited.** `auditAccess` checks every host for over-permissive
  access and drift, and the `@dmc/patch-access` report lists every finding and
  every accepted risk.

### The layers

| Layer | What it does | Where |
| ----- | ------------ | ----- |
| One key, restricted | `authorized_keys` line with `from="<addresses>"`, `no-port-forwarding`, `no-agent-forwarding`, `no-X11-forwarding`, `no-pty`, `no-user-rc`. A copy of the key used from anywhere else is refused by sshd. | every host |
| Unprivileged login | system account with no password (shadow field `*`: no password matches, and sshd without PAM does not call the account locked), in no admin group (`docker`, `wheel`, `sudo`, `adm`, `lxd`, `disk`, `root` are removed). | every host |
| Root-owned key file | home, `~/.ssh` and `authorized_keys` are owned by root; the login cannot add a key or change its options. | every host |
| No sudo for scans | the collector never calls `sudo`. | every host |
| Exact sudo grants | `/etc/sudoers.d/swamp-patch` holds only the commands the machine's policy needs, each as one fixed argv (`Defaults env_reset, !setenv`). Each bin must be a root-owned file in a root-owned directory chain. | hosts that update, reboot or run docker updates |
| Docker helper | the login is not in `docker`; docker updates go through `swamp-patch-docker`, a root-owned helper with fixed subcommands that acts only on the compose projects in a root-owned list. | docker hosts |
| Host-side cache refresh | the host refreshes its own package metadata (`pve-daily-update`, `apt-daily` + `Update-Package-Lists`, `dnf-makecache`, an `apk` timer); the scan only reads and reports the cache age. Nothing is ever installed by the refresh. | every host |
| Privileged producer, unprivileged reader | a root timer writes the docker inventory to `/var/lib/swamp-patch/docker-inventory.json`; the scan only reads it. The login needs no docker access. | docker hosts |
| Fail-closed transport | containers are reached over ssh; `pct` needs `unsafe.pctExec`; a root login needs `unsafe.rootSsh`; an unreadable login is refused before any contact; the collector reports its real `uid`, and uid 0 without a record is a finding. | the fleet model |
| Limited API token | VM and CT snapshots use a privilege-separated Proxmox API token whose role holds only `VM.Audit`, `VM.PowerMgmt`, `VM.Snapshot` and `VM.Snapshot.Rollback`, granted on one pool. It cannot create, delete, reconfigure or open a console on any guest, and it has no rights on the nodes. For `proxmox-cluster` health checks it may also hold `Sys.Audit` on `/` alone, without propagation. | Proxmox cluster |
| Separate provisioning channel | `access.provisionSshModel` must differ from `sshModel`; only the access methods use it. | the fleet model |
| Audit | `auditAccess` probes each host as the patch login and as root and reports findings by severity. | the fleet model |

### Setup

**1. Make a key** for the patch login (ed25519 only) and keep the private key in
your vault. Only the host that runs the scans (for example a `swamp serve`
instance) needs it on disk.

```bash
ssh-keygen -t ed25519 -N '' -C swamp-patch -f ./swamp-patch
```

**2. Two `@swamp/ssh` models.** One for the patch login, one root-capable model
for provisioning (often the one you already have):

```yaml
# patch-ssh: the unprivileged login every scan uses
globalArguments:
  transport: { kind: ssh, user: swamp-patch, identityFile: /var/lib/swamp-serve/secrets/swamp-patch }
  hosts:
    - { name: web1,  address: 192.0.2.21 }
    - { name: node1, address: 192.0.2.11 }
    - { name: ct101, address: 192.0.2.31 }   # containers get their own ssh entry
    - { name: vps1,  address: 203.0.113.5 }  # a host outside your LAN: use an overlay address
```

**3. A Proxmox API token for snapshots** (Proxmox VMs and CTs only). Make a
role with only the snapshot privileges, a dedicated user, a privilege-separated
token, and a pool that holds the guests `@dmc/patch` may snapshot. The
`ensureSnapshotAccess` method of `@dmc/proxmox/node` does this through the API
(dry run first; the new token secret goes to your vault). To do it by hand, run
this once on any node as root:

```bash
pveum role add SwampPatch --privs "VM.Audit,VM.PowerMgmt,VM.Snapshot,VM.Snapshot.Rollback"
pveum user add swamp-patch@pve --comment "@dmc/patch snapshots"
pveum user token add swamp-patch@pve patch --privsep 1
pveum pool add patch --comment "guests @dmc/patch may snapshot"
pveum pool modify patch --vms 101,201,300
pveum acl modify /pool/patch --users swamp-patch@pve --roles SwampPatch --propagate 0
pveum acl modify /pool/patch --tokens 'swamp-patch@pve!patch' --roles SwampPatch --propagate 0

# Only for proxmox-cluster health checks (ensureSnapshotAccess clusterAudit=true):
pveum role add SwampPatchAudit --privs "Sys.Audit"
pveum acl modify / --users swamp-patch@pve --roles SwampPatchAudit --propagate 0
pveum acl modify / --tokens 'swamp-patch@pve!patch' --roles SwampPatchAudit --propagate 0
```

| Privilege | Used for |
| --------- | -------- |
| `VM.Audit` | finding the guest's node, listing its snapshots, the `snapshot-target-resolves` check |
| `VM.Snapshot` | taking and deleting the pre-update snapshot |
| `VM.Snapshot.Rollback` | rolling back (the API stops the CT and rolls it back) |
| `VM.PowerMgmt` | starting the CT again after the rollback (`start=1`; Proxmox checks it) |
| `Sys.Audit` on `/` (optional) | `proxmox-cluster` health checks: `/cluster/status` (node online, quorum) |

Reboots go over ssh inside the guest, not through the API. A
privilege-separated token gets the intersection of the user's and the token's
ACLs, so both lines are needed, and neither grants anything outside the pool
(or, for `Sys.Audit`, below `/`). Keep the token secret in your vault and give
it to a `@dmc/proxmox/node` model that only `@dmc/patch` uses. Verify the API
certificate, because each call sends the token: `skipTlsVerify: false` for a
publicly trusted certificate, or `caCert` for the self-signed Proxmox one (see
the `@dmc/proxmox` README):

```yaml
# patch-pve: the node model @dmc/patch snapshots through
type: "@dmc/proxmox/node"
globalArguments:
  apiUrl: https://192.0.2.11:8006
  node: node1                                  # any node; the guest's current node is looked up
  tokenId: swamp-patch@pve!patch
  tokenSecret: ${{ vault.get(my-vault, "proxmox-patch-token") }}
  skipTlsVerify: false
  caCert: ${{ vault.get(my-vault, "pve-root-ca") }}   # /etc/pve/pve-root-ca.pem
```

Add a guest to the pool when you add it to the fleet. A guest outside the pool
fails `snapshot-target-resolves`, so its update is refused, not run without a
snapshot.

**4. Add `access` to the fleet** and point `sshModel` at the patch login:

```yaml
globalArguments:
  sshModel: patch-ssh
  access:
    user: swamp-patch                         # default; never root
    publicKey: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI… swamp-patch
    from: [192.0.2.50]                        # the address the scans come from
    provisionSshModel: infra-ssh              # root-capable; used ONLY by the access methods
  machines:
    - host: web1
    - host: vps1
      from: [203.0.113.50]                    # this host sees the scanner's overlay address
    - host: node1                             # a Proxmox node: scanned only (see Recommended setup)
    - host: vm300
      vm: { proxmoxNode: patch-pve, vmid: 300 }
    - host: ct101
      ct: { nodeModel: patch-pve, ctid: 101 } # snapshots through the API token
```

**5. Provision, step by step.** Every access method except `auditAccess` is a dry
run unless you say otherwise:

```bash
swamp behavior run patch-fleet renderAccess                       # the plan as data; no host contact
swamp behavior run patch-fleet provisionAccess                    # dry run (default)
swamp behavior run patch-fleet provisionAccess --input dryRun=false --input 'hosts:json=["web1"]'
swamp behavior run patch-fleet auditAccess --input 'hosts:json=["web1"]'
swamp behavior run patch-fleet scan
swamp report get @dmc/patch-access --model patch-fleet --markdown
```

`provisionAccess` creates the account (or refuses with exit 3 to take over an
account it did not create — the account is bound to a random token kept in a
root-owned marker and in the account's GECOS field), sets its shadow field to
`*`, installs the restricted key line, strips admin groups, turns on the host's
metadata refresh, writes the [exact sudoers file](#root-commands-sudo) (or
removes it when the machine needs no root command), and, on docker hosts,
installs the docker inventory producer and its timer, the docker helper and its
project list. On an `auto` machine it configures the host's own updater (see
[OS update policy](#os-update-policy)). It refuses before changing anything when
`bash` is missing, when sudo is needed and missing (exit 5), when docker is
wanted without systemd, when a group with the account's name already exists
without the account, or when a sudoers file at its path was not written by
`@dmc/patch` (exit 4). `revokeAccess` removes all of it again. A host that is
skipped, refused or failed fails the run.

**6. Schedule** `scan` and `auditAccess` (see [Recommended setup](#recommended-setup)).

### Root commands (sudo)

The login is not root, so an upgrade, a reboot or a docker update needs sudo.
`provisionAccess` writes `/etc/sudoers.d/swamp-patch` with only the entries the
machine needs, each one an exact argv. The runtime builds its commands from the
same table, so what runs is what is allowed.

| Entry | Granted when | Command |
| ----- | ------------ | ------- |
| OS upgrade | `osUpdatePolicy: managed` and `os` on | `apt-get update -qq`, `env DEBIAN_FRONTEND=noninteractive apt-get -y upgrade` / `full-upgrade`; `dnf -y upgrade`; `apk upgrade`; `pacman -Syu --noconfirm` (the families the host has) |
| Reboot | every policy except `scan-only` | `systemd-run --on-active=3 --timer-property=AccuracySec=100ms systemctl reboot` |
| Docker helper | the machine has `docker` | `swamp-patch-docker` (subcommands `ps`, `inspect`, `update`, `restore`, `prune`) |
| Plug-in commands | a plugged model declares them | the argvs from its `privileges` method (see [Plug-in privileges](#plug-in-privileges-privileges)) |
| Privileged health checks | a `command` check with `privileged: true` and `unsafe.privilegedHealth` | the check's `argv` |

Rules that hold for every entry:

- Two `Defaults:swamp-patch` lines, `env_reset` and `!setenv`. Env values
  (such as `DEBIAN_FRONTEND`) are fixed arguments of `/usr/bin/env`, never
  `env_keep`.
- A command with no arguments ends in `""`, which sudo reads as exactly no
  arguments.
- Each bin must resolve to an absolute, root-owned, regular file that no group
  or other user can write, through a root-owned directory chain. A bin that
  fails the check is left out and listed in `sudoMissing`.
- The file is written to a temp name, must pass `visudo -cf`, and is moved into
  place. `visudo -c` must then pass, and an `includedir` line must load it, or
  the file is removed again (exit 6).

The docker helper is the gate for docker. It runs only as root, with a fixed
`PATH` and a cleared docker and compose environment. On every call it reads the
root-owned project list (`/etc/swamp-patch/docker-projects`), and one bad line
refuses the call. Project names come from that list only, image ids must be
sha256 hex, and a restore ref must be the image of one of the project's current
containers. `prune` never forces. A machine reached as root through `pct` keeps
the direct docker commands.

### OS update policy

`osUpdatePolicy` says what `@dmc/patch` may do to a machine's OS packages. Set a
fleet default in `globalArguments`, and override it per machine.

| Policy | OS upgrade (`safeOsUpdate`) | Reboot | Sudo entries |
| ------ | --------------------------- | ------ | ------------ |
| `managed` (default) | yes | yes | upgrade and reboot |
| `auto` | no: the host's own updater installs `osAutoScope` (`security`, the default, or `all`) | yes, health-checked | reboot |
| `scan-only` | no | no, also with `force` | none |

Both refusals happen in the method body, before any snapshot or connection, so
a skipped check cannot bypass them. `osAutoScope` on a machine whose policy is
not `auto` is a configuration error.

On an `auto` machine, `provisionAccess` configures the host's updater with
files of its own, and never edits the package's files:

- apt: `/etc/apt/apt.conf.d/52swamp-patch-auto` turns unattended upgrades on,
  sets `Automatic-Reboot "false"`, and replaces the origin lists with the
  `-security` suites (plus the base and `-updates` suites for `all`).
- dnf: `/etc/dnf/swamp-patch-automatic.conf` (`upgrade_type` security or
  default, `apply_updates yes`, `reboot never`) and a `dnf-automatic.service`
  drop-in that runs it.

It refuses (exit 5, before any change) a Proxmox node (it needs
`full-upgrade`), an apk or pacman host, and a host without the updater package
(it never installs packages). A `managed` machine gets the files removed again.
The audit reads the installed scope (`auto-scope-mismatch`) and reports an
`auto` host that does not install updates (`auto-install-off`).

**Changes made outside `@dmc/patch`.** An `auto` host installs its own updates,
and a person can upgrade any host by hand. The collector hashes the installed
package list in its one batched call (no extra call, no privilege, no list
stored). An inventory record whose hash differs from the last one `@dmc/patch`
saw has `packagesChangedOutsidePatch: true` and `lastOutsideChangeAt`, and the
status report lists the host. `safeOsUpdate` sets the baseline to the state it
leaves, so its own upgrade is not flagged. An unknown read gives `null`, never
`false`.

### Accepted risks

An unsafe path is enabled by an **acceptance record**, never by a boolean:

```yaml
- host: ct201
  ct: { nodeModel: patch-pve, proxmoxNode: node1, ctid: 201 }  # proxmoxNode: the ssh host for pct
  unsafe:
    pctExec:                                   # reach this container through pct (root in the CT)
      reason: sshd is not installed in this container yet
      acceptedBy: ops
      acceptedAt: "2026-10-30"
      reviewBy: "2027-01-31"                   # at most 365 days after acceptedAt
  trustRemote:                                 # an updater that runs code fetched at run time
    - source: community-scripts/ProxmoxVE@main # one record for each source it declares
      reason: the app's updater pulls its script from upstream main
      acceptedBy: ops
      acceptedAt: "2026-10-30"
      reviewBy: "2027-04-30"
    - source: community-scripts/core@main
      reason: the helper runs misc/update.sh and build.func from core main
      acceptedBy: ops
      acceptedAt: "2026-10-30"
      reviewBy: "2027-04-30"
  acceptedRisks:                               # an audit finding you decided to live with
    - finding: host-group:docker:deploy
      reason: the deploy user needs docker for the CI runner
      acceptedBy: ops
      acceptedAt: "2026-10-30"
      reviewBy: "2027-04-30"
```

| Record | Enables |
| ------ | ------- |
| `unsafe.pctExec` | reaching a container through `pct exec` on its node; it needs a root login on that node, so the node also needs `unsafe.rootSsh` |
| `unsafe.rootSsh` | an ssh login that is root (for that machine, or for the node of a `pct` container) |
| `unsafe.privilegedUpdater` | an app updater or `osUpdater` that does not declare its root commands (`privileges`); without it such a model is refused |
| `unsafe.privilegedHealth` | `command` health checks with `privileged: true` (an exact argv through `sudo -n`) |
| `trustRemote` | a plug-in that runs code it downloads at run time: one record for each source in its `remoteSources`, whatever `unsafe` says |
| `acceptedRisks` | moves one audit finding, by id, from *findings* to *accepted risks* (it keeps its severity) |

Every record needs a `reason` (10+ characters), `acceptedBy`, `acceptedAt` and a
`reviewBy` at most 365 days later. Accepted risks are **never silent**: the
report always shows them, a record past `reviewBy` is *overdue* (and a
`warning` finding), and a record that matches nothing any more is *stale*. Runs
record which acceptance records they used (`acceptedRisksUsed`).

### Auditing access

`auditAccess` runs two read-only probes per host: one as the patch login
(`id`, `sudo -n -l`, negative probes such as `sudo -n true` and `docker info`,
`test -w` on every managed file) and one as root through the provisioning model
(owners, modes and hashes of the managed files, the `authorized_keys` lines,
password lock, the account token, sudoers rules that name the login, root's
`authorized_keys`, group members, cache refresh and auto-install state, each
compose project directory). For each node model that a machine uses (for
snapshots or for a `proxmox-cluster` check), it also asks Proxmox for the
token's own effective permissions (`/access/permissions`), once per model.

**Sudo grants** are compared with what `provisionAccess` would write for that
machine: the table entries for its policy, the docker helper, and the declared
plug-in and privileged health-check commands. Any other line in our sudoers
file is `privilege-extra`; a rule for the login in another sudoers file is
`privilege-foreign`.

**The API token** may hold `VM.Audit`, `VM.PowerMgmt`, `VM.Snapshot` and
`VM.Snapshot.Rollback` on pools and guests. On `/` it may hold only `Sys.Audit`,
without propagation, and only when some machine's `proxmox-cluster` check uses
that node model. A machine whose own check uses the model must have it.

| Severity | Examples |
| -------- | -------- |
| critical | a sudo line beyond the required set (`privilege-extra`); `sudo -n true` succeeds (`privilege-unrestricted`); the login in `docker` / `wheel` / `sudo` / `lxd` / `disk` / `root`, or able to reach the docker socket; a writable key file or managed file; root accepts the key; the "patch login" is uid 0; the API token holds any other privilege, any other right on `/`, a propagated grant, or `Sys.Audit` on `/` with no `proxmox-cluster` check using it (`api-token-extra`) |
| high | key missing; an extra or unrestricted key line; a password set; the account not created by `@dmc/patch`; a managed file that drifted; the login in `adm`; a `from=` range broader than /24 (IPv4) or /64 (IPv6); a probe that did not run or did not parse (the error gives ssh's reason); sudo grants without both `Defaults` lines; a sudo rule from another file or from LDAP / sssd (`privilege-foreign`; critical when it says `ALL`); a compose directory that a non-root account can change (`compose-writable`) or that cannot be read; the API token lacks a privilege a machine needs (`api-token-missing`), or its answer cannot be read (`api-token-unread`) |
| warning | a required sudo entry missing (`privilege-missing`, naming what cannot run); the docker helper or inventory producer missing; cache refresh off; cache older than 48 h; host auto-install on a `managed` machine (`auto-install-conflict`), off on an `auto` machine, or with the wrong scope; a compose directory missing; an overdue acceptance record |
| info | other users in root-equivalent groups; a stale acceptance record |

`failOn` (default `high`) makes the run fail when a host has a finding at or
above that level — including a host that could not be probed, so an unknown
state never passes. The `@dmc/patch-access` report starts with flag lines
(`CRITICAL`, `HIGH`, `WARNING`, `ACCEPTED RISKS … overdue`, `NOT AUDITED`,
`STALE AUDIT`) and escapes every value that came from a host before it reaches
Markdown.

### Recommended setup

**Reach.** Give every machine, containers included, an ssh entry for the patch
login. Keep `unsafe.pctExec` for the short time a container has no sshd, with a
near `reviewBy`. Do not accept `unsafe.rootSsh` for routine scans. Snapshot
Proxmox guests through the API token (`vm.proxmoxNode` / `ct.nodeModel`), never
through a root login on the node.

**Network.** Set `from=` to the address the scans really arrive from. Behind
NAT a host only sees the shared public address, so reach hosts outside your LAN
over an overlay network (Tailscale, WireGuard) and put the scanner's overlay
address in `from=` — it belongs to one machine and does not change with DHCP.
Add a network rule that lets the scanner reach port 22 and little else.

**Host updates — let the hosts install security updates themselves.** For
general-purpose VMs and servers, set `osUpdatePolicy: auto` (with the default
`osAutoScope: security`). `provisionAccess` then turns on the distribution's
own automatic **security** updates (`unattended-upgrades` or `dnf-automatic`)
with automatic reboots **off** (see [OS update policy](#os-update-policy)).

`@dmc/patch` then does what the host cannot: it **tracks** what each host has
pending and installed, flags `needsReboot`, flags package changes it did not
make, and runs **health-checked reboots** in a window you choose. Packages
arrive within a day of release instead of waiting for a patch run, and the login
gets only the reboot entry.

Keep `@dmc/patch` in charge of the install (`osUpdatePolicy: managed`,
`safeOsUpdate`: snapshot → upgrade → health → rollback) where a bad update must
be reversible or the platform needs a full upgrade:

- hosts whose apps break on library updates, and anything you want snapshotted
  before every change,
- held-back / dist-upgrade packages and major OS upgrades on any host.

**Proxmox nodes — scan only.** Give the nodes `osUpdatePolicy: scan-only`. Let
`@dmc/patch` scan them as the patch login (no sudo entry at all) and patch them
by hand: migrate the guests away, run `apt full-upgrade` (Proxmox needs it;
`unattended-upgrades` only runs `upgrade`), reboot, migrate back. A tool that
can upgrade and reboot a hypervisor needs root on it, and an unplanned node
reboot takes every guest on the node with it. Check node health with
`service` checks (`pve-cluster`, `pvedaemon`, `pveproxy`) and a
[`proxmox-cluster`](#health-checks) check, which reads quorum and node state
from the cluster API and needs nothing on the node.

Docker images (`safeUpdate`) and app updaters (`source`) are a separate layer
and stay with `@dmc/patch` whatever the host does for its OS packages.

**Schedule.** `scan` daily; `auditAccess` daily or weekly with the default
`failOn: high`, so a scheduled run turns red on a new over-permissive grant or a
host that can no longer be probed; `@dmc/patch-access` reviewed weekly, renewing
or removing acceptance records before their `reviewBy`.

**Limits.** The login can read package lists and other world-readable files on
every host. Alpine needs `bash` installed before it can be provisioned. A host
that gets any sudo entry needs `sudo` installed first (`provisionAccess` never
installs packages). The docker inventory producer needs systemd (OpenRC hosts
are refused for docker). Private registry images show `updateAvailable: null`
(the producer has no registry credentials). `osUpdatePolicy: auto` supports apt
and dnf only.

### Upgrading from 2026.10.25.1 and earlier (breaking)

- **No ssh → pct fallback.** A container without an ssh entry is no longer
  scanned through `pct` when ssh fails. Give it an ssh entry, or add
  `unsafe.pctExec`.
- **CT snapshots use the Proxmox API.** Set `ct.nodeModel` to a node model with
  the [snapshot token](#setup). A CT without `nodeModel` is snapshotted with
  `pct` on its node only when it has `unsafe.pctExec` and the node login is
  root with `unsafe.rootSsh`; otherwise `snapshot-target-resolves` fails and
  `safeOsUpdate` is refused. `ct.proxmoxNode` (the ssh host) is now needed only
  for `pct`.
- **`vm.proxmoxNode` should name a snapshot-only node model.** It still accepts
  any node model, but `auditAccess` reports a token with more than the three
  snapshot privileges as `api-token-extra` (critical).
- **Node models are `@dmc/proxmox/node`.** `@dmc/patch` no longer depends on
  `@keeb/proxmox`. `@dmc/proxmox` 2026.11.07.1 takes API tokens only, so give
  each node model a `tokenId` and `tokenSecret`.
- **Root logins need `unsafe.rootSsh`.** `scan` reads each host's login from the
  ssh model before it connects and refuses root (and logins it cannot read).
  The new `restricted-transport` pre-flight check does the same for the other
  methods.
- **`reach: pct` needs `unsafe.pctExec`.** `import` no longer emits `reach: pct`.
- **The collector never uses sudo and never refreshes the cache.** A failed
  `dnf check-update` is reported as unknown (`null`), not 0. Inventories carry
  `schemaVersion` 4 with `cacheAgeHours`, `uid`, `dockerSource`,
  `acceptedRisksUsed`, `securityFindings` and the outside-change fields
  (`packagesHash`, `packagesBaseline`, `packagesChangedOutsidePatch`,
  `lastOutsideChangeAt`).
- **Updates and reboots need the sudoers file.** Run `provisionAccess` (dry run
  first) on every machine you update or reboot through the patch login. Docker
  hosts need `sudo` for the docker helper.
- **`osUpdatePolicy` defaults to `managed`**, which keeps the old behavior.
  `reboot` refuses a `scan-only` machine, also with `force`.
- **Plug-ins declare their root commands.** An app updater or `osUpdater` must
  answer `privileges({ host })`, or the machine needs `unsafe.privilegedUpdater`.
  A snapshotter must always answer. A plug-in that runs remote code needs one
  `trustRemote` record per source.
- **Health checks run as the login.** A `command` check that needs root must
  become `privileged: true` with an `argv` and `unsafe.privilegedHealth`. A
  Proxmox node check that ran `pvesh` should become a `proxmox-cluster` check.

---

## Dependencies

- **`@swamp/ssh`** (required) — the transport. The fleet takes an `sshModel`
  (an `@swamp/ssh` instance name, e.g. `my-ssh`) and reaches every host through
  its `exec` and `script` methods (see
  [How `@dmc/patch` reaches other models](#how-dmcpatch-reaches-other-models)).
  Consumers point `sshModel` at their own fleet.
- **`@dmc/proxmox/node`** (for Proxmox VMs and CTs) — the snapshot API
  (`snapshotVm` / `rollbackVm` / `listVmSnapshots` / `deleteVmSnapshot`,
  `snapshotCt` / `rollbackCt` / `listCtSnapshots` / `deleteCtSnapshot`,
  `clusterHealth` for `proxmox-cluster` health checks, and `permissions` for
  the audit), authenticated with the [snapshot token](#setup).
- **`@dmc/proxmox/community-script`** (optional, for CT app updates) — the
  `source` app updater referenced by a CT.

None of these is required for a mechanism you bring yourself: an app updater, a
snapshotter or an OS updater can be any model that implements the contract — see
[Extending `@dmc/patch`](#extending-dmcpatch--your-own-updater-snapshotter-and-os-updater).

---

## How `@dmc/patch` reaches other models

The fleet does no ssh or Proxmox work itself. It calls the methods of other
models: `<sshModel> exec` / `script`, the `vm.proxmoxNode` model
(`snapshotVm`, `rollbackVm`, `listVmSnapshots`, `deleteVmSnapshot`), the
`proxmoxNodes` models (`listGuests`, for `import`), the `source` updater
(`checkUpdate`, `safeUpdate`), the `snapshotter` model (`snapshot`,
`rollback`, `deleteSnapshot`, `listSnapshots`), and the `osUpdater` model
(`scanOs`, `upgradeOs`, `listPackages`). Updaters, snapshotters and OS updaters
are reached by instance name; their type does not matter.

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
| `host-reachable` | `<sshModel> exec` (`true` on the host, or `pct status <ctid>` on the node of a CT on the `pct` path) |
| `baseline-healthy` | `<sshModel> script` (the machine's batched health checks; on the node through `pct exec` for a CT on the `pct` path) |
| `snapshot-target-resolves` | `<snapshotter.model> listSnapshots` when a `snapshotter` is set; else `<vm.proxmoxNode> listVmSnapshots` for a VM, `<ct.nodeModel> listCtSnapshots` for a CT, or `<sshModel> exec` (`pct listsnapshot <ctid>` on the node) for a CT with `unsafe.pctExec` and no `nodeModel` |

- The model names come from the fleet's own `globalArguments` (`sshModel`,
  `machines[].vm.proxmoxNode`, `machines[].ct.nodeModel`,
  `machines[].snapshotter.model`). They are
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
      + machines with an osUpdater         one `scanOs` per machine (not in the collector calls)
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
  osUpdatePolicy: managed    # optional fleet default: managed | auto | scan-only
  osAutoScope: security      # optional, for auto: security | all
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
  reach: ssh | pct            # ssh (default); pct needs an unsafe.pctExec record; no fallback
  osUpdatePolicy: auto        # optional: overrides the fleet default (see OS update policy)

  # --- location (pick the one that applies) ---
  vm:                         # a Proxmox VM — snapshot-guarded OS update via the node model
    proxmoxNode: patch-pve    # a @dmc/proxmox/node model name (snapshot API, limited token)
    vmid: 300
  ct:                         # a Proxmox CT — reached over ssh, snapshot via the node model
    nodeModel: patch-pve      # a @dmc/proxmox/node model name (snapshot API, limited token)
    ctid: 701
    # proxmoxNode: node1      # ONLY with unsafe.pctExec: the ssh HOST that runs pct
  # (a plain host / VPS needs neither vm nor ct)

  # --- optional app updater on top of the OS lifecycle (any machine kind) ---
  source:
    type: community-script    # optional label for readers; the fleet does not read it
    model: my-app             # ANY model that implements the updater contract,
                              # e.g. a @dmc/proxmox/community-script instance

  # --- optional pluggable snapshot guard (overrides the built-in VM/CT snapshot) ---
  snapshotter:
    model: my-snapshots       # ANY model that implements the snapshotter contract

  # --- optional pluggable OS package layer (overrides the bundled collector + apt/dnf/apk/pacman) ---
  osUpdater:
    model: my-os-updater      # ANY model that implements the OS updater contract

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

- **`vm.proxmoxNode`** and **`ct.nodeModel`** are **node *model*** names (the
  snapshot API). **`ct.proxmoxNode`** is the **ssh *host*** that runs `pct`
  (e.g. `node1`), used only on the `unsafe.pctExec` path. They are different
  kinds of reference.
- A **plain CT** needs only `ct` and an ssh entry — it gets scan +
  OS-patch-with-capture + reboot, no `source` required.
- **`source`** is what triggers app-update delegation — *being a CT does not*. It
  works on every machine kind (VM, CT, bare metal), and the model can be any
  updater you write ([updater contract](#updater-contract-source)).
- **`snapshotter`** replaces the built-in snapshot guard (the VM / CT node
  model) with any model you write, and lets a bare-metal machine be
  snapshot-guarded ([snapshotter contract](#snapshotter-contract-snapshotter)).
- **`osUpdater`** replaces the bundled collector and the built-in
  apt/dnf/apk/pacman upgrade with any model you write
  ([OS updater contract](#os-updater-contract-osupdater)). Health checks and
  reboots still reach the machine over its ssh / `pct` transport.
- The deprecated **`proxmox: { model }`** is a legacy field that supplied both a
  CT's location and its app updater from one reference; still honoured as a
  fallback, but prefer `ct` + `source`.

### Health checks

`health` is an array of checks; the machine is **healthy only when every check
passes**. An empty/absent array falls back to reachability. Works on any machine —
the transport is chosen automatically (`http` and `proxmox-cluster` from the
swamp host; `service` / `command` via ssh or `pct`, as the patch login). All
`service` and `command` checks of one machine run in
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
    name: my-app                   # systemctl is-active, or OpenRC's rc-status (no root)
  - type: command
    label: self-check
    run: /usr/local/bin/my-app --selfcheck   # exit 0 = healthy; runs as the login
    timeoutSec: 30
  - type: command
    label: config valid            # needs root: an exact argv through sudo -n
    privileged: true               # needs unsafe.privilegedHealth on the machine
    argv: [/usr/sbin/nginx, -t]
  - type: proxmox-cluster          # a Proxmox node: online, cluster quorate
    label: node online, cluster quorate
    nodeModel: patch-pve           # a @dmc/proxmox/node model; node defaults to the host
```

- **`service`** reads systemd (`systemctl is-active`) or, on OpenRC, OpenRC's
  own state (`rc-status -a -f ini`: the exact name, state `started`). It does
  not run the init script, so it needs no root, and a crashed daemon is
  unhealthy. The name may use only `A-Za-z0-9@._:+-`.
- **`command` with `privileged: true`** runs `argv` (bin first) through
  `sudo -n`, by the absolute path found on the host. The argv follows the
  plug-in command rules (no shells, interpreters or command runners; arguments
  of letters, digits and `. _ / : = + -`). `provisionAccess` grants exactly that
  argv. Without the machine's `unsafe.privilegedHealth` record, `safeOsUpdate`
  and `reboot` refuse before any call, and the check fails with the reason.
- **`proxmox-cluster`** runs the node model's `clusterHealth` from the swamp
  host, with that model's API token. Nothing runs on the machine, and the login
  gets no secret. The token needs `Sys.Audit` on `/` (`ensureSnapshotAccess`
  with `clusterAudit`). The verdict fails closed: a failed run, no record or two
  records for the node, or a record that does not parse is unhealthy, and
  healthy needs the model's verdict and the facts behind it (listed, online,
  quorate in a cluster, no problem listed).

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
- **`rollback`** runs them after the snapshotter restores the machine. A
  rolled-back CT boots again, so it has the same grace window.

**Grace window (`healthGraceSec`).** A `docker-ce` upgrade restarts every
container, so a check made right after the update can read unhealthy for a good
update. `safeOsUpdate`, `reboot` and `rollback` take `healthGraceSec` (integer,
`>= 0`, default `120`). While the post-update (or post-reboot, post-rollback)
health is unhealthy, the
method checks again every 10 seconds, until the machine is healthy or
`healthGraceSec` seconds have passed. Each failed attempt is logged at `info`
with the failing check labels. `healthGraceSec: 0` checks exactly once. The
window applies to both the CT path and the VM / bare-metal path of
`safeOsUpdate`. It never applies to the `baseline-healthy` pre-flight check,
which is immediate. A machine with no health checks keeps the reachability
fallback, with no wait.

**Secrets:** a check runs as the patch login, and the login must not be able to
read secrets. Choose a check that needs no credential: a `service` state, an
`http` endpoint, or a command that only tests that the app answers. Do not give
the login read access to a credential file to make a check work.

**Deriving from a `source`:** a machine with a `source` and no explicit `health`
derives `[http(healthUrl), service(service)]` from the updater model's
`healthUrl` / `healthExpectStatus` / `service` globalArguments (a
community-script instance has them; your own updater may too), so existing setups
work without extra config, and you can override anytime.

---

## Extending `@dmc/patch` — your own updater, snapshotter and OS updater

`@dmc/patch` has three extension points. Each one is a **contract**: you name a
model instance on a machine, and the fleet calls that model's methods **by name**
(through `runModel`). The fleet never needs the model's type. So you can add your
own update or snapshot mechanism in your own repo, without changing or
upstreaming anything to `@dmc/patch`.

| Decoration | What it plugs in | Contract (methods your model exposes) |
| ---------- | ---------------- | ------------------------------------- |
| `source: { model }` | The app-update step, on top of the OS update | `checkUpdate`, `safeUpdate({ snapshot? })` |
| `snapshotter: { model }` | The snapshot guard: snapshot → rollback → cleanup | `snapshot`, `rollback`, `deleteSnapshot`, `listSnapshots` |
| `osUpdater: { model }` | The OS package layer: scan → upgrade → package list | `scanOs`, `upgradeOs`, `listPackages` |

Every plugged model also answers `privileges({ host })`, so the restricted login
can be granted the root commands it runs (see
[Plug-in privileges](#plug-in-privileges-privileges)).

The built-in behavior is the same code path: the Proxmox VM and CT snapshots are
two snapshotter implementations inside the fleet, the bundled collector with
apt/dnf/apk/pacman is the built-in OS updater, and
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
3. **a CT** (`ct`) — built-in **proxmox-ct**: the node model's `snapshotCt`,
   `rollbackCt`, `deleteCtSnapshot` and `listCtSnapshots` (`ct.nodeModel`).
   Only a CT with `unsafe.pctExec`, no `nodeModel` and a root node login falls
   back to `pct snapshot | rollback | delsnapshot | listsnapshot` on the node.
4. **none** — the update is unguarded (bare metal). Add a `snapshotter` to guard
   bare metal.

**Each snapshot record remembers its snapshotter.** A `snapshot` record stores
the snapshotter that took it (`snapshotter: { kind: proxmox-vm | proxmox-ct |
model, … }`). `rollback` and `pruneSnapshots` dispatch from the **record**, not
from the machine's current decorations. So when you change a machine's
snapshotter, its older snapshots are still rolled back and deleted by the
implementation that took them. Records written before this release have no
`snapshotter` field; they map from `kind` / `vmid` / `proxmoxNode`.

### OS updater contract (`osUpdater`)

The OS package layer is scan, upgrade and package list. Use it for a package
manager `@dmc/patch` does not ship (zypper, xbps, nix, a vendor appliance CLI), or
to reach a machine some other way (an MDM, a cloud agent).

| Method | Arguments | Called by | Your model must |
| ------ | --------- | --------- | --------------- |
| `scanOs` | `host` | `scan`; `safeOsUpdate` before and after the upgrade; `reboot` (the confirming scan); `pruneSnapshots` (the live gate) | Write one resource with the inventory fields. `updatesCount` (number or null) and `needsReboot` (boolean) are required. `packageManager`, `securityUpdatesCount`, `totalPackages`, `rebootReason`, `osType`, `osVersion`, `heldBackCount`, `removalsCount`, `distUpgradeRequired`, `dockerEngine`, `dockerImages` and `scannedAt` are optional. A failed run (or an invalid resource) means "no answer": `scan` writes an error record, and `safeOsUpdate` stops before it changes anything. |
| `upgradeOs` | `host`, `mode` (`safe` / `full`) | `safeOsUpdate`, after the snapshot | Apply the OS updates. A failed run counts as a failed upgrade. `mode` is passed through; ignore it if your package manager has one kind of upgrade. |
| `listPackages` | `host` | `safeOsUpdate`, before and after the upgrade | Write one resource with `packages: [{ name, version }]`. A failed run means no package diff is recorded; the update still goes ahead. |

Rules:

- **`@dmc/patch` keeps everything around the upgrade**: the snapshot guard, the
  app `source`, the health verdict, the rollback and the reboot. Your model only
  does the package work.
- **Health checks and reboots still use the machine's transport** (ssh, or `pct`
  for a CT), so the machine stays a host in the `sshModel` unless it has only
  `http` checks and you never reboot it through the fleet.
- **The bundled collector is skipped** for a machine with an `osUpdater`, so docker
  image drift comes only from `dockerEngine` / `dockerImages` in your `scanOs`
  resource.
- The inventory record names the model (`osUpdater`), with `reachMethod: null`; the
  reports show `via osUpdater <model>`.

A minimal outline (add your own backend calls where the comments are):

```ts
import { z } from "npm:zod@4";

const Host = z.object({ host: z.string() });

export const model = {
  type: "@you/zypper-os",
  version: "2026.10.25.1",
  globalArguments: z.object({ sshModel: z.string() }),
  resources: {
    scan: {
      description: "OS package status of a host",
      // The two required fields, plus any optional inventory fields you report.
      schema: z.object({
        packageManager: z.string(),
        updatesCount: z.number().nullable(),
        securityUpdatesCount: z.number().nullable().optional(),
        needsReboot: z.boolean(),
        rebootReason: z.string().nullable().optional(),
      }),
      lifetime: "infinite" as const,
      garbageCollection: 5,
    },
    packages: {
      description: "Installed packages of a host",
      schema: z.object({
        packages: z.array(z.object({ name: z.string(), version: z.string() })),
      }),
      lifetime: "infinite" as const,
      garbageCollection: 5,
    },
  },
  methods: {
    scanOs: {
      description: "Pending OS updates of `host`",
      arguments: Host,
      execute: async (a, ctx) => {
        // e.g. `zypper -q lu | grep -c '^v '` and `zypper ps -s` over ctx.runModel
        const h = await ctx.writeResource("scan", a.host, {
          packageManager: "zypper",
          updatesCount: 0,
          needsReboot: false,
        });
        return { dataHandles: [h] };
      },
    },
    upgradeOs: {
      description: "Apply the OS updates on `host`",
      arguments: Host.extend({ mode: z.enum(["safe", "full"]) }),
      execute: async (a, ctx) => ({ dataHandles: [] }), // e.g. zypper -n up / dup
    },
    listPackages: {
      description: "Installed packages of `host`",
      arguments: Host,
      execute: async (a, ctx) => {
        const packages: Array<{ name: string; version: string }> = []; // e.g. rpm -qa
        const h = await ctx.writeResource("packages", a.host, { packages });
        return { dataHandles: [h] };
      },
    },
  },
};
```

### Plug-in privileges (`privileges`)

The patch login is not root. A plugged model that needs root for a command
declares it, and `provisionAccess` grants exactly that argv (see
[Root commands](#root-commands-sudo)). The method takes `{ host }`, runs
nothing, and writes one resource with:

```json
{
  "commands": [{ "argv": ["/usr/bin/update"], "env": { "PHS_SILENT": "1" } }],
  "helpers": [],
  "remoteCode": true,
  "remoteSources": ["community-scripts/ProxmoxVE@main", "community-scripts/core@main"]
}
```

Everything a plug-in returns becomes a root grant, so the fleet treats it as
untrusted:

- The shape is strict: an unknown key is an error. At most 16 commands, each 1
  to 32 tokens. `helpers` must be empty in this release.
- The bin is a bare name or a plain absolute path. Arguments and env values use
  letters, digits and `. _ / : = + -` only. A command with `env` runs as
  `env NAME=value … bin args`.
- Refused: shells, interpreters, privilege tools, commands that run other
  commands, editors, pagers and copy tools (also checked on the host against
  the real path a bin resolves to), loader or interpreter env names, and bins
  under `/tmp`, `/var/tmp`, `/dev/shm`, `/home` or `/run/user`.
- On the host, each bin must be a root-owned file in a root-owned directory
  chain, like the built-in entries.
- `remoteCode: true` needs `remoteSources` (1 to 4 distinct `owner/repo@ref`),
  and each source needs its own `trustRemote` record on the machine. An answer
  that does not parse still claims every source it names, so an `unsafe` record
  never excuses untrusted remote code.

The rules fail closed. An app updater or `osUpdater` that does not answer is
refused, unless the machine carries `unsafe.privilegedUpdater` (then recorded as
an accepted risk used). A snapshotter must always answer; an API snapshotter
declares no commands. `renderAccess` and `provisionAccess` refuse a machine
with errors and still provision the others, the `privileges-declared` check
covers `safeOsUpdate`, `rollback`, `pruneSnapshots` and the access methods, and
`safeOsUpdate` checks again before any side effect.

`@dmc/proxmox/community-script` implements it: with `reach: ssh` it declares
`env PHS_SILENT=1 /usr/bin/update` and both community-scripts sources; with
`reach: pct` it refuses, because `pct` runs every command as root on the node.

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

An updater needs two methods, plus `privileges` (the snapshotter and OS updater
outlines above need it too):

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
  privileges: {
    description: "Declare the root commands the update runs (read-only)",
    arguments: z.object({ host: z.string() }),
    execute: async (_a, ctx) => {
      const h = await ctx.writeResource("privileges", "privileges", {
        commands: [{ argv: ["/usr/local/bin/my-app-update"] }],
        helpers: [],
        remoteCode: false,
      });
      return { dataHandles: [h] };
    },
  },
},
```

---

## Methods

| Method | Purpose |
| ------ | ------- |
| `scan` | Fan out over the fleet: collect OS package status + docker image drift per machine, evaluate health, and refresh `source` app-update checks. Batched (one ssh call for all ssh hosts, one call per Proxmox node for its CTs, one health call per machine) and resilient: one unreachable host or node can't sink the run. See the [scan call budget](#the-scan-call-budget). |
| `import` | Emit a suggested `machines:` block seeded from the `sshModel` host list and Proxmox guest discovery (VMs → `vm`, CTs → `ct` + commented `source`). Paste into `globalArguments` and decorate. |
| `safeOsUpdate` | Snapshot-guarded OS update for one machine (see below). Refused unless the machine's `osUpdatePolicy` is `managed` and `os` is on. |
| `safeUpdate` | Health-checked, rollback-capable **docker** update: record image ids → pull + `up -d` → wait for health → roll back to the prior image on failure. Replaced images are retained for `retentionHours` (pruned by `pruneImages`). |
| `reboot` | Graceful reboot: `systemctl reboot` (ssh, through the exact `sudo -n systemd-run` entry so the call returns before the link drops) or `pct reboot` (a CT on the `pct` path). Refused on a `scan-only` machine, also with `force`. Guarded on `needsReboot` unless `force`; waits for return; runs health as **detection** (with the `healthGraceSec` grace window, default 120 s). |
| `rollback` | Deliberately revert a machine to its newest retained pre-update snapshot, or a named one, through the snapshotter that took it (VM or CT snapshot rollback through the node model / `pct rollback` on the `unsafe.pctExec` path / your `snapshotter`'s `rollback`). The recovery for a reboot/update that left a host unhealthy. Then runs health, with the `healthGraceSec` grace window (default 120 s). |
| `pruneSnapshots` | Delete retained pre-update snapshots past their retention window that are health-confirmed, reboot-confirmed (when a reboot was needed), and pass a fresh check: the host answers a scan (over ssh, or over `pct` on its node for a CT on the `pct` path) and has no reboot pending. A snapshot of a host that is no longer in the fleet is kept. `dryRun` to preview. Each snapshot is deleted by the snapshotter that took it: VM or CT → node-model delete (`pct delsnapshot` on the `pct` path); your `snapshotter` → `deleteSnapshot`. |
| `pruneImages` | Delete retained previous docker images past their retention window (via `docker rmi`, which refuses if still in use). `dryRun` to preview. |
| `renderAccess` | Write the access plan per machine (the restricted key line, the provision script and its hash). Contacts no host. See [Secure patching](#secure-patching-restricted-access). |
| `provisionAccess` | Install the patch login on the selected machines through `access.provisionSshModel`. **A bare run is a dry run.** One script call per distinct script; refusals and failures are recorded per host and fail the run. |
| `revokeAccess` | Remove the patch login and everything `provisionAccess` installed. **A bare run is a dry run.** Never deletes an account it did not create. |
| `auditAccess` | Read-only audit of the patch login on each host (as the login and as root); writes one `accessAudit` record per host and fails at `failOn` (default `high`). |
| `clearRetired` | Delete the stored records of **retired machines** (hosts with records that are no longer in `globalArguments.machines`). **A bare run is a preview** (`dryRun` defaults to `true`). See [Retired machines and `clearRetired`](#retired-machines-and-clearretired). |

### `safeOsUpdate` in detail

Arguments: `host`, `mode` (`safe` = `apt upgrade` / `full` = `apt full-upgrade`;
dnf/apk/pacman always do a full upgrade; an `osUpdater` model gets `mode` as is), `retentionHours` (default 168 = 7 days),
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
   when set; else a VM or CT via the node model (a CT on the `pct` path via `pct snapshot`);
   bare metal none. A failed snapshot aborts the update.
2. **Upgrade** — through the machine's `osUpdater` model when set (`upgradeOs`,
   with `scanOs` / `listPackages` around it); else apt/dnf/apk/pacman
   (`pacman -Syu --noconfirm`), over ssh (VM, CT, bare metal) or `pct exec` (a CT on the `pct` path), capturing an
   installed-package **before/after diff** (`{name, from, to}`). The "after" list is
   read before any rollback, so a rolled-back run still records what the update
   changed. When either list cannot be read, the run records no diff (`packages:
   null`) rather than a misleading one; it never aborts the update.
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
| `host-reachable` | `live` | `safeUpdate`, `safeOsUpdate`, `reboot` | The machine answers: ssh `true` through the `sshModel`, or `pct status <ctid>` on the node for a CT on the `pct` path. Not run for `rollback`, because a broken host is the reason to roll back. |
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
| `inventory` | scan / safeOsUpdate | Per-host OS status, docker engine + image drift, reachMethod (or the `osUpdater` model that scanned it), **health** verdict. Keyed by host (latest = current). |
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
  **Reboot required** sections, **Packages changed outside @dmc/patch** (an
  inventory hash that moved since the last change @dmc/patch made), and **Apps
  behind upstream** (an OS-managed app with no pending update whose upstream
  release is newer: only a newer OS release or another repository closes that
  gap, so it does not change `allCurrent`). Current machines only; hosts that
  left the fleet appear under **Retired machines**.
- **`@dmc/patch-history`** — per-host detail: current status (OS, location, app,
  docker, health) followed by that host's **run history** with collapsible
  package / image `from → to` diffs. Every current host gets a section, even with
  no runs. Retired hosts get a **Retired machines** block with their last status
  and run history.
- **`@dmc/patch-prune-history`** — chronological snapshot/image prune runs
  (retired vs kept, with reasons), including `clearRetired` runs.
- **`@dmc/patch-access`** — access posture: flag lines (`CRITICAL`, `HIGH`,
  `WARNING`, `ACCEPTED RISKS … overdue`, `NOT AUDITED`, `STALE AUDIT`), then per
  host the `auditAccess` findings, the accepted risks with their reason and
  review date, the last provision / revoke run, and the accepted risks and
  security findings of the last scan. Host-supplied text is escaped.

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

The collector is a self-contained, OS-detecting bash script (apt / dnf / apk /
pacman) bundled inside the extension — consumers do not need to provide it. A
machine with an `osUpdater` model is scanned by that model instead. It prints **one** `{"_kind":"patch-inventory",…}` JSON line:
pending updates, security updates, held-back / dist-upgrade (apt), total packages,
`needsReboot` (running-vs-installed kernel + `needs-restarting -r` / apt
`reboot-required`), and per-container docker image drift.

On Arch (pacman) it never runs `pacman -Sy` (syncing the live database without
upgrading invites partial upgrades). It counts updates with `checkupdates` from
`pacman-contrib` (which also needs `fakeroot`, not in a minimal install), which
syncs a private copy of the database; without them, it
falls back to `pacman -Qu` against the existing sync database (stale until the
next upgrade) and logs that. `[ignored]` packages are not counted. Security
updates come from `arch-audit -u` when it is installed (else none). A reboot is
needed when the running kernel's `/usr/lib/modules/<uname -r>` tree is gone
(not judged inside a container, which runs the host's kernel). It runs over ssh, or is
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

- **`vm.proxmoxNode` and `ct.nodeModel` = node model, `ct.proxmoxNode` = ssh host** (the `pct` path only). Different refs.
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
- **All three extension points are reached by name, never by type**, so a
  consumer adds an updater, snapshotter or OS updater in their own repo without
  upstreaming it.
- **Every per-machine operation goes through a transport.** `safeOsUpdate`,
  `reboot`, the health checks, `pruneSnapshots`' live gate and the
  `host-reachable` check reach a machine only through a `Transport`: **ssh** (the
  ssh model's `script` / `exec` on the host) or **pct** (`pct exec` / `pct
  status` / `pct reboot` on a CT's node). None of them branches on ssh-vs-pct, so
  every machine kind runs the same flow. `scan` keeps its own batched fan-out to
  stay under the runModel call budget.
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
