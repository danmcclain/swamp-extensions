# swamp-extensions

Custom [swamp](https://github.com/swamp-club/swamp) extensions by
[@danmcclain](https://github.com/danmcclain).

This repository is a **monorepo**: each extension lives in its own subdirectory
that is itself a self-contained swamp repo (its own `.swamp.yaml`,
`manifest.yaml`, and `extensions/` tree). Each extension publishes, tests, and
loads independently.

## Extensions

| Name                   | Kind          | Description                                                                                   |
| ---------------------- | ------------- | --------------------------------------------------------------------------------------------- |
| `@dmc/unifi-networks`  | model + reports | Query UniFi Network sites (VLANs, firewall zones/policies, clients, WiFi) via the official integration API, mapped together, with firewall-summary and zone-matrix reports. See [unifi-networks/README.md](unifi-networks/README.md). |
| `@dmc/proxmox`         | models        | Proxmox VE VM/LXC lifecycle operations, cloud-image storage, and snapshot-guarded updates for community-scripts LXCs, extending the `@keeb/proxmox` family. See [proxmox/README.md](proxmox/README.md). |
| `@dmc/fastmail`        | model + reports | Fastmail email-organization pipeline over JMAP — scan senders (flagging bulk/newsletter mail), generate Sieve scripts sorting senders into folders, and plan/apply moves, with audit, coverage, and plan reports. See [fastmail/README.md](fastmail/README.md). |

## Layout

```
swamp-extensions/            # this repo (umbrella container)
  unifi-networks/            # one extension = one nested swamp repo
    .swamp.yaml
    manifest.yaml            # manifest, README, LICENSE at the extension root
    README.md
    LICENSE.txt
    extensions/
      models/                # TypeScript model definitions
      reports/               # TypeScript report definitions
  proxmox/                   # another extension (models only, depends on @keeb/proxmox)
    .swamp.yaml
    manifest.yaml
    README.md  LICENSE.md  deno.json
    extensions/
      models/                # proxmox_storage.ts, proxmox_vm_extras.ts, proxmox_community_script.ts, lib/
  fastmail/                  # model + reports (JMAP email organization)
    .swamp.yaml
    manifest.yaml
    README.md  LICENSE.txt
    extensions/
      models/                # fastmail.ts
      reports/               # fastmail_audit.ts, fastmail_coverage.ts, fastmail_plan.ts
  <next-extension>/          # add more extensions the same way
```

## Adding a new extension

From the repo root, scaffold a nested swamp repo and drop in your source:

```bash
swamp repo init <extension-name> --tool none
# add source under <extension-name>/extensions/models/*.ts and/or extensions/reports/*.ts
# write <extension-name>/manifest.yaml, plus README.md and LICENSE.txt
```

`--tool none` skips AI-tool scaffolding so Claude tooling stays only at the
top level. Then add a row to the Extensions table above.

## Using these locally

Add the whole monorepo as an extension source from another swamp repo — the
trailing `/*` glob loads each extension subdirectory as its own repo-root
source:

```bash
swamp extension source add /path/to/swamp-extensions/*
```

## Publishing

Each extension carries its own `manifest.yaml`. Publish from the extension's
directory with the `swamp-extension-publish` flow:

```bash
swamp extension push unifi-networks/manifest.yaml --dry-run --json
```
