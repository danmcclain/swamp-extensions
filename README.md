# swamp-extensions

Custom [swamp](https://github.com/swamp-club/swamp) extensions by
[@danmcclain](https://github.com/danmcclain).

## Extensions

| Name                   | Kind          | Description                                                                                   |
| ---------------------- | ------------- | --------------------------------------------------------------------------------------------- |
| `@dmc/unifi-networks`  | model + reports | Query UniFi Network sites (VLANs, firewall zones/policies, clients, WiFi) via the official integration API, mapped together, with firewall-summary and zone-matrix reports. See [extensions/models/README.md](extensions/models/README.md). |

## Layout

```
extensions/
  models/     # TypeScript model definitions + their manifest, README, LICENSE
  reports/    # TypeScript report definitions
```

## Using these locally

Add this repo as an extension source from another swamp repo:

```bash
swamp extension source add /path/to/swamp-extensions
```

## Publishing

Each extension carries its own `manifest.yaml`. Publish with the
`swamp-extension-publish` flow:

```bash
swamp extension push extensions/models/manifest.yaml --dry-run --json
```
