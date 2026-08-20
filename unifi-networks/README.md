# @dmc/unifi-networks

Query UniFi Network sites through Ubiquiti's **official integration API** and
map the pieces together: VLANs, firewall zones/policies, connected clients, and
WiFi SSIDs — with reports that render a firewall summary and a zone posture
matrix.

## Modes

The extension talks to one API with two connection modes, chosen by the required
`mode` global argument. The mode determines which **API key** you must create:

| Mode    | Key source                                         | Reaches                                        |
| ------- | -------------------------------------------------- | ---------------------------------------------- |
| `local` | Console → Settings → Control Plane → Integrations  | `https://<host>/proxy/network/integration`     |
| `cloud` | [unifi.ui.com](https://unifi.ui.com) → API Keys    | Ubiquiti cloud proxy (`api.ui.com`)            |

- **local** requires `host` (the console IP/hostname). Set `verifyTls: false` for
  a factory UDM's self-signed certificate (calls route through `curl`).
- **cloud** discovers consoles automatically; with no `consoleId` it fans out
  over every console the key can see. Pin one with `consoleId`.

## Global arguments

| Arg         | Required        | Description                                              |
| ----------- | --------------- | ------------------------------------------------------- |
| `mode`      | yes             | `local` or `cloud`                                      |
| `apiKey`    | yes             | The key matching the chosen mode                        |
| `host`      | local only      | Console hostname/IP                                     |
| `consoleId` | cloud, optional | Target one console; omit to scan all                    |
| `verifyTls` | no (default on) | Verify local TLS; `false` for self-signed UDM certs     |

## Methods

| Method         | What it does                                                              |
| -------------- | ------------------------------------------------------------------------- |
| `scan`         | Networks/VLANs per site                                                    |
| `scanFirewall` | Firewall zones + policies, joined to zone names with flattened rule detail |
| `scanClients`  | Connected clients, mapped to VLAN by IP-subnet match                       |
| `scanWifi`     | WiFi SSIDs, mapped to VLAN via their network reference                     |
| `consoles`     | List consoles visible to a cloud key (cloud mode)                          |
| `deletePolicy` | Delete one user-defined firewall policy (verifies it is user-defined)      |

## Reports

Both run automatically after `scanFirewall`:

- **`@dmc/unifi-firewall-summary`** — zone inventory + user-defined policy table,
  with an "Attention" section flagging temporary-looking or unrestricted rules.
- **`@dmc/unifi-zone-matrix`** — source→destination posture grid from the
  catch-all defaults, marking pairs a higher-priority rule overrides.

## Example

```yaml
# model instance globalArguments
mode: local
host: udm.example.com
apiKey: ${{ vault.get(local-secrets, UNIFI_API_KEY) }}
```

```bash
swamp model method run my-unifi scan
swamp model method run my-unifi scanFirewall   # renders both reports
swamp model method run my-unifi scanClients
swamp model method run my-unifi scanWifi
```
