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

- **local** requires `host` (the console IP/hostname). For a console with a
  self-signed certificate, set `caCert`. See
  [Self-signed certificates](#self-signed-certificates).
- **cloud** discovers consoles automatically; with no `consoleId` it fans out
  over every console the key can see. Pin one with `consoleId`.

### Self-signed certificates

Every call uses `fetch` and checks the console's TLS certificate and host name.
There is no setting that turns these checks off. For a console with a
self-signed certificate (a factory UDM), set `caCert` to the PEM certificate
that signs it. The extension then trusts that certificate in addition to the
system roots. The certificate must still name the `host` you connect to. It
must also be a server certificate (`basicConstraints CA:FALSE`): Deno's TLS
library refuses a CA certificate that a server presents as its own, even when
it is in `caCert`. For such a console, install a server certificate on it, or
one signed by a CA that you set as `caCert`. Get it
from the console, for example:

```bash
openssl s_client -connect <host>:443 -showcerts </dev/null \
  | openssl x509 -outform PEM > console.pem
```

This trusts whatever answered, so compare the certificate's fingerprint
(`openssl x509 -in console.pem -noout -fingerprint -sha256`) with the console
before you set it.

A TLS failure names the fix: set `caCert`, or, when it is set, check that it
signs the console certificate and that the certificate names the host. `caCert`
is an error in cloud mode, where the proxy has a publicly trusted certificate.

**Upgrading from 2026.07.07.1:** `verifyTls` and its `curl -k` transport are
removed. The upgrade deletes `verifyTls` from existing instances. An instance
that had `verifyTls: false` then fails the TLS check, with that hint, until you
set `caCert`.

## Global arguments

| Arg         | Required        | Description                                              |
| ----------- | --------------- | ------------------------------------------------------- |
| `mode`      | yes             | `local` or `cloud`                                      |
| `apiKey`    | yes             | The key matching the chosen mode                        |
| `host`      | local only      | Console hostname/IP                                     |
| `consoleId` | cloud, optional | Target one console; omit to scan all                    |
| `caCert`    | no              | PEM certificate to trust for a self-signed local console |

## Methods

| Method             | What it does                                                              |
| ------------------ | ------------------------------------------------------------------------- |
| `scan`             | Networks/VLANs per site                                                    |
| `scanFirewall`     | Firewall zones + policies, joined to zone names with flattened rule detail |
| `scanClients`      | Connected clients, mapped to VLAN by IP-subnet match                       |
| `scanWifi`         | WiFi SSIDs, mapped to VLAN via their network reference                     |
| `consoles`         | List consoles visible to a cloud key (cloud mode)                          |
| `deletePolicy`     | Delete one user-defined firewall policy (verifies it is user-defined)      |
| `setNetworkDomain` | Set the DHCP domain name on named networks (dry run by default)            |
| `setDnsRecords`    | Create or update local DNS A records (dry run by default)                  |

### Setting a network's domain name

`setNetworkDomain` sets the **Domain Name** of a network's DHCP server — the
domain the gateway hands to DHCP clients and registers their hostnames under —
on every named network of one site in one run.

| Argument    | Required | Description                                                       |
| ----------- | -------- | ----------------------------------------------------------------- |
| `domain`    | yes      | DNS name to set, e.g. `lan.example` (stored lowercase)            |
| `networks`  | yes      | Network names; exact match, case-insensitive                      |
| `dryRun`    | no       | Default `true`: record the plan only. `false` applies it          |
| `siteId`    | no       | Needed only when the console has more than one site               |
| `consoleId` | no       | Needed only when a cloud key sees more than one console           |

It fails closed. Before any change it rejects an invalid domain, an unknown
name, a name that matches more than one network, and a network that is not
gateway-managed with a DHCP server. Update Network is a full replace, so the
method sends the complete current network with only `domainName` changed. After
each update it reads the network again and stops with an error if the domain is
not set or any other field changed. Each run writes a `networkDomainChange`
resource with each network's current and new domain, and whether it was
applied and verified.

```bash
# dry run: shows current → new per network, changes nothing
swamp model method run my-unifi setNetworkDomain \
  --input '{"domain":"lan.example","networks":["Apps","Lab"]}'

# apply
swamp model method run my-unifi setNetworkDomain \
  --input '{"domain":"lan.example","networks":["Apps","Lab"],"dryRun":false}'
```

The gateway registers names from DHCP leases. A host that sets a static
address itself, without DHCP, may get no name under the domain. Let it use DHCP
with a fixed-IP reservation, or add a local DNS record for it.

The gateway then answers for the whole domain itself. Seen on UniFi Network
10.6.109: before the change it forwarded the domain's queries upstream; after
it, every name it has no lease for got NXDOMAIN, the public SOA included. LAN
clients that use the gateway as resolver no longer see the domain's public
records, so pick a domain that is only used on the LAN.

### Local DNS records

`setDnsRecords` creates or updates local DNS **A records** (UniFi DNS
policies) on one site in one run. Use it for hosts with static addresses,
which get no name from DHCP.

| Argument     | Required | Description                                                      |
| ------------ | -------- | ---------------------------------------------------------------- |
| `records`    | yes      | List of `{ "name": "<fqdn>", "ipv4Address": "<ip>" }`            |
| `ttlSeconds` | no       | TTL for every record in the run, 0–86400 (default 3600)          |
| `dryRun`     | no       | Default `true`: record the plan only. `false` applies it         |
| `siteId`     | no       | Needed only when the console has more than one site              |
| `consoleId`  | no       | Needed only when a cloud key sees more than one console          |

It fails closed. Before any change it rejects an invalid name or IPv4
address, a name given twice, a name that already has a CNAME or forward-domain
policy, and a name with more than one A record. A name with no A record is
created. A name with one A record is updated in place when its address, TTL or
enabled flag differs: the body is the full existing policy with only those
fields changed. After the writes, the method reads all DNS policies again and
fails unless each name has exactly the requested A record. Each run writes a
`dnsRecordChange` resource with each record's current and new values, and
whether it was applied and verified.

```bash
swamp model method run my-unifi setDnsRecords --input '{
  "records": [
    {"name": "fort.lan.example", "ipv4Address": "192.0.2.50"},
    {"name": "pve.lan.example", "ipv4Address": "192.0.2.51"}
  ]}'
# add "dryRun": false to apply
```

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
