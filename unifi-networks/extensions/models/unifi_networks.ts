import { z } from "npm:zod@4";

const CLOUD_BASE = "https://api.ui.com";

const GlobalArgsSchema = z.object({
  mode: z.enum(["local", "cloud"]).describe(
    "Connection mode. Determines which API key you must create: " +
      "'local' = key from the console (Network → Settings → Control Plane → Integrations) reached at https://<host>; " +
      "'cloud' = key from unifi.ui.com (Account → API Keys) reached via Ubiquiti's cloud proxy.",
  ),
  apiKey: z.string().meta({ sensitive: true }).describe(
    "UniFi API key matching the chosen mode",
  ),
  host: z.string().optional().describe(
    "Console hostname or IP — required when mode='local' (e.g. 192.168.1.1)",
  ),
  consoleId: z.string().optional().describe(
    "Cloud console ID to target. When mode='cloud' and omitted, all consoles " +
      "visible to the key are discovered and scanned.",
  ),
  caCert: z.string().optional().describe(
    "PEM certificate(s) to trust for a console with a self-signed TLS " +
      "certificate (local mode only). Trusted in addition to the system " +
      "roots; the host name is still checked. Not needed when the console " +
      "has a publicly trusted certificate.",
  ),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

const ConsoleSchema = z.object({
  id: z.string(),
  shortname: z.string().optional(),
  name: z.string().optional(),
});

const ConsolesSchema = z.object({
  fetchedAt: z.string(),
  consoleCount: z.number(),
  consoles: z.array(ConsoleSchema),
});

const NetworkSchema = z.object({
  id: z.string(),
  name: z.string(),
  management: z.string(),
  enabled: z.boolean(),
  vlanId: z.number(),
  default: z.boolean(),
  zoneId: z.string().optional(),
  deviceId: z.string().optional(),
  metadataOrigin: z.string().optional(),
});

const ZoneSchema = z.object({
  id: z.string(),
  name: z.string(),
  networkIds: z.array(z.string()),
  metadataOrigin: z.string().optional(),
});

const PolicySchema = z.object({
  id: z.string(),
  name: z.string(),
  enabled: z.boolean(),
  index: z.number(),
  action: z.string(),
  sourceZoneId: z.string().optional(),
  sourceZone: z.string().optional(),
  destinationZoneId: z.string().optional(),
  destinationZone: z.string().optional(),
  ipVersion: z.string().optional(),
  protocol: z.string().optional().describe(
    "Readable protocol match, e.g. 'tcp', 'udp', 'icmp', 'all'",
  ),
  sourceMatch: z.string().optional().describe(
    "Readable source traffic filter beyond zone",
  ),
  destinationMatch: z.string().optional().describe(
    "Readable destination traffic filter beyond zone",
  ),
  destinationPorts: z.string().optional().describe(
    "Readable destination port match",
  ),
  connectionStates: z.array(z.string()).optional(),
  ipsecFilter: z.string().optional(),
  loggingEnabled: z.boolean().optional(),
  metadataOrigin: z.string().optional(),
});

const SiteFirewallSchema = z.object({
  scannedAt: z.string(),
  mode: z.enum(["local", "cloud"]),
  target: z.string(),
  consoleId: z.string().optional(),
  consoleShortname: z.string().optional(),
  siteId: z.string(),
  siteName: z.string(),
  zoneCount: z.number(),
  policyCount: z.number(),
  zones: z.array(ZoneSchema),
  policies: z.array(PolicySchema),
});

const SiteNetworksSchema = z.object({
  scannedAt: z.string(),
  mode: z.enum(["local", "cloud"]),
  target: z.string().describe(
    "host (local) or consoleId (cloud) that was scanned",
  ),
  consoleId: z.string().optional(),
  consoleShortname: z.string().optional(),
  siteId: z.string(),
  siteName: z.string(),
  networkCount: z.number(),
  networks: z.array(NetworkSchema),
});

const WifiSchema = z.object({
  id: z.string(),
  name: z.string().describe("SSID"),
  enabled: z.boolean(),
  type: z.string().describe("STANDARD | IOT_OPTIMIZED"),
  security: z.string().optional().describe(
    "OPEN | WPA2_PERSONAL | WPA3_PERSONAL | ...",
  ),
  networkRef: z.string().describe("NATIVE (default/untagged) or SPECIFIC"),
  networkId: z.string().optional(),
  networkName: z.string().optional(),
  vlanId: z.number().optional(),
  metadataOrigin: z.string().optional(),
});

const SiteWifiSchema = z.object({
  scannedAt: z.string(),
  mode: z.enum(["local", "cloud"]),
  target: z.string(),
  consoleId: z.string().optional(),
  consoleShortname: z.string().optional(),
  siteId: z.string(),
  siteName: z.string(),
  wifiCount: z.number(),
  wifis: z.array(WifiSchema),
});

const ClientSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: z.string().describe("WIRED | WIRELESS | VPN | TELEPORT"),
  macAddress: z.string().optional(),
  ipAddress: z.string().optional(),
  connectedAt: z.string().optional(),
  accessType: z.string().optional().describe("DEFAULT | GUEST"),
  uplinkDeviceId: z.string().optional(),
  // Mapped from ipAddress → network subnet (clients carry no networkId/vlanId)
  vlanId: z.number().optional(),
  networkId: z.string().optional(),
  networkName: z.string().optional(),
});

const VlanClientCountSchema = z.object({
  vlanId: z.number().optional(),
  networkName: z.string(),
  clientCount: z.number(),
});

const SiteClientsSchema = z.object({
  scannedAt: z.string(),
  mode: z.enum(["local", "cloud"]),
  target: z.string(),
  consoleId: z.string().optional(),
  consoleShortname: z.string().optional(),
  siteId: z.string(),
  siteName: z.string(),
  clientCount: z.number(),
  unmappedCount: z.number().describe(
    "Clients whose IP matched no known subnet (e.g. VPN)",
  ),
  byVlan: z.array(VlanClientCountSchema),
  clients: z.array(ClientSchema),
});

const NetworkDomainResultSchema = z.object({
  networkId: z.string(),
  networkName: z.string(),
  vlanId: z.number().optional(),
  currentDomain: z.string().optional().describe(
    "Domain name before the run (empty or absent when none is set)",
  ),
  newDomain: z.string(),
  action: z.enum(["change", "unchanged"]),
  applied: z.boolean().describe("True when this run sent the update"),
  verified: z.boolean().optional().describe(
    "Live runs: re-read shows the new domain and no other field changed",
  ),
});

const NetworkDomainChangeSchema = z.object({
  ranAt: z.string(),
  mode: z.enum(["local", "cloud"]),
  target: z.string(),
  consoleId: z.string().optional(),
  consoleShortname: z.string().optional(),
  siteId: z.string(),
  siteName: z.string(),
  domain: z.string(),
  dryRun: z.boolean(),
  changeCount: z.number().describe(
    "Networks whose domain differs from the requested one",
  ),
  networks: z.array(NetworkDomainResultSchema),
});

const DnsRecordResultSchema = z.object({
  name: z.string(),
  ipv4Address: z.string(),
  ttlSeconds: z.number(),
  action: z.enum(["create", "update", "unchanged"]),
  policyId: z.string().optional(),
  currentIpv4Address: z.string().optional(),
  currentTtlSeconds: z.number().optional(),
  currentEnabled: z.boolean().optional(),
  applied: z.boolean().describe("True when this run sent the create/update"),
  verified: z.boolean().optional().describe(
    "Live runs: re-read shows exactly this record and no other field changed",
  ),
});

const DnsRecordChangeSchema = z.object({
  ranAt: z.string(),
  mode: z.enum(["local", "cloud"]),
  target: z.string(),
  consoleId: z.string().optional(),
  consoleShortname: z.string().optional(),
  siteId: z.string(),
  siteName: z.string(),
  dryRun: z.boolean(),
  changeCount: z.number().describe("Records to create or update"),
  records: z.array(DnsRecordResultSchema),
});

// ── HTTP ──────────────────────────────────────────────────────────────────────

interface RequestOptions {
  /** PEM certificate(s) to trust in addition to the system roots. */
  caCert?: string;
  /** JSON request body for POST/PUT/PATCH. */
  body?: unknown;
}

// ── pure helpers (unit-tested in unifi_networks_test.ts) ──────────────────────

const PEM_CERT_RE =
  /^\s*(?:-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*)+$/;

/**
 * The caCert to trust, or undefined when none is set. Fails closed: a caCert
 * that is still an unresolved ${{ }} expression or is not a PEM certificate
 * bundle is an error, and so is a caCert in cloud mode (the cloud proxy has a
 * publicly trusted certificate). Certificate checks can never be turned off.
 * Exported for testing.
 */
export function resolveCaCert(
  g: { mode: string; caCert?: string },
): string | undefined {
  const ca = g.caCert;
  if (ca === undefined) return undefined;
  if (g.mode !== "local") {
    throw new Error(
      "caCert applies only to mode='local'; the cloud proxy has a publicly " +
        "trusted certificate",
    );
  }
  if (ca.includes("${{")) {
    throw new Error(
      "caCert is still an unresolved ${{ }} expression; check the reference",
    );
  }
  if (!PEM_CERT_RE.test(ca)) {
    throw new Error(
      "caCert is not a PEM certificate bundle (-----BEGIN CERTIFICATE----- ...)",
    );
  }
  return ca;
}

/**
 * Turn a fetch failure into an actionable error. A TLS failure says how to
 * fix it: set caCert for a self-signed console certificate, or check that
 * caCert signs the certificate and that the certificate names the host.
 * Exported for testing.
 */
export function describeFetchError(
  method: string,
  url: string,
  err: unknown,
  caCertSet: boolean,
): Error {
  const msg = err instanceof Error ? err.message : String(err);
  if (/CaUsedAsEndEntity/.test(msg)) {
    return new Error(
      `${method} ${url}: TLS check failed (${msg}). The console presents a ` +
        "CA certificate (basicConstraints CA:TRUE) as its server " +
        "certificate, which the TLS library refuses even with caCert. Give " +
        "the console a server certificate (CA:FALSE), or one signed by a CA " +
        "that you set as caCert.",
    );
  }
  if (/certificate|tls|ssl|UnknownIssuer|NotValidForName/i.test(msg)) {
    return new Error(
      `${method} ${url}: TLS check failed (${msg}). ` +
        (caCertSet
          ? "caCert does not sign the console certificate, or the " +
            "certificate does not name the host."
          : "For a console with a self-signed certificate, set caCert to " +
            "its PEM certificate."),
    );
  }
  return new Error(`${method} ${url} failed: ${msg}`);
}

/**
 * Enforce a 2xx status and parse the JSON body, returning null for an empty
 * body (e.g. a 204 from DELETE). Exported for testing.
 */
export function finalizeResponse(
  method: string,
  url: string,
  status: number,
  text: string,
): Record<string, unknown> | null {
  if (status < 200 || status >= 300) {
    throw new Error(`${method} ${url} failed (${status}): ${text}`);
  }
  return text.trim() ? (JSON.parse(text) as Record<string, unknown>) : null;
}

// ── transport ─────────────────────────────────────────────────────────────────

/**
 * Single request core shared by every verb (GET/POST/PUT/PATCH/DELETE). Uses
 * fetch and always verifies the TLS certificate and host name. With caCert,
 * a per-request HTTP client also trusts that certificate (for a console with
 * a self-signed certificate); the client is closed on every path.
 */
async function apiRequest(
  method: string,
  url: string,
  apiKey: string,
  opts: RequestOptions = {},
): Promise<Record<string, unknown> | null> {
  const { caCert, body } = opts;
  const headers: Record<string, string> = {
    "X-API-KEY": apiKey,
    "Accept": "application/json",
  };
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const client = caCert
    ? Deno.createHttpClient({ caCerts: [caCert] })
    : undefined;
  try {
    let resp: Response;
    try {
      resp = await fetch(url, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        client,
      });
    } catch (e) {
      throw describeFetchError(method, url, e, caCert !== undefined);
    }
    const text = await resp.text();
    return finalizeResponse(method, url, resp.status, text);
  } finally {
    client?.close();
  }
}

// Verb helpers over the shared core. PATCH is a one-line apiRequest(...) call
// away when a patch method is added.
const apiGet = (url: string, apiKey: string, caCert?: string) =>
  apiRequest("GET", url, apiKey, { caCert }).then((r) => r ?? {});

const apiPost = (
  url: string,
  apiKey: string,
  body: unknown,
  caCert: string | undefined,
) => apiRequest("POST", url, apiKey, { caCert, body }).then((r) => r ?? {});

const apiPut = (
  url: string,
  apiKey: string,
  body: unknown,
  caCert: string | undefined,
) => apiRequest("PUT", url, apiKey, { caCert, body }).then((r) => r ?? {});

const apiDelete = (url: string, apiKey: string, caCert: string | undefined) =>
  apiRequest("DELETE", url, apiKey, { caCert }).then(() => undefined);

async function fetchAllPages(
  base: string,
  path: string,
  apiKey: string,
  caCert: string | undefined,
): Promise<Array<Record<string, unknown>>> {
  const items: Array<Record<string, unknown>> = [];
  let offset = 0;
  const limit = 100;
  while (true) {
    const page = await apiGet(
      `${base}${path}?offset=${offset}&limit=${limit}`,
      apiKey,
      caCert,
    );
    const data = (page.data ?? []) as Array<Record<string, unknown>>;
    items.push(...data);
    // Stop on the last page, an empty page (guards against a stale totalCount
    // that would otherwise loop forever), or a short page.
    if (
      data.length === 0 ||
      data.length < limit ||
      items.length >= ((page.totalCount as number) ?? 0)
    ) break;
    offset += limit;
  }
  return items;
}

// ── mapping ─────────────────────────────────────────────────────────────────

function mapNetwork(n: Record<string, unknown>): z.infer<typeof NetworkSchema> {
  return {
    id: n.id as string,
    name: n.name as string,
    management: n.management as string,
    enabled: n.enabled as boolean,
    vlanId: n.vlanId as number,
    default: n.default as boolean,
    zoneId: n.zoneId as string | undefined,
    deviceId: n.deviceId as string | undefined,
    metadataOrigin: (n.metadata as Record<string, unknown>)?.origin as
      | string
      | undefined,
  };
}

function mapZone(z_: Record<string, unknown>): z.infer<typeof ZoneSchema> {
  return {
    id: z_.id as string,
    name: z_.name as string,
    networkIds: (z_.networkIds as string[]) ?? [],
    metadataOrigin: (z_.metadata as Record<string, unknown>)?.origin as
      | string
      | undefined,
  };
}

type Obj = Record<string, unknown>;

/** Readable protocol from an ipProtocolScope, e.g. "tcp", "icmp", "proto 47", "all". */
function describeProtocol(scope: Obj | undefined): string | undefined {
  if (!scope) return undefined;
  const pf = scope.protocolFilter as Obj | undefined;
  if (!pf) return "all";
  switch (pf.type) {
    case "NAMED_PROTOCOL": {
      const name = (pf.protocol as Obj)?.name as string | undefined;
      return pf.matchOpposite ? `not ${name}` : name;
    }
    case "PROTOCOL_NUMBER":
      return `proto ${pf.protocolNumber}`;
    case "PRESET":
      return String(pf.preset).toLowerCase();
    default:
      return "all";
  }
}

/** Readable port match, e.g. "22, 80, 8000-8080" or "not 443". */
function describePorts(portFilter: Obj | undefined): string | undefined {
  if (!portFilter) return undefined;
  if (portFilter.type !== "PORTS") return "traffic-matching-list";
  const items = (portFilter.items as Obj[]) ?? [];
  const parts = items.map((it) =>
    it.type === "PORT_NUMBER_RANGE"
      ? `${it.start}-${it.stop}`
      : String(it.value)
  );
  const joined = parts.join(", ");
  return portFilter.matchOpposite ? `not ${joined}` : joined;
}

/** Readable source/destination traffic filter beyond the zone. */
function describeTrafficFilter(
  filter: Obj | undefined,
  zoneNames: Record<string, string>,
): string | undefined {
  if (!filter) return undefined;
  const opp = filter.matchOpposite ? "not " : "";
  switch (filter.type) {
    case "PORT":
      return `ports ${describePorts(filter.portFilter as Obj)}`;
    case "NETWORK": {
      const ids = ((filter.networkFilter as Obj)?.networkIds as string[]) ?? [];
      const names = ids.map((id) => zoneNames[id] ?? id).join(", ");
      return `${opp}networks ${names}`;
    }
    case "IP_ADDRESS": {
      const ipf = filter.ipAddressFilter as Obj | undefined;
      if (ipf?.type !== "IP_ADDRESSES") return `${opp}ip traffic-matching-list`;
      const vals = ((ipf.items as Obj[]) ?? []).map((i) => i.value).join(", ");
      return `${opp}ip ${vals}`;
    }
    case "MAC_ADDRESS":
      return `${opp}mac addresses`;
    case "REGION":
      return `${opp}region`;
    case "DOMAIN":
      return `${opp}domain`;
    case "APPLICATION":
      return `${opp}application`;
    case "APPLICATION_CATEGORY":
      return `${opp}app category`;
    default:
      return filter.type
        ? `${opp}${String(filter.type).toLowerCase()}`
        : undefined;
  }
}

function mapPolicy(
  p: Record<string, unknown>,
  zoneNames: Record<string, string>,
): z.infer<typeof PolicySchema> {
  const source = p.source as Obj | undefined;
  const dest = p.destination as Obj | undefined;
  const srcZoneId = source?.zoneId as string | undefined;
  const dstZoneId = dest?.zoneId as string | undefined;
  const scope = p.ipProtocolScope as Obj | undefined;
  const destFilter = dest?.trafficFilter as Obj | undefined;
  return {
    id: p.id as string,
    name: p.name as string,
    enabled: p.enabled as boolean,
    index: p.index as number,
    action: (p.action as Obj)?.type as string,
    sourceZoneId: srcZoneId,
    sourceZone: srcZoneId ? zoneNames[srcZoneId] : undefined,
    destinationZoneId: dstZoneId,
    destinationZone: dstZoneId ? zoneNames[dstZoneId] : undefined,
    ipVersion: scope?.ipVersion as string | undefined,
    protocol: describeProtocol(scope),
    sourceMatch: describeTrafficFilter(source?.trafficFilter as Obj, zoneNames),
    destinationMatch: describeTrafficFilter(destFilter, zoneNames),
    // NETWORK/IP filters can carry an additional port match alongside the main filter
    destinationPorts: describePorts(destFilter?.portFilter as Obj),
    connectionStates: (p.connectionStateFilter as string[]) ?? undefined,
    ipsecFilter: p.ipsecFilter as string | undefined,
    loggingEnabled: p.loggingEnabled as boolean | undefined,
    metadataOrigin: (p.metadata as Obj)?.origin as string | undefined,
  };
}

// ── IPv4 subnet matching (pure, unit-tested) ──────────────────────────────────

/** Parse a dotted-quad IPv4 string to a uint32, or null if malformed. */
export function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const octet = Number(p);
    if (octet > 255) return null;
    n = (n << 8) | octet;
  }
  return n >>> 0;
}

/** True if an IPv4 address falls within hostIp/prefixLength. */
export function ipv4InSubnet(
  ip: string,
  hostIp: string,
  prefix: number,
): boolean {
  const a = ipv4ToInt(ip);
  const b = ipv4ToInt(hostIp);
  if (a === null || b === null || prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  return (a & mask) === (b & mask);
}

// ── network domain name (pure, unit-tested) ───────────────────────────────────

/**
 * True for an RFC 1123 DNS name: dot-separated labels of 1–63 letters, digits
 * or hyphens, no label starting or ending with a hyphen, 253 chars at most.
 * A trailing dot (empty last label) is rejected.
 */
export function isValidDomainName(domain: string): boolean {
  if (domain.length === 0 || domain.length > 253) return false;
  return domain.split(".").every((label) =>
    /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)
  );
}

/**
 * Resolve requested network names to networks by exact, case-insensitive
 * name. Fails closed: an empty list, a blank name, an unknown name or a name
 * that matches more than one network throws, listing every problem at once,
 * before any change is made. Repeated names are selected once.
 */
export function selectNetworksByName<T extends { id: string; name: string }>(
  networks: T[],
  names: string[],
): T[] {
  if (names.length === 0) {
    throw new Error("networks must name at least one network");
  }
  const errors: string[] = [];
  const selected: T[] = [];
  const seen = new Set<string>();
  for (const raw of names) {
    const want = raw.trim().toLowerCase();
    if (!want) {
      errors.push("a network name is empty");
      continue;
    }
    if (seen.has(want)) continue;
    seen.add(want);
    const matches = networks.filter((n) => n.name.toLowerCase() === want);
    if (matches.length === 0) {
      errors.push(`unknown network "${raw}"`);
    } else if (matches.length > 1) {
      errors.push(
        `ambiguous network "${raw}" matches ${matches.length} networks ` +
          `(${matches.map((m) => `${m.name} ${m.id}`).join(", ")})`,
      );
    } else {
      selected.push(matches[0]);
    }
  }
  if (errors.length > 0) {
    throw new Error(
      `Network selection failed: ${errors.join("; ")}. Known networks: ` +
        networks.map((n) => n.name).join(", "),
    );
  }
  return selected;
}

/**
 * Fields the Get Network Details response carries that the Update Network
 * body does not accept (the update DTO is the details DTO minus these).
 */
const NETWORK_READ_ONLY_FIELDS = ["id", "metadata", "default"];

/** JSON path of the DHCP domain name inside a network details object. */
export const DOMAIN_NAME_PATH =
  "ipv4Configuration.dhcpConfiguration.domainName";

/** The planned domain-name change for one network. */
export interface NetworkDomainPlan {
  networkId: string;
  networkName: string;
  vlanId?: number;
  currentDomain?: string;
  newDomain: string;
  action: "change" | "unchanged";
  /** Full Update Network (PUT) body: the details with only domainName changed. */
  body: Obj;
}

/**
 * Plan a domain-name change from a Get Network Details object. Update Network
 * is a full replace (an omitted optional block such as dhcpConfiguration or
 * ipv6Configuration turns that feature off), so the body is the complete
 * current object with the read-only fields removed and only domainName set.
 * Throws unless the network is gateway-managed with a DHCP server, because
 * the domain name is a setting of the gateway's DHCP server.
 */
export function planNetworkDomain(
  detail: Obj,
  domain: string,
): NetworkDomainPlan {
  const name = String(detail.name ?? detail.id);
  if (detail.management !== "GATEWAY") {
    throw new Error(
      `Network "${name}" is ${detail.management}-managed; only GATEWAY ` +
        `networks have a gateway DHCP server with a domain name`,
    );
  }
  const dhcp = (detail.ipv4Configuration as Obj | undefined)
    ?.dhcpConfiguration as Obj | undefined;
  if (!dhcp || dhcp.mode !== "SERVER") {
    throw new Error(
      `Network "${name}" has no gateway DHCP server (DHCP mode ` +
        `${dhcp?.mode ?? "none"}); the domain name is a DHCP server setting`,
    );
  }
  const body = structuredClone(detail);
  for (const field of NETWORK_READ_ONLY_FIELDS) delete body[field];
  ((body.ipv4Configuration as Obj).dhcpConfiguration as Obj).domainName =
    domain;
  const currentDomain = dhcp.domainName as string | undefined;
  return {
    networkId: detail.id as string,
    networkName: name,
    vlanId: detail.vlanId as number | undefined,
    currentDomain,
    newDomain: domain,
    action: currentDomain === domain ? "unchanged" : "change",
    body,
  };
}

/**
 * Dotted paths whose values differ between two JSON values, skipping the
 * paths in `ignore`. Arrays compare by index; a key present on one side only
 * counts as a difference. Used to prove an update changed nothing else.
 */
export function diffPaths(
  a: unknown,
  b: unknown,
  ignore: Set<string> = new Set(),
  path = "",
): string[] {
  if (ignore.has(path)) return [];
  const isObj = (v: unknown): v is Obj =>
    typeof v === "object" && v !== null && !Array.isArray(v);
  const join = (key: string | number) => (path ? `${path}.${key}` : `${key}`);
  if (isObj(a) && isObj(b)) {
    const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
    return [...keys].flatMap((k) => {
      const p = join(k);
      if (ignore.has(p)) return [];
      if (!(k in a) || !(k in b)) return [p];
      return diffPaths(a[k], b[k], ignore, p);
    });
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return [path || "(root)"];
    return a.flatMap((v, i) => diffPaths(v, b[i], ignore, join(i)));
  }
  return a === b ? [] : [path || "(root)"];
}

// ── local DNS A records (pure, unit-tested) ───────────────────────────────────

/** One requested local A record: fully qualified name → IPv4 address. */
export interface DnsRecordRequest {
  name: string;
  ipv4Address: string;
}

/** The planned change for one local A record. */
export interface DnsARecordPlan {
  name: string;
  ipv4Address: string;
  ttlSeconds: number;
  action: "create" | "update" | "unchanged";
  policyId?: string;
  currentIpv4Address?: string;
  currentTtlSeconds?: number;
  currentEnabled?: boolean;
  /** Existing DNS policy object (update/unchanged only). */
  before?: Obj;
  /** Full Create/Update DNS Policy body. */
  body: Obj;
}

/** Fields of a DNS policy that the create/update body does not accept. */
const DNS_POLICY_READ_ONLY_FIELDS = ["id", "metadata"];

/** Record types that cannot share a name with an A record. */
const DNS_CONFLICTING_TYPES = new Set(["CNAME_RECORD", "FORWARD_DOMAIN"]);

/**
 * Plan local A records against the site's existing DNS policies. Fails
 * closed, listing every problem at once before any change: an invalid name
 * or IPv4 address, a name requested twice, a name that already has a CNAME
 * or forward-domain policy, or a name with more than one A record. A name
 * with no A record is created; one A record is updated in place (full body,
 * only address, TTL and enabled changed) unless it already matches.
 */
export function planDnsARecords(
  existing: Obj[],
  requests: DnsRecordRequest[],
  ttlSeconds: number,
): DnsARecordPlan[] {
  if (requests.length === 0) {
    throw new Error("records must list at least one record");
  }
  const errors: string[] = [];
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 0 || ttlSeconds > 86400) {
    errors.push(`ttlSeconds ${ttlSeconds} is not an integer from 0 to 86400`);
  }
  const plans: DnsARecordPlan[] = [];
  const seen = new Set<string>();
  for (const req of requests) {
    const name = req.name.trim().toLowerCase();
    const ip = req.ipv4Address.trim();
    if (!isValidDomainName(name) || name.length > 127) {
      errors.push(`"${req.name}" is not a valid DNS name (127 chars max)`);
      continue;
    }
    if (ipv4ToInt(ip) === null) {
      errors.push(`"${req.ipv4Address}" for ${name} is not an IPv4 address`);
      continue;
    }
    if (seen.has(name)) {
      errors.push(`${name} is requested more than once`);
      continue;
    }
    seen.add(name);

    const same = existing.filter((p) =>
      String(p.domain ?? "").toLowerCase() === name
    );
    const conflicts = same.filter((p) =>
      DNS_CONFLICTING_TYPES.has(String(p.type))
    );
    const aRecords = same.filter((p) => p.type === "A_RECORD");
    if (conflicts.length > 0) {
      errors.push(
        `${name} already has a ${
          conflicts.map((p) => `${p.type} ${p.id}`).join(", ")
        } policy`,
      );
      continue;
    }
    if (aRecords.length > 1) {
      errors.push(
        `${name} has ${aRecords.length} A records ` +
          `(${aRecords.map((p) => `${p.ipv4Address} ${p.id}`).join(", ")})`,
      );
      continue;
    }

    if (aRecords.length === 0) {
      plans.push({
        name,
        ipv4Address: ip,
        ttlSeconds,
        action: "create",
        body: {
          type: "A_RECORD",
          enabled: true,
          domain: name,
          ipv4Address: ip,
          ttlSeconds,
        },
      });
      continue;
    }

    const before = aRecords[0];
    const body = structuredClone(before);
    for (const field of DNS_POLICY_READ_ONLY_FIELDS) delete body[field];
    Object.assign(body, { enabled: true, ipv4Address: ip, ttlSeconds });
    const matches = before.ipv4Address === ip &&
      before.ttlSeconds === ttlSeconds && before.enabled === true;
    plans.push({
      name,
      ipv4Address: ip,
      ttlSeconds,
      action: matches ? "unchanged" : "update",
      policyId: before.id as string,
      currentIpv4Address: before.ipv4Address as string | undefined,
      currentTtlSeconds: before.ttlSeconds as number | undefined,
      currentEnabled: before.enabled as boolean | undefined,
      before,
      body,
    });
  }
  if (errors.length > 0) {
    throw new Error(`DNS record plan failed: ${errors.join("; ")}`);
  }
  return plans;
}

/** A network's IPv4 subnet plus the identity we map clients onto. */
interface Subnet {
  networkId: string;
  networkName: string;
  vlanId?: number;
  hostIp: string;
  prefix: number;
}

/** Resolve the vlan/network a client IP belongs to, if any. */
function matchSubnet(
  ip: string | undefined,
  subnets: Subnet[],
): Subnet | undefined {
  if (!ip) return undefined;
  return subnets.find((s) => ipv4InSubnet(ip, s.hostIp, s.prefix));
}

function mapClient(
  c: Record<string, unknown>,
  subnets: Subnet[],
): z.infer<typeof ClientSchema> {
  const ip = c.ipAddress as string | undefined;
  const match = matchSubnet(ip, subnets);
  return {
    id: c.id as string,
    name: c.name as string,
    type: c.type as string,
    macAddress: c.macAddress as string | undefined,
    ipAddress: ip,
    connectedAt: c.connectedAt as string | undefined,
    accessType: (c.access as Record<string, unknown>)?.type as
      | string
      | undefined,
    uplinkDeviceId: c.uplinkDeviceId as string | undefined,
    vlanId: match?.vlanId,
    networkId: match?.networkId,
    networkName: match?.networkName,
  };
}

/** Network identity for VLAN lookups, keyed by network id. */
type NetworkLookup = Record<string, { name: string; vlanId?: number }>;

function mapWifi(
  w: Record<string, unknown>,
  networks: NetworkLookup,
  defaultNet: { id: string; name: string; vlanId?: number } | undefined,
): z.infer<typeof WifiSchema> {
  const netRef = w.network as Record<string, unknown> | undefined;
  const refType = (netRef?.type as string) ?? "NATIVE";
  // SPECIFIC binds an explicit networkId; NATIVE rides the default/untagged network.
  const specificId = netRef?.networkId as string | undefined;
  const match = specificId
    ? { id: specificId, ...networks[specificId] }
    : defaultNet;
  return {
    id: w.id as string,
    name: w.name as string,
    enabled: w.enabled as boolean,
    type: w.type as string,
    security: (w.securityConfiguration as Record<string, unknown>)?.type as
      | string
      | undefined,
    networkRef: refType,
    networkId: match?.id,
    networkName: match?.name,
    vlanId: match?.vlanId,
    metadataOrigin: (w.metadata as Record<string, unknown>)?.origin as
      | string
      | undefined,
  };
}

function mapConsole(h: Record<string, unknown>): z.infer<typeof ConsoleSchema> {
  const hardware = (h.reportedState as Record<string, unknown>)?.hardware as
    | Record<string, unknown>
    | undefined;
  return {
    id: h.id as string,
    shortname: hardware?.shortname as string | undefined,
    name: hardware?.name as string | undefined,
  };
}

/** A console to scan: its proxy base URL plus identity for labelling output. */
interface Target {
  base: string;
  target: string;
  consoleId?: string;
  consoleShortname?: string;
  /** Extra certificate to trust (local mode only). */
  caCert?: string;
}

function proxyBase(consoleId: string): string {
  return `${CLOUD_BASE}/v1/connector/consoles/${consoleId}/proxy/network/integration`;
}

/** Resolve the set of consoles to scan from the configured mode + args. */
async function resolveTargets(g: GlobalArgs): Promise<Target[]> {
  // Validates caCert first, so a bad or misplaced one fails before any call.
  const caCert = resolveCaCert(g);
  if (g.mode === "local") {
    if (!g.host) {
      throw new Error("mode='local' requires 'host' (the console IP/hostname)");
    }
    return [{
      base: `https://${g.host}/proxy/network/integration`,
      target: g.host,
      caCert,
    }];
  }

  // cloud
  if (g.consoleId) {
    return [{
      base: proxyBase(g.consoleId),
      target: g.consoleId,
      consoleId: g.consoleId,
    }];
  }

  // cloud, no consoleId → discover and fan out over every console
  const hostsData = await apiGet(`${CLOUD_BASE}/v1/hosts`, g.apiKey);
  const consoles = ((hostsData.data ?? []) as Array<Record<string, unknown>>)
    .map(mapConsole);
  if (consoles.length === 0) {
    throw new Error("No consoles visible to this cloud API key");
  }
  return consoles.map((c) => ({
    base: proxyBase(c.id),
    target: c.id,
    consoleId: c.id,
    consoleShortname: c.shortname,
  }));
}

/**
 * Resolve exactly one console for a write method, narrowed by consoleId when
 * given. Writes never fan out over consoles by accident.
 */
async function resolveSingleTarget(
  g: GlobalArgs,
  method: string,
  consoleId?: string,
): Promise<Target> {
  let targets = await resolveTargets(g);
  if (consoleId) targets = targets.filter((t) => t.consoleId === consoleId);
  if (targets.length !== 1) {
    throw new Error(
      `${method} needs exactly one target console; resolved ` +
        `${targets.length}. Pass consoleId to disambiguate.`,
    );
  }
  return targets[0];
}

/**
 * Resolve exactly one site on a console for a write method: the given siteId,
 * or the only site when the console has one.
 */
async function resolveSingleSite(
  t: Target,
  apiKey: string,
  siteId?: string,
): Promise<{ siteId: string; siteName: string }> {
  const sites = await fetchAllPages(t.base, "/v1/sites", apiKey, t.caCert);
  const candidates = siteId ? sites.filter((s) => s.id === siteId) : sites;
  if (candidates.length !== 1) {
    throw new Error(
      siteId
        ? `Site ${siteId} not found on ${t.target}`
        : `${t.target} has ${sites.length} sites; pass siteId (one of ` +
          `${sites.map((s) => `${s.name} ${s.id}`).join(", ")})`,
    );
  }
  const id = candidates[0].id as string;
  return { siteId: id, siteName: (candidates[0].name as string) ?? id };
}

/**
 * Data instance name for a site. Uses the bare site name for single-target
 * scans so local and cloud modes converge on the same instance; only appends
 * the console identity as a suffix when fanning out over multiple consoles,
 * where it is needed to keep same-named sites from colliding. Suffix (not
 * prefix) so a site's instances sort together, e.g. "Default", "Default-UDMPRO".
 */
function instanceName(
  t: Target,
  siteName: string,
  disambiguate: boolean,
): string {
  const suffix = disambiguate ? (t.consoleShortname ?? t.consoleId) : undefined;
  const raw = suffix ? `${siteName}-${suffix}` : siteName;
  return raw.replace(/[^A-Za-z0-9._-]/g, "-");
}

// ── model ─────────────────────────────────────────────────────────────────────

interface Ctx {
  globalArgs: GlobalArgs;
  logger: {
    info: (message: string, props?: Record<string, unknown>) => void;
  };
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

export const model = {
  type: "@dmc/unifi-networks",
  version: "2026.11.09.1",
  globalArguments: GlobalArgsSchema,
  upgrades: [
    {
      toVersion: "2026.11.09.1",
      description:
        "Remove verifyTls: the curl -k transport is gone, and a console " +
        "with a self-signed certificate is trusted with caCert instead. " +
        "Adds setNetworkDomain and setDnsRecords.",
      upgradeAttributes: (old: Record<string, unknown>) => {
        const { verifyTls: _verifyTls, ...rest } = old;
        return rest;
      },
    },
  ],
  resources: {
    consoles: {
      description: "UniFi consoles visible to the cloud API key",
      schema: ConsolesSchema,
      lifetime: "infinite",
      garbageCollection: 5,
    },
    siteNetworks: {
      description: "Networks (VLANs) per UniFi site",
      schema: SiteNetworksSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    siteFirewall: {
      description: "Firewall zones and policies per UniFi site",
      schema: SiteFirewallSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    siteClients: {
      description:
        "Connected clients per UniFi site, mapped to VLAN by IP subnet",
      schema: SiteClientsSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    siteWifi: {
      description:
        "WiFi broadcasts (SSIDs) per UniFi site, mapped to VLAN by network",
      schema: SiteWifiSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    networkDomainChange: {
      description:
        "Plan or result of a setNetworkDomain run: per network, the current " +
        "and new DHCP domain name and whether it was applied and verified",
      schema: NetworkDomainChangeSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    dnsRecordChange: {
      description:
        "Plan or result of a setDnsRecords run: per record, the current and " +
        "new address and TTL and whether it was applied and verified",
      schema: DnsRecordChangeSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  methods: {
    consoles: {
      description:
        "List UniFi consoles visible to the cloud API key (cloud mode only). " +
        "Use to find a consoleId to pin.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = context.globalArgs;
        if (g.mode !== "cloud") {
          throw new Error(
            "The 'consoles' method requires mode='cloud' (console discovery " +
              "is a cloud API feature)",
          );
        }
        context.logger.info("consoles: listing consoles visible to the key");
        const hostsData = await apiGet(`${CLOUD_BASE}/v1/hosts`, g.apiKey);
        const consoles = ((hostsData.data ?? []) as Array<
          Record<string, unknown>
        >).map(mapConsole);

        const handle = await context.writeResource("consoles", "consoles", {
          fetchedAt: new Date().toISOString(),
          consoleCount: consoles.length,
          consoles,
        });
        context.logger.info("consoles: found {count} console(s)", {
          count: consoles.length,
        });
        return { dataHandles: [handle] };
      },
    },

    scan: {
      description:
        "Fetch all networks/VLANs. Local mode scans the configured host; cloud " +
        "mode scans the given consoleId, or every visible console when omitted.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = context.globalArgs;
        const targets = await resolveTargets(g);
        context.logger.info("{method}: scanning {count} console(s)", {
          method: "scan",
          count: targets.length,
        });
        const disambiguate = targets.length > 1;
        const dataHandles = [];

        for (const t of targets) {
          const sites = await fetchAllPages(
            t.base,
            "/v1/sites",
            g.apiKey,
            t.caCert,
          );

          for (const site of sites) {
            const siteId = site.id as string;
            const siteName = (site.name as string) ?? siteId;
            const networks = await fetchAllPages(
              t.base,
              `/v1/sites/${siteId}/networks`,
              g.apiKey,
              t.caCert,
            );

            const handle = await context.writeResource(
              "siteNetworks",
              instanceName(t, siteName, disambiguate),
              {
                scannedAt: new Date().toISOString(),
                mode: g.mode,
                target: t.target,
                consoleId: t.consoleId,
                consoleShortname: t.consoleShortname,
                siteId,
                siteName,
                networkCount: networks.length,
                networks: networks.map(mapNetwork),
              },
            );
            dataHandles.push(handle);
          }
        }

        context.logger.info("{method}: wrote {count} site snapshot(s)", {
          method: "scan",
          count: dataHandles.length,
        });
        return { dataHandles };
      },
    },

    scanFirewall: {
      description:
        "Fetch firewall zones and policies per site, joined so policies show " +
        "human-readable source/destination zone names. Same mode/fan-out rules as scan.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = context.globalArgs;
        const targets = await resolveTargets(g);
        context.logger.info("{method}: scanning {count} console(s)", {
          method: "scanFirewall",
          count: targets.length,
        });
        const disambiguate = targets.length > 1;
        const dataHandles = [];

        for (const t of targets) {
          const sites = await fetchAllPages(
            t.base,
            "/v1/sites",
            g.apiKey,
            t.caCert,
          );

          for (const site of sites) {
            const siteId = site.id as string;
            const siteName = (site.name as string) ?? siteId;

            const rawZones = await fetchAllPages(
              t.base,
              `/v1/sites/${siteId}/firewall/zones`,
              g.apiKey,
              t.caCert,
            );
            const rawPolicies = await fetchAllPages(
              t.base,
              `/v1/sites/${siteId}/firewall/policies`,
              g.apiKey,
              t.caCert,
            );

            const zones = rawZones.map(mapZone);
            const zoneNames: Record<string, string> = {};
            for (const z_ of zones) zoneNames[z_.id] = z_.name;

            const policies = rawPolicies
              .map((p) => mapPolicy(p, zoneNames))
              .sort((a, b) => a.index - b.index);

            const handle = await context.writeResource(
              "siteFirewall",
              instanceName(t, siteName, disambiguate),
              {
                scannedAt: new Date().toISOString(),
                mode: g.mode,
                target: t.target,
                consoleId: t.consoleId,
                consoleShortname: t.consoleShortname,
                siteId,
                siteName,
                zoneCount: zones.length,
                policyCount: policies.length,
                zones,
                policies,
              },
            );
            dataHandles.push(handle);
          }
        }

        context.logger.info("{method}: wrote {count} site snapshot(s)", {
          method: "scanFirewall",
          count: dataHandles.length,
        });
        return { dataHandles };
      },
    },

    scanWifi: {
      description:
        "Fetch WiFi broadcasts (SSIDs) per site and map each to its VLAN via " +
        "its network reference (SPECIFIC → networkId; NATIVE → default/untagged). " +
        "Same mode/fan-out rules as scan.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = context.globalArgs;
        const targets = await resolveTargets(g);
        context.logger.info("{method}: scanning {count} console(s)", {
          method: "scanWifi",
          count: targets.length,
        });
        const disambiguate = targets.length > 1;
        const dataHandles = [];

        for (const t of targets) {
          const sites = await fetchAllPages(
            t.base,
            "/v1/sites",
            g.apiKey,
            t.caCert,
          );

          for (const site of sites) {
            const siteId = site.id as string;
            const siteName = (site.name as string) ?? siteId;

            const networks = await fetchAllPages(
              t.base,
              `/v1/sites/${siteId}/networks`,
              g.apiKey,
              t.caCert,
            );
            const netLookup: NetworkLookup = {};
            let defaultNet:
              | { id: string; name: string; vlanId?: number }
              | undefined;
            for (const n of networks) {
              const entry = {
                name: n.name as string,
                vlanId: n.vlanId as number | undefined,
              };
              netLookup[n.id as string] = entry;
              if (n.default === true) {
                defaultNet = { id: n.id as string, ...entry };
              }
            }

            const rawWifis = await fetchAllPages(
              t.base,
              `/v1/sites/${siteId}/wifi/broadcasts`,
              g.apiKey,
              t.caCert,
            );
            const wifis = rawWifis.map((w) =>
              mapWifi(w, netLookup, defaultNet)
            );

            const handle = await context.writeResource(
              "siteWifi",
              instanceName(t, siteName, disambiguate),
              {
                scannedAt: new Date().toISOString(),
                mode: g.mode,
                target: t.target,
                consoleId: t.consoleId,
                consoleShortname: t.consoleShortname,
                siteId,
                siteName,
                wifiCount: wifis.length,
                wifis,
              },
            );
            dataHandles.push(handle);
          }
        }

        context.logger.info("{method}: wrote {count} site snapshot(s)", {
          method: "scanWifi",
          count: dataHandles.length,
        });
        return { dataHandles };
      },
    },

    scanClients: {
      description:
        "Fetch connected clients per site and map each to its VLAN/network by " +
        "matching the client IP against network subnets (clients carry no " +
        "networkId). Same mode/fan-out rules as scan.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = context.globalArgs;
        const targets = await resolveTargets(g);
        context.logger.info("{method}: scanning {count} console(s)", {
          method: "scanClients",
          count: targets.length,
        });
        const disambiguate = targets.length > 1;
        const dataHandles = [];

        for (const t of targets) {
          const sites = await fetchAllPages(
            t.base,
            "/v1/sites",
            g.apiKey,
            t.caCert,
          );

          for (const site of sites) {
            const siteId = site.id as string;
            const siteName = (site.name as string) ?? siteId;

            // Build the subnet table: list networks, then fetch each detail for
            // its IPv4 gateway/prefix (only the detail endpoint exposes subnets).
            const networks = await fetchAllPages(
              t.base,
              `/v1/sites/${siteId}/networks`,
              g.apiKey,
              t.caCert,
            );
            const subnets: Subnet[] = [];
            for (const n of networks) {
              const detail = await apiGet(
                `${t.base}/v1/sites/${siteId}/networks/${n.id}`,
                g.apiKey,
                t.caCert,
              );
              const ipv4 = detail.ipv4Configuration as
                | Record<string, unknown>
                | undefined;
              const hostIp = ipv4?.hostIpAddress as string | undefined;
              const prefix = ipv4?.prefixLength as number | undefined;
              if (hostIp && prefix != null) {
                subnets.push({
                  networkId: n.id as string,
                  networkName: n.name as string,
                  vlanId: n.vlanId as number | undefined,
                  hostIp,
                  prefix,
                });
              }
            }

            const rawClients = await fetchAllPages(
              t.base,
              `/v1/sites/${siteId}/clients`,
              g.apiKey,
              t.caCert,
            );
            const clients = rawClients.map((c) => mapClient(c, subnets));

            // Aggregate counts per network (plus an unmapped bucket)
            const counts = new Map<
              string,
              z.infer<typeof VlanClientCountSchema>
            >();
            let unmapped = 0;
            for (const c of clients) {
              if (!c.networkName) {
                unmapped++;
                continue;
              }
              const key = c.networkName;
              const entry = counts.get(key) ??
                {
                  vlanId: c.vlanId,
                  networkName: c.networkName,
                  clientCount: 0,
                };
              entry.clientCount++;
              counts.set(key, entry);
            }
            const byVlan = [...counts.values()].sort(
              (a, b) => (a.vlanId ?? 0) - (b.vlanId ?? 0),
            );

            const handle = await context.writeResource(
              "siteClients",
              instanceName(t, siteName, disambiguate),
              {
                scannedAt: new Date().toISOString(),
                mode: g.mode,
                target: t.target,
                consoleId: t.consoleId,
                consoleShortname: t.consoleShortname,
                siteId,
                siteName,
                clientCount: clients.length,
                unmappedCount: unmapped,
                byVlan,
                clients,
              },
            );
            dataHandles.push(handle);
          }
        }

        context.logger.info("{method}: wrote {count} site snapshot(s)", {
          method: "scanClients",
          count: dataHandles.length,
        });
        return { dataHandles };
      },
    },

    deletePolicy: {
      description:
        "Delete a single user-defined firewall policy by ID. Verifies the " +
        "policy exists and is USER_DEFINED before deleting (refuses derived/" +
        "system rules); UniFi removes the auto-generated Return companion. " +
        "Resolves to exactly one console — pass consoleId to disambiguate.",
      arguments: z.object({
        siteId: z.string().describe("Site ID containing the policy"),
        policyId: z.string().describe("Firewall policy ID to delete"),
        consoleId: z.string().optional().describe(
          "Console to target when the key sees more than one",
        ),
      }),
      execute: async (
        args: { siteId: string; policyId: string; consoleId?: string },
        context: Ctx,
      ) => {
        const g = context.globalArgs;
        const t = await resolveSingleTarget(g, "deletePolicy", args.consoleId);
        const policyUrl =
          `${t.base}/v1/sites/${args.siteId}/firewall/policies/${args.policyId}`;

        // Verify before destroying (rule #5): must exist and be user-defined
        const policy = await apiGet(policyUrl, g.apiKey, t.caCert);
        const origin = (policy.metadata as Obj)?.origin;
        if (origin !== "USER_DEFINED") {
          throw new Error(
            `Refusing to delete policy ${args.policyId} ("${policy.name}"): ` +
              `origin is ${origin}, only USER_DEFINED policies are deletable`,
          );
        }

        context.logger.info("deletePolicy: deleting {policyId} ({name})", {
          policyId: args.policyId,
          name: policy.name,
        });
        await apiDelete(policyUrl, g.apiKey, t.caCert);
        context.logger.info("deletePolicy: deleted {policyId}", {
          policyId: args.policyId,
        });
        return { dataHandles: [] };
      },
    },

    setNetworkDomain: {
      description:
        "Set the DHCP domain name (UniFi 'Domain Name') on the named networks " +
        "of one site in a single run. Fails closed: unknown or ambiguous " +
        "names, an invalid domain, or a network without a gateway DHCP " +
        "server stop the run before any change. dryRun defaults to true and " +
        "only records each current and new value. A live run sends the full " +
        "current network with only domainName changed, then re-reads each " +
        "network and fails if anything else changed.",
      arguments: z.object({
        domain: z.string().describe(
          "Domain name to set, e.g. lan.example (stored lowercase)",
        ),
        networks: z.array(z.string()).min(1).describe(
          "Network names to change (exact match, case-insensitive)",
        ),
        dryRun: z.boolean().default(true).describe(
          "true (default): change nothing, record the plan. false: apply it.",
        ),
        siteId: z.string().optional().describe(
          "Site to change; required when the console has more than one site",
        ),
        consoleId: z.string().optional().describe(
          "Console to target when the key sees more than one",
        ),
      }),
      execute: async (
        args: {
          domain: string;
          networks: string[];
          dryRun?: boolean;
          siteId?: string;
          consoleId?: string;
        },
        context: Ctx,
      ) => {
        const g = context.globalArgs;
        // Anything but an explicit false is a dry run.
        const dryRun = args.dryRun !== false;
        const domain = args.domain.trim().toLowerCase();
        if (!isValidDomainName(domain)) {
          throw new Error(`"${args.domain}" is not a valid DNS domain name`);
        }

        const t = await resolveSingleTarget(
          g,
          "setNetworkDomain",
          args.consoleId,
        );

        const { siteId, siteName } = await resolveSingleSite(
          t,
          g.apiKey,
          args.siteId,
        );
        const netBase = `${t.base}/v1/sites/${siteId}/networks`;

        // Resolve and plan every network before any write, so a bad name or
        // an unsupported network changes nothing.
        const listed = await fetchAllPages(
          t.base,
          `/v1/sites/${siteId}/networks`,
          g.apiKey,
          t.caCert,
        );
        const selected = selectNetworksByName(
          listed.map((n) => ({ id: n.id as string, name: n.name as string })),
          args.networks,
        );
        const planned: Array<{ before: Obj; plan: NetworkDomainPlan }> = [];
        for (const n of selected) {
          const before = await apiGet(
            `${netBase}/${n.id}`,
            g.apiKey,
            t.caCert,
          );
          planned.push({ before, plan: planNetworkDomain(before, domain) });
        }

        const results: Array<z.infer<typeof NetworkDomainResultSchema>> =
          planned.map(({ plan }) => ({
            networkId: plan.networkId,
            networkName: plan.networkName,
            vlanId: plan.vlanId,
            currentDomain: plan.currentDomain,
            newDomain: plan.newDomain,
            action: plan.action,
            applied: false,
          }));

        const record = () =>
          context.writeResource(
            "networkDomainChange",
            instanceName(t, siteName, false),
            {
              ranAt: new Date().toISOString(),
              mode: g.mode,
              target: t.target,
              consoleId: t.consoleId,
              consoleShortname: t.consoleShortname,
              siteId,
              siteName,
              domain,
              dryRun,
              changeCount: results.filter((r) => r.action === "change").length,
              networks: results,
            },
          );

        context.logger.info(
          "setNetworkDomain: {changes} of {count} network(s) on site " +
            "{siteName} need domain {domain} (dryRun {dryRun})",
          {
            changes: results.filter((r) => r.action === "change").length,
            count: results.length,
            siteName,
            domain,
            dryRun,
          },
        );

        if (!dryRun) {
          for (const [i, { before, plan }] of planned.entries()) {
            if (plan.action === "unchanged") continue;
            const url = `${netBase}/${plan.networkId}`;
            context.logger.info(
              "setNetworkDomain: setting {network} from {current} to {domain}",
              {
                network: plan.networkName,
                current: plan.currentDomain || "(none)",
                domain,
              },
            );
            let after: Obj;
            try {
              await apiPut(url, g.apiKey, plan.body, t.caCert);
              results[i].applied = true;
              after = await apiGet(url, g.apiKey, t.caCert);
            } catch (e) {
              // Record which networks were already changed before failing.
              await record();
              throw e;
            }
            const stray = diffPaths(
              before,
              after,
              new Set([DOMAIN_NAME_PATH]),
            );
            const got = ((after.ipv4Configuration as Obj | undefined)
              ?.dhcpConfiguration as Obj | undefined)?.domainName;
            results[i].verified = stray.length === 0 && got === domain;
            if (!results[i].verified) {
              await record();
              throw new Error(
                `Network "${plan.networkName}" updated but verification ` +
                  `failed: domainName is ${got ?? "unset"}, other changed ` +
                  `fields: ${stray.join(", ") || "none"}. Stopped before ` +
                  `the remaining networks.`,
              );
            }
          }
        }

        const handle = await record();
        context.logger.info(
          "setNetworkDomain: done, {applied} network(s) changed and verified",
          { applied: results.filter((r) => r.applied).length },
        );
        return { dataHandles: [handle] };
      },
    },

    setDnsRecords: {
      description:
        "Create or update local DNS A records (UniFi DNS policies) on one " +
        "site in a single run, e.g. names for hosts with static addresses. " +
        "Fails closed: an invalid name or address, a repeated name, a name " +
        "with a CNAME or forward-domain policy, or a name with more than one " +
        "A record stops the run before any change. dryRun defaults to true " +
        "and only records each current and new value. A live run creates " +
        "missing records, updates differing ones in place (full body, only " +
        "address, TTL and enabled changed), then re-reads all DNS policies " +
        "and fails unless each name has exactly the requested A record.",
      arguments: z.object({
        records: z.array(z.object({
          name: z.string().describe(
            "Fully qualified name, e.g. fort.lan.example",
          ),
          ipv4Address: z.string().describe("IPv4 address, e.g. 192.0.2.50"),
        })).min(1).describe("A records to set"),
        ttlSeconds: z.number().int().min(0).max(86400).default(3600).describe(
          "TTL for every record in this run (default 3600)",
        ),
        dryRun: z.boolean().default(true).describe(
          "true (default): change nothing, record the plan. false: apply it.",
        ),
        siteId: z.string().optional().describe(
          "Site to change; required when the console has more than one site",
        ),
        consoleId: z.string().optional().describe(
          "Console to target when the key sees more than one",
        ),
      }),
      execute: async (
        args: {
          records: DnsRecordRequest[];
          ttlSeconds?: number;
          dryRun?: boolean;
          siteId?: string;
          consoleId?: string;
        },
        context: Ctx,
      ) => {
        const g = context.globalArgs;
        // Anything but an explicit false is a dry run.
        const dryRun = args.dryRun !== false;
        const ttl = args.ttlSeconds ?? 3600;

        const t = await resolveSingleTarget(g, "setDnsRecords", args.consoleId);
        const { siteId, siteName } = await resolveSingleSite(
          t,
          g.apiKey,
          args.siteId,
        );
        const dnsPath = `/v1/sites/${siteId}/dns/policies`;

        // Plan every record before any write.
        const existing = await fetchAllPages(
          t.base,
          dnsPath,
          g.apiKey,
          t.caCert,
        );
        const plans = planDnsARecords(existing, args.records, ttl);

        const results: Array<z.infer<typeof DnsRecordResultSchema>> = plans
          .map((p) => ({
            name: p.name,
            ipv4Address: p.ipv4Address,
            ttlSeconds: p.ttlSeconds,
            action: p.action,
            policyId: p.policyId,
            currentIpv4Address: p.currentIpv4Address,
            currentTtlSeconds: p.currentTtlSeconds,
            currentEnabled: p.currentEnabled,
            applied: false,
          }));

        const record = () =>
          context.writeResource(
            "dnsRecordChange",
            instanceName(t, siteName, false),
            {
              ranAt: new Date().toISOString(),
              mode: g.mode,
              target: t.target,
              consoleId: t.consoleId,
              consoleShortname: t.consoleShortname,
              siteId,
              siteName,
              dryRun,
              changeCount: results.filter((r) => r.action !== "unchanged")
                .length,
              records: results,
            },
          );

        context.logger.info(
          "setDnsRecords: {changes} of {count} record(s) on site {siteName} " +
            "need a change (dryRun {dryRun})",
          {
            changes: results.filter((r) => r.action !== "unchanged").length,
            count: results.length,
            siteName,
            dryRun,
          },
        );

        if (!dryRun && results.some((r) => r.action !== "unchanged")) {
          let after: Obj[];
          try {
            for (const [i, p] of plans.entries()) {
              if (p.action !== "unchanged") {
                context.logger.info("setDnsRecords: {action} {name} -> {ip}", {
                  action: p.action,
                  name: p.name,
                  ip: p.ipv4Address,
                });
              }
              if (p.action === "create") {
                const created = await apiPost(
                  `${t.base}${dnsPath}`,
                  g.apiKey,
                  p.body,
                  t.caCert,
                );
                results[i].policyId = created.id as string | undefined;
                results[i].applied = true;
              } else if (p.action === "update") {
                await apiPut(
                  `${t.base}${dnsPath}/${p.policyId}`,
                  g.apiKey,
                  p.body,
                  t.caCert,
                );
                results[i].applied = true;
              }
            }
            // Verify all records with one re-read of the site's DNS policies.
            after = await fetchAllPages(t.base, dnsPath, g.apiKey, t.caCert);
          } catch (e) {
            // Record which records were already written before failing.
            await record();
            throw e;
          }

          const failures: string[] = [];
          for (const [i, p] of plans.entries()) {
            const found = after.filter((x) =>
              x.type === "A_RECORD" &&
              String(x.domain ?? "").toLowerCase() === p.name
            );
            const one = found.length === 1 ? found[0] : undefined;
            const stray = one && p.before
              ? diffPaths(
                p.before,
                one,
                new Set(["ipv4Address", "ttlSeconds", "enabled"]),
              )
              : [];
            const ok = one !== undefined &&
              one.ipv4Address === p.ipv4Address &&
              one.ttlSeconds === p.ttlSeconds && one.enabled === true &&
              stray.length === 0;
            if (one) results[i].policyId = one.id as string;
            if (p.action === "unchanged" && ok) continue;
            results[i].verified = ok;
            if (!ok) {
              failures.push(
                `${p.name}: found ` +
                  (found.length === 1
                    ? `${one?.ipv4Address} ttl ${one?.ttlSeconds} enabled ${one?.enabled}`
                    : `${found.length} A records`) +
                  (stray.length
                    ? `, other changed fields: ${stray.join(", ")}`
                    : ""),
              );
            }
          }
          if (failures.length > 0) {
            await record();
            throw new Error(
              `DNS records written but verification failed: ` +
                failures.join("; "),
            );
          }
        }

        const handle = await record();
        context.logger.info(
          "setDnsRecords: done, {applied} record(s) written and verified",
          { applied: results.filter((r) => r.applied).length },
        );
        return { dataHandles: [handle] };
      },
    },
  },
  checks: {
    "console-reachable": {
      description:
        "Confirm the target console is reachable and the API key authenticates " +
        "before a destructive change. Labelled 'live' (makes an API call) so it " +
        "can be skipped with --skip-check-label live.",
      labels: ["live"],
      appliesTo: ["deletePolicy", "setNetworkDomain", "setDnsRecords"],
      // Checks receive globalArgs but not the per-call method arguments, so this
      // verifies connectivity/auth to the resolved target(s); the policy-specific
      // USER_DEFINED guard stays inline in deletePolicy where policyId is known.
      execute: async (context: { globalArgs: GlobalArgs }) => {
        const g = context.globalArgs;
        try {
          const targets = await resolveTargets(g);
          const t = targets[0];
          await apiGet(`${t.base}/v1/info`, g.apiKey, t.caCert);
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `Console not reachable or API key rejected: ${
                e instanceof Error ? e.message : String(e)
              }`,
            ],
          };
        }
      },
    },
  },
};
