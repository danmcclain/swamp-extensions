/**
 * Unit tests for the pure helpers of the unifi-networks extension: TLS
 * settings and error text, response handling, IPv4 subnet matching, and the
 * planning helpers behind setNetworkDomain and setDnsRecords. Method-level tests are in unifi_networks_methods_test.ts.
 *
 * Run with: deno test extensions/models/unifi_networks_test.ts
 */

import { assertEquals, assertThrows } from "jsr:@std/assert@1";
import {
  describeFetchError,
  diffPaths,
  DOMAIN_NAME_PATH,
  finalizeResponse,
  ipv4InSubnet,
  ipv4ToInt,
  isValidDomainName,
  planDnsARecords,
  planNetworkDomain,
  resolveCaCert,
  selectNetworksByName,
} from "./unifi_networks.ts";

// ── resolveCaCert / describeFetchError ────────────────────────────────────────

/** Shape-only test PEM (a throwaway self-signed certificate). */
const TEST_PEM = `-----BEGIN CERTIFICATE-----
MIIBaDCCAQ6gAwIBAgIUbu1Fr6CHvl3fkKU2hIGra2ykZYYwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPY29uc29sZS5leGFtcGxlMB4XDTI2MTEwOTE3MDk0NloXDTM2
MTEwNjE3MDk0NlowGjEYMBYGA1UEAwwPY29uc29sZS5leGFtcGxlMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEn6V7iXeyfqy46W8m/JbhQvJ5raD0kYAjto2roH1u
Z6OsQlDO5awrkqJhyAOIXjVNCgTAhOAJv5jpFTUz5+ftiKMyMDAwHQYDVR0OBBYE
FBPDw1Cbd+xSSLsmTx6amkK1eHJ8MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0E
AwIDSAAwRQIgRElDBVW5kQEdBuzNpeZvK1Y4myzCwx6OGQ0ZvV1pam4CIQCSIXb9
qnADfuE2S5KKmzPGJ22HmGV1tjmNY84i58ktig==
-----END CERTIFICATE-----
`;

Deno.test("resolveCaCert: no caCert means system roots only", () => {
  assertEquals(resolveCaCert({ mode: "local" }), undefined);
  assertEquals(resolveCaCert({ mode: "cloud" }), undefined);
});

Deno.test("resolveCaCert: accepts one or more PEM certificates in local mode", () => {
  assertEquals(resolveCaCert({ mode: "local", caCert: TEST_PEM }), TEST_PEM);
  const two = `${TEST_PEM}\n${TEST_PEM}`;
  assertEquals(resolveCaCert({ mode: "local", caCert: two }), two);
});

Deno.test("resolveCaCert: fails closed on a bad or misplaced caCert", () => {
  assertThrows(
    () => resolveCaCert({ mode: "local", caCert: "not a cert" }),
    Error,
    "not a PEM certificate bundle",
  );
  assertThrows(
    () => resolveCaCert({ mode: "local", caCert: "" }),
    Error,
    "not a PEM certificate bundle",
  );
  assertThrows(
    () =>
      resolveCaCert({
        mode: "local",
        caCert: '${{ vault.get(infra, "x") }}',
      }),
    Error,
    "unresolved",
  );
  assertThrows(
    () => resolveCaCert({ mode: "cloud", caCert: TEST_PEM }),
    Error,
    "only to mode='local'",
  );
});

Deno.test("describeFetchError: TLS failure without caCert says to set it", () => {
  const err = describeFetchError(
    "GET",
    "https://console.example/x",
    new TypeError(
      "client error (Connect): invalid peer certificate: UnknownIssuer",
    ),
    false,
  );
  assertEquals(err.message.includes("TLS check failed"), true);
  assertEquals(err.message.includes("set caCert"), true);
});

Deno.test("describeFetchError: TLS failure with caCert names the mismatch", () => {
  const err = describeFetchError(
    "GET",
    "https://console.example/x",
    new TypeError("invalid peer certificate: NotValidForName"),
    true,
  );
  assertEquals(err.message.includes("does not name the host"), true);
});

Deno.test("describeFetchError: CA certificate used as server certificate", () => {
  const err = describeFetchError(
    "GET",
    "https://console.example/x",
    new TypeError(
      "invalid peer certificate: Other(OtherError(CaUsedAsEndEntity))",
    ),
    true,
  );
  assertEquals(err.message.includes("CA:TRUE"), true);
  assertEquals(err.message.includes("server certificate (CA:FALSE)"), true);
});

Deno.test("describeFetchError: other failures keep the method, URL and cause", () => {
  const err = describeFetchError(
    "PUT",
    "https://console.example/x",
    new TypeError("connection refused"),
    false,
  );
  assertEquals(
    err.message,
    "PUT https://console.example/x failed: connection refused",
  );
});

// ── finalizeResponse ──────────────────────────────────────────────────────────

Deno.test("finalizeResponse: 2xx JSON body parses", () => {
  assertEquals(finalizeResponse("GET", "/x", 200, '{"ok":true}'), { ok: true });
});

Deno.test("finalizeResponse: 2xx empty body returns null", () => {
  assertEquals(finalizeResponse("DELETE", "/x", 204, ""), null);
  assertEquals(finalizeResponse("DELETE", "/x", 200, "   "), null);
});

Deno.test("finalizeResponse: non-2xx throws with method/url/status/body", () => {
  const err = assertThrows(
    () => finalizeResponse("GET", "/sites", 401, "unauthorized"),
    Error,
    "GET /sites failed (401): unauthorized",
  );
  assertEquals(err instanceof Error, true);
});

Deno.test("finalizeResponse: 5xx throws", () => {
  assertThrows(
    () => finalizeResponse("POST", "/x", 500, "boom"),
    Error,
    "(500)",
  );
});

// ── ipv4ToInt ─────────────────────────────────────────────────────────────────

Deno.test("ipv4ToInt: parses dotted quads to uint32", () => {
  assertEquals(ipv4ToInt("0.0.0.0"), 0);
  assertEquals(ipv4ToInt("10.0.0.1"), 0x0A000001);
  assertEquals(ipv4ToInt("255.255.255.255"), 0xFFFFFFFF); // stays unsigned
  assertEquals(ipv4ToInt("192.168.1.1"), 0xC0A80101);
});

Deno.test("ipv4ToInt: rejects malformed input", () => {
  assertEquals(ipv4ToInt("10.0.0"), null); // too few octets
  assertEquals(ipv4ToInt("10.0.0.1.2"), null); // too many
  assertEquals(ipv4ToInt("10.0.0.256"), null); // octet out of range
  assertEquals(ipv4ToInt("10.0.0.x"), null); // non-numeric
  assertEquals(ipv4ToInt(""), null);
});

// ── ipv4InSubnet ──────────────────────────────────────────────────────────────

Deno.test("ipv4InSubnet: matches inside and rejects outside a /24", () => {
  assertEquals(ipv4InSubnet("192.0.2.51", "192.0.2.1", 24), true);
  assertEquals(ipv4InSubnet("192.0.2.255", "192.0.2.1", 24), true);
  assertEquals(ipv4InSubnet("198.51.100.5", "192.0.2.1", 24), false); // other subnet
  assertEquals(ipv4InSubnet("192.0.3.5", "192.0.2.1", 24), false);
});

Deno.test("ipv4InSubnet: boundary prefixes /32 and /0", () => {
  assertEquals(ipv4InSubnet("10.0.0.1", "10.0.0.1", 32), true); // exact host
  assertEquals(ipv4InSubnet("10.0.0.2", "10.0.0.1", 32), false);
  assertEquals(ipv4InSubnet("8.8.8.8", "10.0.0.1", 0), true); // /0 matches all
});

Deno.test("ipv4InSubnet: malformed IP or bad prefix is a non-match, not a throw", () => {
  assertEquals(ipv4InSubnet("not-an-ip", "10.0.0.1", 24), false);
  assertEquals(ipv4InSubnet("10.0.0.1", "10.0.0.1", 33), false);
  assertEquals(ipv4InSubnet("10.0.0.1", "10.0.0.1", -1), false);
});

// ── isValidDomainName ─────────────────────────────────────────────────────────

Deno.test("isValidDomainName: accepts ordinary DNS names", () => {
  assertEquals(isValidDomainName("lan.example"), true);
  assertEquals(isValidDomainName("lan"), true);
  assertEquals(isValidDomainName("a-b.c1.example"), true);
  assertEquals(isValidDomainName("Lan.Example"), true); // case is the caller's job
});

Deno.test("isValidDomainName: rejects malformed names", () => {
  assertEquals(isValidDomainName(""), false);
  assertEquals(isValidDomainName("lan.example."), false); // trailing dot
  assertEquals(isValidDomainName(".lan.example"), false);
  assertEquals(isValidDomainName("lan..dev"), false);
  assertEquals(isValidDomainName("-lan.dev"), false);
  assertEquals(isValidDomainName("lan-.dev"), false);
  assertEquals(isValidDomainName("lan only.dev"), false);
  assertEquals(isValidDomainName("lan_only.dev"), false);
  assertEquals(isValidDomainName(`${"a".repeat(64)}.dev`), false); // label > 63
  assertEquals(isValidDomainName(`${"a.".repeat(127)}ab`), false); // > 253
});

// ── selectNetworksByName ──────────────────────────────────────────────────────

const NETS = [
  { id: "net-default", name: "Default" },
  { id: "net-apps", name: "Apps" },
  { id: "net-appl", name: "Appliances" },
  { id: "net-iot", name: "IoT" },
];

Deno.test("selectNetworksByName: exact, case-insensitive, keeps request order", () => {
  const got = selectNetworksByName(NETS, ["appliances", "APPS"]);
  assertEquals(got.map((n) => n.id), ["net-appl", "net-apps"]);
});

Deno.test("selectNetworksByName: repeated names select once", () => {
  const got = selectNetworksByName(NETS, ["Apps", "apps", " Apps "]);
  assertEquals(got.map((n) => n.id), ["net-apps"]);
});

Deno.test("selectNetworksByName: no prefix or substring matching", () => {
  assertThrows(
    () => selectNetworksByName(NETS, ["App"]),
    Error,
    'unknown network "App"',
  );
});

Deno.test("selectNetworksByName: unknown name fails the whole selection", () => {
  // One good name and one bad name: nothing is selected, the error lists the
  // bad name and the known networks.
  const err = assertThrows(
    () => selectNetworksByName(NETS, ["Apps", "Lab"]),
    Error,
    'unknown network "Lab"',
  );
  assertEquals(err.message.includes("Known networks: Default, Apps"), true);
});

Deno.test("selectNetworksByName: names differing only in case are ambiguous", () => {
  const nets = [...NETS, { id: "net-apps-2", name: "apps" }];
  assertThrows(
    () => selectNetworksByName(nets, ["Apps"]),
    Error,
    'ambiguous network "Apps" matches 2 networks',
  );
});

Deno.test("selectNetworksByName: empty list or blank name throws", () => {
  assertThrows(() => selectNetworksByName(NETS, []), Error, "at least one");
  assertThrows(() => selectNetworksByName(NETS, ["  "]), Error, "is empty");
});

// ── planNetworkDomain ─────────────────────────────────────────────────────────

/** A gateway-managed network as Get Network Details returns it. */
function gatewayNetwork(domainName?: string): Record<string, unknown> {
  return {
    management: "GATEWAY",
    id: "net-apps",
    name: "Apps",
    enabled: true,
    vlanId: 100,
    metadata: { origin: "USER_DEFINED" },
    default: false,
    isolationEnabled: false,
    cellularBackupEnabled: true,
    zoneId: "z1",
    internetAccessEnabled: true,
    mdnsForwardingEnabled: false,
    ipv4Configuration: {
      autoScaleEnabled: false,
      hostIpAddress: "192.0.2.1",
      prefixLength: 24,
      dhcpConfiguration: {
        mode: "SERVER",
        ipAddressRange: { start: "192.0.2.100", stop: "192.0.2.254" },
        leaseTimeSeconds: 86400,
        pingConflictDetectionEnabled: true,
        dnsServerIpAddressesOverride: ["192.0.2.1"],
        ...(domainName === undefined ? {} : { domainName }),
      },
    },
    ipv6Configuration: {
      interfaceType: "PREFIX_DELEGATION",
      clientAddressAssignment: { slaacEnabled: true },
    },
  };
}

Deno.test("planNetworkDomain: body is the full object with only domainName changed", () => {
  const detail = gatewayNetwork("old.example");
  const plan = planNetworkDomain(detail, "lan.example");
  assertEquals(plan.action, "change");
  assertEquals(plan.currentDomain, "old.example");
  assertEquals(plan.newDomain, "lan.example");
  assertEquals(plan.networkName, "Apps");
  assertEquals(plan.vlanId, 100);
  // Read-only fields are dropped from the PUT body...
  assertEquals("id" in plan.body, false);
  assertEquals("metadata" in plan.body, false);
  assertEquals("default" in plan.body, false);
  // ...and everything else (DHCP range, IPv6, flags) is kept unchanged.
  const ignore = new Set(["id", "metadata", "default", DOMAIN_NAME_PATH]);
  assertEquals(diffPaths(detail, plan.body, ignore), []);
  assertEquals(diffPaths(detail, plan.body).sort(), [
    "default",
    "id",
    DOMAIN_NAME_PATH,
    "metadata",
  ]);
});

Deno.test("planNetworkDomain: does not mutate the details object", () => {
  const detail = gatewayNetwork("old.example");
  const copy = structuredClone(detail);
  planNetworkDomain(detail, "lan.example");
  assertEquals(detail, copy);
});

Deno.test("planNetworkDomain: unset domain becomes a change", () => {
  const plan = planNetworkDomain(gatewayNetwork(), "lan.example");
  assertEquals(plan.currentDomain, undefined);
  assertEquals(plan.action, "change");
});

Deno.test("planNetworkDomain: same domain is unchanged", () => {
  const plan = planNetworkDomain(gatewayNetwork("lan.example"), "lan.example");
  assertEquals(plan.action, "unchanged");
});

Deno.test("planNetworkDomain: refuses non-gateway networks", () => {
  const detail = { ...gatewayNetwork(), management: "SWITCH" };
  assertThrows(
    () => planNetworkDomain(detail, "lan.example"),
    Error,
    "SWITCH-managed",
  );
});

Deno.test("planNetworkDomain: refuses DHCP relay or no DHCP", () => {
  const relay = gatewayNetwork();
  ((relay.ipv4Configuration as Record<string, unknown>)
    .dhcpConfiguration as Record<string, unknown>).mode = "RELAY";
  assertThrows(
    () => planNetworkDomain(relay, "lan.example"),
    Error,
    "DHCP mode RELAY",
  );

  const none = gatewayNetwork();
  delete (none.ipv4Configuration as Record<string, unknown>).dhcpConfiguration;
  assertThrows(
    () => planNetworkDomain(none, "lan.example"),
    Error,
    "DHCP mode none",
  );
});

// ── diffPaths ─────────────────────────────────────────────────────────────────

Deno.test("diffPaths: equal values have no differences", () => {
  assertEquals(diffPaths(gatewayNetwork("a.b"), gatewayNetwork("a.b")), []);
});

Deno.test("diffPaths: reports nested changes, added and removed keys", () => {
  const a = { x: 1, n: { y: 2, z: 3 } };
  const b = { x: 1, n: { y: 9, w: 4 } };
  assertEquals(diffPaths(a, b).sort(), ["n.w", "n.y", "n.z"]);
});

Deno.test("diffPaths: arrays compare by index and length", () => {
  assertEquals(diffPaths({ a: [1, 2] }, { a: [1, 3] }), ["a.1"]);
  assertEquals(diffPaths({ a: [1, 2] }, { a: [1] }), ["a"]);
  assertEquals(diffPaths({ a: [1] }, { a: { 0: 1 } }), ["a"]); // type change
});

Deno.test("diffPaths: ignored path hides only that path", () => {
  const before = gatewayNetwork("old.example");
  const after = gatewayNetwork("lan.example");
  assertEquals(diffPaths(before, after), [DOMAIN_NAME_PATH]);
  assertEquals(diffPaths(before, after, new Set([DOMAIN_NAME_PATH])), []);
  // A stray change next to the domain still shows.
  ((after.ipv4Configuration as Record<string, unknown>)
    .dhcpConfiguration as Record<string, unknown>).leaseTimeSeconds = 60;
  assertEquals(diffPaths(before, after, new Set([DOMAIN_NAME_PATH])), [
    "ipv4Configuration.dhcpConfiguration.leaseTimeSeconds",
  ]);
});

Deno.test("diffPaths: an added domainName is a difference unless ignored", () => {
  const before = gatewayNetwork();
  const after = gatewayNetwork("lan.example");
  assertEquals(diffPaths(before, after), [DOMAIN_NAME_PATH]);
  assertEquals(diffPaths(before, after, new Set([DOMAIN_NAME_PATH])), []);
});

// ── planDnsARecords ───────────────────────────────────────────────────────────

/** An A-record DNS policy as List DNS Policies returns it. */
function aRecord(
  id: string,
  domain: string,
  ipv4Address: string,
  ttlSeconds = 3600,
  enabled = true,
): Record<string, unknown> {
  return {
    type: "A_RECORD",
    id,
    enabled,
    metadata: { origin: "USER_DEFINED" },
    domain,
    ipv4Address,
    ttlSeconds,
  };
}

Deno.test("planDnsARecords: missing names are created with a full create body", () => {
  const plans = planDnsARecords([], [
    { name: "Fort.Lan.Example", ipv4Address: "192.0.2.50" },
    { name: "pve.lan.example", ipv4Address: " 192.0.2.51 " },
  ], 3600);
  assertEquals(plans.map((p) => p.action), ["create", "create"]);
  assertEquals(plans[0].name, "fort.lan.example"); // stored lowercase
  assertEquals(plans[0].body, {
    type: "A_RECORD",
    enabled: true,
    domain: "fort.lan.example",
    ipv4Address: "192.0.2.50",
    ttlSeconds: 3600,
  });
  assertEquals(plans[1].ipv4Address, "192.0.2.51"); // trimmed
});

Deno.test("planDnsARecords: matching record is unchanged", () => {
  const plans = planDnsARecords(
    [aRecord("p1", "fort.lan.example", "192.0.2.50")],
    [{ name: "fort.lan.example", ipv4Address: "192.0.2.50" }],
    3600,
  );
  assertEquals(plans[0].action, "unchanged");
  assertEquals(plans[0].policyId, "p1");
});

Deno.test("planDnsARecords: differing address, TTL or disabled record is updated in place", () => {
  for (
    const existing of [
      aRecord("p1", "fort.lan.example", "192.0.2.99"),
      aRecord("p1", "fort.lan.example", "192.0.2.50", 60),
      aRecord("p1", "fort.lan.example", "192.0.2.50", 3600, false),
    ]
  ) {
    const [plan] = planDnsARecords(
      [existing],
      [{ name: "fort.lan.example", ipv4Address: "192.0.2.50" }],
      3600,
    );
    assertEquals(plan.action, "update");
    assertEquals(plan.policyId, "p1");
    assertEquals(plan.currentIpv4Address, existing.ipv4Address);
    // Body is the existing policy minus read-only fields, with only the
    // address, TTL and enabled flag set.
    assertEquals("id" in plan.body, false);
    assertEquals("metadata" in plan.body, false);
    assertEquals(
      diffPaths(
        existing,
        plan.body,
        new Set(["id", "metadata", "ipv4Address", "ttlSeconds", "enabled"]),
      ),
      [],
    );
    assertEquals(plan.body.ipv4Address, "192.0.2.50");
    assertEquals(plan.body.ttlSeconds, 3600);
    assertEquals(plan.body.enabled, true);
  }
});

Deno.test("planDnsARecords: name match is case-insensitive", () => {
  const [plan] = planDnsARecords(
    [aRecord("p1", "FORT.lan.example", "192.0.2.50")],
    [{ name: "fort.lan.example", ipv4Address: "192.0.2.50" }],
    3600,
  );
  assertEquals(plan.action, "unchanged");
});

Deno.test("planDnsARecords: other record types for the name do not block A records", () => {
  const txt = {
    type: "TXT_RECORD",
    id: "t1",
    enabled: true,
    domain: "fort.lan.example",
    text: "x",
  };
  const [plan] = planDnsARecords(
    [txt],
    [{ name: "fort.lan.example", ipv4Address: "192.0.2.50" }],
    3600,
  );
  assertEquals(plan.action, "create");
});

Deno.test("planDnsARecords: fails closed on conflicts and bad input, listing all", () => {
  const existing = [
    { type: "CNAME_RECORD", id: "c1", enabled: true, domain: "a.lan.example" },
    {
      type: "FORWARD_DOMAIN",
      id: "f1",
      enabled: true,
      domain: "b.lan.example",
      ipAddress: "1.1.1.1",
    },
    aRecord("p1", "c.lan.example", "198.51.100.1"),
    aRecord("p2", "c.lan.example", "198.51.100.2"),
  ];
  const err = assertThrows(
    () =>
      planDnsARecords(existing, [
        { name: "a.lan.example", ipv4Address: "198.51.100.1" },
        { name: "b.lan.example", ipv4Address: "198.51.100.1" },
        { name: "c.lan.example", ipv4Address: "198.51.100.1" },
        { name: "bad_name.dev", ipv4Address: "198.51.100.1" },
        { name: "d.lan.example", ipv4Address: "198.51.100.300" },
        { name: "e.lan.example", ipv4Address: "198.51.100.5" },
        { name: "E.lan.example", ipv4Address: "198.51.100.6" },
      ], 3600),
    Error,
    "DNS record plan failed",
  );
  for (
    const part of [
      "a.lan.example already has a CNAME_RECORD c1",
      "b.lan.example already has a FORWARD_DOMAIN f1",
      "c.lan.example has 2 A records",
      '"bad_name.dev" is not a valid DNS name',
      '"198.51.100.300" for d.lan.example is not an IPv4 address',
      "e.lan.example is requested more than once",
    ]
  ) {
    assertEquals(err.message.includes(part), true, part);
  }
});

Deno.test("planDnsARecords: empty list or bad TTL throws", () => {
  assertThrows(() => planDnsARecords([], [], 3600), Error, "at least one");
  const one = [{ name: "a.lan.example", ipv4Address: "198.51.100.1" }];
  assertThrows(() => planDnsARecords([], one, -1), Error, "ttlSeconds -1");
  assertThrows(() => planDnsARecords([], one, 86401), Error, "ttlSeconds");
  assertThrows(() => planDnsARecords([], one, 1.5), Error, "ttlSeconds");
});
