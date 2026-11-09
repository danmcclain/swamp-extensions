/**
 * Method-level tests for the write methods (setNetworkDomain, setDnsRecords)
 * against an in-memory UniFi console behind a mocked fetch. They cover the
 * dry run, the live run, fail-closed input, and verification failures.
 *
 * Run with: deno test extensions/models/
 */

import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  createModelTestContext,
  withMockedFetch,
} from "jsr:@systeminit/swamp-testing@0.20260604.20";
import { model } from "./unifi_networks.ts";

type Obj = Record<string, unknown>;

const HOST = "console.example";
const BASE = `https://${HOST}/proxy/network/integration`;
const SITE = "site-1";
const GLOBAL_ARGS = {
  mode: "local" as const,
  host: HOST,
  apiKey: "test-key",
};

/** A gateway-managed network as Get Network Details returns it. */
function network(
  id: string,
  name: string,
  vlanId: number,
  hostIp: string,
): Obj {
  return {
    management: "GATEWAY",
    id,
    name,
    enabled: true,
    vlanId,
    metadata: { origin: "USER_DEFINED" },
    default: false,
    isolationEnabled: false,
    cellularBackupEnabled: true,
    internetAccessEnabled: true,
    mdnsForwardingEnabled: false,
    ipv4Configuration: {
      autoScaleEnabled: false,
      hostIpAddress: hostIp,
      prefixLength: 28,
      dhcpConfiguration: {
        mode: "SERVER",
        ipAddressRange: { start: "192.0.2.2", stop: "192.0.2.14" },
        leaseTimeSeconds: 86400,
        pingConflictDetectionEnabled: true,
        domainName: "",
      },
    },
  };
}

interface FakeConsole {
  networks: Map<string, Obj>;
  dns: Map<string, Obj>;
  clients: Obj[];
  policies: Map<string, Obj>;
  /** Called on a network PUT; may alter what the console stores. */
  onNetworkPut?: (stored: Obj) => void;
  /** Called on a DNS POST/PUT; may alter what the console stores. */
  onDnsWrite?: (stored: Obj) => void;
}

function fakeConsole(): FakeConsole {
  return {
    networks: new Map([
      ["net-a", network("net-a", "Apps", 100, "192.0.2.1")],
      ["net-b", network("net-b", "Lab", 200, "192.0.2.17")],
      ["net-c", network("net-c", "Guests", 300, "192.0.2.33")],
    ]),
    dns: new Map(),
    clients: [],
    policies: new Map(),
  };
}

const page = (data: Obj[]) =>
  Response.json({
    offset: 0,
    limit: 100,
    count: data.length,
    totalCount: data.length,
    data,
  });

/** Route a request to the in-memory console. */
function handler(c: FakeConsole) {
  let nextId = 1;
  return async (req: Request): Promise<Response> => {
    const path = new URL(req.url).pathname.replace(
      `/proxy/network/integration`,
      "",
    );
    const m = req.method;
    if (m === "GET" && path === "/v1/sites") {
      return page([{ id: SITE, name: "Default" }]);
    }
    if (m === "GET" && path === `/v1/sites/${SITE}/networks`) {
      return page([...c.networks.values()].map((n) => ({
        id: n.id,
        name: n.name,
        management: n.management,
        enabled: n.enabled,
        vlanId: n.vlanId,
        default: n.default,
      })));
    }
    const netMatch = path.match(`^/v1/sites/${SITE}/networks/([^/]+)$`);
    if (netMatch) {
      const current = c.networks.get(netMatch[1]);
      if (!current) return new Response("not found", { status: 404 });
      if (m === "GET") return Response.json(current);
      if (m === "PUT") {
        const body = await req.json() as Obj;
        const stored = {
          ...body,
          id: current.id,
          metadata: current.metadata,
          default: current.default,
        };
        c.onNetworkPut?.(stored);
        c.networks.set(current.id as string, stored);
        return Response.json(stored);
      }
    }
    if (m === "GET" && path === `/v1/sites/${SITE}/clients`) {
      return page(c.clients);
    }
    const polMatch = path.match(
      `^/v1/sites/${SITE}/firewall/policies/([^/]+)$`,
    );
    if (polMatch) {
      const current = c.policies.get(polMatch[1]);
      if (!current) return new Response("not found", { status: 404 });
      if (m === "GET") return Response.json(current);
      if (m === "DELETE") {
        c.policies.delete(polMatch[1]);
        return new Response(null, { status: 204 });
      }
    }
    if (path === `/v1/sites/${SITE}/dns/policies`) {
      if (m === "GET") return page([...c.dns.values()]);
      if (m === "POST") {
        const body = await req.json() as Obj;
        const stored = {
          ...body,
          id: `dns-${nextId++}`,
          metadata: { origin: "USER_DEFINED" },
        };
        c.onDnsWrite?.(stored);
        c.dns.set(stored.id as string, stored);
        return Response.json(stored, { status: 201 });
      }
    }
    const dnsMatch = path.match(`^/v1/sites/${SITE}/dns/policies/([^/]+)$`);
    if (dnsMatch && m === "PUT") {
      const current = c.dns.get(dnsMatch[1]);
      if (!current) return new Response("not found", { status: 404 });
      const body = await req.json() as Obj;
      const stored = { ...body, id: current.id, metadata: current.metadata };
      c.onDnsWrite?.(stored);
      c.dns.set(current.id as string, stored);
      return Response.json(stored);
    }
    return new Response(`unexpected ${m} ${path}`, { status: 500 });
  };
}

function ctx(methodName: string) {
  return createModelTestContext({ globalArgs: GLOBAL_ARGS, methodName });
}

const writes = <C extends { method: string }>(calls: C[]) =>
  calls.filter((c) => c.method !== "GET");

// ── setNetworkDomain ──────────────────────────────────────────────────────────

Deno.test("setNetworkDomain: dry run plans every match and writes nothing", async () => {
  const c = fakeConsole();
  const { context, getWrittenResources, getLogs } = ctx("setNetworkDomain");
  const { calls } = await withMockedFetch(
    handler(c),
    () =>
      model.methods.setNetworkDomain.execute(
        { domain: "Lan.Example", networks: ["apps", "LAB"] },
        context as never,
      ),
  );
  assertEquals(writes(calls), []);
  const [res] = getWrittenResources();
  assertEquals(res.specName, "networkDomainChange");
  assertEquals(res.name, "Default");
  assertEquals(res.data.dryRun, true);
  assertEquals(res.data.domain, "lan.example");
  assertEquals(res.data.changeCount, 2);
  assertEquals(
    (res.data.networks as Obj[]).map((
      n,
    ) => [n.networkName, n.action, n.applied]),
    [["Apps", "change", false], ["Lab", "change", false]],
  );
  assertEquals(getLogs().length > 0, true);
});

Deno.test("setNetworkDomain: live run sends full body, verifies, leaves others alone", async () => {
  const c = fakeConsole();
  const before = structuredClone(c.networks.get("net-a")!);
  const guests = structuredClone(c.networks.get("net-c")!);
  const { context, getWrittenResources } = ctx("setNetworkDomain");
  const { calls } = await withMockedFetch(
    handler(c),
    () =>
      model.methods.setNetworkDomain.execute(
        { domain: "lan.example", networks: ["Apps", "Lab"], dryRun: false },
        context as never,
      ),
  );
  const puts = writes(calls);
  assertEquals(puts.map((p) => [p.method, p.url]), [
    ["PUT", `${BASE}/v1/sites/${SITE}/networks/net-a`],
    ["PUT", `${BASE}/v1/sites/${SITE}/networks/net-b`],
  ]);
  // The body is the full details object minus read-only fields, with only
  // the domain changed.
  const sent = JSON.parse(puts[0].body!) as Obj;
  const expected = structuredClone(before);
  delete expected.id;
  delete expected.metadata;
  delete expected.default;
  ((expected.ipv4Configuration as Obj).dhcpConfiguration as Obj).domainName =
    "lan.example";
  assertEquals(sent, expected);
  // The key travels in the header.
  assertEquals(puts[0].headers["x-api-key"], "test-key");
  // Unselected network untouched.
  assertEquals(c.networks.get("net-c"), guests);

  const [res] = getWrittenResources();
  assertEquals(res.data.dryRun, false);
  assertEquals(
    (res.data.networks as Obj[]).map((n) => [n.applied, n.verified]),
    [[true, true], [true, true]],
  );
});

Deno.test("setNetworkDomain: unchanged network is not written", async () => {
  const c = fakeConsole();
  ((c.networks.get("net-a")!.ipv4Configuration as Obj)
    .dhcpConfiguration as Obj).domainName = "lan.example";
  const { context, getWrittenResources } = ctx("setNetworkDomain");
  const { calls } = await withMockedFetch(
    handler(c),
    () =>
      model.methods.setNetworkDomain.execute(
        { domain: "lan.example", networks: ["Apps"], dryRun: false },
        context as never,
      ),
  );
  assertEquals(writes(calls), []);
  assertEquals(
    (getWrittenResources()[0].data.networks as Obj[])[0].action,
    "unchanged",
  );
});

Deno.test("setNetworkDomain: unknown name fails before any write", async () => {
  const c = fakeConsole();
  const { context, getWrittenResources } = ctx("setNetworkDomain");
  const { calls } = await withMockedFetch(handler(c), () =>
    assertRejects(
      () =>
        model.methods.setNetworkDomain.execute(
          { domain: "lan.example", networks: ["Apps", "Nope"], dryRun: false },
          context as never,
        ),
      Error,
      'unknown network "Nope"',
    ));
  assertEquals(writes(calls), []);
  assertEquals(getWrittenResources(), []);
});

Deno.test("setNetworkDomain: invalid domain fails before any request", async () => {
  const { context } = ctx("setNetworkDomain");
  const { calls } = await withMockedFetch(
    handler(fakeConsole()),
    () =>
      assertRejects(
        () =>
          model.methods.setNetworkDomain.execute(
            { domain: "bad_domain", networks: ["Apps"], dryRun: false },
            context as never,
          ),
        Error,
        "not a valid DNS domain name",
      ),
  );
  assertEquals(calls, []);
});

Deno.test("setNetworkDomain: stray change on the console fails verification and stops", async () => {
  const c = fakeConsole();
  c.onNetworkPut = (stored) => {
    ((stored.ipv4Configuration as Obj).dhcpConfiguration as Obj)
      .leaseTimeSeconds = 60;
  };
  const { context, getWrittenResources } = ctx("setNetworkDomain");
  const { calls } = await withMockedFetch(handler(c), () =>
    assertRejects(
      () =>
        model.methods.setNetworkDomain.execute(
          { domain: "lan.example", networks: ["Apps", "Lab"], dryRun: false },
          context as never,
        ),
      Error,
      "ipv4Configuration.dhcpConfiguration.leaseTimeSeconds",
    ));
  // Stopped after the first network.
  assertEquals(writes(calls).length, 1);
  const results = getWrittenResources()[0].data.networks as Obj[];
  assertEquals(results.map((r) => [r.applied, r.verified]), [
    [true, false],
    [false, undefined],
  ]);
});

Deno.test("setNetworkDomain: failed PUT records what was already applied", async () => {
  const c = fakeConsole();
  let puts = 0;
  const base = handler(c);
  const { context, getWrittenResources } = ctx("setNetworkDomain");
  await withMockedFetch(async (req) => {
    if (req.method === "PUT" && ++puts === 2) {
      return new Response("boom", { status: 500 });
    }
    return await base(req);
  }, () =>
    assertRejects(
      () =>
        model.methods.setNetworkDomain.execute(
          { domain: "lan.example", networks: ["Apps", "Lab"], dryRun: false },
          context as never,
        ),
      Error,
      "(500)",
    ));
  const results = getWrittenResources()[0].data.networks as Obj[];
  assertEquals(results.map((r) => r.applied), [true, false]);
});

// ── setDnsRecords ─────────────────────────────────────────────────────────────

const RECORDS = [
  { name: "host1.lan.example", ipv4Address: "192.0.2.50" },
  { name: "host2.lan.example", ipv4Address: "192.0.2.51" },
];

Deno.test("setDnsRecords: dry run plans creates and writes nothing", async () => {
  const c = fakeConsole();
  const { context, getWrittenResources } = ctx("setDnsRecords");
  const { calls } = await withMockedFetch(
    handler(c),
    () =>
      model.methods.setDnsRecords.execute(
        { records: RECORDS },
        context as never,
      ),
  );
  assertEquals(writes(calls), []);
  const [res] = getWrittenResources();
  assertEquals(res.specName, "dnsRecordChange");
  assertEquals(res.data.dryRun, true);
  assertEquals(res.data.changeCount, 2);
  assertEquals((res.data.records as Obj[]).map((r) => r.action), [
    "create",
    "create",
  ]);
});

Deno.test("setDnsRecords: live run creates, updates, verifies", async () => {
  const c = fakeConsole();
  c.dns.set("dns-old", {
    type: "A_RECORD",
    id: "dns-old",
    enabled: true,
    metadata: { origin: "USER_DEFINED" },
    domain: "host2.lan.example",
    ipv4Address: "192.0.2.99",
    ttlSeconds: 3600,
  });
  const { context, getWrittenResources } = ctx("setDnsRecords");
  const { calls } = await withMockedFetch(
    handler(c),
    () =>
      model.methods.setDnsRecords.execute(
        { records: RECORDS, ttlSeconds: 3600, dryRun: false },
        context as never,
      ),
  );
  const w = writes(calls);
  assertEquals(w.map((x) => x.method), ["POST", "PUT"]);
  assertEquals(JSON.parse(w[0].body!), {
    type: "A_RECORD",
    enabled: true,
    domain: "host1.lan.example",
    ipv4Address: "192.0.2.50",
    ttlSeconds: 3600,
  });
  assertEquals(w[1].url, `${BASE}/v1/sites/${SITE}/dns/policies/dns-old`);
  assertEquals(c.dns.get("dns-old")!.ipv4Address, "192.0.2.51");

  const results = getWrittenResources()[0].data.records as Obj[];
  assertEquals(results.map((r) => [r.action, r.applied, r.verified]), [
    ["create", true, true],
    ["update", true, true],
  ]);
  assertEquals(results[0].policyId, "dns-1");
  assertEquals(results[1].currentIpv4Address, "192.0.2.99");
});

Deno.test("setDnsRecords: all unchanged sends no write", async () => {
  const c = fakeConsole();
  c.dns.set("dns-x", {
    type: "A_RECORD",
    id: "dns-x",
    enabled: true,
    metadata: { origin: "USER_DEFINED" },
    domain: "host1.lan.example",
    ipv4Address: "192.0.2.50",
    ttlSeconds: 3600,
  });
  const { context } = ctx("setDnsRecords");
  const { calls } = await withMockedFetch(
    handler(c),
    () =>
      model.methods.setDnsRecords.execute(
        { records: [RECORDS[0]], ttlSeconds: 3600, dryRun: false },
        context as never,
      ),
  );
  assertEquals(writes(calls), []);
});

Deno.test("setDnsRecords: CNAME conflict fails before any write", async () => {
  const c = fakeConsole();
  c.dns.set("dns-c", {
    type: "CNAME_RECORD",
    id: "dns-c",
    enabled: true,
    metadata: { origin: "USER_DEFINED" },
    domain: "host1.lan.example",
  });
  const { context, getWrittenResources } = ctx("setDnsRecords");
  const { calls } = await withMockedFetch(handler(c), () =>
    assertRejects(
      () =>
        model.methods.setDnsRecords.execute(
          { records: RECORDS, ttlSeconds: 3600, dryRun: false },
          context as never,
        ),
      Error,
      "already has a CNAME_RECORD dns-c",
    ));
  assertEquals(writes(calls), []);
  assertEquals(getWrittenResources(), []);
});

Deno.test("setDnsRecords: console storing a different value fails verification", async () => {
  const c = fakeConsole();
  c.onDnsWrite = (stored) => {
    stored.ttlSeconds = 60;
  };
  const { context, getWrittenResources } = ctx("setDnsRecords");
  await withMockedFetch(handler(c), () =>
    assertRejects(
      () =>
        model.methods.setDnsRecords.execute(
          { records: [RECORDS[0]], ttlSeconds: 3600, dryRun: false },
          context as never,
        ),
      Error,
      "host1.lan.example: found 192.0.2.50 ttl 60",
    ));
  const results = getWrittenResources()[0].data.records as Obj[];
  assertEquals(results.map((r) => [r.applied, r.verified]), [[true, false]]);
});

// ── read methods and deletePolicy ─────────────────────────────────────────────

Deno.test("scan: writes one siteNetworks snapshot per site", async () => {
  const { context, getWrittenResources } = ctx("scan");
  await withMockedFetch(
    handler(fakeConsole()),
    () => model.methods.scan.execute({}, context as never),
  );
  const [res] = getWrittenResources();
  assertEquals(res.specName, "siteNetworks");
  assertEquals(res.name, "Default");
  assertEquals(res.data.networkCount, 3);
  assertEquals(
    (res.data.networks as Obj[]).map((n) => [n.name, n.vlanId]),
    [["Apps", 100], ["Lab", 200], ["Guests", 300]],
  );
});

Deno.test("scanClients: maps clients to networks by subnet, counts unmapped", async () => {
  const c = fakeConsole();
  c.clients = [
    { id: "c1", name: "a", type: "WIRED", ipAddress: "192.0.2.5" },
    { id: "c2", name: "b", type: "WIRED", ipAddress: "192.0.2.20" },
    { id: "c3", name: "c", type: "WIRELESS", ipAddress: "192.0.2.6" },
    { id: "c4", name: "vpn", type: "VPN", ipAddress: "203.0.113.9" },
  ];
  const { context, getWrittenResources } = ctx("scanClients");
  await withMockedFetch(
    handler(c),
    () => model.methods.scanClients.execute({}, context as never),
  );
  const [res] = getWrittenResources();
  assertEquals(res.specName, "siteClients");
  assertEquals(res.data.clientCount, 4);
  assertEquals(res.data.unmappedCount, 1);
  assertEquals(
    (res.data.clients as Obj[]).map((x) => x.networkName),
    ["Apps", "Lab", "Apps", undefined],
  );
  assertEquals(res.data.byVlan, [
    { vlanId: 100, networkName: "Apps", clientCount: 2 },
    { vlanId: 200, networkName: "Lab", clientCount: 1 },
  ]);
});

Deno.test("consoles: refuses local mode", async () => {
  const { context } = ctx("consoles");
  await assertRejects(
    () => model.methods.consoles.execute({}, context as never),
    Error,
    "requires mode='cloud'",
  );
});

Deno.test("deletePolicy: deletes a USER_DEFINED policy", async () => {
  const c = fakeConsole();
  c.policies.set("pol-1", {
    id: "pol-1",
    name: "temp allow",
    metadata: { origin: "USER_DEFINED" },
  });
  const { context } = ctx("deletePolicy");
  const { calls } = await withMockedFetch(
    handler(c),
    () =>
      model.methods.deletePolicy.execute(
        { siteId: SITE, policyId: "pol-1" },
        context as never,
      ),
  );
  assertEquals(writes(calls).map((x) => x.method), ["DELETE"]);
  assertEquals(c.policies.has("pol-1"), false);
});

Deno.test("deletePolicy: refuses a system-defined policy", async () => {
  const c = fakeConsole();
  c.policies.set("pol-2", {
    id: "pol-2",
    name: "Allow Return Traffic",
    metadata: { origin: "SYSTEM_DEFINED" },
  });
  const { context } = ctx("deletePolicy");
  const { calls } = await withMockedFetch(
    handler(c),
    () =>
      assertRejects(
        () =>
          model.methods.deletePolicy.execute(
            { siteId: SITE, policyId: "pol-2" },
            context as never,
          ),
        Error,
        "only USER_DEFINED policies are deletable",
      ),
  );
  assertEquals(writes(calls), []);
  assertEquals(c.policies.has("pol-2"), true);
});

// ── upgrades ──────────────────────────────────────────────────────────────────

Deno.test("upgrade 2026.11.09.1: drops verifyTls, keeps the rest", () => {
  const [upgrade] = model.upgrades;
  assertEquals(upgrade.toVersion, model.version);
  assertEquals(
    upgrade.upgradeAttributes({
      mode: "local",
      host: HOST,
      apiKey: "${{ vault.get(v, k) }}",
      verifyTls: false,
    }),
    { mode: "local", host: HOST, apiKey: "${{ vault.get(v, k) }}" },
  );
  // Arguments that never had verifyTls pass through unchanged.
  const cloud = { mode: "cloud", apiKey: "k", consoleId: "c1" };
  assertEquals(upgrade.upgradeAttributes(cloud), cloud);
});
