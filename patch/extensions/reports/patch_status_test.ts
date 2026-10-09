import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { createReportTestContext } from "jsr:@systeminit/swamp-testing@0.20260604.20";
import { report } from "./patch_status.ts";

const MODEL_TYPE = "@dmc/patch/fleet";
const MODEL_ID = "fleet-id";
const CS_TYPE = "@dmc/proxmox/community-script";

interface Seed {
  modelType?: string;
  modelId?: string;
  name: string;
  version?: number;
  body: unknown;
  raw?: string;
}

/** Build the fake data repository contents the report reads. */
function artifacts(seeds: Seed[]) {
  return seeds.map((s, i) => ({
    modelType: s.modelType ?? MODEL_TYPE,
    modelId: s.modelId ?? MODEL_ID,
    data: {
      name: s.name,
      kind: "resource" as const,
      dataId: `d${i}`,
      version: s.version ?? 1,
      size: 0,
      contentType: "application/json",
    },
    content: new TextEncoder().encode(s.raw ?? JSON.stringify(s.body)),
  }));
}

async function run(
  seeds: Seed[],
  globalArgs?: Record<string, unknown>,
) {
  const { context } = createReportTestContext({
    scope: "model",
    modelType: MODEL_TYPE,
    modelId: MODEL_ID,
    definition: { name: "fleet" },
    ...(globalArgs ? { globalArgs } : {}),
    dataArtifacts: artifacts(seeds),
  });
  return await report.execute(context as never);
}

function inventory(host: string, over: Record<string, unknown> = {}): Seed {
  return {
    name: host,
    body: {
      hostname: host,
      osType: "Debian GNU/Linux",
      osVersion: "12",
      packageManager: "apt",
      updatesCount: 0,
      securityUpdatesCount: 0,
      heldBackCount: 0,
      removalsCount: 0,
      distUpgradeRequired: false,
      totalPackages: 400,
      needsReboot: false,
      rebootReason: null,
      dockerEngine: null,
      dockerImages: null,
      reachMethod: "ssh",
      health: null,
      error: null,
      scannedAt: "2026-09-30T10:00:00Z",
      ...over,
    },
  };
}

function updateCheck(
  modelId: string,
  over: Record<string, unknown> = {},
  version = 1,
): Seed {
  return {
    modelType: CS_TYPE,
    modelId,
    name: "updateCheck",
    version,
    body: {
      name: "Valkey",
      installedVersion: "9.0.4",
      latestVersion: "9.0.4",
      upstreamVersion: null,
      updateAvailable: false,
      ...over,
    },
  };
}

/** Table cells (trimmed) of the row that starts with `| <host> |`. */
function row(markdown: string, host: string): string[] {
  const line = markdown.split("\n").find((l) => l.startsWith(`| ${host} |`));
  if (!line) throw new Error(`no row for ${host}:\n${markdown}`);
  return line.split("|").slice(1, -1).map((c) => c.trim());
}

const COLUMNS = [
  "Node",
  "OS",
  "Mgr",
  "Via",
  "Health",
  "OS Updates",
  "Security",
  "App (LXC)",
  "Reboot",
  "Docker (engine · containers)",
  "Scanned",
];
const col = (name: string) => COLUMNS.indexOf(name);

Deno.test("status report: metadata names the model-scoped report", () => {
  assertEquals(report.name, "@dmc/patch-status");
  assertEquals(report.scope, "model");
});

Deno.test("status report: no inventory renders the empty notice", async () => {
  const res = await run([]);
  assertStringIncludes(res.markdown, "# Fleet Patch Status");
  assertStringIncludes(res.markdown, "No inventory yet");
  assertEquals(res.json, { status: "no-data" });
});

Deno.test("status report: records that are not inventory do not count as nodes", async () => {
  const res = await run([
    { name: "run-osUpdate-web1-x", body: { host: "web1" } },
    { name: "snap-web1-x", body: { status: "active" } },
    { name: "seed", body: { yaml: "" } },
    inventory("broken", { error: "unreachable" }),
  ]);
  assertStringIncludes(res.markdown, "No inventory yet");
});

Deno.test("status report: Health column shows a check mark, a cross, or a dash", async () => {
  const res = await run([
    inventory("ok", {
      health: {
        healthy: true,
        checks: [{ label: "app", ok: true, detail: "status 200" }],
      },
    }),
    inventory("bad", {
      health: {
        healthy: false,
        checks: [{ label: "app", ok: false, detail: "status 503" }],
      },
    }),
    inventory("none", { health: null }),
  ]);
  assertEquals(row(res.markdown, "ok")[col("Health")], "✅");
  assertEquals(row(res.markdown, "bad")[col("Health")], "❌");
  assertEquals(row(res.markdown, "none")[col("Health")], "—");
});

Deno.test("status report: an unhealthy node is called out with its failed checks", async () => {
  const res = await run([
    inventory("bad", {
      health: {
        healthy: false,
        checks: [
          { label: "app http", ok: false, detail: "status 503" },
          { label: "db", ok: true, detail: "active" },
        ],
      },
    }),
  ]);
  assertStringIncludes(res.markdown, "❌ 1 node(s) UNHEALTHY");
  assertStringIncludes(res.markdown, "## Unhealthy");
  assertStringIncludes(res.markdown, "- **bad** — app http (status 503)");
  assertEquals(res.json.unhealthyNodes, ["bad"]);
  assertEquals(res.json.allCurrent, true);
});

Deno.test("status report: App cell shows the installed version with upstream drift", async () => {
  const res = await run([
    inventory("valkey"),
    updateCheck("cs-valkey", { upstreamVersion: "9.1.2" }),
  ]);
  assertEquals(
    row(res.markdown, "valkey")[col("App (LXC)")],
    "Valkey 9.0.4 _(upstream 9.1.2)_",
  );
});

Deno.test("status report: no drift note when upstream equals the installed version", async () => {
  const res = await run([
    inventory("valkey"),
    updateCheck("cs-valkey", { upstreamVersion: "9.0.4" }),
  ]);
  assertEquals(row(res.markdown, "valkey")[col("App (LXC)")], "Valkey 9.0.4");
});

Deno.test("status report: App cell shows a pending app update as an upward arrow", async () => {
  const res = await run([
    inventory("valkey"),
    updateCheck("cs-valkey", {
      installedVersion: "9.0.4",
      latestVersion: "9.1.2",
      updateAvailable: true,
    }),
  ]);
  assertEquals(
    row(res.markdown, "valkey")[col("App (LXC)")],
    "⬆️ Valkey 9.0.4→9.1.2",
  );
  assertStringIncludes(res.markdown, "1 LXC app(s) with updates");
  assertEquals(res.json.lxcAppsWithUpdates, ["Valkey"]);
  assertEquals(res.json.allCurrent, false);
});

Deno.test("status report: App cell is a dash for a host without an app; the newest updateCheck wins", async () => {
  const res = await run([
    inventory("plain"),
    inventory("valkey"),
    updateCheck("cs-valkey", { installedVersion: "1.0.0" }, 1),
    updateCheck("cs-valkey", { installedVersion: "9.0.4" }, 2),
  ]);
  assertEquals(row(res.markdown, "plain")[col("App (LXC)")], "—");
  assertEquals(row(res.markdown, "valkey")[col("App (LXC)")], "Valkey 9.0.4");
});

Deno.test("status report: only the latest version of each inventory record is used", async () => {
  const res = await run([
    { ...inventory("web1", { updatesCount: 9 }), version: 1 },
    { ...inventory("web1", { updatesCount: 2 }), version: 2 },
  ]);
  assertEquals(row(res.markdown, "web1")[col("OS Updates")], "**2**");
  assertEquals(res.json.nodes, 1);
  assertEquals(res.json.totalPendingUpdates, 2);
});

Deno.test("status report: OS updates, security, held-back, reboot and docker cells", async () => {
  const res = await run([
    inventory("web1", {
      updatesCount: 5,
      securityUpdatesCount: 2,
      heldBackCount: 1,
      distUpgradeRequired: true,
      needsReboot: true,
      rebootReason: "kernel mismatch",
      dockerEngine: "27.0.1",
      dockerImages: [
        { container: "web", image: "nginx:1", updateAvailable: true },
        { container: "db", image: "pg:16", updateAvailable: false },
      ],
    }),
    inventory("alp", { packageManager: "apk", securityUpdatesCount: null }),
  ]);
  const web = row(res.markdown, "web1");
  assertEquals(web[col("OS Updates")], "**5** (+1 held)");
  assertEquals(web[col("Security")], "🔒 **2**");
  assertEquals(web[col("Reboot")], "⚠️ yes");
  assertEquals(web[col("Docker (engine · containers)")], "🐳 27.0.1 · 2c ⬆️1");
  assertEquals(web[col("Scanned")], "2026-09-30 10:00 UTC");
  const alp = row(res.markdown, "alp");
  assertEquals(alp[col("OS Updates")], "—");
  assertEquals(alp[col("Security")], "n/a");
  assertEquals(alp[col("Docker (engine · containers)")], "—");
  assertStringIncludes(res.markdown, "## Reboot required");
  assertStringIncludes(res.markdown, "- **web1** — kernel mismatch");
  assertStringIncludes(res.markdown, "## Docker containers");
  assertStringIncludes(res.markdown, "| web1 | web | nginx:1 | ⬆️ **yes** |");
  assertStringIncludes(res.markdown, "| web1 | db | pg:16 | — |");
});

Deno.test("status report: the nodes most in need sort first", async () => {
  const res = await run([
    inventory("calm"),
    inventory("busy", { updatesCount: 10 }),
    inventory("risky", { updatesCount: 1, securityUpdatesCount: 1 }),
  ]);
  const order = (res.json.hosts as Array<{ hostname: string }>).map((h) =>
    h.hostname
  );
  assertEquals(order, ["risky", "busy", "calm"]);
});

Deno.test("status report: a fully current, healthy fleet says so", async () => {
  const res = await run([
    inventory("a", {
      health: { healthy: true, checks: [] },
    }),
    inventory("b"),
  ]);
  assertStringIncludes(
    res.markdown,
    "✅ All fleet nodes, containers and LXC apps up to date and healthy",
  );
  assertStringIncludes(res.markdown, "**Nodes**: 2");
  assertEquals(res.json.allCurrent, true);
});

Deno.test("status report: counts retained snapshots and images that are active", async () => {
  const res = await run([
    inventory("web1"),
    { name: "snap-web1-1", body: { status: "active" } },
    { name: "snap-web1-2", body: { status: "pruned" } },
    { name: "image-web1-1", body: { status: "active" } },
    { name: "image-web1-2", body: { status: "active" } },
  ]);
  assertStringIncludes(
    res.markdown,
    "**Retained snapshots**: 1 · **Retained images**: 2",
  );
  assertEquals(res.json.retainedSnapshots, 1);
  assertEquals(res.json.retainedImages, 2);
});

Deno.test("status report: unreadable records are skipped, not fatal", async () => {
  const res = await run([
    inventory("web1"),
    { name: "junk", body: null, raw: "{not json" },
  ]);
  assertEquals(res.json.nodes, 1);
});

// --- Retired machines ---------------------------------------------------------

const machines = (...hosts: string[]) => ({
  machines: hosts.map((host) => ({ host })),
});

/** A fleet of `web1`, with `old1` retired (it still has records). */
function retiredSeeds(): Seed[] {
  return [
    inventory("web1", { updatesCount: 2, securityUpdatesCount: 1 }),
    inventory("old1", {
      updatesCount: 16,
      securityUpdatesCount: 11,
      needsReboot: true,
      distUpgradeRequired: true,
      scannedAt: "2026-08-01T09:30:00Z",
      dockerEngine: "27.0",
      dockerImages: [
        { container: "gone", image: "gone:1", updateAvailable: true },
      ],
    }),
    { name: "update-old1", body: { host: "old1" } },
    { name: "run-osUpdate-old1-1", body: { host: "old1" } },
    { name: "snap-old1-1", body: { host: "old1", status: "active" } },
    { name: "snap-old1-0", body: { host: "old1", status: "pruned" } },
    { name: "image-old1-1-a", body: { host: "old1", status: "active" } },
    { name: "snap-web1-1", body: { host: "web1", status: "active" } },
    { name: "image-web1-1-a", body: { host: "web1", status: "active" } },
  ];
}

Deno.test("status report: a retired host is left out of the node table and every total", async () => {
  const res = await run(retiredSeeds(), machines("web1"));
  const md = res.markdown;
  assertEquals(
    md.split("\n").some((l) =>
      l.startsWith("| old1 |") && l.includes("Debian")
    ),
    false,
  );
  assertStringIncludes(md, "**Nodes**: 1 ·");
  assertStringIncludes(
    md,
    "**Retained snapshots**: 1 · **Retained images**: 1",
  );
  assertStringIncludes(md, "2 update(s) pending");
  assertStringIncludes(md, "1 node(s) with security updates");
  assertEquals(md.includes("need dist-upgrade"), false);
  assertEquals(md.includes("need reboot"), false);
  assertEquals(md.includes("container image(s) with updates"), false);
  assertEquals(res.json.nodes, 1);
  assertEquals(res.json.totalPendingUpdates, 2);
  assertEquals(res.json.nodesWithSecurityUpdates, ["web1"]);
  assertEquals(res.json.nodesRequiringDistUpgrade, []);
  assertEquals(res.json.nodesNeedingReboot, []);
  assertEquals(res.json.containerImagesWithUpdates, []);
  assertEquals(res.json.retainedSnapshots, 1);
  assertEquals(res.json.retainedImages, 1);
});

Deno.test("status report: the Retired machines section lists last scanned, records and active retention", async () => {
  const res = await run(retiredSeeds(), machines("web1"));
  const md = res.markdown;
  assertStringIncludes(md, "## Retired machines");
  assertStringIncludes(
    md,
    "| Host | Last scanned | Records | Active retention |",
  );
  // old1: inventory, update, run, 2 snaps, 1 image = 6 records; 2 active retention.
  assertStringIncludes(md, "| old1 | 2026-08-01 09:30 UTC | 6 | 2 |");
  assertStringIncludes(md, "`swamp model method run fleet clearRetired`");
  assertStringIncludes(
    md,
    "`swamp model method run fleet clearRetired --input dryRun=false`",
  );
  assertEquals(res.json.retired, [{
    host: "old1",
    lastScanned: "2026-08-01T09:30:00Z",
    records: 6,
    activeRetention: 2,
  }]);
});

Deno.test("status report: a retired host with no inventory shows a dash for last scanned", async () => {
  const res = await run(
    [inventory("web1"), {
      name: "run-osUpdate-old1-1",
      body: { host: "old1" },
    }],
    machines("web1"),
  );
  assertStringIncludes(res.markdown, "| old1 | — | 1 | 0 |");
});

Deno.test("status report: no Retired section when every host is in the fleet", async () => {
  const res = await run(
    [inventory("web1"), inventory("web2")],
    machines("web1", "web2"),
  );
  assertEquals(res.markdown.includes("Retired machines"), false);
  assertEquals(res.json.retired, []);
});

Deno.test("status report: node is never mistaken for node2", async () => {
  const res = await run(
    [
      inventory("node"),
      inventory("node2", { updatesCount: 9 }),
      { name: "snap-node2-1", body: { host: "node2", status: "active" } },
      { name: "snap-node-1", body: { host: "node", status: "active" } },
    ],
    machines("node"),
  );
  assertStringIncludes(res.markdown, "**Nodes**: 1 ·");
  assertStringIncludes(res.markdown, "**Retained snapshots**: 1");
  assertStringIncludes(res.markdown, "| node2 | ");
  assertEquals(res.json.totalPendingUpdates, 0);
  assertEquals(
    (res.json.retired as Array<{ host: string; records: number }>).map((
      r,
    ) => [r.host, r.records]),
    [["node2", 2]],
  );
});

Deno.test("status report: an app of a retired host stays out of the LXC totals", async () => {
  const res = await run(
    [
      inventory("web1"),
      inventory("retired1"),
      updateCheck("m1", { name: "Retired1", updateAvailable: true }),
      updateCheck("m2", { name: "Valkey", updateAvailable: true }),
    ],
    machines("web1"),
  );
  assertEquals(res.json.lxcAppsWithUpdates, ["Valkey"]);
});

Deno.test("status report: without machines in the context every host is shown (fallback)", async () => {
  for (const globalArgs of [undefined, {}, { machines: [] }]) {
    const res = await run(retiredSeeds(), globalArgs);
    assertEquals(res.json.nodes, 2);
    assertEquals(res.markdown.includes("Retired machines"), false);
    assertEquals(res.json.retired, []);
    assertStringIncludes(res.markdown, "| old1 |");
  }
});

Deno.test("status report: when no current host has inventory the retired hosts are still listed", async () => {
  const res = await run([inventory("old1")], machines("web1"));
  assertStringIncludes(res.markdown, "_No inventory yet");
  assertStringIncludes(res.markdown, "## Retired machines");
  assertEquals(res.json.status, "no-data");
});
