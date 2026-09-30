import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { createReportTestContext } from "jsr:@systeminit/swamp-testing@0.20260604.20";
import { report } from "./patch_history.ts";

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

async function run(
  seeds: Seed[],
  globalArgs: Record<string, unknown> = {},
) {
  const { context } = createReportTestContext({
    scope: "model",
    modelType: MODEL_TYPE,
    modelId: MODEL_ID,
    globalArgs,
    dataArtifacts: seeds.map((s, i) => ({
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
    })),
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

function runRecord(
  host: string,
  suffix: string,
  over: Record<string, unknown> = {},
): Seed {
  return {
    name: `run-${suffix}-${host}`,
    body: {
      runId: `${suffix}-${host}`,
      action: "osUpdate",
      host,
      outcome: "updated",
      beforeUpdates: 3,
      afterUpdates: 0,
      packages: null,
      packagesChanged: null,
      images: null,
      imagesChanged: null,
      snapshot: null,
      rolledBack: false,
      needsReboot: false,
      timestamp: "2026-09-30T11:00:00Z",
      ...over,
    },
  };
}

Deno.test("history report: metadata names the model-scoped report", () => {
  assertEquals(report.name, "@dmc/patch-history");
  assertEquals(report.scope, "model");
});

Deno.test("history report: no data renders the empty notice", async () => {
  const res = await run([]);
  assertStringIncludes(res.markdown, "# Fleet Host Detail");
  assertStringIncludes(res.markdown, "No data yet");
  assertEquals(res.json, { status: "no-data" });
});

Deno.test("history report: package diff table lists changed, added and removed packages", async () => {
  const res = await run([
    inventory("web1"),
    runRecord("web1", "a", {
      packages: [
        { name: "openssl", from: "3.0.1", to: "3.0.2" },
        { name: "new-lib", from: null, to: "2.0" },
        { name: "old-lib", from: "1.0", to: null },
      ],
      packagesChanged: 3,
    }),
  ]);
  const md = res.markdown;
  assertStringIncludes(
    md,
    "<details><summary>2026-09-30 11:00 UTC — osUpdate details</summary>",
  );
  assertStringIncludes(md, "| Package | From | To |");
  assertStringIncludes(md, "| ------- | ---- | -- |");
  assertStringIncludes(md, "| openssl | 3.0.1 | 3.0.2 |");
  assertStringIncludes(md, "| new-lib | — | 2.0 |");
  assertStringIncludes(md, "| old-lib | 1.0 | removed |");
  // The runs table summarises the same run.
  assertStringIncludes(
    md,
    "| 2026-09-30 11:00 UTC | 📦 osUpdate | updated | 3→0 updates · 3 pkgs | ok | — |",
  );
});

Deno.test("history report: a long package diff is cut at 200 rows with a count of the rest", async () => {
  const packages = Array.from({ length: 250 }, (_, i) => ({
    name: `pkg${String(i).padStart(3, "0")}`,
    from: "1",
    to: "2",
  }));
  const res = await run([
    inventory("web1"),
    runRecord("web1", "a", { packages, packagesChanged: 250 }),
  ]);
  assertStringIncludes(res.markdown, "| pkg199 | 1 | 2 |");
  assertEquals(res.markdown.includes("| pkg200 |"), false);
  assertStringIncludes(res.markdown, "| … | 50 more | |");
});

Deno.test("history report: image diff table shows refs with digests cut to 19 characters", async () => {
  const res = await run([
    inventory("dock1"),
    runRecord("dock1", "d", {
      action: "docker",
      outcome: "updated",
      images: [
        {
          ref: "nginx:1",
          from: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          to: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        },
        { ref: "redis:7", from: null, to: "sha256:cccccccccccccccc" },
      ],
      imagesChanged: 2,
    }),
  ]);
  const md = res.markdown;
  assertStringIncludes(md, "| Image | From | To |");
  assertStringIncludes(md, "| ----- | ---- | -- |");
  assertStringIncludes(
    md,
    "| nginx:1 | sha256:aaaaaaaaaaaa | sha256:bbbbbbbbbbbb |",
  );
  assertStringIncludes(md, "| redis:7 | — | sha256:cccccccccccc |");
  assertStringIncludes(md, "| 🐳 docker | updated | 2 image(s) |");
  assertStringIncludes(md, "— docker details</summary>");
});

Deno.test("history report: runs are listed newest first with outcome marks and reboot state", async () => {
  const res = await run([
    inventory("web1"),
    runRecord("web1", "old", {
      outcome: "rolled-back",
      rolledBack: true,
      snapshot: "preupdate-1",
      timestamp: "2026-09-01T00:00:00Z",
    }),
    runRecord("web1", "mid", {
      action: "reboot",
      outcome: "unhealthy",
      needsReboot: null,
      timestamp: "2026-09-15T00:00:00Z",
    }),
    runRecord("web1", "new", {
      action: "docker",
      outcome: "no-change",
      imagesChanged: 0,
      needsReboot: true,
      timestamp: "2026-09-20T00:00:00Z",
    }),
  ]);
  const md = res.markdown;
  const newest = md.indexOf("| 2026-09-20 00:00 UTC |");
  const middle = md.indexOf("| 2026-09-15 00:00 UTC |");
  const oldest = md.indexOf("| 2026-09-01 00:00 UTC |");
  assertEquals(newest < middle && middle < oldest, true);
  assertStringIncludes(md, "| 🔄 reboot | ❌ unhealthy | — | — | — |");
  assertStringIncludes(
    md,
    "| 🐳 docker | no-change | no change | ⚠️ needed | — |",
  );
  assertStringIncludes(
    md,
    "| 📦 osUpdate | ⏪ rolled-back | 3→0 updates | ok | yes |",
  );
  assertStringIncludes(md, "**1 host(s)** · **3 recorded run(s)**");
});

Deno.test("history report: host status lines cover OS, reboot, health, app drift and docker", async () => {
  const res = await run([
    inventory("valkey", {
      updatesCount: 4,
      securityUpdatesCount: 1,
      heldBackCount: 2,
      distUpgradeRequired: true,
      needsReboot: true,
      rebootReason: "kernel mismatch",
      reachMethod: "pct",
      dockerEngine: "27.0.1",
      dockerImages: [
        { container: "web", image: "nginx:1", updateAvailable: true },
        { container: "db", image: "pg:16", updateAvailable: false },
      ],
      health: {
        healthy: false,
        checks: [
          { label: "app", ok: false, detail: "status 503" },
          { label: "svc", ok: true, detail: "active" },
        ],
      },
    }),
    {
      modelType: CS_TYPE,
      modelId: "cs-valkey",
      name: "updateCheck",
      body: {
        name: "Valkey",
        node: "pve",
        ctid: 301,
        installedVersion: "9.0.4",
        latestVersion: "9.0.4",
        upstreamVersion: "9.1.2",
        updateAvailable: false,
        osManaged: true,
      },
    },
  ]);
  const md = res.markdown;
  assertStringIncludes(md, "## valkey");
  assertStringIncludes(
    md,
    "**Debian GNU/Linux 12** · apt · Proxmox CT · ctid 301 on pve · via pct · scanned 2026-09-30 10:00 UTC",
  );
  assertStringIncludes(
    md,
    "- **OS**: **4** updates · 🔒 1 security · 2 held back · needs dist-upgrade · 400 installed",
  );
  assertStringIncludes(md, "- **Reboot**: ⚠️ required (kernel mismatch)");
  assertStringIncludes(md, "- **Health**: ❌ unhealthy — ✗ app, ✓ svc");
  assertStringIncludes(
    md,
    "- **App**: Valkey 9.0.4 (current) — upstream 9.1.2 (OS-managed, not installable here)",
  );
  assertStringIncludes(
    md,
    "- **Docker**: 🐳 27.0.1 · 2 container(s) · ⬆️ 1 with updates",
  );
  assertStringIncludes(md, "  - web `nginx:1` ⬆️");
  assertStringIncludes(md, "  - db `pg:16`");
  assertStringIncludes(md, "_No runs recorded._");
});

Deno.test("history report: a host with a pending app update shows the upward arrow", async () => {
  const res = await run([
    inventory("valkey"),
    {
      modelType: CS_TYPE,
      modelId: "cs-valkey",
      name: "updateCheck",
      body: {
        name: "Valkey",
        installedVersion: "9.0.4",
        latestVersion: "9.1.2",
        updateAvailable: true,
      },
    },
  ]);
  assertStringIncludes(res.markdown, "- **App**: ⬆️ Valkey 9.0.4 → 9.1.2");
});

Deno.test("history report: location comes from the machine decoration", async () => {
  const res = await run(
    [inventory("vm1"), inventory("plain")],
    { machines: [{ host: "vm1", vm: { proxmoxNode: "pve", vmid: 100 } }] },
  );
  assertStringIncludes(res.markdown, "Proxmox VM · vmid 100 on pve");
  assertStringIncludes(res.markdown, "host / VPS");
});

Deno.test("history report: a host with runs but no current inventory is marked not scanned", async () => {
  const res = await run([runRecord("gone", "a")]);
  assertStringIncludes(res.markdown, "## gone");
  assertStringIncludes(res.markdown, "_Not scanned recently._");
  assertStringIncludes(res.markdown, "### Runs");
  assertEquals(
    (res.json.hosts as Array<{ host: string; os: unknown }>)[0].os,
    null,
  );
});

Deno.test("history report: json summary carries per-host runs", async () => {
  const res = await run([
    inventory("web1", { updatesCount: 2 }),
    runRecord("web1", "a", { packagesChanged: 4 }),
    { name: "bad", body: null, raw: "{nope" },
  ]);
  const hosts = res.json.hosts as Array<Record<string, unknown>>;
  assertEquals(res.json.totalRuns, 1);
  assertEquals(hosts[0].host, "web1");
  assertEquals(hosts[0].updatesCount, 2);
  assertEquals(hosts[0].app, null);
  assertEquals((hosts[0].runs as Array<Record<string, unknown>>)[0], {
    action: "osUpdate",
    outcome: "updated",
    packagesChanged: 4,
    imagesChanged: null,
    rolledBack: false,
    timestamp: "2026-09-30T11:00:00Z",
  });
});
