import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { createReportTestContext } from "jsr:@systeminit/swamp-testing@0.20260604.20";
import { report } from "./patch_prune_history.ts";

const MODEL_TYPE = "@dmc/patch/fleet";
const MODEL_ID = "fleet-id";

interface Seed {
  name: string;
  version?: number;
  body: unknown;
  raw?: string;
}

async function run(seeds: Seed[]) {
  const { context } = createReportTestContext({
    scope: "model",
    modelType: MODEL_TYPE,
    modelId: MODEL_ID,
    dataArtifacts: seeds.map((s, i) => ({
      modelType: MODEL_TYPE,
      modelId: MODEL_ID,
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

const SNAPSHOT_RUN = {
  scannedAt: "2026-09-29T08:30:00.000Z",
  kind: "snapshots",
  dryRun: false,
  pruned: [
    { host: "web1", name: "preupdate-1", detail: "vmid:100" },
    { host: "db1", name: "preupdate-2", detail: null },
  ],
  kept: [
    { host: "app1", name: "preupdate-3", reason: "reboot not confirmed" },
  ],
};

const IMAGE_RUN = {
  scannedAt: "2026-09-30T09:15:00.000Z",
  kind: "images",
  dryRun: true,
  pruned: [{ host: "dock1", name: "nginx:1", detail: "sha256:0123456789ab" }],
  kept: [],
};

Deno.test("prune history report: metadata names the model-scoped report", () => {
  assertEquals(report.name, "@dmc/patch-prune-history");
  assertEquals(report.scope, "model");
});

Deno.test("prune history report: no runs renders the empty notice", async () => {
  const res = await run([
    { name: "snap-web1-1", body: { status: "active" } },
  ]);
  assertStringIncludes(res.markdown, "No prune runs recorded yet");
  assertEquals(res.json, { status: "no-data" });
});

Deno.test("prune history report: a snapshot prune run renders its summary row and detail tables", async () => {
  const res = await run([
    { name: "prune-snapshots-2026-09-29T08-30-00-000Z", body: SNAPSHOT_RUN },
  ]);
  const md = res.markdown;
  assertStringIncludes(md, "# Prune History");
  assertStringIncludes(md, "**1 run(s)** · **2 item(s) retired**");
  assertStringIncludes(md, "| When | Kind | Mode | Retired | Kept |");
  assertStringIncludes(
    md,
    "| 2026-09-29 08:30 UTC | snapshots | live | **2** | 1 |",
  );
  assertStringIncludes(
    md,
    "<details><summary>2026-09-29 08:30 — snapshots (live)</summary>",
  );
  assertStringIncludes(md, "| Host | Item | Detail |");
  assertStringIncludes(md, "| web1 | preupdate-1 | vmid:100 |");
  assertStringIncludes(md, "| db1 | preupdate-2 | — |");
  assertStringIncludes(md, "| Host | Item | Reason |");
  assertStringIncludes(md, "| app1 | preupdate-3 | reboot not confirmed |");
  assertStringIncludes(md, "</details>");
  assertEquals(res.json, {
    totalRuns: 1,
    totalRetired: 2,
    runs: [{
      scannedAt: "2026-09-29T08:30:00.000Z",
      kind: "snapshots",
      dryRun: false,
      retired: 2,
      kept: 1,
    }],
  });
});

Deno.test("prune history report: runs are listed newest first with dry-run marked", async () => {
  const res = await run([
    { name: "prune-snapshots-a", body: SNAPSHOT_RUN },
    { name: "prune-images-b", body: IMAGE_RUN },
  ]);
  const md = res.markdown;
  assertStringIncludes(md, "**2 run(s)** · **3 item(s) retired**");
  assertStringIncludes(
    md,
    "| 2026-09-30 09:15 UTC | images | dry-run | **1** | 0 |",
  );
  assertEquals(
    md.indexOf("| 2026-09-30 09:15 UTC |") <
      md.indexOf("| 2026-09-29 08:30 UTC |"),
    true,
  );
  assertEquals(
    (res.json.runs as Array<{ kind: string }>).map((r) => r.kind),
    ["images", "snapshots"],
  );
});

Deno.test("prune history report: a run that retired nothing shows a dash and no detail block", async () => {
  const res = await run([{
    name: "prune-snapshots-empty",
    body: {
      scannedAt: "2026-09-28T00:00:00.000Z",
      kind: "snapshots",
      dryRun: false,
      pruned: [],
      kept: [],
    },
  }]);
  assertStringIncludes(
    res.markdown,
    "| 2026-09-28 00:00 UTC | snapshots | live | — | 0 |",
  );
  assertEquals(res.markdown.includes("<details>"), false);
  assertEquals(res.json.totalRetired, 0);
});

Deno.test("prune history report: only the latest version of a run is used; other records and bad JSON are ignored", async () => {
  const res = await run([
    {
      name: "prune-images-x",
      version: 1,
      body: { ...IMAGE_RUN, pruned: [], kept: [] },
    },
    { name: "prune-images-x", version: 2, body: IMAGE_RUN },
    { name: "prune-bad", body: null, raw: "{oops" },
    { name: "run-osUpdate-web1-x", body: { host: "web1" } },
  ]);
  assertEquals(res.json.totalRuns, 1);
  assertEquals(res.json.totalRetired, 1);
});

Deno.test("prune history report: a retired run renders deleted records and kept records with reasons", async () => {
  const live = {
    scannedAt: "2026-10-04T12:00:00.000Z",
    kind: "retired",
    dryRun: false,
    pruned: [
      { host: "old1", name: "old1", detail: "inventory" },
      { host: "old1", name: "run-osUpdate-old1-1", detail: "run" },
    ],
    kept: [
      {
        host: "old1",
        name: "snap-old1-1",
        reason: "active snapshot record: the snapshot may still exist",
      },
    ],
  };
  const dry = { ...live, scannedAt: "2026-10-03T12:00:00.000Z", dryRun: true };
  const res = await run([
    { name: "prune-retired-2026-10-04T12-00-00-000Z", body: live },
    { name: "prune-retired-2026-10-03T12-00-00-000Z", body: dry },
  ]);
  const md = res.markdown;
  assertStringIncludes(
    md,
    "| 2026-10-04 12:00 UTC | retired | live | **2** | 1 |",
  );
  assertStringIncludes(
    md,
    "| 2026-10-03 12:00 UTC | retired | dry-run | **2** | 1 |",
  );
  assertStringIncludes(
    md,
    "<details><summary>2026-10-04 12:00 — retired (live)</summary>",
  );
  assertStringIncludes(md, "**Deleted**");
  assertStringIncludes(md, "**Would delete**");
  assertStringIncludes(md, "| Host | Record | Spec |");
  assertStringIncludes(md, "| old1 | run-osUpdate-old1-1 | run |");
  assertStringIncludes(
    md,
    "| old1 | snap-old1-1 | active snapshot record: the snapshot may still exist |",
  );
  assertEquals(
    (res.json.runs as Array<{ kind: string }>).map((r) => r.kind),
    ["retired", "retired"],
  );
});
