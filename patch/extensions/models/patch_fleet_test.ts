/**
 * Unit tests for @dmc/patch/fleet.
 *
 * Nothing here needs a real host. Methods reach other models through
 * `context.runModel` / `readModelData` / `definitionRepository`; pre-flight checks run
 * `swamp model method run` as a subprocess. Both paths end in `testdata/fake_swamp.sh`,
 * a test double that prints canned JSON chosen by `FAKE_SWAMP_*` environment
 * variables: `mkCtx` gives methods a `runModel` that runs the fake with the CLI
 * arguments, and checks run it as `SWAMP_BIN`. The model reads `SWAMP_BIN` when it
 * loads, so it is imported dynamically after the variable is set.
 */
import {
  assert,
  assertEquals,
  assertMatch,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing@0.20260604.20";

const FAKE_SWAMP = new URL("./testdata/fake_swamp.sh", import.meta.url)
  .pathname;
Deno.env.set("SWAMP_BIN", FAKE_SWAMP);
const fleet = await import("./patch_fleet.ts");
type SwampApi = import("./patch_fleet.ts").SwampApi;
const { model } = fleet;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type Env = Record<string, string>;

/** Run `fn` with the given FAKE_SWAMP_* variables set, then remove them. */
async function withFake<T>(env: Env, fn: () => Promise<T>): Promise<T> {
  const all: Env = { ...env, FAKE_SWAMP_STATE: crypto.randomUUID() };
  for (const [k, v] of Object.entries(all)) Deno.env.set(k, v);
  try {
    return await fn();
  } finally {
    // Remove the fake's sequence marker files for this case.
    await new Deno.Command(FAKE_SWAMP, { args: ["cleanup"] }).output();
    for (const k of Object.keys(all)) Deno.env.delete(k);
  }
}

/** What the fake prints for `<ssh-model> script`: one artifact per host. */
function scriptOut(host: string, stdout: string, exitCode = 0): string {
  return JSON.stringify({
    dataArtifacts: [{ attributes: { host, stdout, exitCode } }],
  });
}

/** What the fake prints for a health batch: one `@@PATCH-HC <i> rc=<rc>` line per rc. */
function hcOut(host: string, ...rcs: number[]): string {
  return scriptOut(
    host,
    rcs.map((rc, i) => `@@PATCH-HC ${i} rc=${rc}\n`).join(""),
  );
}

/** What the fake prints for `<ssh-model> exec`: stdout plus the rc sentinel line. */
function execOut(stdout: string, rc = 0): string {
  return JSON.stringify({
    dataArtifacts: [{
      attributes: {
        host: "x",
        stdout: `${stdout}\n${fleet.RC_SENTINEL}=${rc}\n`,
        exitCode: 0,
      },
    }],
  });
}

const INVENTORY = {
  _kind: "patch-inventory",
  schemaVersion: 3,
  hostname: "web1",
  osType: "Debian GNU/Linux",
  osVersion: "12",
  packageManager: "apt",
  updatesCount: 3,
  securityUpdatesCount: 1,
  heldBackCount: 0,
  removalsCount: 0,
  distUpgradeRequired: false,
  totalPackages: 400,
  needsReboot: false,
  rebootReason: null,
  dockerEngine: null,
  dockerImages: null,
  scannedAt: "2026-09-30T10:00:00Z",
};

/** A collector stdout: some noise, then the marker JSON line. */
function collectorStdout(over: Record<string, unknown> = {}): string {
  return `apt-get update skipped\n${
    JSON.stringify({ ...INVENTORY, ...over })
  }\n`;
}

interface ModelDatum {
  name: string;
  isLatest: boolean;
  attributes: Record<string, unknown>;
  /** The `modelName` tag stamped when the record was written (default: the current name). */
  modelName?: string;
}

const TEST_MODEL_TYPE = { normalized: "@dmc/patch/fleet" };
const TEST_MODEL_ID = "11111111-2222-3333-4444-555555555555";

/**
 * A stub `definitionRepository`. `findByNameGlobal` answers from FAKE_SWAMP_MODEL_GET
 * (a `{ globalArguments }` JSON document) and FAKE_SWAMP_GET_RC, read at call time.
 * It gives null (no such model) when the variable is unset, not JSON, or the rc is not 0.
 */
const fakeDefinitions = {
  findByNameGlobal: (_name: string) => {
    const raw = Deno.env.get("FAKE_SWAMP_MODEL_GET");
    if ((Deno.env.get("FAKE_SWAMP_GET_RC") ?? "0") !== "0" || raw === undefined) {
      return Promise.resolve(null);
    }
    let parsed: { globalArguments?: Record<string, unknown> };
    try {
      parsed = JSON.parse(raw);
    } catch {
      return Promise.resolve(null);
    }
    return Promise.resolve({
      definition: { globalArguments: parsed?.globalArguments ?? {} },
      type: {},
    });
  },
};

/** The CLI SwampApi a check uses, for direct helper tests (runs the fake as SWAMP_BIN). */
const CLI = fleet.checkSwamp({
  repoDir: "/r",
  definitionRepository: fakeDefinitions,
});

/** A record of another model, as `readModelData` returns it. */
interface OtherRecord {
  model: string;
  spec: string;
  name: string;
  attributes: Record<string, unknown>;
}

/** One `runModel` call the adapter received. */
interface RunModelCall {
  definition: string;
  method: string;
  arguments?: Record<string, unknown>;
}

/**
 * A `runModel` like swamp's, backed by the fake: it runs `fake_swamp.sh` with the CLI
 * arguments (`model method run <def> <method> --json --quiet --input …`), so the
 * FAKE_SWAMP_* knobs and the call log work as for the CLI. rc 0 → `ok` with the
 * printed artifacts as resources (empty output = no resources). Otherwise → not ok
 * with stderr (or stdout) as the message; then, like @swamp/ssh, every printed host
 * artifact is stored as `run-<method>-<host>` with `startedAt` = now, for `readModelData`.
 * After `maxCalls` calls it answers like swamp at its cap, without running the fake.
 */
function fakeRunModel(
  store: OtherRecord[],
  calls: RunModelCall[],
  maxCalls = Infinity,
) {
  return async (opts: RunModelCall) => {
    calls.push(opts);
    if (calls.length > maxCalls) {
      return {
        ok: false as const,
        error: {
          message:
            "Maximum cross-model invocation count (100) exceeded in this execution. Reduce the number of runModel calls.",
        },
      };
    }
    const out = await new Deno.Command(FAKE_SWAMP, {
      args: fleet.methodRunArgv(
        opts.definition,
        opts.method,
        opts.arguments ?? {},
        "/tmp/swamp-test",
      ),
      stdout: "piped",
      stderr: "piped",
    }).output();
    const stdout = new TextDecoder().decode(out.stdout).trim();
    const stderr = new TextDecoder().decode(out.stderr).trim();
    let artifacts: Array<{ attributes?: Record<string, unknown> }> = [];
    let parsed = stdout === "";
    try {
      artifacts = JSON.parse(stdout).dataArtifacts ?? [];
      parsed = true;
    } catch { /* not JSON */ }
    if (out.code === 0 && parsed) {
      return {
        ok: true as const,
        resources: artifacts.map((a, i) => ({
          name: `${opts.method}-${i}`,
          specName: "result",
          attributes: a.attributes ?? {},
        })),
      };
    }
    if (out.code !== 0) {
      for (const a of artifacts) {
        const host = a.attributes?.host;
        if (typeof host !== "string") continue;
        store.push({
          model: opts.definition,
          spec: "runResult",
          name: `run-${opts.method}-${host}`,
          attributes: { ...a.attributes, startedAt: new Date().toISOString() },
        });
      }
    }
    return { ok: false as const, error: { message: stderr || stdout } };
  };
}

/**
 * Build a method context. `data` (by spec name) feeds the stub `dataRepository`, which
 * answers by model id like swamp does. Records that are not the latest version are not
 * returned, because `findAllForModel` returns the latest version of each name only.
 * `runModel` is the fake-backed adapter (`fakeRunModel`); `definitionRepository` is
 * `fakeDefinitions`. `readModelData` serves OTHER models' records (`otherData`, plus
 * the run results of failed calls) and throws for this model's own name: the model
 * must read its own records by model id, because `readModelData` matches the
 * `modelName` tag and misses records of a renamed model.
 */
function mkCtx(
  globalArgs: unknown,
  opts: {
    stored?: Record<string, Record<string, unknown>>;
    data?: Record<string, ModelDatum[]>;
    /** Names for which the deleteResource stub throws. */
    deleteFails?: string[];
    /** Records of other models that readModelData serves. */
    otherData?: OtherRecord[];
    /** runModel answers like swamp at its cap after this many calls. */
    maxRunModelCalls?: number;
  } = {},
) {
  const t = createModelTestContext({
    globalArgs: model.globalArguments.parse(globalArgs) as Record<
      string,
      unknown
    >,
    definition: { name: "fleet" },
    storedResources: opts.stored,
  });
  const store: OtherRecord[] = [...(opts.otherData ?? [])];
  const calls: RunModelCall[] = [];
  const readModelData = (modelName: string, specName?: string) => {
    if (modelName === "fleet") {
      throw new Error("readModelData must not be used for the model's own data");
    }
    // Latest version of each name: the last record stored under it.
    const latest = new Map<string, OtherRecord>();
    for (const r of store) {
      if (r.model === modelName && (!specName || r.spec === specName)) {
        latest.set(r.name, r);
      }
    }
    return Promise.resolve(
      [...latest.values()].map((r) => ({
        name: r.name,
        specName: r.spec,
        attributes: r.attributes,
      })),
    );
  };
  const records = Object.entries(opts.data ?? {}).flatMap(([spec, rows]) =>
    rows.filter((r) => r.isLatest).map((r) => ({ spec, row: r }))
  );
  const byId = (type: unknown, modelId: string) => {
    if (type !== TEST_MODEL_TYPE || modelId !== TEST_MODEL_ID) {
      throw new Error(`read by the wrong model type or id: ${modelId}`);
    }
  };
  const dataRepository = {
    findAllForModel: (type: unknown, modelId: string) => {
      byId(type, modelId);
      return Promise.resolve(records.map(({ spec, row }) => ({
        name: row.name,
        version: 1,
        tags: {
          specName: spec,
          type: "resource",
          modelName: row.modelName ?? "fleet",
        },
      })));
    },
    getContent: (type: unknown, modelId: string, name: string) => {
      byId(type, modelId);
      const rec = records.find((r) => r.row.name === name);
      return Promise.resolve(
        rec ? new TextEncoder().encode(JSON.stringify(rec.row.attributes)) : null,
      );
    },
  };
  // createModelTestContext has no deleteResource, so this stub records the deletions.
  const deleted: string[] = [];
  const deleteResource = (name: string) => {
    if (opts.deleteFails?.includes(name)) {
      return Promise.reject(new Error(`cannot delete ${name}`));
    }
    deleted.push(name);
    return Promise.resolve();
  };
  return {
    // The testing context and the model's own context type differ slightly.
    ctx: {
      ...t.context,
      modelType: TEST_MODEL_TYPE,
      modelId: TEST_MODEL_ID,
      dataRepository,
      readModelData,
      runModel: fakeRunModel(store, calls, opts.maxRunModelCalls),
      definitionRepository: fakeDefinitions,
      deleteResource,
    } as never,
    deleted,
    /** Every runModel call, in order. */
    calls,
    written: (spec: string) =>
      t.getWrittenResources().filter((r) => r.specName === spec),
    one: (spec: string) => {
      const found = t.getWrittenResources().filter((r) => r.specName === spec);
      assertEquals(found.length, 1, `expected one "${spec}" resource`);
      return found[0].data;
    },
    logs: t.getLogs,
    getLogsByLevel: t.getLogsByLevel,
  };
}

/** Local HTTP server. `status(n)` gives the status for the n-th request. */
function startServer(status: (n: number) => number) {
  let n = 0;
  const ac = new AbortController();
  const server = Deno.serve(
    { hostname: "127.0.0.1", port: 0, signal: ac.signal, onListen() {} },
    () => new Response(null, { status: status(++n) }),
  );
  return {
    url: `http://127.0.0.1:${server.addr.port}/`,
    requests: () => n,
    stop: async () => {
      ac.abort();
      await server.finished;
    },
  };
}

const SNAPSHOT = {
  host: "web1",
  kind: "vm",
  vmid: 100,
  proxmoxNode: "pve",
  name: "preupdate-1",
  reason: "safeOsUpdate",
  createdAt: "2026-01-01T00:00:00.000Z",
  retainUntil: "2026-01-08T00:00:00.000Z",
  healthConfirmed: true,
  rebootRequired: false,
  rebootConfirmed: false,
  status: "active",
  prunedAt: null,
};

function snapDatum(
  name: string,
  over: Record<string, unknown> = {},
  isLatest = true,
): ModelDatum {
  return { name, isLatest, attributes: { ...SNAPSHOT, ...over } };
}

const IMAGE = {
  host: "dock1",
  ref: "nginx:1",
  imageId: "sha256:0123456789abcdef0123456789abcdef",
  replacedBy: "sha256:fedcba9876543210",
  service: "web",
  reason: "safeUpdate",
  createdAt: "2026-01-01T00:00:00.000Z",
  retainUntil: "2026-01-08T00:00:00.000Z",
  healthConfirmed: true,
  status: "active",
  prunedAt: null,
};

// ---------------------------------------------------------------------------
// Schema: Machine, HealthCheck, global arguments
// ---------------------------------------------------------------------------

function parseMachine(machine: unknown) {
  return model.globalArguments.parse({ sshModel: "ssh", machines: [machine] })
    .machines[0];
}

Deno.test("schema: a minimal machine gets its defaults", () => {
  const args = model.globalArguments.parse({
    sshModel: "ssh",
    machines: [{ host: "web1" }],
  });
  assertEquals(args.proxmoxNodes, []);
  assertEquals(args.machines[0].host, "web1");
  assertEquals(args.machines[0].os, true);
  assertEquals(args.machines[0].health, []);
  assertEquals(args.machines[0].ct, undefined);
  assertEquals(args.machines[0].source, undefined);
});

Deno.test("schema: machines default to an empty fleet", () => {
  assertEquals(model.globalArguments.parse({ sshModel: "ssh" }).machines, []);
});

Deno.test("schema: http health check defaults (expectStatus 200, timeoutSec 10)", () => {
  const m = parseMachine({
    host: "h",
    health: [{ type: "http", url: "http://h.example/health" }],
  });
  assertEquals(m.health[0], {
    type: "http",
    url: "http://h.example/health",
    expectStatus: 200,
    timeoutSec: 10,
  });
});

Deno.test("schema: command health check defaults (timeoutSec 30)", () => {
  const m = parseMachine({
    host: "h",
    health: [{ type: "command", run: "test -f /ok" }],
  });
  assertEquals(m.health[0], {
    type: "command",
    run: "test -f /ok",
    timeoutSec: 30,
  });
});

Deno.test("schema: service health check keeps its name and optional label", () => {
  const m = parseMachine({
    host: "h",
    health: [
      { type: "service", name: "nginx" },
      { type: "service", name: "sshd", label: "ssh daemon" },
    ],
  });
  assertEquals(m.health[0], { type: "service", name: "nginx" });
  assertEquals(m.health[1].label, "ssh daemon");
});

Deno.test("schema: explicit health values override the defaults", () => {
  const m = parseMachine({
    host: "h",
    health: [
      {
        type: "http",
        label: "app",
        url: "http://h/x",
        expectStatus: 204,
        timeoutSec: 3,
      },
      { type: "command", run: "true", timeoutSec: 5 },
    ],
  });
  assertEquals(m.health[0], {
    type: "http",
    label: "app",
    url: "http://h/x",
    expectStatus: 204,
    timeoutSec: 3,
  });
  assertEquals(m.health[1].type === "command" && m.health[1].timeoutSec, 5);
});

Deno.test("schema: an invalid health type is rejected", () => {
  assertThrows(() =>
    parseMachine({ host: "h", health: [{ type: "tcp", port: 22 }] })
  );
});

Deno.test("schema: health checks reject bad fields", () => {
  assertThrows(() =>
    parseMachine({ host: "h", health: [{ type: "http", url: "not a url" }] })
  );
  assertThrows(() =>
    parseMachine({ host: "h", health: [{ type: "service", name: "" }] })
  );
  assertThrows(() =>
    parseMachine({ host: "h", health: [{ type: "command", run: "" }] })
  );
  assertThrows(() => parseMachine({ host: "h", health: [{ type: "http" }] }));
});

Deno.test("schema: ct and source decorate a community-script CT", () => {
  const m = parseMachine({
    host: "valkey",
    reach: "pct",
    ct: { proxmoxNode: "pve", ctid: 301 },
    source: { type: "community-script", model: "valkey" },
  });
  assertEquals(m.reach, "pct");
  assertEquals(m.ct, { proxmoxNode: "pve", ctid: 301 });
  assertEquals(m.source, { type: "community-script", model: "valkey" });
});

Deno.test("schema: a plain CT needs only ct (no source)", () => {
  const m = parseMachine({ host: "c", ct: { proxmoxNode: "pve", ctid: 5 } });
  assertEquals(m.source, undefined);
});

Deno.test("schema: bad ct, source, reach, vm and host values are rejected", () => {
  assertThrows(() =>
    parseMachine({ host: "c", ct: { proxmoxNode: "", ctid: 5 } })
  );
  assertThrows(() =>
    parseMachine({ host: "c", ct: { proxmoxNode: "pve", ctid: 1.5 } })
  );
  assertThrows(() =>
    parseMachine({ host: "c", source: { type: "github-release", model: "m" } })
  );
  assertThrows(() =>
    parseMachine({ host: "c", source: { type: "community-script", model: "" } })
  );
  assertThrows(() => parseMachine({ host: "c", reach: "winrm" }));
  assertThrows(() =>
    parseMachine({ host: "v", vm: { proxmoxNode: "pve", vmid: "100" } })
  );
  assertThrows(() => parseMachine({ host: "" }));
  assertThrows(() => parseMachine({}));
});

Deno.test("schema: docker decoration defaults healthExpectStatus to 200", () => {
  const m = parseMachine({ host: "d", docker: { service: "web" } });
  assertEquals(m.docker?.healthExpectStatus, 200);
  assertThrows(() => parseMachine({ host: "d", docker: { healthUrl: "nope" } }));
});

Deno.test("schema: sshModel is required and non-empty", () => {
  assertThrows(() => model.globalArguments.parse({}));
  assertThrows(() => model.globalArguments.parse({ sshModel: "" }));
});

Deno.test("schema: snapshot record defaults kind to vm; run record action is an enum", () => {
  const snap = model.resources.snapshot.schema.parse({
    ...SNAPSHOT,
    kind: undefined,
  });
  assertEquals(snap.kind, "vm");
  assertThrows(() =>
    model.resources.snapshot.schema.parse({ ...SNAPSHOT, status: "gone" })
  );
  const run = {
    runId: "r",
    action: "rollback",
    host: "h",
    outcome: "rolled-back",
    beforeUpdates: null,
    afterUpdates: null,
    packages: [{ name: "curl", from: "1", to: null }],
    packagesChanged: 1,
    images: null,
    imagesChanged: null,
    snapshot: null,
    rolledBack: true,
    needsReboot: null,
    timestamp: "2026-09-30T00:00:00Z",
  };
  assertEquals(model.resources.run.schema.parse(run).action, "rollback");
  assertThrows(() =>
    model.resources.run.schema.parse({ ...run, action: "format-disk" })
  );
});

Deno.test("schema: method arguments carry their documented defaults", () => {
  assertEquals(model.methods.safeOsUpdate.arguments.parse({ host: "h" }), {
    host: "h",
    mode: "safe",
    retentionHours: 168,
    rollbackOnFailure: true,
    healthGraceSec: 120,
  });
  assertThrows(() =>
    model.methods.safeOsUpdate.arguments.parse({
      host: "h",
      healthGraceSec: -1,
    })
  );
  assertThrows(() =>
    model.methods.reboot.arguments.parse({ host: "h", healthGraceSec: 1.5 })
  );
  // The baseline gate is the `baseline-healthy` pre-flight check now; its bypass
  // is `--skip-check baseline-healthy`, not a method argument.
  assertEquals("force" in model.methods.safeOsUpdate.arguments.shape, false);
  assertEquals(model.methods.reboot.arguments.parse({ host: "h" }), {
    host: "h",
    force: false,
    wait: true,
    waitTimeoutSec: 300,
    healthGraceSec: 120,
  });
  assertEquals(model.methods.pruneSnapshots.arguments.parse({}), {
    dryRun: false,
    requireRebootConfirmed: true,
  });
  assertEquals(model.methods.pruneImages.arguments.parse({}), {
    dryRun: false,
  });
  assertEquals(model.methods.safeUpdate.arguments.parse({ host: "h" }), {
    host: "h",
    healthTimeoutSec: 120,
    pollIntervalSec: 5,
    rollbackOnFailure: true,
    retentionHours: 168,
  });
  assertThrows(() =>
    model.methods.safeOsUpdate.arguments.parse({ host: "h", mode: "yolo" })
  );
  assertThrows(() => model.methods.reboot.arguments.parse({ host: "" }));
});

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

Deno.test("COLLECTOR_SCRIPT is the bundled bash collector", () => {
  const s = fleet.COLLECTOR_SCRIPT;
  assertEquals(typeof s, "string");
  assert(s.length > 1000);
  assert(s.startsWith("#!/usr/bin/env bash\n"));
  assertStringIncludes(s.split("\n")[1], "patch-inventory.sh");
  assertStringIncludes(s, '"_kind":"patch-inventory"');
  assertStringIncludes(s, "main </dev/null");
  assert(s.endsWith("\n"));
});

Deno.test("RC_SENTINEL is the exec return-code marker", () => {
  assertEquals(fleet.RC_SENTINEL, "__SWAMP_RC__");
});

Deno.test("runName builds a filesystem-safe unique run name", () => {
  assertEquals(
    fleet.runName("osUpdate", "web1", "2026-09-30T10:11:12.345Z"),
    "run-osUpdate-web1-2026-09-30T10-11-12-345Z",
  );
  assertEquals(
    fleet.runName("reboot", "h", "2026-09-30T10:11:12.345Z").includes(":"),
    false,
  );
});

Deno.test("markerLine returns the marker JSON line and ignores noise", () => {
  const line = '{"_kind":"patch-inventory","hostname":"a"}';
  assertEquals(
    fleet.markerLine(`warning: x\n   ${line}   \ntrailer\n`, "patch-inventory"),
    line,
  );
});

Deno.test("markerLine returns the first match, and null when there is none", () => {
  assertEquals(
    fleet.markerLine(
      '{"_kind":"patch-inventory","n":1}\n{"_kind":"patch-inventory","n":2}',
      "patch-inventory",
    ),
    '{"_kind":"patch-inventory","n":1}',
  );
  assertEquals(fleet.markerLine("", "patch-inventory"), null);
  assertEquals(fleet.markerLine("hello\nworld", "patch-inventory"), null);
  // Right kind text but not a JSON object line.
  assertEquals(
    fleet.markerLine('echo "_kind":"patch-inventory"', "patch-inventory"),
    null,
  );
  // Another kind.
  assertEquals(
    fleet.markerLine('{"_kind":"other"}', "patch-inventory"),
    null,
  );
});

Deno.test("utf8b64 round-trips ASCII and non-Latin1 text", () => {
  const decode = (b64: string) =>
    new TextDecoder().decode(
      Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)),
    );
  assertEquals(fleet.utf8b64("hello"), btoa("hello"));
  assertEquals(fleet.utf8b64(""), "");
  const text = "# patch — collector ✓ ünï\n";
  assertEquals(decode(fleet.utf8b64(text)), text);
  // The real collector has non-Latin1 characters in its comments.
  assertEquals(
    decode(fleet.utf8b64(fleet.COLLECTOR_SCRIPT)),
    fleet.COLLECTOR_SCRIPT,
  );
});

Deno.test("isCtMachine recognises ct, legacy proxmox and reach=pct", () => {
  assertEquals(
    fleet.isCtMachine({ host: "a", ct: { proxmoxNode: "pve", ctid: 1 } }),
    true,
  );
  assertEquals(fleet.isCtMachine({ host: "a", proxmox: { model: "m" } }), true);
  assertEquals(fleet.isCtMachine({ host: "a", reach: "pct" }), true);
  assertEquals(fleet.isCtMachine({ host: "a" }), false);
  assertEquals(fleet.isCtMachine({ host: "a", reach: "ssh" }), false);
});

Deno.test("isCtMachine: a vm decoration wins over legacy CT hints", () => {
  const vm = { proxmoxNode: "pve", vmid: 100 };
  assertEquals(fleet.isCtMachine({ host: "a", vm, reach: "pct" }), false);
  assertEquals(
    fleet.isCtMachine({ host: "a", vm, proxmox: { model: "m" } }),
    false,
  );
  // An explicit ct decoration still marks a CT.
  assertEquals(
    fleet.isCtMachine({
      host: "a",
      vm,
      ct: { proxmoxNode: "pve", ctid: 1 },
    }),
    true,
  );
});

Deno.test("appSource prefers source, falls back to legacy proxmox, else null", () => {
  assertEquals(
    fleet.appSource({
      host: "a",
      source: { type: "community-script", model: "valkey" },
    }),
    "valkey",
  );
  assertEquals(
    fleet.appSource({
      host: "a",
      source: { type: "community-script", model: "new" },
      proxmox: { model: "old" },
    }),
    "new",
  );
  assertEquals(fleet.appSource({ host: "a", proxmox: { model: "old" } }), "old");
  assertEquals(fleet.appSource({ host: "a" }), null);
  // A ct alone (plain CT) has no app source.
  assertEquals(
    fleet.appSource({ host: "a", ct: { proxmoxNode: "pve", ctid: 1 } }),
    null,
  );
  // An unknown source type gives no source.
  assertEquals(
    fleet.appSource({ host: "a", source: { type: "other", model: "m" } }),
    null,
  );
});

Deno.test("ctLocation reads the ct decoration without calling swamp", async () => {
  assertEquals(
    await fleet.ctLocation(
      { host: "a", ct: { proxmoxNode: "pve", ctid: 301 } },
      CLI,
    ),
    { node: "pve", ctid: 301 },
  );
});

Deno.test("ctLocation falls back to the legacy proxmox model", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: JSON.stringify({
      globalArguments: { node: "node2", ctid: 402 },
    }),
  }, async () => {
    assertEquals(
      await fleet.ctLocation({ host: "a", proxmox: { model: "m" } }, CLI),
      { node: "node2", ctid: 402 },
    );
  });
});

Deno.test("ctLocation throws when no location can be found", async () => {
  await assertRejects(
    () => fleet.ctLocation({ host: "a" }, CLI),
    Error,
    "no CT location",
  );
  await withFake({
    FAKE_SWAMP_MODEL_GET: JSON.stringify({ globalArguments: { node: "pve" } }),
  }, async () => {
    await assertRejects(
      () => fleet.ctLocation({ host: "a", proxmox: { model: "m" } }, CLI),
      Error,
      "m: no node/ctid",
    );
  });
});

Deno.test("resolveHealthChecks returns the machine's own checks first", async () => {
  const own = [{ type: "service" as const, name: "sshd" }];
  assertEquals(
    await fleet.resolveHealthChecks({
      host: "a",
      health: own,
      source: { type: "community-script", model: "m" },
    }, CLI),
    own,
  );
});

Deno.test("resolveHealthChecks is empty without checks or source", async () => {
  assertEquals(await fleet.resolveHealthChecks({ host: "a" }, CLI), []);
  assertEquals(
    await fleet.resolveHealthChecks({ host: "a", health: [] }, CLI),
    [],
  );
});

Deno.test("resolveHealthChecks derives http + service checks from a community-script source", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: JSON.stringify({
      globalArguments: {
        healthUrl: "http://192.0.2.5:6379/ping",
        healthExpectStatus: 204,
        service: "valkey",
      },
    }),
  }, async () => {
    const checks = await fleet.resolveHealthChecks({
      host: "valkey",
      source: { type: "community-script", model: "valkey-app" },
    }, CLI);
    assertEquals(checks, [
      {
        type: "http",
        label: "valkey-app app HTTP",
        url: "http://192.0.2.5:6379/ping",
        expectStatus: 204,
        timeoutSec: 10,
      },
      { type: "service", label: "valkey active", name: "valkey" },
    ]);
  });
});

Deno.test("resolveHealthChecks: http check defaults to status 200; service-only source", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: JSON.stringify({
      globalArguments: { healthUrl: "http://h/ok" },
    }),
  }, async () => {
    const checks = await fleet.resolveHealthChecks({
      host: "h",
      proxmox: { model: "legacy" }, // legacy reference still counts as a source
    }, CLI);
    assertEquals(checks.length, 1);
    assertEquals(checks[0].type === "http" && checks[0].expectStatus, 200);
  });
  await withFake({
    FAKE_SWAMP_MODEL_GET: JSON.stringify({
      globalArguments: { service: "caddy" },
    }),
  }, async () => {
    const checks = await fleet.resolveHealthChecks({
      host: "h",
      source: { type: "community-script", model: "m" },
    }, CLI);
    assertEquals(checks, [{
      type: "service",
      label: "caddy active",
      name: "caddy",
    }]);
  });
});

Deno.test("resolveHealthChecks is empty when the source has no health data or cannot be read", async () => {
  const machine = {
    host: "h",
    source: { type: "community-script", model: "m" },
  };
  await withFake(
    { FAKE_SWAMP_MODEL_GET: JSON.stringify({ globalArguments: {} }) },
    async () => assertEquals(await fleet.resolveHealthChecks(machine, CLI), []),
  );
  await withFake(
    { FAKE_SWAMP_MODEL_GET: JSON.stringify({}) },
    async () => assertEquals(await fleet.resolveHealthChecks(machine, CLI), []),
  );
  await withFake(
    { FAKE_SWAMP_MODEL_GET: "", FAKE_SWAMP_GET_RC: "1" },
    async () => assertEquals(await fleet.resolveHealthChecks(machine, CLI), []),
  );
});

Deno.test("runScript parses per-host artifacts and keeps partial results on failure", async () => {
  await withFake({
    FAKE_SWAMP_SCRIPT_1: JSON.stringify({
      dataArtifacts: [
        { attributes: { host: "a", stdout: "out-a", exitCode: 0 } },
        { attributes: { host: "b", stdout: "out-b", exitCode: 2 } },
        { attributes: { stdout: "no host" } }, // dropped: no host
        {}, // dropped: no attributes
        { attributes: { host: "c" } }, // defaults
      ],
    }),
    FAKE_SWAMP_SCRIPT_RC: "1", // the method fails when any host fails
  }, async () => {
    assertEquals(await fleet.runScript("ssh", ["a", "b", "c"], "true", 5, CLI), [
      { host: "a", stdout: "out-a", exitCode: 0 },
      { host: "b", stdout: "out-b", exitCode: 2 },
      { host: "c", stdout: "", exitCode: -1 },
    ]);
  });
});

Deno.test("runScript returns [] when there are no artifacts and throws when the call fails with no host result", async () => {
  await withFake({ FAKE_SWAMP_SCRIPT_1: "{}" }, async () => {
    assertEquals(await fleet.runScript("ssh", ["a"], "true", 5, CLI), []);
  });
  await withFake(
    { FAKE_SWAMP_SCRIPT_1: "boom: not json", FAKE_SWAMP_SCRIPT_RC: "1" },
    async () => {
      await assertRejects(
        () => fleet.runScript("ssh", ["a"], "true", 5, CLI),
        Error,
        "ssh script failed: could not parse ssh script output: boom: not json",
      );
    },
  );
});

Deno.test("methodRunArgv: strings as k=v, other values as k:json=, one argv element each", () => {
  assertEquals(
    fleet.methodRunArgv("ssh", "exec", {
      hosts: ["a"],
      command: "echo 'x y'; true",
      captureOutput: true,
      timeoutSec: 30,
    }, "/repo"),
    [
      "model",
      "method",
      "run",
      "ssh",
      "exec",
      "--json",
      "--quiet",
      "--repo-dir",
      "/repo",
      "--input",
      'hosts:json=["a"]',
      "--input",
      "command=echo 'x y'; true",
      "--input",
      "captureOutput:json=true",
      "--input",
      "timeoutSec:json=30",
    ],
  );
});

Deno.test("checkSwamp: keeps the artifacts of a failed call and reports stderr", async () => {
  await withFake({
    FAKE_SWAMP_SCRIPT_1: scriptOut("a", "out-a"),
    FAKE_SWAMP_SCRIPT_RC: "1",
  }, async () => {
    const res = await CLI.run("ssh", "script", { hosts: ["a"], script: "true" });
    assertEquals(res.ok, false);
    assertEquals(res.artifacts, [{ host: "a", stdout: "out-a", exitCode: 0 }]);
  });
  assertEquals(CLI.readData, undefined);
});

Deno.test("methodSwamp maps runModel success and failure, and omits empty arguments", async () => {
  const seen: unknown[] = [];
  const answers = [
    {
      ok: true as const,
      resources: [
        { name: "r1", attributes: { host: "a" } },
        { name: "r2" }, // no attributes: {}
      ],
    },
    { ok: false as const, error: { message: "Unknown argument(s): x" } },
  ];
  const swamp = fleet.methodSwamp({
    runModel: (opts) => {
      seen.push(opts);
      return Promise.resolve(answers[seen.length - 1]);
    },
  });
  assertEquals(await swamp.run("m", "go", { x: 1 }), {
    ok: true,
    artifacts: [{ host: "a" }, {}],
    error: "",
  });
  assertEquals(await swamp.run("m", "go"), {
    ok: false,
    artifacts: [],
    error: "Unknown argument(s): x",
  });
  assertEquals(seen, [
    { definition: "m", method: "go", arguments: { x: 1 } },
    { definition: "m", method: "go" },
  ]);
  // No readModelData in the context: no readData.
  assertEquals(swamp.readData, undefined);
  // No runModel at all (e.g. a remote execution): a failure, not an exception.
  const none = await fleet.methodSwamp({}).run("m", "go");
  assertEquals(none.ok, false);
  assertStringIncludes(none.error, "runModel is not available");
});

Deno.test("globalArguments: null when the model does not exist or there is no definition repository", async () => {
  await withFake({}, async () => {
    assertEquals(await CLI.globalArguments("gone"), null);
  });
  await withFake({ FAKE_SWAMP_MODEL_GET: "{}", FAKE_SWAMP_GET_RC: "1" }, async () => {
    assertEquals(await CLI.globalArguments("m"), null);
  });
  await withFake({ FAKE_SWAMP_MODEL_GET: JSON.stringify({ globalArguments: { a: 1 } }) }, async () => {
    assertEquals(await CLI.globalArguments("m"), { a: 1 });
  });
  assertEquals(await fleet.methodSwamp({}).globalArguments("m"), null);
  assertEquals(await fleet.checkSwamp({ repoDir: "/r" }).globalArguments("m"), null);
});

Deno.test("runScript: a failed call recovers fresh runResult records of the requested hosts and ignores a stale one", async () => {
  const stale = "2020-01-01T00:00:00.000Z";
  const fresh = () => new Date(Date.now() + 1000).toISOString();
  const records = [
    { name: "run-script-a", attributes: { host: "a", stdout: "out-a", exitCode: 0, startedAt: fresh() } },
    { name: "run-script-b", attributes: { host: "b", stdout: "out-b", exitCode: 2, startedAt: fresh() } },
    // stale: from an earlier run
    { name: "run-script-c", attributes: { host: "c", stdout: "old", exitCode: 0, startedAt: stale } },
    // not requested
    { name: "run-script-z", attributes: { host: "z", stdout: "z", exitCode: 0, startedAt: fresh() } },
    // another method
    { name: "run-exec-a", attributes: { host: "a", stdout: "x", exitCode: 0, startedAt: fresh() } },
  ];
  const s = stubSwamp([{ ok: false, error: "script failed on 1/3 host(s): b (exit 2)" }], {
    readData: (model, spec) => {
      assertEquals([model, spec], ["ssh", "runResult"]);
      return Promise.resolve(records);
    },
  });
  const res = await fleet.runScriptOutcome("ssh", ["a", "b", "c"], "true", 5, s.api);
  assertEquals(res.ok, false);
  assertEquals(res.runs, [
    { host: "a", stdout: "out-a", exitCode: 0 },
    { host: "b", stdout: "out-b", exitCode: 2 },
  ]);
  assertStringIncludes(res.error, "b (exit 2)");
  // Only stale records: nothing to recover, so the call's error is thrown.
  const onlyStale = stubSwamp([{ ok: false, error: "script failed" }], {
    readData: () => Promise.resolve([records[2]]),
  });
  await assertRejects(
    () => fleet.runScript("ssh", ["c"], "true", 5, onlyStale.api),
    Error,
    "ssh script failed: script failed",
  );
});

Deno.test("runScript through runModel: a partial failure keeps the hosts the ssh model recorded", async () => {
  // The fake prints both hosts and exits 1, like @swamp/ssh when one host fails. The
  // adapter stores them as runResult records and returns no handles, like runModel.
  await withFake({
    FAKE_SWAMP_SCRIPT_1: JSON.stringify({
      dataArtifacts: [
        { attributes: { host: "a", stdout: "out-a", exitCode: 0 } },
        { attributes: { host: "b", stdout: "", exitCode: 1 } },
      ],
    }),
    FAKE_SWAMP_SCRIPT_RC: "1",
  }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [] }, {
      // A stale record of host c from an earlier run.
      otherData: [{
        model: "ssh",
        spec: "runResult",
        name: "run-script-c",
        attributes: { host: "c", stdout: "old", exitCode: 0, startedAt: "2020-01-01T00:00:00.000Z" },
      }],
    });
    const swamp = fleet.methodSwamp(t.ctx);
    assertEquals(await fleet.runScript("ssh", ["a", "b", "c"], "true", 5, swamp), [
      { host: "a", stdout: "out-a", exitCode: 0 },
      { host: "b", stdout: "", exitCode: 1 },
    ]);
  });
});

Deno.test("nodeExec strips the rc sentinel and returns the rc", async () => {
  await withFake({ FAKE_SWAMP_EXEC: execOut("hello world\n", 3) }, async () => {
    assertEquals(await fleet.nodeExec("ssh", "a", "cmd", 5, CLI), {
      rc: 3,
      out: "hello world",
    });
  });
  await withFake({ FAKE_SWAMP_EXEC: execOut("fine", 0) }, async () => {
    assertEquals(await fleet.nodeExec("ssh", "a", "cmd", 5, CLI), {
      rc: 0,
      out: "fine",
    });
  });
});

Deno.test("nodeExec falls back to exitCode when the sentinel is missing", async () => {
  await withFake({
    FAKE_SWAMP_EXEC: JSON.stringify({
      dataArtifacts: [{ attributes: { stdout: "raw out", exitCode: 7 } }],
    }),
  }, async () => {
    assertEquals(await fleet.nodeExec("ssh", "a", "cmd", 5, CLI), {
      rc: 7,
      out: "raw out",
    });
  });
  await withFake({ FAKE_SWAMP_EXEC: "{}" }, async () => {
    assertEquals(await fleet.nodeExec("ssh", "a", "cmd", 5, CLI), {
      rc: -1,
      out: "",
    });
  });
});

Deno.test("nodeExec throws when the ssh transport fails", async () => {
  await withFake({ FAKE_SWAMP_EXEC: "", FAKE_SWAMP_EXEC_RC: "1" }, async () => {
    await assertRejects(
      () => fleet.nodeExec("ssh", "a", "cmd", 5, CLI),
      Error,
      "ssh transport to a via ssh failed",
    );
  });
});

// ---------------------------------------------------------------------------
// evalHealth
// ---------------------------------------------------------------------------

Deno.test("evalHealth: no checks means healthy", async () => {
  assertEquals(await fleet.evalHealth({ host: "a" }, [], "ssh", CLI), {
    healthy: true,
    results: [],
  });
});

Deno.test("evalHealth: http check passes on the expected status and fails otherwise", async () => {
  const server = startServer((n) => (n === 1 ? 200 : 503));
  try {
    const check = model.globalArguments.parse({
      sshModel: "ssh",
      machines: [{
        host: "a",
        health: [{ type: "http", url: server.url }],
      }],
    }).machines[0].health;
    const ok = await fleet.evalHealth({ host: "a" }, check, "ssh", CLI);
    assertEquals(ok.healthy, true);
    assertEquals(ok.results[0].ok, true);
    assertEquals(ok.results[0].detail, "status 200");
    assertEquals(ok.results[0].label, `http 200 ${server.url}`);
    const bad = await fleet.evalHealth({ host: "a" }, check, "ssh", CLI);
    assertEquals(bad.healthy, false);
    assertEquals(bad.results[0].detail, "status 503");
    assertEquals(server.requests(), 2);
  } finally {
    await server.stop();
  }
});

Deno.test("evalHealth: http check honours expectStatus and a custom label", async () => {
  const server = startServer(() => 204);
  try {
    const res = await fleet.evalHealth({ host: "a" }, [{
      type: "http",
      label: "my app",
      url: server.url,
      expectStatus: 204,
      timeoutSec: 5,
    }], "ssh", CLI);
    assertEquals(res.healthy, true);
    assertEquals(res.results[0].label, "my app");
  } finally {
    await server.stop();
  }
});

Deno.test("evalHealth: an unreachable http endpoint is unhealthy, not an exception", async () => {
  const res = await fleet.evalHealth({ host: "a" }, [{
    type: "http",
    url: "http://127.0.0.1:1/",
    expectStatus: 200,
    timeoutSec: 5,
  }], "ssh", CLI);
  assertEquals(res.healthy, false);
  assertMatch(res.results[0].detail, /^fetch failed: /);
});

Deno.test("evalHealth: service and command checks run in ONE batch on the machine's transport", async () => {
  await withCallLog({ FAKE_SWAMP_HC: hcOut("a", 0, 0) }, async (calls) => {
    const res = await fleet.evalHealth({ host: "a" }, [
      { type: "service", name: "nginx" },
      { type: "command", run: "test -f /ok", timeoutSec: 5 },
    ], "ssh", CLI);
    assertEquals(res.healthy, true);
    assertEquals(res.results, [
      { label: "service nginx active", ok: true, detail: "active" },
      { label: "command: test -f /ok", ok: true, detail: "rc 0" },
    ]);
    const all = await calls();
    assertEquals(all.length, 1);
    assert(all[0].startsWith("ssh script "));
    assertStringIncludes(all[0], 'hosts:json=["a"]');
    // Timeout = the command's timeoutSec + 30 per service check.
    assertStringIncludes(all[0], "timeoutSec:json=35");
  });
  await withFake({ FAKE_SWAMP_HC: hcOut("a", 1, 1) }, async () => {
    const res = await fleet.evalHealth({ host: "a" }, [
      { type: "service", name: "nginx", label: "web" },
      { type: "command", run: "false", timeoutSec: 5 },
    ], "ssh", CLI);
    assertEquals(res.healthy, false);
    assertEquals(res.results[0], {
      label: "web",
      ok: false,
      detail: "not active (rc 1)",
    });
    assertEquals(res.results[1].detail, "rc 1");
  });
});

Deno.test("evalHealth: each check gets its own rc, and a missing marker is 'no result'", async () => {
  // Only checks 0 and 2 report; check 1 has no marker.
  await withFake({
    FAKE_SWAMP_HC: scriptOut("a", "@@PATCH-HC 0 rc=0\n@@PATCH-HC 2 rc=4\n"),
  }, async () => {
    const res = await fleet.evalHealth({ host: "a" }, [
      { type: "service", name: "one" },
      { type: "command", run: "two", timeoutSec: 5 },
      { type: "command", run: "three", timeoutSec: 5 },
    ], "ssh", CLI);
    assertEquals(res.results.map((r) => [r.ok, r.detail]), [
      [true, "active"],
      [false, "no result"],
      [false, "rc 4"],
    ]);
    assertEquals(res.healthy, false);
  });
});

Deno.test("evalHealth: a CT's checks run through pct exec on its node, in one call", async () => {
  await withCallLog({ FAKE_SWAMP_HC: hcOut("pve", 0, 3) }, async (calls) => {
    const res = await fleet.evalHealth(
      { host: "ct1", ct: { proxmoxNode: "pve", ctid: 200 } },
      [
        { type: "service", name: "caddy" },
        { type: "command", run: "exit 3", timeoutSec: 5 },
      ],
      "ssh",
      CLI,
    );
    assertEquals(res.results.map((r) => r.detail), ["active", "rc 3"]);
    const all = await calls();
    assertEquals(all.length, 1);
    assertStringIncludes(all[0], 'hosts:json=["pve"]');
    assertStringIncludes(all[0], "script=pct exec 200 -- bash -c");
  });
});

Deno.test("evalHealth: a transport failure of the batch is an exception (callers decide)", async () => {
  await withFake({ FAKE_SWAMP_HC: "", FAKE_SWAMP_HC_RC: "1" }, async () => {
    await assertRejects(
      () =>
        fleet.evalHealth({ host: "a" }, [{ type: "service", name: "x" }], "ssh", CLI),
      Error,
      "ssh script failed",
    );
  });
});

Deno.test("healthBatchScript: a bare exit in a check does not hide the next check's marker", async () => {
  const script = fleet.healthBatchScript([
    "exit 3",
    "echo noise; true",
    "cat >/dev/null; exit 0", // reads stdin: gets /dev/null, not the rest of the batch
    "false",
  ]);
  // Feed the batch on stdin, as the ssh model does.
  const proc = new Deno.Command("bash", {
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const w = proc.stdin.getWriter();
  await w.write(new TextEncoder().encode(script));
  await w.close();
  const out = new TextDecoder().decode((await proc.output()).stdout);
  assertEquals([...fleet.parseHealthBatch(out).entries()], [
    [0, 3],
    [1, 0],
    [2, 0],
    [3, 1],
  ]);
  // The snippets' own output goes to /dev/null.
  assertEquals(out.includes("noise"), false);
});

Deno.test("parseHealthBatch: reads only whole marker lines", () => {
  assertEquals(
    [...fleet.parseHealthBatch(
      "x @@PATCH-HC 9 rc=0\n@@PATCH-HC 1 rc=2\n@@PATCH-HC 0 rc=0  \n",
    ).entries()],
    [[1, 2], [0, 0]],
  );
});

Deno.test("evalHealth: every check must pass", async () => {
  const server = startServer(() => 200);
  try {
    await withFake({ FAKE_SWAMP_HC: hcOut("a", 1) }, async () => {
      const res = await fleet.evalHealth({ host: "a" }, [
        {
          type: "http",
          url: server.url,
          expectStatus: 200,
          timeoutSec: 5,
        },
        { type: "service", name: "db" },
      ], "ssh", CLI);
      assertEquals(res.healthy, false);
      assertEquals(res.results.map((r) => r.ok), [true, false]);
    });
  } finally {
    await server.stop();
  }
});

Deno.test("evalHealth: a long command is labelled with its first 40 characters", async () => {
  await withFake({ FAKE_SWAMP_HC: hcOut("a", 0) }, async () => {
    const run = "x".repeat(60);
    const res = await fleet.evalHealth({ host: "a" }, [
      { type: "command", run, timeoutSec: 5 },
    ], "ssh", CLI);
    assertEquals(res.results[0].label, `command: ${"x".repeat(40)}`);
  });
});

// ---------------------------------------------------------------------------
// Methods through createModelTestContext (runModel backed by the fake)
// ---------------------------------------------------------------------------

Deno.test("scan: skips machines with os=false and writes nothing", async () => {
  const t = mkCtx({ sshModel: "ssh", machines: [{ host: "a", os: false }] });
  const result = await model.methods.scan.execute({}, t.ctx);
  assertEquals(result.dataHandles, []);
  assertEquals(t.written("inventory"), []);
  assert(t.getLogsByLevel("info").length >= 2);
});

Deno.test("scan: a reachable host writes an inventory record with reachMethod ssh", async () => {
  await withFake({
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", collectorStdout()),
  }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
    const result = await model.methods.scan.execute({}, t.ctx);
    assertEquals(result.dataHandles.length, 1);
    const inv = t.one("inventory");
    assertEquals(inv.hostname, "web1");
    assertEquals(inv.updatesCount, 3);
    assertEquals(inv.reachMethod, "ssh");
    assertEquals(inv.health, null);
    assertEquals(inv.error, null);
    assertEquals(t.written("inventory")[0].name, "web1");
  });
});

Deno.test("scan: evaluates the machine's health checks into the record", async () => {
  const server = startServer(() => 200);
  try {
    await withFake({
      FAKE_SWAMP_SCRIPT_1: scriptOut("web1", collectorStdout()),
    }, async () => {
      const t = mkCtx({
        sshModel: "ssh",
        machines: [{
          host: "web1",
          health: [{ type: "http", label: "app", url: server.url }],
        }],
      });
      await model.methods.scan.execute({}, t.ctx);
      assertEquals(t.one("inventory").health, {
        healthy: true,
        checks: [{ label: "app", ok: true, detail: "status 200" }],
      });
    });
  } finally {
    await server.stop();
  }
});

Deno.test("scan: a host without inventory output gets an error record", async () => {
  await withFake({
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", "no json here\n", 1),
  }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertEquals(inv.hostname, "web1");
    assertEquals(inv.error, "no inventory (exit 1)");
    assertEquals(inv.updatesCount, null);
    assertEquals(inv.reachMethod, null);
    assertEquals(inv.needsReboot, false);
  });
});

Deno.test("scan: an ssh transport failure is recorded per host, not thrown", async () => {
  await withFake({ FAKE_SWAMP_SCRIPT_1: "not json" }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
    await model.methods.scan.execute({}, t.ctx);
    assertEquals(t.one("inventory").error, "ssh: ssh script failed: not json");
  });
});

/** One CT's section in a CT batch's output, as ctBatchScript prints it. */
function ctSection(ctid: number, stdout: string, rc = 0): string {
  return `@@PATCH-CT ${ctid} BEGIN\n${stdout}\n@@PATCH-CT ${ctid} END rc=${rc}\n`;
}

Deno.test("scan: a reach=pct CT is scanned on its node and recorded as pct", async () => {
  await withCallLog({
    FAKE_SWAMP_PCT: scriptOut(
      "pve",
      ctSection(200, collectorStdout({ hostname: "ct1" })),
    ),
  }, async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{
        host: "ct1",
        reach: "pct",
        ct: { proxmoxNode: "pve", ctid: 200 },
      }],
    });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertEquals(inv.hostname, "ct1");
    assertEquals(inv.reachMethod, "pct");
    assertEquals(t.written("inventory")[0].name, "ct1");
    // reach=pct: no ssh collector call, one node call.
    const all = await calls();
    assertEquals(all.length, 1);
    assertStringIncludes(all[0], 'hosts:json=["pve"]');
  });
});

Deno.test("scan: a CT falls back to pct when ssh gives no inventory, and reports both errors when pct fails too", async () => {
  // ssh answers with no marker; the node answers with no section for the CT.
  await withFake({
    FAKE_SWAMP_SCRIPT_1: scriptOut("ct1", "nothing\n", 0),
    FAKE_SWAMP_PCT: scriptOut("pve", "nothing\n", 0),
  }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "ct1", ct: { proxmoxNode: "pve", ctid: 200 } }],
    });
    await model.methods.scan.execute({}, t.ctx);
    assertEquals(
      t.one("inventory").error,
      "no inventory (exit 0); pct: no inventory",
    );
  });
  // A section without the marker line reports the CT's exit code.
  await withFake({
    FAKE_SWAMP_SCRIPT_1: scriptOut("ct1", "nothing\n", 0),
    FAKE_SWAMP_PCT: scriptOut("pve", ctSection(200, "boom", 7)),
  }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "ct1", ct: { proxmoxNode: "pve", ctid: 200 } }],
    });
    await model.methods.scan.execute({}, t.ctx);
    assertEquals(
      t.one("inventory").error,
      "no inventory (exit 0); pct: no inventory (exit 7)",
    );
  });
});

Deno.test("scan: the scanned hosts keep their own record each", async () => {
  await withFake({
    FAKE_SWAMP_SCRIPT_1: scriptOut("a", collectorStdout({ hostname: "a" })),
  }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "a" }, { host: "b", os: false }, { host: "c" }],
    });
    const result = await model.methods.scan.execute({}, t.ctx);
    assertEquals(result.dataHandles.length, 2);
    assertEquals(t.written("inventory").map((r) => r.name), ["a", "c"]);
    // c has no result in the one batch call: it gets an error record.
    assertEquals(t.written("inventory")[1].data.error, "no inventory");
  });
});

Deno.test("scan: ONE ssh script call collects every ssh host", async () => {
  await withCallLog({
    FAKE_SWAMP_SCRIPT_1: JSON.stringify({
      dataArtifacts: [
        { attributes: { host: "a", stdout: collectorStdout({ hostname: "a" }), exitCode: 0 } },
        { attributes: { host: "b", stdout: "no marker", exitCode: 1 } },
      ],
    }),
  }, async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "a" }, { host: "b" }, { host: "c" }, { host: "d", os: false }],
    });
    await model.methods.scan.execute({}, t.ctx);
    const all = await calls();
    assertEquals(all.length, 1);
    assertEquals(t.calls[0].arguments?.hosts, ["a", "b", "c"]);
    assertEquals(t.calls[0].arguments?.timeoutSec, 240);
    const inv = Object.fromEntries(
      t.written("inventory").map((r) => [r.name, r.data]),
    );
    assertEquals(inv.a.reachMethod, "ssh");
    assertEquals(inv.a.error, null);
    assertEquals(inv.b.error, "no inventory (exit 1)");
    assertEquals(inv.c.error, "no inventory");
  });
});

Deno.test("scan: a partial ssh failure keeps the hosts that ran (recovered from runResult records)", async () => {
  await withFake({
    FAKE_SWAMP_SCRIPT_1: JSON.stringify({
      dataArtifacts: [
        { attributes: { host: "a", stdout: collectorStdout({ hostname: "a" }), exitCode: 0 } },
        { attributes: { host: "b", stdout: "", exitCode: 255 } },
      ],
    }),
    FAKE_SWAMP_SCRIPT_RC: "1",
  }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "a" }, { host: "b" }, { host: "c" }],
    }, {
      // A stale record of c from an earlier run must not be used.
      otherData: [{
        model: "ssh",
        spec: "runResult",
        name: "run-script-c",
        attributes: {
          host: "c",
          stdout: collectorStdout({ hostname: "c" }),
          exitCode: 0,
          startedAt: "2020-01-01T00:00:00.000Z",
        },
      }],
    });
    await model.methods.scan.execute({}, t.ctx);
    const inv = Object.fromEntries(
      t.written("inventory").map((r) => [r.name, r.data]),
    );
    assertEquals(inv.a.error, null);
    assertEquals(inv.a.updatesCount, 3);
    assertEquals(inv.b.error, "no inventory (exit 255)");
    assertMatch(String(inv.c.error), /^ssh: /);
    assertEquals(inv.c.updatesCount, null);
  });
});

/** Two nodes' CT batch outputs in one fake answer; each node call picks its own host. */
function twoNodePct(): string {
  return JSON.stringify({
    dataArtifacts: [
      {
        attributes: {
          host: "pve",
          // ctid 201 has no section: only ct2 gets an error record.
          stdout: ctSection(200, collectorStdout({ hostname: "ct1" })),
          exitCode: 0,
        },
      },
      {
        attributes: {
          host: "pve2",
          stdout: ctSection(300, collectorStdout({ hostname: "ct3" })),
          exitCode: 0,
        },
      },
    ],
  });
}

const PCT_FLEET = {
  sshModel: "ssh",
  machines: [
    { host: "ct1", reach: "pct", ct: { proxmoxNode: "pve", ctid: 200 } },
    { host: "ct2", reach: "pct", ct: { proxmoxNode: "pve", ctid: 201 } },
    { host: "ct3", reach: "pct", ct: { proxmoxNode: "pve2", ctid: 300 } },
  ],
};

Deno.test("scan: the pct path is grouped per node: one call per node, sections parsed per CT", async () => {
  await withFake({ FAKE_SWAMP_PCT: twoNodePct() }, async () => {
    const t = mkCtx(PCT_FLEET);
    await model.methods.scan.execute({}, t.ctx);
    assertEquals(t.calls.length, 2);
    assertEquals(t.calls.map((c) => c.arguments?.hosts), [["pve"], ["pve2"]]);
    // Timeout = 240 per CT on the node.
    assertEquals(t.calls.map((c) => c.arguments?.timeoutSec), [480, 240]);
    const pveScript = String(t.calls[0].arguments?.script);
    assertStringIncludes(pveScript, "@@PATCH-CT 200 BEGIN");
    assertStringIncludes(pveScript, "@@PATCH-CT 201 BEGIN");
    // The collector is sent once per node, not once per CT.
    assertEquals(pveScript.split(fleet.utf8b64(fleet.COLLECTOR_SCRIPT)).length, 2);
    const inv = Object.fromEntries(
      t.written("inventory").map((r) => [r.name, r.data]),
    );
    assertEquals(inv.ct1.hostname, "ct1");
    assertEquals(inv.ct1.reachMethod, "pct");
    assertEquals(inv.ct2.error, "pct: no inventory");
    assertEquals(inv.ct3.hostname, "ct3");
    assertEquals(inv.ct3.reachMethod, "pct");
  });
});

Deno.test("scan: a failing node does not affect the other node or the ssh hosts", async () => {
  await withFake({
    FAKE_SWAMP_PCT: twoNodePct(),
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", collectorStdout({ hostname: "web1" })),
  }, async () => {
    const t = mkCtx({
      ...PCT_FLEET,
      machines: [...PCT_FLEET.machines, { host: "web1" }],
    });
    const base = (t.ctx as { runModel: (o: unknown) => Promise<unknown> }).runModel;
    // The node "pve" is down: its call fails with no result.
    const runModel = (o: { arguments?: { hosts?: string[] } }) =>
      o.arguments?.hosts?.[0] === "pve"
        ? Promise.resolve({
          ok: false,
          error: { message: "script failed on 1/1 host(s): pve (exit 255)" },
        })
        : base(o);
    await model.methods.scan.execute({}, { ...(t.ctx as object), runModel } as never);
    const inv = Object.fromEntries(
      t.written("inventory").map((r) => [r.name, r.data]),
    );
    assertStringIncludes(String(inv.ct1.error), "pct: ssh script failed: script failed on 1/1 host(s): pve");
    assertStringIncludes(String(inv.ct2.error), "pct: ssh script failed");
    assertEquals(inv.ct3.reachMethod, "pct");
    assertEquals(inv.web1.reachMethod, "ssh");
  });
});

Deno.test("scan: call budget for 10 machines (3 CTs on 2 nodes, 4 app sources, shell health everywhere) is at most 1 + 2 + 10 + 4", async () => {
  const health = [{ type: "service", name: "sshd" }];
  const machines = [
    ...["h1", "h2", "h3", "h4", "h5", "h6", "h7"].map((host, i) => ({
      host,
      health,
      ...(i < 3 ? { source: { type: "community-script", model: `app-${host}` } } : {}),
    })),
    { host: "ct1", reach: "pct", ct: { proxmoxNode: "pve", ctid: 200 }, health },
    { host: "ct2", reach: "pct", ct: { proxmoxNode: "pve", ctid: 201 }, health },
    {
      host: "ct3",
      reach: "pct",
      ct: { proxmoxNode: "pve2", ctid: 300 },
      source: { type: "community-script", model: "app-ct3" },
      health,
    },
  ];
  await withCallLog({
    FAKE_SWAMP_SCRIPT_1: scriptOut("h1", collectorStdout({ hostname: "h1" })),
    FAKE_SWAMP_PCT: twoNodePct(),
    FAKE_SWAMP_HC: hcOut("h1", 0),
  }, async (calls) => {
    const t = mkCtx({ sshModel: "ssh", machines });
    await model.methods.scan.execute({}, t.ctx);
    const all = await calls();
    assert(all.length <= 1 + 2 + 10 + 4, `${all.length} calls`);
    assertEquals(all.length, 17);
    const scripts = t.calls.filter((c) => c.method === "script");
    const pct = scripts.filter((c) => String(c.arguments?.script).includes("@@PATCH-CT"));
    const collector = scripts.filter((c) => c.arguments?.script === fleet.COLLECTOR_SCRIPT);
    assertEquals(collector.length, 1);
    assertEquals(collector[0].arguments?.hosts, ["h1", "h2", "h3", "h4", "h5", "h6", "h7"]);
    assertEquals(pct.length, 2);
    assertEquals(scripts.length - collector.length - pct.length, 10); // one health batch each
    assertEquals(t.calls.filter((c) => c.method === "checkUpdate").length, 4);
    assertEquals(t.written("inventory").length, 10);
    assertStringIncludes(JSON.stringify(t.getLogsByLevel("info")), "17");
  });
});

Deno.test("scan: when swamp's model-call cap is reached, ONE warn names the cap and the machine count", async () => {
  const health = [{ type: "service", name: "sshd" }];
  await withFake({
    FAKE_SWAMP_SCRIPT_1: scriptOut("a", collectorStdout({ hostname: "a" })),
    FAKE_SWAMP_HC: hcOut("a", 0),
  }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [
        { host: "a", health },
        { host: "b", health },
        { host: "c", health },
      ],
    }, { maxRunModelCalls: 2 });
    await model.methods.scan.execute({}, t.ctx);
    const warns = t.getLogsByLevel("warning");
    assertEquals(warns.length, 1);
    const w = JSON.stringify(warns[0]);
    assertStringIncludes(w, "cap of {cap} model calls");
    assertStringIncludes(w, '"cap":100');
    assertStringIncludes(w, '"count":3');
    // Each machine still gets its record; the capped health checks are left unset.
    assertEquals(t.written("inventory").length, 3);
    assertEquals(t.written("inventory")[2].data.health, null);
  });
});

Deno.test("parseCtSections: splits per CT; a cut-short section has rc null; a missing CT is absent", () => {
  const out = "noise\n" + ctSection(200, "line-a\nline-b", 0) +
    "@@PATCH-CT 201 BEGIN\npartial\n" + // no END: cut short
    "@@PATCH-CT 202 BEGIN\nx\n@@PATCH-CT 202 END rc=3\n";
  const s = fleet.parseCtSections(out);
  assertEquals(s.get(200), { out: "line-a\nline-b", rc: 0 });
  assertEquals(s.get(201), { out: "partial", rc: null });
  assertEquals(s.get(202), { out: "x", rc: 3 });
  assertEquals(s.has(203), false);
});

Deno.test("ctBatchScript: one collector copy, each CT delimited, pct exec reads /dev/null", () => {
  const script = fleet.ctBatchScript([200, 201], "QUJD");
  assertEquals(script.split("QUJD").length, 2);
  assertStringIncludes(script, 'echo "@@PATCH-CT 200 BEGIN"');
  assertStringIncludes(
    script,
    `pct exec 201 -- bash -c "echo '\${PATCH_COLLECTOR}' | base64 -d | bash" </dev/null`,
  );
  assertStringIncludes(script, "printf '\\n@@PATCH-CT %s END rc=%s\\n' 201 \"$?\"");
});

Deno.test("import: seeds a machines block from the ssh host list and Proxmox guests", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: JSON.stringify({
      globalArguments: {
        hosts: [{ name: "web1", tags: ["docker"] }, { name: "vm1" }],
      },
    }),
    // listGuests writes the `guests` resource: its attributes hold the list.
    FAKE_SWAMP_GUESTS: JSON.stringify({
      dataArtifacts: [{
        attributes: {
          guests: [
            { type: "qemu", vmid: 100, name: "vm1", node: "pve", ip: "192.0.2.5" },
            { type: "lxc", vmid: 200, name: "ct1", node: "pve", ip: null },
            { type: "lxc", vmid: 201, name: "ct2", node: "pve", ip: "192.0.2.9" },
            { type: "other", vmid: 1, name: "skip", node: "pve", ip: null },
          ],
        },
      }],
    }),
  }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      proxmoxNodes: ["pve"],
      machines: [],
    });
    await model.methods.import.execute({}, t.ctx);
    const seed = t.one("seed");
    const yaml = String(seed.yaml);
    assertEquals(seed.source, "ssh + proxmox(pve)");
    assertEquals(seed.machineCount, 4);
    assert(yaml.startsWith("machines:\n"));
    assertStringIncludes(yaml, "  - host: web1");
    assertStringIncludes(yaml, "    docker: {}");
    // vm1 is an ssh host that is also a qemu guest: decorated with vm.
    assertStringIncludes(
      yaml,
      "    vm:   # Proxmox VM — snapshot before OS update\n      proxmoxNode: pve\n      vmid: 100",
    );
    // ct1 is discovered only via Proxmox: a CT with pct reach.
    assertStringIncludes(yaml, "  - host: ct1   # CT 200, no ip — agent off?");
    assertStringIncludes(yaml, "    reach: pct");
    assertStringIncludes(yaml, "      ctid: 200");
    // Only guests with an ip get an ssh host suggestion.
    assertStringIncludes(yaml, "#     - name: ct2\n#       address: 192.0.2.9");
    assertEquals(yaml.includes("name: ct1\n#       address"), false);
    assertEquals(yaml.includes("skip"), false);
    assertEquals(typeof seed.checkedAt, "string");
  });
});

Deno.test("import: records a read failure in the YAML instead of throwing", async () => {
  await withFake({ FAKE_SWAMP_MODEL_GET: "not json" }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [] });
    await model.methods.import.execute({}, t.ctx);
    const seed = t.one("seed");
    assertEquals(seed.source, "ssh");
    assertEquals(seed.machineCount, 0);
    assertStringIncludes(String(seed.yaml), "# sshModel ssh read failed");
  });
});

Deno.test("import: a failed listGuests is noted in the YAML, and the ssh hosts are still seeded", async () => {
  await withCallLog({
    FAKE_SWAMP_MODEL_GET: JSON.stringify({ globalArguments: { hosts: [{ name: "web1" }] } }),
    FAKE_SWAMP_GUESTS: "",
    FAKE_SWAMP_GUESTS_RC: "1",
  }, async (calls) => {
    const t = mkCtx({ sshModel: "ssh", proxmoxNodes: ["pve"], machines: [] });
    await model.methods.import.execute({}, t.ctx);
    const seed = t.one("seed");
    assertEquals(seed.machineCount, 1);
    // One model call (listGuests); the ssh host list is read from the definition.
    assertEquals((await calls()).map((c) => c.split(" ").slice(0, 2).join(" ")), ["pve listGuests"]);
    assertEquals(t.calls[0].arguments, undefined);
    assertStringIncludes(String(seed.yaml), "  - host: web1");
    assertEquals(String(seed.yaml).includes("Proxmox pve"), false); // no guests: no discovery block
  });
});

Deno.test("safeUpdate: rejects a machine without a docker decoration", async () => {
  const t = mkCtx({ sshModel: "ssh", machines: [{ host: "a" }] });
  await assertRejects(
    () =>
      model.methods.safeUpdate.execute(
        model.methods.safeUpdate.arguments.parse({ host: "a" }),
        t.ctx,
      ),
    Error,
    'machine "a" has no docker decoration',
  );
  await assertRejects(
    () =>
      model.methods.safeUpdate.execute(
        model.methods.safeUpdate.arguments.parse({ host: "missing" }),
        t.ctx,
      ),
    Error,
    'machine "missing" has no docker decoration',
  );
});

Deno.test("safeUpdate: no running containers is a skipped run", async () => {
  await withFake({ FAKE_SWAMP_PS: execOut("") }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "dock1", docker: { service: "web" } }],
    });
    await model.methods.safeUpdate.execute(
      model.methods.safeUpdate.arguments.parse({ host: "dock1" }),
      t.ctx,
    );
    const update = t.one("update");
    assertEquals(update.outcome, "skipped");
    assertEquals(update.service, "web");
    assertEquals(update.containers, []);
    const run = t.one("run");
    assertEquals(run.action, "docker");
    assertEquals(run.outcome, "skipped");
    assertEquals(run.images, null);
    assertEquals(run.imagesChanged, null);
  });
});

function dockerMachine(url: string) {
  return {
    host: "dock1",
    docker: {
      composePath: "/srv/app",
      service: "web",
      healthUrl: url,
    },
  };
}

Deno.test("safeUpdate: a changed image is diffed, recorded and retained as a rollback point", async () => {
  const server = startServer(() => 200);
  try {
    await withFake({
      FAKE_SWAMP_PS: execOut("abc123\n"),
      FAKE_SWAMP_INSPECT_1: execOut("nginx:1|sha256:aaaaaaaaaaaaaaaaaaaaaaaa\n"),
      FAKE_SWAMP_INSPECT_2: execOut("nginx:1|sha256:bbbbbbbbbbbbbbbbbbbbbbbb\n"),
      FAKE_SWAMP_EXEC: execOut(""),
    }, async () => {
      const t = mkCtx({
        sshModel: "ssh",
        machines: [dockerMachine(server.url)],
      });
      await model.methods.safeUpdate.execute(
        model.methods.safeUpdate.arguments.parse({
          host: "dock1",
          retentionHours: 24,
        }),
        t.ctx,
      );
      const update = t.one("update");
      assertEquals(update.outcome, "updated");
      assertEquals(update.imageChanged, true);
      assertEquals(update.healthyAfter, true);
      assertEquals(update.rolledBack, false);
      assertEquals(update.containers, [{
        ref: "nginx:1",
        beforeImage: "sha256:aaaaaaaaaaaaaaaaaaaaaaaa",
        afterImage: "sha256:bbbbbbbbbbbbbbbbbbbbbbbb",
      }]);
      const run = t.one("run");
      assertEquals(run.images, [{
        ref: "nginx:1",
        from: "sha256:aaaaaaaaaaaaaaaaaaaaaaaa",
        to: "sha256:bbbbbbbbbbbbbbbbbbbbbbbb",
      }]);
      assertEquals(run.imagesChanged, 1);
      assertEquals(t.written("run")[0].name.startsWith("run-docker-dock1-"), true);
      // The replaced image is retained, then retired by pruneImages later.
      const img = t.one("image");
      assertEquals(img.host, "dock1");
      assertEquals(img.ref, "nginx:1");
      assertEquals(img.imageId, "sha256:aaaaaaaaaaaaaaaaaaaaaaaa");
      assertEquals(img.replacedBy, "sha256:bbbbbbbbbbbbbbbbbbbbbbbb");
      assertEquals(img.status, "active");
      assertEquals(img.prunedAt, null);
      assertEquals(
        new Date(String(img.retainUntil)).getTime() -
          new Date(String(img.createdAt)).getTime(),
        24 * 3600 * 1000,
      );
    });
  } finally {
    await server.stop();
  }
});

Deno.test("safeUpdate: an unchanged image is no-change and retains nothing", async () => {
  const server = startServer(() => 200);
  try {
    await withFake({
      FAKE_SWAMP_PS: execOut("abc123\n"),
      FAKE_SWAMP_INSPECT_1: execOut("nginx:1|sha256:same\n"),
      FAKE_SWAMP_INSPECT_2: execOut("nginx:1|sha256:same\n"),
      FAKE_SWAMP_EXEC: execOut(""),
    }, async () => {
      const t = mkCtx({
        sshModel: "ssh",
        machines: [dockerMachine(server.url)],
      });
      await model.methods.safeUpdate.execute(
        model.methods.safeUpdate.arguments.parse({ host: "dock1" }),
        t.ctx,
      );
      assertEquals(t.one("update").outcome, "no-change");
      assertEquals(t.one("run").images, []);
      assertEquals(t.one("run").imagesChanged, 0);
      assertEquals(t.written("image"), []);
    });
  } finally {
    await server.stop();
  }
});

Deno.test("safeUpdate: an unhealthy service is rolled back; without rollback it stays unhealthy", async () => {
  const server = startServer(() => 503);
  try {
    const env = {
      FAKE_SWAMP_PS: execOut("abc123\n"),
      FAKE_SWAMP_INSPECT_1: execOut("nginx:1|sha256:old\n"),
      FAKE_SWAMP_INSPECT_2: execOut("nginx:1|sha256:new\n"),
      FAKE_SWAMP_EXEC: execOut(""),
    };
    await withFake(env, async () => {
      const t = mkCtx({
        sshModel: "ssh",
        machines: [dockerMachine(server.url)],
      });
      await model.methods.safeUpdate.execute(
        model.methods.safeUpdate.arguments.parse({
          host: "dock1",
          healthTimeoutSec: 0,
        }),
        t.ctx,
      );
      const update = t.one("update");
      assertEquals(update.outcome, "rolled-back");
      assertEquals(update.rolledBack, true);
      assertEquals(update.healthyAfter, false);
      assertEquals(t.one("run").rolledBack, true);
      assertEquals(t.written("image"), []);
    });
    await withFake(env, async () => {
      const t = mkCtx({
        sshModel: "ssh",
        machines: [dockerMachine(server.url)],
      });
      await model.methods.safeUpdate.execute(
        model.methods.safeUpdate.arguments.parse({
          host: "dock1",
          healthTimeoutSec: 0,
          rollbackOnFailure: false,
        }),
        t.ctx,
      );
      assertEquals(t.one("update").outcome, "unhealthy");
      assertEquals(t.one("update").rolledBack, false);
    });
  } finally {
    await server.stop();
  }
});

// --- safeOsUpdate ---------------------------------------------------------

const PKGS_BEFORE = "openssl\t3.0.1\ncurl\t7.0\nold-lib\t1.0\n";
const PKGS_AFTER = "openssl\t3.0.2\ncurl\t7.0\nnew-lib\t2.0\n";

function osUpdateEnv(): Env {
  return {
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", collectorStdout()),
    FAKE_SWAMP_SCRIPT_2: scriptOut(
      "web1",
      collectorStdout({ updatesCount: 0, needsReboot: true }),
    ),
    FAKE_SWAMP_PKGS_1: execOut(PKGS_BEFORE),
    FAKE_SWAMP_PKGS_2: execOut(PKGS_AFTER),
    FAKE_SWAMP_EXEC: execOut(""),
  };
}

Deno.test("safeOsUpdate: rejects an unknown host", async () => {
  const t = mkCtx({ sshModel: "ssh", machines: [{ host: "a" }] });
  await assertRejects(
    () =>
      model.methods.safeOsUpdate.execute(
        model.methods.safeOsUpdate.arguments.parse({ host: "zzz" }),
        t.ctx,
      ),
    Error,
    'no machine "zzz" in the fleet',
  );
});

Deno.test("safeOsUpdate: a bare-metal host is upgraded and the package diff is sorted and complete", async () => {
  await withFake(osUpdateEnv(), async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
    await model.methods.safeOsUpdate.execute(
      model.methods.safeOsUpdate.arguments.parse({ host: "web1" }),
      t.ctx,
    );
    const os = t.one("osUpdate");
    assertEquals(os.kind, "bare-metal");
    assertEquals(os.outcome, "updated");
    assertEquals(os.snapshot, null);
    assertEquals(os.snapshotKept, false);
    assertEquals(os.beforeUpdates, 3);
    assertEquals(os.afterUpdates, 0);
    assertEquals(os.healthyAfter, true);
    assertEquals(os.rolledBack, false);
    assertEquals(os.needsReboot, true);
    const run = t.one("run");
    assertEquals(run.action, "osUpdate");
    assertEquals(run.packages, [
      { name: "new-lib", from: null, to: "2.0" },
      { name: "old-lib", from: "1.0", to: null },
      { name: "openssl", from: "3.0.1", to: "3.0.2" },
    ]);
    assertEquals(run.packagesChanged, 3);
    assertEquals(t.written("snapshot"), []);
    // The inventory is refreshed from the post-update scan.
    const inv = t.one("inventory");
    assertEquals(inv.updatesCount, 0);
    assertEquals(inv.needsReboot, true);
    assertEquals(inv.reachMethod, "ssh");
  });
});

Deno.test("safeOsUpdate: identical before/after scans and manifests mean no-change and no package diff", async () => {
  await withFake({
    ...osUpdateEnv(),
    FAKE_SWAMP_SCRIPT_2: scriptOut("web1", collectorStdout()),
    FAKE_SWAMP_PKGS_2: execOut(PKGS_BEFORE),
  }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
    await model.methods.safeOsUpdate.execute(
      model.methods.safeOsUpdate.arguments.parse({ host: "web1" }),
      t.ctx,
    );
    assertEquals(t.one("osUpdate").outcome, "no-change");
    assertEquals(t.one("run").packages, []);
    assertEquals(t.one("run").packagesChanged, 0);
  });
});

Deno.test("safeOsUpdate: a VM is snapshotted first and the snapshot record tracks its retention", async () => {
  await withFake(osUpdateEnv(), async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "web1", vm: { proxmoxNode: "pve", vmid: 100 } }],
    });
    await model.methods.safeOsUpdate.execute(
      model.methods.safeOsUpdate.arguments.parse({
        host: "web1",
        retentionHours: 48,
      }),
      t.ctx,
    );
    const os = t.one("osUpdate");
    assertEquals(os.kind, "vm");
    assertEquals(os.outcome, "updated");
    assertMatch(String(os.snapshot), /^preupdate-\d{4}-\d{2}-\d{2}T/);
    assertEquals(os.snapshotKept, true);
    const snap = t.one("snapshot");
    assertEquals(snap.host, "web1");
    assertEquals(snap.kind, "vm");
    assertEquals(snap.vmid, 100);
    assertEquals(snap.proxmoxNode, "pve");
    assertEquals(snap.name, os.snapshot);
    assertEquals(snap.status, "active");
    assertEquals(snap.healthConfirmed, true);
    assertEquals(snap.rebootRequired, true);
    assertEquals(snap.rebootConfirmed, false);
    assertEquals(
      new Date(String(snap.retainUntil)).getTime() -
        new Date(String(snap.createdAt)).getTime(),
      48 * 3600 * 1000,
    );
    assertStringIncludes(t.written("snapshot")[0].name, "snap-web1-");
  });
});

Deno.test("safeOsUpdate: a failed VM snapshot aborts before any upgrade", async () => {
  await withFake({ ...osUpdateEnv(), FAKE_SWAMP_METHOD_RC: "1" }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "web1", vm: { proxmoxNode: "pve", vmid: 100 } }],
    });
    await assertRejects(
      () =>
        model.methods.safeOsUpdate.execute(
          model.methods.safeOsUpdate.arguments.parse({ host: "web1" }),
          t.ctx,
        ),
      Error,
      "snapshot failed on pve for vmid 100",
    );
    assertEquals(t.written("osUpdate"), []);
    assertEquals(t.written("run"), []);
  });
});

Deno.test("safeOsUpdate: an unreachable host is an error, not a record", async () => {
  await withFake({
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", "garbage\n", 1),
  }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
    await assertRejects(
      () =>
        model.methods.safeOsUpdate.execute(
          model.methods.safeOsUpdate.arguments.parse({ host: "web1" }),
          t.ctx,
        ),
      Error,
      'host "web1" is not ssh-reachable',
    );
  });
});

Deno.test("safeOsUpdate: the method itself does not gate on baseline health (the baseline-healthy check does)", async () => {
  // Unhealthy on every probe. The method must NOT refuse up front: the before-
  // update gate is the pre-flight check, so the upgrade runs and only the
  // after-update verdict is judged (bare metal: no snapshot → failed).
  const server = startServer(() => 503);
  try {
    const machines = [{
      host: "web1",
      health: [{ type: "http", url: server.url }],
    }];
    await withFake(osUpdateEnv(), async () => {
      const t = mkCtx({ sshModel: "ssh", machines });
      await model.methods.safeOsUpdate.execute(
        model.methods.safeOsUpdate.arguments.parse({
          host: "web1",
          healthGraceSec: 0,
        }),
        t.ctx,
      );
      const os = t.one("osUpdate");
      assertEquals(os.outcome, "failed");
      assertEquals(os.rolledBack, false);
      assertEquals(os.healthyAfter, false);
      assertEquals(String(os.logs).includes("baseline"), false);
      assertEquals(t.written("run").length, 1);
    });
  } finally {
    await server.stop();
  }
});

Deno.test("safeOsUpdate: a VM that turns unhealthy after the upgrade is rolled back", async () => {
  // Unhealthy on the post-update probe (the method makes no baseline probe).
  const server = startServer(() => 503);
  try {
    await withFake(osUpdateEnv(), async () => {
      const t = mkCtx({
        sshModel: "ssh",
        machines: [{
          host: "web1",
          vm: { proxmoxNode: "pve", vmid: 100 },
          health: [{ type: "http", url: server.url }],
        }],
      });
      await model.methods.safeOsUpdate.execute(
        model.methods.safeOsUpdate.arguments.parse({
          host: "web1",
          healthGraceSec: 0,
        }),
        t.ctx,
      );
      const os = t.one("osUpdate");
      assertEquals(os.outcome, "rolled-back");
      assertEquals(os.rolledBack, true);
      assertEquals(os.healthyAfter, false);
      assertEquals(t.one("run").rolledBack, true);
    });
    // With rollback disabled the VM is left as-is and reported failed.
    const server2 = startServer(() => 503);
    try {
      await withFake(osUpdateEnv(), async () => {
        const t = mkCtx({
          sshModel: "ssh",
          machines: [{
            host: "web1",
            vm: { proxmoxNode: "pve", vmid: 100 },
            health: [{ type: "http", url: server2.url }],
          }],
        });
        await model.methods.safeOsUpdate.execute(
          model.methods.safeOsUpdate.arguments.parse({
            host: "web1",
            rollbackOnFailure: false,
            healthGraceSec: 0,
          }),
          t.ctx,
        );
        assertEquals(t.one("osUpdate").outcome, "failed");
        assertEquals(t.one("osUpdate").rolledBack, false);
      });
    } finally {
      await server2.stop();
    }
  } finally {
    await server.stop();
  }
});

// --- safeOsUpdate: one snapshot for a community-script CT -------------------

/** Run `fn` with a call log: the fake appends one line per `model method run` call. */
async function withCallLog<T>(
  env: Env,
  fn: (calls: () => Promise<string[]>) => Promise<T>,
): Promise<T> {
  const file = `${Deno.env.get("TMPDIR") ?? "/tmp"}/fake-swamp-calls-${crypto.randomUUID()}`;
  const calls = async () => {
    try {
      return (await Deno.readTextFile(file)).split("\n").filter(Boolean);
    } catch {
      return []; // the fake never wrote: no calls
    }
  };
  try {
    return await withFake({ ...env, FAKE_SWAMP_CALL_LOG: file }, () => fn(calls));
  } finally {
    await new Deno.Command("rm", { args: ["-f", file] }).output();
  }
}

/** A community-script CT with an app updater, as safeOsUpdate sees it. */
function ctAppFleet(healthUrl: string) {
  return {
    sshModel: "ssh",
    machines: [{
      host: "ct1",
      ct: { proxmoxNode: "pve", ctid: 200 },
      source: { type: "community-script", model: "app1" },
      health: [{ type: "http", label: "app", url: healthUrl }],
    }],
  };
}

function ctAppEnv(extra: Env = {}): Env {
  const inv = scriptOut("pve", collectorStdout());
  return {
    FAKE_SWAMP_SCRIPT_1: inv,
    FAKE_SWAMP_SCRIPT_2: inv,
    FAKE_SWAMP_EXEC: execOut(""),
    ...extra,
  };
}

const appCalls = (all: string[]) => all.filter((c) => c.startsWith("app1 safeUpdate "));

Deno.test("safeOsUpdate: a community-script CT takes ONE snapshot and passes snapshot:false to the source", async () => {
  const server = startServer(() => 200);
  try {
    await withCallLog(ctAppEnv(), async (calls) => {
      const t = mkCtx(ctAppFleet(server.url));
      await model.methods.safeOsUpdate.execute(
        model.methods.safeOsUpdate.arguments.parse({ host: "ct1" }),
        t.ctx,
      );
      const all = await calls();
      // One source call, with the argument, and no retry.
      const app = appCalls(all);
      assertEquals(app.length, 1);
      assertStringIncludes(app[0], "--input snapshot:json=false");
      // The model's own snapshot is the only one it asks for.
      const snaps = all.filter((c) => c.includes("pct snapshot 200 preupdate-"));
      assertEquals(snaps.length, 1);
      const os = t.one("osUpdate");
      assertEquals(os.kind, "ct");
      assertMatch(String(os.snapshot), /^preupdate-/);
      assertEquals(os.healthyAfter, true);
      assertEquals(os.rolledBack, false);
      assertStringIncludes(String(os.logs), "app app1: ok");
      assertEquals(t.getLogsByLevel("warning").length, 0);
    });
  } finally {
    await server.stop();
  }
});

Deno.test("safeOsUpdate: an older source that rejects snapshot:false is retried ONCE with no arguments and a warn is logged", async () => {
  const server = startServer(() => 200);
  try {
    await withCallLog(
      ctAppEnv({ FAKE_SWAMP_APP_REJECT_SNAPSHOT: "1" }),
      async (calls) => {
        const t = mkCtx(ctAppFleet(server.url));
        await model.methods.safeOsUpdate.execute(
          model.methods.safeOsUpdate.arguments.parse({ host: "ct1" }),
          t.ctx,
        );
        const app = appCalls(await calls());
        assertEquals(app.length, 2);
        assertStringIncludes(app[0], "snapshot:json=false");
        assertEquals(app[1].includes("snapshot"), false);
        assertEquals(app[1].includes("--input"), false);
        const warns = JSON.stringify(t.getLogsByLevel("warning"));
        assertStringIncludes(warns, "does not support snapshot:false");
        assertStringIncludes(warns, "2026.10.01.1");
        // The retry worked, so the app step is ok and the run is not rolled back.
        assertStringIncludes(String(t.one("osUpdate").logs), "app app1: ok");
        assertEquals(t.one("osUpdate").rolledBack, false);
      },
    );
  } finally {
    await server.stop();
  }
});

Deno.test("safeOsUpdate: a source failure that is not about the argument is NOT retried", async () => {
  const server = startServer(() => 200);
  try {
    await withCallLog(
      ctAppEnv({ FAKE_SWAMP_APP_RC: "1", FAKE_SWAMP_APP_ERR: "update script exploded" }),
      async (calls) => {
        const t = mkCtx(ctAppFleet(server.url));
        await model.methods.safeOsUpdate.execute(
          model.methods.safeOsUpdate.arguments.parse({ host: "ct1" }),
          t.ctx,
        );
        assertEquals(appCalls(await calls()).length, 1);
        assertStringIncludes(String(t.one("osUpdate").logs), "app app1: failed");
        assertEquals(
          JSON.stringify(t.getLogsByLevel("warning")).includes(
            "does not support snapshot:false",
          ),
          false,
        );
      },
    );
  } finally {
    await server.stop();
  }
});

Deno.test("isUnknownArgumentError: only an 'unknown input' error that names the argument counts", () => {
  const fail = (error: string) => ({ ok: false, artifacts: [], error });
  assert(
    fleet.isUnknownArgumentError(
      fail(
        '{"error": "Unknown method input(s): snapshot. Valid inputs are: keepSnapshot"}',
      ),
      "snapshot",
    ),
  );
  // The valid-inputs list must not count as a rejected name.
  assertEquals(
    fleet.isUnknownArgumentError(
      fail("Unknown method input(s): other. Valid inputs are: snapshot"),
      "snapshot",
    ),
    false,
  );
  assertEquals(
    fleet.isUnknownArgumentError(fail("snapshot failed: disk full"), "snapshot"),
    false,
  );
  assertEquals(
    fleet.isUnknownArgumentError(
      { ok: true, artifacts: [], error: "Unknown input snapshot" },
      "snapshot",
    ),
    false,
  );
});

Deno.test("isUnknownArgumentError: recognises runModel's 'Unknown argument(s)' message", () => {
  const fail = (error: string) => ({ ok: false, artifacts: [], error });
  assert(
    fleet.isUnknownArgumentError(
      fail("Unknown argument(s): snapshot. Valid arguments are: keepSnapshot, node"),
      "snapshot",
    ),
  );
  // Only the part before "Valid arguments" lists the rejected names.
  assertEquals(
    fleet.isUnknownArgumentError(
      fail("Unknown argument(s): other. Valid arguments are: snapshot"),
      "snapshot",
    ),
    false,
  );
});

/** A SwampApi stub: `run` answers from `answers` in order and records each call. */
function stubSwamp(
  answers: Array<{ ok: boolean; artifacts?: Array<Record<string, unknown>>; error?: string }>,
  extra: Partial<Pick<SwampApi, "readData" | "globalArguments">> = {},
) {
  const calls: Array<{ model: string; method: string; args?: Record<string, unknown> }> = [];
  const api: SwampApi = {
    run: (model, method, args) => {
      calls.push({ model, method, args });
      const a = answers[Math.min(calls.length - 1, answers.length - 1)];
      return Promise.resolve({
        ok: a.ok,
        artifacts: a.artifacts ?? [],
        error: a.error ?? "",
      });
    },
    globalArguments: () => Promise.resolve(null),
    ...extra,
  };
  return { api, calls };
}

Deno.test("runSourceSafeUpdate: runModel's 'Unknown argument(s)' answer is retried ONCE with no arguments", async () => {
  const s = stubSwamp([
    { ok: false, error: "Unknown argument(s): snapshot. Valid arguments are: keepSnapshot" },
    { ok: true },
  ]);
  const l = collectLogger();
  assertEquals(await fleet.runSourceSafeUpdate("app1", s.api, l.logger), true);
  assertEquals(s.calls, [
    { model: "app1", method: "safeUpdate", args: { snapshot: false } },
    { model: "app1", method: "safeUpdate", args: {} },
  ]);
  assertStringIncludes(JSON.stringify(l.lines), "does not support snapshot:false");
  // Any other failure is not retried, and is logged with its error.
  const other = stubSwamp([{ ok: false, error: "update script exploded" }]);
  const l2 = collectLogger();
  assertEquals(await fleet.runSourceSafeUpdate("app1", other.api, l2.logger), false);
  assertEquals(other.calls.length, 1);
  assertEquals(l2.lines[0].msg, "{model} {method} failed: {error}");
  assertEquals(l2.lines[0].props.error, "update script exploded");
});
// --- post-update health grace ---------------------------------------------------

/** A fake clock for evalHealthWithGrace: sleeping moves the clock, nothing really waits. */
function fakeTiming() {
  let now = 0;
  const sleeps: number[] = [];
  return {
    sleeps,
    timing: {
      intervalMs: 10_000,
      now: () => now,
      sleep: (ms: number) => {
        sleeps.push(ms);
        now += ms;
        return Promise.resolve();
      },
    },
  };
}

/** An evaluator that returns the given verdicts in order, then repeats the last one. */
function verdicts(...oks: boolean[]) {
  let calls = 0;
  return {
    calls: () => calls,
    evaluate: () => {
      const ok = oks[Math.min(calls++, oks.length - 1)];
      return Promise.resolve({
        healthy: ok,
        results: [
          { label: "web up", ok, detail: "" },
          { label: "db up", ok: true, detail: "" },
        ],
      });
    },
  };
}

function collectLogger() {
  const lines: Array<{ msg: string; props: Record<string, unknown> }> = [];
  const add = (msg: string, props: Record<string, unknown> = {}) =>
    lines.push({ msg, props });
  return { lines, logger: { debug: add, info: add, warn: add, error: add } };
}

Deno.test("evalHealthWithGrace: healthy on the first attempt returns at once, no wait, no log", async () => {
  const c = fakeTiming();
  const v = verdicts(true);
  const l = collectLogger();
  const res = await fleet.evalHealthWithGrace(v.evaluate, 120, l.logger, c.timing);
  assertEquals(res.healthy, true);
  assertEquals(v.calls(), 1);
  assertEquals(c.sleeps, []);
  assertEquals(l.lines, []);
});

Deno.test("evalHealthWithGrace: returns healthy as soon as a later attempt passes, logging each failed attempt", async () => {
  const c = fakeTiming();
  const v = verdicts(false, false, true);
  const l = collectLogger();
  const res = await fleet.evalHealthWithGrace(v.evaluate, 120, l.logger, c.timing);
  assertEquals(res.healthy, true);
  assertEquals(v.calls(), 3);
  assertEquals(c.sleeps, [10_000, 10_000]);
  assertEquals(l.lines.length, 2);
  assertEquals(l.lines[0].props, { attempt: 1, labels: "web up" });
  assertEquals(l.lines[1].props, { attempt: 2, labels: "web up" });
});

Deno.test("evalHealthWithGrace: gives up after the window and returns the last unhealthy result", async () => {
  const c = fakeTiming();
  const v = verdicts(false);
  const l = collectLogger();
  const res = await fleet.evalHealthWithGrace(v.evaluate, 25, l.logger, c.timing);
  assertEquals(res.healthy, false);
  assertEquals(res.results.filter((r) => !r.ok).map((r) => r.label), ["web up"]);
  // Attempts at 0, 10, 20 and 25 s; the last wait is cut to the time that is left.
  assertEquals(v.calls(), 4);
  assertEquals(c.sleeps, [10_000, 10_000, 5_000]);
  assertEquals(l.lines.length, 4);
});

Deno.test("evalHealthWithGrace: healthGraceSec 0 evaluates exactly once", async () => {
  const c = fakeTiming();
  const v = verdicts(false, true);
  const res = await fleet.evalHealthWithGrace(
    v.evaluate,
    0,
    collectLogger().logger,
    c.timing,
  );
  assertEquals(res.healthy, false);
  assertEquals(v.calls(), 1);
  assertEquals(c.sleeps, []);
});

/** Shrink the real poll interval for a method-level test, then restore it. */
async function withFastPolling<T>(fn: () => Promise<T>): Promise<T> {
  const saved = fleet.healthPolling.intervalMs;
  fleet.healthPolling.intervalMs = 20;
  try {
    return await fn();
  } finally {
    fleet.healthPolling.intervalMs = saved;
  }
}

Deno.test("safeOsUpdate: a VM that becomes healthy within the grace window is NOT rolled back", async () => {
  // Two unhealthy probes (containers still restarting), then healthy.
  const server = startServer((n) => (n <= 2 ? 503 : 200));
  try {
    await withFastPolling(() =>
      withCallLog(osUpdateEnv(), async (calls) => {
        const t = mkCtx({
          sshModel: "ssh",
          machines: [{
            host: "web1",
            vm: { proxmoxNode: "pve", vmid: 100 },
            health: [{ type: "http", url: server.url }],
          }],
        });
        await model.methods.safeOsUpdate.execute(
          model.methods.safeOsUpdate.arguments.parse({
            host: "web1",
            healthGraceSec: 30,
          }),
          t.ctx,
        );
        const os = t.one("osUpdate");
        assertEquals(os.healthyAfter, true);
        assertEquals(os.rolledBack, false);
        assertEquals(os.outcome === "rolled-back", false);
        assertEquals(server.requests(), 3);
        assertEquals((await calls()).some((c) => c.includes(" rollbackVm ")), false);
        // The refreshed inventory is schema-valid and carries the post-update verdict
        // (it used to omit `health`, which erased the host's health from the report).
        const inv = model.resources.inventory.schema.parse(t.one("inventory"));
        assertEquals(inv.health?.healthy, true);
        assertEquals(inv.health?.checks.map((c) => c.ok), [true]);
      })
    );
  } finally {
    await server.stop();
  }
});

Deno.test("safeOsUpdate: a VM that stays unhealthy past the grace window is rolled back", async () => {
  const server = startServer(() => 503);
  try {
    await withFastPolling(() =>
      withCallLog(osUpdateEnv(), async (calls) => {
        const t = mkCtx({
          sshModel: "ssh",
          machines: [{
            host: "web1",
            vm: { proxmoxNode: "pve", vmid: 100 },
            health: [{ type: "http", url: server.url }],
          }],
        });
        await model.methods.safeOsUpdate.execute(
          model.methods.safeOsUpdate.arguments.parse({
            host: "web1",
            healthGraceSec: 1,
          }),
          t.ctx,
        );
        const os = t.one("osUpdate");
        assertEquals(os.outcome, "rolled-back");
        assertEquals(os.healthyAfter, false);
        // It re-checked during the window before it gave up.
        assert(server.requests() > 2);
        assertEquals((await calls()).some((c) => c.includes(" rollbackVm ")), true);
        // After a rollback the restored state is unchecked: health is null, and the
        // record still matches the schema.
        for (const r of t.written("inventory")) {
          const inv = model.resources.inventory.schema.parse(r.data);
          assertEquals(inv.health, null);
        }
      })
    );
  } finally {
    await server.stop();
  }
});

Deno.test("inventoryHealth maps a verdict to the inventory shape, and no verdict to null", () => {
  const checks = [{ label: "app", ok: false, detail: "rc 1" }];
  assertEquals(fleet.inventoryHealth({ healthy: false, results: checks }), {
    healthy: false,
    checks,
  });
  assertEquals(fleet.inventoryHealth(null), null);
});

// --- reboot ---------------------------------------------------------------

Deno.test("reboot: rejects an unknown host", async () => {
  const t = mkCtx({ sshModel: "ssh", machines: [{ host: "a" }] });
  await assertRejects(
    () =>
      model.methods.reboot.execute(
        model.methods.reboot.arguments.parse({ host: "zzz" }),
        t.ctx,
      ),
    Error,
    'no machine "zzz" in the fleet',
  );
});

Deno.test("reboot: skips when the last scan shows no reboot is needed", async () => {
  const t = mkCtx(
    { sshModel: "ssh", machines: [{ host: "web1" }] },
    { stored: { web1: { needsReboot: false } } },
  );
  await model.methods.reboot.execute(
    model.methods.reboot.arguments.parse({ host: "web1" }),
    t.ctx,
  );
  const reboot = t.one("reboot");
  assertEquals(reboot.outcome, "skipped");
  assertEquals(reboot.neededReboot, false);
  assertEquals(reboot.via, "ssh");
  assertEquals(reboot.waited, false);
  assertEquals(t.one("run").outcome, "skipped");
  assertEquals(t.one("run").needsReboot, false);
});

Deno.test("reboot: a needed reboot runs over ssh; wait=false finishes as rebooted", async () => {
  await withFake({ FAKE_SWAMP_EXEC: execOut("", 0) }, async () => {
    const t = mkCtx(
      { sshModel: "ssh", machines: [{ host: "web1" }] },
      { stored: { web1: { needsReboot: true } } },
    );
    await model.methods.reboot.execute(
      model.methods.reboot.arguments.parse({ host: "web1", wait: false }),
      t.ctx,
    );
    const reboot = t.one("reboot");
    assertEquals(reboot.outcome, "rebooted");
    assertEquals(reboot.neededReboot, true);
    assertEquals(reboot.confirmed, false);
    assertEquals(reboot.waited, false);
    assertEquals(reboot.via, "ssh");
    assertStringIncludes(String(reboot.logs), "scheduling systemctl reboot");
    assertEquals(t.written("run")[0].name.startsWith("run-reboot-web1-"), true);
  });
});

Deno.test("reboot: force reboots when needsReboot is unknown, and a CT goes through pct", async () => {
  await withFake({ FAKE_SWAMP_EXEC: execOut("", 0) }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "ct1", ct: { proxmoxNode: "pve", ctid: 200 } }],
    });
    await model.methods.reboot.execute(
      model.methods.reboot.arguments.parse({
        host: "ct1",
        force: true,
        wait: false,
      }),
      t.ctx,
    );
    const reboot = t.one("reboot");
    assertEquals(reboot.via, "pct");
    assertEquals(reboot.outcome, "rebooted");
    assertEquals(reboot.neededReboot, null);
    assertStringIncludes(String(reboot.logs), "pct reboot 200 on pve");
  });
});

Deno.test("reboot: unknown needsReboot proceeds without force", async () => {
  await withFake({ FAKE_SWAMP_EXEC: execOut("", 0) }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
    await model.methods.reboot.execute(
      model.methods.reboot.arguments.parse({ host: "web1", wait: false }),
      t.ctx,
    );
    assertStringIncludes(
      String(t.one("reboot").logs),
      "needsReboot unknown — proceeding",
    );
  });
});

Deno.test("reboot: a failing reboot command is recorded as failed", async () => {
  await withFake({ FAKE_SWAMP_EXEC: execOut("denied", 1) }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
    await model.methods.reboot.execute(
      model.methods.reboot.arguments.parse({
        host: "web1",
        force: true,
        wait: false,
      }),
      t.ctx,
    );
    const reboot = t.one("reboot");
    assertEquals(reboot.outcome, "failed");
    assertEquals(reboot.confirmed, false);
    assertEquals(reboot.needsRebootAfter, null);
    assertEquals(t.one("run").outcome, "failed");
  });
});

// --- rollback -------------------------------------------------------------

Deno.test("rollback: needs a machine and a retained snapshot", async () => {
  const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
  await assertRejects(
    () =>
      model.methods.rollback.execute(
        model.methods.rollback.arguments.parse({ host: "zzz" }),
        t.ctx,
      ),
    Error,
    'no machine "zzz" in the fleet',
  );
  await assertRejects(
    () =>
      model.methods.rollback.execute(
        model.methods.rollback.arguments.parse({ host: "web1" }),
        t.ctx,
      ),
    Error,
    'no retained snapshot for "web1" to roll back to',
  );
  const named = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] }, {
    data: { snapshot: [snapDatum("snap-web1-1")] },
  });
  await assertRejects(
    () =>
      model.methods.rollback.execute(
        model.methods.rollback.arguments.parse({
          host: "web1",
          snapshot: "nope",
        }),
        named.ctx,
      ),
    Error,
    "named nope",
  );
});

Deno.test("rollback: reverts a VM to the newest active snapshot", async () => {
  const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] }, {
    data: {
      snapshot: [
        snapDatum("snap-web1-1", { name: "old", createdAt: "2026-01-01T00:00:00Z" }),
        snapDatum("snap-web1-2", { name: "newest", createdAt: "2026-02-01T00:00:00Z" }),
        snapDatum("snap-web1-3", {
          name: "pruned",
          createdAt: "2026-03-01T00:00:00Z",
          status: "pruned",
        }),
        snapDatum("snap-other", { host: "other", name: "other-host" }),
        snapDatum("snap-web1-old-version", { name: "stale" }, false),
      ],
    },
  });
  await model.methods.rollback.execute(
    model.methods.rollback.arguments.parse({ host: "web1" }),
    t.ctx,
  );
  const run = t.one("run");
  assertEquals(run.action, "rollback");
  assertEquals(run.snapshot, "newest");
  assertEquals(run.outcome, "rolled-back");
  assertEquals(run.rolledBack, true);
  assertEquals(t.written("run")[0].name.startsWith("run-rollback-web1-"), true);
});

Deno.test("rollback: a named snapshot is used, a CT goes through pct, and failures are recorded", async () => {
  const data = {
    snapshot: [
      snapDatum("snap-web1-1", { name: "first", createdAt: "2026-01-01T00:00:00Z" }),
      snapDatum("snap-web1-2", {
        name: "ct-snap",
        kind: "ct",
        vmid: 200,
        createdAt: "2026-02-01T00:00:00Z",
      }),
    ],
  };
  await withFake({ FAKE_SWAMP_EXEC: execOut("", 0) }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] }, { data });
    await model.methods.rollback.execute(
      model.methods.rollback.arguments.parse({ host: "web1", snapshot: "first" }),
      t.ctx,
    );
    assertEquals(t.one("run").snapshot, "first");
    const ct = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] }, { data });
    await model.methods.rollback.execute(
      model.methods.rollback.arguments.parse({ host: "web1" }),
      ct.ctx,
    );
    assertEquals(ct.one("run").snapshot, "ct-snap");
    assertEquals(ct.one("run").outcome, "rolled-back");
  });
  await withFake({ FAKE_SWAMP_EXEC: execOut("", 1) }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] }, { data });
    await model.methods.rollback.execute(
      model.methods.rollback.arguments.parse({ host: "web1" }),
      t.ctx,
    );
    assertEquals(t.one("run").outcome, "failed");
    assertEquals(t.one("run").rolledBack, false);
  });
  await withFake({ FAKE_SWAMP_METHOD_RC: "1" }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] }, { data });
    await model.methods.rollback.execute(
      model.methods.rollback.arguments.parse({ host: "web1", snapshot: "first" }),
      t.ctx,
    );
    assertEquals(t.one("run").outcome, "failed");
  });
});

// --- pruneSnapshots (snapshot retention / prune selection) -------------------

const FLEET = { sshModel: "ssh", machines: [{ host: "web1" }] };
const HEALTHY_NOW = scriptOut("web1", collectorStdout({ needsReboot: false }));

Deno.test("pruneSnapshots: keeps snapshots that are unconfirmed, reboot-pending or still retained", async () => {
  const t = mkCtx(FLEET, {
    data: {
      snapshot: [
        snapDatum("s-a", { name: "a", healthConfirmed: false }),
        snapDatum("s-b", {
          name: "b",
          rebootRequired: true,
          rebootConfirmed: false,
        }),
        snapDatum("s-c", { name: "c", retainUntil: "2999-01-01T00:00:00.000Z" }),
        snapDatum("s-d", { name: "d", status: "pruned" }),
        snapDatum("s-e", { name: "e" }, false),
      ],
    },
  });
  await model.methods.pruneSnapshots.execute(
    model.methods.pruneSnapshots.arguments.parse({}),
    t.ctx,
  );
  const prune = t.one("prune");
  assertEquals(prune.kind, "snapshots");
  assertEquals(prune.dryRun, false);
  assertEquals(prune.pruned, []);
  assertEquals(prune.kept, [
    { host: "web1", name: "a", reason: "not health-confirmed" },
    { host: "web1", name: "b", reason: "reboot not confirmed" },
    {
      host: "web1",
      name: "c",
      reason: "retained until 2999-01-01T00:00:00.000Z",
    },
  ]);
  assertEquals(t.written("snapshot"), []);
  assertStringIncludes(t.written("prune")[0].name, "prune-snapshots-");
});

Deno.test("pruneSnapshots: dryRun reports an eligible snapshot without deleting it", async () => {
  await withFake({ FAKE_SWAMP_SCRIPT_1: HEALTHY_NOW }, async () => {
    const t = mkCtx(FLEET, { data: { snapshot: [snapDatum("s-1")] } });
    await model.methods.pruneSnapshots.execute(
      model.methods.pruneSnapshots.arguments.parse({ dryRun: true }),
      t.ctx,
    );
    const prune = t.one("prune");
    assertEquals(prune.dryRun, true);
    assertEquals(prune.pruned, [
      { host: "web1", name: "preupdate-1", detail: "vm:100" },
    ]);
    assertEquals(prune.kept, []);
    assertEquals(t.written("snapshot"), []);
  });
});

Deno.test("pruneSnapshots: a live run deletes the snapshot and marks the record pruned", async () => {
  await withFake({ FAKE_SWAMP_SCRIPT_1: HEALTHY_NOW }, async () => {
    const t = mkCtx(FLEET, { data: { snapshot: [snapDatum("s-1")] } });
    await model.methods.pruneSnapshots.execute(
      model.methods.pruneSnapshots.arguments.parse({}),
      t.ctx,
    );
    assertEquals(t.one("prune").pruned, [
      { host: "web1", name: "preupdate-1", detail: "vmid:100" },
    ]);
    const snap = t.one("snapshot");
    assertEquals(snap.status, "pruned");
    assertEquals(typeof snap.prunedAt, "string");
    assertEquals(snap.name, "preupdate-1");
    assertEquals(t.written("snapshot")[0].name, "s-1");
  });
});

Deno.test("pruneSnapshots: a CT snapshot is deleted with pct over the node host", async () => {
  await withFake({
    FAKE_SWAMP_SCRIPT_1: HEALTHY_NOW,
    FAKE_SWAMP_EXEC: execOut("", 0),
  }, async () => {
    const t = mkCtx(FLEET, {
      data: { snapshot: [snapDatum("s-ct", { kind: "ct", vmid: 200 })] },
    });
    await model.methods.pruneSnapshots.execute(
      model.methods.pruneSnapshots.arguments.parse({}),
      t.ctx,
    );
    assertEquals(t.one("snapshot").status, "pruned");
    assertEquals((t.one("prune").pruned as unknown[]).length, 1);
  });
});

Deno.test("pruneSnapshots: the live gate of a CT scans it with pct on its node, not ssh to the CT", async () => {
  await withCallLog({
    FAKE_SWAMP_SCRIPT_1: scriptOut("node1", collectorStdout({ needsReboot: false })),
    FAKE_SWAMP_EXEC: execOut("", 0),
  }, async (calls) => {
    const fleetCt = {
      sshModel: "ssh",
      machines: [{ host: "ct1", ct: { proxmoxNode: "node1", ctid: 200 } }],
    };
    const t = mkCtx(fleetCt, {
      data: {
        snapshot: [
          snapDatum("s-ct", { host: "ct1", kind: "ct", vmid: 200, proxmoxNode: "node1" }),
        ],
      },
    });
    await model.methods.pruneSnapshots.execute(
      model.methods.pruneSnapshots.arguments.parse({ dryRun: true }),
      t.ctx,
    );
    assertEquals((t.one("prune").pruned as unknown[]).length, 1);
    assertEquals(t.one("prune").kept, []);
    const scripts = (await calls()).filter((c) => c.startsWith("ssh script"));
    assertEquals(scripts.length, 1);
    assertStringIncludes(scripts[0], 'hosts:json=["node1"]');
    assertStringIncludes(scripts[0], "pct exec 200");
  });
});

Deno.test("pruneSnapshots: keeps the snapshot of a host that is not in the fleet", async () => {
  await withCallLog({ FAKE_SWAMP_SCRIPT_1: HEALTHY_NOW }, async (calls) => {
    const t = mkCtx(FLEET, {
      data: { snapshot: [snapDatum("s-old", { host: "old1" })] },
    });
    await model.methods.pruneSnapshots.execute(
      model.methods.pruneSnapshots.arguments.parse({ dryRun: true }),
      t.ctx,
    );
    assertEquals(t.one("prune").pruned, []);
    assertEquals(t.one("prune").kept, [
      { host: "old1", name: "preupdate-1", reason: "host not in the fleet" },
    ]);
    assertEquals(await calls(), []);
  });
});

Deno.test("pruneSnapshots: keeps a snapshot when the host is not healthy now or the delete fails", async () => {
  await withFake({
    FAKE_SWAMP_SCRIPT_1: scriptOut(
      "web1",
      collectorStdout({ needsReboot: true }),
    ),
  }, async () => {
    const t = mkCtx(FLEET, { data: { snapshot: [snapDatum("s-1")] } });
    await model.methods.pruneSnapshots.execute(
      model.methods.pruneSnapshots.arguments.parse({}),
      t.ctx,
    );
    assertEquals(t.one("prune").kept, [
      { host: "web1", name: "preupdate-1", reason: "host not healthy now" },
    ]);
    assertEquals(t.written("snapshot"), []);
  });
  await withFake({
    FAKE_SWAMP_SCRIPT_1: "garbage",
  }, async () => {
    const t = mkCtx(FLEET, { data: { snapshot: [snapDatum("s-1")] } });
    await model.methods.pruneSnapshots.execute(
      model.methods.pruneSnapshots.arguments.parse({}),
      t.ctx,
    );
    assertEquals(
      (t.one("prune").kept as Array<{ reason: string }>)[0].reason,
      "host not healthy now",
    );
  });
  await withFake({
    FAKE_SWAMP_SCRIPT_1: HEALTHY_NOW,
    FAKE_SWAMP_METHOD_RC: "1",
  }, async () => {
    const t = mkCtx(FLEET, { data: { snapshot: [snapDatum("s-1")] } });
    await model.methods.pruneSnapshots.execute(
      model.methods.pruneSnapshots.arguments.parse({}),
      t.ctx,
    );
    assertEquals(t.one("prune").kept, [
      { host: "web1", name: "preupdate-1", reason: "delete call failed" },
    ]);
    assertEquals(t.written("snapshot"), []);
  });
});

Deno.test("pruneSnapshots: requireRebootConfirmed=false lets a reboot-pending snapshot through; host filter limits the scan", async () => {
  await withFake({ FAKE_SWAMP_SCRIPT_1: HEALTHY_NOW }, async () => {
    const data = {
      snapshot: [
        snapDatum("s-1", { rebootRequired: true, rebootConfirmed: false }),
        snapDatum("s-2", { host: "db1", name: "db-snap" }),
      ],
    };
    const t = mkCtx(FLEET, { data });
    await model.methods.pruneSnapshots.execute(
      model.methods.pruneSnapshots.arguments.parse({
        host: "web1",
        dryRun: true,
        requireRebootConfirmed: false,
      }),
      t.ctx,
    );
    assertEquals(t.one("prune").pruned, [
      { host: "web1", name: "preupdate-1", detail: "vm:100" },
    ]);
    assertEquals(t.one("prune").kept, []);
  });
});

// --- pruneImages (image retention / prune selection) -------------------------

function imageDatum(
  name: string,
  over: Record<string, unknown> = {},
  isLatest = true,
): ModelDatum {
  return { name, isLatest, attributes: { ...IMAGE, ...over } };
}

Deno.test("pruneImages: keeps images still inside their retention window or already pruned", async () => {
  const t = mkCtx(FLEET, {
    data: {
      image: [
        imageDatum("i-a", { retainUntil: "2999-01-01T00:00:00.000Z" }),
        imageDatum("i-b", { status: "pruned", ref: "gone:1" }),
        imageDatum("i-c", { ref: "stale:1" }, false),
      ],
    },
  });
  await model.methods.pruneImages.execute(
    model.methods.pruneImages.arguments.parse({}),
    t.ctx,
  );
  const prune = t.one("prune");
  assertEquals(prune.kind, "images");
  assertEquals(prune.pruned, []);
  assertEquals(prune.kept, [{
    host: "dock1",
    name: "nginx:1",
    reason: "retained until 2999-01-01T00:00:00.000Z",
  }]);
  assertStringIncludes(t.written("prune")[0].name, "prune-images-");
});

Deno.test("pruneImages: an unreachable host keeps its images", async () => {
  await withFake({ FAKE_SWAMP_EXEC: "", FAKE_SWAMP_EXEC_RC: "1" }, async () => {
    const t = mkCtx(FLEET, { data: { image: [imageDatum("i-1")] } });
    await model.methods.pruneImages.execute(
      model.methods.pruneImages.arguments.parse({}),
      t.ctx,
    );
    assertEquals(t.one("prune").kept, [
      { host: "dock1", name: "nginx:1", reason: "host not reachable now" },
    ]);
    assertEquals(t.written("image"), []);
  });
});

Deno.test("pruneImages: dryRun lists the image id prefix; a live run removes the image and marks it pruned", async () => {
  await withFake({ FAKE_SWAMP_EXEC: execOut("24.0.7", 0) }, async () => {
    const dry = mkCtx(FLEET, { data: { image: [imageDatum("i-1")] } });
    await model.methods.pruneImages.execute(
      model.methods.pruneImages.arguments.parse({ dryRun: true }),
      dry.ctx,
    );
    assertEquals(dry.one("prune").dryRun, true);
    assertEquals(dry.one("prune").pruned, [
      { host: "dock1", name: "nginx:1", detail: "sha256:0123456789ab" },
    ]);
    assertEquals(dry.written("image"), []);

    const live = mkCtx(FLEET, { data: { image: [imageDatum("i-1")] } });
    await model.methods.pruneImages.execute(
      model.methods.pruneImages.arguments.parse({}),
      live.ctx,
    );
    assertEquals((live.one("prune").pruned as unknown[]).length, 1);
    const img = live.one("image");
    assertEquals(img.status, "pruned");
    assertEquals(typeof img.prunedAt, "string");
    assertEquals(live.written("image")[0].name, "i-1");
  });
});

Deno.test("pruneImages: the host filter limits which images are considered", async () => {
  await withFake({ FAKE_SWAMP_EXEC: execOut("24.0.7", 0) }, async () => {
    const t = mkCtx(FLEET, {
      data: {
        image: [
          imageDatum("i-1"),
          imageDatum("i-2", { host: "dock2", ref: "redis:7" }),
        ],
      },
    });
    await model.methods.pruneImages.execute(
      model.methods.pruneImages.arguments.parse({ host: "dock2", dryRun: true }),
      t.ctx,
    );
    assertEquals(
      (t.one("prune").pruned as Array<{ name: string }>).map((p) => p.name),
      ["redis:7"],
    );
  });
});

// ---------------------------------------------------------------------------
// Pre-flight checks
// ---------------------------------------------------------------------------

const MUTATING = [
  "safeUpdate",
  "safeOsUpdate",
  "reboot",
  "rollback",
  "pruneSnapshots",
  "pruneImages",
  "clearRetired",
];
const READ_ONLY = ["scan", "import"];

type CheckName = keyof typeof model.checks;

/** Build a check context like swamp does: global args, repo dir, method name, method args. */
function checkCtx(
  globalArgs: unknown,
  methodName: string,
  args: Record<string, unknown> = {},
) {
  return {
    globalArgs: model.globalArguments.parse(globalArgs),
    repoDir: "/tmp/swamp-test",
    definitionRepository: fakeDefinitions,
    methodName,
    unresolvedMethodArgs: args,
  };
}

function runCheck(name: CheckName, ctx: ReturnType<typeof checkCtx>) {
  return model.checks[name].execute(ctx);
}

const CHECK_FLEET = {
  sshModel: "ssh",
  machines: [
    { host: "bare" },
    { host: "dock", docker: { composePath: "/srv/app", service: "app" } },
    { host: "vm1", vm: { proxmoxNode: "pve-node", vmid: 100 } },
    { host: "ct1", ct: { proxmoxNode: "pve", ctid: 101 } },
    {
      host: "hc",
      health: [
        { type: "command", label: "db up", run: "true" },
        { type: "command", label: "queue up", run: "true" },
      ],
    },
  ],
};

Deno.test("checks: every mutating method has at least one check, read-only methods have none", () => {
  const checks = Object.values(model.checks);
  for (const method of MUTATING) {
    assert(method in model.methods, `${method} is a method`);
    assert(
      checks.some((c) => (c.appliesTo as string[]).includes(method)),
      `${method} has a pre-flight check`,
    );
  }
  for (const method of READ_ONLY) {
    assert(method in model.methods, `${method} is a method`);
    assert(
      !checks.some((c) => (c.appliesTo as string[]).includes(method)),
      `${method} has no pre-flight check`,
    );
  }
  // Every method is classified: a new method must be added to one of the two lists.
  assertEquals(
    Object.keys(model.methods).sort(),
    [...MUTATING, ...READ_ONLY].sort(),
  );
});

Deno.test("checks: each check has a description, a known label and valid appliesTo", () => {
  for (const [name, c] of Object.entries(model.checks)) {
    assert(c.description.length > 0, `${name} has a description`);
    assertEquals(c.labels.length, 1, `${name} has one label`);
    assert(["policy", "live"].includes(c.labels[0]), `${name} label`);
    for (const m of c.appliesTo) assert(m in model.methods, `${name}: ${m}`);
  }
  assertEquals(model.checks["host-in-fleet"].labels, ["policy"]);
  assertEquals(model.checks["host-retired"].labels, ["policy"]);
  assertEquals(model.checks["docker-configured"].labels, ["policy"]);
  assertEquals(model.checks["host-reachable"].labels, ["live"]);
  assertEquals(model.checks["baseline-healthy"].labels, ["live"]);
  assertEquals(model.checks["snapshot-target-resolves"].labels, ["live"]);
});

Deno.test("checks: recovery rule — rollback needs no healthy or reachable host; reboot needs no healthy host", () => {
  assertEquals(model.checks["host-reachable"].appliesTo.includes("rollback"), false);
  assertEquals(model.checks["baseline-healthy"].appliesTo.includes("rollback"), false);
  assertEquals(model.checks["baseline-healthy"].appliesTo.includes("reboot"), false);
  assertEquals(
    model.checks["snapshot-target-resolves"].appliesTo.includes("rollback"),
    true,
  );
});

// --- host-in-fleet ---------------------------------------------------------

Deno.test("host-in-fleet: passes for a machine in the fleet", async () => {
  for (const method of ["safeUpdate", "safeOsUpdate", "reboot", "rollback"]) {
    const r = await runCheck(
      "host-in-fleet",
      checkCtx(CHECK_FLEET, method, { host: "bare" }),
    );
    assertEquals(r, { pass: true });
  }
});

Deno.test("host-in-fleet: fails for an unknown host and names the fix and the skip flags", async () => {
  const r = await runCheck(
    "host-in-fleet",
    checkCtx(CHECK_FLEET, "safeOsUpdate", { host: "nope" }),
  );
  assertEquals(r.pass, false);
  const msg = r.errors!.join(" ");
  assertStringIncludes(msg, '"nope"');
  assertStringIncludes(msg, "bare, dock");
  assertStringIncludes(msg, "--skip-check host-in-fleet");
  assertStringIncludes(msg, "--skip-check-label policy");
});

Deno.test("host-in-fleet: prune methods pass without a host filter and fail for a bad filter", async () => {
  for (const method of ["pruneSnapshots", "pruneImages"]) {
    assertEquals(
      await runCheck("host-in-fleet", checkCtx(CHECK_FLEET, method, {})),
      { pass: true },
    );
    assertEquals(
      (await runCheck(
        "host-in-fleet",
        checkCtx(CHECK_FLEET, method, { host: "dock" }),
      )).pass,
      true,
    );
    assertEquals(
      (await runCheck(
        "host-in-fleet",
        checkCtx(CHECK_FLEET, method, { host: "nope" }),
      )).pass,
      false,
    );
  }
});

Deno.test("host-in-fleet: an argument swamp has not resolved yet (CEL text) does not fail the check", async () => {
  assertEquals(
    await runCheck(
      "host-in-fleet",
      checkCtx(CHECK_FLEET, "reboot", { host: "${{ inputs.host }}" }),
    ),
    { pass: true },
  );
});

// --- docker-configured -----------------------------------------------------

Deno.test("docker-configured: passes for a machine with a docker block", async () => {
  assertEquals(
    await runCheck(
      "docker-configured",
      checkCtx(CHECK_FLEET, "safeUpdate", { host: "dock" }),
    ),
    { pass: true },
  );
});

Deno.test("docker-configured: fails without a docker block and leaves an unknown host to host-in-fleet", async () => {
  const r = await runCheck(
    "docker-configured",
    checkCtx(CHECK_FLEET, "safeUpdate", { host: "bare" }),
  );
  assertEquals(r.pass, false);
  assertStringIncludes(r.errors!.join(" "), "--skip-check docker-configured");
  assertEquals(
    (await runCheck(
      "docker-configured",
      checkCtx(CHECK_FLEET, "safeUpdate", { host: "nope" }),
    )).pass,
    true,
  );
});

// --- host-reachable --------------------------------------------------------

Deno.test("host-reachable: an ssh host that answers passes", async () => {
  await withFake({ FAKE_SWAMP_EXEC: execOut("", 0) }, async () => {
    for (const method of ["safeUpdate", "safeOsUpdate", "reboot"]) {
      assertEquals(
        await runCheck(
          "host-reachable",
          checkCtx(CHECK_FLEET, method, { host: "vm1" }),
        ),
        { pass: true },
      );
    }
  });
});

Deno.test("host-reachable: a host whose command fails, or whose transport fails, is reported with the skip flags", async () => {
  await withFake({ FAKE_SWAMP_EXEC: execOut("", 255) }, async () => {
    const r = await runCheck(
      "host-reachable",
      checkCtx(CHECK_FLEET, "safeOsUpdate", { host: "bare" }),
    );
    assertEquals(r.pass, false);
    assertStringIncludes(r.errors!.join(" "), "--skip-check host-reachable");
    assertStringIncludes(r.errors!.join(" "), "--skip-check-label live");
  });
  await withFake({ FAKE_SWAMP_EXEC_RC: "1" }, async () => {
    const r = await runCheck(
      "host-reachable",
      checkCtx(CHECK_FLEET, "reboot", { host: "bare" }),
    );
    assertEquals(r.pass, false);
    assertStringIncludes(r.errors!.join(" "), "not reachable");
  });
});

Deno.test("host-reachable: a CT is checked with pct status on its node", async () => {
  await withFake({ FAKE_SWAMP_EXEC: execOut("status: running", 0) }, async () => {
    assertEquals(
      await runCheck(
        "host-reachable",
        checkCtx(CHECK_FLEET, "reboot", { host: "ct1" }),
      ),
      { pass: true },
    );
  });
  await withFake({ FAKE_SWAMP_EXEC: execOut("status: stopped", 0) }, async () => {
    const r = await runCheck(
      "host-reachable",
      checkCtx(CHECK_FLEET, "safeOsUpdate", { host: "ct1" }),
    );
    assertEquals(r.pass, false);
    assertStringIncludes(r.errors!.join(" "), "ctid 101");
    assertStringIncludes(r.errors!.join(" "), 'node "pve"');
  });
  await withFake({ FAKE_SWAMP_EXEC: execOut("no such CT", 2) }, async () => {
    assertEquals(
      (await runCheck(
        "host-reachable",
        checkCtx(CHECK_FLEET, "reboot", { host: "ct1" }),
      )).pass,
      false,
    );
  });
});

Deno.test("host-reachable: safeUpdate reaches a docker host over ssh even when it is a CT", async () => {
  // `pct status` would fail on this output; ssh `true` only needs rc 0.
  await withFake({ FAKE_SWAMP_EXEC: execOut("status: stopped", 0) }, async () => {
    assertEquals(
      await runCheck(
        "host-reachable",
        checkCtx(CHECK_FLEET, "safeUpdate", { host: "ct1" }),
      ),
      { pass: true },
    );
  });
});

Deno.test("host-reachable: a CT with no resolvable location fails", async () => {
  const fleet = {
    sshModel: "ssh",
    machines: [{ host: "old", reach: "pct", proxmox: { model: "gone" } }],
  };
  await withFake({ FAKE_SWAMP_GET_RC: "1" }, async () => {
    const r = await runCheck(
      "host-reachable",
      checkCtx(fleet, "reboot", { host: "old" }),
    );
    assertEquals(r.pass, false);
  });
});

Deno.test("host-reachable: passes when the host argument is not visible to checks", async () => {
  assertEquals(
    await runCheck("host-reachable", checkCtx(CHECK_FLEET, "reboot", {})),
    { pass: true },
  );
});

// --- baseline-healthy ------------------------------------------------------

Deno.test("baseline-healthy: passes when the machine resolves no health checks", async () => {
  // No fake is needed: nothing is run.
  for (const method of ["safeUpdate", "safeOsUpdate"]) {
    assertEquals(
      await runCheck(
        "baseline-healthy",
        checkCtx(CHECK_FLEET, method, { host: "bare" }),
      ),
      { pass: true },
    );
  }
});

Deno.test("baseline-healthy: passes when every health check passes", async () => {
  await withFake({ FAKE_SWAMP_HC: hcOut("hc", 0, 0) }, async () => {
    assertEquals(
      await runCheck(
        "baseline-healthy",
        checkCtx(CHECK_FLEET, "safeOsUpdate", { host: "hc" }),
      ),
      { pass: true },
    );
  });
});

Deno.test("baseline-healthy: fails and names each failing health check label", async () => {
  // Both commands run in one batch; both report a failing rc.
  await withFake({ FAKE_SWAMP_HC: hcOut("hc", 1, 1) }, async () => {
    const r = await runCheck(
      "baseline-healthy",
      checkCtx(CHECK_FLEET, "safeOsUpdate", { host: "hc" }),
    );
    assertEquals(r.pass, false);
    const msg = r.errors!.join(" ");
    assertStringIncludes(msg, "db up");
    assertStringIncludes(msg, "queue up");
    assertStringIncludes(msg, "--skip-check baseline-healthy");
    assertStringIncludes(msg, "--skip-check-label live");
  });
});

Deno.test("baseline-healthy: only the failing label is named when one check passes", async () => {
  const srv = startServer((n) => (n === 1 ? 200 : 503));
  try {
    const fleet = {
      sshModel: "ssh",
      machines: [{
        host: "web",
        health: [
          { type: "http", label: "front page", url: srv.url },
          { type: "http", label: "api", url: srv.url },
        ],
      }],
    };
    const r = await runCheck(
      "baseline-healthy",
      checkCtx(fleet, "safeUpdate", { host: "web" }),
    );
    assertEquals(r.pass, false);
    const msg = r.errors!.join(" ");
    assertStringIncludes(msg, "api");
    assertEquals(msg.includes("front page"), false);
    // The pre-flight check is immediate: one request per check, no grace re-checks.
    assertEquals(srv.requests(), 2);
  } finally {
    await srv.stop();
  }
});

Deno.test("baseline-healthy: a transport failure while checking is a failed check, not an exception", async () => {
  await withFake({ FAKE_SWAMP_HC: "", FAKE_SWAMP_HC_RC: "1" }, async () => {
    const r = await runCheck(
      "baseline-healthy",
      checkCtx(CHECK_FLEET, "safeOsUpdate", { host: "hc" }),
    );
    assertEquals(r.pass, false);
    assertStringIncludes(r.errors!.join(" "), "Could not evaluate");
  });
});

// --- snapshot-target-resolves ----------------------------------------------

const snaps = (...names: string[]) =>
  JSON.stringify({
    dataArtifacts: [{
      attributes: { snapshots: names.map((name) => ({ name })) },
    }],
  });

Deno.test("snapshot-target-resolves: a bare-metal machine has nothing to snapshot and passes", async () => {
  for (const method of ["safeOsUpdate", "rollback", "pruneSnapshots"]) {
    assertEquals(
      await runCheck(
        "snapshot-target-resolves",
        checkCtx(CHECK_FLEET, method, { host: "bare" }),
      ),
      { pass: true },
    );
  }
});

Deno.test("snapshot-target-resolves: a VM whose node answers passes", async () => {
  await withFake({ FAKE_SWAMP_VMSNAPS: snaps() }, async () => {
    for (const method of ["safeOsUpdate", "pruneSnapshots"]) {
      assertEquals(
        await runCheck(
          "snapshot-target-resolves",
          checkCtx(CHECK_FLEET, method, { host: "vm1" }),
        ),
        { pass: true },
      );
    }
  });
});

Deno.test("snapshot-target-resolves: a VM whose node model fails is reported with the skip flags", async () => {
  await withFake({ FAKE_SWAMP_VMSNAPS_RC: "1" }, async () => {
    const r = await runCheck(
      "snapshot-target-resolves",
      checkCtx(CHECK_FLEET, "safeOsUpdate", { host: "vm1" }),
    );
    assertEquals(r.pass, false);
    assertStringIncludes(
      r.errors!.join(" "),
      "--skip-check snapshot-target-resolves",
    );
    assertStringIncludes(r.errors!.join(" "), "--skip-check-label live");
  });
});

Deno.test("snapshot-target-resolves: rollback of a VM needs a snapshot on the node, and a named one must exist", async () => {
  await withFake({ FAKE_SWAMP_VMSNAPS: snaps("preupdate-1", "current") }, async () => {
    assertEquals(
      await runCheck(
        "snapshot-target-resolves",
        checkCtx(CHECK_FLEET, "rollback", { host: "vm1" }),
      ),
      { pass: true },
    );
    assertEquals(
      await runCheck(
        "snapshot-target-resolves",
        checkCtx(CHECK_FLEET, "rollback", { host: "vm1", snapshot: "preupdate-1" }),
      ),
      { pass: true },
    );
    const r = await runCheck(
      "snapshot-target-resolves",
      checkCtx(CHECK_FLEET, "rollback", { host: "vm1", snapshot: "other" }),
    );
    assertEquals(r.pass, false);
    assertStringIncludes(r.errors!.join(" "), '"other"');
  });
  await withFake({ FAKE_SWAMP_VMSNAPS: snaps("current") }, async () => {
    const r = await runCheck(
      "snapshot-target-resolves",
      checkCtx(CHECK_FLEET, "rollback", { host: "vm1" }),
    );
    assertEquals(r.pass, false);
    assertStringIncludes(r.errors!.join(" "), "no snapshot to roll back to");
  });
});

Deno.test("snapshot-target-resolves: rollback does not need the host to be reachable or healthy", async () => {
  // The ssh transport is broken, yet the snapshot target still resolves through the node model.
  await withFake(
    { FAKE_SWAMP_EXEC_RC: "1", FAKE_SWAMP_VMSNAPS: snaps("preupdate-1") },
    async () => {
      assertEquals(
        await runCheck(
          "snapshot-target-resolves",
          checkCtx(CHECK_FLEET, "rollback", { host: "vm1" }),
        ),
        { pass: true },
      );
    },
  );
});

Deno.test("snapshot-target-resolves: a CT is checked with pct listsnapshot on its node", async () => {
  const listing = "`-> preupdate-2026-09-29T03-50-59Z 2026-09-29 03:50:59 no description\n" +
    "    `-> current                                       You are here!";
  await withFake({ FAKE_SWAMP_EXEC: execOut(listing, 0) }, async () => {
    for (const method of ["safeOsUpdate", "pruneSnapshots", "rollback"]) {
      assertEquals(
        await runCheck(
          "snapshot-target-resolves",
          checkCtx(CHECK_FLEET, method, { host: "ct1" }),
        ),
        { pass: true },
      );
    }
    const r = await runCheck(
      "snapshot-target-resolves",
      checkCtx(CHECK_FLEET, "rollback", { host: "ct1", snapshot: "missing" }),
    );
    assertEquals(r.pass, false);
  });
  await withFake({ FAKE_SWAMP_EXEC: execOut("`-> current  You are here!", 0) }, async () => {
    assertEquals(
      (await runCheck(
        "snapshot-target-resolves",
        checkCtx(CHECK_FLEET, "rollback", { host: "ct1" }),
      )).pass,
      false,
    );
  });
  await withFake({ FAKE_SWAMP_EXEC: execOut("no such CT", 2) }, async () => {
    const r = await runCheck(
      "snapshot-target-resolves",
      checkCtx(CHECK_FLEET, "safeOsUpdate", { host: "ct1" }),
    );
    assertEquals(r.pass, false);
    assertStringIncludes(r.errors!.join(" "), "CT 101");
  });
});

Deno.test("snapshot-target-resolves: pruneSnapshots without a host filter passes (per-host skips stay in the method)", async () => {
  assertEquals(
    await runCheck(
      "snapshot-target-resolves",
      checkCtx(CHECK_FLEET, "pruneSnapshots", {}),
    ),
    { pass: true },
  );
});

// --- host-retired and clearRetired ------------------------------------------

Deno.test("host-retired: applies to clearRetired only; host-in-fleet does not apply to it", () => {
  assertEquals(model.checks["host-retired"].appliesTo, ["clearRetired"]);
  assertEquals(
    (model.checks["host-in-fleet"].appliesTo as string[]).includes(
      "clearRetired",
    ),
    false,
  );
});

Deno.test("host-retired: passes without a host, for a retired host, and for CEL text", async () => {
  for (const args of [{}, { host: "gone" }, { host: "${{ inputs.host }}" }]) {
    assertEquals(
      await runCheck("host-retired", checkCtx(CHECK_FLEET, "clearRetired", args)),
      { pass: true },
    );
  }
});

Deno.test("host-retired: fails for a host that is in the fleet and names the skip flags", async () => {
  const r = await runCheck(
    "host-retired",
    checkCtx(CHECK_FLEET, "clearRetired", { host: "bare" }),
  );
  assertEquals(r.pass, false);
  const msg = r.errors!.join(" ");
  assertStringIncludes(msg, '"bare"');
  assertStringIncludes(msg, "--skip-check host-retired");
  assertStringIncludes(msg, "--skip-check-label policy");
});

/** A datum for a host-owned record. */
function hostDatum(
  name: string,
  attributes: Record<string, unknown>,
): ModelDatum {
  return { name, isLatest: true, attributes };
}

/**
 * Stored records of a fleet where only `node` is current. `node2` and `old1` are retired.
 * The names `node` and `node2` make a prefix match fail the tests.
 */
function retiredData(): Record<string, ModelDatum[]> {
  const run = (host: string, n: number) =>
    hostDatum(`run-osUpdate-${host}-${n}`, { host, action: "osUpdate" });
  return {
    inventory: [
      hostDatum("node", { hostname: "node" }),
      hostDatum("node2", { hostname: "node2" }),
      hostDatum("old1", { hostname: "old1" }),
    ],
    update: [
      hostDatum("update-node", { host: "node" }),
      hostDatum("update-node2", { host: "node2" }),
    ],
    osUpdate: [
      hostDatum("os-update-node", { host: "node" }),
      hostDatum("os-update-node2", { host: "node2" }),
    ],
    reboot: [hostDatum("reboot-node2", { host: "node2" })],
    run: [run("node", 1), run("node2", 1), run("old1", 1)],
    snapshot: [
      hostDatum("snap-node-1", { host: "node", status: "active" }),
      hostDatum("snap-node2-1", { host: "node2", status: "active" }),
      hostDatum("snap-node2-0", { host: "node2", status: "pruned" }),
    ],
    image: [
      hostDatum("image-node2-1-a", { host: "node2", status: "active" }),
      hostDatum("image-node2-0-a", { host: "node2", status: "pruned" }),
    ],
  };
}

const RETIRED_FLEET = { sshModel: "ssh", machines: [{ host: "node" }] };

type PruneRecord = {
  kind: string;
  dryRun: boolean;
  pruned: Array<{ host: string; name: string; detail: string | null }>;
  kept: Array<{ host: string; name: string; reason: string }>;
};

async function clearRetired(
  globalArgs: unknown,
  data: Record<string, ModelDatum[]>,
  input: Record<string, unknown>,
  opts: { deleteFails?: string[] } = {},
) {
  const t = mkCtx(globalArgs, { data, ...opts });
  const result = await model.methods.clearRetired.execute(
    model.methods.clearRetired.arguments.parse(input),
    t.ctx,
  );
  return { t, result };
}

const names = (entries: Array<{ name: string }>) =>
  entries.map((e) => e.name).sort();

Deno.test("clearRetired: arguments default to a dry run that keeps nothing extra", () => {
  assertEquals(model.methods.clearRetired.arguments.parse({}), {
    dryRun: true,
    keepHistory: false,
    force: false,
  });
  assertEquals(
    model.methods.clearRetired.arguments.safeParse({ host: "" }).success,
    false,
  );
});

Deno.test("clearRetired: PruneResult accepts the kind retired", () => {
  assertEquals(
    model.resources.prune.schema.safeParse({
      scannedAt: "2026-10-04T00:00:00Z",
      kind: "retired",
      dryRun: true,
      pruned: [],
      kept: [],
    }).success,
    true,
  );
});

Deno.test("clearRetired: a bare run is a dry run, deletes nothing and lists everything", async () => {
  const { t, result } = await clearRetired(RETIRED_FLEET, retiredData(), {});
  assertEquals(t.deleted, []);
  assertEquals(result.dataHandles.length, 1);
  const rec = t.one("prune") as PruneRecord;
  assertEquals(rec.kind, "retired");
  assertEquals(rec.dryRun, true);
  assertEquals(names(rec.pruned), [
    "old1",
    "os-update-node2",
    "node2",
    "reboot-node2",
    "run-osUpdate-old1-1",
    "run-osUpdate-node2-1",
    "snap-node2-0",
    "image-node2-0-a",
    "update-node2",
  ].sort());
  assertEquals(
    rec.pruned.find((p) => p.name === "node2"),
    { host: "node2", name: "node2", detail: "inventory" },
  );
  assertEquals(
    rec.pruned.find((p) => p.name === "snap-node2-0")?.detail,
    "snapshot",
  );
  // Active retention is kept, with a reason.
  assertEquals(names(rec.kept), ["image-node2-1-a", "snap-node2-1"].sort());
  for (const k of rec.kept) assertStringIncludes(k.reason, "force=true");
});

Deno.test("clearRetired: dryRun=false deletes status and history of every retired host", async () => {
  const { t } = await clearRetired(RETIRED_FLEET, retiredData(), {
    dryRun: false,
  });
  assertEquals(
    [...t.deleted].sort(),
    [
      "image-node2-0-a",
      "node2",
      "old1",
      "os-update-node2",
      "reboot-node2",
      "run-osUpdate-node2-1",
      "run-osUpdate-old1-1",
      "snap-node2-0",
      "update-node2",
    ],
  );
  const rec = t.one("prune") as PruneRecord;
  assertEquals(rec.dryRun, false);
  assertEquals(names(rec.pruned), [...t.deleted].sort());
  assertStringIncludes(t.written("prune")[0].name, "prune-retired-");
  // Records of the current host `node` are never touched.
  for (const n of t.deleted) {
    assert(!["node", "update-node", "os-update-node", "snap-node-1"].includes(n));
    assert(!n.includes("-node-"), `${n} belongs to the current host`);
  }
});

Deno.test("clearRetired: keepHistory deletes status records only", async () => {
  const { t } = await clearRetired(RETIRED_FLEET, retiredData(), {
    dryRun: false,
    keepHistory: true,
  });
  assertEquals(
    [...t.deleted].sort(),
    ["node2", "old1", "os-update-node2", "reboot-node2", "update-node2"],
  );
  const rec = t.one("prune") as PruneRecord;
  assertEquals(names(rec.kept), [
    "image-node2-0-a",
    "image-node2-1-a",
    "run-osUpdate-node2-1",
    "run-osUpdate-old1-1",
    "snap-node2-0",
    "snap-node2-1",
  ]);
  assertStringIncludes(
    rec.kept.find((k) => k.name === "run-osUpdate-node2-1")!.reason,
    "keepHistory",
  );
});

Deno.test("clearRetired: force also deletes active snapshot and image records", async () => {
  const { t } = await clearRetired(RETIRED_FLEET, retiredData(), {
    dryRun: false,
    force: true,
  });
  assert(t.deleted.includes("snap-node2-1"));
  assert(t.deleted.includes("image-node2-1-a"));
  assertEquals((t.one("prune") as PruneRecord).kept, []);
  // force with keepHistory: active retention goes, pruned retention and runs stay.
  const k = await clearRetired(RETIRED_FLEET, retiredData(), {
    dryRun: false,
    force: true,
    keepHistory: true,
  });
  assert(k.t.deleted.includes("snap-node2-1"));
  assert(!k.t.deleted.includes("snap-node2-0"));
  assert(!k.t.deleted.includes("run-osUpdate-node2-1"));
});

Deno.test("clearRetired: the host argument limits the run to one retired host", async () => {
  const { t } = await clearRetired(RETIRED_FLEET, retiredData(), {
    dryRun: false,
    host: "old1",
  });
  assertEquals([...t.deleted].sort(), ["old1", "run-osUpdate-old1-1"]);
  const rec = t.one("prune") as PruneRecord;
  assertEquals(rec.pruned.every((p) => p.host === "old1"), true);
});

Deno.test("clearRetired: node and node2 never match each other", async () => {
  // node2 is current, node is retired.
  const fleet = { sshModel: "ssh", machines: [{ host: "node2" }] };
  const { t } = await clearRetired(fleet, retiredData(), {
    dryRun: false,
    host: "node",
  });
  assertEquals(
    [...t.deleted].sort(),
    ["node", "os-update-node", "run-osUpdate-node-1", "update-node"],
  );
  // The active snapshot of node is kept, the records of node2 are untouched.
  assertEquals(
    names((t.one("prune") as PruneRecord).kept),
    ["snap-node-1"],
  );
  // And the other way: node current, node2 named explicitly.
  const other = await clearRetired(RETIRED_FLEET, retiredData(), {
    dryRun: false,
    host: "node2",
  });
  assert(!other.t.deleted.includes("node"));
  assert(!other.t.deleted.includes("old1"));
});

Deno.test("clearRetired: a host that is in the fleet is an error and deletes nothing", async () => {
  const t = mkCtx(RETIRED_FLEET, { data: retiredData() });
  await assertRejects(
    () =>
      model.methods.clearRetired.execute(
        model.methods.clearRetired.arguments.parse({
          host: "node",
          dryRun: false,
        }),
        t.ctx,
      ),
    Error,
    "is in globalArguments.machines",
  );
  assertEquals(t.deleted, []);
  assertEquals(t.written("prune"), []);
});

Deno.test("clearRetired: a host with no stored records is an error and deletes nothing", async () => {
  const t = mkCtx(RETIRED_FLEET, { data: retiredData() });
  await assertRejects(
    () =>
      model.methods.clearRetired.execute(
        model.methods.clearRetired.arguments.parse({
          host: "ghost",
          dryRun: false,
        }),
        t.ctx,
      ),
    Error,
    'No stored records for host "ghost"',
  );
  assertEquals(t.deleted, []);
  assertEquals(t.written("prune"), []);
});

Deno.test("clearRetired: an empty fleet is refused, so no host looks retired by mistake", async () => {
  const t = mkCtx({ sshModel: "ssh", machines: [] }, { data: retiredData() });
  await assertRejects(
    () =>
      model.methods.clearRetired.execute(
        model.methods.clearRetired.arguments.parse({ dryRun: false }),
        t.ctx,
      ),
    Error,
    "machines is empty",
  );
  assertEquals(t.deleted, []);
});

Deno.test("clearRetired: a record that cannot be deleted is kept and reported", async () => {
  const { t } = await clearRetired(
    RETIRED_FLEET,
    retiredData(),
    { dryRun: false, host: "old1" },
    { deleteFails: ["old1"] },
  );
  assertEquals(t.deleted, ["run-osUpdate-old1-1"]);
  const rec = t.one("prune") as PruneRecord;
  assertEquals(names(rec.pruned), ["run-osUpdate-old1-1"]);
  assertStringIncludes(rec.kept[0].reason, "delete failed");
});

Deno.test("clearRetired: nothing retired gives an empty prune record", async () => {
  const data = { inventory: [hostDatum("node", { hostname: "node" })] };
  const { t } = await clearRetired(RETIRED_FLEET, data, { dryRun: false });
  assertEquals(t.deleted, []);
  const rec = t.one("prune") as PruneRecord;
  assertEquals(rec.pruned, []);
  assertEquals(rec.kept, []);
});

Deno.test("clearRetired: logs entry, one line per host, a warning per kept active record and completion", async () => {
  const { t } = await clearRetired(RETIRED_FLEET, retiredData(), {});
  const info = JSON.stringify(t.getLogsByLevel("info"));
  assertStringIncludes(info, "Clearing retired machines");
  assertStringIncludes(info, "Retired host");
  assertStringIncludes(info, "Retired machines:");
  assertEquals(t.getLogsByLevel("warning").length, 2);
});

Deno.test("recordHost: inventory by exact name, other records by their host field only", () => {
  assertEquals(fleet.recordHost("inventory", "node2", {}), "node2");
  assertEquals(fleet.recordHost("run", "run-osUpdate-node2-1", { host: "node" }), "node");
  assertEquals(fleet.recordHost("run", "run-osUpdate-node2-1", {}), null);
  assertEquals(fleet.recordHost("snapshot", "snap-node2-1", { host: "" }), null);
});

// --- records written before a model rename (old `modelName` tag) -------------------

/** A datum written when the model had another name. readModelData would not find it. */
const old = (d: ModelDatum): ModelDatum => ({ ...d, modelName: "old-fleet" });

Deno.test("own data: clearRetired finds records tagged with an old model name", async () => {
  const data = retiredData();
  for (const rows of Object.values(data)) rows.forEach((r) => r.modelName = "old-fleet");
  const { t } = await clearRetired(RETIRED_FLEET, data, { dryRun: false });
  assertEquals(t.deleted.length, 9);
  assert(t.deleted.includes("node2"));
  assert(t.deleted.includes("old1"));
});

Deno.test("own data: pruneSnapshots finds a snapshot record tagged with an old model name", async () => {
  await withFake({ FAKE_SWAMP_SCRIPT_1: HEALTHY_NOW }, async () => {
    const t = mkCtx(FLEET, { data: { snapshot: [old(snapDatum("s-1"))] } });
    await model.methods.pruneSnapshots.execute(
      model.methods.pruneSnapshots.arguments.parse({}),
      t.ctx,
    );
    assertEquals(t.one("prune").pruned, [
      { host: "web1", name: "preupdate-1", detail: "vmid:100" },
    ]);
    assertEquals(t.one("snapshot").status, "pruned");
  });
});

Deno.test("own data: pruneImages finds an image record tagged with an old model name", async () => {
  await withFake({ FAKE_SWAMP_EXEC: execOut("24.0.7", 0) }, async () => {
    const t = mkCtx(FLEET, { data: { image: [old(imageDatum("i-1"))] } });
    await model.methods.pruneImages.execute(
      model.methods.pruneImages.arguments.parse({}),
      t.ctx,
    );
    assertEquals((t.one("prune").pruned as unknown[]).length, 1);
    assertEquals(t.one("image").status, "pruned");
  });
});

Deno.test("own data: rollback finds a snapshot record tagged with an old model name", async () => {
  const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] }, {
    data: { snapshot: [old(snapDatum("snap-web1-1", { name: "first" }))] },
  });
  await model.methods.rollback.execute(
    model.methods.rollback.arguments.parse({ host: "web1" }),
    t.ctx,
  );
  assertEquals(t.one("run").snapshot, "first");
});

Deno.test("own data: reboot confirms a snapshot record tagged with an old model name", async () => {
  await withFake(
    {
      FAKE_SWAMP_EXEC: execOut("", 0),
      FAKE_SWAMP_SCRIPT_1: scriptOut("pve", collectorStdout({ needsReboot: false })),
    },
    async () => {
      const t = mkCtx(
        {
          sshModel: "ssh",
          machines: [{ host: "ct1", ct: { proxmoxNode: "pve", ctid: 200 } }],
        },
        {
          data: {
            snapshot: [old(snapDatum("snap-ct1-1", { host: "ct1", name: "pre" }))],
          },
        },
      );
      await model.methods.reboot.execute(
        model.methods.reboot.arguments.parse({
          host: "ct1",
          force: true,
          waitTimeoutSec: 20,
        }),
        t.ctx,
      );
      assertEquals(t.one("reboot").outcome, "rebooted");
      const snap = t.one("snapshot");
      assertEquals(snap.rebootConfirmed, true);
      assertEquals(t.written("snapshot")[0].name, "snap-ct1-1");
    },
  );
});

Deno.test("own data: readOwnRecords reads by model id, filters by specName tag, skips deleted and non-JSON records", async () => {
  const calls: string[] = [];
  const enc = (v: string) => new TextEncoder().encode(v);
  const content: Record<string, string> = {
    a: '{"x":1}',
    b: '{"x":2}',
    c: "not json",
    d: '{"x":4}',
  };
  const ctx = {
    modelType: TEST_MODEL_TYPE,
    modelId: TEST_MODEL_ID,
    dataRepository: {
      findAllForModel: (_t: unknown, id: string) => {
        calls.push(`findAllForModel ${id}`);
        return Promise.resolve<
          Array<{
            name: string;
            version: number;
            tags: Record<string, string>;
            isDeleted?: boolean;
          }>
        >([
          { name: "a", version: 3, tags: { specName: "snapshot" } },
          { name: "b", version: 1, tags: { specName: "image" } },
          { name: "c", version: 1, tags: { specName: "snapshot" } },
          { name: "d", version: 1, tags: { specName: "snapshot" }, isDeleted: true },
          { name: "e", version: 1, tags: {} },
        ]);
      },
      getContent: (_t: unknown, _id: string, name: string, version?: number) => {
        calls.push(`getContent ${name} v${version}`);
        return Promise.resolve(content[name] ? enc(content[name]) : null);
      },
    },
  };
  const rows = await fleet.readOwnRecords(ctx, "snapshot");
  assertEquals(rows.map((r) => [r.name, r.attributes]), [["a", { x: 1 }]]);
  assertEquals(rows[0].isLatest, true);
  assertEquals(calls, [
    `findAllForModel ${TEST_MODEL_ID}`,
    "getContent a v3",
    "getContent c v1",
  ]);
  const both = await fleet.readOwnRecords(ctx, ["snapshot", "image"]);
  assertEquals(both.map((r) => r.name), ["a", "b"]);
});
