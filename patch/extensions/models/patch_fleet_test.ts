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
import { authorizedKeysLine, PATHS } from "./lib/access_artifacts.ts";
import {
  PRIV_COMMANDS,
  runtimeCommand,
  shellPaths,
} from "./lib/access_sudoers.ts";

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

/** `unsafe` of a CT that is reached through pct: a valid unsafe.pctExec record. */
const PCT_OK = {
  pctExec: {
    reason: "Legacy CT without sshd, reviewed by ops",
    acceptedBy: "dmc",
    acceptedAt: "2026-10-29",
    reviewBy: "2027-04-29",
  },
};

/** `unsafe` of a machine with privileged health checks: a valid unsafe.privilegedHealth record. */
const PRIV_HEALTH_OK = {
  privilegedHealth: {
    reason: "Health probe needs root, reviewed by ops",
    acceptedBy: "dmc",
    acceptedAt: "2026-10-29",
    reviewBy: "2027-04-29",
  },
};

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
  imageId: `sha256:${"0123456789abcdef".repeat(4)}`,
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
    privileged: false,
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
  // The name goes into a shell command: only unit and service name characters.
  for (const name of ["nginx; reboot", "a b", "$(id)", "x'y"]) {
    assertThrows(() =>
      parseMachine({ host: "h", health: [{ type: "service", name }] })
    );
  }
  parseMachine({
    host: "h",
    health: [{ type: "service", name: "getty@tty1.service" }],
  });
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
  // An empty updater model is still rejected (model is required, min(1)) ...
  assertThrows(() =>
    parseMachine({ host: "c", source: { type: "community-script", model: "" } })
  );
  assertThrows(() => parseMachine({ host: "c", source: { model: "" } }));
  assertThrows(() => parseMachine({ host: "c", reach: "winrm" }));
  assertThrows(() =>
    parseMachine({ host: "v", vm: { proxmoxNode: "pve", vmid: "100" } })
  );
  assertThrows(() => parseMachine({ host: "" }));
  assertThrows(() => parseMachine({}));
});

Deno.test("schema: source is pluggable — any updater type/model is accepted, type optional", () => {
  // A non-community-script updater is valid; `source.model` is reached by name.
  const a = parseMachine({
    host: "c",
    source: { type: "swamp-binary", model: "serve-updater" },
  });
  assertEquals(a.source?.model, "serve-updater");
  // `type` is an optional documentation label.
  const b = parseMachine({ host: "c", source: { model: "any-updater" } });
  assertEquals(b.source?.model, "any-updater");
  assertEquals(b.source?.type, undefined);
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
  // Any source.model is honoured regardless of type (pluggable updater).
  assertEquals(
    fleet.appSource({ host: "a", source: { type: "other", model: "m" } }),
    "m",
  );
  // ...and with no type label at all.
  assertEquals(fleet.appSource({ host: "a", source: { model: "m2" } }), "m2");
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

Deno.test("runScriptOutcome: a record's stderr is kept, and a record without one gets none", async () => {
  const s = stubSwamp([{
    ok: false,
    error: "script failed on 1/2 host(s): a (exit 255)",
    artifacts: [
      {
        host: "a",
        stdout: "",
        exitCode: 255,
        stderr: "u@a: Permission denied (publickey).\r\n",
      },
      { host: "b", stdout: "ok", exitCode: 0 },
    ],
  }]);
  const res = await fleet.runScriptOutcome("ssh", ["a", "b"], "true", 5, s.api);
  assertEquals(res.runs, [
    {
      host: "a",
      stdout: "",
      exitCode: 255,
      stderr: "u@a: Permission denied (publickey).\r\n",
    },
    { host: "b", stdout: "ok", exitCode: 0 },
  ]);
});

Deno.test("probeOutcome: a failed probe's error names ssh's stderr, after the stdout tail", () => {
  const kind = "patch-access-user-probe";
  // ssh refused the key: nothing on stdout, the reason only on stderr.
  assertEquals(
    fleet.probeOutcome(kind, {
      host: "a",
      stdout: "",
      exitCode: 255,
      stderr: "u@a: Permission denied (publickey).\r\n",
    }),
    {
      probe: null,
      error: "exit 255: stderr: u@a: Permission denied (publickey).",
    },
  );
  // Both streams: stdout first, then stderr.
  assertEquals(
    fleet.probeOutcome(kind, {
      host: "a",
      stdout: "partial\n",
      exitCode: 1,
      stderr: "boom\n",
    }),
    { probe: null, error: "exit 1: partial; stderr: boom" },
  );
  // No stderr, or only whitespace: the error is as before.
  assertEquals(
    fleet.probeOutcome(kind, { host: "a", stdout: "partial", exitCode: 1 }),
    { probe: null, error: "exit 1: partial" },
  );
  assertEquals(
    fleet.probeOutcome(kind, {
      host: "a",
      stdout: "",
      exitCode: 255,
      stderr: " \r\n",
    }),
    { probe: null, error: "exit 255: " },
  );
  // A long stderr keeps only its last 300 characters.
  const long = fleet.probeOutcome(kind, {
    host: "a",
    stdout: "",
    exitCode: 255,
    stderr: "x".repeat(400) + "END",
  });
  assertEquals(long.probe, null);
  assertStringIncludes(String(long.error), "END");
  assert(String(long.error).length < 340);
  // A good probe line still wins over stderr.
  assertEquals(
    fleet.probeOutcome(kind, {
      host: "a",
      stdout: `{"_kind":"${kind}","x":1}\n`,
      exitCode: 0,
      stderr: "warning\n",
    }),
    { probe: { _kind: kind, x: 1 }, error: null },
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
    // OpenRC is read with rc-status (no root), never rc-service <name> status.
    assertStringIncludes(all[0], "rc-status -a -f ini");
    assertEquals(all[0].includes("rc-service"), false);
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
      { host: "ct1", ct: { proxmoxNode: "pve", ctid: 200 }, unsafe: PCT_OK },
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
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
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
      FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
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
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
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
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: "not json",
  }, async () => {
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
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "pve" }]),
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
        unsafe: PCT_OK,
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

Deno.test("scan: a CT without an unsafe.pctExec record is never reached through pct, even when ssh gives no inventory", async () => {
  // ssh answers with no marker. The node would answer with a section for the CT, but
  // there is no fallback to pct: the node is not called at all.
  await withCallLog({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "ct1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut("ct1", "nothing\n", 0),
    FAKE_SWAMP_PCT: scriptOut("pve", ctSection(200, collectorStdout({ hostname: "ct1" }))),
  }, async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "ct1", ct: { proxmoxNode: "pve", ctid: 200 } }],
    });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertEquals(inv.error, "no inventory (exit 0)");
    assertEquals(inv.reachMethod, null);
    assertEquals(inv.acceptedRisksUsed, []);
    const all = await calls();
    assertEquals(all.length, 1);
    assertStringIncludes(all[0], 'hosts:json=["ct1"]');
  });
});

Deno.test("scan: the scanned hosts keep their own record each", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "a" }, { name: "c" }]),
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
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "a" }, { name: "b" }, { name: "c" }]),
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
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "a" }, { name: "b" }, { name: "c" }]),
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
    {
      host: "ct1",
      reach: "pct",
      ct: { proxmoxNode: "pve", ctid: 200 },
      unsafe: PCT_OK,
    },
    {
      host: "ct2",
      reach: "pct",
      ct: { proxmoxNode: "pve", ctid: 201 },
      unsafe: PCT_OK,
    },
    {
      host: "ct3",
      reach: "pct",
      ct: { proxmoxNode: "pve2", ctid: 300 },
      unsafe: PCT_OK,
    },
  ],
};

Deno.test("scan: the pct path is grouped per node: one call per node, sections parsed per CT", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "pve" }, { name: "pve2" }]),
    FAKE_SWAMP_PCT: twoNodePct(),
  }, async () => {
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
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "pve" }, { name: "pve2" }, { name: "web1" }]),
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
    {
      host: "ct1",
      reach: "pct",
      ct: { proxmoxNode: "pve", ctid: 200 },
      health,
      unsafe: PCT_OK,
    },
    {
      host: "ct2",
      reach: "pct",
      ct: { proxmoxNode: "pve", ctid: 201 },
      health,
      unsafe: PCT_OK,
    },
    {
      host: "ct3",
      reach: "pct",
      ct: { proxmoxNode: "pve2", ctid: 300 },
      source: { type: "community-script", model: "app-ct3" },
      health,
      unsafe: PCT_OK,
    },
  ];
  await withCallLog({
    FAKE_SWAMP_MODEL_GET: sshDefinition(
      "ops",
      ["h1", "h2", "h3", "h4", "h5", "h6", "h7", "pve", "pve2"].map((name) => ({ name })),
    ),
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
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "a" }, { name: "b" }, { name: "c" }]),
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
    // ct1 is discovered only via Proxmox: a CT located by its ct block, reached over ssh.
    assertStringIncludes(yaml, "  - host: ct1   # CT 200, no ip — agent off?");
    assertEquals(yaml.includes("reach: pct"), false);
    assertStringIncludes(
      yaml,
      "# reached over ssh; to use pct instead add unsafe.pctExec (reason, acceptedBy, acceptedAt, reviewBy)",
    );
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
  await withFake({ FAKE_SWAMP_PS: execOut(""), FAKE_SWAMP_INSPECT_1: execOut("") }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "dock1", docker: { composePath: "/srv/app", service: "web" } }],
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
      FAKE_SWAMP_INSPECT_1: execOut("abc123def456|nginx:1|sha256:aaaaaaaaaaaaaaaaaaaaaaaa|running|none\n"),
      FAKE_SWAMP_INSPECT_2: execOut("abc123def456|nginx:1|sha256:bbbbbbbbbbbbbbbbbbbbbbbb|running|none\n"),
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
      FAKE_SWAMP_INSPECT_1: execOut("abc123def456|nginx:1|sha256:same|running|none\n"),
      FAKE_SWAMP_INSPECT_2: execOut("abc123def456|nginx:1|sha256:same|running|none\n"),
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
      FAKE_SWAMP_INSPECT_1: execOut("abc123def456|nginx:1|sha256:1111111111111111111111111111111111111111111111111111111111111111|running|none\n"),
      FAKE_SWAMP_INSPECT_2: execOut("abc123def456|nginx:1|sha256:2222222222222222222222222222222222222222222222222222222222222222|running|none\n"),
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
      unsafe: PCT_OK,
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

Deno.test("reboot: force reboots when needsReboot is unknown, and a CT with an unsafe.pctExec record goes through pct", async () => {
  await withFake({ FAKE_SWAMP_EXEC: execOut("", 0) }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{
        host: "ct1",
        ct: { proxmoxNode: "pve", ctid: 200 },
        unsafe: PCT_OK,
      }],
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

Deno.test("reboot: a CT without an unsafe.pctExec record reboots like a VM: systemd-run over ssh to the CT, never pct on its node", async () => {
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
    assertEquals(reboot.via, "ssh");
    assertEquals(reboot.outcome, "rebooted");
    assertStringIncludes(String(reboot.logs), "scheduling systemctl reboot");
    const execs = t.calls.filter((c) => c.method === "exec");
    assertEquals(execs.length, 1);
    const input = execs[0].arguments as { hosts?: string[]; command?: string };
    assertEquals(input.hosts, ["ct1"]);
    assertStringIncludes(String(input.command), "systemd-run");
    assert(!String(input.command).includes("pct "), String(input.command));
    // A reboot that does not wait runs no health checks: no accepted risk is used.
    assertEquals(t.one("run").acceptedRisksUsed, []);
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
    const ct = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "web1", unsafe: PCT_OK }],
    }, { data });
    await model.methods.rollback.execute(
      model.methods.rollback.arguments.parse({ host: "web1" }),
      ct.ctx,
    );
    assertEquals(ct.one("run").snapshot, "ct-snap");
    assertEquals(ct.one("run").outcome, "rolled-back");
  });
  await withFake({ FAKE_SWAMP_EXEC: execOut("", 1) }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "web1", unsafe: PCT_OK }],
    }, { data });
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

Deno.test("rollback: a machine that is still booting gets the health grace window", async () => {
  // The restored machine answers 503 twice (services still starting), then 200.
  const data = {
    snapshot: [
      snapDatum("snap-web1-1", {
        name: "first",
        createdAt: "2026-01-01T00:00:00Z",
      }),
    ],
  };
  const booting = startServer((n) => (n <= 2 ? 503 : 200));
  try {
    await withFastPolling(async () => {
      const t = mkCtx({
        sshModel: "ssh",
        machines: [{
          host: "web1",
          health: [{ type: "http", url: booting.url }],
        }],
      }, { data });
      await model.methods.rollback.execute(
        model.methods.rollback.arguments.parse({
          host: "web1",
          healthGraceSec: 30,
        }),
        t.ctx,
      );
      assertEquals(t.one("run").outcome, "rolled-back");
      assertEquals(booting.requests(), 3);
    });
  } finally {
    await booting.stop();
  }
  // With no grace window the same machine reads unhealthy after one check.
  const once = startServer((n) => (n <= 2 ? 503 : 200));
  try {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "web1", health: [{ type: "http", url: once.url }] }],
    }, { data });
    await model.methods.rollback.execute(
      model.methods.rollback.arguments.parse({
        host: "web1",
        healthGraceSec: 0,
      }),
      t.ctx,
    );
    assertEquals(t.one("run").outcome, "unhealthy");
    assertEquals(once.requests(), 1);
  } finally {
    await once.stop();
  }
  // A machine that never recovers is still reported unhealthy after the window.
  const down = startServer(() => 503);
  try {
    await withFastPolling(async () => {
      const t = mkCtx({
        sshModel: "ssh",
        machines: [{ host: "web1", health: [{ type: "http", url: down.url }] }],
      }, { data });
      await model.methods.rollback.execute(
        model.methods.rollback.arguments.parse({
          host: "web1",
          healthGraceSec: 1,
        }),
        t.ctx,
      );
      assertEquals(t.one("run").outcome, "unhealthy");
      assertEquals(down.requests() > 1, true);
    });
  } finally {
    await down.stop();
  }
});

Deno.test("rollback: a pct snapshot is refused without the machine's unsafe.pctExec record, before any call", async () => {
  const data = {
    snapshot: [
      snapDatum("snap-web1-2", {
        name: "ct-snap",
        kind: "ct",
        vmid: 200,
        createdAt: "2026-02-01T00:00:00Z",
      }),
    ],
  };
  await withCallLog({ FAKE_SWAMP_EXEC: execOut("", 0) }, async (calls) => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] }, { data });
    const err = await assertRejects(() =>
      model.methods.rollback.execute(
        model.methods.rollback.arguments.parse({ host: "web1" }),
        t.ctx,
      )
    );
    assertStringIncludes((err as Error).message, "rollback of web1 refused");
    assertStringIncludes((err as Error).message, "unsafe.pctExec");
    assertEquals(await calls(), []);
    assertEquals(t.written("run").length, 0);
  });
});

// --- pruneSnapshots (snapshot retention / prune selection) -------------------

const FLEET = { sshModel: "ssh", machines: [{ host: "web1" }] };
// The fleet of the pruneImages tests: the images belong to two docker hosts, each with a compose project.
const PRUNE_FLEET = {
  sshModel: "ssh",
  machines: [
    { host: "dock1", docker: { composePath: "/srv/app", service: "web" } },
    { host: "dock2", docker: { composePath: "/srv/redis" } },
  ],
};
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
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "web1", unsafe: PCT_OK }],
    }, {
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

Deno.test("pruneSnapshots: a CT snapshot is kept, and pct is not run, without the machine's unsafe.pctExec record", async () => {
  await withCallLog({
    FAKE_SWAMP_SCRIPT_1: HEALTHY_NOW,
    FAKE_SWAMP_EXEC: execOut("", 0),
  }, async (calls) => {
    const t = mkCtx(FLEET, {
      data: { snapshot: [snapDatum("s-ct", { kind: "ct", vmid: 200 })] },
    });
    await model.methods.pruneSnapshots.execute(
      model.methods.pruneSnapshots.arguments.parse({}),
      t.ctx,
    );
    assertEquals(t.one("prune").pruned, []);
    const kept = t.one("prune").kept as Array<{ reason: string }>;
    assertEquals(kept.length, 1);
    assertStringIncludes(kept[0].reason, "unsafe.pctExec");
    assertEquals((await calls()).filter((c) => c.includes("pct delsnapshot")), []);
    assertEquals(t.written("snapshot").length, 0);
  });
});

Deno.test("pruneSnapshots: the live gate of a CT scans it with pct on its node, not ssh to the CT", async () => {
  await withCallLog({
    FAKE_SWAMP_SCRIPT_1: scriptOut("node1", collectorStdout({ needsReboot: false })),
    FAKE_SWAMP_EXEC: execOut("", 0),
  }, async (calls) => {
    const fleetCt = {
      sshModel: "ssh",
      machines: [{
        host: "ct1",
        ct: { proxmoxNode: "node1", ctid: 200 },
        unsafe: PCT_OK,
      }],
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
  const t = mkCtx(PRUNE_FLEET, {
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
    const t = mkCtx(PRUNE_FLEET, { data: { image: [imageDatum("i-1")] } });
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
    const dry = mkCtx(PRUNE_FLEET, { data: { image: [imageDatum("i-1")] } });
    await model.methods.pruneImages.execute(
      model.methods.pruneImages.arguments.parse({ dryRun: true }),
      dry.ctx,
    );
    assertEquals(dry.one("prune").dryRun, true);
    assertEquals(dry.one("prune").pruned, [
      { host: "dock1", name: "nginx:1", detail: "sha256:0123456789ab" },
    ]);
    assertEquals(dry.written("image"), []);

    const live = mkCtx(PRUNE_FLEET, { data: { image: [imageDatum("i-1")] } });
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
    const t = mkCtx(PRUNE_FLEET, {
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
  "renderAccess",
  "provisionAccess",
  "revokeAccess",
  "auditAccess",
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
    { host: "ct1", ct: { proxmoxNode: "pve", ctid: 101 }, unsafe: PCT_OK },
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

Deno.test("snapshot-target-resolves: a CT reached over ssh with no snapshotter and no unsafe.pctExec record fails without a call", async () => {
  await withCallLog({ FAKE_SWAMP_EXEC: execOut("", 0) }, async (calls) => {
    const fleet = {
      sshModel: "ssh",
      machines: [{ host: "ct2", ct: { proxmoxNode: "pve", ctid: 102 } }],
    };
    for (const method of ["safeOsUpdate", "pruneSnapshots", "rollback"]) {
      const r = await runCheck(
        "snapshot-target-resolves",
        checkCtx(fleet, method, { host: "ct2" }),
      );
      assertEquals(r.pass, false, method);
      assertStringIncludes(String(r.errors?.[0]), "unsafe.pctExec");
    }
    assertEquals(await calls(), []);
  });
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
    const t = mkCtx(PRUNE_FLEET, { data: { image: [old(imageDatum("i-1"))] } });
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

// --- pluggable snapshotter ------------------------------------------------------
// Snapshot, rollback and cleanup are one contract. The built-in proxmox-vm / proxmox-ct
// snapshotters are covered by the safeOsUpdate / rollback / pruneSnapshots tests above
// (they pin the exact Proxmox calls). These cover the selection rules and the pluggable
// `snapshotter` model.

/** A record of a snapshot taken by the snapshotter model "zfs". */
const MODEL_SNAP = {
  kind: "model",
  vmid: null,
  proxmoxNode: null,
  snapshotter: { kind: "model", model: "zfs" },
};

Deno.test("schema: a machine takes a snapshotter decoration; its model must be non-empty", () => {
  const m = parseMachine({ host: "b", snapshotter: { model: "zfs" } });
  assertEquals(m.snapshotter?.model, "zfs");
  assertThrows(() => parseMachine({ host: "b", snapshotter: { model: "" } }));
});

Deno.test("snapshotterRefFor: an explicit snapshotter wins, then vm, then a CT location, else none", () => {
  const vm = { proxmoxNode: "pve", vmid: 100 };
  assertEquals(
    fleet.snapshotterRefFor({ host: "a", vm, snapshotter: { model: "zfs" } }),
    { kind: "model", model: "zfs" },
  );
  assertEquals(fleet.snapshotterRefFor({ host: "a", vm }), {
    kind: "proxmox-vm",
    node: "pve",
    vmid: 100,
  });
  assertEquals(
    fleet.snapshotterRefFor({ host: "a" }, { node: "pve", ctid: 200 }),
    { kind: "proxmox-ct", node: "pve", ctid: 200 },
  );
  assertEquals(fleet.snapshotterRefFor({ host: "a" }), null);
});

Deno.test("snapshotterRefFromRecord: a recorded snapshotter wins; older vm/ct records map from their fields", () => {
  const rec = (over: Record<string, unknown>) =>
    model.resources.snapshot.schema.parse({ ...SNAPSHOT, ...over });
  assertEquals(fleet.snapshotterRefFromRecord(rec(MODEL_SNAP)), {
    kind: "model",
    model: "zfs",
  });
  assertEquals(fleet.snapshotterRefFromRecord(rec({})), {
    kind: "proxmox-vm",
    node: "pve",
    vmid: 100,
  });
  assertEquals(
    fleet.snapshotterRefFromRecord(
      rec({ kind: "ct", vmid: 200, proxmoxNode: "node1" }),
    ),
    { kind: "proxmox-ct", node: "node1", ctid: 200 },
  );
  // A model record that lost its snapshotter names nothing to dispatch to.
  assertThrows(() =>
    fleet.snapshotterRefFromRecord(
      rec({ kind: "model", vmid: null, proxmoxNode: null }),
    )
  );
});

Deno.test("snapshotRecordLocation: every snapshotter writes a valid record that leads back to it", () => {
  for (
    const ref of [
      { kind: "proxmox-vm" as const, node: "pve", vmid: 100 },
      { kind: "proxmox-ct" as const, node: "pve", ctid: 200 },
      { kind: "model" as const, model: "zfs" },
    ]
  ) {
    const a = model.resources.snapshot.schema.parse({
      ...SNAPSHOT,
      ...fleet.snapshotRecordLocation(ref),
    });
    assertEquals(fleet.snapshotterRefFromRecord(a), ref);
  }
  // Proxmox records keep the plain location fields.
  assertEquals(
    fleet.snapshotRecordLocation({ kind: "proxmox-ct", node: "pve", ctid: 200 }),
    {
      kind: "ct",
      vmid: 200,
      proxmoxNode: "pve",
      snapshotter: { kind: "proxmox-ct", node: "pve", ctid: 200 },
    },
  );
});

Deno.test("snapshotterFor(model): drives the snapshotter contract by name with { host, name }", async () => {
  const s = stubSwamp([
    { ok: true },
    { ok: true },
    { ok: true },
    {
      ok: true,
      artifacts: [{
        snapshots: [{ name: "preupdate-1" }, { name: "current" }],
      }],
    },
  ]);
  const snapper = fleet.snapshotterFor(
    { kind: "model", model: "zfs" },
    { sshModel: "ssh", swamp: s.api, host: "web1" },
  );
  assertEquals(await snapper.snapshot("preupdate-1"), true);
  assertEquals(await snapper.rollback("preupdate-1"), true);
  assertEquals(await snapper.delete("preupdate-1"), true);
  assertEquals(await snapper.list(), ["preupdate-1"]);
  const args = { host: "web1", name: "preupdate-1" };
  assertEquals(s.calls, [
    { model: "zfs", method: "snapshot", args },
    { model: "zfs", method: "rollback", args },
    { model: "zfs", method: "deleteSnapshot", args },
    { model: "zfs", method: "listSnapshots", args: { host: "web1" } },
  ]);
  assertStringIncludes(snapper.where, 'snapshotter model "zfs"');
});

Deno.test("snapshotterFor(model): a failed run is false and warned; a failed list throws", async () => {
  const s = stubSwamp([{ ok: false, error: "pool is full" }]);
  const l = collectLogger();
  const snapper = fleet.snapshotterFor(
    { kind: "model", model: "zfs" },
    { sshModel: "ssh", swamp: s.api, host: "web1", logger: l.logger },
  );
  assertEquals(await snapper.snapshot("p"), false);
  assertStringIncludes(JSON.stringify(l.lines), "pool is full");
  await assertRejects(() => snapper.list(), Error, "pool is full");
});

Deno.test("snapshotterFor(proxmox-vm): issues snapshotVm / rollbackVm / deleteVmSnapshot on the node model", async () => {
  const s = stubSwamp([{ ok: true }]);
  const snapper = fleet.snapshotterFor(
    { kind: "proxmox-vm", node: "pve", vmid: 100 },
    { sshModel: "ssh", swamp: s.api, host: "web1" },
  );
  await snapper.snapshot("p");
  await snapper.rollback("p");
  await snapper.delete("p");
  assertEquals(s.calls.map((c) => [c.model, c.method, c.args]), [
    ["pve", "snapshotVm", { vmid: 100, name: "p" }],
    ["pve", "rollbackVm", { vmid: 100, name: "p" }],
    ["pve", "deleteVmSnapshot", { vmid: 100, name: "p" }],
  ]);
});

Deno.test("safeOsUpdate: a snapshotter guards bare metal — the model takes the snapshot and the record names it", async () => {
  const server = startServer(() => 200);
  try {
    await withCallLog(osUpdateEnv(), async (calls) => {
      const t = mkCtx({
        sshModel: "ssh",
        machines: [{
          host: "web1",
          snapshotter: { model: "zfs" },
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
      const all = await calls();
      const taken = all.filter((c) => c.startsWith("zfs snapshot "));
      assertEquals(taken.length, 1);
      assertStringIncludes(taken[0], "--input host=web1");
      assertStringIncludes(taken[0], "--input name=preupdate-");
      assertEquals(
        all.some((c) => c.includes(" snapshotVm ") || c.includes("pct snapshot")),
        false,
      );
      const os = t.one("osUpdate");
      assertEquals(os.kind, "bare-metal");
      assertEquals(os.snapshotKept, true);
      assertEquals(os.rolledBack, false);
      const rec = t.one("snapshot");
      assertEquals(rec.kind, "model");
      assertEquals(rec.vmid, null);
      assertEquals(rec.snapshotter, { kind: "model", model: "zfs" });
    });
  } finally {
    await server.stop();
  }
});

Deno.test("safeOsUpdate: a VM with a snapshotter is snapshotted and rolled back by the model, not the node", async () => {
  const server = startServer(() => 503);
  try {
    await withCallLog(osUpdateEnv(), async (calls) => {
      const t = mkCtx({
        sshModel: "ssh",
        machines: [{
          host: "web1",
          vm: { proxmoxNode: "pve", vmid: 100 },
          snapshotter: { model: "zfs" },
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
      const all = await calls();
      assertEquals(all.filter((c) => c.startsWith("zfs snapshot ")).length, 1);
      assertEquals(all.filter((c) => c.startsWith("zfs rollback ")).length, 1);
      assertEquals(
        all.some((c) => c.includes(" snapshotVm ") || c.includes(" rollbackVm ")),
        false,
      );
      assertEquals(t.one("osUpdate").outcome, "rolled-back");
      assertEquals(t.one("osUpdate").rolledBack, true);
    });
  } finally {
    await server.stop();
  }
});

Deno.test("safeOsUpdate: a failed snapshotter snapshot aborts the update before the upgrade", async () => {
  await withCallLog(
    { ...osUpdateEnv(), FAKE_SWAMP_SNAPSHOT_RC: "1" },
    async (calls) => {
      const t = mkCtx({
        sshModel: "ssh",
        machines: [{ host: "web1", snapshotter: { model: "zfs" } }],
      });
      await assertRejects(
        () =>
          model.methods.safeOsUpdate.execute(
            model.methods.safeOsUpdate.arguments.parse({ host: "web1" }),
            t.ctx,
          ),
        Error,
        'snapshotter model "zfs" failed to snapshot web1',
      );
      assertEquals(
        (await calls()).some((c) => c.includes("-y upgrade")),
        false,
      );
    },
  );
});

Deno.test("safeOsUpdate: a CT with a snapshotter snapshots via the model, not pct, and the app source still runs", async () => {
  const server = startServer(() => 200);
  try {
    await withCallLog(ctAppEnv(), async (calls) => {
      const base = ctAppFleet(server.url);
      const t = mkCtx({
        ...base,
        machines: [{ ...base.machines[0], snapshotter: { model: "zfs" } }],
      });
      await model.methods.safeOsUpdate.execute(
        model.methods.safeOsUpdate.arguments.parse({ host: "ct1" }),
        t.ctx,
      );
      const all = await calls();
      assertEquals(all.filter((c) => c.startsWith("zfs snapshot ")).length, 1);
      assertEquals(all.some((c) => c.includes("pct snapshot")), false);
      // One snapshot guards both: the app source is still told not to snapshot.
      assertEquals(appCalls(all).length, 1);
      assertEquals(t.one("snapshot").snapshotter, {
        kind: "model",
        model: "zfs",
      });
    });
  } finally {
    await server.stop();
  }
});

Deno.test("rollback: a snapshot is rolled back by the snapshotter that took it, from the record", async () => {
  // The machine is no longer decorated with the snapshotter; the record still names it.
  await withCallLog({}, async (calls) => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] }, {
      data: { snapshot: [snapDatum("s-m", MODEL_SNAP)] },
    });
    await model.methods.rollback.execute(
      model.methods.rollback.arguments.parse({ host: "web1" }),
      t.ctx,
    );
    const rb = (await calls()).filter((c) => c.startsWith("zfs rollback "));
    assertEquals(rb.length, 1);
    assertStringIncludes(rb[0], "--input host=web1");
    assertStringIncludes(rb[0], "--input name=preupdate-1");
    assertEquals(t.one("run").rolledBack, true);
  });
});

Deno.test("pruneSnapshots: a snapshotter model's snapshot is deleted by that model (deleteSnapshot)", async () => {
  await withCallLog({ FAKE_SWAMP_SCRIPT_1: HEALTHY_NOW }, async (calls) => {
    const dry = mkCtx(FLEET, {
      data: { snapshot: [snapDatum("s-m", MODEL_SNAP)] },
    });
    await model.methods.pruneSnapshots.execute(
      model.methods.pruneSnapshots.arguments.parse({ dryRun: true }),
      dry.ctx,
    );
    assertEquals(dry.one("prune").pruned, [
      { host: "web1", name: "preupdate-1", detail: "model:zfs" },
    ]);

    const t = mkCtx(FLEET, {
      data: { snapshot: [snapDatum("s-m", MODEL_SNAP)] },
    });
    await model.methods.pruneSnapshots.execute(
      model.methods.pruneSnapshots.arguments.parse({}),
      t.ctx,
    );
    const del = (await calls()).filter((c) =>
      c.startsWith("zfs deleteSnapshot ")
    );
    assertEquals(del.length, 1);
    assertStringIncludes(del[0], "--input name=preupdate-1");
    assertEquals(t.one("prune").pruned, [
      { host: "web1", name: "preupdate-1", detail: "model:zfs" },
    ]);
    assertEquals(t.one("snapshot").status, "pruned");
  });
});

// --- safeOsUpdate outcome: the CT path decides exactly like the VM / bare path -----
// Health first: unhealthy + snapshot + rollbackOnFailure → rolled-back; unhealthy
// otherwise → failed; healthy but the upgrade failed → failed; healthy → updated.

/** A plain CT (no app source) with one http health check. */
function plainCtFleet(healthUrl: string) {
  return {
    sshModel: "ssh",
    machines: [{
      host: "ct1",
      ct: { proxmoxNode: "pve", ctid: 200 },
      health: [{ type: "http", label: "app", url: healthUrl }],
      unsafe: PCT_OK,
    }],
  };
}

/**
 * Run safeOsUpdate on the plain CT against a health server answering `status`.
 * The CT path's script calls alternate _1/_2: before-scan, package list, upgrade,
 * after-scan, package list. So _1 carries the upgrade's exit code (`upgradeRc`) and
 * _2 the after-scan (`after`; pass a marker-less stdout to make the rescan fail).
 */
async function ctOutcome(
  status: number,
  args: Record<string, unknown> = {},
  opts: { upgradeRc?: number; after?: string } = {},
) {
  const server = startServer(() => status);
  try {
    return await withCallLog({
      FAKE_SWAMP_SCRIPT_1: scriptOut(
        "pve",
        collectorStdout(),
        opts.upgradeRc ?? 0,
      ),
      FAKE_SWAMP_SCRIPT_2: scriptOut(
        "pve",
        opts.after ?? collectorStdout({ updatesCount: 0 }),
      ),
      FAKE_SWAMP_EXEC: execOut(""),
    }, async (calls) => {
      const t = mkCtx(plainCtFleet(server.url));
      await model.methods.safeOsUpdate.execute(
        model.methods.safeOsUpdate.arguments.parse({
          host: "ct1",
          healthGraceSec: 0,
          ...args,
        }),
        t.ctx,
      );
      const all = await calls();
      const snaps = t.written("snapshot");
      return {
        os: t.one("osUpdate"),
        snapshotRecords: snaps.length,
        snap: (snaps[0]?.data ?? {}) as Record<string, unknown>,
        rollbacks: all.filter((c) => c.includes("pct rollback 200 preupdate-")),
      };
    });
  } finally {
    await server.stop();
  }
}

Deno.test("safeOsUpdate CT: healthy after the update → updated, snapshot retained and health-confirmed", async () => {
  const r = await ctOutcome(200);
  assertEquals(r.os.outcome, "updated");
  assertEquals(r.os.rolledBack, false);
  assertEquals(r.rollbacks.length, 0);
  assertEquals(r.snap.healthConfirmed, true);
  assertStringIncludes(String(r.os.logs), "healthy after (0 updates left)");
});

Deno.test("safeOsUpdate CT: unhealthy → rolled back, and the snapshot is still tracked", async () => {
  const r = await ctOutcome(503);
  assertEquals(r.os.outcome, "rolled-back");
  assertEquals(r.os.rolledBack, true);
  assertEquals(r.rollbacks.length, 1);
  // A rollback reverts to the snapshot but does not delete it: keep tracking it,
  // or it is never pruned.
  assertEquals(r.os.snapshotKept, true);
  assertEquals(r.snapshotRecords, 1);
  assertEquals(r.snap.healthConfirmed, false);
  assertEquals(r.snap.status, "active");
});

Deno.test("safeOsUpdate CT: unhealthy with rollbackOnFailure=false → failed, NOT rolled back", async () => {
  const r = await ctOutcome(503, { rollbackOnFailure: false });
  assertEquals(r.os.outcome, "failed");
  assertEquals(r.os.rolledBack, false);
  assertEquals(r.rollbacks.length, 0);
  assertStringIncludes(String(r.os.logs), "rollback disabled; snapshot retained");
  assertEquals(r.snap.healthConfirmed, false);
});

Deno.test("safeOsUpdate CT: healthy but the upgrade command failed → failed, no rollback", async () => {
  const r = await ctOutcome(200, {}, { upgradeRc: 1 });
  assertEquals(r.os.outcome, "failed");
  assertEquals(r.os.rolledBack, false);
  assertEquals(r.rollbacks.length, 0);
  assertStringIncludes(String(r.os.logs), "machine healthy, no rollback");
});

Deno.test("safeOsUpdate CT: unhealthy after a failed upgrade → rolled back (health decides first)", async () => {
  const r = await ctOutcome(503, {}, { upgradeRc: 1 });
  assertEquals(r.os.outcome, "rolled-back");
  assertEquals(r.rollbacks.length, 1);
});

Deno.test("safeOsUpdate CT: healthy while the rescan fails does not crash", async () => {
  const r = await ctOutcome(200, {}, { after: "no inventory here" });
  assertEquals(r.os.healthyAfter, true);
  assertEquals(r.os.rolledBack, false);
  assertEquals(r.os.afterUpdates, null);
});

Deno.test("safeOsUpdate VM: unhealthy after a failed upgrade → rolled back (health decides first)", async () => {
  const server = startServer(() => 503);
  try {
    await withCallLog(
      { ...osUpdateEnv(), FAKE_SWAMP_EXEC: execOut("", 1) },
      async (calls) => {
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
        assertEquals(t.one("osUpdate").outcome, "rolled-back");
        assertEquals(
          (await calls()).some((c) => c.includes(" rollbackVm ")),
          true,
        );
      },
    );
  } finally {
    await server.stop();
  }
});

Deno.test("safeOsUpdate bare metal: a failed upgrade on an unguarded host does not claim a snapshot", async () => {
  const server = startServer(() => 200);
  try {
    await withFake(
      { ...osUpdateEnv(), FAKE_SWAMP_EXEC: execOut("", 1) },
      async () => {
        const t = mkCtx({
          sshModel: "ssh",
          machines: [{
            host: "web1",
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
        assertEquals(os.outcome, "failed");
        assertEquals(os.snapshotKept, false);
        assertStringIncludes(String(os.logs), "machine healthy, no rollback");
        assertEquals(String(os.logs).includes("snapshot retained"), false);
      },
    );
  } finally {
    await server.stop();
  }
});

// --- pluggable updater on every machine kind -----------------------------------

Deno.test("runSourceSafeUpdate: on an unguarded machine the updater is called with no arguments, once", async () => {
  const s = stubSwamp([{ ok: true }]);
  const l = collectLogger();
  assertEquals(
    await fleet.runSourceSafeUpdate("upd", s.api, l.logger, {
      patchOwnsSnapshot: false,
    }),
    true,
  );
  assertEquals(s.calls, [{ model: "upd", method: "safeUpdate", args: {} }]);
});

/** safeOsUpdate of `web1` over ssh with an updater; returns the updater's call lines. */
async function sshUpdaterCalls(machine: Record<string, unknown>) {
  const server = startServer(() => 200);
  try {
    return await withCallLog(osUpdateEnv(), async (calls) => {
      const t = mkCtx({
        sshModel: "ssh",
        machines: [{
          host: "web1",
          source: { type: "swamp-binary", model: "upd" },
          health: [{ type: "http", url: server.url }],
          ...machine,
        }],
      });
      await model.methods.safeOsUpdate.execute(
        model.methods.safeOsUpdate.arguments.parse({
          host: "web1",
          healthGraceSec: 0,
        }),
        t.ctx,
      );
      assertStringIncludes(String(t.one("osUpdate").logs), "app upd: ok");
      return (await calls()).filter((c) => c.startsWith("upd safeUpdate "));
    });
  } finally {
    await server.stop();
  }
}

Deno.test("safeOsUpdate: a VM's source updater runs under the VM snapshot, told snapshot:false", async () => {
  const app = await sshUpdaterCalls({ vm: { proxmoxNode: "pve", vmid: 100 } });
  assertEquals(app.length, 1);
  assertStringIncludes(app[0], "--input snapshot:json=false");
});

Deno.test("safeOsUpdate: a bare-metal source updater with a snapshotter is told snapshot:false", async () => {
  const app = await sshUpdaterCalls({ snapshotter: { model: "zfs" } });
  assertEquals(app.length, 1);
  assertStringIncludes(app[0], "--input snapshot:json=false");
});

Deno.test("safeOsUpdate: an unguarded bare-metal source updater is called with no snapshot argument", async () => {
  const app = await sshUpdaterCalls({});
  assertEquals(app.length, 1);
  assertEquals(app[0].includes("snapshot"), false);
});

Deno.test("snapshot-target-resolves: a snapshotter is checked with its listSnapshots, also on bare metal", async () => {
  const withSnapper = {
    sshModel: "ssh",
    machines: [{ host: "b", snapshotter: { model: "zfs" } }],
  };
  await withFake({ FAKE_SWAMP_SNAPLIST: snaps("preupdate-1") }, async () => {
    for (const method of ["safeOsUpdate", "pruneSnapshots", "rollback"]) {
      assertEquals(
        await runCheck(
          "snapshot-target-resolves",
          checkCtx(withSnapper, method, { host: "b" }),
        ),
        { pass: true },
      );
    }
    const r = await runCheck(
      "snapshot-target-resolves",
      checkCtx(withSnapper, "rollback", { host: "b", snapshot: "missing" }),
    );
    assertEquals(r.pass, false);
  });
  await withFake({ FAKE_SWAMP_SNAPLIST_RC: "1" }, async () => {
    const r = await runCheck(
      "snapshot-target-resolves",
      checkCtx(withSnapper, "safeOsUpdate", { host: "b" }),
    );
    assertEquals(r.pass, false);
    assertStringIncludes(r.errors!.join(" "), 'snapshotter model "zfs"');
  });
});

// --- transports -------------------------------------------------------------------
// safeOsUpdate, reboot, the health checks, prune's live gate and the host-reachable
// check reach a machine only through a Transport. The method tests above pin the calls
// each transport makes end to end; these pin the transports themselves.

/** A stub `exec` answer: stdout plus the rc sentinel line, as the ssh model returns it. */
const execAnswer = (stdout: string, rc = 0) => ({
  ok: true,
  artifacts: [{
    host: "x",
    stdout: `${stdout}\n${fleet.RC_SENTINEL}=${rc}\n`,
    exitCode: 0,
  }],
});

Deno.test("transportVia / transportFor: a CT with an unsafe.pctExec record goes through pct on its node; all else over ssh", async () => {
  const ct = { proxmoxNode: "pve", ctid: 200 };
  assertEquals(fleet.transportVia({ host: "a" }), "ssh");
  assertEquals(
    fleet.transportVia({ host: "a", vm: { proxmoxNode: "pve", vmid: 1 } }),
    "ssh",
  );
  assertEquals(fleet.transportVia({ host: "a", ct, unsafe: PCT_OK }), "pct");
  const deps = { sshModel: "ssh", swamp: stubSwamp([{ ok: true }]).api };
  const t = await fleet.transportFor({ host: "a", ct, unsafe: PCT_OK }, deps);
  assertEquals(t.via, "pct");
  assertEquals(t.ct, { node: "pve", ctid: 200 });
  assertEquals((await fleet.transportFor({ host: "a" }, deps)).via, "ssh");
});

Deno.test("pctTransport: scripts AND single commands are shipped base64 into pct exec on the node", async () => {
  const s = stubSwamp([{
    ok: true,
    artifacts: [{ host: "pve", stdout: "out", exitCode: 0 }],
  }]);
  const t = fleet.pctTransport("ct1", { node: "pve", ctid: 200 }, {
    sshModel: "ssh",
    swamp: s.api,
  });
  assertEquals(await t.script("echo hi", 60), { rc: 0, out: "out" });
  assertEquals(await t.exec("uptime", 60), { rc: 0, out: "out" });
  const shipped = (cmd: string) =>
    `pct exec 200 -- bash -c "echo '${fleet.utf8b64(cmd)}' | base64 -d | bash"`;
  assertEquals(
    s.calls.map((c) => [c.model, c.method, c.args?.hosts, c.args?.script]),
    [
      ["ssh", "script", ["pve"], shipped("echo hi")],
      ["ssh", "script", ["pve"], shipped("uptime")],
    ],
  );
});

Deno.test("pctTransport: probe needs pct status 'running'; reboot runs pct reboot on the node", async () => {
  const at = (answer: ReturnType<typeof execAnswer>) => {
    const s = stubSwamp([answer]);
    const t = fleet.pctTransport("ct1", { node: "pve", ctid: 200 }, {
      sshModel: "ssh",
      swamp: s.api,
    });
    return { s, t };
  };
  const running = at(execAnswer("status: running"));
  assertEquals(await running.t.probe(), null);
  assertEquals(running.s.calls[0].args?.hosts, ["pve"]);
  assertStringIncludes(String(running.s.calls[0].args?.command), "pct status 200");
  assertStringIncludes(
    String(await at(execAnswer("status: stopped")).t.probe()),
    'CT "ct1" (ctid 200) is not running on node "pve"',
  );
  const rb = at(execAnswer(""));
  assertEquals(await rb.t.reboot(), 0);
  assertStringIncludes(String(rb.s.calls[0].args?.command), "pct reboot 200");
  assertEquals(rb.t.rebootLabel, "pct reboot 200 on pve");
});

Deno.test("sshTransport: script uses the ssh model's script on the host; exec, probe and reboot use exec", async () => {
  const s = stubSwamp([
    { ok: true, artifacts: [{ host: "web1", stdout: "out", exitCode: 0 }] },
    execAnswer(""),
    execAnswer(""),
  ]);
  const t = fleet.sshTransport("web1", { sshModel: "ssh", swamp: s.api });
  assertEquals(await t.script("echo hi", 60), { rc: 0, out: "out" });
  assertEquals(await t.probe(), null);
  assertEquals(await t.reboot(), 0);
  assertEquals(s.calls.map((c) => [c.method, c.args?.hosts]), [
    ["script", ["web1"]],
    ["exec", ["web1"]],
    ["exec", ["web1"]],
  ]);
  assertEquals(s.calls[0].args?.script, "echo hi");
  assertStringIncludes(String(s.calls[2].args?.command), "systemd-run");
});

Deno.test("sshTransport: a host that does not answer is reported with its ssh model", async () => {
  const t = fleet.sshTransport("web1", {
    sshModel: "ssh",
    swamp: stubSwamp([execAnswer("", 255)]).api,
  });
  assertStringIncludes(
    String(await t.probe()),
    'Host "web1" did not answer over ssh (rc 255)',
  );
});

Deno.test("transport.scan: parses the collector's marker line; no marker or no answer is null", async () => {
  const ok = stubSwamp([{
    ok: true,
    artifacts: [{ host: "web1", stdout: collectorStdout(), exitCode: 0 }],
  }]);
  const inv = await fleet.sshTransport("web1", { sshModel: "ssh", swamp: ok.api })
    .scan();
  assertEquals(inv?.updatesCount, 3);
  assertEquals(ok.calls[0].args?.script, fleet.COLLECTOR_SCRIPT);
  for (
    const answer of [
      { ok: true, artifacts: [{ host: "web1", stdout: "no marker", exitCode: 0 }] },
      { ok: false, error: "link down" },
    ]
  ) {
    const t = fleet.sshTransport("web1", {
      sshModel: "ssh",
      swamp: stubSwamp([answer]).api,
    });
    assertEquals(await t.scan(), null);
  }
});

Deno.test("transport.packages: an unreadable package list is null (unknown) on both transports — never an empty list", async () => {
  const at = (answer: { ok: boolean; error?: string }) => [
    fleet.sshTransport("web1", {
      sshModel: "ssh",
      swamp: stubSwamp([answer]).api,
    }),
    fleet.pctTransport("ct1", { node: "pve", ctid: 200 }, {
      sshModel: "ssh",
      swamp: stubSwamp([answer]).api,
    }),
  ];
  // The run fails: no exception escapes, the list is unknown.
  for (const t of at({ ok: false, error: "link down" })) {
    assertEquals(await t.packages(), null);
  }
  // The command exits non-zero: also unknown, not a list parsed from its error text.
  const ssh = fleet.sshTransport("web1", {
    sshModel: "ssh",
    swamp: stubSwamp([execAnswer("dpkg-query: error", 2)]).api,
  });
  assertEquals(await ssh.packages(), null);
});

Deno.test("safeOsUpdate: an unreadable package list records NO diff, not a fake one", async () => {
  // Before-read fails, after-read works: a naive diff would list every package as added.
  await withFake(
    { ...osUpdateEnv(), FAKE_SWAMP_PKGS_1: execOut("", 1) },
    async () => {
      const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
      await model.methods.safeOsUpdate.execute(
        model.methods.safeOsUpdate.arguments.parse({
          host: "web1",
          healthGraceSec: 0,
        }),
        t.ctx,
      );
      const run = t.one("run");
      assertEquals(run.packages, null);
      assertEquals(run.packagesChanged, null);
      assertStringIncludes(
        String(t.one("osUpdate").logs),
        "package list unreadable",
      );
    },
  );
});

Deno.test("pruneSnapshots: a record that names no snapshotter is kept with the reason; the others still prune", async () => {
  await withFake({ FAKE_SWAMP_SCRIPT_1: HEALTHY_NOW }, async () => {
    const t = mkCtx(FLEET, {
      data: {
        snapshot: [
          snapDatum("s-bad", {
            name: "bad",
            kind: "model",
            vmid: null,
            proxmoxNode: null,
          }),
          snapDatum("s-ok", { name: "ok" }),
        ],
      },
    });
    await model.methods.pruneSnapshots.execute(
      model.methods.pruneSnapshots.arguments.parse({}),
      t.ctx,
    );
    const prune = t.one("prune");
    assertEquals(
      (prune.pruned as Array<{ name: string }>).map((p) => p.name),
      ["ok"],
    );
    const kept = prune.kept as Array<{ name: string; reason: string }>;
    assertEquals(kept.map((k) => k.name), ["bad"]);
    assertStringIncludes(kept[0].reason, "names no snapshotter");
  });
});

Deno.test("safeOsUpdate: the after-update package list is read BEFORE a rollback, on a VM too", async () => {
  const server = startServer(() => 503);
  try {
    await withCallLog(osUpdateEnv(), async (calls) => {
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
      const all = await calls();
      // The package reads are the `exec` calls that run the manifest. A collector script
      // (a scan, also the restored-machine scan after a rollback) names dpkg-query too.
      const lastPkgRead = all.map((c, i) =>
        c.startsWith("ssh exec ") && c.includes("dpkg-query") ? i : -1
      ).filter((i) => i >= 0).pop()!;
      const rollback = all.findIndex((c) => c.includes(" rollbackVm "));
      assert(rollback > lastPkgRead, "package diff read before the rollback");
      // So the run record still shows what the update changed.
      assert((t.one("run").packages as unknown[]).length > 0);
    });
  } finally {
    await server.stop();
  }
});

// ---------------------------------------------------------------------------
// pacman (built-in) and the pluggable OS updater
// ---------------------------------------------------------------------------

/**
 * Run the bundled collector with a PATH of only `stubs` (name → sh body) plus the
 * basic tools it needs, so no real package manager on the test machine is found.
 */
async function runCollector(
  stubs: Record<string, string>,
): Promise<Record<string, unknown>> {
  const dir = await Deno.makeTempDir();
  try {
    const tools = [
      "sed", "tr", "grep", "wc", "ls", "uname", "hostname", "date", "id",
      "head", "sort", "cat", "tail",
    ];
    for (const t of tools) {
      const out = await new Deno.Command("sh", {
        args: ["-c", `command -v ${t}`],
        stdout: "piped",
      }).output();
      const path = new TextDecoder().decode(out.stdout).trim();
      if (path) await Deno.symlink(path, `${dir}/${t}`);
    }
    for (const [name, body] of Object.entries(stubs)) {
      await Deno.writeTextFile(`${dir}/${name}`, `#!/bin/sh\n${body}\n`);
      await Deno.chmod(`${dir}/${name}`, 0o755);
    }
    await Deno.writeTextFile(`${dir}/collector.sh`, fleet.COLLECTOR_SCRIPT);
    const bash = new TextDecoder().decode(
      (await new Deno.Command("sh", {
        args: ["-c", "command -v bash"],
        stdout: "piped",
      }).output()).stdout,
    ).trim();
    const out = await new Deno.Command(bash, {
      args: [`${dir}/collector.sh`],
      env: { PATH: dir },
      clearEnv: true,
      stdout: "piped",
      stderr: "piped",
    }).output();
    const line = fleet.markerLine(
      new TextDecoder().decode(out.stdout),
      "patch-inventory",
    );
    assert(line, `no inventory line: ${new TextDecoder().decode(out.stderr)}`);
    return JSON.parse(line);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
}

const PACMAN_STUB = [
  'case "$1" in',
  "  -Qq) printf 'base\\nlinux\\nopenssl\\ncurl\\nbash\\n' ;;",
  "  -Qu) printf 'openssl 3.0.1-1 -> 3.0.2-1\\ncurl 8.0-1 -> 8.1-1 [ignored]\\n' ;;",
  "esac",
].join("\n");

Deno.test("collector (pacman): counts checkupdates' list and pacman -Qq; no security channel without arch-audit", async () => {
  const inv = await runCollector({
    pacman: PACMAN_STUB,
    checkupdates:
      "printf 'openssl 3.0.1-1 -> 3.0.2-1\\nlinux 6.9-1 -> 6.10-1\\n'",
  });
  assertEquals(inv.packageManager, "pacman");
  assertEquals(inv.updatesCount, 2);
  assertEquals(inv.totalPackages, 5);
  assertEquals(inv.securityUpdatesCount, null);
  assertEquals(inv.distUpgradeRequired, null);
});

Deno.test("collector (pacman): checkupdates exit 2 means no updates", async () => {
  const inv = await runCollector({ pacman: PACMAN_STUB, checkupdates: "exit 2" });
  assertEquals(inv.updatesCount, 0);
});

Deno.test("collector (pacman): without checkupdates it reads pacman -Qu, skipping [ignored]; arch-audit gives the security count", async () => {
  const inv = await runCollector({
    pacman: PACMAN_STUB,
    "arch-audit": "printf 'openssl\\n'",
  });
  assertEquals(inv.updatesCount, 1);
  assertEquals(inv.securityUpdatesCount, 1);
});

Deno.test("collector: pacman is detected only after apt, dnf and apk", () => {
  const s = fleet.COLLECTOR_SCRIPT;
  assert(s.indexOf("collect_apk\n") < s.indexOf("collect_pacman\n", s.indexOf("main()")));
  assertStringIncludes(s, "no supported package manager found (apt/dnf/apk/pacman)");
  // Arch's os-release has no VERSION_ID, only BUILD_ID=rolling.
  assertStringIncludes(s, 'os_version="${VERSION_ID:-${BUILD_ID:-Unknown}}"');
  // Never sync the live db without upgrading (partial-upgrade hazard).
  const code = s.split("\n").filter((l) => !l.trim().startsWith("#"));
  assert(!code.some((l) => l.includes("pacman -Sy")));
});

Deno.test("osUpgradeScript: apt honours mode; pacman runs a full -Syu non-interactively, last", () => {
  const safe = fleet.osUpgradeScript("safe");
  assertStringIncludes(
    safe,
    '$SUDO "$BIN_ENV" DEBIAN_FRONTEND=noninteractive "$BIN_APT_GET" -y upgrade',
  );
  assertStringIncludes(
    fleet.osUpgradeScript("full"),
    '"$BIN_APT_GET" -y full-upgrade',
  );
  assertStringIncludes(safe, '$SUDO "$BIN_PACMAN" -Syu --noconfirm');
  assert(safe.indexOf('"$BIN_APK" upgrade') < safe.indexOf("BIN_PACMAN"));
});

/** The privileged words a runtime script runs after $SUDO, one per command (split at && and newlines). */
function sudoLines(script: string): string[] {
  const out: string[] = [];
  for (const piece of script.split("\n").flatMap((l) => l.split(" && "))) {
    const at = piece.indexOf("$SUDO ");
    if (at >= 0) out.push(piece.slice(at + "$SUDO ".length).trim());
  }
  return out;
}

Deno.test("contract: every privileged line of the upgrade and reboot scripts is a table entry, and every entry is run", () => {
  const argvOf = (cmd: (typeof PRIV_COMMANDS)[number]) =>
    runtimeCommand(cmd, shellPaths(cmd)).join(" ");
  const emitted = new Set<string>();
  for (const mode of ["safe", "full"] as const) {
    for (const l of sudoLines(fleet.osUpgradeScript(mode))) emitted.add(l);
  }
  for (const l of sudoLines(fleet.SSH_REBOOT_CMD)) emitted.add(l);
  const table = new Set(PRIV_COMMANDS.map(argvOf));
  for (const l of emitted) {
    assert(table.has(l), `a privileged line is not a table entry: ${l}`);
  }
  for (const cmd of PRIV_COMMANDS) {
    assert(emitted.has(argvOf(cmd)), `no script runs the ${cmd.id} entry`);
  }
  assertEquals(emitted.size, PRIV_COMMANDS.length);
});

Deno.test("contract: the runtime runs each privileged binary by its resolved absolute path, never by a bare name", () => {
  for (
    const s of [
      fleet.osUpgradeScript("safe"),
      fleet.osUpgradeScript("full"),
      fleet.SSH_REBOOT_CMD,
    ]
  ) {
    assertStringIncludes(s, "abs_cmd() {");
    assertStringIncludes(s, "/*) printf '%s\\n' \"$p\" ;;");
    assertStringIncludes(s, "*) echo \"no absolute path for $1");
    for (const l of sudoLines(s)) {
      assert(/^"\$BIN_[A-Z_]+" /.test(l), `a bare name reached sudo: ${l}`);
    }
  }
  const upgrade = fleet.osUpgradeScript("safe");
  for (
    const [v, name] of [
      ["BIN_ENV", "env"],
      ["BIN_APT_GET", "apt-get"],
      ["BIN_DNF", "dnf"],
      ["BIN_APK", "apk"],
      ["BIN_PACMAN", "pacman"],
    ]
  ) {
    assertStringIncludes(upgrade, `${v}="$(abs_cmd ${name})" || exit 3`);
  }
  assertStringIncludes(
    fleet.SSH_REBOOT_CMD,
    'BIN_SYSTEMD_RUN="$(abs_cmd systemd-run)" || exit 3',
  );
});

Deno.test("osUpgradeScript: the families are checked in apt, dnf, apk, pacman order, and an unknown host exits 3", () => {
  const s = fleet.osUpgradeScript("safe");
  const at = ["command -v apt-get", "command -v dnf", "command -v apk", "command -v pacman"]
    .map((x) => s.indexOf(x));
  assert(at.every((i) => i >= 0), "every family is checked");
  assert(at[0] < at[1] && at[1] < at[2] && at[2] < at[3], "the family order");
  assertStringIncludes(s, 'else echo "no known package manager" >&2; exit 3; fi');
});

Deno.test("reboot over ssh: the table's reboot entry, with its absolute path resolved on the host", () => {
  assertStringIncludes(
    fleet.SSH_REBOOT_CMD,
    '$SUDO "$BIN_SYSTEMD_RUN" --on-active=3 --timer-property=AccuracySec=100ms systemctl reboot',
  );
  assert(!fleet.SSH_REBOOT_CMD.includes("sudo -n systemd-run"));
});

Deno.test("accessTargets: each machine's sudo flags follow its capabilities", () => {
  const { targets } = fleet.accessTargets({
    sshModel: "ssh",
    access: ACCESS,
    machines: [
      { host: "managed" },
      { host: "auto", osUpdatePolicy: "auto" },
      { host: "scan", osUpdatePolicy: "scan-only" },
      { host: "noos", os: false },
    ],
  } as never);
  const sudo = Object.fromEntries(targets.map((t) => [t.host, t.input.sudo]));
  assertEquals(sudo, {
    managed: { osUpgrade: true, reboot: true, docker: false },
    auto: { osUpgrade: false, reboot: true, docker: false },
    scan: { osUpgrade: false, reboot: false, docker: false },
    noos: { osUpgrade: false, reboot: true, docker: false },
  });
  const auto = targets.find((t) => t.host === "auto")!;
  assertEquals(auto.input.autoUpdates, "security");
});

Deno.test("PKG_MANIFEST_CMD lists pacman packages as name<TAB>version, after the others", () => {
  const cmd = fleet.PKG_MANIFEST_CMD;
  assertStringIncludes(cmd, "pacman -Q | tr ' ' '\\t'");
  assert(cmd.indexOf("dpkg-query") < cmd.indexOf("pacman -Q"));
});

Deno.test("schema: osUpdater takes a model name; an empty one is rejected", () => {
  const m = parseMachine({ host: "arch1", osUpdater: { model: "pacman-os" } });
  assertEquals(m.osUpdater, { model: "pacman-os" });
  assertThrows(() => parseMachine({ host: "arch1", osUpdater: { model: "" } }));
});

Deno.test("modelOsScan: a minimal scanOs resource becomes a full inventory record", async () => {
  const s = stubSwamp([{
    ok: true,
    artifacts: [{ updatesCount: 4, needsReboot: true, packageManager: "pacman" }],
  }]);
  const { inv, error } = await fleet.modelOsScan("pacman-os", "arch1", s.api);
  assertEquals(error, "");
  assertEquals(s.calls, [{ model: "pacman-os", method: "scanOs", args: { host: "arch1" } }]);
  assertEquals(inv!.hostname, "arch1");
  assertEquals(inv!.updatesCount, 4);
  assertEquals(inv!.needsReboot, true);
  assertEquals(inv!.packageManager, "pacman");
  assertEquals(inv!.securityUpdatesCount, null);
  assertEquals(inv!.osType, "Unknown");
  assertEquals(inv!.reachMethod, null);
  assertEquals(inv!.osUpdater, "pacman-os");
  assertEquals(inv!.error, null);
});

Deno.test("modelOsScan: a failed run or an invalid resource is an error, not an inventory", async () => {
  const failed = await fleet.modelOsScan(
    "os",
    "h",
    stubSwamp([{ ok: false, error: "no route" }]).api,
  );
  assertEquals(failed.inv, null);
  assertStringIncludes(failed.error, "no route");
  const invalid = await fleet.modelOsScan(
    "os",
    "h",
    stubSwamp([{ ok: true, artifacts: [{ updatesCount: 1 }] }]).api,
  );
  assertEquals(invalid.inv, null);
  assertStringIncludes(invalid.error, "needsReboot");
  const none = await fleet.modelOsScan("os", "h", stubSwamp([{ ok: true }]).api);
  assertEquals(none.inv, null);
});

function stubTransport(): import("./patch_fleet.ts").Transport {
  const inv = { ...INVENTORY, reachMethod: null, health: null, error: null };
  return {
    via: "ssh",
    where: "stub",
    note: "",
    notReachable: "stub down",
    script: () => Promise.resolve({ rc: 0, out: "" }),
    exec: (command) => Promise.resolve({ rc: 0, out: command }),
    scan: () => Promise.resolve(inv as never),
    packages: () => Promise.resolve(new Map([["a", "1"]])),
    probe: () => Promise.resolve(null),
    rebootLabel: "",
    reboot: () => Promise.resolve(0),
    rebootSettleMs: 0,
  };
}

Deno.test("osUpdaterFor: without an osUpdater the built-in one runs over the transport", async () => {
  const s = stubSwamp([{ ok: true }]);
  const os = fleet.osUpdaterFor({ host: "web1" }, stubTransport(), { swamp: s.api });
  assertEquals(os.model, null);
  assertEquals((await os.scan())!.packageManager, "apt");
  assertEquals((await os.upgrade("full")).out, fleet.osUpgradeScript("full"));
  assertEquals(await os.packages(), new Map([["a", "1"]]));
  assertEquals(s.calls, []);
});

Deno.test("osUpdaterFor(model): drives the OS updater contract by name with { host }", async () => {
  const s = stubSwamp([
    { ok: true },
    {
      ok: true,
      artifacts: [{ packages: [{ name: "openssl", version: "3.0.2-1" }, { name: "base" }] }],
    },
  ]);
  const os = fleet.osUpdaterFor(
    { host: "arch1", osUpdater: { model: "pacman-os" } },
    stubTransport(),
    { swamp: s.api },
  );
  assertEquals(os.model, "pacman-os");
  assertEquals((await os.upgrade("safe")).rc, 0);
  assertEquals(
    await os.packages(),
    new Map([["openssl", "3.0.2-1"], ["base", ""]]),
  );
  assertEquals(s.calls, [
    { model: "pacman-os", method: "upgradeOs", args: { host: "arch1", mode: "safe" } },
    { model: "pacman-os", method: "listPackages", args: { host: "arch1" } },
  ]);
});

Deno.test("osUpdaterFor(model): a failed upgrade is rc 1 and warned; an unreadable package list is null", async () => {
  const l = collectLogger();
  const os = fleet.osUpdaterFor(
    { host: "arch1", osUpdater: { model: "pacman-os" } },
    stubTransport(),
    { swamp: stubSwamp([{ ok: false, error: "mirror down" }]).api, logger: l.logger },
  );
  assertEquals((await os.upgrade("safe")).rc, 1);
  assertStringIncludes(JSON.stringify(l.lines), "mirror down");
  assertEquals(await os.packages(), null);
  const bad = fleet.osUpdaterFor(
    { host: "arch1", osUpdater: { model: "pacman-os" } },
    stubTransport(),
    { swamp: stubSwamp([{ ok: true, artifacts: [{ packages: [{ version: "1" }] }] }]).api },
  );
  assertEquals(await bad.packages(), null);
});

/** What the fake prints for a model method that writes one resource. */
function resourceOut(attributes: Record<string, unknown>): string {
  return JSON.stringify({ dataArtifacts: [{ attributes }] });
}

Deno.test("scan: an osUpdater machine is scanned by its model's scanOs, not by the collector", async () => {
  await withCallLog({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", collectorStdout()),
    FAKE_SWAMP_OSSCAN_1: resourceOut({
      packageManager: "pacman",
      updatesCount: 7,
      needsReboot: false,
    }),
  }, async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "web1" }, { host: "arch1", osUpdater: { model: "pacman-os" } }],
    });
    await model.methods.scan.execute({}, t.ctx);
    const all = await calls();
    const script = all.filter((c) => c.startsWith("ssh script "));
    assertEquals(script.length, 1);
    assertStringIncludes(script[0], 'hosts:json=["web1"]');
    assertEquals(all.filter((c) => c.startsWith("pacman-os scanOs ")).length, 1);
    const invs = t.written("inventory");
    const arch = invs.find((r) => r.name === "arch1")!.data;
    assertEquals(arch.updatesCount, 7);
    assertEquals(arch.packageManager, "pacman");
    assertEquals(arch.osUpdater, "pacman-os");
    assertEquals(arch.reachMethod, null);
    const web = invs.find((r) => r.name === "web1")!.data;
    assertEquals(web.osUpdater, null);
    assertEquals(web.reachMethod, "ssh");
  });
});

Deno.test("scan: a failed scanOs gives that machine an error record naming the osUpdater", async () => {
  await withFake({ FAKE_SWAMP_OSSCAN_RC: "1" }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "arch1", osUpdater: { model: "pacman-os" } }],
    });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertStringIncludes(inv.error as string, "osUpdater pacman-os");
    assertEquals(inv.osUpdater, "pacman-os");
  });
});

function osModelEnv(extra: Env = {}): Env {
  return {
    FAKE_SWAMP_OSSCAN_1: resourceOut({ packageManager: "pacman", updatesCount: 2, needsReboot: false }),
    FAKE_SWAMP_OSSCAN_2: resourceOut({ packageManager: "pacman", updatesCount: 0, needsReboot: true }),
    FAKE_SWAMP_OSPKGS_1: resourceOut({ packages: [{ name: "openssl", version: "3.0.1-1" }] }),
    FAKE_SWAMP_OSPKGS_2: resourceOut({ packages: [{ name: "openssl", version: "3.0.2-1" }] }),
    ...extra,
  };
}

Deno.test("safeOsUpdate: an osUpdater model scans, upgrades and lists packages; no built-in upgrade runs", async () => {
  await withCallLog(osModelEnv(), async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "arch1", osUpdater: { model: "pacman-os" } }],
    });
    await model.methods.safeOsUpdate.execute(
      model.methods.safeOsUpdate.arguments.parse({ host: "arch1", mode: "full" }),
      t.ctx,
    );
    const all = await calls();
    assertEquals(
      all.map((c) => c.split(" ").slice(0, 2).join(" ")),
      [
        // The guard asks the plug-in for its privileges before anything else.
        "pacman-os privileges",
        "pacman-os scanOs",
        "pacman-os listPackages",
        "pacman-os upgradeOs",
        "pacman-os scanOs",
        "pacman-os listPackages",
      ],
    );
    assertStringIncludes(all[3], "mode=full");
    assertStringIncludes(all[2], "host=arch1");
    const os = t.one("osUpdate");
    assertEquals(os.outcome, "updated");
    assertEquals(os.beforeUpdates, 2);
    assertEquals(os.afterUpdates, 0);
    assertEquals(os.needsReboot, true);
    assertStringIncludes(os.logs as string, 'via osUpdater "pacman-os"');
    assertEquals(t.one("run").packages, [
      { name: "openssl", from: "3.0.1-1", to: "3.0.2-1" },
    ]);
    const inv = t.one("inventory");
    assertEquals(inv.osUpdater, "pacman-os");
    assertEquals(inv.reachMethod, null);
  });
});

Deno.test("safeOsUpdate: a failed upgradeOs on a healthy machine is failed; a failed scanOs aborts", async () => {
  await withFake(osModelEnv({ FAKE_SWAMP_OSUPGRADE_RC: "1" }), async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "arch1", osUpdater: { model: "pacman-os" } }],
    });
    await model.methods.safeOsUpdate.execute(
      model.methods.safeOsUpdate.arguments.parse({ host: "arch1" }),
      t.ctx,
    );
    assertEquals(t.one("osUpdate").outcome, "failed");
  });
  await withFake({ FAKE_SWAMP_OSSCAN_RC: "1" }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "arch1", osUpdater: { model: "pacman-os" } }],
    });
    await assertRejects(
      () =>
        model.methods.safeOsUpdate.execute(
          model.methods.safeOsUpdate.arguments.parse({ host: "arch1" }),
          t.ctx,
        ),
      Error,
      'osUpdater "pacman-os" could not scan arch1',
    );
  });
});

Deno.test("reboot: the confirming scan goes through the osUpdater model", async () => {
  await withCallLog({
    FAKE_SWAMP_EXEC: execOut(""),
    FAKE_SWAMP_OSSCAN_1: resourceOut({ updatesCount: 0, needsReboot: false }),
  }, async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "arch1", osUpdater: { model: "pacman-os" } }],
    });
    await withFastPolling(() =>
      model.methods.reboot.execute(
        model.methods.reboot.arguments.parse({ host: "arch1", force: true }),
        t.ctx,
      )
    );
    const all = await calls();
    assert(all.some((c) => c.startsWith("ssh exec ")), "reboot over ssh");
    assert(all.some((c) => c.startsWith("pacman-os scanOs ")), "confirm via scanOs");
    assert(!all.some((c) => c.startsWith("ssh script ")), "no collector run");
    assertEquals(t.one("reboot").confirmed, true);
    assertEquals(t.one("inventory").osUpdater, "pacman-os");
  });
});

Deno.test("globalArguments: unsafe, acceptedRisks and access parse; a boolean pctExec is rejected", () => {
  const rec = {
    reason: "Pinned by ops; reviewed quarterly",
    acceptedBy: "dmc",
    acceptedAt: "2026-10-01",
    reviewBy: "2026-10-29",
  };
  const ga = model.globalArguments.parse({
    sshModel: "ssh",
    machines: [{
      host: "h1",
      unsafe: { pctExec: rec },
      acceptedRisks: [{ ...rec, finding: "host-group-docker:dmc" }],
    }],
    access: {
      publicKey:
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
      from: ["192.0.2.0/24"],
      provisionSshModel: "pve-root",
    },
  });
  assertEquals(ga.machines[0].host, "h1");
  assert(!model.globalArguments.safeParse({
    sshModel: "ssh",
    machines: [{ host: "h1", unsafe: { pctExec: true } }],
  }).success, "a boolean pctExec must be rejected");
});

Deno.test("collector: never uses root or sudo, and never refreshes the package cache", () => {
  const s = fleet.COLLECTOR_SCRIPT;
  assert(!s.includes("sudo"), "no sudo, not even in a comment");
  assert(!s.includes("apt-get update"));
  assert(!s.includes("apk update"));
  assertStringIncludes(s, '"schemaVersion":5');
  for (const key of ["cacheAgeHours", "dockerSource", "dockerFileB64"]) {
    assertStringIncludes(s, key);
  }
});

/**
 * Run collect_dnf from the bundled collector with a fake `dnf` (a sh body) and a fake
 * `rpm` first on PATH. Returns the echoed counts (stdout) and the log (stderr).
 */
async function runDnf(dnf: string): Promise<{ out: string; err: string }> {
  const dir = await Deno.makeTempDir();
  try {
    await Deno.writeTextFile(`${dir}/dnf`, `#!/bin/sh\n${dnf}\n`);
    await Deno.writeTextFile(`${dir}/rpm`, "#!/bin/sh\nexit 0\n");
    await Deno.chmod(`${dir}/dnf`, 0o755);
    await Deno.chmod(`${dir}/rpm`, 0o755);
    const body = fleet.COLLECTOR_SCRIPT.split("\n")
      .filter((l) => l !== "main </dev/null")
      .join("\n");
    const script = body +
      "\ncollect_dnf\necho \"U=$updates S=$security C=${dnf_user_cache:-0} A=$cache_age\"\n";
    const out = await new Deno.Command("bash", {
      args: ["-c", script],
      env: { PATH: `${dir}:${Deno.env.get("PATH") ?? ""}` },
      stdout: "piped",
      stderr: "piped",
    }).output();
    return {
      out: new TextDecoder().decode(out.stdout),
      err: new TextDecoder().decode(out.stderr),
    };
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
}

Deno.test("collector (dnf): a failing check-update is unknown (null), never 0", async () => {
  const r = await runDnf("exit 1");
  assertStringIncludes(r.out, "U=null S=null C=0");
  assertStringIncludes(r.err, "dnf check-update failed (rc 1)");
});

Deno.test("collector (dnf): an error on the system cache falls back to the per-user cache", async () => {
  const r = await runDnf([
    'case " $* " in *" -C "*) exit 1 ;; esac',
    "printf 'foo.x86_64  1.0-1  baseos\\nbar.noarch  2.0-1  appstream\\n'",
    "exit 100",
  ].join("\n"));
  assertStringIncludes(r.out, "U=2 S=2 C=1 A=0");
});

Deno.test("collector (dnf): no updates (rc 0) is 0, not null", async () => {
  const r = await runDnf("exit 0");
  assertStringIncludes(r.out, "U=0 S=0 C=0");
});

/** A collector stdout that reports the root-written docker file, base64 as shipped. */
function dockerFileStdout(file: unknown, over: Record<string, unknown> = {}): string {
  return collectorStdout({
    schemaVersion: 4,
    dockerSource: "file",
    dockerFileB64: btoa(JSON.stringify(file)),
    ...over,
  });
}

Deno.test("scan: a valid root-written docker file gives the images; its base64 is never stored", async () => {
  const file = {
    schemaVersion: 1,
    generatedAt: new Date(Date.now() - 2 * 3600e3).toISOString(),
    dockerEngine: "27.3.1",
    dockerImages: [{
      container: "web",
      image: "nginx:1.27",
      localDigest: "sha256:" + "a".repeat(64),
      registryDigest: "sha256:" + "b".repeat(64),
      updateAvailable: true,
    }],
  };
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", dockerFileStdout(file, { cacheAgeHours: 5 })),
  }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertEquals(inv.dockerSource, "file");
    assertEquals(inv.dockerEngine, "27.3.1");
    assertEquals(inv.dockerImages, file.dockerImages);
    assertEquals(inv.dockerFileAgeHours, 2);
    assertEquals(inv.cacheAgeHours, 5);
    assert(!("dockerFileB64" in inv), "the base64 is not a stored field");
    assert(!JSON.stringify(inv).includes(btoa(JSON.stringify(file))));
  });
});

Deno.test("scan: an invalid root-written docker file is file-invalid with no images", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", collectorStdout({
      schemaVersion: 4,
      dockerSource: "file",
      dockerFileB64: btoa("not json"),
    })),
  }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertEquals(inv.dockerSource, "file-invalid");
    assertEquals(inv.dockerImages, null);
    assertEquals(inv.dockerFileAgeHours, null);
    assert(!("dockerFileB64" in inv), "the base64 is not a stored field");
  });
});

/** One socket-sourced image item, as the collector writes it. */
function socketItem(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    container: "web",
    image: "nginx:1.27",
    localDigest: "",
    registryDigest: "",
    updateAvailable: null,
    ...over,
  };
}

Deno.test("scan: a socket docker item with a bad container name is socket-invalid with no images", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", collectorStdout({
      schemaVersion: 4,
      dockerSource: "socket",
      dockerEngine: "27.3.1",
      dockerImages: [socketItem({ container: "x|<script>" })],
    })),
  }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertEquals(inv.dockerSource, "socket-invalid");
    assertEquals(inv.dockerImages, null);
  });
});

Deno.test("scan: a good socket docker inventory is stored unchanged", async () => {
  const images = [socketItem()];
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", collectorStdout({
      schemaVersion: 4,
      dockerSource: "socket",
      dockerEngine: "27.3.1",
      dockerImages: images,
    })),
  }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertEquals(inv.dockerSource, "socket");
    assertEquals(inv.dockerEngine, "27.3.1");
    assertEquals(inv.dockerImages, images);
  });
});

// ---------------------------------------------------------------------------
// Fail closed: pct needs an unsafe.pctExec record, a root ssh login needs an
// unsafe.rootSsh record, and no machine falls back from one transport to the other.
// ---------------------------------------------------------------------------

const RECORD = {
  reason: "Reviewed by ops for this one machine",
  acceptedBy: "dmc",
  acceptedAt: "2026-10-29",
  reviewBy: "2027-04-29",
};

Deno.test("transportVia: a container without a record is ssh, with an unsafe.pctExec record pct, a VM ssh", () => {
  const ct = { proxmoxNode: "pve", ctid: 200 };
  assertEquals(fleet.transportVia({ host: "a", ct }), "ssh");
  assertEquals(
    fleet.transportVia({ host: "a", ct, unsafe: { pctExec: RECORD } }),
    "pct",
  );
  assertEquals(
    fleet.transportVia({ host: "a", vm: { proxmoxNode: "pve", vmid: 100 } }),
    "ssh",
  );
});

Deno.test("transportFor: a reach=pct machine without an unsafe.pctExec record throws the refusal, never falls back", async () => {
  const deps = { sshModel: "ssh", swamp: stubSwamp([{ ok: true }]).api };
  const m = {
    host: "ct1",
    reach: "pct" as const,
    ct: { proxmoxNode: "pve", ctid: 200 },
  };
  await assertRejects(() => fleet.transportFor(m, deps), Error, "unsafe.pctExec");
  assertStringIncludes(String(fleet.pctRefusal(m)), 'machine "ct1" asks for pct');
  assertEquals(fleet.pctRefusal({ ...m, unsafe: { pctExec: RECORD } }), null);
});

Deno.test("scan: a CT without a record whose ssh fails is stored with an ssh error and is never contacted through pct", async () => {
  await withCallLog({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "ct1" }]),
    FAKE_SWAMP_SCRIPT_1: "not json",
    FAKE_SWAMP_PCT: scriptOut("pve", ctSection(200, collectorStdout({ hostname: "ct1" }))),
  }, async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "ct1", ct: { proxmoxNode: "pve", ctid: 200 } }],
    });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertEquals(inv.error, "ssh: ssh script failed: not json");
    assertEquals(inv.reachMethod, null);
    // One ssh call for the CT itself; the node is never called.
    const all = await calls();
    assertEquals(all.length, 1);
    assertStringIncludes(all[0], 'hosts:json=["ct1"]');
  });
});

Deno.test("scan: a CT with an unsafe.pctExec record is scanned through pct and records the accepted risk it used", async () => {
  await withCallLog({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "pve" }]),
    FAKE_SWAMP_PCT: scriptOut("pve", ctSection(200, collectorStdout({ hostname: "ct1" }))),
  }, async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{
        host: "ct1",
        ct: { proxmoxNode: "pve", ctid: 200 },
        unsafe: PCT_OK,
      }],
    });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertEquals(inv.error, null);
    assertEquals(inv.reachMethod, "pct");
    assertEquals(inv.acceptedRisksUsed, ["unsafe.pctExec"]);
    const all = await calls();
    assertEquals(all.length, 1);
    assertStringIncludes(all[0], 'hosts:json=["pve"]');
  });
});

Deno.test("scan: reach=pct without an unsafe.pctExec record gets an error record with the refusal, and is not contacted", async () => {
  await withCallLog({
    FAKE_SWAMP_PCT: scriptOut("pve", ctSection(200, collectorStdout({ hostname: "ct1" }))),
    FAKE_SWAMP_SCRIPT_1: scriptOut("ct1", collectorStdout()),
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
    assertStringIncludes(String(inv.error), 'machine "ct1" asks for pct');
    assertStringIncludes(String(inv.error), "unsafe.pctExec");
    assertEquals(inv.reachMethod, null);
    assertEquals(await calls(), []);
  });
});

/** The `globalArguments` of an @swamp/ssh definition: a default login and host entries. */
function sshDefinition(
  defaultUser: string,
  hosts: Array<{ name: string; user?: string }>,
): string {
  return JSON.stringify({
    globalArguments: {
      transport: { user: defaultUser },
      hosts: hosts.map((h) => ({
        name: h.name,
        ...(h.user === undefined ? {} : { transport: { user: h.user } }),
      })),
    },
  });
}

const RT_FLEET = {
  sshModel: "ssh",
  machines: [
    { host: "web1" },
    { host: "rootbox", unsafe: { rootSsh: RECORD } },
    { host: "old", reach: "pct", ct: { proxmoxNode: "pve", ctid: 201 } },
    { host: "ct1", ct: { proxmoxNode: "pve", ctid: 200 }, unsafe: PCT_OK },
  ],
};

Deno.test("restricted-transport: an unprivileged ssh login passes", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
  }, async () => {
    assertEquals(
      await runCheck(
        "restricted-transport",
        checkCtx(RT_FLEET, "reboot", { host: "web1" }),
      ),
      { pass: true },
    );
  });
});

Deno.test("restricted-transport: a host-level root login fails and names the record to add", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1", user: "root" }]),
  }, async () => {
    const r = await runCheck(
      "restricted-transport",
      checkCtx(RT_FLEET, "reboot", { host: "web1" }),
    );
    assertEquals(r.pass, false);
    assertStringIncludes(r.errors!.join(" "), 'logs in as root through ssh');
    assertStringIncludes(r.errors!.join(" "), "unsafe.rootSsh");
    assertStringIncludes(r.errors!.join(" "), "--skip-check restricted-transport");
  });
});

Deno.test("restricted-transport: the default root login fails when the host has no override", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("root", [{ name: "web1" }]),
  }, async () => {
    const r = await runCheck(
      "restricted-transport",
      checkCtx(RT_FLEET, "safeOsUpdate", { host: "web1" }),
    );
    assertEquals(r.pass, false);
    assertStringIncludes(r.errors!.join(" "), "logs in as root");
  });
});

Deno.test("restricted-transport: a root login passes with an unsafe.rootSsh record", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("root", [{ name: "rootbox" }]),
  }, async () => {
    assertEquals(
      await runCheck(
        "restricted-transport",
        checkCtx(RT_FLEET, "safeOsUpdate", { host: "rootbox" }),
      ),
      { pass: true },
    );
  });
});

Deno.test("restricted-transport: an unreadable ssh definition or host entry fails closed", async () => {
  await withFake({ FAKE_SWAMP_GET_RC: "1" }, async () => {
    const r = await runCheck(
      "restricted-transport",
      checkCtx(RT_FLEET, "reboot", { host: "web1" }),
    );
    assertEquals(r.pass, false);
    assertStringIncludes(r.errors!.join(" "), "cannot be read");
  });
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "other" }]),
  }, async () => {
    const r = await runCheck(
      "restricted-transport",
      checkCtx(RT_FLEET, "reboot", { host: "web1" }),
    );
    assertEquals(r.pass, false);
    assertStringIncludes(r.errors!.join(" "), 'for "web1"');
  });
});

Deno.test("restricted-transport: a reach=pct machine without an unsafe.pctExec record fails", async () => {
  const r = await runCheck(
    "restricted-transport",
    checkCtx(RT_FLEET, "reboot", { host: "old" }),
  );
  assertEquals(r.pass, false);
  assertStringIncludes(r.errors!.join(" "), "unsafe.pctExec");
});

Deno.test("restricted-transport: safeUpdate always uses ssh, so only its login counts", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "old" }]),
  }, async () => {
    assertEquals(
      await runCheck(
        "restricted-transport",
        checkCtx(RT_FLEET, "safeUpdate", { host: "old" }),
      ),
      { pass: true },
    );
  });
});

Deno.test("restricted-transport: a CT with a record reads the login of its node, which is what pct runs over", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "pve" }]),
  }, async () => {
    assertEquals(
      await runCheck(
        "restricted-transport",
        checkCtx(RT_FLEET, "reboot", { host: "ct1" }),
      ),
      { pass: true },
    );
  });
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "pve", user: "root" }]),
  }, async () => {
    const r = await runCheck(
      "restricted-transport",
      checkCtx(RT_FLEET, "reboot", { host: "ct1" }),
    );
    assertEquals(r.pass, false);
    assertStringIncludes(
      r.errors!.join(" "),
      'is reached through pct on node "pve", which logs in as root through ssh',
    );
    assertStringIncludes(r.errors!.join(" "), "unsafe.rootSsh");
  });
});

// ---------------------------------------------------------------------------
// The snapshot guard does not depend on the transport: every CT the snapshot
// pre-flight treats as guarded is snapshotted (pct on its node) before the upgrade.
// ---------------------------------------------------------------------------

Deno.test("safeOsUpdate: a CT with an unsafe.pctExec record is snapshotted with pct on its node before the upgrade", async () => {
  const cases = [
    // With an unsafe.pctExec record: the container is reached through pct.
    { label: "through pct", host: "ct1", unsafe: PCT_OK },
  ];
  for (const c of cases) {
    const server = startServer(() => 200);
    try {
      await withCallLog({
        FAKE_SWAMP_SCRIPT_1: scriptOut(c.unsafe ? "pve" : "ct1", collectorStdout()),
        FAKE_SWAMP_SCRIPT_2: scriptOut(
          c.unsafe ? "pve" : "ct1",
          collectorStdout({ updatesCount: 0 }),
        ),
        FAKE_SWAMP_EXEC: execOut(""),
      }, async (calls) => {
        const t = mkCtx({
          sshModel: "ssh",
          machines: [{
            host: c.host,
            ct: { proxmoxNode: "pve", ctid: 200 },
            health: [{ type: "http", label: "app", url: server.url }],
            ...(c.unsafe ? { unsafe: c.unsafe } : {}),
          }],
        });
        await model.methods.safeOsUpdate.execute(
          model.methods.safeOsUpdate.arguments.parse({
            host: c.host,
            healthGraceSec: 0,
          }),
          t.ctx,
        );
        const all = await calls();
        const snap = all.findIndex((line) =>
          line.includes("pct snapshot 200 preupdate-")
        );
        assert(snap >= 0, `${c.label}: the CT is snapshotted with pct on its node`);
        // The upgrade runs after the snapshot: plain over ssh, base64-shipped into
        // `pct exec` through pct (so only the `pct exec 200` wrapper shows).
        assert(
          all.slice(snap + 1).some((line) =>
            line.includes("update -qq") || line.includes("pct exec 200")
          ),
          `${c.label}: an upgrade runs after the snapshot`,
        );
        assertEquals(t.one("osUpdate").kind, "ct", c.label);
        assertEquals(t.one("osUpdate").outcome, "updated", c.label);
      });
    } finally {
      await server.stop();
    }
  }
});

Deno.test("safeOsUpdate: a CT reached over ssh with no snapshotter and no unsafe.pctExec record is refused before any call", async () => {
  await withCallLog({
    FAKE_SWAMP_SCRIPT_1: scriptOut("ct1", collectorStdout()),
    FAKE_SWAMP_EXEC: execOut(""),
  }, async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "ct1", ct: { proxmoxNode: "pve", ctid: 200 } }],
    });
    const err = await assertRejects(() =>
      model.methods.safeOsUpdate.execute(
        model.methods.safeOsUpdate.arguments.parse({ host: "ct1" }),
        t.ctx,
      )
    );
    assertStringIncludes((err as Error).message, "safeOsUpdate of ct1 refused");
    assertStringIncludes((err as Error).message, "unsafe.pctExec");
    // No scan, no snapshot, no upgrade: not a single call.
    assertEquals(await calls(), []);
    assertEquals(t.written("osUpdate").length, 0);
  });
});

Deno.test("safeOsUpdate: a CT whose location cannot be resolved fails before any upgrade, and is never run unguarded", async () => {
  await withCallLog({
    FAKE_SWAMP_SCRIPT_1: scriptOut("ct1", collectorStdout()),
    FAKE_SWAMP_EXEC: execOut(""),
    FAKE_SWAMP_GET_RC: "1",
  }, async (calls) => {
    // A legacy proxmox ref whose model cannot be read: the CT has no location.
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "ct1", proxmox: { model: "gone" } }],
    });
    await assertRejects(() =>
      model.methods.safeOsUpdate.execute(
        model.methods.safeOsUpdate.arguments.parse({ host: "ct1" }),
        t.ctx,
      )
    );
    // Nothing was contacted: no scan, no snapshot, no upgrade. Only the plug-in (the
    // legacy proxmox ref is the app updater) was asked for its privileges.
    assertEquals(
      (await calls()).map((c) => c.split(" ").slice(0, 2).join(" ")),
      ["gone privileges"],
    );
    assertEquals(t.written("osUpdate").length, 0);
  });
});

// ---------------------------------------------------------------------------
// scan reads the login before any contact. A root login needs the machine's own
// unsafe.rootSsh record, an unknown login is refused, and the uid the collector
// reports is checked: uid 0 over ssh without the record is a security finding.
// ---------------------------------------------------------------------------

Deno.test("scan: a root login without an unsafe.rootSsh record is refused, and the host is not contacted", async () => {
  await withCallLog({
    FAKE_SWAMP_MODEL_GET: sshDefinition("root", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", collectorStdout()),
  }, async (calls) => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertStringIncludes(String(inv.error), 'refused: logs in as root through ssh (host "web1")');
    assertStringIncludes(String(inv.error), "unsafe.rootSsh");
    assertEquals(inv.reachMethod, null);
    assertEquals(await calls(), []);
  });
});

Deno.test("scan: an ssh login that cannot be read is refused, and so is every login when there is no definition repository", async () => {
  await withCallLog({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "other" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", collectorStdout()),
  }, async (calls) => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertStringIncludes(String(inv.error), 'refused: the ssh login for "web1" cannot be read from ssh');
    assertEquals(inv.reachMethod, null);
    assertEquals(await calls(), []);
  });
  await withCallLog({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", collectorStdout()),
  }, async (calls) => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
    await model.methods.scan.execute(
      {},
      { ...(t.ctx as object), definitionRepository: undefined } as never,
    );
    assertStringIncludes(String(t.one("inventory").error), 'refused: the ssh login for "web1"');
    assertEquals(await calls(), []);
  });
});

Deno.test("scan: a root login with an unsafe.rootSsh record is scanned, and that record is the accepted risk it used", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("root", [{ name: "rootbox" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut("rootbox", collectorStdout({ hostname: "rootbox", uid: 0 })),
  }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "rootbox", unsafe: { rootSsh: RECORD } }],
    });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertEquals(inv.error, null);
    assertEquals(inv.reachMethod, "ssh");
    assertEquals(inv.acceptedRisksUsed, ["unsafe.rootSsh"]);
    assertEquals(inv.securityFindings, []);
  });
});

Deno.test("scan: an unprivileged login is scanned with no accepted risk and no security finding", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", collectorStdout({ uid: 1000 })),
  }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertEquals(inv.error, null);
    assertEquals(inv.acceptedRisksUsed, []);
    assertEquals(inv.securityFindings, []);
  });
});

Deno.test("scan: a pct CT whose node logs in as root is refused without an unsafe.rootSsh record on the CT, and its node is not called", async () => {
  await withCallLog({
    FAKE_SWAMP_MODEL_GET: sshDefinition("root", [{ name: "pve" }]),
    FAKE_SWAMP_PCT: scriptOut("pve", ctSection(200, collectorStdout({ hostname: "ct1" }))),
  }, async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{
        host: "ct1",
        ct: { proxmoxNode: "pve", ctid: 200 },
        unsafe: PCT_OK,
      }],
    });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertStringIncludes(String(inv.error), 'refused: logs in as root through ssh (host "pve")');
    assertEquals(inv.reachMethod, null);
    assertEquals(await calls(), []);
  });
});

Deno.test("scan: on a root node, only the CTs with an unsafe.rootSsh record go into its pct batch", async () => {
  await withCallLog({
    FAKE_SWAMP_MODEL_GET: sshDefinition("root", [{ name: "pve" }]),
    FAKE_SWAMP_PCT: scriptOut("pve", ctSection(200, collectorStdout({ hostname: "ct1" }))),
  }, async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [
        {
          host: "ct1",
          ct: { proxmoxNode: "pve", ctid: 200 },
          unsafe: { ...PCT_OK, rootSsh: RECORD },
        },
        {
          host: "ct2",
          ct: { proxmoxNode: "pve", ctid: 201 },
          unsafe: PCT_OK,
        },
      ],
    });
    await model.methods.scan.execute({}, t.ctx);
    const inv = Object.fromEntries(
      t.written("inventory").map((r) => [r.name, r.data]),
    );
    assertEquals(inv.ct1.reachMethod, "pct");
    assertStringIncludes(String(inv.ct2.error), 'refused: logs in as root through ssh (host "pve")');
    const all = await calls();
    assertEquals(all.length, 1);
    assertStringIncludes(all[0], 'hosts:json=["pve"]');
    const script = String(t.calls[0].arguments?.script);
    assertStringIncludes(script, "@@PATCH-CT 200 BEGIN");
    assert(!script.includes("@@PATCH-CT 201"), "ct2 is not in the batch");
  });
});

Deno.test("scan: a pct CT whose node logs in as root is scanned through pct with both records", async () => {
  await withCallLog({
    FAKE_SWAMP_MODEL_GET: sshDefinition("root", [{ name: "pve" }]),
    FAKE_SWAMP_PCT: scriptOut("pve", ctSection(200, collectorStdout({ hostname: "ct1", uid: 0 }))),
  }, async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{
        host: "ct1",
        ct: { proxmoxNode: "pve", ctid: 200 },
        unsafe: { ...PCT_OK, rootSsh: RECORD },
      }],
    });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertEquals(inv.error, null);
    assertEquals(inv.reachMethod, "pct");
    assertEquals(inv.acceptedRisksUsed, ["unsafe.pctExec", "unsafe.rootSsh"]);
    // uid 0 is expected through pct (root in the container): no security finding.
    assertEquals(inv.securityFindings, []);
    const all = await calls();
    assertEquals(all.length, 1);
    assertStringIncludes(all[0], 'hosts:json=["pve"]');
  });
});

Deno.test("scan: uid 0 over ssh without an unsafe.rootSsh record is a root-login-unaccepted finding; uid 1000 is not", async () => {
  // The ssh config can override the definition's login, so the host reports its real uid.
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", collectorStdout({ uid: 0 })),
  }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertEquals(inv.error, null);
    assertEquals(inv.uid, 0);
    assertEquals(inv.securityFindings, ["root-login-unaccepted"]);
    assertEquals(inv.acceptedRisksUsed, []);
    assertStringIncludes(JSON.stringify(t.getLogsByLevel("warning")), "web1");
  });
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", collectorStdout({ uid: 1000 })),
  }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertEquals(inv.uid, 1000);
    assertEquals(inv.securityFindings, []);
  });
});

Deno.test("collector: prints the uid it runs as (id -u) in the marker line", async () => {
  const s = fleet.COLLECTOR_SCRIPT;
  assertStringIncludes(s, "id -u");
  assertStringIncludes(s, '"uid":');
  const real = new TextDecoder().decode(
    (await new Deno.Command("id", { args: ["-u"], stdout: "piped" }).output())
      .stdout,
  ).trim();
  const inv = await runCollector({});
  assertEquals(inv.uid, Number(real));
});

// ---------------------------------------------------------------------------
// The swamp-patch access login: renderAccess, provisionAccess, revokeAccess
// ---------------------------------------------------------------------------

const ACCESS_KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBjngojWT4QUfy2bl78lWkaepNtOZYDlAzZbel8QNoWN swamp-serve";
const ACCESS = {
  user: "swamp-patch",
  publicKey: ACCESS_KEY,
  from: ["10.0.0.0/24"],
  provisionSshModel: "prov",
};
const ACCESS_FLEET = {
  sshModel: "ssh",
  access: ACCESS,
  machines: [
    { host: "web1" },
    {
      host: "dock",
      docker: { composePath: "/srv/app", service: "app" },
      from: ["192.0.2.57"],
    },
  ],
};

const PROVISION_RESULT = {
  _kind: "patch-access-provision",
  user: "swamp-patch",
  created: true,
  groupsRemoved: [],
  cacheRefresh: "apt",
  docker: false,
};
const REVOKE_RESULT = {
  _kind: "patch-access-revoke",
  user: "swamp-patch",
  removed: [],
};

/** The stdout of a provisioning run that applied: its steps, then the result line. */
function provisionOk(): string {
  return `== root\n== preflight\n== account\n== key\n${
    JSON.stringify(PROVISION_RESULT)
  }\n`;
}

/** The stdout of a revoke run that applied. */
function revokeOk(): string {
  return `== root\n${JSON.stringify(REVOKE_RESULT)}\n`;
}

/** What the fake prints for a `script` call over several hosts: one artifact per host run. */
function scriptRunsOut(
  runs: Array<{ host: string; stdout: string; exitCode?: number }>,
): string {
  return JSON.stringify({
    dataArtifacts: runs.map((r) => ({
      attributes: {
        host: r.host,
        stdout: r.stdout,
        exitCode: r.exitCode ?? 0,
      },
    })),
  });
}

type WrittenRecord = { name: string; data: Record<string, unknown> };

/** The accessRun records written through a test context, keyed by host. */
function accessRunsByHost(
  t: ReturnType<typeof mkCtx>,
): Map<string, Record<string, unknown>> {
  return new Map(
    (t.written("accessRun") as WrittenRecord[]).map((
      r,
    ): [string, Record<string, unknown>] => [String(r.data.host), r.data]),
  );
}

Deno.test("access: renderAccess writes one accessPlan per machine, with the restricted key line, and contacts no host", async () => {
  await withCallLog({}, async (calls) => {
    const t = mkCtx(ACCESS_FLEET);
    await model.methods.renderAccess.execute({}, t.ctx);
    const plans = t.written("accessPlan");
    // Never the bare host name, which inventory records use.
    assertEquals(plans.map((p) => p.name), [
      "access-plan-web1",
      "access-plan-dock",
    ]);

    const web1 = plans[0].data as Record<string, unknown>;
    assertEquals(web1.from, ["10.0.0.0/24"]);
    assertEquals(web1.docker, false);
    assertStringIncludes(
      String(web1.keyLine),
      'from="10.0.0.0/24",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc ',
    );
    assert(String(web1.keyLine).endsWith(` ${ACCESS_KEY}`));
    assertMatch(String(web1.provisionScriptSha256), /^[0-9a-f]{64}$/);
    assertMatch(String(web1.revokeScriptSha256), /^[0-9a-f]{64}$/);
    assertStringIncludes(
      String(web1.provisionScript),
      "PATCH_USER='swamp-patch'",
    );

    // dock overrides the source addresses, and it is a docker host.
    const dock = plans[1].data as Record<string, unknown>;
    assertEquals(dock.from, ["192.0.2.57"]);
    assertEquals(dock.docker, true);
    assertStringIncludes(String(dock.keyLine), 'from="192.0.2.57",');
    assertStringIncludes(String(dock.provisionScript), "WANT_DOCKER=1");

    assertEquals(t.calls, []);
    assertEquals(await calls(), []);
  });
});

Deno.test("access: provisionAccess is a dry run by default and contacts no host", async () => {
  const env = {
    FAKE_SWAMP_MODEL_GET: sshDefinition("root", [{ name: "web1" }, {
      name: "dock",
    }]),
  };
  await withCallLog(env, async (calls) => {
    const t = mkCtx(ACCESS_FLEET);
    const args = model.methods.provisionAccess.arguments.parse({});
    assertEquals(args.dryRun, true);
    await model.methods.provisionAccess.execute(args, t.ctx);
    const runs = accessRunsByHost(t);
    assertEquals([...runs.keys()], ["web1", "dock"]);
    for (const r of runs.values()) {
      assertEquals(r.outcome, "dry-run");
      assertEquals(r.ok, true);
      assertEquals(r.dryRun, true);
      assertEquals(r.exitCode, null);
    }
    assertEquals(t.written("accessPlan").length, 2);
    assertEquals(t.calls, []);
    assertEquals(await calls(), []);
  });
  // A call with no dryRun value is a dry run too.
  await withCallLog(env, async (calls) => {
    const t = mkCtx(ACCESS_FLEET);
    await model.methods.provisionAccess.execute({} as never, t.ctx);
    assertEquals(accessRunsByHost(t).get("web1")?.dryRun, true);
    assertEquals(await calls(), []);
  });
});

Deno.test("access: provisionAccess applies through provisionSshModel only, one script call per script and sudo, without sudo for root", async () => {
  await withCallLog({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [
      { name: "web1", user: "root" },
      { name: "web2", user: "root" },
      { name: "web3" },
    ]),
    FAKE_SWAMP_SCRIPT_1: scriptRunsOut([
      { host: "web1", stdout: provisionOk() },
      { host: "web2", stdout: provisionOk() },
    ]),
    FAKE_SWAMP_SCRIPT_2: scriptRunsOut([
      { host: "web3", stdout: provisionOk() },
    ]),
  }, async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      access: ACCESS,
      machines: [{ host: "web1" }, { host: "web2" }, { host: "web3" }],
    });
    await model.methods.provisionAccess.execute({ dryRun: false }, t.ctx);

    // Every call goes to the provisioning model, never to the patch login's model.
    const lines = await calls();
    assertEquals(lines.length, 2);
    for (const l of lines) assert(l.startsWith("prov script "), l);
    // web1 and web2 share one script and need no sudo; web3 is not root, so it uses sudo.
    assertStringIncludes(lines[0], 'hosts:json=["web1","web2"]');
    assert(!lines[0].includes("sudo:json"));
    assertStringIncludes(lines[1], 'hosts:json=["web3"]');
    assertStringIncludes(lines[1], "sudo:json=true");

    const runs = accessRunsByHost(t);
    for (const h of ["web1", "web2", "web3"]) {
      assertEquals(runs.get(h)?.outcome, "applied");
      assertEquals(runs.get(h)?.ok, true);
      assertEquals(runs.get(h)?.dryRun, false);
      assertMatch(String(runs.get(h)?.scriptSha256), /^[0-9a-f]{64}$/);
    }
    assertEquals(runs.get("web1")?.sudo, false);
    assertEquals(runs.get("web3")?.sudo, true);
    assertEquals(runs.get("web1")?.result, PROVISION_RESULT);
  });
});

Deno.test("access: a host whose provisioning login cannot be read is skipped and never contacted", async () => {
  await withCallLog({
    FAKE_SWAMP_MODEL_GET: sshDefinition("root", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptRunsOut([{
      host: "web1",
      stdout: provisionOk(),
    }]),
  }, async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      access: ACCESS,
      machines: [{ host: "web1" }, { host: "ghost" }],
    });
    // The other host still runs, but a skipped host fails the run: success must not hide
    // a host that has no access.
    await assertRejects(
      () => model.methods.provisionAccess.execute({ dryRun: false }, t.ctx),
      Error,
      "ghost (skipped)",
    );
    const lines = await calls();
    assertEquals(accessRunsByHost(t).get("web1")?.outcome, "applied");
    assertEquals(lines.length, 1);
    assertStringIncludes(lines[0], 'hosts:json=["web1"]');
    const ghost = accessRunsByHost(t).get("ghost");
    assertEquals(ghost?.outcome, "skipped");
    assertEquals(ghost?.ok, false);
    assertEquals(ghost?.exitCode, null);
    assertEquals(ghost?.detail, "login cannot be read from prov");
  });
});

Deno.test("access: refusals and failures are recorded per host, and the run throws after every host", async () => {
  await withCallLog({
    FAKE_SWAMP_MODEL_GET: sshDefinition("root", [
      { name: "web1" },
      { name: "web2" },
      { name: "web3" },
      { name: "web4" },
      { name: "web5" },
    ]),
    FAKE_SWAMP_SCRIPT_1: scriptRunsOut([
      { host: "web1", stdout: provisionOk() },
      {
        host: "web2",
        stdout:
          "== account\nrefusing to take over existing account swamp-patch\n",
        exitCode: 3,
      },
      {
        host: "web3",
        stdout: "== preflight\nno bash on this host\n",
        exitCode: 4,
      },
      { host: "web4", stdout: "== root\nboom\n", exitCode: 1 },
      { host: "web5", stdout: "== key\n", exitCode: 0 },
    ]),
  }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      access: ACCESS,
      machines: ["web1", "web2", "web3", "web4", "web5"].map((host) => ({
        host,
      })),
    });
    await assertRejects(
      () => model.methods.provisionAccess.execute({ dryRun: false }, t.ctx),
      Error,
      "web2 (refused-takeover), web3 (refused-preflight), web4 (failed), web5 (failed)",
    );
    // Every host has its record, written before the throw.
    const runs = accessRunsByHost(t);
    assertEquals(t.written("accessRun").length, 5);
    assertEquals(runs.get("web1")?.outcome, "applied");
    assertEquals(runs.get("web2")?.outcome, "refused-takeover");
    assertEquals(runs.get("web2")?.exitCode, 3);
    assertEquals(runs.get("web2")?.result, null);
    assertStringIncludes(
      String(runs.get("web2")?.detail),
      "refusing to take over",
    );
    assertEquals(runs.get("web3")?.outcome, "refused-preflight");
    assertEquals(runs.get("web4")?.outcome, "failed");
    assertEquals(runs.get("web5")?.outcome, "failed");
    assertEquals(runs.get("web5")?.exitCode, 0);
  });
});

Deno.test("access: exit 6 (the sudoers step rolled back) is failed, not refused", async () => {
  await withCallLog({
    FAKE_SWAMP_MODEL_GET: sshDefinition("root", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptRunsOut([{
      host: "web1",
      stdout: "== sudo\nthe sudoers entries do not parse: nothing was installed\n",
      exitCode: 6,
    }]),
  }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      access: ACCESS,
      machines: [{ host: "web1" }],
    });
    await assertRejects(
      () => model.methods.provisionAccess.execute({ dryRun: false }, t.ctx),
      Error,
      "web1 (failed)",
    );
    const run = accessRunsByHost(t).get("web1");
    assertEquals(run?.outcome, "failed");
    assertEquals(run?.exitCode, 6);
  });
});

Deno.test("access: the access methods throw without access, when provisionSshModel is sshModel, and for an unknown host", async () => {
  const noAccess = { sshModel: "ssh", machines: [{ host: "web1" }] };
  const sameModel = {
    ...ACCESS_FLEET,
    access: { ...ACCESS, provisionSshModel: "ssh" },
  };
  const none = mkCtx(noAccess);
  await assertRejects(
    () => model.methods.renderAccess.execute({}, none.ctx),
    Error,
    "access is not configured",
  );
  await assertRejects(
    () => model.methods.provisionAccess.execute({ dryRun: true }, none.ctx),
    Error,
    "access is not configured",
  );
  await assertRejects(
    () => model.methods.revokeAccess.execute({ dryRun: true }, none.ctx),
    Error,
    "access is not configured",
  );
  const same = mkCtx(sameModel);
  await assertRejects(
    () => model.methods.renderAccess.execute({}, same.ctx),
    Error,
    "must differ from sshModel",
  );
  await assertRejects(
    () => model.methods.provisionAccess.execute({ dryRun: false }, same.ctx),
    Error,
    "must differ from sshModel",
  );
  await assertRejects(
    () => model.methods.revokeAccess.execute({ dryRun: false }, same.ctx),
    Error,
    "must differ from sshModel",
  );
  const ok = mkCtx(ACCESS_FLEET);
  await assertRejects(
    () => model.methods.renderAccess.execute({ hosts: ["nope"] }, ok.ctx),
    Error,
    'No machine "nope"',
  );

  const parsed = model.globalArguments.parse(ACCESS_FLEET);
  assertEquals(
    fleet.accessTargets(parsed).targets.map((t) => t.host),
    ["web1", "dock"],
  );
  assertEquals(
    fleet.accessTargets(parsed, ["dock"]).targets.map((t) => t.host),
    ["dock"],
  );
  assertThrows(
    () => fleet.accessTargets(model.globalArguments.parse(sameModel)),
    Error,
    "must differ from sshModel",
  );
  assertThrows(
    () => fleet.accessTargets(parsed, ["nope"]),
    Error,
    'No machine "nope"',
  );
});

Deno.test("checks: access-configured fails without access, when the patch login provisions, or for an unknown host, and passes otherwise", async () => {
  const noAccess = { sshModel: "ssh", machines: [{ host: "web1" }] };
  const sameModel = {
    ...ACCESS_FLEET,
    access: { ...ACCESS, provisionSshModel: "ssh" },
  };
  const missing = await runCheck(
    "access-configured",
    checkCtx(noAccess, "renderAccess"),
  );
  assertEquals(missing.pass, false);
  assertStringIncludes(missing.errors!.join(" "), "access is not configured");

  const same = await runCheck(
    "access-configured",
    checkCtx(sameModel, "provisionAccess", { dryRun: false }),
  );
  assertEquals(same.pass, false);
  assertStringIncludes(same.errors!.join(" "), "must differ from sshModel");
  assertStringIncludes(
    same.errors!.join(" "),
    "--skip-check access-configured",
  );

  const unknown = await runCheck(
    "access-configured",
    checkCtx(ACCESS_FLEET, "revokeAccess", { hosts: ["web1", "nope"] }),
  );
  assertEquals(unknown.pass, false);
  assertStringIncludes(unknown.errors!.join(" "), 'No machine "nope"');

  assertEquals(
    await runCheck(
      "access-configured",
      checkCtx(ACCESS_FLEET, "provisionAccess", {
        hosts: ["web1"],
        dryRun: false,
      }),
    ),
    { pass: true },
  );
  assertEquals(
    await runCheck("access-configured", checkCtx(ACCESS_FLEET, "renderAccess")),
    { pass: true },
  );
});

Deno.test("access: revokeAccess is a dry run by default, and a good run is applied with its result", async () => {
  const env = {
    FAKE_SWAMP_MODEL_GET: sshDefinition("root", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptRunsOut([{ host: "web1", stdout: revokeOk() }]),
  };
  await withCallLog(env, async (calls) => {
    const t = mkCtx(ACCESS_FLEET);
    await model.methods.revokeAccess.execute(
      model.methods.revokeAccess.arguments.parse({}),
      t.ctx,
    );
    const runs = accessRunsByHost(t);
    assertEquals([...runs.keys()], ["web1", "dock"]);
    for (const r of runs.values()) {
      assertEquals(r.outcome, "dry-run");
      assertEquals(r.action, "revoke");
    }
    assertEquals(t.written("accessPlan"), []);
    assertEquals(await calls(), []);
  });

  await withCallLog(env, async (calls) => {
    const t = mkCtx({ ...ACCESS_FLEET, machines: [{ host: "web1" }] });
    await model.methods.revokeAccess.execute(
      { hosts: ["web1"], dryRun: false },
      t.ctx,
    );
    const lines = await calls();
    assertEquals(lines.length, 1);
    assert(lines[0].startsWith("prov script "), lines[0]);
    assert(!lines[0].includes("sudo:json"));
    const rec = accessRunsByHost(t).get("web1");
    assertEquals(rec?.action, "revoke");
    assertEquals(rec?.outcome, "applied");
    assertEquals(rec?.ok, true);
    assertEquals(rec?.result, REVOKE_RESULT);
    assertEquals(t.written("accessPlan"), []);
  });
});

// ---------------------------------------------------------------------------
// The access audit: auditAccess. The fake answers every `script` call with the same
// output, so one stdout carries both probe lines and each call reads its own.
// ---------------------------------------------------------------------------

const AUDIT_FROM = ["10.0.0.0/24"];
const AUDIT_LINE = authorizedKeysLine(ACCESS_KEY, AUDIT_FROM);
const AUDIT_TOKEN = "0123456789abcdef0123456789abcdef";
const NO_WRITE_PATHS = {
  authorizedKeys: false,
  sshDir: false,
  marker: false,
  stateDir: false,
  libexec: false,
  dockerProducer: false,
  sudoersDir: false,
  unitService: false,
  unitTimer: false,
  aptConf: false,
  apkPeriodic: false,
  aptAuto: false,
  dnfAutoConf: false,
  dnfAutoDropIn: false,
  dockerHelper: false,
  dockerProjects: false,
};

/** The user probe of a clean login: the patch login, no sudo, no docker, nothing writable. */
const CLEAN_USER_PROBE = {
  _kind: "patch-access-user-probe",
  user: "swamp-patch",
  uid: 1001,
  groups: ["swamp-patch"],
  sudoList: null,
  sudoTrueRc: null,
  dockerRc: null,
  canWrite: NO_WRITE_PATHS,
};

/** The root probe of a clean host: the login with its one key line, and root-owned files. */
function cleanRootProbe(
  over: Record<string, unknown> = {},
): Record<string, unknown> {
  const file = { owner: "root", group: "root", mode: "644" };
  const dir = { owner: "root", group: "root", mode: "755" };
  const absent = (path: string) => ({
    path,
    exists: false,
    owner: null,
    group: null,
    mode: null,
    sha256: null,
    hasManagedHeader: false,
  });
  return {
    _kind: "patch-access-root-probe",
    account: {
      exists: true,
      markerOk: true,
      shadowLocked: true,
      shell: "/bin/bash",
      gecos: `swamp-patch token=${AUDIT_TOKEN}`,
    },
    groupsOfUser: ["swamp-patch"],
    authorizedKeys: {
      lines: [AUDIT_LINE],
      total: 1,
      file,
      dir,
      home: dir,
    },
    rootHasKey: false,
    managedFiles: [
      {
        path: PATHS.marker,
        exists: true,
        owner: "root",
        group: "root",
        mode: "644",
        sha256: null,
        hasManagedHeader: false,
      },
      absent(PATHS.dockerProducer),
      absent(PATHS.unitService),
      absent(PATHS.unitTimer),
      absent(PATHS.aptConf),
      absent(PATHS.apkPeriodic),
      absent(PATHS.sudoers),
    ],
    dirs: {
      stateDir: dir,
      libexec: null,
      sudoersDir: dir,
      systemdDir: dir,
      projectsDir: null,
    },
    sudoRules: [],
    cache: {
      family: "apt",
      refreshOn: true,
      ageHours: 1,
      autoInstall: false,
      autoScope: null,
    },
    hostGroups: {
      docker: [],
      wheel: [],
      sudo: [],
      admin: [],
      adm: [],
      lxd: [],
      disk: [],
    },
    dockerSocket: null,
    sudoersFile: { exists: false, lines: [], total: 0 },
    sudoFamilies: ["apt", "systemd"],
    compose: [],
    ...over,
  };
}

/** A host's stdout: the user probe line, then the root probe line, as the probes print them. */
function probeStdout(userProbe: unknown, rootProbe: unknown): string {
  const user = JSON.stringify(userProbe);
  const root = JSON.stringify(rootProbe);
  return `${user}\n== root\n${root}\n`;
}

/**
 * The env of an audit run: one `script` answer for every host, carrying both probe lines
 * (a host's override replaces its clean probe). `definition` is the login definition.
 */
function auditEnv(
  definition: string,
  runs: Array<{ host: string; rootProbe?: unknown }>,
): Env {
  return {
    FAKE_SWAMP_MODEL_GET: definition,
    FAKE_SWAMP_SCRIPT_1: scriptRunsOut(runs.map((r) => ({
      host: r.host,
      stdout: probeStdout(
        CLEAN_USER_PROBE,
        r.rootProbe ?? cleanRootProbe(),
      ),
    }))),
  };
}

/** The accessAudit record of one host, written through a test context. */
function auditOf(
  t: ReturnType<typeof mkCtx>,
  host: string,
): Record<string, unknown> {
  const found = (t.written("accessAudit") as WrittenRecord[]).find((r) =>
    r.name === `access-audit-${host}`
  );
  assert(found !== undefined, `no accessAudit record for ${host}`);
  return found.data;
}

/** The findings of an accessAudit record as "id severity", sorted. */
function auditFindings(rec: Record<string, unknown>): string[] {
  return (rec.findings as Array<{ id: string; severity: string }>)
    .map((f) => `${f.id} ${f.severity}`)
    .sort();
}

const AUDIT_ARGS = model.methods.auditAccess.arguments;

/**
 * The grant warnings of a managed machine whose sudoers file has no grants (cleanRootProbe
 * leaves it empty): the three apt entries and reboot, sorted as auditFindings sorts them.
 */
const NO_GRANTS_WARNINGS = [
  "privilege-missing:apt-full-upgrade warning",
  "privilege-missing:apt-update warning",
  "privilege-missing:apt-upgrade warning",
  "privilege-missing:reboot warning",
];

Deno.test("auditAccess: the user probe goes to sshModel without sudo; the root probe goes to provisionSshModel, under sudo only for a non-root login, one call per group", async () => {
  const env = auditEnv(
    sshDefinition("root", [
      { name: "web1" },
      { name: "web2", user: "ops" },
      { name: "web3", user: "ops" },
    ]),
    ["web1", "web2", "web3"].map((host) => ({ host })),
  );
  await withCallLog(env, async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      access: ACCESS,
      machines: [{ host: "web1" }, { host: "web2" }, { host: "web3" }],
    });
    await model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), t.ctx);

    // One user probe through the ssh model, then one root probe per sudo group.
    const lines = await calls();
    assertEquals(lines.length, 3);
    assert(lines[0].startsWith("ssh script "), lines[0]);
    assert(!lines[0].includes("sudo:json"), lines[0]);
    assertStringIncludes(lines[0], 'hosts:json=["web1","web2","web3"]');
    const roots = lines.slice(1);
    for (const l of roots) assert(l.startsWith("prov script "), l);
    const plain = roots.find((l) => !l.includes("sudo:json"));
    const sudo = roots.find((l) => l.includes("sudo:json=true"));
    assert(plain !== undefined, "a root probe call without sudo");
    assert(sudo !== undefined, "a root probe call with sudo");
    assertStringIncludes(plain, 'hosts:json=["web1"]');
    assertStringIncludes(sudo, 'hosts:json=["web2","web3"]');
  });
});

Deno.test("auditAccess: a managed host whose sudoers file has no grants gives only the privilege-missing warnings, ok true, and no throw", async () => {
  await withCallLog(
    auditEnv(sshDefinition("root", [{ name: "web1" }]), [{ host: "web1" }]),
    async () => {
      const t = mkCtx({
        sshModel: "ssh",
        access: ACCESS,
        machines: [{ host: "web1" }],
      });
      await model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), t.ctx);
      assertEquals(
        t.written("accessAudit").map((r) => r.name),
        ["access-audit-web1"],
      );
      const rec = auditOf(t, "web1");
      assertEquals(rec.host, "web1");
      assertEquals(rec.ok, true);
      assertEquals(auditFindings(rec), NO_GRANTS_WARNINGS);
      assertEquals(rec.acceptedRisks, []);
      assertEquals(rec.summary, {
        critical: 0,
        high: 0,
        warning: 4,
        info: 0,
        accepted: 0,
        overdue: 0,
      });
      assertEquals(rec.userProbe, CLEAN_USER_PROBE);
      assertEquals(rec.rootProbe, cleanRootProbe());
      assertEquals(rec.userProbeError, null);
      assertEquals(rec.rootProbeError, null);
    },
  );
});

Deno.test("auditAccess: a managed machine's OS policy requires the apt grants: with an empty sudoers file and only apt on the host, each apt entry is privilege-missing and reboot is not", async () => {
  await withCallLog(
    auditEnv(sshDefinition("root", [{ name: "web1" }]), [{
      host: "web1",
      rootProbe: cleanRootProbe({ sudoFamilies: ["apt"] }),
    }]),
    async () => {
      const t = mkCtx({
        sshModel: "ssh",
        access: ACCESS,
        osUpdatePolicy: "managed",
        machines: [{ host: "web1" }],
      });
      await model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), t.ctx);
      const rec = auditOf(t, "web1");
      assertEquals(rec.ok, true);
      assertEquals(auditFindings(rec), [
        "privilege-missing:apt-full-upgrade warning",
        "privilege-missing:apt-update warning",
        "privilege-missing:apt-upgrade warning",
      ]);
    },
  );
});

Deno.test("auditAccess: the patch login in the docker group is critical, the run throws naming the host and the id, and failOn none does not throw", async () => {
  const docker = cleanRootProbe({ groupsOfUser: ["swamp-patch", "docker"] });
  await withCallLog(
    auditEnv(sshDefinition("root", [{ name: "web1" }]), [{
      host: "web1",
      rootProbe: docker,
    }]),
    async () => {
      const t = mkCtx({
        sshModel: "ssh",
        access: ACCESS,
        machines: [{ host: "web1" }],
      });
      await assertRejects(
        () => model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), t.ctx),
        Error,
        "web1: group-root-equivalent:docker",
      );
      const rec = auditOf(t, "web1");
      assertEquals(rec.ok, false);
      assertEquals(auditFindings(rec), [
        "group-root-equivalent:docker critical",
        ...NO_GRANTS_WARNINGS,
      ]);

      const quiet = mkCtx({
        sshModel: "ssh",
        access: ACCESS,
        machines: [{ host: "web1" }],
      });
      await model.methods.auditAccess.execute(
        AUDIT_ARGS.parse({ failOn: "none" }),
        quiet.ctx,
      );
      const passed = auditOf(quiet, "web1");
      assertEquals(passed.ok, true);
      assertEquals(auditFindings(passed), [
        "group-root-equivalent:docker critical",
        ...NO_GRANTS_WARNINGS,
      ]);
    },
  );
});

Deno.test("auditAccess: a provisioning login that cannot be read is not contacted and gives probe-failed:root", async () => {
  await withCallLog(
    auditEnv(sshDefinition("root", [{ name: "web1" }]), [
      { host: "web1" },
      { host: "ghost" },
    ]),
    async (calls) => {
      const t = mkCtx({
        sshModel: "ssh",
        access: ACCESS,
        machines: [{ host: "web1" }, { host: "ghost" }],
      });
      // probe-failed is high and the default failOn is high: an unknown state fails the run.
      await assertRejects(
        () => model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), t.ctx),
        Error,
        "ghost: probe-failed:root",
      );

      const roots = (await calls()).filter((l) => l.startsWith("prov script "));
      assertEquals(roots.length, 1);
      assertStringIncludes(roots[0], 'hosts:json=["web1"]');
      assertEquals(roots.some((l) => l.includes("ghost")), false);

      const ghost = auditOf(t, "ghost");
      assertEquals(ghost.rootProbe, null);
      assertEquals(
        ghost.rootProbeError,
        "login cannot be read from prov",
      );
      assertEquals(ghost.userProbeError, null);
      assertEquals(auditFindings(ghost), ["probe-failed:root high"]);
      assertEquals(auditOf(t, "web1").ok, true);

      // Only an explicit, looser failOn lets it pass.
      const loose = mkCtx({
        sshModel: "ssh",
        access: ACCESS,
        machines: [{ host: "web1" }, { host: "ghost" }],
      });
      await model.methods.auditAccess.execute(
        AUDIT_ARGS.parse({ failOn: "critical" }),
        loose.ctx,
      );
      assertEquals(auditOf(loose, "ghost").ok, true);
    },
  );
});

Deno.test("auditAccess: a probe whose call fails records the error on every host", async () => {
  await withCallLog({
    FAKE_SWAMP_MODEL_GET: sshDefinition("root", [
      { name: "web1" },
      { name: "web2" },
    ]),
    FAKE_SWAMP_SCRIPT_RC: "1",
  }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      access: ACCESS,
      machines: [{ host: "web1" }, { host: "web2" }],
    });
    // Every host is written before the run fails on the unknown state.
    await assertRejects(
      () => model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), t.ctx),
      Error,
      "web2: probe-failed:user, probe-failed:root",
    );
    for (const host of ["web1", "web2"]) {
      const rec = auditOf(t, host);
      assertEquals(rec.userProbe, null);
      assertStringIncludes(String(rec.userProbeError), "ssh script failed");
      assertStringIncludes(String(rec.rootProbeError), "prov script failed");
      assertEquals(auditFindings(rec), [
        "probe-failed:root high",
        "probe-failed:user high",
      ]);
    }
  });
});

Deno.test("auditAccess: an accepted risk moves the docker finding out, and the run passes at failOn critical", async () => {
  await withCallLog(
    auditEnv(sshDefinition("root", [{ name: "web1" }]), [{
      host: "web1",
      rootProbe: cleanRootProbe({ groupsOfUser: ["swamp-patch", "docker"] }),
    }]),
    async () => {
      const t = mkCtx({
        sshModel: "ssh",
        access: ACCESS,
        machines: [{
          host: "web1",
          acceptedRisks: [{
            reason: "Docker builds run as this login, reviewed quarterly",
            acceptedBy: "dmc",
            acceptedAt: "2026-10-01",
            reviewBy: "2027-06-30",
            finding: "group-root-equivalent:docker",
          }],
        }],
      });
      await model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), t.ctx);
      const rec = auditOf(t, "web1");
      assertEquals(rec.ok, true);
      assertEquals(auditFindings(rec), NO_GRANTS_WARNINGS);
      const accepted = rec.acceptedRisks as Array<
        { id: string; severity: string }
      >;
      assertEquals(
        accepted.map((a) => `${a.id} ${a.severity}`),
        ["group-root-equivalent:docker critical"],
      );
      assertEquals(
        (rec.summary as { critical: number; accepted: number }).critical,
        0,
      );
      assertEquals(
        (rec.summary as { critical: number; accepted: number }).accepted,
        1,
      );
    },
  );
});

Deno.test("auditAccess: throws without access, when provisionSshModel is sshModel, or for an unknown host; the access-configured check fails the same way", async () => {
  const noAccess = { sshModel: "ssh", machines: [{ host: "web1" }] };
  const sameModel = {
    ...ACCESS_FLEET,
    access: { ...ACCESS, provisionSshModel: "ssh" },
  };
  await assertRejects(
    () =>
      model.methods.auditAccess.execute(
        AUDIT_ARGS.parse({}),
        mkCtx(noAccess).ctx,
      ),
    Error,
    "access is not configured",
  );
  await assertRejects(
    () =>
      model.methods.auditAccess.execute(
        AUDIT_ARGS.parse({}),
        mkCtx(sameModel).ctx,
      ),
    Error,
    "must differ from sshModel",
  );
  await assertRejects(
    () =>
      model.methods.auditAccess.execute(
        AUDIT_ARGS.parse({ hosts: ["nope"] }),
        mkCtx(ACCESS_FLEET).ctx,
      ),
    Error,
    'No machine "nope"',
  );

  const missing = await runCheck(
    "access-configured",
    checkCtx(noAccess, "auditAccess"),
  );
  assertEquals(missing.pass, false);
  assertStringIncludes(missing.errors!.join(" "), "access is not configured");
  const same = await runCheck(
    "access-configured",
    checkCtx(sameModel, "auditAccess", {}),
  );
  assertEquals(same.pass, false);
  assertStringIncludes(same.errors!.join(" "), "must differ from sshModel");
  const unknown = await runCheck(
    "access-configured",
    checkCtx(ACCESS_FLEET, "auditAccess", { hosts: ["nope"] }),
  );
  assertEquals(unknown.pass, false);
  assertStringIncludes(unknown.errors!.join(" "), 'No machine "nope"');
});

Deno.test("auditAccess: an empty selection contacts nothing and does not fail", async () => {
  await withCallLog({}, async (calls) => {
    const t = mkCtx({ sshModel: "ssh", access: ACCESS, machines: [] });
    await model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), t.ctx);
    assertEquals((await calls()).length, 0);
  });
});

// ---------------------------------------------------------------------------
// OS update policy: the schema, the runtime guards of safeOsUpdate and reboot, and the
// audit's auto-install-off. A refused run makes no runModel call at all (the fake records
// none) and writes no record, so a refusal can never have snapshotted, connected or upgraded.
// ---------------------------------------------------------------------------

Deno.test("os policy: the fleet defaults are managed and security, and a machine inherits them", () => {
  const g = model.globalArguments.parse({
    sshModel: "ssh",
    machines: [{ host: "a" }],
  });
  assertEquals(g.osUpdatePolicy, "managed");
  assertEquals(g.osAutoScope, "security");
  assertEquals(g.machines[0].osUpdatePolicy, undefined);
  assertEquals(g.machines[0].osAutoScope, undefined);
});

Deno.test("os policy: a machine may set auto with a scope, and an auto fleet default needs no machine field", () => {
  const g = model.globalArguments.parse({
    sshModel: "ssh",
    osUpdatePolicy: "auto",
    osAutoScope: "all",
    machines: [{ host: "a" }, {
      host: "b",
      osUpdatePolicy: "auto",
      osAutoScope: "security",
    }],
  });
  assertEquals(g.osUpdatePolicy, "auto");
  assertEquals(g.machines[1].osAutoScope, "security");
});

Deno.test("os policy: osAutoScope on a machine that sets managed or scan-only is rejected by the schema", () => {
  for (const policy of ["managed", "scan-only"]) {
    const r = model.globalArguments.safeParse({
      sshModel: "ssh",
      machines: [{ host: "a", osUpdatePolicy: policy, osAutoScope: "security" }],
    });
    assertEquals(r.success, false, policy);
    assertStringIncludes(
      r.success ? "" : r.error.message,
      "osAutoScope applies only when osUpdatePolicy is auto",
    );
  }
});

Deno.test("os policy: unknown policy and scope values are rejected", () => {
  assertEquals(
    model.globalArguments.safeParse({
      sshModel: "ssh",
      machines: [{ host: "a", osUpdatePolicy: "yolo" }],
    }).success,
    false,
  );
  assertEquals(
    model.globalArguments.safeParse({ sshModel: "ssh", osAutoScope: "some" })
      .success,
    false,
  );
});

Deno.test("safeOsUpdate: refused on an auto VM with no snapshot, no connection and no upgrade", async () => {
  await withFake(osUpdateEnv(), async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{
        host: "web1",
        vm: { proxmoxNode: "pve", vmid: 100 },
        osUpdatePolicy: "auto",
      }],
    });
    await assertRejects(
      () =>
        model.methods.safeOsUpdate.execute(
          model.methods.safeOsUpdate.arguments.parse({ host: "web1" }),
          t.ctx,
        ),
      Error,
      "safeOsUpdate refused for web1: osUpdatePolicy is auto (the host installs its own OS updates); use reboot for pending reboots",
    );
    assertEquals(t.calls.length, 0);
    assertEquals(t.written("snapshot"), []);
    assertEquals(t.written("osUpdate"), []);
    assertEquals(t.written("run"), []);
  });
});

Deno.test("safeOsUpdate: refused on a scan-only fleet and on a machine with os false, before any call", async () => {
  await withFake(osUpdateEnv(), async () => {
    const scan = mkCtx({
      sshModel: "ssh",
      osUpdatePolicy: "scan-only",
      machines: [{ host: "web1" }],
    });
    await assertRejects(
      () =>
        model.methods.safeOsUpdate.execute(
          model.methods.safeOsUpdate.arguments.parse({ host: "web1" }),
          scan.ctx,
        ),
      Error,
      "safeOsUpdate refused for web1: osUpdatePolicy is scan-only",
    );
    assertEquals(scan.calls.length, 0);
    assertEquals(scan.written("osUpdate"), []);

    const off = mkCtx({ sshModel: "ssh", machines: [{ host: "web1", os: false }] });
    await assertRejects(
      () =>
        model.methods.safeOsUpdate.execute(
          model.methods.safeOsUpdate.arguments.parse({ host: "web1" }),
          off.ctx,
        ),
      Error,
      "safeOsUpdate refused for web1: os is false",
    );
    assertEquals(off.calls.length, 0);
  });
});

Deno.test("safeOsUpdate: a machine's managed policy overrides an auto fleet default, and it upgrades", async () => {
  await withFake(osUpdateEnv(), async () => {
    const t = mkCtx({
      sshModel: "ssh",
      osUpdatePolicy: "auto",
      machines: [{ host: "web1", osUpdatePolicy: "managed" }],
    });
    await model.methods.safeOsUpdate.execute(
      model.methods.safeOsUpdate.arguments.parse({ host: "web1" }),
      t.ctx,
    );
    assertEquals(t.one("osUpdate").outcome, "updated");
  });
});

Deno.test("reboot: refused on a scan-only machine even with force, before any call or record", async () => {
  await withFake({ FAKE_SWAMP_EXEC: execOut("", 0) }, async () => {
    const t = mkCtx(
      {
        sshModel: "ssh",
        machines: [{ host: "web1", osUpdatePolicy: "scan-only" }],
      },
      { stored: { web1: { needsReboot: true } } },
    );
    await assertRejects(
      () =>
        model.methods.reboot.execute(
          model.methods.reboot.arguments.parse({
            host: "web1",
            force: true,
            wait: false,
          }),
          t.ctx,
        ),
      Error,
      "reboot refused for web1: osUpdatePolicy is scan-only (the host is only scanned; reboots are refused, even with force)",
    );
    assertEquals(t.calls.length, 0);
    assertEquals(t.written("reboot"), []);
    assertEquals(t.written("run"), []);
  });
});

Deno.test("reboot: allowed on an auto machine, which installs its own updates but can still need a reboot", async () => {
  await withFake({ FAKE_SWAMP_EXEC: execOut("", 0) }, async () => {
    const t = mkCtx(
      { sshModel: "ssh", machines: [{ host: "web1", osUpdatePolicy: "auto" }] },
      { stored: { web1: { needsReboot: true } } },
    );
    await model.methods.reboot.execute(
      model.methods.reboot.arguments.parse({ host: "web1", wait: false }),
      t.ctx,
    );
    assertEquals(t.one("reboot").outcome, "rebooted");
  });
});

Deno.test("reboot: os false does not refuse a reboot; the policy alone decides", async () => {
  await withFake({ FAKE_SWAMP_EXEC: execOut("", 0) }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1", os: false }] });
    let err = "";
    try {
      await model.methods.reboot.execute(
        model.methods.reboot.arguments.parse({
          host: "web1",
          force: true,
          wait: false,
        }),
        t.ctx,
      );
    } catch (e) {
      err = String(e);
    }
    assert(!err.includes("refused"), err);
    assert(t.calls.length > 0, "the reboot reached the transport");
  });
});

Deno.test("globalArguments: a machine that inherits a non-auto policy may not set osAutoScope", () => {
  const bad = model.globalArguments.safeParse({
    sshModel: "ssh",
    machines: [{ host: "web1", osAutoScope: "all" }],
  });
  assert(!bad.success);
  assertStringIncludes(
    JSON.stringify(bad.error.issues),
    "web1 inherits osUpdatePolicy: managed from the fleet",
  );
  assert(
    model.globalArguments.safeParse({
      sshModel: "ssh",
      osUpdatePolicy: "auto",
      machines: [{ host: "web1", osAutoScope: "all" }],
    }).success,
  );
});

Deno.test("auditAccess: an auto machine whose host does not install updates gets auto-install-off, and the run still passes", async () => {
  const off = cleanRootProbe({
    cache: {
      family: "apt",
      refreshOn: true,
      ageHours: 1,
      autoInstall: false,
      autoScope: null,
    },
  });
  await withCallLog(
    auditEnv(sshDefinition("root", [{ name: "web1" }]), [{
      host: "web1",
      rootProbe: off,
    }]),
    async () => {
      const t = mkCtx({
        sshModel: "ssh",
        access: ACCESS,
        machines: [{ host: "web1", osUpdatePolicy: "auto" }],
      });
      await model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), t.ctx);
      const rec = auditOf(t, "web1");
      // An auto machine's OS upgrades are off, so only reboot is required of its grants.
      assertEquals(auditFindings(rec), [
        "auto-install-off warning",
        "privilege-missing:reboot warning",
      ]);
      assertEquals(rec.ok, true);
    },
  );
});

Deno.test("auditAccess: the fleet's auto default is audited per machine: no install or scope finding when the host installs its own updates", async () => {
  const on = cleanRootProbe({
    cache: {
      family: "apt",
      refreshOn: true,
      ageHours: 1,
      autoInstall: true,
      autoScope: "security",
    },
  });
  await withCallLog(
    auditEnv(sshDefinition("root", [{ name: "web1" }]), [{
      host: "web1",
      rootProbe: on,
    }]),
    async () => {
      const t = mkCtx({
        sshModel: "ssh",
        access: ACCESS,
        osUpdatePolicy: "auto",
        machines: [{ host: "web1" }],
      });
      await model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), t.ctx);
      // Reboot is the one grant an auto machine needs; the empty sudoers file lacks it.
      assertEquals(auditFindings(auditOf(t, "web1")), [
        "privilege-missing:reboot warning",
      ]);
    },
  );
});

Deno.test("access: the auto scope comes from the OS policy: the fleet default, a machine's own scope, and os false or managed give none", async () => {
  await withCallLog({}, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      access: ACCESS,
      osUpdatePolicy: "auto",
      machines: [
        { host: "web1" },
        { host: "web2", osAutoScope: "all" },
        { host: "web3", os: false },
        { host: "web4", osUpdatePolicy: "managed" },
      ],
    });
    await model.methods.renderAccess.execute({}, t.ctx);
    const scripts = new Map(
      t.written("accessPlan").map((p) => [
        p.name,
        String((p.data as Record<string, unknown>).provisionScript),
      ]),
    );
    const of = (host: string) => scripts.get(`access-plan-${host}`) ?? "";

    // The fleet default is security; web2 overrides it to all.
    assertStringIncludes(of("web1"), `auto_json='"security"'`);
    assertStringIncludes(of("web1"), "upgrade_type = security");
    assertStringIncludes(of("web2"), `auto_json='"all"'`);
    assertStringIncludes(of("web2"), "upgrade_type = default");
    assertStringIncludes(of("web2"), '-updates";');
    // os false turns OS actions off, so the host gets no auto files, and no pre-flight either.
    for (const host of ["web3", "web4"]) {
      assertStringIncludes(of(host), "auto_json=null");
      assert(!of(host).includes("auto OS updates are refused"), host);
      assert(!of(host).includes("upgrade_type ="), host);
    }
    // The scripts of the auto machines carry the pre-flight, before the account is made.
    assert(
      of("web1").indexOf("auto OS updates are refused") <
        of("web1").indexOf("== account"),
    );

    // provisionAccess takes the same targets, so its dry run carries the same scope. It
    // contacts no host.
    const p = mkCtx({
      sshModel: "ssh",
      access: ACCESS,
      osUpdatePolicy: "auto",
      machines: [{ host: "web1" }, { host: "web2", osAutoScope: "all" }],
    });
    await model.methods.provisionAccess.execute({ dryRun: true }, p.ctx);
    const planned = new Map(
      p.written("accessPlan").map((r) => [
        r.name,
        String((r.data as Record<string, unknown>).provisionScript),
      ]),
    );
    assertStringIncludes(
      planned.get("access-plan-web1") ?? "",
      `auto_json='"security"'`,
    );
    assertStringIncludes(
      planned.get("access-plan-web2") ?? "",
      `auto_json='"all"'`,
    );
  });
});

Deno.test("access: a pre-flight refusal (exit 5) is refused-preflight, the run throws, and nothing else is recorded as applied", async () => {
  await withCallLog({
    FAKE_SWAMP_MODEL_GET: sshDefinition("root", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptRunsOut([{
      host: "web1",
      stdout:
        "== preflight\nauto OS updates are refused on a Proxmox node (it needs full-upgrade under @dmc/patch)\n",
      exitCode: 5,
    }]),
  }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      access: ACCESS,
      osUpdatePolicy: "auto",
      machines: [{ host: "web1" }],
    });
    await assertRejects(
      () => model.methods.provisionAccess.execute({ dryRun: false }, t.ctx),
      Error,
      "web1 (refused-preflight)",
    );
    const rec = accessRunsByHost(t).get("web1");
    assertEquals(rec?.outcome, "refused-preflight");
    assertEquals(rec?.exitCode, 5);
    assertEquals(rec?.ok, false);
  });
});

Deno.test("auditAccess: an auto file whose scope differs from the machine's scope gives auto-scope-mismatch, a warning that does not fail the run", async () => {
  const all = cleanRootProbe({
    cache: {
      family: "apt",
      refreshOn: true,
      ageHours: 1,
      autoInstall: true,
      autoScope: "all",
    },
  });
  await withCallLog(
    auditEnv(sshDefinition("root", [{ name: "web1" }]), [{
      host: "web1",
      rootProbe: all,
    }]),
    async () => {
      // The fleet default scope is security, so an all file is a mismatch.
      const t = mkCtx({
        sshModel: "ssh",
        access: ACCESS,
        osUpdatePolicy: "auto",
        machines: [{ host: "web1" }],
      });
      await model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), t.ctx);
      const rec = auditOf(t, "web1");
      assertEquals(auditFindings(rec), [
        "auto-scope-mismatch warning",
        "privilege-missing:reboot warning",
      ]);
      assertEquals(rec.ok, true);
    },
  );
});

// ---------------------------------------------------------------------------
// Package-set verdict: a change made outside @dmc/patch, read from the packages hash
// ---------------------------------------------------------------------------

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const HASH_G = "9".repeat(64);
const EARLIER = "2026-10-01T00:00:00.000Z";
const NOW = "2026-10-30T12:00:00.000Z";

Deno.test("packagesHashOf: only 64 lowercase hex characters are a hash", () => {
  assertEquals(fleet.packagesHashOf(HASH_A), HASH_A);
  assertEquals(fleet.packagesHashOf("A".repeat(64)), null);
  assertEquals(fleet.packagesHashOf("a".repeat(63)), null);
  assertEquals(fleet.packagesHashOf(`${HASH_A}0`), null);
  assertEquals(fleet.packagesHashOf(null), null);
  assertEquals(fleet.packagesHashOf(undefined), null);
  assertEquals(fleet.packagesHashOf(42), null);
});

Deno.test("outsidePackageChange: no previous record is an unknown verdict, and this read is the baseline", () => {
  assertEquals(fleet.outsidePackageChange(null, HASH_A, NOW), {
    packagesHash: HASH_A,
    packagesBaseline: HASH_A,
    packagesChangedOutsidePatch: null,
    lastOutsideChangeAt: null,
  });
});

Deno.test("outsidePackageChange: a previous record without a baseline is compared with its hash", () => {
  assertEquals(
    fleet.outsidePackageChange({ packagesHash: HASH_G }, HASH_A, NOW),
    {
      packagesHash: HASH_A,
      packagesBaseline: HASH_A,
      packagesChangedOutsidePatch: true,
      lastOutsideChangeAt: NOW,
    },
  );
  assertEquals(
    fleet.outsidePackageChange(
      { packagesHash: HASH_G, packagesBaseline: null },
      HASH_G,
      NOW,
    ).packagesChangedOutsidePatch,
    false,
  );
});

Deno.test("outsidePackageChange: an equal hash is false, and the carried lastOutsideChangeAt stays", () => {
  const prev = {
    packagesHash: HASH_A,
    packagesBaseline: HASH_A,
    lastOutsideChangeAt: EARLIER,
  };
  assertEquals(fleet.outsidePackageChange(prev, HASH_A, NOW), {
    packagesHash: HASH_A,
    packagesBaseline: HASH_A,
    packagesChangedOutsidePatch: false,
    lastOutsideChangeAt: EARLIER,
  });
});

Deno.test("outsidePackageChange: a different hash is true, and lastOutsideChangeAt becomes this scan", () => {
  const prev = {
    packagesHash: HASH_G,
    packagesBaseline: HASH_G,
    lastOutsideChangeAt: EARLIER,
  };
  assertEquals(fleet.outsidePackageChange(prev, HASH_B, NOW), {
    packagesHash: HASH_B,
    packagesBaseline: HASH_B,
    packagesChangedOutsidePatch: true,
    lastOutsideChangeAt: NOW,
  });
});

Deno.test("outsidePackageChange: an unknown read gives a null verdict and carries the baseline and the time", () => {
  const prev = {
    packagesHash: HASH_B,
    packagesBaseline: HASH_G,
    lastOutsideChangeAt: EARLIER,
  };
  assertEquals(fleet.outsidePackageChange(prev, null, NOW), {
    packagesHash: null,
    packagesBaseline: HASH_G,
    packagesChangedOutsidePatch: null,
    lastOutsideChangeAt: EARLIER,
  });
  // A value that is not a hash is an unknown read too.
  assertEquals(
    fleet.outsidePackageChange(prev, "not-a-hash", NOW).packagesChangedOutsidePatch,
    null,
  );
  // Nothing known on either side: all unknown.
  assertEquals(fleet.outsidePackageChange(null, null, NOW), {
    packagesHash: null,
    packagesBaseline: null,
    packagesChangedOutsidePatch: null,
    lastOutsideChangeAt: null,
  });
});

Deno.test("updatedPackageState: the verdict reads the before hash; the record holds the hash the update left", () => {
  // An outside change before the update (G -> B) is flagged; the update leaves A.
  const flagged = fleet.updatedPackageState(
    { packagesHash: HASH_G, packagesBaseline: HASH_G },
    HASH_B,
    HASH_A,
    NOW,
  );
  assertEquals(flagged, {
    packagesHash: HASH_A,
    packagesBaseline: HASH_A,
    packagesChangedOutsidePatch: true,
    lastOutsideChangeAt: NOW,
  });
  // The next scan of the state left behind does not flag.
  assertEquals(
    fleet.outsidePackageChange(
      flagged,
      HASH_A,
      "2026-10-31T00:00:00.000Z",
    ).packagesChangedOutsidePatch,
    false,
  );
});

Deno.test("updatedPackageState: an unknown final state carries the baseline (the before read's, else the previous)", () => {
  assertEquals(
    fleet.updatedPackageState(
      { packagesHash: HASH_G, packagesBaseline: HASH_G },
      HASH_B,
      null,
      NOW,
    ),
    {
      packagesHash: null,
      packagesBaseline: HASH_B,
      packagesChangedOutsidePatch: true,
      lastOutsideChangeAt: NOW,
    },
  );
  assertEquals(
    fleet.updatedPackageState(
      { packagesHash: HASH_G, packagesBaseline: HASH_G, lastOutsideChangeAt: EARLIER },
      null,
      null,
      NOW,
    ),
    {
      packagesHash: null,
      packagesBaseline: HASH_G,
      packagesChangedOutsidePatch: null,
      lastOutsideChangeAt: EARLIER,
    },
  );
});

Deno.test("inventory schema: a record without the package fields parses with them null; a malformed hash is rejected", () => {
  const schema = model.resources.inventory.schema;
  const v4 = {
    ...INVENTORY,
    schemaVersion: 4,
    reachMethod: null,
    health: null,
    error: null,
  };
  const parsed = schema.parse(v4);
  assertEquals(parsed.packagesHash, null);
  assertEquals(parsed.packagesBaseline, null);
  assertEquals(parsed.packagesChangedOutsidePatch, null);
  assertEquals(parsed.lastOutsideChangeAt, null);
  assertThrows(() => schema.parse({ ...v4, packagesHash: "XYZ" }));
  assertThrows(() => schema.parse({ ...v4, packagesBaseline: "a".repeat(63) }));
  assertEquals(
    schema.parse({ ...v4, packagesHash: HASH_A, packagesBaseline: HASH_A })
      .packagesHash,
    HASH_A,
  );
});

Deno.test("scan: a collector hash is compared with the previous record, and a change sets lastOutsideChangeAt", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut(
      "web1",
      collectorStdout({ schemaVersion: 5, packagesHash: HASH_B }),
    ),
  }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] }, {
      stored: {
        web1: {
          packagesHash: HASH_G,
          packagesBaseline: HASH_G,
          packagesChangedOutsidePatch: false,
          lastOutsideChangeAt: null,
        },
      },
    });
    const before = Date.now();
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertEquals(inv.packagesHash, HASH_B);
    assertEquals(inv.packagesBaseline, HASH_B);
    assertEquals(inv.packagesChangedOutsidePatch, true);
    assert(typeof inv.lastOutsideChangeAt === "string");
    assert(Date.parse(inv.lastOutsideChangeAt) >= before);
  });
});

Deno.test("scan: an unchanged collector hash is false and keeps the earlier lastOutsideChangeAt", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut(
      "web1",
      collectorStdout({ schemaVersion: 5, packagesHash: HASH_B }),
    ),
  }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] }, {
      stored: {
        web1: {
          packagesHash: HASH_B,
          packagesBaseline: HASH_B,
          packagesChangedOutsidePatch: true,
          lastOutsideChangeAt: EARLIER,
        },
      },
    });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertEquals(inv.packagesChangedOutsidePatch, false);
    assertEquals(inv.lastOutsideChangeAt, EARLIER);
  });
});

Deno.test("scan: a schemaVersion 4 line stores the package fields as unknown, and the baseline is carried", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", collectorStdout({ schemaVersion: 4 })),
  }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] }, {
      stored: {
        web1: {
          packagesHash: HASH_B,
          packagesBaseline: HASH_G,
          lastOutsideChangeAt: EARLIER,
        },
      },
    });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertEquals(inv.updatesCount, 3);
    assertEquals(inv.packagesHash, null);
    assertEquals(inv.packagesChangedOutsidePatch, null);
    assertEquals(inv.packagesBaseline, HASH_G);
    assertEquals(inv.lastOutsideChangeAt, EARLIER);
  });
});

Deno.test("scan: an error record carries the baseline, so an unreachable host does not reset it", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", "no json here\n", 1),
  }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines: [{ host: "web1" }] }, {
      stored: {
        web1: {
          packagesHash: HASH_B,
          packagesBaseline: HASH_G,
          lastOutsideChangeAt: EARLIER,
        },
      },
    });
    await model.methods.scan.execute({}, t.ctx);
    const inv = t.one("inventory");
    assertEquals(inv.error, "no inventory (exit 1)");
    assertEquals(inv.packagesHash, null);
    assertEquals(inv.packagesBaseline, HASH_G);
    assertEquals(inv.packagesChangedOutsidePatch, null);
    assertEquals(inv.lastOutsideChangeAt, EARLIER);
  });
});

Deno.test("scan: an osUpdater model's record has no hash, so its verdict is unknown and the baseline is carried", async () => {
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut("web1", collectorStdout()),
    FAKE_SWAMP_OSSCAN_1: resourceOut({
      packageManager: "pacman",
      updatesCount: 7,
      needsReboot: false,
    }),
  }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "web1" }, {
        host: "arch1",
        osUpdater: { model: "pacman-os" },
      }],
    }, {
      stored: {
        arch1: {
          packagesHash: HASH_B,
          packagesBaseline: HASH_G,
          lastOutsideChangeAt: EARLIER,
        },
      },
    });
    await model.methods.scan.execute({}, t.ctx);
    const arch = t.written("inventory").find((r) => r.name === "arch1")!.data;
    assertEquals(arch.updatesCount, 7);
    assertEquals(arch.packagesHash, null);
    assertEquals(arch.packagesChangedOutsidePatch, null);
    assertEquals(arch.packagesBaseline, HASH_G);
    assertEquals(arch.lastOutsideChangeAt, EARLIER);
  });
});

Deno.test("safeOsUpdate: a change made outside @dmc/patch before the update is flagged; the next scan does not flag the update's own change", async () => {
  const machines = [{ host: "web1" }];
  let inv: Record<string, unknown>;
  await withFake({
    ...osUpdateEnv(),
    FAKE_SWAMP_SCRIPT_1: scriptOut(
      "web1",
      collectorStdout({ schemaVersion: 5, packagesHash: HASH_B }),
    ),
    FAKE_SWAMP_SCRIPT_2: scriptOut(
      "web1",
      collectorStdout({
        schemaVersion: 5,
        updatesCount: 0,
        needsReboot: true,
        packagesHash: HASH_A,
      }),
    ),
  }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines }, {
      stored: {
        web1: {
          packagesHash: HASH_G,
          packagesBaseline: HASH_G,
          packagesChangedOutsidePatch: false,
          lastOutsideChangeAt: null,
        },
      },
    });
    await model.methods.safeOsUpdate.execute(
      model.methods.safeOsUpdate.arguments.parse({ host: "web1" }),
      t.ctx,
    );
    inv = t.one("inventory");
    assertEquals(inv.packagesChangedOutsidePatch, true);
    assertEquals(inv.packagesHash, HASH_A);
    assertEquals(inv.packagesBaseline, HASH_A);
    assert(typeof inv.lastOutsideChangeAt === "string");
  });
  // The next scan reads the state the update left behind (A): no flag, and the time stays.
  await withFake({
    FAKE_SWAMP_MODEL_GET: sshDefinition("ops", [{ name: "web1" }]),
    FAKE_SWAMP_SCRIPT_1: scriptOut(
      "web1",
      collectorStdout({ schemaVersion: 5, packagesHash: HASH_A }),
    ),
  }, async () => {
    const t = mkCtx({ sshModel: "ssh", machines }, {
      stored: { web1: inv },
    });
    await model.methods.scan.execute({}, t.ctx);
    const next = t.one("inventory");
    assertEquals(next.packagesChangedOutsidePatch, false);
    assertEquals(next.lastOutsideChangeAt, inv.lastOutsideChangeAt);
  });
});

Deno.test("safeOsUpdate: a rolled-back VM records the restored machine's hash, so the rollback does not flag", async () => {
  const server = startServer(() => 503);
  try {
    await withFake({
      ...osUpdateEnv(),
      // Run order: before scan (1), after scan (2), restored scan (1 again, the fake
      // cycles its two answers): the restored machine is in the before state.
      FAKE_SWAMP_SCRIPT_1: scriptOut(
        "web1",
        collectorStdout({ schemaVersion: 5, packagesHash: HASH_B }),
      ),
      FAKE_SWAMP_SCRIPT_2: scriptOut(
        "web1",
        collectorStdout({
          schemaVersion: 5,
          updatesCount: 0,
          needsReboot: true,
          packagesHash: HASH_A,
        }),
      ),
    }, async () => {
      const t = mkCtx({
        sshModel: "ssh",
        machines: [{
          host: "web1",
          vm: { proxmoxNode: "pve", vmid: 100 },
          health: [{ type: "http", url: server.url }],
        }],
      }, {
        stored: {
          web1: {
            packagesHash: HASH_B,
            packagesBaseline: HASH_B,
            packagesChangedOutsidePatch: false,
            lastOutsideChangeAt: null,
          },
        },
      });
      await model.methods.safeOsUpdate.execute(
        model.methods.safeOsUpdate.arguments.parse({
          host: "web1",
          healthGraceSec: 0,
        }),
        t.ctx,
      );
      assertEquals(t.one("osUpdate").outcome, "rolled-back");
      const inv = t.one("inventory");
      assertEquals(inv.packagesHash, HASH_B);
      assertEquals(inv.packagesBaseline, HASH_B);
      assertEquals(inv.packagesChangedOutsidePatch, false);
    });
  } finally {
    await server.stop();
  }
});

/** sha256 of a text as lowercase hex (the digest sha256sum prints). */
async function sha256Of(text: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Run collect_packages_hash from the bundled collector with a fake `dpkg-query` (a sh
 * body) first on PATH, and echo the hash the function set.
 */
async function runPackagesHash(dpkgQuery: string): Promise<string> {
  const dir = await Deno.makeTempDir();
  try {
    await Deno.writeTextFile(`${dir}/dpkg-query`, `#!/bin/sh\n${dpkgQuery}\n`);
    await Deno.chmod(`${dir}/dpkg-query`, 0o755);
    const body = fleet.COLLECTOR_SCRIPT.split("\n")
      .filter((l) => l !== "main </dev/null")
      .join("\n");
    const script = body + "\ncollect_packages_hash\necho \"H=$packages_hash\"\n";
    const out = await new Deno.Command("bash", {
      args: ["-c", script],
      env: { PATH: `${dir}:${Deno.env.get("PATH") ?? ""}` },
      stdout: "piped",
      stderr: "piped",
    }).output();
    return new TextDecoder().decode(out.stdout).trim();
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
}

Deno.test("collector: the packages hash is the sha256 of the manifest sorted in the C locale", async () => {
  // C-locale order puts "Apt" before "apt", and "apt" before "zlib".
  const h = await sha256Of("Apt\t9\napt\t2.0\nzlib\t1.2\n");
  assertEquals(
    await runPackagesHash(
      "printf 'zlib\\t1.2\\napt\\t2.0\\nApt\\t9\\n'",
    ),
    `H="${h}"`,
  );
});

Deno.test("collector: the packages hash is null when the manifest command fails, prints nothing, or fails part-way", async () => {
  assertEquals(await runPackagesHash("exit 1"), "H=null");
  assertEquals(await runPackagesHash("exit 0"), "H=null");
  assertEquals(
    await runPackagesHash("printf 'zlib\\t1.2\\n'; exit 1"),
    "H=null",
  );
});

Deno.test("collector: the manifest command is embedded verbatim, one source of truth with the model", () => {
  assertStringIncludes(fleet.COLLECTOR_SCRIPT, fleet.PKG_MANIFEST_CMD);
  assertStringIncludes(fleet.COLLECTOR_SCRIPT, '"packagesHash":%s');
});

// --- swamp-patch-docker: the runtime route (safeUpdate, pruneImages) ----------

const HELPER = "sudo -n '/usr/local/libexec/swamp-patch/swamp-patch-docker'";
const OLD_ID = `sha256:${"a".repeat(64)}`;
const NEW_ID = `sha256:${"b".repeat(64)}`;

/** The env that makes the ssh model log in to dock1 as `user`. */
function loginEnv(user: string): Env {
  return {
    FAKE_SWAMP_MODEL_GET: JSON.stringify({
      globalArguments: { hosts: [{ name: "dock1", transport: { user } }] },
    }),
  };
}

Deno.test("safeUpdate: a non-root login runs docker only through swamp-patch-docker, for the project named by composePath", async () => {
  const server = startServer(() => 200);
  try {
    await withCallLog({
      ...loginEnv("swamp-patch"),
      FAKE_SWAMP_INSPECT_1: execOut(`abc123def456|nginx:1|${OLD_ID}|running|none\n`),
      FAKE_SWAMP_INSPECT_2: execOut(`abc123def456|nginx:1|${NEW_ID}|running|none\n`),
      FAKE_SWAMP_EXEC: execOut(""),
    }, async (calls) => {
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
      const lines = await calls();
      assertEquals(t.one("update").outcome, "updated");
      assert(
        lines.some((l) => l.includes(`${HELPER} 'inspect' 'app'`)),
        "the snapshot goes through inspect",
      );
      assert(
        lines.some((l) => l.includes(`${HELPER} 'update' 'app'`)),
        "the pull and up go through update",
      );
      assert(
        !lines.some((l) => /docker (compose|inspect|tag|rmi) /.test(l)),
        "no direct docker call",
      );
    });
  } finally {
    await server.stop();
  }
});

Deno.test("safeUpdate: a rollback through the helper restores each old image by its ref and id", async () => {
  const server = startServer(() => 503);
  try {
    await withCallLog({
      ...loginEnv("swamp-patch"),
      FAKE_SWAMP_INSPECT_1: execOut(`abc123def456|nginx:1|${OLD_ID}|running|none\n`),
      FAKE_SWAMP_INSPECT_2: execOut(`abc123def456|nginx:1|${NEW_ID}|running|none\n`),
      FAKE_SWAMP_EXEC: execOut(""),
    }, async (calls) => {
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
      assertEquals(t.one("update").outcome, "rolled-back");
      const lines = await calls();
      assert(
        lines.some((l) =>
          l.includes(`${HELPER} 'restore' 'app' 'nginx:1' '${OLD_ID}'`)
        ),
        "the rollback names the old image id",
      );
      assert(!lines.some((l) => l.includes("docker tag ")), "no direct tag");
    });
  } finally {
    await server.stop();
  }
});

Deno.test("safeUpdate: a root login keeps the direct docker commands and never calls the helper", async () => {
  const server = startServer(() => 200);
  try {
    await withCallLog({
      ...loginEnv("root"),
      FAKE_SWAMP_PS: execOut("abc123def456\n"),
      FAKE_SWAMP_INSPECT_1: execOut(`nginx:1|${OLD_ID}|running|none\n`),
      FAKE_SWAMP_INSPECT_2: execOut(`nginx:1|${NEW_ID}|running|none\n`),
      FAKE_SWAMP_EXEC: execOut(""),
    }, async (calls) => {
      const t = mkCtx({
        sshModel: "ssh",
        machines: [dockerMachine(server.url)],
      });
      await model.methods.safeUpdate.execute(
        model.methods.safeUpdate.arguments.parse({ host: "dock1" }),
        t.ctx,
      );
      assertEquals(t.one("update").outcome, "updated");
      const lines = await calls();
      assert(lines.some((l) => l.includes("docker compose ps -q web")));
      assert(
        !lines.some((l) => l.includes("swamp-patch-docker")),
        "a root login does not use the helper",
      );
    });
  } finally {
    await server.stop();
  }
});

Deno.test("safeUpdate: a non-root login needs a composePath, and a service override is refused, before any docker call", async () => {
  await withCallLog(loginEnv("swamp-patch"), async (calls) => {
    const noPath = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "dock1", docker: { service: "web" } }],
    });
    await assertRejects(
      () =>
        model.methods.safeUpdate.execute(
          model.methods.safeUpdate.arguments.parse({ host: "dock1" }),
          noPath.ctx,
        ),
      Error,
      "has no docker composePath",
    );
    const override = mkCtx({
      sshModel: "ssh",
      machines: [dockerMachine("http://127.0.0.1:1/")],
    });
    await assertRejects(
      () =>
        model.methods.safeUpdate.execute(
          model.methods.safeUpdate.arguments.parse({
            host: "dock1",
            service: "worker",
          }),
          override.ctx,
        ),
      Error,
      "service override (worker)",
    );
    assertEquals(await calls(), []);
  });
});

Deno.test("pruneImages: a non-root login checks the host with ps and removes the image with prune", async () => {
  await withCallLog({ ...loginEnv("swamp-patch"), FAKE_SWAMP_EXEC: execOut("") }, async (calls) => {
    const t = mkCtx(PRUNE_FLEET, { data: { image: [imageDatum("i-1")] } });
    await model.methods.pruneImages.execute(
      model.methods.pruneImages.arguments.parse({}),
      t.ctx,
    );
    assertEquals((t.one("prune").pruned as unknown[]).length, 1);
    const lines = await calls();
    assert(lines.some((l) => l.includes(`${HELPER} 'ps' 'app'`)));
    assert(lines.some((l) => l.includes(`${HELPER} 'prune' '${IMAGE.imageId}'`)));
    assert(!lines.some((l) => l.includes("docker rmi")), "no direct rmi");
  });
});

Deno.test("pruneImages: a root login keeps docker rmi, and an image id the helper would refuse is kept", async () => {
  await withCallLog({ ...loginEnv("root"), FAKE_SWAMP_EXEC: execOut("") }, async (calls) => {
    const root = mkCtx(PRUNE_FLEET, { data: { image: [imageDatum("i-1")] } });
    await model.methods.pruneImages.execute(
      model.methods.pruneImages.arguments.parse({}),
      root.ctx,
    );
    assert((await calls()).some((l) => l.includes(`docker rmi ${IMAGE.imageId}`)));
  });
  await withCallLog({ ...loginEnv("swamp-patch"), FAKE_SWAMP_EXEC: execOut("") }, async () => {
    const bad = mkCtx(PRUNE_FLEET, {
      data: { image: [imageDatum("i-2", { imageId: "sha256:short" })] },
    });
    await model.methods.pruneImages.execute(
      model.methods.pruneImages.arguments.parse({}),
      bad.ctx,
    );
    assertEquals(t_kept(bad.one("prune")), [{
      host: "dock1",
      name: "nginx:1",
      reason: "the image id is not one swamp-patch-docker accepts",
    }]);
  });
});

/** The kept list of a prune record, as the assertions above compare it. */
function t_kept(prune: Record<string, unknown>) {
  return prune.kept;
}

Deno.test("helperLine: sudo -n, the helper's path, then each word shell-quoted; a refused value throws", () => {
  assertEquals(
    fleet.helperLine("ps", "app"),
    "sudo -n '/usr/local/libexec/swamp-patch/swamp-patch-docker' 'ps' 'app'",
  );
  assertEquals(
    fleet.helperLine("prune", IMAGE.imageId),
    `sudo -n '/usr/local/libexec/swamp-patch/swamp-patch-docker' 'prune' '${IMAGE.imageId}'`,
  );
  assertThrows(() => fleet.helperLine("ps", "a;id"), Error, "project name");
  assertThrows(() => fleet.helperLine("prune", "sha256:short"), Error, "sha256:");
});

Deno.test("parseInspectRows: keeps the container rows, and skips docker's own lines", () => {
  const out = [
    "docker warning: the attribute version is obsolete",
    "abc123def456|nginx:1|sha256:x|running|healthy",
    "",
    "not a row",
  ].join("\n");
  assertEquals(fleet.parseInspectRows(out), [{
    ref: "nginx:1",
    imageId: "sha256:x",
    status: "running",
    health: "healthy",
  }]);
});

Deno.test("accessTargets: a docker machine gets its compose project and the helper grant, whatever its OS policy", () => {
  const { targets } = fleet.accessTargets({
    sshModel: "ssh",
    access: ACCESS,
    machines: [
      {
        host: "dock",
        docker: { composePath: "/srv/app", service: "web" },
        osUpdatePolicy: "scan-only",
      },
      { host: "bare", docker: { service: "web" } },
      { host: "plain" },
    ],
  } as never);
  const by = Object.fromEntries(targets.map((t) => [t.host, t.input]));
  assertEquals(by.dock.sudo, { osUpgrade: false, reboot: false, docker: true });
  assertEquals(by.dock.dockerProjects, [{
    name: "app",
    composeDir: "/srv/app",
    service: "web",
  }]);
  // A docker block without a composePath has no project to run.
  assertEquals(by.bare.dockerProjects, []);
  assertEquals(by.bare.sudo.docker, true);
  assertEquals(by.plain.docker, false);
  assertEquals(by.plain.sudo.docker, false);
  assertEquals(by.plain.dockerProjects, []);
});

// ---------------------------------------------------------------------------
// Plug-in privileges: pluginPrivilegesFor, the access methods, the check, the guard
// ---------------------------------------------------------------------------

/** A privileges declaration as a plug-in's resource attributes. */
function privs(
  commands: unknown[] = [],
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return { commands, helpers: [], remoteCode: false, ...extra };
}

/**
 * A SwampApi that answers privileges per model: an object is the declaration, null a run
 * that fails. It records every call.
 */
function privilegesSwamp(answers: Record<string, unknown>) {
  const calls: string[] = [];
  const api: SwampApi = {
    run: (m, method, args) => {
      calls.push(`${m} ${method} ${JSON.stringify(args ?? {})}`);
      const a = answers[m];
      return Promise.resolve(
        a === null || a === undefined
          ? { ok: false, artifacts: [], error: "Unknown method: privileges" }
          : { ok: true, artifacts: [a as Record<string, unknown>], error: "" },
      );
    },
    globalArguments: () => Promise.resolve(null),
  };
  return { api, calls };
}

const REMOTE = "acme/updater@v1.2.3";

Deno.test("pluggedModels: the updater that runs (source, else the legacy proxmox), the osUpdater, the snapshotter; one entry per model", () => {
  assertEquals(fleet.pluggedModels({ host: "a" }), []);
  assertEquals(
    fleet.pluggedModels({
      host: "a",
      source: { model: "app" },
      proxmox: { model: "legacy" },
      osUpdater: { model: "os" },
      snapshotter: { model: "snap" },
    }),
    [
      { model: "app", roles: ["updater"] },
      { model: "os", roles: ["osUpdater"] },
      { model: "snap", roles: ["snapshotter"] },
    ],
  );
  assertEquals(
    fleet.pluggedModels({
      host: "a",
      proxmox: { model: "legacy" },
      osUpdater: { model: "legacy" },
    }),
    [{ model: "legacy", roles: ["updater", "osUpdater"] }],
  );
});

Deno.test("pluginPrivilegesFor: asks each distinct model once with the host, and numbers the ids across models", async () => {
  const { api, calls } = privilegesSwamp({
    app: privs([{ argv: ["myapp-update", "-y"] }]),
    snap: privs([{ argv: ["/opt/snap/bin/take"] }, {
      argv: ["snapctl", "ls"],
    }]),
  });
  const p = await fleet.pluginPrivilegesFor({
    host: "web1",
    source: { model: "app" },
    osUpdater: { model: "app" },
    snapshotter: { model: "snap" },
  }, api);
  assertEquals(calls, [
    'app privileges {"host":"web1"}',
    'snap privileges {"host":"web1"}',
  ]);
  assertEquals(p.errors, []);
  assertEquals(p.acceptedRisksUsed, []);
  assertEquals(p.commands.map((c) => c.id), [
    "plugin-1-app",
    "plugin-2-snap",
    "plugin-3-snap",
  ]);
  assertEquals(p.commands[1].args, []);
});

Deno.test("pluginPrivilegesFor: an updater or osUpdater must declare, unless unsafe.privilegedUpdater; a snapshotter always", async () => {
  const none = privilegesSwamp({});
  // No declaration, no record: refused, for each role.
  for (
    const m of [
      { host: "a", source: { model: "app" } },
      { host: "a", proxmox: { model: "app" } },
      { host: "a", osUpdater: { model: "app" } },
      { host: "a", snapshotter: { model: "app" } },
    ]
  ) {
    const p = await fleet.pluginPrivilegesFor(m, none.api);
    assertEquals(p.errors.length, 1, JSON.stringify(m));
    assertStringIncludes(p.errors[0], 'privileges of "app" did not run');
  }
  // With the record, an updater and an osUpdater are excused: nothing granted, risk used.
  for (
    const m of [
      { host: "a", source: { model: "app" } },
      { host: "a", osUpdater: { model: "app" } },
    ]
  ) {
    const p = await fleet.pluginPrivilegesFor(
      { ...m, unsafe: { privilegedUpdater: RECORD } },
      none.api,
    );
    assertEquals(p.errors, []);
    assertEquals(p.commands, []);
    assertEquals(p.acceptedRisksUsed, ["unsafe.privilegedUpdater"]);
  }
  // A malformed declaration is excused the same way.
  const bad = privilegesSwamp({ app: privs([{ argv: ["bash"] }]) });
  assertEquals(
    (await fleet.pluginPrivilegesFor({
      host: "a",
      source: { model: "app" },
      unsafe: { privilegedUpdater: RECORD },
    }, bad.api)).acceptedRisksUsed,
    ["unsafe.privilegedUpdater"],
  );
  // The record never excuses a snapshotter, nor a model that is also the snapshotter.
  for (
    const m of [
      { host: "a", snapshotter: { model: "app" } },
      { host: "a", source: { model: "app" }, snapshotter: { model: "app" } },
    ]
  ) {
    const p = await fleet.pluginPrivilegesFor(
      { ...m, unsafe: { privilegedUpdater: RECORD } },
      none.api,
    );
    assertEquals(p.errors.length, 1, JSON.stringify(m));
  }
  // A declaration that works does not use the record.
  const ok = privilegesSwamp({ app: privs() });
  assertEquals(
    (await fleet.pluginPrivilegesFor({
      host: "a",
      source: { model: "app" },
      unsafe: { privilegedUpdater: RECORD },
    }, ok.api)).acceptedRisksUsed,
    [],
  );
  // An API snapshotter declares no commands and passes.
  const api = await fleet.pluginPrivilegesFor(
    { host: "a", snapshotter: { model: "app" } },
    ok.api,
  );
  assertEquals(api.errors, []);
  assertEquals(api.commands, []);
});

Deno.test("pluginPrivilegesFor: remote code needs a trustRemote record with the same source, with or without the unsafe record", async () => {
  const remote = privilegesSwamp({
    app: privs([], { remoteCode: true, remoteSources: [REMOTE] }),
  });
  const base = { host: "a", source: { model: "app" } };
  const trusted = await fleet.pluginPrivilegesFor(
    { ...base, trustRemote: [{ ...RECORD, source: REMOTE }] },
    remote.api,
  );
  assertEquals(trusted.errors, []);
  assertEquals(trusted.acceptedRisksUsed, [`trustRemote:${REMOTE}`]);
  assertEquals(trusted.remote, [{ model: "app", source: REMOTE }]);
  for (
    const m of [
      base,
      { ...base, trustRemote: [{ ...RECORD, source: "acme/updater@main" }] },
      { ...base, unsafe: { privilegedUpdater: RECORD } },
    ]
  ) {
    const p = await fleet.pluginPrivilegesFor(m, remote.api);
    assertEquals(p.errors.length, 1, JSON.stringify(m));
    assertStringIncludes(p.errors[0], `runs remote code from ${REMOTE}`);
    assertEquals(p.acceptedRisksUsed, []);
  }
  // An answer that does not parse but claims remote code is not excused by the unsafe record.
  const claim = privilegesSwamp({
    app: { remoteCode: true, remoteSource: REMOTE, commands: "x" },
  });
  const p = await fleet.pluginPrivilegesFor(
    { ...base, unsafe: { privilegedUpdater: RECORD } },
    claim.api,
  );
  assertEquals(p.errors.length, 1);
  assertStringIncludes(p.errors[0], "runs remote code");
});

Deno.test("pluginPrivilegesFor: each remote source needs its own trustRemote record", async () => {
  const CORE = "acme/core@main";
  const remote = privilegesSwamp({
    app: privs([], { remoteCode: true, remoteSources: [REMOTE, CORE] }),
  });
  const base = { host: "a", source: { model: "app" } };
  const both = await fleet.pluginPrivilegesFor({
    ...base,
    trustRemote: [{ ...RECORD, source: REMOTE }, { ...RECORD, source: CORE }],
  }, remote.api);
  assertEquals(both.errors, []);
  assertEquals(both.acceptedRisksUsed, [
    `trustRemote:${REMOTE}`,
    `trustRemote:${CORE}`,
  ]);
  assertEquals(both.remote, [
    { model: "app", source: REMOTE },
    { model: "app", source: CORE },
  ]);
  // One record is not enough: the error names the source with no record, and nothing is used.
  const one = await fleet.pluginPrivilegesFor(
    { ...base, trustRemote: [{ ...RECORD, source: REMOTE }] },
    remote.api,
  );
  assertEquals(one.errors, [
    `"app" runs remote code from ${CORE}, but the machine has no trustRemote record with that source`,
  ]);
  assertEquals(one.acceptedRisksUsed, []);
  assertEquals(one.remote, []);
  const none = await fleet.pluginPrivilegesFor(base, remote.api);
  assertStringIncludes(none.errors[0], `${REMOTE}, ${CORE}`);
  assertStringIncludes(none.errors[0], "those sources");
});

Deno.test("remoteClaim: an answer that does not parse still claims every source it names", () => {
  assertEquals(fleet.remoteClaim(null), []);
  assertEquals(
    fleet.remoteClaim({ remoteCode: false, remoteSources: ["a/b@1"] }),
    [],
  );
  assertEquals(
    fleet.remoteClaim({ remoteCode: true, remoteSources: ["a/b@1", "a/c@1"] }),
    ["a/b@1", "a/c@1"],
  );
  assertEquals(
    fleet.remoteClaim({ remoteCode: true, remoteSources: ["a/b@1", 7] }),
    ["a/b@1", "(unnamed)"],
  );
  assertEquals(
    fleet.remoteClaim({ remoteCode: true, remoteSources: "a/b@1" }),
    ["(unnamed)"],
  );
  assertEquals(fleet.remoteClaim({ remoteCode: true, remoteSource: "a/b@1" }), [
    "a/b@1",
  ]);
  assertEquals(fleet.remoteClaim({ remoteCode: true }), ["(unnamed)"]);
  assertEquals(fleet.remoteClaim({ remoteCode: true, remoteSources: [] }), [
    "(unnamed)",
  ]);
});

Deno.test("privilegesForRoles: keeps only the models of the roles a method uses", async () => {
  const { api } = privilegesSwamp({ snap: privs() });
  const p = await fleet.pluginPrivilegesFor({
    host: "a",
    source: { model: "app" },
    snapshotter: { model: "snap" },
  }, api);
  assertEquals(p.errors.length, 1);
  assertEquals(fleet.privilegesForRoles(p, ["snapshotter"]).errors, []);
  assertEquals(fleet.privilegesForRoles(p, ["updater"]).errors.length, 1);
});

const PLUGIN_FLEET = {
  sshModel: "ssh",
  access: ACCESS,
  machines: [
    { host: "web1", source: { model: "good-app" } },
    { host: "web2", source: { model: "bad-app" } },
  ],
};
const PLUGIN_ENV: Env = {
  FAKE_SWAMP_MODEL_GET: sshDefinition("root", [{ name: "web1" }, {
    name: "web2",
  }]),
  FAKE_SWAMP_PRIVS__good_app: resourceOut(
    privs([
      { argv: ["/opt/app/bin/reload"] },
      { argv: ["appctl", "sync"], env: { APP_MODE: "batch" } },
    ]),
  ),
  FAKE_SWAMP_PRIVS_RC__bad_app: "1",
};

Deno.test("access: provisionAccess refuses a machine whose plug-in does not declare, and still provisions the clean one with its plug-in grants", async () => {
  await withCallLog({
    ...PLUGIN_ENV,
    FAKE_SWAMP_SCRIPT_1: scriptRunsOut([{
      host: "web1",
      stdout: provisionOk(),
    }]),
  }, async (calls) => {
    const t = mkCtx(PLUGIN_FLEET);
    await assertRejects(
      () => model.methods.provisionAccess.execute({ dryRun: false }, t.ctx),
      Error,
      "web2 (refused-preflight)",
    );
    const runs = accessRunsByHost(t);
    assertEquals(runs.get("web1")?.outcome, "applied");
    assertEquals(runs.get("web2")?.outcome, "refused-preflight");
    assertEquals(runs.get("web2")?.ok, false);
    assertStringIncludes(
      String(runs.get("web2")?.detail),
      'plug-in privileges: privileges of "bad-app" did not run',
    );
    // Only web1 got a plan and a script call; web2 was never contacted.
    assertEquals(t.written("accessPlan").map((p) => p.name), [
      "access-plan-web1",
    ]);
    const scriptCalls = (await calls()).filter((c) => c.startsWith("prov "));
    assertEquals(scriptCalls.length, 1);
    assert(!scriptCalls[0].includes("web2"));
    const script = String(
      (t.written("accessPlan")[0].data as Record<string, unknown>)
        .provisionScript,
    );
    assertStringIncludes(
      script,
      `plugin_grant plugin-1-good-app '@/opt/app/bin/reload@ ""'`,
    );
    assertStringIncludes(
      script,
      `plugin_grant plugin-2-good-app '@env@ APP_MODE\\=batch @appctl@ sync'`,
    );
  });
});

Deno.test("access: a provisionAccess dry run also refuses the machine whose plug-in does not declare", async () => {
  await withCallLog(PLUGIN_ENV, async () => {
    const t = mkCtx(PLUGIN_FLEET);
    await assertRejects(
      () => model.methods.provisionAccess.execute({ dryRun: true }, t.ctx),
      Error,
      "web2 (refused-preflight)",
    );
    const runs = accessRunsByHost(t);
    assertEquals(runs.get("web1")?.outcome, "dry-run");
    assertEquals(runs.get("web2")?.outcome, "refused-preflight");
  });
});

Deno.test("access: renderAccess writes the clean plans, then fails naming the refused machine", async () => {
  await withCallLog(PLUGIN_ENV, async () => {
    const t = mkCtx(PLUGIN_FLEET);
    await assertRejects(
      () => model.methods.renderAccess.execute({}, t.ctx),
      Error,
      'plug-in privileges refused on web2 (privileges of "bad-app" did not run',
    );
    assertEquals(t.written("accessPlan").map((p) => p.name), [
      "access-plan-web1",
    ]);
  });
});

Deno.test("auditAccess: the accessAudit record carries the plug-in grants the host is expected to have", async () => {
  await withCallLog({
    ...auditEnv(sshDefinition("root", [{ name: "web1" }]), [{ host: "web1" }]),
    FAKE_SWAMP_PRIVS__good_app: PLUGIN_ENV.FAKE_SWAMP_PRIVS__good_app,
  }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      access: ACCESS,
      machines: [{ host: "web1", source: { model: "good-app" } }],
    });
    await model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), t.ctx);
    assertEquals(auditOf(t, "web1").pluginGrants, [
      '@/opt/app/bin/reload@ ""',
      "@env@ APP_MODE\\=batch @appctl@ sync",
    ]);
  });
});

Deno.test("privileges-declared: passes without plugged models and for a declaring plug-in; fails naming the host, with the skip flags", async () => {
  await withFake(PLUGIN_ENV, async () => {
    assertEquals(
      await runCheck(
        "privileges-declared",
        checkCtx(PLUGIN_FLEET, "safeOsUpdate", { host: "web1" }),
      ),
      { pass: true },
    );
    assertEquals(
      await runCheck(
        "privileges-declared",
        checkCtx(
          { sshModel: "ssh", machines: [{ host: "bare" }] },
          "safeOsUpdate",
          { host: "bare" },
        ),
      ),
      { pass: true },
    );
    const r = await runCheck(
      "privileges-declared",
      checkCtx(PLUGIN_FLEET, "safeOsUpdate", { host: "web2" }),
    );
    assertEquals(r.pass, false);
    assertStringIncludes(String(r.errors), 'web2: privileges of "bad-app"');
    assertStringIncludes(String(r.errors), "--skip-check privileges-declared");
    // rollback uses only the snapshotter: web2's updater does not matter there.
    assertEquals(
      await runCheck(
        "privileges-declared",
        checkCtx(PLUGIN_FLEET, "rollback", { host: "web2" }),
      ),
      { pass: true },
    );
    // The access methods check every selected machine; a hosts filter narrows them.
    const all = await runCheck(
      "privileges-declared",
      checkCtx(PLUGIN_FLEET, "provisionAccess"),
    );
    assertEquals(all.pass, false);
    assertStringIncludes(String(all.errors), "web2:");
    assertEquals(
      await runCheck(
        "privileges-declared",
        checkCtx(PLUGIN_FLEET, "provisionAccess", { hosts: ["web1"] }),
      ),
      { pass: true },
    );
  });
});

Deno.test("safeOsUpdate: a remote-code updater without trustRemote is refused before any contact", async () => {
  await withCallLog({
    ...osModelEnv(),
    FAKE_SWAMP_PRIVS__app: resourceOut(
      privs([], { remoteCode: true, remoteSources: [REMOTE] }),
    ),
  }, async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{
        host: "arch1",
        source: { model: "app" },
        osUpdater: { model: "pacman-os" },
      }],
    });
    await assertRejects(
      () =>
        model.methods.safeOsUpdate.execute(
          model.methods.safeOsUpdate.arguments.parse({ host: "arch1" }),
          t.ctx,
        ),
      Error,
      `refused: plug-in privileges: "app" runs remote code from ${REMOTE}`,
    );
    assertEquals(
      (await calls()).map((c) => c.split(" ").slice(0, 2).join(" ")),
      ["app privileges", "pacman-os privileges"],
    );
    assertEquals(t.written("osUpdate").length, 0);
  });
});

Deno.test("safeOsUpdate: the run record and the inventory list the accepted risks the plug-ins used", async () => {
  await withCallLog({
    ...osModelEnv(),
    FAKE_SWAMP_PRIVS__app: resourceOut(
      privs([], { remoteCode: true, remoteSources: [REMOTE] }),
    ),
    FAKE_SWAMP_PRIVS_RC__pacman_os: "1",
  }, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{
        host: "arch1",
        source: { model: "app" },
        osUpdater: { model: "pacman-os" },
        unsafe: { privilegedUpdater: RECORD },
        trustRemote: [{ ...RECORD, source: REMOTE }],
      }],
    });
    await model.methods.safeOsUpdate.execute(
      model.methods.safeOsUpdate.arguments.parse({ host: "arch1" }),
      t.ctx,
    );
    const run = t.written("run")[0].data as Record<string, unknown>;
    assertEquals(run.acceptedRisksUsed, [
      `trustRemote:${REMOTE}`,
      "unsafe.privilegedUpdater",
    ]);
    const inv = t.one("inventory");
    assertEquals(inv.acceptedRisksUsed, [
      `trustRemote:${REMOTE}`,
      "unsafe.privilegedUpdater",
    ]);
  });
});

// ---------------------------------------------------------------------------
// Privileged health checks: the schema, healthPrivilegesFor, the privileges-declared check,
// evalHealth, and the reboot and safeOsUpdate refusals
// ---------------------------------------------------------------------------

/** The schema's issue messages for one health check, joined; empty when it parses. */
function healthIssues(check: unknown): string {
  const r = model.globalArguments.safeParse({
    sshModel: "ssh",
    machines: [{ host: "h", health: [check] }],
  });
  return r.success ? "" : r.error.issues.map((i) => i.message).join("; ");
}

Deno.test("schema: a privileged health check takes argv and no run", () => {
  const m = parseMachine({
    host: "h",
    health: [{
      type: "command",
      privileged: true,
      argv: ["myhealth", "--quiet"],
    }],
  });
  assertEquals(m.health[0], {
    type: "command",
    privileged: true,
    argv: ["myhealth", "--quiet"],
    timeoutSec: 30,
  });
});

Deno.test("schema: a privileged check needs argv, and runs argv rather than a run command", () => {
  assertStringIncludes(
    healthIssues({ type: "command", privileged: true }),
    "a privileged check needs argv",
  );
  assertStringIncludes(
    healthIssues({
      type: "command",
      privileged: true,
      argv: ["myhealth"],
      run: "true",
    }),
    "a privileged check runs argv, not a shell command",
  );
});

Deno.test("schema: argv is only for a privileged check, and a plain run check still parses", () => {
  assertStringIncludes(
    healthIssues({ type: "command", run: "true", argv: ["myhealth"] }),
    "argv is only for a privileged check",
  );
  assertEquals(healthIssues({ type: "command", run: "true" }), "");
});

Deno.test("healthPrivilegesFor: null without privileged checks", () => {
  assertEquals(fleet.healthPrivilegesFor(parseMachine({ host: "h" })), null);
  assertEquals(
    fleet.healthPrivilegesFor(parseMachine({
      host: "h",
      health: [
        { type: "command", run: "true" },
        { type: "http", url: "http://h.example/health" },
      ],
    })),
    null,
  );
});

Deno.test("healthPrivilegesFor: no record is one error naming the checks, with no commands and no accepted risk", () => {
  const m = parseMachine({
    host: "h",
    health: [
      { type: "command", run: "true" },
      { type: "command", privileged: true, argv: ["myhealth"] },
      {
        type: "command",
        label: "second",
        privileged: true,
        argv: ["/usr/sbin/other"],
      },
    ],
  });
  assertEquals(fleet.healthPrivilegesFor(m), {
    model: "health checks",
    roles: ["health"],
    commands: [],
    errors: [
      'health checks: health[1], "second" are privileged, but the machine has no unsafe.privilegedHealth acceptance record',
    ],
    acceptedRisksUsed: [],
    remote: [],
  });
});

Deno.test("healthPrivilegesFor: with the record, each privileged check is a plug-in command numbered from first", () => {
  const m = parseMachine({
    host: "h",
    unsafe: PRIV_HEALTH_OK,
    health: [
      { type: "command", run: "true" },
      { type: "command", privileged: true, argv: ["myhealth", "--quiet"] },
      { type: "command", privileged: true, argv: ["/usr/sbin/other"] },
    ],
  });
  const e = fleet.healthPrivilegesFor(m);
  assertEquals(e?.errors, []);
  assertEquals(e?.commands, [
    {
      id: "plugin-1-health",
      capability: "plugin",
      family: "plugin",
      bin: "myhealth",
      args: ["--quiet"],
    },
    {
      id: "plugin-2-health",
      capability: "plugin",
      family: "plugin",
      bin: "/usr/sbin/other",
      args: [],
    },
  ]);
  assertEquals(e?.acceptedRisksUsed, ["unsafe.privilegedHealth"]);
  assertEquals(
    fleet.healthPrivilegesFor(m, 5)?.commands.map((c) => c.id),
    ["plugin-5-health", "plugin-6-health"],
  );
});

Deno.test("healthPrivilegesFor: one bad argv refuses every privileged check, and names the bad one", () => {
  const m = parseMachine({
    host: "h",
    unsafe: PRIV_HEALTH_OK,
    health: [
      { type: "command", privileged: true, argv: ["myhealth"] },
      { type: "command", privileged: true, argv: ["bash", "-c", "true"] },
    ],
  });
  const e = fleet.healthPrivilegesFor(m);
  assertEquals(e?.errors.length, 1);
  assertStringIncludes(
    e?.errors[0] ?? "",
    "health checks: health[1]: argv[0]: bash may not run as root",
  );
  assertEquals(e?.commands, []);
  assertEquals(e?.acceptedRisksUsed, []);
});

Deno.test("healthPrivilegesFor: at most 16 privileged checks; a 17th is one error, with no commands", () => {
  const health = (n: number) =>
    Array.from({ length: n }, (_, i) => ({
      type: "command",
      privileged: true,
      argv: [`check${i}`],
    }));
  assertEquals(
    fleet.healthPrivilegesFor(
      parseMachine({ host: "h", unsafe: PRIV_HEALTH_OK, health: health(16) }),
    )?.errors,
    [],
  );
  const e = fleet.healthPrivilegesFor(
    parseMachine({ host: "h", unsafe: PRIV_HEALTH_OK, health: health(17) }),
  );
  assertEquals(e?.errors, [
    "health checks: at most 16 privileged checks per machine",
  ]);
  assertEquals(e?.commands, []);
  assertEquals(e?.acceptedRisksUsed, []);
});

Deno.test("pluginPrivilegesFor: a machine with only privileged checks has one model entry, and asks no plug-in", async () => {
  const { api, calls } = privilegesSwamp({});
  const p = await fleet.pluginPrivilegesFor({
    host: "h",
    unsafe: PRIV_HEALTH_OK,
    health: [{ type: "command", privileged: true, argv: ["myhealth"] }],
  }, api);
  assertEquals(calls, []);
  assertEquals(p.errors, []);
  assertEquals(p.models.map((x) => x.model), ["health checks"]);
  assertEquals(p.commands.map((c) => c.id), ["plugin-1-health"]);
  assertEquals(p.acceptedRisksUsed, ["unsafe.privilegedHealth"]);
});

Deno.test("pluginPrivilegesFor: the health ids continue after a plugged model's commands", async () => {
  const { api, calls } = privilegesSwamp({
    app: privs([
      { argv: ["myapp-update", "-y"] },
      { argv: ["myapp-ctl", "sync"] },
    ]),
  });
  const p = await fleet.pluginPrivilegesFor({
    host: "web1",
    source: { model: "app" },
    unsafe: PRIV_HEALTH_OK,
    health: [{ type: "command", privileged: true, argv: ["myhealth"] }],
  }, api);
  assertEquals(calls, ['app privileges {"host":"web1"}']);
  assertEquals(p.errors, []);
  assertEquals(p.commands.map((c) => c.id), [
    "plugin-1-app",
    "plugin-2-app",
    "plugin-3-health",
  ]);
  assertEquals(p.models.map((x) => x.model), ["app", "health checks"]);
  assertEquals(p.acceptedRisksUsed, ["unsafe.privilegedHealth"]);
});

Deno.test("privileges-declared: a privileged check without its record fails for safeOsUpdate and provisionAccess, and passes with it", async () => {
  const check = {
    type: "command",
    label: "myhealth",
    privileged: true,
    argv: ["myhealth"],
  };
  const bare = {
    sshModel: "ssh",
    machines: [{ host: "hc1", health: [check] }],
  };
  const recorded = {
    sshModel: "ssh",
    machines: [{ host: "hc1", unsafe: PRIV_HEALTH_OK, health: [check] }],
  };
  for (const method of ["safeOsUpdate", "provisionAccess"]) {
    const r = await runCheck(
      "privileges-declared",
      checkCtx(bare, method, { host: "hc1" }),
    );
    assertEquals(r.pass, false, method);
    assertStringIncludes(
      String(r.errors),
      'hc1: health checks: "myhealth" is privileged, but the machine has no unsafe.privilegedHealth acceptance record',
    );
    assertEquals(
      await runCheck(
        "privileges-declared",
        checkCtx(recorded, method, { host: "hc1" }),
      ),
      { pass: true },
    );
  }
});

Deno.test("evalHealth: a privileged check without its record is refused, and no script runs", async () => {
  await withCallLog({}, async (calls) => {
    const m = parseMachine({
      host: "a",
      health: [{
        type: "command",
        label: "myhealth",
        privileged: true,
        argv: ["myhealth"],
      }],
    });
    const res = await fleet.evalHealth(m, m.health, "ssh", CLI);
    assertEquals(res.healthy, false);
    assertEquals(res.results, [{
      label: "myhealth",
      ok: false,
      detail:
        "refused: a privileged check needs an unsafe.privilegedHealth acceptance record",
    }]);
    assertEquals(await calls(), []);
  });
});

Deno.test("evalHealth: a refused privileged check is left out of the batch that runs the other checks", async () => {
  await withCallLog({ FAKE_SWAMP_HC: hcOut("a", 0) }, async (calls) => {
    const m = parseMachine({
      host: "a",
      health: [
        { type: "command", label: "plain", run: "true" },
        {
          type: "command",
          label: "myhealth",
          privileged: true,
          argv: ["myhealth"],
        },
      ],
    });
    const res = await fleet.evalHealth(m, m.health, "ssh", CLI);
    assertEquals(res.results, [
      { label: "plain", ok: true, detail: "rc 0" },
      {
        label: "myhealth",
        ok: false,
        detail:
          "refused: a privileged check needs an unsafe.privilegedHealth acceptance record",
      },
    ]);
    const all = await calls();
    assertEquals(all.length, 1);
    assertStringIncludes(all[0], "true");
    assert(!all[0].includes("myhealth"), all[0]);
  });
});

Deno.test("evalHealth: with the record, a privileged check runs its argv through sudo -n, and each check keeps its own rc", async () => {
  await withCallLog({ FAKE_SWAMP_HC: hcOut("a", 0, 3) }, async (calls) => {
    const m = parseMachine({
      host: "a",
      unsafe: PRIV_HEALTH_OK,
      health: [
        {
          type: "command",
          privileged: true,
          argv: ["myhealth", "--quiet", "--max-age=60"],
        },
        { type: "command", label: "plain", run: "exit 3" },
      ],
    });
    const res = await fleet.evalHealth(m, m.health, "ssh", CLI);
    assertEquals(res.healthy, false);
    assertEquals(res.results, [
      {
        label: "privileged: myhealth --quiet --max-age=60",
        ok: true,
        detail: "rc 0",
      },
      { label: "plain", ok: false, detail: "rc 3" },
    ]);
    const all = await calls();
    assertEquals(all.length, 1);
    assertStringIncludes(all[0], 'SUDO="sudo -n"');
    assertStringIncludes(all[0], "abs_cmd() {");
    assertStringIncludes(
      all[0],
      'BIN_MYHEALTH="$(abs_cmd myhealth)" || exit 3',
    );
    assertStringIncludes(all[0], '$SUDO "$BIN_MYHEALTH" --quiet --max-age=60');
    assertStringIncludes(all[0], "exit 3");
  });
});

Deno.test("reboot: a privileged check without its record refuses the reboot before any call or record", async () => {
  await withFake({ FAKE_SWAMP_EXEC: execOut("", 0) }, async () => {
    const t = mkCtx(
      {
        sshModel: "ssh",
        machines: [{
          host: "web1",
          health: [{
            type: "command",
            label: "myhealth",
            privileged: true,
            argv: ["myhealth"],
          }],
        }],
      },
      { stored: { web1: { needsReboot: true } } },
    );
    await assertRejects(
      () =>
        model.methods.reboot.execute(
          model.methods.reboot.arguments.parse({
            host: "web1",
            force: true,
            wait: false,
          }),
          t.ctx,
        ),
      Error,
      'reboot of web1 refused: health checks: "myhealth" is privileged, but the machine has no unsafe.privilegedHealth acceptance record',
    );
    assertEquals(t.calls.length, 0);
    assertEquals(t.written("reboot"), []);
    assertEquals(t.written("run"), []);
  });
});

Deno.test("safeOsUpdate: a privileged check without its record refuses the update before any call or record", async () => {
  await withFake(osUpdateEnv(), async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{
        host: "web1",
        health: [{
          type: "command",
          label: "myhealth",
          privileged: true,
          argv: ["myhealth"],
        }],
      }],
    });
    await assertRejects(
      () =>
        model.methods.safeOsUpdate.execute(
          model.methods.safeOsUpdate.arguments.parse({ host: "web1" }),
          t.ctx,
        ),
      Error,
      'safeOsUpdate of web1 refused: plug-in privileges: health checks: "myhealth" is privileged, but the machine has no unsafe.privilegedHealth acceptance record',
    );
    assertEquals(t.calls.length, 0);
    assertEquals(t.written("osUpdate"), []);
    assertEquals(t.written("run"), []);
  });
});

Deno.test("safeOsUpdate: with the record, an update that passes its privileged health check lists unsafe.privilegedHealth in the run record", async () => {
  const env = { ...osModelEnv(), FAKE_SWAMP_HC: hcOut("arch1", 0) };
  await withFake(env, async () => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{
        host: "arch1",
        osUpdater: { model: "pacman-os" },
        unsafe: PRIV_HEALTH_OK,
        health: [{
          type: "command",
          label: "myhealth",
          privileged: true,
          argv: ["myhealth"],
        }],
      }],
    });
    await model.methods.safeOsUpdate.execute(
      model.methods.safeOsUpdate.arguments.parse({ host: "arch1" }),
      t.ctx,
    );
    assertEquals(t.one("osUpdate").outcome, "updated");
    assertEquals(t.one("run").acceptedRisksUsed, ["unsafe.privilegedHealth"]);
  });
});

// ---------------------------------------------------------------------------
// A CT through a Proxmox node model (ct.nodeModel): the node model's API token takes the
// snapshots, so there is no pct, no unsafe.pctExec record and no root on the node. The
// snapshotter is proxmox-ct-api, and the token is audited through the node model.
// ---------------------------------------------------------------------------

Deno.test("schema: a ct needs a proxmoxNode (pct) or a nodeModel (API snapshots), and may have both", () => {
  assertThrows(() => parseMachine({ host: "c", ct: { ctid: 101 } }));
  assertEquals(
    parseMachine({ host: "c", ct: { ctid: 101, nodeModel: "patch-pve" } }).ct,
    { ctid: 101, nodeModel: "patch-pve" },
  );
  assertEquals(
    parseMachine({
      host: "c",
      ct: { proxmoxNode: "pve", ctid: 101, nodeModel: "patch-pve" },
    }).ct,
    { proxmoxNode: "pve", ctid: 101, nodeModel: "patch-pve" },
  );
});

Deno.test("snapshotterRefFor: a ct nodeModel is proxmox-ct-api and beats a pct location; an explicit snapshotter model still wins", () => {
  const ct = { ctid: 101, nodeModel: "patch-pve" };
  assertEquals(fleet.snapshotterRefFor({ host: "a", ct }), {
    kind: "proxmox-ct-api",
    node: "patch-pve",
    ctid: 101,
  });
  assertEquals(
    fleet.snapshotterRefFor({ host: "a", ct }, { node: "pve", ctid: 101 }),
    { kind: "proxmox-ct-api", node: "patch-pve", ctid: 101 },
  );
  assertEquals(
    fleet.snapshotterRefFor({ host: "a", ct, snapshotter: { model: "zfs" } }),
    { kind: "model", model: "zfs" },
  );
});

Deno.test("usesPctSnapshots: only a CT with no snapshotter model and no ct.nodeModel snapshots with pct", () => {
  assertEquals(
    fleet.usesPctSnapshots({ host: "a", ct: { proxmoxNode: "pve", ctid: 101 } }),
    true,
  );
  assertEquals(
    fleet.usesPctSnapshots({
      host: "a",
      ct: { ctid: 101, nodeModel: "patch-pve" },
    }),
    false,
  );
  assertEquals(
    fleet.usesPctSnapshots({
      host: "a",
      ct: { proxmoxNode: "pve", ctid: 101 },
      snapshotter: { model: "zfs" },
    }),
    false,
  );
  // A VM is never snapshotted with pct, even with a ct decoration beside it.
  assertEquals(
    fleet.usesPctSnapshots({
      host: "a",
      vm: { proxmoxNode: "pve", vmid: 100 },
      ct: { proxmoxNode: "pve", ctid: 101 },
    }),
    false,
  );
  assertEquals(fleet.usesPctSnapshots({ host: "a" }), false);
});

Deno.test("snapshotTokenTarget: a VM or a CT with a nodeModel names its node model and guest; pct, a snapshotter model and bare metal name none", () => {
  assertEquals(
    fleet.snapshotTokenTarget({
      host: "a",
      vm: { proxmoxNode: "pve", vmid: 100 },
    }),
    { model: "pve", guest: { type: "vm", vmid: 100 } },
  );
  assertEquals(
    fleet.snapshotTokenTarget({
      host: "a",
      ct: { ctid: 101, nodeModel: "patch-pve" },
    }),
    { model: "patch-pve", guest: { type: "ct", vmid: 101 } },
  );
  assertEquals(
    fleet.snapshotTokenTarget({
      host: "a",
      ct: { proxmoxNode: "pve", ctid: 101 },
    }),
    null,
  );
  assertEquals(
    fleet.snapshotTokenTarget({
      host: "a",
      ct: { ctid: 101, nodeModel: "patch-pve" },
      snapshotter: { model: "zfs" },
    }),
    null,
  );
  assertEquals(fleet.snapshotTokenTarget({ host: "a" }), null);
});

Deno.test("ctLocation: a ct with only a nodeModel has no node for pct, and the error says so", async () => {
  await assertRejects(
    () =>
      fleet.ctLocation(
        { host: "a", ct: { ctid: 101, nodeModel: "patch-pve" } },
        CLI,
      ),
    Error,
    "ct.proxmoxNode",
  );
});

Deno.test("snapshotterFor(proxmox-ct-api): snapshotCt, rollbackCt (start), deleteCtSnapshot and listCtSnapshots on the node model; list drops current", async () => {
  const s = stubSwamp([
    { ok: true },
    { ok: true },
    { ok: true },
    {
      ok: true,
      artifacts: [{
        snapshots: [{ name: "preupdate-1" }, { name: "current" }],
      }],
    },
  ]);
  const snapper = fleet.snapshotterFor(
    { kind: "proxmox-ct-api", node: "patch-pve", ctid: 101 },
    { sshModel: "ssh", swamp: s.api, host: "ct1" },
  );
  assertEquals(await snapper.snapshot("preupdate-1"), true);
  assertEquals(await snapper.rollback("preupdate-1"), true);
  assertEquals(await snapper.delete("preupdate-1"), true);
  assertEquals(await snapper.list(), ["preupdate-1"]);
  assertEquals(s.calls, [
    {
      model: "patch-pve",
      method: "snapshotCt",
      args: { vmid: 101, name: "preupdate-1" },
    },
    {
      model: "patch-pve",
      method: "rollbackCt",
      args: { vmid: 101, name: "preupdate-1", start: true },
    },
    {
      model: "patch-pve",
      method: "deleteCtSnapshot",
      args: { vmid: 101, name: "preupdate-1" },
    },
    { model: "patch-pve", method: "listCtSnapshots", args: { vmid: 101 } },
  ]);
  assertStringIncludes(snapper.where, 'node model "patch-pve"');
});

Deno.test("readTokenPermissions: asks each distinct model once; a failed run or a record without paths is kept as its error", async () => {
  const asked: string[] = [];
  const swamp: SwampApi = {
    run: (model) => {
      asked.push(model);
      if (model === "bad") {
        return Promise.resolve({ ok: false, artifacts: [], error: "no route" });
      }
      if (model === "empty") {
        return Promise.resolve({ ok: true, artifacts: [{}], error: "" });
      }
      return Promise.resolve({
        ok: true,
        artifacts: [{ paths: [] }],
        error: "",
      });
    },
    globalArguments: () => Promise.resolve(null),
  };
  const out = await fleet.readTokenPermissions(
    ["good", "bad", "good", "empty"],
    swamp,
  );
  assertEquals(asked, ["good", "bad", "empty"]);
  assertEquals(out.get("good"), { paths: [], error: null });
  assertEquals(out.get("bad"), { paths: null, error: "no route" });
  assertEquals(out.get("empty"), {
    paths: null,
    error: "no permissions record",
  });
});

/** osUpdateEnv under a CT's name: the scans of ct1 run over ssh, with no pct answers. */
function ctNodeEnv(): Env {
  return {
    ...osUpdateEnv(),
    FAKE_SWAMP_SCRIPT_1: scriptOut("ct1", collectorStdout()),
    FAKE_SWAMP_SCRIPT_2: scriptOut(
      "ct1",
      collectorStdout({ updatesCount: 0, needsReboot: true }),
    ),
  };
}

Deno.test("safeOsUpdate CT nodeModel: a CT over ssh is snapshotted through its node model, with no pct and no unsafe.pctExec record", async () => {
  await withCallLog(ctNodeEnv(), async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "ct1", ct: { ctid: 101, nodeModel: "patch-pve" } }],
    });
    await model.methods.safeOsUpdate.execute(
      model.methods.safeOsUpdate.arguments.parse({
        host: "ct1",
        healthGraceSec: 0,
      }),
      t.ctx,
    );
    const all = await calls();
    const taken = all.filter((c) => c.startsWith("patch-pve snapshotCt "));
    assertEquals(taken.length, 1);
    assertStringIncludes(taken[0], "--input vmid:json=101");
    assertStringIncludes(taken[0], "--input name=preupdate-");
    assertEquals(
      all.some((c) => /pct (snapshot|rollback|delsnapshot|listsnapshot)/.test(c)),
      false,
    );
    assertEquals(t.one("osUpdate").kind, "ct");
    assertEquals(t.one("osUpdate").outcome, "updated");
    const rec = t.one("snapshot");
    assertEquals(rec.kind, "ct");
    assertEquals(rec.vmid, 101);
    assertEquals(rec.proxmoxNode, "patch-pve");
    assertEquals(rec.snapshotter, {
      kind: "proxmox-ct-api",
      node: "patch-pve",
      ctid: 101,
    });
  });
});

Deno.test("safeOsUpdate CT nodeModel: unhealthy after the update → rolled back by rollbackCt, started again", async () => {
  const server = startServer(() => 503);
  try {
    await withCallLog(ctNodeEnv(), async (calls) => {
      const t = mkCtx({
        sshModel: "ssh",
        machines: [{
          host: "ct1",
          ct: { ctid: 101, nodeModel: "patch-pve" },
          health: [{ type: "http", url: server.url }],
        }],
      });
      await model.methods.safeOsUpdate.execute(
        model.methods.safeOsUpdate.arguments.parse({
          host: "ct1",
          healthGraceSec: 0,
        }),
        t.ctx,
      );
      const rb = (await calls()).filter((c) =>
        c.startsWith("patch-pve rollbackCt ")
      );
      assertEquals(rb.length, 1);
      assertStringIncludes(rb[0], "--input vmid:json=101");
      assertStringIncludes(
        rb[0],
        `--input name=${String(t.one("snapshot").name)}`,
      );
      assertStringIncludes(rb[0], "--input start:json=true");
      assertEquals(t.one("osUpdate").outcome, "rolled-back");
      assertEquals(t.one("osUpdate").rolledBack, true);
    });
  } finally {
    await server.stop();
  }
});

Deno.test("rollback CT nodeModel: a snapshot taken through a node model is rolled back by rollbackCt, with no unsafe.pctExec record", async () => {
  const data = {
    snapshot: [snapDatum("snap-ct1-1", {
      host: "ct1",
      name: "ct-snap",
      kind: "ct",
      vmid: 101,
      proxmoxNode: "patch-pve",
      snapshotter: { kind: "proxmox-ct-api", node: "patch-pve", ctid: 101 },
    })],
  };
  await withCallLog({ FAKE_SWAMP_EXEC: execOut("", 0) }, async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "ct1", ct: { ctid: 101, nodeModel: "patch-pve" } }],
    }, { data });
    await model.methods.rollback.execute(
      model.methods.rollback.arguments.parse({ host: "ct1" }),
      t.ctx,
    );
    const rb = (await calls()).filter((c) =>
      c.startsWith("patch-pve rollbackCt ")
    );
    assertEquals(rb.length, 1);
    assertStringIncludes(rb[0], "--input vmid:json=101");
    assertStringIncludes(rb[0], "--input name=ct-snap");
    assertStringIncludes(rb[0], "--input start:json=true");
    assertEquals(t.one("run").snapshot, "ct-snap");
    assertEquals(t.one("run").outcome, "rolled-back");
  });
});

Deno.test("pruneSnapshots CT nodeModel: an expired snapshot taken through a node model is deleted by deleteCtSnapshot", async () => {
  await withCallLog({ FAKE_SWAMP_SCRIPT_1: HEALTHY_NOW }, async (calls) => {
    const t = mkCtx({
      sshModel: "ssh",
      machines: [{ host: "web1", ct: { ctid: 101, nodeModel: "patch-pve" } }],
    }, {
      data: {
        snapshot: [snapDatum("s-ct", {
          kind: "ct",
          vmid: 101,
          proxmoxNode: "patch-pve",
          snapshotter: { kind: "proxmox-ct-api", node: "patch-pve", ctid: 101 },
        })],
      },
    });
    await model.methods.pruneSnapshots.execute(
      model.methods.pruneSnapshots.arguments.parse({}),
      t.ctx,
    );
    const del = (await calls()).filter((c) =>
      c.startsWith("patch-pve deleteCtSnapshot ")
    );
    assertEquals(del.length, 1);
    assertStringIncludes(del[0], "--input vmid:json=101");
    assertStringIncludes(del[0], "--input name=preupdate-1");
    const pruned = t.one("prune").pruned as Array<Record<string, unknown>>;
    assertEquals(pruned.map((p) => [p.host, p.name]), [
      ["web1", "preupdate-1"],
    ]);
    assertEquals(t.one("snapshot").status, "pruned");
  });
});

Deno.test("snapshot-target-resolves CT nodeModel: a CT with a nodeModel and no pctExec record is listed through its node model", async () => {
  const fleet = {
    sshModel: "ssh",
    machines: [{ host: "ct4", ct: { ctid: 101, nodeModel: "patch-pve" } }],
  };
  await withCallLog({}, async (calls) => {
    for (const method of ["safeOsUpdate", "pruneSnapshots", "rollback"]) {
      assertEquals(
        await runCheck(
          "snapshot-target-resolves",
          checkCtx(fleet, method, { host: "ct4" }),
        ),
        { pass: true },
        method,
      );
    }
    const listed = (await calls()).filter((c) =>
      c.startsWith("patch-pve listCtSnapshots ")
    );
    assertEquals(listed.length, 3);
    assertStringIncludes(listed[0], "--input vmid:json=101");
  });
  await withFake({ FAKE_SWAMP_METHOD_RC: "1" }, async () => {
    const r = await runCheck(
      "snapshot-target-resolves",
      checkCtx(fleet, "safeOsUpdate", { host: "ct4" }),
    );
    assertEquals(r.pass, false);
    assertStringIncludes(
      r.errors!.join(" "),
      'CT 101 via node model "patch-pve" did not resolve',
    );
  });
});

// --- auditAccess: the snapshot token of a VM or CT with a node model --------------

const TOKEN_PRIVS = [
  "VM.Audit",
  "VM.PowerMgmt",
  "VM.Snapshot",
  "VM.Snapshot.Rollback",
];

/** The `paths` of a permissions record: each path with the given privileges, propagated. */
function tokenPaths(...entries: Array<[string, string[]]>) {
  return entries.map(([path, names]) => ({
    path,
    privileges: names.map((name) => ({ name, propagate: true })),
  }));
}

/** A token that holds exactly the snapshot privileges on its pool and on guests 100 and 101. */
const CLEAN_TOKEN_PATHS = tokenPaths(
  ["/pool/patch", TOKEN_PRIVS],
  ["/vms/100", TOKEN_PRIVS],
  ["/vms/101", TOKEN_PRIVS],
);

/**
 * Answers the `permissions` method of the node models in an audit run: `answer(model)`
 * gives a record's `paths`, or `{ error }` for a run that fails. Other methods go to the
 * fake as usual. Returns the models asked, in order.
 */
function tokenPermissions(
  t: ReturnType<typeof mkCtx>,
  answer: (model: string) => { paths: unknown } | { error: string },
): string[] {
  const ctx = t.ctx as unknown as {
    runModel: (opts: RunModelCall) => Promise<unknown>;
  };
  const base = ctx.runModel;
  const asked: string[] = [];
  ctx.runModel = (opts: RunModelCall) => {
    if (opts.method !== "permissions") return base(opts);
    asked.push(opts.definition);
    const a = answer(opts.definition);
    return Promise.resolve(
      "error" in a
        ? { ok: false, error: { message: a.error } }
        : {
          ok: true,
          resources: [{
            name: "permissions-0",
            specName: "result",
            attributes: { paths: a.paths },
          }],
        },
    );
  };
  return asked;
}

Deno.test("auditAccess token: a VM whose node token holds exactly the snapshot privileges adds no api-token finding", async () => {
  await withCallLog(
    auditEnv(sshDefinition("root", [{ name: "web1" }]), [{ host: "web1" }]),
    async () => {
      const t = mkCtx({
        sshModel: "ssh",
        access: ACCESS,
        machines: [{
          host: "web1",
          vm: { proxmoxNode: "patch-pve", vmid: 100 },
        }],
      });
      const asked = tokenPermissions(t, () => ({ paths: CLEAN_TOKEN_PATHS }));
      await model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), t.ctx);
      assertEquals(asked, ["patch-pve"]);
      assertEquals(auditFindings(auditOf(t, "web1")), NO_GRANTS_WARNINGS);
    },
  );
});

Deno.test("auditAccess token: a privilege on / is an api-token-extra critical, and the run fails at the default failOn", async () => {
  await withCallLog(
    auditEnv(sshDefinition("root", [{ name: "web1" }]), [{ host: "web1" }]),
    async () => {
      const t = mkCtx({
        sshModel: "ssh",
        access: ACCESS,
        machines: [{
          host: "web1",
          vm: { proxmoxNode: "patch-pve", vmid: 100 },
        }],
      });
      tokenPermissions(t, () => ({
        paths: [...CLEAN_TOKEN_PATHS, ...tokenPaths(["/", ["Sys.Audit"]])],
      }));
      await assertRejects(
        () => model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), t.ctx),
        Error,
        "web1: api-token-extra:/",
      );
      const rec = auditOf(t, "web1");
      assertEquals(rec.ok, false);
      assertEquals(auditFindings(rec), [
        "api-token-extra:/ critical",
        ...NO_GRANTS_WARNINGS,
      ]);
    },
  );
});

Deno.test("auditAccess token: a failed permissions run is api-token-unread:<model>, high, and fails the run", async () => {
  await withCallLog(
    auditEnv(sshDefinition("root", [{ name: "web1" }]), [{ host: "web1" }]),
    async () => {
      const t = mkCtx({
        sshModel: "ssh",
        access: ACCESS,
        machines: [{
          host: "web1",
          vm: { proxmoxNode: "patch-pve", vmid: 100 },
        }],
      });
      tokenPermissions(t, () => ({ error: "permissions exploded" }));
      await assertRejects(
        () => model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), t.ctx),
        Error,
        "web1: api-token-unread:patch-pve",
      );
      const rec = auditOf(t, "web1");
      assertEquals(rec.ok, false);
      assertEquals(auditFindings(rec), [
        "api-token-unread:patch-pve high",
        ...NO_GRANTS_WARNINGS,
      ]);
      assertStringIncludes(JSON.stringify(rec.findings), "permissions exploded");
    },
  );
});

Deno.test("auditAccess token: two machines on one node model read its permissions once", async () => {
  await withCallLog(
    auditEnv(sshDefinition("root", [{ name: "web1" }, { name: "web2" }]), [
      { host: "web1" },
      { host: "web2" },
    ]),
    async () => {
      const t = mkCtx({
        sshModel: "ssh",
        access: ACCESS,
        machines: [
          { host: "web1", vm: { proxmoxNode: "patch-pve", vmid: 100 } },
          { host: "web2", ct: { ctid: 101, nodeModel: "patch-pve" } },
        ],
      });
      const asked = tokenPermissions(t, () => ({ paths: CLEAN_TOKEN_PATHS }));
      await model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), t.ctx);
      assertEquals(asked, ["patch-pve"]);
      assertEquals(auditFindings(auditOf(t, "web2")), NO_GRANTS_WARNINGS);
    },
  );
});
// --- proxmox-cluster health checks and the token's Sys.Audit on / ----------------

/** Sys.Audit on / without propagation: what ensureSnapshotAccess clusterAudit grants. */
const ROOT_AUDIT_PATHS = [{
  path: "/",
  privileges: [{ name: "Sys.Audit", propagate: false }],
}];

Deno.test("auditAccess token: a node's proxmox-cluster check needs Sys.Audit on /, and allows it for the fleet's other machines", async () => {
  await withCallLog(
    auditEnv(sshDefinition("root", [{ name: "web1" }, { name: "pve1" }]), [
      { host: "web1" },
      { host: "pve1" },
    ]),
    async () => {
      const machines = [
        { host: "web1", vm: { proxmoxNode: "patch-pve", vmid: 100 } },
        {
          host: "pve1",
          health: [{ type: "proxmox-cluster", nodeModel: "patch-pve" }],
        },
      ];
      // With Sys.Audit on /: no token finding on either machine.
      const ok = mkCtx({ sshModel: "ssh", access: ACCESS, machines });
      const asked = tokenPermissions(ok, () => ({
        paths: [...CLEAN_TOKEN_PATHS, ...ROOT_AUDIT_PATHS],
      }));
      await model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), ok.ctx);
      assertEquals(asked, ["patch-pve"]);
      assertEquals(auditFindings(auditOf(ok, "web1")), NO_GRANTS_WARNINGS);
      assertEquals(auditFindings(auditOf(ok, "pve1")), NO_GRANTS_WARNINGS);

      // Without it: the node's check would fail, so the node has api-token-missing.
      const missing = mkCtx({ sshModel: "ssh", access: ACCESS, machines });
      tokenPermissions(missing, () => ({ paths: CLEAN_TOKEN_PATHS }));
      await assertRejects(
        () =>
          model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), missing.ctx),
        Error,
        "pve1: api-token-missing:patch-pve",
      );
      assertEquals(auditFindings(auditOf(missing, "web1")), NO_GRANTS_WARNINGS);
      assertEquals(auditFindings(auditOf(missing, "pve1")), [
        "api-token-missing:patch-pve high",
        ...NO_GRANTS_WARNINGS,
      ]);

      // Propagated: critical on both machines.
      const prop = mkCtx({ sshModel: "ssh", access: ACCESS, machines });
      tokenPermissions(prop, () => ({
        paths: [
          ...CLEAN_TOKEN_PATHS,
          ...tokenPaths(["/", ["Sys.Audit"]]),
        ],
      }));
      await assertRejects(
        () => model.methods.auditAccess.execute(AUDIT_ARGS.parse({}), prop.ctx),
        Error,
        "api-token-extra:/",
      );
      for (const host of ["web1", "pve1"]) {
        assertEquals(auditFindings(auditOf(prop, host)), [
          "api-token-extra:/ critical",
          ...NO_GRANTS_WARNINGS,
        ]);
      }
    },
  );
});

Deno.test("apiTokenUses: one entry per model, with the guest and how Sys.Audit on / is judged", () => {
  const parse = (m: unknown) =>
    model.globalArguments.parse({ sshModel: "ssh", machines: [m] })
      .machines[0];
  const ct = parse({
    host: "valkey",
    ct: { ctid: 701, nodeModel: "patch-pve" },
  });
  const node = parse({
    host: "node1",
    health: [
      { type: "proxmox-cluster", nodeModel: "patch-pve" },
      { type: "proxmox-cluster", nodeModel: "patch-pve", node: "pve" },
      { type: "proxmox-cluster", nodeModel: "audit-only" },
    ],
  });
  const both = parse({
    host: "web1",
    vm: { proxmoxNode: "patch-pve", vmid: 100 },
    health: [{ type: "proxmox-cluster", nodeModel: "patch-pve" }],
  });
  assertEquals(fleet.apiTokenUses(ct, [ct]), [
    {
      model: "patch-pve",
      guest: { type: "ct", vmid: 701 },
      clusterAudit: "extra",
    },
  ]);
  assertEquals(fleet.apiTokenUses(ct, [ct, node]), [
    {
      model: "patch-pve",
      guest: { type: "ct", vmid: 701 },
      clusterAudit: "allowed",
    },
  ]);
  assertEquals(fleet.apiTokenUses(node, [ct, node]), [
    { model: "patch-pve", guest: null, clusterAudit: "required" },
    { model: "audit-only", guest: null, clusterAudit: "required" },
  ]);
  assertEquals(fleet.apiTokenUses(both, [both]), [
    {
      model: "patch-pve",
      guest: { type: "vm", vmid: 100 },
      clusterAudit: "required",
    },
  ]);
  assertEquals(fleet.apiTokenUses(parse({ host: "bare" }), [node]), []);
});

Deno.test("proxmox-cluster health check: schema needs a nodeModel and accepts only a safe node name", () => {
  const parse = (c: unknown) =>
    model.globalArguments.safeParse({
      sshModel: "ssh",
      machines: [{ host: "node1", health: [c] }],
    }).success;
  assert(parse({ type: "proxmox-cluster", nodeModel: "patch-pve" }));
  assert(
    parse({ type: "proxmox-cluster", nodeModel: "patch-pve", node: "pve2" }),
  );
  assertEquals(parse({ type: "proxmox-cluster" }), false);
  assertEquals(parse({ type: "proxmox-cluster", nodeModel: "" }), false);
  for (const node of ["../x", "pve/2", "", "-pve"]) {
    assertEquals(
      parse({ type: "proxmox-cluster", nodeModel: "patch-pve", node }),
      false,
      node,
    );
  }
});

/** A clusterHealth record for `node`, healthy and quorate unless overridden. */
function clusterRecord(node: string, over: Record<string, unknown> = {}) {
  return {
    node,
    answeredBy: "node1",
    clustered: true,
    cluster: "bridges",
    quorate: true,
    nodeListed: true,
    nodeOnline: true,
    nodesOnline: 2,
    nodesTotal: 2,
    healthy: true,
    problems: [],
    checkedAt: "2026-11-07T00:00:00Z",
    ...over,
  };
}

Deno.test("proxmoxClusterVerdict: runs clusterHealth for the node and passes a healthy, quorate record", async () => {
  const s = stubSwamp([{ ok: true, artifacts: [clusterRecord("pve")] }]);
  assertEquals(await fleet.proxmoxClusterVerdict("patch-pve", "pve", s.api), {
    ok: true,
    detail: "online, quorate (2/2 nodes online)",
  });
  assertEquals(s.calls, [
    { model: "patch-pve", method: "clusterHealth", args: { node: "pve" } },
  ]);
  const solo = stubSwamp([{
    ok: true,
    artifacts: [clusterRecord("solo", {
      clustered: false,
      cluster: null,
      quorate: null,
      nodesOnline: 1,
      nodesTotal: 1,
    })],
  }]);
  assertEquals(
    (await fleet.proxmoxClusterVerdict("m", "solo", solo.api)).detail,
    "online, standalone (1/1 nodes online)",
  );
});

Deno.test("proxmoxClusterVerdict: fails closed on a failed run, a missing, duplicate or malformed record, or an inconsistent verdict", async () => {
  const cases: Array<
    [
      string,
      {
        ok: boolean;
        artifacts?: Array<Record<string, unknown>>;
        error?: string;
      },
      string,
    ]
  > = [
    [
      "the run fails",
      { ok: false, error: "HTTP 403: Permission check failed" },
      "clusterHealth failed: HTTP 403",
    ],
    ["no record", { ok: true, artifacts: [] }, "no readable record for pve"],
    ["a record for another node", {
      ok: true,
      artifacts: [clusterRecord("node1")],
    }, "no readable record for pve"],
    ["two records", {
      ok: true,
      artifacts: [clusterRecord("pve"), clusterRecord("pve")],
    }, "2 records for pve"],
    ["a malformed record", {
      ok: true,
      artifacts: [clusterRecord("pve", { quorate: "yes" })],
    }, "no readable record"],
    ["offline", {
      ok: true,
      artifacts: [
        clusterRecord("pve", {
          nodeOnline: false,
          healthy: false,
          problems: ["node pve is offline"],
        }),
      ],
    }, "node pve is offline"],
    ["no quorum", {
      ok: true,
      artifacts: [
        clusterRecord("pve", {
          quorate: false,
          healthy: false,
          problems: ["cluster bridges is not quorate"],
        }),
      ],
    }, "not quorate"],
    ["healthy but offline", {
      ok: true,
      artifacts: [clusterRecord("pve", { nodeOnline: false })],
    }, "online false"],
    ["healthy but unlisted", {
      ok: true,
      artifacts: [clusterRecord("pve", { nodeListed: false })],
    }, "listed false"],
    ["clustered with no quorum value", {
      ok: true,
      artifacts: [clusterRecord("pve", { quorate: null })],
    }, "quorate null"],
    ["standalone with a quorum value", {
      ok: true,
      artifacts: [clusterRecord("pve", { clustered: false, quorate: true })],
    }, "quorate true"],
    ["healthy with a problem", {
      ok: true,
      artifacts: [clusterRecord("pve", { problems: ["odd"] })],
    }, "odd"],
  ];
  for (const [name, answer, fragment] of cases) {
    const s = stubSwamp([answer]);
    const v = await fleet.proxmoxClusterVerdict("patch-pve", "pve", s.api);
    assertEquals(v.ok, false, name);
    assertStringIncludes(v.detail, fragment, name);
  }
  const throwing: SwampApi = {
    run: () => Promise.reject(new Error("host API broke")),
    globalArguments: () => Promise.resolve(null),
  };
  const t = await fleet.proxmoxClusterVerdict("patch-pve", "pve", throwing);
  assertEquals(t.ok, false);
  assertStringIncludes(t.detail, "host API broke");
});

Deno.test("evalHealth: a proxmox-cluster check runs from the swamp host for the machine's host, or its node", async () => {
  const m = model.globalArguments.parse({
    sshModel: "ssh",
    machines: [{
      host: "node1",
      health: [
        { type: "proxmox-cluster", nodeModel: "patch-pve" },
        {
          type: "proxmox-cluster",
          nodeModel: "patch-pve",
          node: "pve",
          label: "pve seen",
        },
      ],
    }],
  }).machines[0];
  const s: SwampApi = {
    run: (_model, _method, args) =>
      Promise.resolve({
        ok: true,
        artifacts: [clusterRecord(
          String(args?.node),
          args?.node === "pve"
            ? {
              nodeOnline: false,
              healthy: false,
              problems: ["node pve is offline"],
            }
            : {},
        )],
        error: "",
      }),
    globalArguments: () => Promise.resolve(null),
  };
  const h = await fleet.evalHealth(m, m.health!, "ssh", s);
  assertEquals(h.healthy, false);
  assertEquals(h.results, [
    {
      label: "proxmox cluster: node1 online and quorate",
      ok: true,
      detail: "online, quorate (2/2 nodes online)",
    },
    { label: "pve seen", ok: false, detail: "node pve is offline" },
  ]);
});
