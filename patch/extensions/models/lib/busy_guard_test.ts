import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import {
  askGuard,
  busyGate,
  type BusyGuardRef,
  type BusyOptions,
  type GuardRun,
  MAX_BUSY_ROUNDS,
  pollIntervalSec,
  withBusyGuards,
} from "./busy_guard.ts";

type Answer = {
  ok: boolean;
  artifacts?: Array<Record<string, unknown>>;
  error?: string;
};

/** A swamp stub: answers per "model method" in order (the last one repeats). */
function stub(answers: Record<string, Answer[]>) {
  const calls: string[] = [];
  const seen: Record<string, number> = {};
  const run: GuardRun = (model, method, args) => {
    const key = `${model} ${method}`;
    calls.push(`${key} ${JSON.stringify(args)}`);
    const list = answers[key] ?? [{ ok: true }];
    const i = seen[key] ?? 0;
    seen[key] = i + 1;
    const a = list[Math.min(i, list.length - 1)];
    return Promise.resolve({
      ok: a.ok,
      artifacts: a.artifacts ?? [],
      error: a.error ?? "",
    });
  };
  return { run, calls };
}

function clock() {
  let now = 0;
  const sleeps: number[] = [];
  return {
    sleeps,
    timing: {
      now: () => now,
      sleep: (ms: number) => {
        sleeps.push(ms);
        now += ms;
        return Promise.resolve();
      },
    },
  };
}

const opts = (o: Partial<BusyOptions> = {}): BusyOptions => ({
  ignoreBusy: false,
  busyWaitSec: 0,
  busyPollSec: 30,
  ...o,
});

const free: Answer = { ok: true, artifacts: [{ busy: false }] };
const busyJobs: Answer = {
  ok: true,
  artifacts: [{
    busy: true,
    reason: "2 Actions jobs running",
    items: ["ai-infra#12 build", "uca#3 test"],
  }],
};
const ci: BusyGuardRef = { model: "ci", drain: false };
const ciDrain: BusyGuardRef = { model: "ci", drain: true };
const noop = () => {};

Deno.test("askGuard: a boolean busy answer is read with its reason and items", async () => {
  const s = stub({ "ci busy": [busyJobs] });
  const a = await askGuard(ci, "forgejo", s.run);
  assertEquals(a, {
    model: "ci",
    busy: true,
    reason: "2 Actions jobs running",
    items: ["ai-infra#12 build", "uca#3 test"],
  });
  assertEquals(s.calls, ['ci busy {"host":"forgejo"}']);
});

Deno.test("askGuard: a failed run or an answer without a boolean busy counts as busy", async () => {
  const failed = await askGuard(
    ci,
    "h",
    stub({ "ci busy": [{ ok: false, error: "401 Unauthorized" }] }).run,
  );
  assert(failed.busy);
  assertStringIncludes(failed.reason, "401 Unauthorized");
  for (const artifacts of [[], [{ busy: "no" }], [{}]]) {
    const a = await askGuard(
      ci,
      "h",
      stub({ "ci busy": [{ ok: true, artifacts }] }).run,
    );
    assert(a.busy, JSON.stringify(artifacts));
    assertStringIncludes(a.reason, 'no boolean "busy"');
  }
});

Deno.test("busyGate: no guards, or ignoreBusy, proceeds without a call", async () => {
  const s = stub({});
  assertEquals((await busyGate([], "h", opts(), s.run, noop)).proceed, true);
  const g = await busyGate(
    [ciDrain],
    "h",
    opts({ ignoreBusy: true }),
    s.run,
    noop,
  );
  assertEquals(g.proceed, true);
  assertEquals(g.drained, []);
  assertEquals(s.calls, []);
  assertStringIncludes(g.logs[0], "ignoreBusy");
});

Deno.test("busyGate: busy with no wait stops after one round, and never sleeps", async () => {
  const c = clock();
  const g = await busyGate(
    [ci],
    "h",
    opts(),
    stub({ "ci busy": [busyJobs] }).run,
    noop,
    c.timing,
  );
  assertEquals(g.proceed, false);
  assertEquals(g.rounds, 1);
  assertEquals(c.sleeps, []);
  assertStringIncludes(g.logs.join("\n"), "ai-infra#12 build");
});

Deno.test("busyGate: waits and asks again until the guard is free", async () => {
  const c = clock();
  const s = stub({ "ci busy": [busyJobs, busyJobs, free] });
  const g = await busyGate(
    [ci],
    "h",
    opts({ busyWaitSec: 600, busyPollSec: 30 }),
    s.run,
    noop,
    c.timing,
  );
  assertEquals(g.proceed, true);
  assertEquals(g.rounds, 3);
  assertEquals(c.sleeps, [30_000, 30_000]);
});

Deno.test("busyGate: the wait ends at busyWaitSec, the last sleep cut to what is left", async () => {
  const c = clock();
  const g = await busyGate(
    [ci],
    "h",
    opts({ busyWaitSec: 50, busyPollSec: 30 }),
    stub({ "ci busy": [busyJobs] }).run,
    noop,
    c.timing,
  );
  assertEquals(g.proceed, false);
  assertEquals(c.sleeps, [30_000, 20_000]);
  assertEquals(g.rounds, 3);
});

Deno.test("busyGate: a long wait stretches the interval so the rounds stay under the runModel cap", async () => {
  assertEquals(
    pollIntervalSec(opts({ busyWaitSec: 3600, busyPollSec: 30 })),
    90,
  );
  assertEquals(
    pollIntervalSec(opts({ busyWaitSec: 600, busyPollSec: 30 })),
    30,
  );
  const c = clock();
  const g = await busyGate(
    [ci],
    "h",
    opts({ busyWaitSec: 100_000, busyPollSec: 5 }),
    stub({ "ci busy": [busyJobs] }).run,
    noop,
    c.timing,
  );
  assertEquals(g.rounds, MAX_BUSY_ROUNDS);
});

Deno.test("busyGate: every guard must be free; one busy guard keeps the machine busy", async () => {
  const s = stub({ "a busy": [free], "b busy": [busyJobs] });
  const g = await busyGate(
    [{ model: "a", drain: false }, { model: "b", drain: false }],
    "h",
    opts(),
    s.run,
    noop,
  );
  assertEquals(g.proceed, false);
  assertEquals(g.busy.map((b) => b.model), ["b"]);
});

Deno.test("busyGate: drain runs before the first busy question", async () => {
  const s = stub({ "ci busy": [free] });
  const g = await busyGate([ciDrain], "h", opts(), s.run, noop);
  assertEquals(g.proceed, true);
  assertEquals(g.drained, [ciDrain]);
  assertEquals(s.calls, [
    'ci drain {"host":"h"}',
    'ci busy {"host":"h","drained":true}',
  ]);
});

Deno.test("busyGate: a failed drain stops before any busy question and resumes the guards drained before it", async () => {
  const a: BusyGuardRef = { model: "a", drain: true };
  const b: BusyGuardRef = { model: "b", drain: true };
  const s = stub({
    "b drain": [{ ok: false, error: "runner-pool unreachable" }],
  });
  const g = await busyGate([a, b], "h", opts(), s.run, noop);
  assertEquals(g.proceed, false);
  assertEquals(g.drained, []);
  assertStringIncludes(
    g.busy[0].reason,
    "could not drain: runner-pool unreachable",
  );
  assertEquals(s.calls.map((c) => c.split(" {")[0]), [
    "a drain",
    "b drain",
    "a resume",
  ]);
});

Deno.test("withBusyGuards: runs the body when free and resumes after it", async () => {
  const s = stub({ "ci busy": [free] });
  const order: string[] = [];
  const out = await withBusyGuards(
    [ciDrain],
    "h",
    opts(),
    (m, me, a) => {
      order.push(`${m} ${me}`);
      return s.run(m, me, a);
    },
    noop,
    () => Promise.resolve("busy"),
    () => {
      order.push("body");
      return Promise.resolve("done");
    },
  );
  assertEquals(out, "done");
  assertEquals(order, ["ci drain", "ci busy", "body", "ci resume"]);
});

Deno.test("withBusyGuards: busy runs onBusy, not the body, and still resumes", async () => {
  const s = stub({ "ci busy": [busyJobs] });
  let bodyRan = false;
  const out = await withBusyGuards(
    [ciDrain],
    "h",
    opts(),
    s.run,
    noop,
    (gate) => Promise.resolve(`busy: ${gate.busy[0].reason}`),
    () => {
      bodyRan = true;
      return Promise.resolve("done");
    },
  );
  assertEquals(out, "busy: 2 Actions jobs running");
  assertEquals(bodyRan, false);
  assertEquals(s.calls.at(-1)?.split(" {")[0], "ci resume");
});

Deno.test("withBusyGuards: a throwing body still resumes, and the error is kept", async () => {
  const s = stub({ "ci busy": [free] });
  await assertRejects(
    () =>
      withBusyGuards(
        [ciDrain],
        "h",
        opts(),
        s.run,
        noop,
        () => Promise.resolve(0),
        () => {
          throw new Error("upgrade exploded");
        },
      ),
    Error,
    "upgrade exploded",
  );
  assertEquals(s.calls.at(-1)?.split(" {")[0], "ci resume");
});

Deno.test("withBusyGuards: a failed resume fails the run, so stopped work is not missed", async () => {
  const s = stub({
    "ci busy": [free],
    "ci resume": [{ ok: false, error: "timeout" }],
  });
  await assertRejects(
    () =>
      withBusyGuards(
        [ciDrain],
        "h",
        opts(),
        s.run,
        noop,
        () => Promise.resolve(0),
        () => Promise.resolve(1),
      ),
    Error,
    "resume failed for busy guard(s) ci",
  );
  // On a throwing body, both errors are reported.
  await assertRejects(
    () =>
      withBusyGuards(
        [ciDrain],
        "h",
        opts(),
        s.run,
        noop,
        () => Promise.resolve(0),
        () => {
          throw new Error("upgrade exploded");
        },
      ),
    Error,
    "upgrade exploded; ALSO resume failed",
  );
});

Deno.test("withBusyGuards: a guard without drain is never drained or resumed", async () => {
  const s = stub({ "ci busy": [free] });
  await withBusyGuards(
    [ci],
    "h",
    opts(),
    s.run,
    noop,
    () => Promise.resolve(0),
    () => Promise.resolve(1),
  );
  assertEquals(s.calls.map((c) => c.split(" {")[0]), ["ci busy"]);
});
