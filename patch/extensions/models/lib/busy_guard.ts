// Busy guards — the pluggable "is this machine in use now?" gate.
//
// A machine's `busyGuards` names models that know whether work depends on it right now:
// running CI jobs, a backup, a logged-in operator. Before safeOsUpdate, safeUpdate or
// reboot makes any change, the fleet asks each guard. While one says busy, the method
// waits (up to busyWaitSec) and asks again; when the wait ends with a guard still busy,
// the method changes nothing and records outcome `busy`.
//
// A guard with `drain: true` can also stop new work from starting: the fleet calls
// `drain` before the first `busy` question, and `resume` when the method ends, whatever
// its outcome (also on a throw, and when it ends busy). Work that arrives meanwhile
// waits in the guard's own queue (for CI: the jobs wait in Forgejo).
//
// Busy guard contract — the referenced model MUST expose:
//   • busy({ host })    — write one resource whose attributes hold `busy` (boolean),
//                         optionally `reason` (string) and `items` (string[]).
// and, when the decoration sets drain: true, ALSO:
//   • drain({ host })   — stop new work that would depend on `host` from starting.
//   • resume({ host })  — undo drain. Must be safe to call when not drained.
// After a drain, busy is called as busy({ host, drained: true }): a drain may take
// effect a little later than drain returns, so the guard should then also say busy
// until no new work can start any more (for CI: until no idle runner is left).
// Success = the method run succeeds.
//
// A guard fails closed: a failed `busy` run, or an answer without a boolean `busy`,
// counts as busy, and a failed `drain` stops the method before any change. A guard runs
// where swamp runs, not on the machine, so it gets no sudo grants (it is not a
// privileges({ host }) plug-in).

export interface BusyGuardRef {
  model: string;
  drain: boolean;
}

/** One answer from a guard. */
export interface GuardAnswer {
  model: string;
  busy: boolean;
  reason: string;
  items: string[];
}

/** The run outcome the guards need from swamp (a subset of SwampApi.run's). */
export type GuardRun = (
  model: string,
  method: string,
  args: Record<string, unknown>,
) => Promise<{
  ok: boolean;
  artifacts: Array<Record<string, unknown>>;
  error: string;
}>;

export interface GuardTiming {
  now(): number;
  sleep(ms: number): Promise<void>;
}

export const REAL_TIMING: GuardTiming = {
  now: () => Date.now(),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
};

/** The most `busy` rounds one method may ask: swamp caps runModel at 100 calls per
 *  top-level run, and the method itself needs the rest. */
export const MAX_BUSY_ROUNDS = 40;

export interface BusyOptions {
  ignoreBusy: boolean;
  busyWaitSec: number;
  busyPollSec: number;
}

/** The seconds between two rounds: busyPollSec, made longer when the wait would
 *  otherwise need more than MAX_BUSY_ROUNDS rounds. */
export function pollIntervalSec(o: BusyOptions): number {
  return Math.max(o.busyPollSec, Math.ceil(o.busyWaitSec / MAX_BUSY_ROUNDS));
}

function shortError(e: string): string {
  const t = e.trim();
  return t.length > 300 ? `…${t.slice(-300)}` : t;
}

/** Ask one guard. A failed run or an unreadable answer is busy (fail closed). A guard
 *  that this run drained is asked with drained: true. */
export async function askGuard(
  g: BusyGuardRef,
  host: string,
  run: GuardRun,
  drained = false,
): Promise<GuardAnswer> {
  const res = await run(
    g.model,
    "busy",
    drained ? { host, drained: true } : { host },
  );
  if (!res.ok) {
    return {
      model: g.model,
      busy: true,
      reason: `busy guard "${g.model}" failed, so the machine counts as busy: ${
        shortError(res.error) || "no error text"
      }`,
      items: [],
    };
  }
  const a = res.artifacts[0];
  if (!a || typeof a.busy !== "boolean") {
    return {
      model: g.model,
      busy: true,
      reason:
        `busy guard "${g.model}" gave no boolean "busy" in its first resource, so the machine counts as busy`,
      items: [],
    };
  }
  const items = Array.isArray(a.items)
    ? a.items.filter((i): i is string => typeof i === "string")
    : [];
  const reason = typeof a.reason === "string" && a.reason
    ? a.reason
    : a.busy
    ? `busy guard "${g.model}" says busy`
    : "";
  return { model: g.model, busy: a.busy, reason, items };
}

/** One line for a busy answer, with up to 5 of its items. */
export function describeBusy(a: GuardAnswer): string {
  const shown = a.items.slice(0, 5).join(", ");
  const more = a.items.length > 5 ? ` (+${a.items.length - 5} more)` : "";
  return a.items.length ? `${a.reason}: ${shown}${more}` : a.reason;
}

/** What the gate decided. `busy` answers are the ones that kept the machine busy. */
export interface GateResult {
  proceed: boolean;
  busy: GuardAnswer[];
  /** Guards that were drained and must be resumed. */
  drained: BusyGuardRef[];
  rounds: number;
  logs: string[];
}

/**
 * Drain the drain guards, then ask every guard until none is busy or busyWaitSec has
 * passed. With ignoreBusy, or with no guards, it proceeds at once and drains nothing.
 * A failed drain stops it (proceed: false) after resuming the guards drained before.
 * The caller MUST call `resumeGuards(result.drained, …)` when the method ends — when
 * proceed is false it is already done here, and `drained` is empty.
 */
export async function busyGate(
  guards: BusyGuardRef[],
  host: string,
  o: BusyOptions,
  run: GuardRun,
  log: (m: string) => void,
  timing: GuardTiming = REAL_TIMING,
): Promise<GateResult> {
  const logs: string[] = [];
  const say = (m: string) => {
    logs.push(m);
    log(m);
  };
  if (!guards.length) {
    return { proceed: true, busy: [], drained: [], rounds: 0, logs };
  }
  if (o.ignoreBusy) {
    say(
      `ignoreBusy: not asking busy guards (${
        guards.map((g) => g.model).join(", ")
      })`,
    );
    return { proceed: true, busy: [], drained: [], rounds: 0, logs };
  }
  const drained: BusyGuardRef[] = [];
  for (const g of guards.filter((g) => g.drain)) {
    const res = await run(g.model, "drain", { host });
    if (!res.ok) {
      const answer: GuardAnswer = {
        model: g.model,
        busy: true,
        reason: `busy guard "${g.model}" could not drain: ${
          shortError(res.error) || "no error text"
        }`,
        items: [],
      };
      say(answer.reason);
      // Leave nothing drained behind on the way out.
      const failed = await resumeGuards(drained, host, run, say);
      if (failed.length) {
        say(`resume failed for ${failed.join(", ")} — resume them by hand`);
      }
      return { proceed: false, busy: [answer], drained: [], rounds: 0, logs };
    }
    drained.push(g);
    say(`drained "${g.model}": no new work starts`);
  }
  const interval = pollIntervalSec(o);
  const deadline = timing.now() + o.busyWaitSec * 1000;
  let rounds = 0;
  let busy: GuardAnswer[] = [];
  while (true) {
    rounds++;
    const answers: GuardAnswer[] = [];
    for (const g of guards) {
      answers.push(await askGuard(g, host, run, drained.includes(g)));
    }
    busy = answers.filter((a) => a.busy);
    if (!busy.length) {
      say(
        `busy guards: free (${guards.map((g) => g.model).join(", ")})${
          rounds > 1 ? ` after ${rounds} rounds` : ""
        }`,
      );
      return { proceed: true, busy: [], drained, rounds, logs };
    }
    const left = deadline - timing.now();
    if (left <= 0 || rounds >= MAX_BUSY_ROUNDS) break;
    say(
      `busy: ${
        busy.map(describeBusy).join("; ")
      } — asking again in ${interval} s`,
    );
    await timing.sleep(Math.min(interval * 1000, left));
  }
  for (const b of busy) say(`busy: ${describeBusy(b)}`);
  return { proceed: false, busy, drained, rounds, logs };
}

/** Resume drained guards. Returns the models whose resume failed (empty = all done). */
export async function resumeGuards(
  drained: BusyGuardRef[],
  host: string,
  run: GuardRun,
  log: (m: string) => void,
): Promise<string[]> {
  const failed: string[] = [];
  for (const g of drained) {
    const res = await run(g.model, "resume", { host });
    if (res.ok) {
      log(`resumed "${g.model}"`);
    } else {
      failed.push(g.model);
      log(
        `resume of "${g.model}" failed: ${
          shortError(res.error) || "no error text"
        }`,
      );
    }
  }
  return failed;
}

/** Run `body` behind the gate. When the gate says busy, `onBusy` writes the method's
 *  `busy` records instead and nothing else runs. Drained guards are resumed when it ends,
 *  also on a throw; a failed resume fails the run (new work would stay stopped). */
export async function withBusyGuards<T>(
  guards: BusyGuardRef[],
  host: string,
  o: BusyOptions,
  run: GuardRun,
  log: (m: string) => void,
  onBusy: (gate: GateResult) => Promise<T>,
  body: (gate: GateResult) => Promise<T>,
  timing: GuardTiming = REAL_TIMING,
): Promise<T> {
  const gate = await busyGate(guards, host, o, run, log, timing);
  let result: T;
  try {
    result = gate.proceed ? await body(gate) : await onBusy(gate);
  } catch (e) {
    const failed = await resumeGuards(gate.drained, host, run, log);
    if (failed.length) {
      throw new Error(
        `${(e as Error).message}; ALSO resume failed for busy guard(s) ${
          failed.join(", ")
        }: new work stays stopped until they are resumed`,
      );
    }
    throw e;
  }
  const failed = await resumeGuards(gate.drained, host, run, log);
  if (failed.length) {
    throw new Error(
      `${host}: the method finished, but resume failed for busy guard(s) ${
        failed.join(", ")
      }: new work stays stopped until they are resumed`,
    );
  }
  return result;
}
