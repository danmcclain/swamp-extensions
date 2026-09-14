/**
 * Tests for the @dmc/fastmail-coverage report — covers the success path (per-setup
 * coverage %, ranked uncategorized senders, json coverage ratio), the
 * wrong-method short-circuit (no `sieve` handle), and the non-categorizing-setup
 * filter (allowlist/merged outputs are skipped).
 *
 * Run with: deno test extensions/reports/fastmail_coverage_test.ts
 */

import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { report } from "./fastmail_coverage.ts";

type Ctx = Parameters<typeof report.execute>[0];

const SIEVE = {
  source: "config",
  mode: "categorize",
  folderPrefix: "INBOX",
  sendersMatched: 8,
  bulkFallbackCount: 2,
  leftInInbox: 5,
  uncategorized: [
    { email: "promo@shop.example", name: "Shop Promos", count: 12 },
    { email: "updates@app.example", name: null, count: 4 },
  ],
};

function ctx(
  handles: { specName: string; name: string; version: number }[],
  content: Record<string, unknown | null>,
): Ctx {
  return {
    modelType: "@dmc/fastmail",
    modelId: "m1",
    dataHandles: handles,
    dataRepository: {
      getContent: (_t, _m, name) => {
        const v = content[name];
        return Promise.resolve(
          v == null ? null : new TextEncoder().encode(JSON.stringify(v)),
        );
      },
    },
  } as Ctx;
}

Deno.test("fastmail-coverage: renders per-setup coverage and uncategorized senders", async () => {
  const { markdown, json } = await report.execute(
    ctx([{ specName: "sieve", name: "config", version: 1 }], { config: SIEVE }),
  );
  assertStringIncludes(markdown, "# Fastmail Rule Coverage");
  assertStringIncludes(markdown, "## Setup: `config`");
  assertStringIncludes(markdown, "**Filed to folders:** 8 senders");
  // 8 matched of 10 categorizable = 80%.
  assertStringIncludes(markdown, "80% of categorizable mail");
  assertStringIncludes(markdown, "promo@shop.example");

  const j = json as { applicable: boolean; setups: Record<string, unknown>[] };
  assertEquals(j.applicable, true);
  assertEquals(j.setups[0].coverage, 0.8);
});

Deno.test("fastmail-coverage: no sieve data short-circuits (not a sieve_generate run)", async () => {
  const { markdown, json } = await report.execute(
    ctx([{ specName: "senders", name: "inbox", version: 1 }], {}),
  );
  assertStringIncludes(markdown, "not a sieve_generate run");
  assertEquals((json as { applicable: boolean }).applicable, false);
});

Deno.test("fastmail-coverage: non-categorizing setup is skipped", async () => {
  const allowlist = {
    source: "allowlist",
    mode: "allowlist",
    folderPrefix: "INBOX",
    sendersMatched: 0,
    bulkFallbackCount: 0,
    leftInInbox: 0,
    uncategorized: [],
  };
  const { markdown, json } = await report.execute(
    ctx([{ specName: "sieve", name: "allow", version: 1 }], {
      allow: allowlist,
    }),
  );
  assertStringIncludes(markdown, "no categorizing setups");
  assertEquals((json as { applicable: boolean }).applicable, false);
});
