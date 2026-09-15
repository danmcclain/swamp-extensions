/**
 * Tests for the @dmc/fastmail-analyze report — covers the success path
 * (composition summary + rule-candidate table + kept-by-design table + covered
 * folders), the wrong-method short-circuit (no `analysis` handle), and the
 * missing-content path.
 *
 * Run with: deno test extensions/reports/fastmail_analyze_test.ts
 */

import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { report } from "./fastmail_analyze.ts";

type Ctx = Parameters<typeof report.execute>[0];

const ANALYSIS = {
  sourceMailbox: "Inbox",
  scannedMessages: 100,
  covered: 60,
  coveredByCategory: { Newsletters: 40, Shipments: 20 },
  remaining: {
    total: 40,
    bulk: 25,
    personal: 15,
    unread: 12,
    distinctSenders: 8,
    byReason: { unmatched: 30, excluded: 5, protected: 3, flagged: 2 },
    candidates: [
      {
        token: "deals.example.com",
        count: 12,
        bulk: 1,
        unread: 4,
        reason: "unmatched",
        sampleFroms: ["deals@deals.example.com"],
        sampleSubjects: ["50% off today"],
      },
    ],
    keptByDesign: [
      {
        token: "github.com",
        count: 8,
        bulk: 0,
        unread: 2,
        reason: "excluded",
        sampleFroms: ["noreply@github.com"],
        sampleSubjects: ["[repo] PR merged"],
      },
    ],
  },
};

/** Build a report context that serves `handles` from `content` by name. */
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

Deno.test("fastmail-analyze: renders composition, candidates, kept-by-design, and coverage", async () => {
  const { markdown, json } = await report.execute(
    ctx([{ specName: "analysis", name: "inbox-analysis", version: 1 }], {
      "inbox-analysis": ANALYSIS,
    }),
  );
  assertStringIncludes(markdown, "# Inbox Analysis");
  assertStringIncludes(markdown, "**Scanned:** 100 messages in `Inbox`");
  assertStringIncludes(markdown, "**Covered by current rules:** 60 (60%)");
  assertStringIncludes(markdown, "**Left in the inbox:** 40 (40%)");
  // Candidate row: bulk kind, unread count, sample subject.
  assertStringIncludes(
    markdown,
    "| 12 | deals.example.com | bulk | 4 | 50% off today |",
  );
  // Kept-by-design maps `excluded` -> "exclude list".
  assertStringIncludes(markdown, "| 8 | github.com | exclude list |");
  // Covered folders sorted by volume (Newsletters 40 above Shipments 20).
  assertStringIncludes(markdown, "| 40 | Newsletters |");
  assertStringIncludes(markdown, "| 20 | Shipments |");
  const j = json as { applicable: boolean; covered: number };
  assertEquals(j.applicable, true);
  assertEquals(j.covered, 60);
});

Deno.test("fastmail-analyze: no analysis handle short-circuits (not an email_analyze run)", async () => {
  const { markdown, json } = await report.execute(
    ctx([{ specName: "senders", name: "inbox", version: 1 }], {}),
  );
  assertStringIncludes(markdown, "not an email_analyze run");
  assertEquals((json as { applicable: boolean }).applicable, false);
});

Deno.test("fastmail-analyze: missing analysis content reports not-found", async () => {
  const { markdown } = await report.execute(
    ctx([{ specName: "analysis", name: "inbox-analysis", version: 1 }], {
      "inbox-analysis": null,
    }),
  );
  assertStringIncludes(markdown, "Analysis data not found");
});
