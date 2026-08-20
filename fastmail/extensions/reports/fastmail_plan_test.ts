/**
 * Tests for the @dmc/fastmail-plan report — covers the success path (destination
 * table sorted by volume + sample messages + json summary), the wrong-method
 * short-circuit (no `plan` handle), and the missing-content path.
 *
 * Run with: deno test extensions/reports/fastmail_plan_test.ts
 */

import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { report } from "./fastmail_plan.ts";

type Ctx = Parameters<typeof report.execute>[0];

const PLAN = {
  sourceMailbox: "Inbox",
  scannedMessages: 100,
  moveCount: 3,
  leftInInbox: 97,
  byDestination: { Newsletters: 2, Receipts: 1 },
  moves: [
    {
      messageId: "m1",
      from: "news@example.com",
      subject: "Weekly digest",
      category: "Newsletters",
      sievePath: "INBOX/Newsletters",
      mailboxId: "mb1",
      matchedBy: "rule from:news",
    },
    {
      messageId: "m2",
      from: "news@example.com",
      subject: "",
      category: "Newsletters",
      sievePath: "INBOX/Newsletters",
      mailboxId: "mb1",
      matchedBy: "rule from:news",
    },
    {
      messageId: "m3",
      from: "billing@shop.example",
      subject: "Your receipt",
      category: "Receipts",
      sievePath: "INBOX/Receipts",
      mailboxId: "mb2",
      matchedBy: "rule from:billing",
    },
  ],
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

Deno.test("fastmail-plan: renders destinations (by volume) and sample messages", async () => {
  const { markdown, json } = await report.execute(
    ctx([{ specName: "plan", name: "apply-plan", version: 1 }], {
      "apply-plan": PLAN,
    }),
  );
  assertStringIncludes(markdown, "# Apply-Sieve Plan");
  assertStringIncludes(markdown, "**Scanned:** 100 messages");
  assertStringIncludes(markdown, "**Would move:** 3");
  // Newsletters (2) sorts above Receipts (1).
  assertStringIncludes(markdown, "| 2 | Newsletters |");
  assertStringIncludes(markdown, "| 1 | Receipts |");
  // Empty subject renders the (no subject) placeholder.
  assertStringIncludes(markdown, "(no subject)");
  const j = json as { applicable: boolean; moveCount: number };
  assertEquals(j.applicable, true);
  assertEquals(j.moveCount, 3);
});

Deno.test("fastmail-plan: no plan handle short-circuits (not an email_plan run)", async () => {
  const { markdown, json } = await report.execute(
    ctx([{ specName: "senders", name: "inbox", version: 1 }], {}),
  );
  assertStringIncludes(markdown, "not an email_plan run");
  assertEquals((json as { applicable: boolean }).applicable, false);
});

Deno.test("fastmail-plan: missing plan content reports not-found", async () => {
  const { markdown } = await report.execute(
    ctx([{ specName: "plan", name: "apply-plan", version: 1 }], {
      "apply-plan": null,
    }),
  );
  assertStringIncludes(markdown, "Plan data not found");
});
