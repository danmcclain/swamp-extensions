/**
 * Tests for the @dmc/fastmail-audit report — covers the success path (scope
 * summary, bulk/unread stats, volume concentration), the wrong-method
 * short-circuit (no `senders` handle), and multi-scope aggregation.
 *
 * Run with: deno test extensions/reports/fastmail_audit_test.ts
 */

import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { report } from "./fastmail_audit.ts";

type Ctx = Parameters<typeof report.execute>[0];

/** One scanned scope: a heavy bulk sender + a light personal sender. */
const SENDERS = {
  scannedAt: "2026-08-19T00:00:00.000Z",
  scope: { name: "inbox", mode: "role", inMailbox: null, maxMessages: null },
  scannedMessages: 100,
  unreadMessages: 30,
  senderCount: 2,
  bulkSenders: 1,
  senders: [
    {
      email: "news@example.com",
      name: "Example News",
      count: 80,
      bulkCount: 80,
      unreadCount: 25,
      oneClickUnsubscribe: true,
      listIds: ["news.example.com"],
      mostRecent: "2026-08-18T00:00:00.000Z",
      sampleSubjects: ["Weekly digest"],
    },
    {
      email: "mom@example.com",
      name: "Mom",
      count: 20,
      bulkCount: 0,
      unreadCount: 5,
      oneClickUnsubscribe: false,
      listIds: [],
      mostRecent: "2026-08-17T00:00:00.000Z",
      sampleSubjects: ["dinner?"],
    },
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

Deno.test("fastmail-audit: renders scope summary, bulk stats, and concentration", async () => {
  const { markdown, json } = await report.execute(
    ctx([{ specName: "senders", name: "inbox", version: 1 }], {
      inbox: SENDERS,
    }),
  );
  assertStringIncludes(markdown, "# Inbox Audit");
  assertStringIncludes(markdown, "## Scope: `inbox` (role)");
  assertStringIncludes(markdown, "**Messages scanned:** 100");
  assertStringIncludes(markdown, "**Bulk senders:** 1");
  assertStringIncludes(markdown, "news@example.com");

  const scope = json as {
    applicable: boolean;
    scopes: Record<string, unknown>[];
  };
  assertEquals(scope.applicable, true);
  assertEquals(scope.scopes[0].bulkSenders, 1);
  assertEquals(scope.scopes[0].oneClickUnsubscribe, 1);
  // 80 of 100 messages come from one sender → 1 sender is >=50% and >=80%.
  assertEquals(scope.scopes[0].concentration50, 1);
  assertEquals(scope.scopes[0].concentration80, 1);
});

Deno.test("fastmail-audit: no senders data short-circuits (not an email_senders scan)", async () => {
  const { markdown, json } = await report.execute(
    ctx([{ specName: "sieve", name: "config", version: 1 }], {}),
  );
  assertStringIncludes(markdown, "not an email_senders scan");
  assertEquals((json as { applicable: boolean }).applicable, false);
});

Deno.test("fastmail-audit: aggregates multiple senders scopes", async () => {
  const second = { ...SENDERS, scope: { ...SENDERS.scope, name: "archive" } };
  const { markdown, json } = await report.execute(
    ctx(
      [
        { specName: "senders", name: "inbox", version: 1 },
        { specName: "senders", name: "archive", version: 1 },
      ],
      { inbox: SENDERS, archive: second },
    ),
  );
  assertStringIncludes(markdown, "## Scope: `inbox`");
  assertStringIncludes(markdown, "## Scope: `archive`");
  assertEquals(
    (json as { scopes: unknown[] }).scopes.length,
    2,
  );
});
