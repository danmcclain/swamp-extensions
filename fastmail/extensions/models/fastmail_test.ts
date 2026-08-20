/**
 * Tests for the @dmc/fastmail model's `valid-api-token` check. The check calls
 * the JMAP session endpoint via global `fetch`, so these stub `globalThis.fetch`
 * to exercise the pass path, the missing-primary-account failure, and the
 * token-redaction branch on a transport error.
 *
 * Run with: deno test extensions/models/fastmail_test.ts
 */

import { assertEquals } from "jsr:@std/assert@1";
import { model } from "./fastmail.ts";

const MAIL_URN = "urn:ietf:params:jmap:mail";
const check = model.checks["valid-api-token"];

type CheckResult = { pass: boolean; errors?: string[] };

/** Run `fn` with global fetch replaced by `stub`, always restoring it after. */
async function withFetch(
  stub: typeof fetch,
  fn: () => Promise<unknown>,
): Promise<unknown> {
  const original = globalThis.fetch;
  globalThis.fetch = stub;
  try {
    return await fn();
  } finally {
    globalThis.fetch = original;
  }
}

/** A minimal ok Response whose json() yields `body`. */
function jsonResponse(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    json: () => Promise.resolve(body),
  } as Response;
}

const globalArgs = {
  apiToken: "secret-token",
  sessionUrl: "https://api.fastmail.com/.well-known/jmap",
};

Deno.test("valid-api-token: passes when the session exposes a mail account", async () => {
  const result = await withFetch(
    () =>
      Promise.resolve(
        jsonResponse({
          apiUrl: "https://api",
          primaryAccounts: { [MAIL_URN]: "acct1" },
        }),
      ),
    () => check.execute({ globalArgs }),
  ) as CheckResult;
  assertEquals(result.pass, true);
});

Deno.test("valid-api-token: fails when no primary mail account is present", async () => {
  const result = await withFetch(
    () =>
      Promise.resolve(
        jsonResponse({ apiUrl: "https://api", primaryAccounts: {} }),
      ),
    () => check.execute({ globalArgs }),
  ) as CheckResult;
  assertEquals(result.pass, false);
  assertEquals(
    (result.errors ?? []).some((e) => e.includes("no primary account")),
    true,
  );
});

Deno.test("valid-api-token: redacts the token if it leaks into an error", async () => {
  const result = await withFetch(
    () => Promise.reject(new Error(`connect failed for secret-token`)),
    () => check.execute({ globalArgs }),
  ) as CheckResult;
  assertEquals(result.pass, false);
  assertEquals(result.errors, ["[token redacted]"]);
});
