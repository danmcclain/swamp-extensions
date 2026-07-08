/**
 * Unit tests for the pure request-handling seams of the unifi-networks
 * extension — focused on the insecure (curl) path, whose string-surgery on
 * curl's stdout is the most regression-prone logic in the transport layer.
 *
 * Run with: deno test extensions/models/unifi_networks_test.ts
 */

import { assertEquals, assertThrows } from "jsr:@std/assert@1";
import { buildCurlArgs, finalizeResponse, parseCurlOutput } from "./unifi_networks.ts";

// ── parseCurlOutput ───────────────────────────────────────────────────────────

Deno.test("parseCurlOutput: body + trailing status line", () => {
  const { status, body } = parseCurlOutput('{"a":1}\n200');
  assertEquals(status, 200);
  assertEquals(body, '{"a":1}');
});

Deno.test("parseCurlOutput: empty body (204 from DELETE)", () => {
  // curl with -w "\n%{http_code}" emits just "\n204" when the body is empty
  const { status, body } = parseCurlOutput("\n204");
  assertEquals(status, 204);
  assertEquals(body, "");
});

Deno.test("parseCurlOutput: multi-line JSON body keeps every line", () => {
  // The status must be split off the LAST newline, not the first, or a
  // pretty-printed body would be truncated.
  const raw = '{\n  "a": 1,\n  "b": 2\n}\n200';
  const { status, body } = parseCurlOutput(raw);
  assertEquals(status, 200);
  assertEquals(body, '{\n  "a": 1,\n  "b": 2\n}');
  assertEquals(JSON.parse(body), { a: 1, b: 2 });
});

Deno.test("parseCurlOutput: error status with a body", () => {
  const { status, body } = parseCurlOutput('{"code":"unauthorized"}\n401');
  assertEquals(status, 401);
  assertEquals(body, '{"code":"unauthorized"}');
});

// ── finalizeResponse ──────────────────────────────────────────────────────────

Deno.test("finalizeResponse: 2xx JSON body parses", () => {
  assertEquals(finalizeResponse("GET", "/x", 200, '{"ok":true}'), { ok: true });
});

Deno.test("finalizeResponse: 2xx empty body returns null", () => {
  assertEquals(finalizeResponse("DELETE", "/x", 204, ""), null);
  assertEquals(finalizeResponse("DELETE", "/x", 200, "   "), null);
});

Deno.test("finalizeResponse: non-2xx throws with method/url/status/body", () => {
  const err = assertThrows(
    () => finalizeResponse("GET", "/sites", 401, "unauthorized"),
    Error,
    "GET /sites failed (401): unauthorized",
  );
  assertEquals(err instanceof Error, true);
});

Deno.test("finalizeResponse: 5xx throws", () => {
  assertThrows(() => finalizeResponse("POST", "/x", 500, "boom"), Error, "(500)");
});

// ── buildCurlArgs ─────────────────────────────────────────────────────────────

Deno.test("buildCurlArgs: GET includes -k, verb, auth, status writeout", () => {
  const args = buildCurlArgs("GET", "https://udm/x", "secret");
  assertEquals(args.includes("-sk"), true); // -k skips TLS verify
  assertEquals(args[args.indexOf("-X") + 1], "GET");
  assertEquals(args.includes("X-API-KEY: secret"), true);
  assertEquals(args[args.indexOf("-w") + 1], "\n%{http_code}");
  assertEquals(args[args.length - 1], "https://udm/x"); // url is last
  // No body → no content-type / data
  assertEquals(args.includes("--data-binary"), false);
  assertEquals(args.some((a) => a.startsWith("Content-Type")), false);
});

Deno.test("buildCurlArgs: body adds content-type and serialized payload", () => {
  const args = buildCurlArgs("PATCH", "https://udm/p", "secret", { enabled: false });
  assertEquals(args.includes("Content-Type: application/json"), true);
  assertEquals(args[args.indexOf("--data-binary") + 1], '{"enabled":false}');
  assertEquals(args[args.indexOf("-X") + 1], "PATCH");
  assertEquals(args[args.length - 1], "https://udm/p");
});

Deno.test("buildCurlArgs: secret is passed as a header arg, never inline in url", () => {
  const args = buildCurlArgs("GET", "https://udm/x", "s3cr3t");
  // key travels only in the X-API-KEY header, not smuggled into the URL
  assertEquals(args[args.length - 1].includes("s3cr3t"), false);
});
