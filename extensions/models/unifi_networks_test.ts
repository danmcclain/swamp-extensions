/**
 * Unit tests for the pure request-handling seams of the unifi-networks
 * extension — focused on the insecure (curl) path, whose string-surgery on
 * curl's stdout is the most regression-prone logic in the transport layer.
 *
 * Run with: deno test extensions/models/unifi_networks_test.ts
 */

import { assertEquals, assertThrows } from "jsr:@std/assert@1";
import {
  buildCurlArgs,
  finalizeResponse,
  ipv4InSubnet,
  ipv4ToInt,
  parseCurlOutput,
} from "./unifi_networks.ts";

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

// ── ipv4ToInt ─────────────────────────────────────────────────────────────────

Deno.test("ipv4ToInt: parses dotted quads to uint32", () => {
  assertEquals(ipv4ToInt("0.0.0.0"), 0);
  assertEquals(ipv4ToInt("10.0.0.1"), 0x0A000001);
  assertEquals(ipv4ToInt("255.255.255.255"), 0xFFFFFFFF); // stays unsigned
  assertEquals(ipv4ToInt("192.168.1.1"), 0xC0A80101);
});

Deno.test("ipv4ToInt: rejects malformed input", () => {
  assertEquals(ipv4ToInt("10.0.0"), null); // too few octets
  assertEquals(ipv4ToInt("10.0.0.1.2"), null); // too many
  assertEquals(ipv4ToInt("10.0.0.256"), null); // octet out of range
  assertEquals(ipv4ToInt("10.0.0.x"), null); // non-numeric
  assertEquals(ipv4ToInt(""), null);
});

// ── ipv4InSubnet ──────────────────────────────────────────────────────────────

Deno.test("ipv4InSubnet: matches inside and rejects outside a /24", () => {
  assertEquals(ipv4InSubnet("10.0.10.51", "10.0.10.1", 24), true);
  assertEquals(ipv4InSubnet("10.0.10.255", "10.0.10.1", 24), true);
  assertEquals(ipv4InSubnet("10.0.11.5", "10.0.10.1", 24), false); // next subnet
  assertEquals(ipv4InSubnet("10.0.0.5", "10.0.10.1", 24), false);
});

Deno.test("ipv4InSubnet: boundary prefixes /32 and /0", () => {
  assertEquals(ipv4InSubnet("10.0.0.1", "10.0.0.1", 32), true); // exact host
  assertEquals(ipv4InSubnet("10.0.0.2", "10.0.0.1", 32), false);
  assertEquals(ipv4InSubnet("8.8.8.8", "10.0.0.1", 0), true); // /0 matches all
});

Deno.test("ipv4InSubnet: malformed IP or bad prefix is a non-match, not a throw", () => {
  assertEquals(ipv4InSubnet("not-an-ip", "10.0.0.1", 24), false);
  assertEquals(ipv4InSubnet("10.0.0.1", "10.0.0.1", 33), false);
  assertEquals(ipv4InSubnet("10.0.0.1", "10.0.0.1", -1), false);
});
