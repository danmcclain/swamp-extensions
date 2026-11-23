/**
 * Tests for the DNS records report — the diff between two siteDnsRecords
 * snapshots, the summary, the rendered markdown, and the failed,
 * wrong-method, first-snapshot and no-data paths.
 *
 * Run with: deno test extensions/reports/unifi_dns_records_test.ts
 */

import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import {
  buildSiteDns,
  diffDnsRecords,
  report,
  typeLabel,
} from "./unifi_dns_records.ts";

type Ctx = Parameters<typeof report.execute>[0];
type Obj = Record<string, unknown>;

const host1 = (over: Obj = {}) => ({
  id: "p1",
  type: "A_RECORD",
  domain: "host1.lan.example",
  value: "192.0.2.50",
  ttlSeconds: 3600,
  enabled: true,
  ...over,
});
const www = (over: Obj = {}) => ({
  id: "p2",
  type: "CNAME_RECORD",
  domain: "www.lan.example",
  value: "host1.lan.example",
  ttlSeconds: 300,
  enabled: true,
  ...over,
});
const site = (records: Obj[], scannedAt = "2026-11-23T05:15:00.000Z") => ({
  scannedAt,
  siteName: "Default",
  records,
});

Deno.test("typeLabel: short names", () => {
  assertEquals(typeLabel("A_RECORD"), "A");
  assertEquals(typeLabel("SRV_RECORD"), "SRV");
  assertEquals(typeLabel("FORWARD_DOMAIN"), "Forward");
});

Deno.test("diffDnsRecords: added, removed, changed fields", () => {
  const changes = diffDnsRecords(
    [host1(), www()] as never,
    [
      host1({ value: "192.0.2.51", enabled: false }),
      { ...www(), id: "p3", domain: "app.lan.example" },
    ] as never,
  );
  assertEquals(changes, [
    {
      domain: "host1.lan.example",
      type: "A_RECORD",
      kind: "changed",
      fields: [
        { field: "value", from: "192.0.2.50", to: "192.0.2.51" },
        { field: "enabled", from: "true", to: "false" },
      ],
    },
    { domain: "app.lan.example", type: "CNAME_RECORD", kind: "added" },
    { domain: "www.lan.example", type: "CNAME_RECORD", kind: "removed" },
  ]);
});

Deno.test("buildSiteDns: summary counts by type and disabled", () => {
  const s = buildSiteDns(site([host1(), www({ enabled: false })]) as never);
  assertEquals(s.summary, {
    records: 2,
    disabled: 1,
    byType: { A: 1, CNAME: 1 },
  });
  assertEquals(s.changes, []);
});

/** A report context whose repository serves siteDnsRecords versions. */
function ctx(
  versions: Record<number, Obj>,
  current: number,
  overrides: Partial<Ctx> = {},
): Ctx {
  return {
    modelType: "@dmc/unifi-networks",
    modelId: "m1",
    methodName: "scanDns",
    executionStatus: "succeeded",
    dataHandles: [{
      name: "dns-Default",
      specName: "siteDnsRecords",
      version: current,
    }],
    dataRepository: {
      getContent: (_t, _m, _n, v) => {
        const s = v === undefined ? undefined : versions[v];
        return Promise.resolve(
          s ? new TextEncoder().encode(JSON.stringify(s)) : null,
        );
      },
    },
    ...overrides,
  };
}

Deno.test("report: renders the table and the changes since the previous version", async () => {
  const r = await report.execute(ctx({
    4: site([host1()], "2026-11-22T05:15:00.000Z"),
    5: site([host1({ ttlSeconds: 60 }), www({ enabled: false })]),
  }, 5));
  assertStringIncludes(r.markdown, "# UniFi DNS Records — Default");
  assertStringIncludes(r.markdown, "**Records**: 2 (A 1, CNAME 1)");
  assertStringIncludes(
    r.markdown,
    "`host1.lan.example` (A): ttlSeconds 3600 → 60",
  );
  assertStringIncludes(r.markdown, "`www.lan.example` (CNAME): added");
  assertStringIncludes(
    r.markdown,
    "| www.lan.example | CNAME | host1.lan.example | 300 | — | **no** |",
  );
});

Deno.test("report: first snapshot, empty site, and a non-DNS previous version", async () => {
  const first = await report.execute(ctx({ 1: site([]) }, 1));
  assertStringIncludes(first.markdown, "First snapshot");
  assertStringIncludes(first.markdown, "No local DNS records.");
  const otherSpec = await report.execute(
    ctx({ 2: { siteName: "Default", devices: [] }, 3: site([host1()]) }, 3),
  );
  assertStringIncludes(otherSpec.markdown, "First snapshot");
});

Deno.test("report: a pipe or newline in a value does not break the table", async () => {
  const r = await report.execute(
    ctx({
      1: site([{
        ...host1(),
        type: "TXT_RECORD",
        value: "a|b\nc",
        ttlSeconds: undefined,
      }]),
    }, 1),
  );
  assertStringIncludes(r.markdown, "| a\\|b c |");
});

Deno.test("report: failed scan, other methods and no data", async () => {
  const failed = await report.execute(
    ctx({}, 1, { executionStatus: "failed", errorMessage: "boom" }),
  );
  assertEquals(failed.json, { status: "failed", error: "boom" });
  const other = await report.execute(
    ctx({}, 1, { methodName: "scanDevices" }),
  );
  assertEquals(other, { markdown: "", json: {} });
  const none = await report.execute(ctx({}, 1, { dataHandles: [] }));
  assertEquals(none.json, { status: "no-data" });
});
