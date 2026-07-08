/**
 * Tests for the zone-matrix report — covers the success path (posture grid +
 * override marks + legend), the failed-scan path, the wrong-method
 * short-circuit, and the no-data path.
 *
 * Run with: deno test extensions/reports/unifi_zone_matrix_test.ts
 */

import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { report } from "./unifi_zone_matrix.ts";

type Ctx = Parameters<typeof report.execute>[0];

const CATCH_ALL = 2147483647;

const SITE = {
  scannedAt: "2026-07-07T00:00:00.000Z",
  siteName: "Default",
  consoleShortname: "UDMPRO",
  zones: [
    { name: "Internal", networkIds: ["n1"] },
    { name: "Dmz", networkIds: [] },
  ],
  policies: [
    // default posture
    {
      index: CATCH_ALL,
      enabled: true,
      action: "ALLOW",
      sourceZone: "Internal",
      destinationZone: "Dmz",
    },
    {
      index: CATCH_ALL,
      enabled: true,
      action: "BLOCK",
      sourceZone: "Dmz",
      destinationZone: "Internal",
    },
    // a higher-priority override on Dmz→Internal (should mark the cell with *)
    {
      index: 10000,
      enabled: true,
      action: "ALLOW",
      sourceZone: "Dmz",
      destinationZone: "Internal",
    },
  ],
};

function ctx(overrides: Partial<Ctx> = {}): Ctx {
  return {
    modelType: "@dmc/unifi-networks",
    modelId: "m1",
    methodName: "scanFirewall",
    executionStatus: "succeeded",
    dataHandles: [{ name: "Default", specName: "siteFirewall", version: 1 }],
    dataRepository: {
      getContent: () =>
        Promise.resolve(new TextEncoder().encode(JSON.stringify(SITE))),
    },
    ...overrides,
  } as Ctx;
}

Deno.test("zone-matrix: success renders the grid, override mark, and legend", async () => {
  const { markdown, json } = await report.execute(ctx());
  assertStringIncludes(markdown, "UniFi Zone Matrix — UDMPRO · Default");
  assertStringIncludes(markdown, "from ↓ / to →");
  assertStringIncludes(markdown, "_(empty)_"); // Dmz labelled empty
  assertStringIncludes(markdown, "Legend:");
  assertStringIncludes(markdown, "*"); // the Dmz→Internal override mark
  const j = json as { status: string; sites: { overrideCount: number }[] };
  assertEquals(j.status, "ok");
  assertEquals(j.sites[0].overrideCount, 1);
});

Deno.test("zone-matrix: failed scan reports the error", async () => {
  const { markdown, json } = await report.execute(
    ctx({ executionStatus: "failed", errorMessage: "kaboom" }),
  );
  assertStringIncludes(markdown, "Scan failed");
  assertStringIncludes(markdown, "kaboom");
  assertEquals((json as { status: string }).status, "failed");
});

Deno.test("zone-matrix: non-scanFirewall method short-circuits", async () => {
  const { markdown, json } = await report.execute(ctx({ methodName: "scan" }));
  assertEquals(markdown, "");
  assertEquals(json, {});
});

Deno.test("zone-matrix: no firewall data yields no-data status", async () => {
  const { markdown, json } = await report.execute(ctx({ dataHandles: [] }));
  assertStringIncludes(markdown, "No firewall data");
  assertEquals((json as { status: string }).status, "no-data");
});
