/**
 * Tests for the firewall-summary report — covers the success path (zones +
 * policy table + attention callouts), the failed-scan path, the wrong-method
 * short-circuit, and the no-data path.
 *
 * Run with: deno test extensions/reports/unifi_firewall_summary_test.ts
 */

import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { report } from "./unifi_firewall_summary.ts";

type Ctx = Parameters<typeof report.execute>[0];

const SITE = {
  scannedAt: "2026-07-07T00:00:00.000Z",
  siteName: "Default",
  consoleShortname: "UDMPRO",
  zoneCount: 2,
  policyCount: 2,
  zones: [
    { id: "z1", name: "Internal", networkIds: ["n1"], metadataOrigin: "SYSTEM_DEFINED" },
    { id: "z2", name: "Dmz", networkIds: [], metadataOrigin: "SYSTEM_DEFINED" },
  ],
  policies: [
    {
      id: "p1",
      name: "Allow DMZ to server (for now)",
      enabled: true,
      index: 10000,
      action: "ALLOW",
      sourceZone: "Dmz",
      destinationZone: "Internal",
      protocol: "all",
      metadataOrigin: "USER_DEFINED",
    },
    {
      id: "p2",
      name: "Block All Traffic",
      enabled: true,
      index: 2147483647,
      action: "BLOCK",
      sourceZone: "Internal",
      destinationZone: "Dmz",
      metadataOrigin: "SYSTEM_DEFINED",
    },
  ],
};

/** Build a report context whose dataRepository serves the given site fixtures. */
function ctx(overrides: Partial<Ctx> = {}, sites: Record<string, unknown>[] = [SITE]): Ctx {
  return {
    modelType: "@dmc/unifi-networks",
    modelId: "m1",
    methodName: "scanFirewall",
    executionStatus: "succeeded",
    dataHandles: sites.map((_, i) => ({
      name: `Default${i || ""}`,
      specName: "siteFirewall",
      version: 1,
    })),
    dataRepository: {
      getContent: (_t, _m, name) => {
        const idx = name === "Default" ? 0 : Number(name.replace("Default", "")) || 0;
        const s = sites[idx];
        return Promise.resolve(
          s ? new TextEncoder().encode(JSON.stringify(s)) : null,
        );
      },
    },
    ...overrides,
  } as Ctx;
}

Deno.test("firewall-summary: success renders zones, policies, and attention flags", async () => {
  const { markdown, json } = await report.execute(ctx());
  assertStringIncludes(markdown, "UniFi Firewall Summary — UDMPRO · Default");
  assertStringIncludes(markdown, "## Zones");
  assertStringIncludes(markdown, "Internal");
  assertStringIncludes(markdown, "— (empty)"); // Dmz has no networks
  assertStringIncludes(markdown, "## User-Defined Policies");
  assertStringIncludes(markdown, "Allow DMZ to server (for now)");
  // Attention section flags the temp-name rule AND the unrestricted allow
  assertStringIncludes(markdown, "## Attention");
  assertStringIncludes(markdown, "temporary rule");
  assertStringIncludes(markdown, "unrestricted ALLOW");
  assertEquals((json as { status: string }).status, "ok");
});

Deno.test("firewall-summary: failed scan reports the error", async () => {
  const { markdown, json } = await report.execute(
    ctx({ executionStatus: "failed", errorMessage: "boom" }),
  );
  assertStringIncludes(markdown, "Scan failed");
  assertStringIncludes(markdown, "boom");
  assertEquals((json as { status: string }).status, "failed");
});

Deno.test("firewall-summary: non-scanFirewall method short-circuits", async () => {
  const { markdown, json } = await report.execute(ctx({ methodName: "scan" }));
  assertEquals(markdown, "");
  assertEquals(json, {});
});

Deno.test("firewall-summary: no firewall data yields no-data status", async () => {
  const { markdown, json } = await report.execute(ctx({ dataHandles: [] }));
  assertStringIncludes(markdown, "No firewall data");
  assertEquals((json as { status: string }).status, "no-data");
});
