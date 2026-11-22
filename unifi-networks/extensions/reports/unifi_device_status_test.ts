/**
 * Tests for the device-status report — the diff between two siteDevices
 * snapshots, the summary and row order, the rendered markdown, and the
 * failed, wrong-method, first-snapshot and no-data paths.
 *
 * Run with: deno test extensions/reports/unifi_device_status_test.ts
 */

import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import {
  buildSiteStatus,
  diffDevices,
  formatAgo,
  report,
} from "./unifi_device_status.ts";

type Ctx = Parameters<typeof report.execute>[0];
type Obj = Record<string, unknown>;

const core = (over: Obj = {}) => ({
  name: "Core",
  mac: "aa:aa",
  model: "SW24",
  state: "ONLINE",
  firmwareVersion: "7.0.15",
  firmwareUpdatable: false,
  lastSeen: "2026-11-22T14:00:00.000Z",
  stpBlockedPorts: [] as number[],
  ports: [{ portIdx: 9, stpState: "forwarding" }],
  ...over,
});
const ups = (over: Obj = {}) => ({
  name: "ups-1",
  mac: "bb:bb",
  model: "ups-1",
  state: "ONLINE",
  firmwareVersion: "1.0.4",
  firmwareUpdatable: false,
  lastSeen: "2026-11-22T13:59:00.000Z",
  uplink: { deviceMac: "aa:aa", deviceName: "Core", port: 9 },
  stpBlockedPorts: [] as number[],
  ports: [],
  ...over,
});
const site = (devices: Obj[], scannedAt = "2026-11-22T14:00:30.000Z") => ({
  scannedAt,
  siteName: "Default",
  deviceCount: devices.length,
  devices,
});

Deno.test("diffDevices: state, firmware, upgrade, uplink, STP, added, removed", () => {
  const prev = [core(), ups(), { ...ups(), name: "Old AP", mac: "cc:cc" }];
  const cur = [
    core({
      firmwareVersion: "7.0.16",
      stpBlockedPorts: [9],
      ports: [{ portIdx: 9, stpState: "blocking" }],
    }),
    ups({
      state: "OFFLINE",
      firmwareUpdatable: true,
      upgradeToFirmware: "1.0.9",
      uplink: { deviceMac: "aa:aa", deviceName: "Core", port: 10 },
    }),
    { ...core(), name: "New switch", mac: "dd:dd" },
  ];
  const changes = diffDevices(prev as never, cur as never);
  assertEquals(changes.map((c) => [c.device, c.kind, c.from, c.to]), [
    ["Core", "firmware", "7.0.15", "7.0.16"],
    ["Core", "stp", "none", "9 (blocking)"],
    ["ups-1", "state", "ONLINE", "OFFLINE"],
    ["ups-1", "upgrade", "1.0.4", "1.0.9"],
    ["ups-1", "uplink", "Core port 9", "Core port 10"],
    ["New switch", "added", undefined, "ONLINE"],
    ["Old AP", "removed", "ONLINE", undefined],
  ]);
});

Deno.test("diffDevices: an upgrade already offered last time is not repeated", () => {
  const offered = ups({ firmwareUpdatable: true, upgradeToFirmware: "1.0.9" });
  assertEquals(diffDevices([offered] as never, [offered] as never), []);
});

Deno.test("buildSiteStatus: summary counts, not-online first, last seen age", () => {
  const s = buildSiteStatus(
    site([
      core(),
      ups({ state: "OFFLINE", lastSeen: "2026-10-08T12:00:00.000Z" }),
    ]) as never,
  );
  assertEquals(s.summary, {
    devices: 2,
    online: 1,
    notOnline: 1,
    upgradesAvailable: 0,
    stpBlockedPorts: 0,
  });
  assertEquals(s.devices.map((d) => d.name), ["ups-1", "Core"]);
  assertEquals(formatAgo(s.devices[0].lastSeenAgoSeconds), "45d");
  assertEquals(s.devices[0].uplink, "Core port 9");
  assertEquals(s.changes, [], "no previous snapshot: no changes");
});

Deno.test("formatAgo: units", () => {
  assertEquals(
    [undefined, 30, 600, 7200 * 3, 86400 * 3].map(formatAgo),
    ["never", "now", "10m", "6h", "3d"],
  );
});

/** A report context whose repository serves siteDevices versions by number. */
function ctx(
  versions: Record<number, Obj>,
  current: number,
  overrides: Partial<Ctx> = {},
): Ctx {
  return {
    modelType: "@dmc/unifi-networks",
    modelId: "m1",
    methodName: "scanDevices",
    executionStatus: "succeeded",
    dataHandles: [{
      name: "Default",
      specName: "siteDevices",
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
    4: site([core(), ups()], "2026-11-21T14:00:00.000Z"),
    5: site([core(), ups({ state: "OFFLINE" })]),
  }, 5));
  assertStringIncludes(r.markdown, "# UniFi Device Status — Default");
  assertStringIncludes(r.markdown, "**ups-1** state: ONLINE → OFFLINE");
  assertStringIncludes(r.markdown, "| ups-1 | ups-1 | **OFFLINE** | 1.0.4 |");
  const [s] = (r.json as unknown as { sites: Obj[] }).sites;
  assertEquals(s.previousScannedAt, "2026-11-21T14:00:00.000Z");
  assertEquals((s.changes as Obj[]).length, 1);
});

Deno.test("report: first snapshot and a garbage-collected previous version", async () => {
  const first = await report.execute(ctx({ 1: site([core()]) }, 1));
  assertStringIncludes(
    first.markdown,
    "First snapshot; nothing to compare yet.",
  );
  const gone = await report.execute(ctx({ 9: site([core()]) }, 9));
  assertStringIncludes(gone.markdown, "First snapshot");
  const otherSpec = await report.execute(
    ctx({ 2: { siteName: "Default", ports: [] }, 3: site([core()]) }, 3),
  );
  assertStringIncludes(otherSpec.markdown, "First snapshot");
});

Deno.test("report: failed scan, other methods and no data", async () => {
  const failed = await report.execute(
    ctx({}, 1, { executionStatus: "failed", errorMessage: "boom" }),
  );
  assertEquals(failed.json, { status: "failed", error: "boom" });
  const other = await report.execute(ctx({}, 1, { methodName: "scanPorts" }));
  assertEquals(other, { markdown: "", json: {} });
  const none = await report.execute(ctx({}, 1, { dataHandles: [] }));
  assertEquals(none.json, { status: "no-data" });
});

Deno.test("report: groupBy model makes one table per model, problems counted", async () => {
  const r = await report.execute(
    ctx({ 1: site([core(), ups({ state: "OFFLINE" })]) }, 1, {
      methodArgs: { groupBy: "model" },
    }),
  );
  assertStringIncludes(r.markdown, "### SW24 (1)");
  assertStringIncludes(r.markdown, "### ups-1 (1, 1 not online)");
  assertStringIncludes(r.markdown, "| Device | State | Firmware |");
  assertEquals((r.json as Obj).groupBy, "model");
  const flat = await report.execute(ctx({ 1: site([core()]) }, 1));
  assertStringIncludes(flat.markdown, "| Device | Model | State |");
});
