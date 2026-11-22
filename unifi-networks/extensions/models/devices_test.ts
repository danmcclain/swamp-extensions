/**
 * Unit tests for mapDevices behind scanDevices: the MAC join of integration
 * API devices (state, firmware) with classic stat/device entries (last seen,
 * uptime, offered upgrade, uplink, per-port STP state).
 *
 * Run with: deno test extensions/models/devices_test.ts
 */

import { assertEquals } from "jsr:@std/assert@1";
import { mapDevices } from "./unifi_networks.ts";

type Obj = Record<string, unknown>;

const INTEGRATION: Obj[] = [
  {
    id: "d-core",
    name: "Core",
    model: "SW24A",
    macAddress: "AA:AA:AA:00:00:01",
    ipAddress: "192.0.2.10",
    state: "ONLINE",
    firmwareVersion: "7.1.26",
    firmwareUpdatable: false,
  },
  {
    id: "d-ups",
    name: "UPS",
    model: "UPS1A",
    macAddress: "aa:aa:aa:00:00:02",
    ipAddress: "192.0.2.20",
    state: "OFFLINE",
    firmwareVersion: "1.0.9",
    firmwareUpdatable: true,
  },
];

const CLASSIC: Obj[] = [
  {
    name: "Core",
    mac: "aa:aa:aa:00:00:01",
    version: "7.1.26",
    last_seen: 1_763_800_000,
    uptime: 86_400,
    upgrade_to_firmware: "7.1.26",
    port_table: [
      {
        port_idx: 9,
        name: "Port 9",
        up: true,
        speed: 100,
        stp_state: "blocking",
        stp_pathcost: 200000,
      },
      {
        port_idx: 13,
        name: "Port 13",
        up: true,
        speed: 1000,
        stp_state: "forwarding",
      },
      { port_idx: 14, name: "Port 14", up: false, stp_state: "disabled" },
    ],
  },
  {
    name: "UPS",
    mac: "aa:aa:aa:00:00:02",
    version: "1.6.8",
    last_seen: 1_763_700_000,
    upgradable: true,
    upgrade_to_firmware: "1.7.0",
    uplink: { uplink_mac: "AA:AA:AA:00:00:01", uplink_remote_port: 9 },
    port_table: [{ port_idx: 1, name: "Port 1", up: false }],
  },
  { name: "Classic only", mac: "aa:aa:aa:00:00:03", version: "6.0.0" },
];

Deno.test("mapDevices: integration state and firmware win, classic adds last seen and STP", () => {
  const [core] = mapDevices(INTEGRATION, CLASSIC);
  assertEquals(core.mac, "aa:aa:aa:00:00:01");
  assertEquals([core.state, core.firmwareVersion], ["ONLINE", "7.1.26"]);
  assertEquals(core.lastSeen, new Date(1_763_800_000 * 1000).toISOString());
  assertEquals(core.uptimeSeconds, 86_400);
  assertEquals(
    core.upgradeToFirmware,
    undefined,
    "same as current: no upgrade",
  );
  assertEquals(core.stpBlockedPorts, [9]);
  assertEquals(core.ports.map((p) => [p.portIdx, p.stpState]), [
    [9, "blocking"],
    [13, "forwarding"],
    [14, "disabled"],
  ]);
  assertEquals(core.ports[0].stpPathCost, 200000);
});

Deno.test("mapDevices: offline device keeps its last firmware, offered upgrade and named uplink", () => {
  const ups = mapDevices(INTEGRATION, CLASSIC)[1];
  assertEquals(ups.state, "OFFLINE");
  assertEquals(ups.firmwareVersion, "1.0.9", "integration firmware wins");
  assertEquals(ups.firmwareUpdatable, true);
  assertEquals(ups.upgradeToFirmware, "1.7.0");
  assertEquals(ups.uplink, {
    deviceMac: "aa:aa:aa:00:00:01",
    deviceName: "Core",
    port: 9,
  });
  assertEquals(ups.stpBlockedPorts, []);
});

Deno.test("mapDevices: a device in only one list is still reported", () => {
  const all = mapDevices(INTEGRATION, CLASSIC);
  assertEquals(all.map((d) => d.name), ["Core", "UPS", "Classic only"]);
  const only = all[2];
  assertEquals([only.state, only.firmwareVersion, only.id], [
    undefined,
    "6.0.0",
    undefined,
  ]);
  assertEquals(mapDevices(INTEGRATION, []).map((d) => d.ports.length), [0, 0]);
});
