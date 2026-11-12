/**
 * Unit tests for the switch port helpers behind scanPorts: network indexing,
 * VLAN resolution (override, then profile, then port defaults) and the
 * per-port join with clients and LLDP neighbours.
 *
 * Run with: deno test extensions/models/switch_ports_test.ts
 */

import { assertEquals } from "jsr:@std/assert@1";
import {
  classicBase,
  mapClassicNetworks,
  mapSwitchPorts,
  resolvePortVlans,
} from "./unifi_networks.ts";

type Obj = Record<string, unknown>;

const NETWORKS: Obj[] = [
  {
    _id: "n-default",
    name: "Default",
    purpose: "corporate",
    vlan_enabled: false,
    attr_no_delete: true,
  },
  {
    _id: "n-10",
    name: "Servers",
    purpose: "corporate",
    vlan: 10,
    vlan_enabled: true,
  },
  {
    _id: "n-20",
    name: "Services",
    purpose: "corporate",
    vlan: "20",
    vlan_enabled: true,
  },
  {
    _id: "n-90",
    name: "IoT",
    purpose: "corporate",
    vlan: 90,
    vlan_enabled: true,
  },
  { _id: "n-wan", name: "Internet 1", purpose: "wan", vlan_enabled: false },
];
const NETS = mapClassicNetworks(NETWORKS);
const vlans = (r: { tagged: { vlanId: number }[] }) =>
  r.tagged.map((t) => t.vlanId);

Deno.test("mapClassicNetworks: VLAN ids, 1 for untagged, Default found", () => {
  assertEquals(NETS.defaultId, "n-default");
  assertEquals(NETS.byId["n-default"].vlanId, 1);
  assertEquals(NETS.byId["n-20"].vlanId, 20);
  assertEquals(NETS.byId["n-wan"].vlanId, 1);
});

Deno.test("resolvePortVlans: forward all = Default native, every VLAN tagged", () => {
  const r = resolvePortVlans(
    { port_idx: 25, forward: "all" },
    undefined,
    {},
    NETS,
  );
  assertEquals(r.source, "port");
  assertEquals(r.native?.networkName, "Default");
  assertEquals(r.taggedMode, "all");
  assertEquals(vlans(r), [10, 20, 90]);
});

Deno.test("resolvePortVlans: no forward field defaults to all", () => {
  const r = resolvePortVlans({ port_idx: 1 }, undefined, {}, NETS);
  assertEquals(r.forward, "all");
  assertEquals(r.native?.vlanId, 1);
});

Deno.test("resolvePortVlans: override with a native VLAN and auto tags the rest, not the native", () => {
  const r = resolvePortVlans(
    { port_idx: 19, forward: "all" },
    {
      port_idx: 19,
      forward: "customize",
      native_networkconf_id: "n-10",
      tagged_vlan_mgmt: "auto",
    },
    {},
    NETS,
  );
  assertEquals(r.source, "override");
  assertEquals(r.native, {
    networkId: "n-10",
    networkName: "Servers",
    vlanId: 10,
  });
  assertEquals(r.taggedMode, "all");
  assertEquals(vlans(r), [20, 90]);
});

Deno.test("resolvePortVlans: custom excludes the listed networks", () => {
  const r = resolvePortVlans(
    { port_idx: 3 },
    {
      port_idx: 3,
      forward: "customize",
      native_networkconf_id: "n-10",
      tagged_vlan_mgmt: "custom",
      excluded_networkconf_ids: ["n-90"],
    },
    {},
    NETS,
  );
  assertEquals(r.taggedMode, "custom");
  assertEquals(vlans(r), [20]);
  assertEquals(r.excluded.map((e) => e.networkName), ["IoT"]);
});

Deno.test("resolvePortVlans: block_all and native forward carry no tagged VLANs", () => {
  const block = resolvePortVlans(
    {
      port_idx: 4,
      forward: "customize",
      tagged_vlan_mgmt: "block_all",
      native_networkconf_id: "n-20",
    },
    undefined,
    {},
    NETS,
  );
  assertEquals([block.taggedMode, block.tagged, block.native?.vlanId], [
    "none",
    [],
    20,
  ]);
  const native = resolvePortVlans(
    { port_idx: 5, forward: "native" },
    undefined,
    {},
    NETS,
  );
  assertEquals([native.taggedMode, native.native?.networkName], [
    "none",
    "Default",
  ]);
});

Deno.test("resolvePortVlans: disabled port has no native and no tagged", () => {
  const r = resolvePortVlans(
    { port_idx: 6 },
    { port_idx: 6, forward: "disabled" },
    {},
    NETS,
  );
  assertEquals([r.native, r.taggedMode, r.tagged], [undefined, "none", []]);
});

Deno.test("resolvePortVlans: a profile named by the override supplies the VLANs", () => {
  const profiles = {
    "pc-1": {
      _id: "pc-1",
      name: "K3S Ports",
      forward: "customize",
      native_networkconf_id: "n-20",
      tagged_vlan_mgmt: "block_all",
    },
  };
  const r = resolvePortVlans(
    { port_idx: 7, forward: "all" },
    { port_idx: 7, portconf_id: "pc-1", name: "k3s-1" },
    profiles,
    NETS,
  );
  assertEquals(r.source, "profile");
  assertEquals(r.profileName, "K3S Ports");
  assertEquals([r.native?.vlanId, r.taggedMode], [20, "none"]);
});

Deno.test("resolvePortVlans: older explicit tagged list is custom", () => {
  const r = resolvePortVlans(
    { port_idx: 8 },
    {
      port_idx: 8,
      forward: "customize",
      native_networkconf_id: "n-default",
      tagged_networkconf_ids: ["n-90", "n-20"],
    },
    {},
    NETS,
  );
  assertEquals([r.taggedMode, vlans(r)], ["custom", [20, 90]]);
});

Deno.test("resolvePortVlans: an unknown network id is kept, with VLAN 0", () => {
  const r = resolvePortVlans(
    {
      port_idx: 9,
      forward: "customize",
      native_networkconf_id: "gone",
      tagged_vlan_mgmt: "block_all",
    },
    undefined,
    {},
    NETS,
  );
  assertEquals(r.native, { networkId: "gone", networkName: "gone", vlanId: 0 });
});

Deno.test("mapSwitchPorts: joins ports to clients and LLDP, skips devices without ports", () => {
  const devices: Obj[] = [
    {
      name: "Core",
      mac: "aa:aa",
      model: "SW24A",
      port_table: [
        {
          port_idx: 1,
          name: "Port 1",
          up: true,
          speed: 10000,
          media: "SFP+",
          forward: "all",
        },
        { port_idx: 2, name: "Port 2", up: false, is_uplink: true },
      ],
      port_overrides: [{
        port_idx: 1,
        forward: "customize",
        native_networkconf_id: "n-10",
        tagged_vlan_mgmt: "auto",
      }],
      lldp_table: [{ local_port_idx: 2, chassis_id: "bb:bb", port_id: "eth0" }],
    },
    { name: "AP", mac: "cc:cc", port_table: [] },
    { name: "Old AP", mac: "dd:dd" },
  ];
  const clients: Obj[] = [
    {
      mac: "11:11",
      name: "hv-1",
      ip: "192.0.2.50",
      sw_mac: "aa:aa",
      sw_port: 1,
    },
    { mac: "22:22", hostname: "laptop", sw_mac: "aa:aa", sw_port: 3 },
    { mac: "33:33", ip: "192.0.2.9" },
  ];
  const ports = mapSwitchPorts(devices, [], NETWORKS, clients);
  assertEquals(ports.length, 2);
  const [p1, p2] = ports;
  assertEquals(
    [
      p1.deviceName,
      p1.portIdx,
      p1.up,
      p1.speedMbps,
      p1.media,
      p1.native?.vlanId,
    ],
    ["Core", 1, true, 10000, "SFP+", 10],
  );
  assertEquals(p1.clients, [{ name: "hv-1", mac: "11:11", ip: "192.0.2.50" }]);
  assertEquals([p2.isUplink, p2.up, p2.clients, p2.lldpNeighbors], [
    true,
    false,
    [],
    [{ chassisId: "bb:bb", portId: "eth0" }],
  ]);
});

Deno.test("classicBase: swaps /integration for /api on local and cloud bases", () => {
  assertEquals(
    classicBase("https://console/proxy/network/integration"),
    "https://console/proxy/network/api",
  );
  assertEquals(
    classicBase(
      "https://api.ui.com/v1/connector/consoles/c1/proxy/network/integration",
    ),
    "https://api.ui.com/v1/connector/consoles/c1/proxy/network/api",
  );
});
