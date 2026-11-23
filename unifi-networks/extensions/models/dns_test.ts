/**
 * Tests for mapDnsRecords — one row per DNS policy with the type-specific
 * target folded into `value`, sorted by domain then type.
 *
 * Run with: deno test extensions/models/dns_test.ts
 */

import { assertEquals } from "jsr:@std/assert@1";
import { mapDnsRecords } from "./unifi_networks.ts";

const meta = { origin: "USER_DEFINED" };

Deno.test("mapDnsRecords: every record type folds its target into value", () => {
  const rows = mapDnsRecords([
    {
      id: "a",
      type: "A_RECORD",
      domain: "host1.lan.example",
      ipv4Address: "192.0.2.50",
      ttlSeconds: 3600,
      enabled: true,
      metadata: meta,
    },
    {
      id: "aaaa",
      type: "AAAA_RECORD",
      domain: "host1.lan.example",
      ipv6Address: "2001:db8::50",
      ttlSeconds: 600,
      enabled: true,
    },
    {
      id: "cname",
      type: "CNAME_RECORD",
      domain: "www.lan.example",
      targetDomain: "host1.lan.example",
      ttlSeconds: 300,
      enabled: false,
    },
    {
      id: "mx",
      type: "MX_RECORD",
      domain: "lan.example",
      mailServerDomain: "mail.lan.example",
      priority: 10,
      enabled: true,
    },
    {
      id: "txt",
      type: "TXT_RECORD",
      domain: "lan.example",
      text: "v=spf1 -all",
      enabled: true,
    },
    {
      id: "srv",
      type: "SRV_RECORD",
      domain: "lan.example",
      service: "_sip",
      protocol: "_tcp",
      serverDomain: "sip.lan.example",
      port: 5060,
      priority: 1,
      weight: 5,
      enabled: true,
    },
    {
      id: "fwd",
      type: "FORWARD_DOMAIN",
      domain: "corp.example",
      ipAddress: "198.51.100.53",
      enabled: true,
    },
    { type: "A_RECORD", domain: "no-id.lan.example" },
  ]);
  assertEquals(
    rows.map((r) => [r.domain, r.type, r.value]),
    [
      ["corp.example", "FORWARD_DOMAIN", "198.51.100.53"],
      ["host1.lan.example", "A_RECORD", "192.0.2.50"],
      ["host1.lan.example", "AAAA_RECORD", "2001:db8::50"],
      ["lan.example", "MX_RECORD", "mail.lan.example"],
      ["lan.example", "SRV_RECORD", "_sip._tcp sip.lan.example:5060"],
      ["lan.example", "TXT_RECORD", "v=spf1 -all"],
      ["www.lan.example", "CNAME_RECORD", "host1.lan.example"],
    ],
  );
  const a = rows[1];
  assertEquals(a.ttlSeconds, 3600);
  assertEquals(a.origin, "USER_DEFINED");
  const srv = rows[4];
  assertEquals([srv.priority, srv.weight], [1, 5]);
  assertEquals(rows[6].enabled, false);
});

Deno.test("mapDnsRecords: an unknown type keeps the row with an empty value", () => {
  const [r] = mapDnsRecords([
    { id: "x", type: "NEW_KIND", domain: "x.lan.example", enabled: true },
  ]);
  assertEquals([r.type, r.value, r.ttlSeconds], ["NEW_KIND", "", undefined]);
});
