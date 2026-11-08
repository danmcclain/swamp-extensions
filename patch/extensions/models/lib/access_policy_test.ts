/**
 * Unit tests for the access policy schemas and helpers (acceptance records, the
 * access profile, source addresses). Pure schema checks; no host, no swamp.
 */
import { assert, assertEquals, assertFalse } from "jsr:@std/assert@1";
import {
  AcceptanceRecord,
  AcceptedRisk,
  AccessProfile,
  isOverdue,
  isSourceAddr,
  isValidDay,
  SourceAddr,
  TrustRemote,
  Unsafe,
  unsafeRecord,
} from "./access_policy.ts";

const passes = (
  schema: { safeParse(v: unknown): { success: boolean } },
  v: unknown,
): boolean => schema.safeParse(v).success;

const REC = {
  reason: "Pinned by ops; reviewed quarterly",
  acceptedBy: "dmc",
  acceptedAt: "2026-10-01",
  reviewBy: "2026-10-29",
};

const KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBjngojWT4QUfy2bl78lWkaepNtOZYDlAzZbel8QNoWN swamp-serve";

Deno.test("AcceptanceRecord: a complete record parses", () => {
  assert(passes(AcceptanceRecord, REC));
});

Deno.test("AcceptanceRecord: reviewBy equal to acceptedAt is allowed", () => {
  assert(passes(AcceptanceRecord, { ...REC, reviewBy: REC.acceptedAt }));
});

Deno.test("AcceptanceRecord: reviewBy exactly 365 days after acceptedAt passes", () => {
  const rec = { ...REC, acceptedAt: "2026-10-29", reviewBy: "2027-10-29" };
  assert(passes(AcceptanceRecord, rec));
});

Deno.test("AcceptanceRecord: reviewBy 366 days after acceptedAt fails", () => {
  const rec = { ...REC, acceptedAt: "2026-10-29", reviewBy: "2027-10-30" };
  assertFalse(passes(AcceptanceRecord, rec));
});

Deno.test("AcceptanceRecord: a leap year still allows 365 days", () => {
  // 2027-10-29 to 2028-10-28 spans Feb 29 2028: 365 days, so it passes.
  const ok = { ...REC, acceptedAt: "2027-10-29", reviewBy: "2028-10-28" };
  assert(passes(AcceptanceRecord, ok));
  const late = { ...REC, acceptedAt: "2027-10-29", reviewBy: "2028-10-29" };
  assertFalse(passes(AcceptanceRecord, late));
});

Deno.test("AcceptanceRecord: a review date decades out fails", () => {
  const rec = { ...REC, acceptedAt: "2026-10-29", reviewBy: "2099-12-31" };
  assertFalse(passes(AcceptanceRecord, rec));
});

Deno.test("TrustRemote and AcceptedRisk: the same 365-day window applies", () => {
  const far = { ...REC, acceptedAt: "2026-10-29", reviewBy: "2099-12-31" };
  assertFalse(
    passes(TrustRemote, { ...far, source: "community-scripts/ProxmoxVE@main" }),
  );
  assertFalse(
    passes(AcceptedRisk, { ...far, finding: "host-group-docker:dmc" }),
  );
});

Deno.test("AcceptanceRecord: a reason shorter than 10 chars fails", () => {
  assertFalse(passes(AcceptanceRecord, { ...REC, reason: "too short" }));
});

Deno.test("AcceptanceRecord: a missing reviewBy fails", () => {
  const { reviewBy: _omit, ...rest } = REC;
  assertFalse(passes(AcceptanceRecord, rest));
});

Deno.test("AcceptanceRecord: reviewBy before acceptedAt fails", () => {
  assertFalse(
    passes(AcceptanceRecord, {
      ...REC,
      acceptedAt: "2026-10-29",
      reviewBy: "2026-10-01",
    }),
  );
});

Deno.test("AcceptanceRecord: a date that is not a real day fails", () => {
  assertFalse(passes(AcceptanceRecord, { ...REC, acceptedAt: "2026-02-30" }));
});

Deno.test("AcceptanceRecord: an unknown extra key fails", () => {
  assertFalse(passes(AcceptanceRecord, { ...REC, extra: 1 }));
});

Deno.test("Unsafe: a present key with a valid record parses", () => {
  assert(passes(Unsafe, { pctExec: REC }));
});

Deno.test("Unsafe: a boolean in place of a record fails", () => {
  assertFalse(passes(Unsafe, { pctExec: true }));
});

Deno.test("Unsafe: an unknown key fails", () => {
  assertFalse(passes(Unsafe, { sudoAll: REC }));
});

Deno.test("TrustRemote: community-scripts/ProxmoxVE@main is accepted", () => {
  assert(
    passes(TrustRemote, { ...REC, source: "community-scripts/ProxmoxVE@main" }),
  );
});

Deno.test("TrustRemote: a URL fails", () => {
  assertFalse(passes(TrustRemote, { ...REC, source: "https://evil" }));
});

Deno.test("TrustRemote: a source without @ref fails", () => {
  assertFalse(passes(TrustRemote, { ...REC, source: "a/b" }));
});

Deno.test("AcceptedRisk: a finding id with a scope is accepted", () => {
  assert(passes(AcceptedRisk, { ...REC, finding: "host-group-docker:dmc" }));
});

Deno.test("AcceptedRisk: a finding id with a space fails", () => {
  assertFalse(passes(AcceptedRisk, { ...REC, finding: "Bad Id" }));
});

Deno.test("AcceptedRisk: a finding id with shell metacharacters fails", () => {
  assertFalse(passes(AcceptedRisk, { ...REC, finding: "x;rm -rf /" }));
});

Deno.test("AcceptedRisk: a finding id with several segments is accepted", () => {
  assert(passes(AcceptedRisk, { ...REC, finding: "host-group:adm:daemon" }));
  assert(
    passes(AcceptedRisk, { ...REC, finding: "from-broad:2001:db8::/32" }),
  );
});

Deno.test("AcceptedRisk: spaces, quotes, ;, $, backticks and newlines fail in any segment", () => {
  for (
    const finding of [
      "a b",
      "x;y",
      "x`y",
      "host-group:adm:da emon",
      'from-broad:"2001"',
      "host-group:adm:$HOME",
      "host-group:adm:x\ny",
    ]
  ) {
    assertFalse(passes(AcceptedRisk, { ...REC, finding }), finding);
  }
});

Deno.test("AcceptedRisk: a finding id is at most 200 characters", () => {
  assert(passes(AcceptedRisk, { ...REC, finding: "a".repeat(200) }));
  assertFalse(passes(AcceptedRisk, { ...REC, finding: "a".repeat(201) }));
});

Deno.test("SourceAddr: valid addresses and CIDRs are accepted", () => {
  const ok = [
    "192.0.2.131",
    "192.0.2.0/24",
    "0.0.0.0/1",
    "2001:db8::1",
    "2001:db8::/32",
    "::1",
  ];
  for (const s of ok) assert(passes(SourceAddr, s), `should accept ${s}`);
});

Deno.test("SourceAddr: malformed addresses and non-addresses are rejected", () => {
  const bad = [
    "0.0.0.0/0",
    "::/0",
    "10.0.0.0/0",
    "192.0.2.256",
    "192.0.2.1/33",
    "010.0.0.1",
    "10.0.0.1,10.0.0.2",
    "*",
    "host.example",
    "10.0.0.1 ",
    '"10.0.0.1"',
    "2001:db8::/129",
    "1::2::3",
  ];
  for (const s of bad) assertFalse(passes(SourceAddr, s), `should reject ${s}`);
});

Deno.test("isSourceAddr: IPv6 group count is limited to eight", () => {
  assert(isSourceAddr("1:2:3:4:5:6:7:8"));
  assertFalse(isSourceAddr("1:2:3:4:5:6:7:8:9"));
  assert(isSourceAddr("1:2:3:4:5:6:7::"));
  assertFalse(isSourceAddr("1:2:3:4:5:6:7:8::"));
});

Deno.test("AccessProfile: a valid profile parses and user defaults to swamp-patch", () => {
  const p = AccessProfile.parse({
    publicKey: KEY,
    from: ["192.0.2.0/24"],
    provisionSshModel: "pve-root",
  });
  assertEquals(p.user, "swamp-patch");
});

Deno.test("AccessProfile: a user with shell metacharacters fails", () => {
  assertFalse(
    passes(AccessProfile, {
      user: "root;id",
      publicKey: KEY,
      from: ["192.0.2.0/24"],
      provisionSshModel: "pve-root",
    }),
  );
});

Deno.test("AccessProfile: a user with uppercase fails", () => {
  assertFalse(
    passes(AccessProfile, {
      user: "Root",
      publicKey: KEY,
      from: ["192.0.2.0/24"],
      provisionSshModel: "pve-root",
    }),
  );
});

Deno.test("AccessProfile: root and toor are refused as the access user", () => {
  for (const user of ["root", "toor"]) {
    assertFalse(
      passes(AccessProfile, {
        user,
        publicKey: KEY,
        from: ["192.0.2.0/24"],
        provisionSshModel: "pve-root",
      }),
      `should reject user ${user}`,
    );
  }
});

Deno.test("AccessProfile: a non-ed25519 public key fails", () => {
  assertFalse(
    passes(AccessProfile, {
      publicKey: "ssh-rsa AAAA",
      from: ["192.0.2.0/24"],
      provisionSshModel: "pve-root",
    }),
  );
});

Deno.test("AccessProfile: a base64 blob that is not an ed25519 key blob fails", () => {
  // Right algorithm name, but the blob is 42 chars and has the wrong prefix.
  const shortBlob = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + "A".repeat(42);
  const wrongPrefix = "ssh-ed25519 AAAAB3NzaC1yc2EAAAADAQABAAABAQC" +
    "A".repeat(43);
  for (const publicKey of [shortBlob, wrongPrefix]) {
    assertFalse(
      passes(AccessProfile, {
        publicKey,
        from: ["192.0.2.0/24"],
        provisionSshModel: "pve-root",
      }),
      `should reject ${publicKey}`,
    );
  }
});

Deno.test("AccessProfile: a second key appended by newline or space fails", () => {
  for (
    const publicKey of [
      `${KEY}\nssh-ed25519 BBBB`,
      `${KEY} ssh-ed25519 BBBB`,
    ]
  ) {
    assertFalse(
      passes(AccessProfile, {
        publicKey,
        from: ["192.0.2.0/24"],
        provisionSshModel: "pve-root",
      }),
      `should reject ${JSON.stringify(publicKey)}`,
    );
  }
});

Deno.test("AccessProfile: a quote in the key comment fails", () => {
  assertFalse(
    passes(AccessProfile, {
      publicKey: `${KEY.split(" ").slice(0, 2).join(" ")} dmc"x`,
      from: ["192.0.2.0/24"],
      provisionSshModel: "pve-root",
    }),
  );
});

Deno.test("AccessProfile: an empty from list fails", () => {
  assertFalse(
    passes(AccessProfile, {
      publicKey: KEY,
      from: [],
      provisionSshModel: "pve-root",
    }),
  );
});

Deno.test("isValidDay: leap days are checked against the calendar", () => {
  assert(isValidDay("2024-02-29"));
  assertFalse(isValidDay("2026-02-29"));
  assertFalse(isValidDay("2026-13-01"));
  assertFalse(isValidDay("2026-1-01"));
});

Deno.test("isOverdue: the review day itself is not overdue", () => {
  const rec = { reviewBy: "2026-10-29" };
  assertFalse(isOverdue(rec, new Date("2026-10-29T23:59:59Z")));
  assert(isOverdue(rec, new Date("2026-10-30T00:00:00Z")));
});

Deno.test("isOverdue: a reviewBy that is not a real day is overdue (fails closed)", () => {
  assert(isOverdue({ reviewBy: "garbage" }, new Date()));
  assert(
    isOverdue({ reviewBy: "2026-02-30" }, new Date("2026-01-01T00:00:00Z")),
  );
});

Deno.test("unsafeRecord: returns the record when present", () => {
  const m = { unsafe: { pctExec: REC } };
  assertEquals(unsafeRecord(m, "pctExec"), REC);
});

Deno.test("unsafeRecord: null when the key is absent or unsafe is undefined", () => {
  assertEquals(unsafeRecord({ unsafe: {} }, "rootSsh"), null);
  assertEquals(unsafeRecord({}, "pctExec"), null);
});
