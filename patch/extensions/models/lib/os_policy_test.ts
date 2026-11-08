/**
 * Unit tests for the OS update policy: the effective policy (inheritance, overrides and the
 * osAutoScope consistency rule), the capability matrix that the sudoers generator and the
 * runtime guards read, and the refusal messages. Pure; no host, no swamp.
 */
import {
  assertEquals,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import { capabilitiesFor, effectivePolicy, osRefusal } from "./os_policy.ts";
import type { PolicyGlobals, PolicyMachine } from "./os_policy.ts";

const REC = {
  reason: "Legacy CT without sshd, reviewed by ops",
  acceptedBy: "dmc",
  acceptedAt: "2026-10-29",
  reviewBy: "2027-04-29",
};
const PCT_OK = { pctExec: REC };
const DEFAULTS: PolicyGlobals = {
  osUpdatePolicy: "managed",
  osAutoScope: "security",
};

Deno.test("effectivePolicy: no policy anywhere is managed, with no autoScope", () => {
  assertEquals(effectivePolicy({ host: "a" }, {}), {
    policy: "managed",
    autoScope: null,
  });
  assertEquals(effectivePolicy({ host: "a" }, DEFAULTS), {
    policy: "managed",
    autoScope: null,
  });
});

Deno.test("effectivePolicy: a machine inherits the fleet policy, and overrides it", () => {
  const g: PolicyGlobals = {
    osUpdatePolicy: "scan-only",
    osAutoScope: "security",
  };
  assertEquals(effectivePolicy({ host: "a" }, g).policy, "scan-only");
  assertEquals(
    effectivePolicy({ host: "a", osUpdatePolicy: "managed" }, g).policy,
    "managed",
  );
  assertEquals(
    effectivePolicy({ host: "a", osUpdatePolicy: "auto" }, g),
    { policy: "auto", autoScope: "security" },
  );
});

Deno.test("effectivePolicy: autoScope comes from the machine, else the fleet, and only for auto", () => {
  assertEquals(
    effectivePolicy({ host: "a", osUpdatePolicy: "auto" }, DEFAULTS),
    { policy: "auto", autoScope: "security" },
  );
  assertEquals(
    effectivePolicy(
      { host: "a", osUpdatePolicy: "auto", osAutoScope: "all" },
      DEFAULTS,
    ),
    { policy: "auto", autoScope: "all" },
  );
  assertEquals(
    effectivePolicy({ host: "a" }, {
      osUpdatePolicy: "auto",
      osAutoScope: "all",
    }),
    { policy: "auto", autoScope: "all" },
  );
});

Deno.test("effectivePolicy: osAutoScope on a machine whose policy is not auto is a configuration error", () => {
  // Set on the machine itself.
  assertThrows(
    () =>
      effectivePolicy(
        { host: "web1", osUpdatePolicy: "managed", osAutoScope: "all" },
        DEFAULTS,
      ),
    Error,
    "web1: osAutoScope is set, but the effective osUpdatePolicy is managed",
  );
  assertThrows(
    () =>
      effectivePolicy(
        { host: "web1", osUpdatePolicy: "scan-only", osAutoScope: "security" },
        DEFAULTS,
      ),
    Error,
    "osAutoScope applies only when the policy is auto",
  );
  // Set on the machine, with the policy inherited from a non-auto fleet default.
  assertThrows(
    () =>
      effectivePolicy(
        { host: "web1", osAutoScope: "all" },
        { osUpdatePolicy: "scan-only", osAutoScope: "security" },
      ),
    Error,
    "(inherited from the fleet)",
  );
});

Deno.test("effectivePolicy: an unknown policy or scope is refused, never defaulted", () => {
  assertThrows(
    () =>
      effectivePolicy(
        { host: "a", osUpdatePolicy: "yolo" as never },
        DEFAULTS,
      ),
    Error,
    'unknown osUpdatePolicy "yolo"',
  );
  assertThrows(
    () =>
      effectivePolicy(
        { host: "a", osUpdatePolicy: "auto", osAutoScope: "some" as never },
        DEFAULTS,
      ),
    Error,
    'unknown osAutoScope "some"',
  );
  assertThrows(
    () => effectivePolicy({ host: "a" }, { osUpdatePolicy: "nope" as never }),
    Error,
    'unknown osUpdatePolicy "nope"',
  );
});

const POLICIES: PolicyMachine[] = [
  { osUpdatePolicy: "managed" },
  { osUpdatePolicy: "auto", osAutoScope: "security" },
  { osUpdatePolicy: "auto", osAutoScope: "all" },
  { osUpdatePolicy: "scan-only" },
];

const PCT_CASES: Array<{ label: string; extra: PolicyMachine }> = [
  { label: "ssh", extra: {} },
  { label: "pct without the record", extra: { reach: "pct" } },
  { label: "pct with the record", extra: { reach: "pct", unsafe: PCT_OK } },
  { label: "ssh with the record", extra: { unsafe: PCT_OK } },
];

Deno.test("capabilitiesFor: the matrix over policy, os, docker and pct", () => {
  for (const policy of POLICIES) {
    for (const os of [true, false]) {
      for (const docker of [false, true]) {
        for (const pct of PCT_CASES) {
          const m: PolicyMachine = {
            host: "web1",
            os,
            ...policy,
            ...(docker
              ? { docker: { composePath: "/x", service: "app" } }
              : {}),
            ...pct.extra,
          };
          const p = policy.osUpdatePolicy!;
          const on = os;
          const want = {
            scan: true,
            osUpgrade: on && p === "managed",
            reboot: p !== "scan-only",
            docker,
            autoUpdates: on && p === "auto" ? policy.osAutoScope! : null,
            pctExec: pct.label.startsWith("pct with the record"),
          };
          assertEquals(
            capabilitiesFor(m, DEFAULTS),
            want,
            `${p} os=${os} docker=${docker} ${pct.label}`,
          );
        }
      }
    }
  }
});

Deno.test("capabilitiesFor: managed upgrades and reboots; auto only reboots; scan-only does neither", () => {
  const managed = capabilitiesFor({ host: "a" }, DEFAULTS);
  assertEquals([managed.osUpgrade, managed.reboot, managed.autoUpdates], [
    true,
    true,
    null,
  ]);
  const auto = capabilitiesFor({ host: "a", osUpdatePolicy: "auto" }, DEFAULTS);
  assertEquals([auto.osUpgrade, auto.reboot, auto.autoUpdates], [
    false,
    true,
    "security",
  ]);
  const scan = capabilitiesFor(
    { host: "a", osUpdatePolicy: "scan-only" },
    DEFAULTS,
  );
  assertEquals([scan.osUpgrade, scan.reboot, scan.autoUpdates], [
    false,
    false,
    null,
  ]);
});

Deno.test("capabilitiesFor: a pct machine with no pctExec record never gets pctExec", () => {
  const r = capabilitiesFor({ host: "a", reach: "pct" }, DEFAULTS);
  assertEquals(r.pctExec, false);
});

Deno.test("capabilitiesFor: an inconsistent osAutoScope throws instead of giving capabilities", () => {
  assertThrows(() =>
    capabilitiesFor({ host: "a", osAutoScope: "all" }, {
      osUpdatePolicy: "managed",
    })
  );
});

Deno.test("osRefusal: safeOsUpdate is refused on auto and scan-only, with the host and the policy named", () => {
  const onAuto = osRefusal(
    "safeOsUpdate",
    { host: "web1", osUpdatePolicy: "auto" },
    DEFAULTS,
  );
  assertEquals(
    onAuto,
    "safeOsUpdate refused for web1: osUpdatePolicy is auto (the host installs its own OS updates); use reboot for pending reboots",
  );
  const onScan = osRefusal(
    "safeOsUpdate",
    { host: "web1" },
    { osUpdatePolicy: "scan-only" },
  );
  assertStringIncludes(
    onScan!,
    "safeOsUpdate refused for web1: osUpdatePolicy is scan-only",
  );
  assertEquals(
    osRefusal("safeOsUpdate", { host: "web1" }, DEFAULTS),
    null,
  );
});

Deno.test("osRefusal: reboot is refused on scan-only, and allowed on managed and auto", () => {
  const scan = osRefusal("reboot", {
    host: "web1",
    osUpdatePolicy: "scan-only",
  }, DEFAULTS);
  assertStringIncludes(scan!, "reboot refused for web1");
  assertStringIncludes(scan!, "even with force");
  assertEquals(
    osRefusal("reboot", { host: "web1", osUpdatePolicy: "auto" }, DEFAULTS),
    null,
  );
  assertEquals(osRefusal("reboot", { host: "web1" }, DEFAULTS), null);
});

Deno.test("osRefusal: os false refuses an OS upgrade, but a reboot follows the policy", () => {
  assertStringIncludes(
    osRefusal("safeOsUpdate", { host: "ct9", os: false }, DEFAULTS)!,
    "safeOsUpdate refused for ct9: os is false",
  );
  assertEquals(osRefusal("reboot", { host: "ct9", os: false }, DEFAULTS), null);
  assertStringIncludes(
    osRefusal("reboot", {
      host: "ct9",
      os: false,
      osUpdatePolicy: "scan-only",
    }, DEFAULTS)!,
    "reboot refused for ct9: osUpdatePolicy is scan-only",
  );
});
