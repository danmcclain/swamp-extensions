/**
 * Unit tests for the pending-update parser: each package manager's list as the collector
 * ships it, the security marks, and the refusals (bad base64, a line that does not parse,
 * text that is not a package name or version). Pure; no host, no swamp.
 */
import { assert, assertEquals } from "jsr:@std/assert@1";
import { parsePending, PENDING_LIMIT } from "./pending_updates.ts";

const b64 = (s: string) =>
  btoa(String.fromCharCode(...new TextEncoder().encode(s)));

function ok(r: ReturnType<typeof parsePending>) {
  assert(r.ok, r.ok ? "" : r.error);
  return r;
}

function err(r: ReturnType<typeof parsePending>): string {
  assert(!r.ok, "expected a refusal");
  return r.error;
}

// dnf check-update -q, as Rocky 9 prints it, with the obsoletes section after the list.
const DNF_LIST = [
  "",
  "docker-ce.x86_64                 3:29.9.3-1.el9                  docker-ce-stable",
  "grub2-tools.x86_64               1:2.06-127.el9_8.rocky.0.1      baseos",
  "kernel-core.x86_64               5.14.0-687.66.1.el9_8           baseos",
  "tailscale.x86_64                 1.104.6-1                       tailscale-stable",
  "tzdata.noarch                    2026f-1.el9_8                   baseos",
  "Obsoleting Packages",
  "grub2-tools.x86_64               1:2.06-127.el9_8.rocky.0.1      baseos",
  "    grub2-tools.x86_64           1:2.06-126.el9_8.rocky.0.3      @baseos",
  "",
].join("\n");
const DNF_SECURITY = [
  "kernel-core.x86_64               5.14.0-687.66.1.el9_8           baseos",
  "tzdata.noarch                    2026f-1.el9_8                   baseos",
].join("\n");

Deno.test("parsePending (dnf): name, arch, version and repo; the obsoletes section is not read", () => {
  const r = ok(parsePending("dnf", b64(DNF_LIST), b64(DNF_SECURITY)));
  assertEquals(r.truncated, false);
  assertEquals(r.items.map((i) => i.name), [
    "docker-ce",
    "grub2-tools",
    "kernel-core",
    "tailscale",
    "tzdata",
  ]);
  assertEquals(r.items[0], {
    name: "docker-ce",
    arch: "x86_64",
    from: null,
    to: "3:29.9.3-1.el9",
    source: "docker-ce-stable",
    security: false,
  });
  assertEquals(
    r.items.filter((i) => i.security).map((i) => i.name),
    ["kernel-core", "tzdata"],
  );
});

Deno.test("parsePending (dnf): without the security list, security is unknown (null), never false", () => {
  const r = ok(parsePending("dnf", b64(DNF_LIST), null));
  assert(r.items.every((i) => i.security === null));
});

Deno.test("parsePending (dnf): security matches name and arch, not the name alone", () => {
  const list = "foo.x86_64 1-1 baseos\nfoo.i686 1-1 baseos\n";
  const r = ok(parsePending("dnf", b64(list), b64("foo.i686 1-1 baseos\n")));
  assertEquals(r.items.map((i) => [i.arch, i.security]), [
    ["x86_64", false],
    ["i686", true],
  ]);
});

Deno.test("parsePending (dnf): no updates is an empty list", () => {
  assertEquals(ok(parsePending("dnf", b64("\n"), b64("\n"))).items, []);
});

Deno.test("parsePending (dnf): a counted line with a missing column refuses the whole list", () => {
  const e = err(parsePending("dnf", b64("foo.x86_64 1-1\n"), null));
  assert(e.includes("a dnf line does not parse"), e);
});

// apt-get -s dist-upgrade's Inst lines, including a new dependency and a trailing [].
const APT_INST = [
  "Inst libssl3 [3.0.11-1~deb12u2] (3.0.13-1~deb12u1 Debian:12.5/stable, Debian-Security:12/stable-security [amd64])",
  "Inst tzdata [2024a-0+deb12u1] (2025b-0+deb12u1 Debian:12.11/stable-updates [all])",
  "Inst linux-image-6.1.0-37-amd64 (6.1.140-1 Debian:12.11/stable [amd64]) []",
].join("\n");

Deno.test("parsePending (apt): installed and new version, origin, arch and the security channel", () => {
  const r = ok(parsePending("apt", b64(APT_INST), null));
  assertEquals(r.items, [
    {
      name: "libssl3",
      arch: "amd64",
      from: "3.0.11-1~deb12u2",
      to: "3.0.13-1~deb12u1",
      source: "Debian:12.5/stable, Debian-Security:12/stable-security",
      security: true,
    },
    {
      name: "tzdata",
      arch: "all",
      from: "2024a-0+deb12u1",
      to: "2025b-0+deb12u1",
      source: "Debian:12.11/stable-updates",
      security: false,
    },
    {
      name: "linux-image-6.1.0-37-amd64",
      arch: "amd64",
      from: null,
      to: "6.1.140-1",
      source: "Debian:12.11/stable",
      security: false,
    },
  ]);
});

Deno.test("parsePending (apk): name and installed version split at the -r release; no security channel", () => {
  const list = [
    "Installed:                                Available:",
    "musl-1.2.5-r0                           < 1.2.5-r1",
    "py3-pip-24.0-r2                         < 24.0-r3",
  ].join("\n");
  const r = ok(parsePending("apk", b64(list), null));
  assertEquals(r.items.map((i) => [i.name, i.from, i.to, i.security]), [
    ["musl", "1.2.5-r0", "1.2.5-r1", null],
    ["py3-pip", "24.0-r2", "24.0-r3", null],
  ]);
});

Deno.test("parsePending (pacman): [ignored] is skipped, as the count skips it; arch-audit marks security", () => {
  const list =
    "openssl 3.0.1-1 -> 3.0.2-1\ncurl 8.0-1 -> 8.1-1 [ignored]\nlinux 6.9-1 -> 6.10-1\n";
  const r = ok(parsePending("pacman", b64(list), b64("openssl\n")));
  assertEquals(r.items.map((i) => [i.name, i.from, i.to, i.security]), [
    ["openssl", "3.0.1-1", "3.0.2-1", true],
    ["linux", "6.9-1", "6.10-1", false],
  ]);
  const noAudit = ok(parsePending("pacman", b64(list), null));
  assert(noAudit.items.every((i) => i.security === null));
});

Deno.test("parsePending: markup or control characters in a name or version refuse the list", () => {
  // A dnf line the count does not count (its name is not a package name) is not read:
  // nothing of it is stored, and the list still matches the count.
  assertEquals(
    ok(parsePending("dnf", b64("foo|bar.x86_64 1-1 baseos\n"), null)).items,
    [],
  );
  for (
    const list of [
      "foo.x86_64 1-1<b> baseos\n",
      "foo.x86_64 1-1 base`os\n",
    ]
  ) {
    const e = err(parsePending("dnf", b64(list), null));
    assert(e.length > 0);
  }
  err(
    parsePending(
      "apt",
      b64("Inst foo [1] (2 Debian:12/stable [amd64]) <x>\n"),
      null,
    ),
  );
  err(parsePending("pacman", b64("open\u0007ssl 1 -> 2\n"), null));
  err(parsePending("pacman", b64("openssl 1 -> 2\n"), b64("open|ssl\n")));
});

Deno.test("parsePending: text that is not base64 UTF-8, or an unknown package manager, is refused", () => {
  err(parsePending("dnf", "!!!", null));
  err(parsePending("dnf", btoa("\xff\xfe"), null));
  err(parsePending("dnf", b64("foo.x86_64 1 baseos\n"), "!!!"));
  err(parsePending("unknown", b64(""), null));
});

Deno.test("parsePending: more than PENDING_LIMIT entries keeps the first ones and says it was cut", () => {
  const n = PENDING_LIMIT + 5;
  const list = Array.from({ length: n }, (_, i) => `p${i}.noarch 1-1 baseos`)
    .join("\n");
  const r = ok(parsePending("dnf", b64(list), null));
  assertEquals(r.items.length, PENDING_LIMIT);
  assertEquals(r.truncated, true);
  assertEquals(r.items[0].name, "p0");
});
