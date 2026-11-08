/**
 * Unit tests for the access audit: the two probe scripts (bash -n, the injection rule, and
 * the user probe run with bash in a temp HOME) and the pure evaluator (one fixture per
 * catalog entry, accepted risks, and invalid probe output). Nothing touches a host.
 */
import {
  assert,
  assertEquals,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import {
  aptAutoConf,
  aptPeriodicConf,
  authorizedKeysLine,
  identityBlock,
  MANAGED_HEADER,
  PATHS,
} from "./access_artifacts.ts";
import {
  type AuditInput,
  type AuditResult,
  evaluateAudit,
  rootProbeScript,
  userProbeScript,
} from "./access_audit.ts";
import {
  DOCKER_HELPER_PATH,
  dockerHelperScript,
  dockerProjectsFile,
} from "./docker_helper.ts";
import {
  pathNames,
  type PrivCommand,
  privCommand,
  sudoersLine,
} from "./access_sudoers.ts";

const KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBjngojWT4QUfy2bl78lWkaepNtOZYDlAzZbel8QNoWN swamp-serve";
const BLOB = KEY.split(" ")[1];
const OTHER_KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOTHERKEYOTHERKEYOTHERKEYOTHERKEYOTHERKEY other";
const FROM = ["192.0.2.131"];
// A user name that appears nowhere else in a generated script, so its occurrences can be counted.
const USER = "patchq-test";
const NOW = new Date("2026-10-29T12:00:00Z");
const LINE = authorizedKeysLine(KEY, FROM);
const TOKEN = "0123456789abcdef0123456789abcdef";
const BAD_USERS = ["root", "toor", "Root", "a b", "x'y", "$(id)", "a;rm -rf /"];
const REC = {
  reason: "Pinned by ops; reviewed quarterly",
  acceptedBy: "dmc",
  acceptedAt: "2026-10-01",
  reviewBy: "2026-10-29",
};

const ONES = "1".repeat(64);
const ZEROS = "0".repeat(64);
const APT_SHA = await sha256Hex(aptPeriodicConf());

const NO_WRITES = {
  authorizedKeys: false,
  sshDir: false,
  marker: false,
  stateDir: false,
  libexec: false,
  dockerProducer: false,
  sudoersDir: false,
  unitService: false,
  unitTimer: false,
  aptConf: false,
  apkPeriodic: false,
  aptAuto: false,
  dnfAutoConf: false,
  dnfAutoDropIn: false,
  dockerHelper: false,
  dockerProjects: false,
};
const ROOT_FILE = { owner: "root", group: "root", mode: "644" };
const ROOT_DIR = { owner: "root", group: "root", mode: "755" };
const NO_HOSTS = {
  docker: [],
  wheel: [],
  sudo: [],
  admin: [],
  adm: [],
  lxd: [],
  disk: [],
};

function occurrences(text: string, value: string): number {
  return text.split(value).length - 1;
}

/** Each value appears once in the top-of-script assignments and nowhere else in the script. */
function assertOnlyInTop(script: string, values: string[]): void {
  const split = script.indexOf(identityBlock());
  assert(split > 0, "the script has no top-of-script assignments");
  const top = script.slice(0, split);
  for (const value of values) {
    assertEquals(
      occurrences(top, value),
      1,
      `${value} must be assigned once at the top`,
    );
    assertEquals(
      occurrences(script, value),
      1,
      `${value} appears outside the top-of-script assignments`,
    );
  }
}

/** bash -n on one script. Throws with bash's message when the syntax is wrong. */
async function assertBashSyntax(script: string): Promise<void> {
  const dir = await Deno.makeTempDir();
  try {
    const file = `${dir}/script.sh`;
    await Deno.writeTextFile(file, script);
    const out = await new Deno.Command("bash", { args: ["-n", file] }).output();
    assertEquals(out.code, 0, new TextDecoder().decode(out.stderr));
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** The tools the user probe needs, as links in a fresh dir. Extra scripts go in too. */
async function toolDir(extra: Record<string, string> = {}): Promise<string> {
  const dir = await Deno.makeTempDir();
  for (const name of ["bash", "id", "sed", "tr"]) {
    let source: string | null = null;
    for (const base of ["/usr/bin", "/bin"]) {
      try {
        await Deno.stat(`${base}/${name}`);
        source = `${base}/${name}`;
        break;
      } catch {
        // Not in this directory; try the next.
      }
    }
    if (source === null) throw new Error(`${name} is not in /usr/bin or /bin`);
    await Deno.symlink(source, `${dir}/${name}`);
  }
  for (const [name, body] of Object.entries(extra)) {
    await Deno.writeTextFile(`${dir}/${name}`, body);
    await Deno.chmod(`${dir}/${name}`, 0o755);
  }
  return dir;
}

/** Run the user probe with bash, a temp HOME, and only `path` on PATH. */
async function runUserProbe(
  path: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
  const dir = await Deno.makeTempDir();
  const home = await Deno.makeTempDir();
  try {
    const file = `${dir}/user-probe.sh`;
    await Deno.writeTextFile(file, userProbeScript());
    const out = await new Deno.Command("bash", {
      args: [file],
      env: { HOME: home, PATH: path },
    }).output();
    return {
      code: out.code,
      stdout: new TextDecoder().decode(out.stdout),
      stderr: new TextDecoder().decode(out.stderr),
    };
  } finally {
    await Deno.remove(dir, { recursive: true });
    await Deno.remove(home, { recursive: true });
  }
}

// ---------------------------------------------------------------------------
// Probe scripts
// ---------------------------------------------------------------------------

Deno.test("userProbeScript and rootProbeScript pass bash -n", async () => {
  await assertBashSyntax(userProbeScript());
  await assertBashSyntax(rootProbeScript(USER, KEY));
});

Deno.test("rootProbeScript refuses a bad user", () => {
  for (const user of BAD_USERS) {
    assertThrows(() => rootProbeScript(user, KEY));
  }
});

Deno.test("rootProbeScript refuses anything but one ed25519 key", () => {
  assertThrows(() => rootProbeScript(USER, `${KEY}\n${KEY}`));
  assertThrows(() => rootProbeScript(USER, `${KEY} ${KEY}`));
  assertThrows(() => rootProbeScript(USER, `${KEY}'; id; '`));
  assertThrows(() =>
    rootProbeScript(
      USER,
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC swamp-serve",
    )
  );
});

Deno.test("INJECTION: rootProbeScript takes the user and key only from the top assignments", () => {
  assertOnlyInTop(rootProbeScript(USER, KEY), [USER, KEY]);
});

Deno.test("rootProbeScript quotes the user and the key in the assignments", () => {
  const script = rootProbeScript(USER, KEY);
  assertStringIncludes(script, `PATCH_USER='${USER}'\n`);
  assertStringIncludes(script, `PUBLIC_KEY='${KEY}'\n`);
});

Deno.test("userProbeScript: runs with bash in a temp HOME and prints one JSON line when sudo and docker are absent", async () => {
  const bin = await toolDir();
  try {
    const out = await runUserProbe(bin);
    assertEquals(out.code, 0, out.stderr);
    const lines = out.stdout.split("\n").filter((l) => l.length > 0);
    assertEquals(lines.length, 1);
    const probe = JSON.parse(lines[0]);
    assertEquals(probe._kind, "patch-access-user-probe");
    assertEquals(probe.sudoList, null);
    assertEquals(probe.sudoTrueRc, null);
    assertEquals(probe.dockerRc, null);
    assert(Array.isArray(probe.groups));
    for (const v of Object.values(probe.canWrite)) {
      assertEquals(typeof v, "boolean");
    }
  } finally {
    await Deno.remove(bin, { recursive: true });
  }
});

Deno.test("userProbeScript: reports the sudo and docker answers when both are present", async () => {
  const bin = await toolDir({
    sudo:
      "#!/bin/sh\necho 'User x may run the following commands on host'\nexit 0\n",
    docker: "#!/bin/sh\nexit 0\n",
  });
  try {
    const out = await runUserProbe(bin);
    assertEquals(out.code, 0, out.stderr);
    const probe = JSON.parse(out.stdout.trim());
    assertEquals(probe.sudoList.rc, 0);
    assertStringIncludes(probe.sudoList.out, "may run");
    assertEquals(probe.sudoTrueRc, 0);
    assertEquals(probe.dockerRc, 0);
  } finally {
    await Deno.remove(bin, { recursive: true });
  }
});

Deno.test("userProbeScript: the user is the login that runs it", async () => {
  const id = await new Deno.Command("id", { args: ["-un"] }).output();
  const bin = await toolDir();
  try {
    const out = await runUserProbe(bin);
    const probe = JSON.parse(out.stdout.trim());
    assertEquals(probe.user, new TextDecoder().decode(id.stdout).trim());
  } finally {
    await Deno.remove(bin, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// Evaluator fixtures
// ---------------------------------------------------------------------------

function userFacts(
  over: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    _kind: "patch-access-user-probe",
    user: USER,
    uid: 1001,
    groups: [USER],
    sudoList: null,
    sudoTrueRc: null,
    dockerRc: null,
    canWrite: NO_WRITES,
    ...over,
  };
}

function present(
  path: string,
  sha256: string | null,
  over: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    path,
    exists: true,
    owner: "root",
    group: "root",
    mode: "644",
    sha256,
    hasManagedHeader: true,
    ...over,
  };
}

function absent(path: string): Record<string, unknown> {
  return {
    path,
    exists: false,
    owner: null,
    group: null,
    mode: null,
    sha256: null,
    hasManagedHeader: false,
  };
}

/** Every managed path. The marker is present and the rest absent, unless `set` replaces one. */
function managedFiles(...set: Record<string, unknown>[]): unknown[] {
  const base = [
    present(PATHS.marker, ONES, { hasManagedHeader: false }),
    absent(PATHS.dockerProducer),
    absent(PATHS.unitService),
    absent(PATHS.unitTimer),
    absent(PATHS.aptConf),
    absent(PATHS.apkPeriodic),
    absent(PATHS.sudoers),
    absent(PATHS.dockerHelper),
    absent(PATHS.dockerProjects),
  ];
  return base.map((b) => set.find((s) => s.path === b.path) ?? b);
}

function rootFacts(
  over: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    _kind: "patch-access-root-probe",
    account: {
      exists: true,
      markerOk: true,
      shadowLocked: true,
      shell: "/bin/bash",
      gecos: `swamp-patch token=${TOKEN}`,
    },
    groupsOfUser: [USER],
    authorizedKeys: {
      lines: [LINE],
      total: 1,
      file: ROOT_FILE,
      dir: ROOT_DIR,
      home: ROOT_DIR,
    },
    rootHasKey: false,
    managedFiles: managedFiles(),
    dirs: {
      stateDir: ROOT_DIR,
      libexec: null,
      sudoersDir: ROOT_DIR,
      systemdDir: ROOT_DIR,
      projectsDir: null,
    },
    sudoRules: [],
    cache: {
      family: "apt",
      refreshOn: true,
      ageHours: 1,
      autoInstall: false,
      autoScope: null,
    },
    hostGroups: NO_HOSTS,
    dockerSocket: null,
    sudoersFile: { exists: false, lines: [], total: 0 },
    sudoFamilies: ["apt", "systemd"],
    compose: [],
    ...over,
  };
}

/** A clean machine: no findings. Each test changes one thing. */
function input(over: Partial<AuditInput> = {}): AuditInput {
  return {
    host: "web1",
    user: USER,
    publicKey: KEY,
    from: FROM,
    docker: false,
    userProbe: userFacts(),
    userProbeError: null,
    rootProbe: rootFacts(),
    rootProbeError: null,
    machine: {},
    now: NOW,
    ...over,
  };
}

/** Each finding as "id severity", sorted, so the order of the catalog does not matter. */
function signatures(r: AuditResult): string[] {
  return r.findings.map((f) => `${f.id} ${f.severity}`).sort();
}

function expectFindings(r: AuditResult, ...expected: string[]): void {
  assertEquals(signatures(r), [...expected].sort());
}

// ---------------------------------------------------------------------------
// Sudoers fixtures: the lines the provision script writes, built by the real code
// ---------------------------------------------------------------------------

/** The absolute path each binary name has on the fixture host. */
const HOST_PATHS: Record<string, string> = {
  env: "/usr/bin/env",
  "apt-get": "/usr/bin/apt-get",
  dnf: "/usr/bin/dnf",
  apk: "/sbin/apk",
  pacman: "/usr/bin/pacman",
  "systemd-run": "/usr/bin/systemd-run",
};
const DEFAULTS_LINES = [
  `Defaults:${USER} env_reset`,
  `Defaults:${USER} !setenv`,
];
const APT_IDS = ["apt-update", "apt-upgrade", "apt-full-upgrade"];
const ALL_IDS = [...APT_IDS, "reboot"];
const OS_BOTH = { osUpgrade: true, reboot: true };

/** The sudoers line that grants the table entry `id` to USER, each binary at its HOST_PATHS path. */
function grantLine(id: string): string {
  const cmd = privCommand(id);
  const paths = Object.fromEntries(
    pathNames(cmd).map((n) => [n, HOST_PATHS[n]]),
  );
  return sudoersLine(USER, cmd, paths);
}

/** The two Defaults lines, then one grant line for each entry of `ids`. */
function grantFile(ids: string[]): string[] {
  return [...DEFAULTS_LINES, ...ids.map((id) => grantLine(id))];
}

/**
 * An input whose machine has the OS sudo caps by default, and whose root probe has this
 * sudoers file. The families default to apt and systemd, as on a Debian-style host.
 */
function grantsInput(
  lines: string[],
  over: {
    families?: string[];
    machine?: AuditInput["machine"];
    userProbe?: unknown;
    total?: number;
  } = {},
): AuditInput {
  return input({
    machine: over.machine ?? { sudo: OS_BOTH },
    userProbe: over.userProbe ?? userFacts(),
    rootProbe: rootFacts({
      sudoersFile: { exists: true, lines, total: over.total ?? lines.length },
      sudoFamilies: over.families ?? ["apt", "systemd"],
    }),
  });
}

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------

Deno.test("evaluateAudit: a clean fixture gives zero findings", async () => {
  const r = await evaluateAudit(input());
  assertEquals(r.findings, []);
  assertEquals(r.acceptedRisks, []);
  assertEquals(r.summary, {
    critical: 0,
    high: 0,
    warning: 0,
    info: 0,
    accepted: 0,
    overdue: 0,
  });
});

Deno.test("evaluateAudit: a failed user probe gives probe-failed:user with its error", async () => {
  const r = await evaluateAudit(
    input({ userProbe: null, userProbeError: "ssh timed out" }),
  );
  expectFindings(r, "probe-failed:user high");
  assertStringIncludes(r.findings[0].message, "ssh timed out");
});

Deno.test("evaluateAudit: a root probe that returned nothing gives probe-failed:root", async () => {
  const r = await evaluateAudit(input({ rootProbe: null }));
  expectFindings(r, "probe-failed:root high");
  assertStringIncludes(r.findings[0].message, "returned no output");
});

Deno.test("evaluateAudit: invalid user probe output gives probe-invalid:user and nothing derived from it", async () => {
  const r = await evaluateAudit(
    input({ userProbe: userFacts({ dockerRc: 0, extra: 1 }) }),
  );
  expectFindings(r, "probe-invalid:user high");
});

Deno.test("evaluateAudit: invalid root probe output gives probe-invalid:root", async () => {
  const r = await evaluateAudit(
    input({ rootProbe: { _kind: "patch-access-root-probe" } }),
  );
  expectFindings(r, "probe-invalid:root high");
});

Deno.test("evaluateAudit: invalid probes give probe-invalid only, even when they would show findings", async () => {
  const r = await evaluateAudit(input({
    userProbe: "not an object",
    rootProbe: rootFacts({ rootHasKey: true, rootHasKeyExtra: true }),
  }));
  expectFindings(r, "probe-invalid:user high", "probe-invalid:root high");
});

Deno.test("evaluateAudit: a failed root probe still reports user findings", async () => {
  const r = await evaluateAudit(input({
    rootProbe: null,
    userProbe: userFacts({ dockerRc: 0 }),
  }));
  expectFindings(
    r,
    "probe-failed:root high",
    "docker-socket-access critical",
  );
});

Deno.test("evaluateAudit: a missing account gives account-missing", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      account: {
        exists: false,
        markerOk: false,
        shadowLocked: null,
        shell: null,
        gecos: null,
      },
      groupsOfUser: [],
    }),
  }));
  expectFindings(r, "account-missing high");
});

Deno.test("evaluateAudit: an account without our marker gives account-not-managed", async () => {
  const acct = {
    exists: true,
    markerOk: false,
    shadowLocked: true,
    shell: "/bin/bash",
    gecos: "someone",
  };
  const r = await evaluateAudit(
    input({ rootProbe: rootFacts({ account: acct }) }),
  );
  expectFindings(r, "account-not-managed high");
});

Deno.test("evaluateAudit: an unlocked password gives password-not-locked", async () => {
  const acct = {
    exists: true,
    markerOk: true,
    shadowLocked: false,
    shell: "/bin/bash",
    gecos: `swamp-patch token=${TOKEN}`,
  };
  const r = await evaluateAudit(
    input({ rootProbe: rootFacts({ account: acct }) }),
  );
  expectFindings(r, "password-not-locked high");
});

Deno.test("evaluateAudit: no line for the access key gives key-missing", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      authorizedKeys: {
        lines: [],
        total: 0,
        file: null,
        dir: ROOT_DIR,
        home: ROOT_DIR,
      },
    }),
  }));
  expectFindings(r, "key-missing high");
});

Deno.test("evaluateAudit: another line gives authorized-keys-extra", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      authorizedKeys: {
        lines: [LINE, OTHER_KEY],
        total: 2,
        file: ROOT_FILE,
        dir: ROOT_DIR,
        home: ROOT_DIR,
      },
    }),
  }));
  expectFindings(r, "authorized-keys-extra high");
});

Deno.test("evaluateAudit: lines past the 20-line cap still count as extra", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      authorizedKeys: {
        lines: [LINE],
        total: 21,
        file: ROOT_FILE,
        dir: ROOT_DIR,
        home: ROOT_DIR,
      },
    }),
  }));
  expectFindings(r, "authorized-keys-extra high");
});

Deno.test("evaluateAudit: a key line without the full restriction gives authorized-keys-unrestricted", async () => {
  // The bad line is also not the expected line, so key-missing and extra follow from the catalog.
  for (
    const line of [
      `from="${FROM[0]}",no-pty ${KEY}`,
      `no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc ${KEY}`,
    ]
  ) {
    const r = await evaluateAudit(input({
      rootProbe: rootFacts({
        authorizedKeys: {
          lines: [line],
          total: 1,
          file: ROOT_FILE,
          dir: ROOT_DIR,
          home: ROOT_DIR,
        },
      }),
    }));
    expectFindings(
      r,
      "authorized-keys-extra high",
      "authorized-keys-unrestricted high",
      "key-missing high",
    );
  }
});

Deno.test("evaluateAudit: the user can write authorized_keys gives authorized-keys-writable", async () => {
  const r = await evaluateAudit(input({
    userProbe: userFacts({ canWrite: { ...NO_WRITES, authorizedKeys: true } }),
  }));
  expectFindings(r, "authorized-keys-writable critical");
});

Deno.test("evaluateAudit: a key file or dir not owned by root, or group- or other-writable, gives authorized-keys-writable", async () => {
  const variants = [
    { file: { owner: "dmc", group: "root", mode: "644" } },
    { dir: { owner: "root", group: "staff", mode: "775" } },
    { home: { owner: "root", group: "root", mode: "757" } },
  ];
  for (const v of variants) {
    const ak = {
      lines: [LINE],
      total: 1,
      file: ROOT_FILE,
      dir: ROOT_DIR,
      home: ROOT_DIR,
      ...v,
    };
    const r = await evaluateAudit(
      input({ rootProbe: rootFacts({ authorizedKeys: ak }) }),
    );
    expectFindings(r, "authorized-keys-writable critical");
  }
});

Deno.test("evaluateAudit: root accepting the key gives root-accepts-key", async () => {
  const r = await evaluateAudit(
    input({ rootProbe: rootFacts({ rootHasKey: true }) }),
  );
  expectFindings(r, "root-accepts-key critical");
});

Deno.test("evaluateAudit: a root-equivalent group gives group-root-equivalent critical, and adm high", async () => {
  const docker = await evaluateAudit(input({
    rootProbe: rootFacts({ groupsOfUser: [USER, "docker"] }),
  }));
  expectFindings(docker, "group-root-equivalent:docker critical");
  const adm = await evaluateAudit(input({
    rootProbe: rootFacts({ groupsOfUser: [USER, "adm"] }),
  }));
  expectFindings(adm, "group-root-equivalent:adm high");
});

Deno.test("evaluateAudit: a user probe that runs as uid 0 gives login-is-root critical, and not probe-wrong-user", async () => {
  const r = await evaluateAudit(
    input({ userProbe: userFacts({ uid: 0 }) }),
  );
  expectFindings(r, "login-is-root critical");
  const asRoot = await evaluateAudit(
    input({ userProbe: userFacts({ uid: 0, user: "root" }) }),
  );
  expectFindings(asRoot, "login-is-root critical");
});

Deno.test("evaluateAudit: a user probe that ran as another user gives probe-wrong-user high", async () => {
  const r = await evaluateAudit(
    input({ userProbe: userFacts({ user: "dmc" }) }),
  );
  expectFindings(r, "probe-wrong-user high");
});

Deno.test("evaluateAudit: docker info that succeeds gives docker-socket-access", async () => {
  const r = await evaluateAudit(
    input({ userProbe: userFacts({ dockerRc: 0 }) }),
  );
  expectFindings(r, "docker-socket-access critical");
});

Deno.test("evaluateAudit: sudo that runs true for the login gives privilege-unrestricted, and a may-run list with no sudoers file gives privilege-foreign:sudo-list", async () => {
  const byTrue = await evaluateAudit(input({
    userProbe: userFacts({ sudoTrueRc: 0 }),
  }));
  expectFindings(byTrue, "privilege-unrestricted critical");
  const byList = await evaluateAudit(input({
    userProbe: userFacts({
      sudoList: { rc: 0, out: "User x may run the following commands" },
    }),
  }));
  expectFindings(byList, "privilege-foreign:sudo-list high");
});

Deno.test("evaluateAudit: a may-run list that a required grant in our sudoers file explains gives no finding", async () => {
  const r = await evaluateAudit(grantsInput(grantFile(APT_IDS), {
    families: ["apt"],
    machine: { sudo: { osUpgrade: true, reboot: false } },
    userProbe: userFacts({
      sudoList: { rc: 0, out: "User x may run the following commands" },
    }),
  }));
  assertEquals(r.findings, []);
});

Deno.test("evaluateAudit: sudo that refuses the login gives no privilege finding", async () => {
  const r = await evaluateAudit(input({
    userProbe: userFacts({
      sudoList: { rc: 1, out: "Sorry, user x may not run sudo on host." },
      sudoTrueRc: 1,
    }),
  }));
  assertEquals(r.findings, []);
});

Deno.test("evaluateAudit: a sudoers rule with ALL gives privilege-foreign critical", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      sudoRules: [{
        file: "/etc/sudoers.d/ops",
        lines: ["3:patchq-test ALL=(ALL) NOPASSWD: ALL"],
      }],
    }),
  }));
  expectFindings(r, "privilege-foreign:/etc/sudoers.d/ops critical");
});

Deno.test("evaluateAudit: a sudoers rule without ALL gives privilege-foreign high", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      sudoRules: [{
        file: "/etc/sudoers.d/ops",
        lines: ["4:%adm ops=(root) /usr/bin/true"],
      }],
    }),
  }));
  expectFindings(r, "privilege-foreign:/etc/sudoers.d/ops high");
});

Deno.test("evaluateAudit: the user can write a managed file gives managed-file-writable", async () => {
  const user = await evaluateAudit(input({
    userProbe: userFacts({ canWrite: { ...NO_WRITES, marker: true } }),
  }));
  expectFindings(user, `managed-file-writable:${PATHS.marker} critical`);
  const root = await evaluateAudit(input({
    rootProbe: rootFacts({
      managedFiles: managedFiles(
        present(PATHS.aptConf, APT_SHA, { owner: "dmc" }),
      ),
    }),
  }));
  expectFindings(root, `managed-file-writable:${PATHS.aptConf} critical`);
  const dir = await evaluateAudit(input({
    rootProbe: rootFacts({
      dirs: {
        stateDir: { owner: "root", group: "root", mode: "777" },
        libexec: null,
        sudoersDir: ROOT_DIR,
        systemdDir: ROOT_DIR,
        projectsDir: null,
      },
    }),
  }));
  expectFindings(dir, `managed-file-writable:${PATHS.stateDir} critical`);
});

Deno.test("evaluateAudit: a managed file whose content differs gives managed-file-drift", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      managedFiles: managedFiles(
        present(PATHS.aptConf, ZEROS, { hasManagedHeader: true }),
      ),
    }),
  }));
  expectFindings(r, `managed-file-drift:${PATHS.aptConf} high`);
});

Deno.test("evaluateAudit: a managed file with the expected content gives no drift", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      managedFiles: managedFiles(
        present(PATHS.aptConf, APT_SHA, { hasManagedHeader: true }),
      ),
    }),
  }));
  assertEquals(r.findings, []);
});

Deno.test("evaluateAudit: docker wanted with the producer missing gives docker-producer-missing", async () => {
  const r = await evaluateAudit(input({ docker: true }));
  // The sudoers file has no grant for the docker helper, which the host needs.
  expectFindings(
    r,
    "docker-producer-missing warning",
    "docker-helper-missing warning",
    "privilege-missing:docker-helper warning",
  );
});

Deno.test("evaluateAudit: a from entry broader than /24 or /64 gives from-broad", async () => {
  for (const from of ["10.0.0.0/16", "2001:db8::/48"]) {
    const line = authorizedKeysLine(KEY, [from]);
    const r = await evaluateAudit(input({
      from: [from],
      rootProbe: rootFacts({
        authorizedKeys: {
          lines: [line],
          total: 1,
          file: ROOT_FILE,
          dir: ROOT_DIR,
          home: ROOT_DIR,
        },
      }),
    }));
    expectFindings(r, `from-broad:${from} high`);
  }
});

Deno.test("evaluateAudit: from entries at /24, /64 and single addresses are not broad", async () => {
  for (const from of ["10.0.0.0/24", "2001:db8::/64", "192.0.2.131"]) {
    const line = authorizedKeysLine(KEY, [from]);
    const r = await evaluateAudit(input({
      from: [from],
      rootProbe: rootFacts({
        authorizedKeys: {
          lines: [line],
          total: 1,
          file: ROOT_FILE,
          dir: ROOT_DIR,
          home: ROOT_DIR,
        },
      }),
    }));
    assertEquals(r.findings, []);
  }
});

Deno.test("evaluateAudit: a package cache with no refresh timer gives cache-refresh-off", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      cache: {
        family: "dnf",
        refreshOn: false,
        ageHours: 1,
        autoInstall: false,
        autoScope: null,
      },
    }),
  }));
  expectFindings(r, "cache-refresh-off warning");
});

Deno.test("evaluateAudit: a cache older than 48 hours gives cache-stale", async () => {
  const stale = await evaluateAudit(input({
    rootProbe: rootFacts({
      cache: {
        family: "apt",
        refreshOn: true,
        ageHours: 49,
        autoInstall: false,
        autoScope: null,
      },
    }),
  }));
  expectFindings(stale, "cache-stale warning");
  const edge = await evaluateAudit(input({
    rootProbe: rootFacts({
      cache: {
        family: "apt",
        refreshOn: true,
        ageHours: 48,
        autoInstall: false,
        autoScope: null,
      },
    }),
  }));
  assertEquals(edge.findings, []);
});

Deno.test("evaluateAudit: unattended installs with a policy that is not auto give auto-install-conflict", async () => {
  const cache = {
    family: "apt",
    refreshOn: true,
    ageHours: 1,
    autoInstall: true,
    autoScope: null,
  };
  const conflict = await evaluateAudit(input({
    rootProbe: rootFacts({ cache }),
  }));
  expectFindings(conflict, "auto-install-conflict warning");
  const agreed = await evaluateAudit(input({
    rootProbe: rootFacts({ cache }),
    machine: { osUpdatePolicy: "auto" },
  }));
  assertEquals(agreed.findings, []);
});

Deno.test("evaluateAudit: an auto policy on a host that does not install updates gives auto-install-off", async () => {
  // The default fixture has autoInstall false.
  const off = await evaluateAudit(input({
    machine: { osUpdatePolicy: "auto" },
  }));
  expectFindings(off, "auto-install-off warning");
  const on = await evaluateAudit(input({
    rootProbe: rootFacts({
      cache: {
        family: "apt",
        refreshOn: true,
        ageHours: 1,
        autoInstall: true,
        autoScope: null,
      },
    }),
    machine: { osUpdatePolicy: "auto" },
  }));
  assertEquals(on.findings, []);
  const managed = await evaluateAudit(input({
    machine: { osUpdatePolicy: "managed" },
  }));
  assertEquals(managed.findings, []);
  const unset = await evaluateAudit(input());
  assertEquals(unset.findings, []);
});

Deno.test("evaluateAudit: auto-install-off is not derived from a root probe that did not run, and can be accepted", async () => {
  const unknown = await evaluateAudit(input({
    rootProbe: null,
    rootProbeError: "ssh refused",
    machine: { osUpdatePolicy: "auto" },
  }));
  expectFindings(unknown, "probe-failed:root high");
  const accepted = await evaluateAudit(input({
    machine: {
      osUpdatePolicy: "auto",
      acceptedRisks: [{
        ...REC,
        finding: "auto-install-off",
        reason:
          "Updates are applied by the vendor's own timer, reviewed quarterly",
      }],
    },
  }));
  assertEquals(accepted.findings, []);
  assertEquals(accepted.acceptedRisks.map((a) => a.id), ["auto-install-off"]);
});

Deno.test("evaluateAudit: another user in a root-equivalent group gives host-group, not root", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      hostGroups: { ...NO_HOSTS, docker: ["dmc", "root", USER] },
    }),
  }));
  expectFindings(r, "host-group:docker:dmc info");
});

Deno.test("evaluateAudit: a machine unsafe key is an accepted risk, not a finding", async () => {
  const r = await evaluateAudit(input({
    machine: { unsafe: { rootSsh: REC } },
  }));
  assertEquals(r.findings, []);
  assertEquals(r.acceptedRisks.length, 1);
  assertEquals(r.acceptedRisks[0].id, "unsafe:rootSsh");
  assertEquals(r.acceptedRisks[0].severity, "warning");
  assertEquals(r.summary.accepted, 1);
  assertEquals(r.summary.warning, 0);
});

Deno.test("evaluateAudit: trustRemote is an accepted info risk, keyed by source", async () => {
  const r = await evaluateAudit(input({
    machine: {
      trustRemote: [{ ...REC, source: "community-scripts/ProxmoxVE@main" }],
    },
  }));
  assertEquals(r.findings, []);
  assertEquals(
    r.acceptedRisks[0].id,
    "trust-remote:community-scripts/ProxmoxVE@main",
  );
  assertEquals(r.acceptedRisks[0].severity, "info");
});

Deno.test("evaluateAudit: an accepted risk moves its finding out and keeps the severity", async () => {
  const r = await evaluateAudit(input({
    userProbe: userFacts({ dockerRc: 0 }),
    machine: { acceptedRisks: [{ ...REC, finding: "docker-socket-access" }] },
  }));
  assertEquals(r.findings, []);
  assertEquals(r.acceptedRisks.length, 1);
  assertEquals(r.acceptedRisks[0].id, "docker-socket-access");
  assertEquals(r.acceptedRisks[0].severity, "critical");
  assertEquals(r.summary.critical, 0);
  assertEquals(r.summary.accepted, 1);
});

Deno.test("evaluateAudit: an overdue accepted risk still moves its finding and adds acceptance-overdue", async () => {
  const r = await evaluateAudit(input({
    userProbe: userFacts({ dockerRc: 0 }),
    machine: {
      acceptedRisks: [{
        ...REC,
        reviewBy: "2026-10-28",
        finding: "docker-socket-access",
      }],
    },
  }));
  expectFindings(r, "acceptance-overdue:docker-socket-access warning");
  assertEquals(r.acceptedRisks[0].id, "docker-socket-access");
  assertEquals(r.summary.overdue, 1);
});

Deno.test("evaluateAudit: a review date that is today is not overdue", async () => {
  const r = await evaluateAudit(input({
    userProbe: userFacts({ dockerRc: 0 }),
    machine: {
      acceptedRisks: [{
        ...REC,
        reviewBy: "2026-10-29",
        finding: "docker-socket-access",
      }],
    },
  }));
  assertEquals(r.findings, []);
  assertEquals(r.summary.overdue, 0);
});

Deno.test("evaluateAudit: overdue unsafe and trustRemote records get acceptance-overdue too", async () => {
  const old = {
    reason: "Pinned by ops; reviewed quarterly",
    acceptedBy: "dmc",
    acceptedAt: "2026-09-01",
    reviewBy: "2026-10-01",
  };
  const r = await evaluateAudit(input({
    machine: {
      unsafe: { rootSsh: old },
      trustRemote: [{ ...old, source: "community-scripts/ProxmoxVE@main" }],
    },
  }));
  expectFindings(
    r,
    "acceptance-overdue:unsafe:rootSsh warning",
    "acceptance-overdue:trust-remote:community-scripts/ProxmoxVE@main warning",
  );
  assertEquals(r.summary.overdue, 2);
  assertEquals(r.summary.accepted, 2);
});

Deno.test("evaluateAudit: an accepted risk that matches no finding gives acceptance-stale", async () => {
  const r = await evaluateAudit(input({
    machine: { acceptedRisks: [{ ...REC, finding: "privilege-unrestricted" }] },
  }));
  expectFindings(r, "acceptance-stale:privilege-unrestricted info");
});

Deno.test("evaluateAudit: no acceptance-stale when a probe failed or was invalid", async () => {
  const stale = { ...REC, finding: "privilege-unrestricted" };
  const userFailed = await evaluateAudit(input({
    userProbe: null,
    userProbeError: "ssh timed out",
    machine: { acceptedRisks: [stale] },
  }));
  expectFindings(userFailed, "probe-failed:user high");
  const rootFailed = await evaluateAudit(input({
    rootProbe: null,
    rootProbeError: "login cannot be read from prov",
    machine: { acceptedRisks: [stale] },
  }));
  expectFindings(rootFailed, "probe-failed:root high");
  const rootInvalid = await evaluateAudit(input({
    rootProbe: { _kind: "patch-access-root-probe" },
    machine: { acceptedRisks: [stale] },
  }));
  expectFindings(rootInvalid, "probe-invalid:root high");
});

Deno.test("evaluateAudit: a second record for one finding is redundant, not stale", async () => {
  const r = await evaluateAudit(input({
    userProbe: userFacts({ dockerRc: 0 }),
    machine: {
      acceptedRisks: [
        { ...REC, finding: "docker-socket-access" },
        {
          ...REC,
          finding: "docker-socket-access",
          reason: "A second, redundant record",
        },
      ],
    },
  }));
  assertEquals(r.findings, []);
  assertEquals(r.acceptedRisks.length, 1);
});

Deno.test("evaluateAudit: messages never include the full key", async () => {
  const r = await evaluateAudit(input({
    from: ["10.0.0.0/8"],
    rootProbe: rootFacts({
      authorizedKeys: {
        lines: [`from="10.0.0.0/8",no-pty ${KEY}`],
        total: 1,
        file: ROOT_FILE,
        dir: ROOT_DIR,
        home: ROOT_DIR,
      },
    }),
  }));
  assert(r.findings.length > 0);
  assertEquals(JSON.stringify(r.findings).includes(BLOB), false);
  assertEquals(JSON.stringify(r.acceptedRisks).includes(BLOB), false);
});

Deno.test("evaluateAudit: the summary counts each severity, accepted and overdue", async () => {
  const r = await evaluateAudit(input({
    userProbe: userFacts({ dockerRc: 0 }),
    rootProbe: rootFacts({
      groupsOfUser: [USER, "wheel"],
      cache: {
        family: "apt",
        refreshOn: true,
        ageHours: 49,
        autoInstall: false,
        autoScope: null,
      },
    }),
    machine: { unsafe: { rootSsh: REC } },
  }));
  assertEquals(r.summary, {
    critical: 2,
    high: 0,
    warning: 1,
    info: 0,
    accepted: 1,
    overdue: 0,
  });
});

// ---------------------------------------------------------------------------
// Auto OS updates: the auto files are audited like the other managed files
// ---------------------------------------------------------------------------

const AUTO_APT_SECURITY = await sha256Hex(aptAutoConf("security"));
const AUTO_APT_ALL = await sha256Hex(aptAutoConf("all"));

Deno.test("evaluateAudit: an auto file with the machine's scope, on a host that installs its own updates, gives no finding", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      managedFiles: [
        ...managedFiles(),
        present(PATHS.aptAuto, AUTO_APT_SECURITY),
      ],
      cache: {
        family: "apt",
        refreshOn: true,
        ageHours: 1,
        autoInstall: true,
        autoScope: "security",
      },
    }),
    machine: { osUpdatePolicy: "auto", autoUpdates: "security" },
  }));
  assertEquals(r.findings, []);
});

Deno.test("evaluateAudit: an auto file of the other scope gives auto-scope-mismatch, and its content gives managed-file-drift", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      managedFiles: [
        ...managedFiles(),
        present(PATHS.aptAuto, AUTO_APT_ALL),
      ],
      cache: {
        family: "apt",
        refreshOn: true,
        ageHours: 1,
        autoInstall: true,
        autoScope: "all",
      },
    }),
    machine: { osUpdatePolicy: "auto", autoUpdates: "security" },
  }));
  expectFindings(
    r,
    "auto-scope-mismatch warning",
    `managed-file-drift:${PATHS.aptAuto} high`,
  );
});

Deno.test("evaluateAudit: a tampered dnf auto config gives managed-file-drift for that path", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      managedFiles: [
        ...managedFiles(),
        present(PATHS.dnfAutoConf, ZEROS),
      ],
      cache: {
        family: "dnf",
        refreshOn: true,
        ageHours: 1,
        autoInstall: true,
        autoScope: "security",
      },
    }),
    machine: { osUpdatePolicy: "auto", autoUpdates: "security" },
  }));
  expectFindings(r, `managed-file-drift:${PATHS.dnfAutoConf} high`);
});

Deno.test("evaluateAudit: a managed machine with a leftover auto file that installs gives auto-install-conflict, and no drift check", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      managedFiles: [
        ...managedFiles(),
        present(PATHS.aptAuto, AUTO_APT_ALL),
      ],
      cache: {
        family: "apt",
        refreshOn: true,
        ageHours: 1,
        autoInstall: true,
        autoScope: "all",
      },
    }),
  }));
  expectFindings(r, "auto-install-conflict warning");
});

Deno.test("evaluateAudit: the patch login that can write an auto file gives managed-file-writable", async () => {
  const cases: Array<[string, string]> = [
    ["aptAuto", PATHS.aptAuto],
    ["dnfAutoConf", PATHS.dnfAutoConf],
    ["dnfAutoDropIn", PATHS.dnfAutoDropIn],
  ];
  for (const [key, path] of cases) {
    const r = await evaluateAudit(input({
      userProbe: userFacts({ canWrite: { ...NO_WRITES, [key]: true } }),
    }));
    expectFindings(r, `managed-file-writable:${path} critical`);
  }
});

Deno.test("rootProbeScript: the probe reads the auto files, the dnf drop-in and its config, and the scope", () => {
  const s = rootProbeScript(USER, KEY);
  assertStringIncludes(s, `$(managed "$APT_AUTO")`);
  assertStringIncludes(s, `$(managed "$DNF_AUTO_CONF")`);
  assertStringIncludes(s, `$(managed "$DNF_AUTO_DROP_IN")`);
  assertStringIncludes(
    s,
    'grep -qxF "ExecStart=/usr/bin/dnf-automatic $DNF_AUTO_CONF --timer" "$DNF_AUTO_DROP_IN"',
  );
  assertStringIncludes(s, '"autoInstall":%s,"autoScope":%s}');
  assertStringIncludes(s, '"$auto_install" "$auto_scope"');
});

Deno.test("rootProbeScript: our sudoers file is read line by line, and the families and compose entries are printed", () => {
  const s = rootProbeScript(USER, KEY);
  assertStringIncludes(s, `[ "$f" = "$SUDOERS" ] && continue`);
  assertStringIncludes(
    s,
    `"sudoersFile":%s,"sudoFamilies":[%s],"compose":[%s]}`,
  );
});

// ---------------------------------------------------------------------------
// The docker helper and its project list
// ---------------------------------------------------------------------------

const PROJECTS = [{ name: "app", composeDir: "/srv/app", service: "-" }];
/** The sudoers file of a docker host: the two Defaults lines and the helper grant. */
const DOCKER_SUDOERS = {
  exists: true,
  lines: [
    ...DEFAULTS_LINES,
    `${USER} ALL=(root) NOPASSWD: ${DOCKER_HELPER_PATH}`,
  ],
  total: 3,
};

Deno.test("evaluateAudit docker helper: the helper and the list match their content and are not writable", async () => {
  const helperSha = await sha256Hex(dockerHelperScript(MANAGED_HEADER));
  const listSha = await sha256Hex(dockerProjectsFile(PROJECTS, MANAGED_HEADER));
  const files = managedFiles(
    present(PATHS.dockerHelper, helperSha, { mode: "755" }),
    present(PATHS.dockerProjects, listSha, { mode: "644" }),
  );
  // The producer is missing in this fixture, so only that warning is expected.
  const r = await evaluateAudit(input({
    docker: true,
    machine: { dockerProjects: PROJECTS },
    rootProbe: rootFacts({ managedFiles: files, sudoersFile: DOCKER_SUDOERS }),
  }));
  expectFindings(r, "docker-producer-missing warning");
});

Deno.test("evaluateAudit docker helper: a helper or list that differs from its content gives drift", async () => {
  const files = managedFiles(
    present(PATHS.dockerHelper, "0".repeat(64), { mode: "755" }),
    present(PATHS.dockerProjects, "1".repeat(64), { mode: "644" }),
  );
  const r = await evaluateAudit(input({
    docker: true,
    machine: { dockerProjects: PROJECTS },
    rootProbe: rootFacts({ managedFiles: files, sudoersFile: DOCKER_SUDOERS }),
  }));
  expectFindings(
    r,
    `managed-file-drift:${PATHS.dockerHelper} high`,
    `managed-file-drift:${PATHS.dockerProjects} high`,
    "docker-producer-missing warning",
  );
});

Deno.test("evaluateAudit docker helper: a helper or list the login can write gives managed-file-writable", async () => {
  for (const key of ["dockerHelper", "dockerProjects"] as const) {
    const path = key === "dockerHelper"
      ? PATHS.dockerHelper
      : PATHS.dockerProjects;
    const r = await evaluateAudit(input({
      userProbe: userFacts({ canWrite: { ...NO_WRITES, [key]: true } }),
    }));
    expectFindings(r, `managed-file-writable:${path} critical`);
  }
});

Deno.test("evaluateAudit docker helper: a projects directory that is not root's gives managed-file-writable", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      dirs: {
        stateDir: ROOT_DIR,
        libexec: null,
        sudoersDir: ROOT_DIR,
        systemdDir: ROOT_DIR,
        projectsDir: { owner: "root", group: "root", mode: "777" },
      },
    }),
  }));
  expectFindings(r, `managed-file-writable:${PATHS.projectsDir} critical`);
});

Deno.test("evaluateAudit docker helper: a host without docker wants no helper, so a missing one is not a warning", async () => {
  const r = await evaluateAudit(input({ docker: false }));
  expectFindings(r);
});

// ---------------------------------------------------------------------------
// Sudoers grants: our file is compared with the required set
// ---------------------------------------------------------------------------

Deno.test("evaluateAudit grants: the required set of an apt host with reboot gives no finding", async () => {
  const r = await evaluateAudit(grantsInput(grantFile(ALL_IDS)));
  assertEquals(r.findings, []);
});

Deno.test("evaluateAudit grants: one missing apt entry gives privilege-missing for that entry, as a warning", async () => {
  for (const id of APT_IDS) {
    const r = await evaluateAudit(
      grantsInput(grantFile(ALL_IDS.filter((x) => x !== id))),
    );
    expectFindings(r, `privilege-missing:${id} warning`);
  }
});

Deno.test("evaluateAudit grants: entries of a family the host lacks are not missing, and the other families' are", async () => {
  // Only apt is on the host, so reboot (systemd) is not expected either.
  const apt = await evaluateAudit(
    grantsInput(grantFile(APT_IDS), { families: ["apt"] }),
  );
  expectFindings(apt);
  const dnf = await evaluateAudit(grantsInput([], { families: ["dnf"] }));
  expectFindings(dnf, "privilege-missing:dnf-upgrade warning");
  const apkPacman = await evaluateAudit(
    grantsInput([], { families: ["apk", "pacman"] }),
  );
  expectFindings(
    apkPacman,
    "privilege-missing:apk-upgrade warning",
    "privilege-missing:pacman-upgrade warning",
  );
});

Deno.test("evaluateAudit grants: a sudoers line that is not in the required set gives privilege-extra, critical", async () => {
  const extra = `${USER} ALL=(root) NOPASSWD: /usr/bin/apt-get install foo`;
  const r = await evaluateAudit(grantsInput([...grantFile(ALL_IDS), extra]));
  expectFindings(r, `privilege-extra:${extra} critical`);
});

Deno.test("evaluateAudit grants: a grant whose binary path is not the resolved absolute path gives privilege-extra and privilege-missing", async () => {
  // The path must be the binary's own absolute path: no other binary, no .. segment, no //,
  // and no relative path. The entry is then missing, since its line does not match.
  for (
    const bad of [
      "/usr/bin/sh",
      "/usr/bin/../bin/apt-get",
      "/usr//bin/apt-get",
      "usr/bin/apt-get",
    ]
  ) {
    const line = grantLine("apt-upgrade").replace("/usr/bin/apt-get", bad);
    const r = await evaluateAudit(grantsInput([
      ...DEFAULTS_LINES,
      grantLine("apt-update"),
      line,
      grantLine("apt-full-upgrade"),
      grantLine("reboot"),
    ]));
    expectFindings(
      r,
      `privilege-extra:${line} critical`,
      "privilege-missing:apt-upgrade warning",
    );
  }
});

Deno.test("evaluateAudit grants: lines sudo reads as something other than a grant for the login give privilege-extra, critical", async () => {
  // A directive, a numeric user id, a line the probe could not print, and a line for root.
  const forRoot = grantLine("apt-update").replace(USER, "root");
  for (
    const bad of [
      "#include /tmp/x",
      "#1000 ALL=(ALL) NOPASSWD: ALL",
      "<unreadable line>",
      forRoot,
    ]
  ) {
    const r = await evaluateAudit(grantsInput([...grantFile(ALL_IDS), bad]));
    expectFindings(r, `privilege-extra:${bad} critical`);
  }
});

Deno.test("evaluateAudit grants: two long extra lines with the same start give two findings", async () => {
  const start = `${USER} ALL=(root) NOPASSWD: /usr/bin/apt-get ${
    "x".repeat(250)
  }`;
  const r = await evaluateAudit(
    grantsInput([...grantFile(ALL_IDS), `${start} a`, `${start} b`]),
  );
  expectFindings(
    r,
    `privilege-extra:${start} a critical`,
    `privilege-extra:${start} b critical`,
  );
});

Deno.test("evaluateAudit grants: a sudoers file with more lines than the probe read gives privilege-extra:unread", async () => {
  // The filler is the Defaults line, which the evaluator accepts, so only the count is wrong.
  const lines = grantFile(ALL_IDS);
  while (lines.length < 128) lines.push(DEFAULTS_LINES[0]);
  const r = await evaluateAudit(grantsInput(lines, { total: 130 }));
  expectFindings(r, "privilege-extra:unread critical");
});

Deno.test("evaluateAudit grants: grants without both Defaults lines give privilege-defaults-missing, and no grant and no Defaults give nothing", async () => {
  const grants = ALL_IDS.map((id) => grantLine(id));
  expectFindings(
    await evaluateAudit(grantsInput(grants)),
    "privilege-defaults-missing high",
  );
  expectFindings(
    await evaluateAudit(grantsInput([DEFAULTS_LINES[0], ...grants])),
    "privilege-defaults-missing high",
  );
  expectFindings(await evaluateAudit(grantsInput([], { machine: {} })));
});

Deno.test("evaluateAudit grants: a reboot line on a host whose policy does not allow reboot gives privilege-extra", async () => {
  const reboot = grantLine("reboot");
  const r = await evaluateAudit(grantsInput([...grantFile(APT_IDS), reboot], {
    machine: { sudo: { osUpgrade: true, reboot: false } },
  }));
  expectFindings(r, `privilege-extra:${reboot} critical`);
});

Deno.test("evaluateAudit grants: a plug-in grant with its binary at the declared path is required, and at another path is privilege-extra", async () => {
  const plugin: PrivCommand = {
    id: "plugin-1-update",
    capability: "plugin",
    family: "plugin",
    bin: "/usr/bin/update",
    args: [],
    env: { PHS_SILENT: "1" },
  };
  const at = (bin: string) =>
    sudoersLine(USER, plugin, { env: "/usr/bin/env", "/usr/bin/update": bin });
  const pluginMachine = { pluginCommands: [plugin] };
  const good = await evaluateAudit(grantsInput(
    [...DEFAULTS_LINES, at("/usr/bin/update")],
    { machine: pluginMachine },
  ));
  assertEquals(good.findings, []);
  const elsewhere = at("/usr/local/bin/update");
  const bad = await evaluateAudit(grantsInput(
    [...DEFAULTS_LINES, elsewhere],
    { machine: pluginMachine },
  ));
  expectFindings(
    bad,
    `privilege-extra:${elsewhere} critical`,
    "privilege-missing:plugin-1-update warning",
  );
});

Deno.test("evaluateAudit grants: an accepted risk for a missing grant moves that finding to acceptedRisks", async () => {
  const r = await evaluateAudit(grantsInput(
    grantFile(ALL_IDS.filter((x) => x !== "apt-upgrade")),
    {
      machine: {
        sudo: OS_BOTH,
        acceptedRisks: [{ ...REC, finding: "privilege-missing:apt-upgrade" }],
      },
    },
  ));
  assertEquals(r.findings, []);
  assertEquals(
    r.acceptedRisks.map((a) => `${a.id} ${a.severity}`),
    ["privilege-missing:apt-upgrade warning"],
  );
  assertEquals(r.summary.warning, 0);
  assertEquals(r.summary.accepted, 1);
});

// ---------------------------------------------------------------------------
// Compose projects: the directories the docker helper runs as root
// ---------------------------------------------------------------------------

/** One compose project of the root probe: a root-owned, scanned directory under root's parents. */
function composeEntry(
  over: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    name: "app",
    dir: "/srv/app",
    realDir: "/srv/app",
    owned: ROOT_DIR,
    chain: [
      { path: "/srv", owned: ROOT_DIR },
      { path: "/", owned: ROOT_DIR },
    ],
    scanOk: true,
    unsafe: [],
    unsafeTotal: 0,
    ...over,
  };
}

Deno.test("evaluateAudit compose: a root-owned directory under root-owned parents, with no unsafe entry, gives no finding", async () => {
  const r = await evaluateAudit(
    input({ rootProbe: rootFacts({ compose: [composeEntry()] }) }),
  );
  assertEquals(r.findings, []);
});

Deno.test("evaluateAudit compose: a directory owned by another account gives compose-writable, and the message names the real directory", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      compose: [composeEntry({
        dir: "/opt/app",
        realDir: "/srv/app-real",
        owned: { owner: "dmc", group: "root", mode: "755" },
      })],
    }),
  }));
  expectFindings(r, "compose-writable:/opt/app high");
  assertStringIncludes(r.findings[0].message, "/srv/app-real");
});

Deno.test("evaluateAudit compose: a parent directory owned by another account gives compose-writable", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      compose: [composeEntry({
        dir: "/home/dmc/app",
        realDir: "/home/dmc/app",
        chain: [
          {
            path: "/home/dmc",
            owned: { owner: "dmc", group: "dmc", mode: "755" },
          },
          { path: "/home", owned: ROOT_DIR },
          { path: "/", owned: ROOT_DIR },
        ],
      })],
    }),
  }));
  expectFindings(r, "compose-writable:/home/dmc/app high");
  assertStringIncludes(r.findings[0].message, "/home/dmc");
});

Deno.test("evaluateAudit compose: a directory that is group-writable gives compose-writable", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      compose: [composeEntry({
        owned: { owner: "root", group: "root", mode: "775" },
      })],
    }),
  }));
  expectFindings(r, "compose-writable:/srv/app high");
});

Deno.test("evaluateAudit compose: an entry in the directory that a non-root account can change gives compose-writable", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      compose: [composeEntry({ unsafe: ["compose.yaml"], unsafeTotal: 1 })],
    }),
  }));
  expectFindings(r, "compose-writable:/srv/app high");
  assertStringIncludes(r.findings[0].message, "/srv/app/compose.yaml");
});

Deno.test("evaluateAudit compose: more unsafe entries than the probe lists say how many more", async () => {
  const names = Array.from({ length: 10 }, (_, k) => `f${k}.yaml`);
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      compose: [composeEntry({ unsafe: names, unsafeTotal: 12 })],
    }),
  }));
  expectFindings(r, "compose-writable:/srv/app high");
  assertStringIncludes(r.findings[0].message, "and 2 more");
});

Deno.test("evaluateAudit compose: a project directory that is missing gives compose-missing, and nothing else for it", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      compose: [composeEntry({
        owned: null,
        realDir: "",
        chain: [],
        scanOk: false,
      })],
    }),
  }));
  expectFindings(r, "compose-missing:/srv/app warning");
});

Deno.test("evaluateAudit compose: a directory the probe could not scan gives compose-unreadable", async () => {
  const r = await evaluateAudit(input({
    rootProbe: rootFacts({
      compose: [composeEntry({ scanOk: false })],
    }),
  }));
  expectFindings(r, "compose-unreadable:/srv/app high");
});
