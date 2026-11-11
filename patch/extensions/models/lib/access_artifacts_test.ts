/**
 * Unit tests for the access artifact generators. The scripts are checked as text and
 * with bash: bash -n for syntax, and the docker producer runs against a fake docker in
 * a temp dir. Nothing touches a host.
 */
import {
  assert,
  assertEquals,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import {
  apkPeriodicScript,
  aptAutoConf,
  aptPeriodicConf,
  authorizedKeysLine,
  dnfAutoDropInUnit,
  dnfAutomaticConf,
  dockerProducerScript,
  dockerTimerUnits,
  identityBlock,
  MANAGED_HEADER,
  PATHS,
  type ProvisionInput,
  provisionScript,
  revokeScript,
  shQuote,
  validateProvisionInput,
} from "./access_artifacts.ts";
import { dockerHelperScript, dockerProjectsFile } from "./docker_helper.ts";
import { parseDockerFile } from "./docker_inventory.ts";

const KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBjngojWT4QUfy2bl78lWkaepNtOZYDlAzZbel8QNoWN swamp-serve";
const FROM = ["192.0.2.131"];
// A user name that appears nowhere else in a generated script, so its occurrences can be counted.
const USER = "patchq-test";
const INPUT: ProvisionInput = {
  user: USER,
  publicKey: KEY,
  from: FROM,
  docker: true,
  autoUpdates: null,
  // Scan-only except for the docker helper and, because the login then has sudo, the dnf
  // check (capabilitiesFor). One project, of a docker host.
  sudo: { osUpgrade: false, osCheck: true, reboot: false, docker: true },
  dockerProjects: [{ name: "app", composeDir: "/srv/app", service: "-" }],
};

/** INPUT with the docker flag set, and the helper grant and project that go with it. */
function withDocker(docker: boolean): ProvisionInput {
  return {
    ...INPUT,
    docker,
    // As capabilitiesFor: a scan-only host without docker has no grant, so no osCheck either.
    sudo: { ...INPUT.sudo, docker, osCheck: docker },
    dockerProjects: docker ? INPUT.dockerProjects : [],
  };
}
const BAD_USERS = ["root", "toor", "Root", "a b", "x'y", "$(id)", "a;rm -rf /"];

const DIGEST_LOCAL = "sha256:" + "a".repeat(64);
const DIGEST_REG = "sha256:" + "b".repeat(64);

function occurrences(text: string, value: string): number {
  return text.split(value).length - 1;
}

/** Each value appears once in the top-of-script assignments and nowhere else in the script. */
function assertOnlyInTop(script: string, values: string[]): void {
  const top = script.slice(0, script.indexOf("\nset -"));
  assert(top.length > 0, "the script has no top-of-script assignments");
  for (const value of values) {
    const inTop = occurrences(top, value);
    assertEquals(inTop, 1, `${value} must be assigned once at the top`);
    assertEquals(
      occurrences(script, value),
      inTop,
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

Deno.test("shQuote: wraps in single quotes and escapes each single quote", () => {
  assertEquals(shQuote("a'b"), "'a'\\''b'");
  assertEquals(shQuote("plain"), "'plain'");
});

Deno.test("shQuote: $(id) and backticks stay literal when bash expands the word", async () => {
  for (const v of ["$(id)", "`id`", "a b", "x\\y", "$HOME"]) {
    const out = await new Deno.Command("bash", {
      args: ["-c", `printf %s ${shQuote(v)}`],
    }).output();
    assertEquals(new TextDecoder().decode(out.stdout), v);
  }
});

Deno.test("shQuote: refuses NUL, newline and carriage return", () => {
  assertThrows(() => shQuote("a\nb"));
  assertThrows(() => shQuote("a\rb"));
  assertThrows(() => shQuote("a\u0000b"));
});

Deno.test("authorizedKeysLine: the exact line for the access key", () => {
  assertEquals(
    authorizedKeysLine(KEY, ["192.0.2.131"]),
    `from="192.0.2.131",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc ${KEY}`,
  );
});

Deno.test("authorizedKeysLine: refuses an empty, open or injected from list", () => {
  assertThrows(() => authorizedKeysLine(KEY, []));
  assertThrows(() => authorizedKeysLine(KEY, ["0.0.0.0/0"]));
  assertThrows(() => authorizedKeysLine(KEY, ['10.0.0.1" ,command="id']));
});

Deno.test("authorizedKeysLine: refuses anything but one ed25519 key", () => {
  assertThrows(() => authorizedKeysLine(`${KEY}\n${KEY}`, FROM));
  assertThrows(() => authorizedKeysLine(`${KEY} ${KEY}`, FROM));
  assertThrows(() =>
    authorizedKeysLine(
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC swamp-serve",
      FROM,
    )
  );
});

Deno.test("validateProvisionInput: returns a copy of valid input", () => {
  const v = validateProvisionInput(INPUT);
  // The copy always holds the plug-in list, empty when the input has none.
  assertEquals(v, { ...INPUT, sudo: { ...INPUT.sudo, extra: [] } });
  assert(v.from !== INPUT.from);
});

Deno.test("validateProvisionInput and provisionScript refuse bad users", () => {
  for (const user of BAD_USERS) {
    assertThrows(() => validateProvisionInput({ ...INPUT, user }));
    assertThrows(() => provisionScript({ ...INPUT, user }));
    assertThrows(() => revokeScript(user));
  }
});

Deno.test("provisionScript refuses an unsafe from list", () => {
  assertThrows(() => provisionScript({ ...INPUT, from: ["0.0.0.0/0"] }));
  assertThrows(() => provisionScript({ ...INPUT, from: [] }));
});

Deno.test("INJECTION: provision and revoke take their inputs only from the top assignments", () => {
  for (const docker of [true, false]) {
    assertOnlyInTop(provisionScript(withDocker(docker)), [
      USER,
      KEY,
      "192.0.2.131",
    ]);
  }
  assertOnlyInTop(revokeScript(USER), [USER]);
});

Deno.test("INJECTION: scripts without inputs contain none of the test values", () => {
  for (const script of [dockerProducerScript(), apkPeriodicScript()]) {
    for (const value of [USER, KEY, "192.0.2.131"]) {
      assertEquals(occurrences(script, value), 0);
    }
  }
});

Deno.test("every generated script passes bash -n", async () => {
  await assertBashSyntax(provisionScript(withDocker(true)));
  await assertBashSyntax(provisionScript(withDocker(false)));
  await assertBashSyntax(revokeScript(USER));
  await assertBashSyntax(dockerProducerScript());
  await assertBashSyntax(apkPeriodicScript());
});

Deno.test("provisionScript: takeover refusal, locking, group removal, key file, no sudo grant", () => {
  const s = provisionScript(INPUT);
  assertStringIncludes(s, "refusing to take over existing account");
  assertStringIncludes(s, "exit 3");
  assertStringIncludes(s, "chpasswd -e");
  assertEquals(s.includes("passwd -l"), false);
  assertStringIncludes(
    s,
    "for g in docker wheel sudo admin adm lxd disk root; do",
  );
  assertStringIncludes(s, 'chown root:root "$HOME_DIR" "$HOME_DIR/.ssh"');
  assertStringIncludes(s, 'chown root:root "$tmp"');
  assertStringIncludes(s, 'install_file "$HOME_DIR/.ssh/authorized_keys" 0644');
  assertStringIncludes(s, 'remove_managed "$SUDOERS"');
  assert(!s.includes('install_file "$SUDOERS"'), "sudoers must not be written");
  assert(
    !provisionScript(withDocker(false)).includes("NOPASSWD"),
    "a scan-only login gets no grant",
  );
  assert(!s.includes("Unattended-Upgrade"));
  assert(!s.includes("curl"));
  assert(!s.includes("wget"));
});

Deno.test("provisionScript: the result line names the fields the caller reads", () => {
  const s = provisionScript(INPUT);
  assertStringIncludes(s, '{"_kind":"patch-access-provision"');
  assertStringIncludes(s, '"groupsRemoved":[%s]');
  assertStringIncludes(s, '"cacheRefresh":"%s"');
});

Deno.test("provisionScript: WANT_DOCKER follows the docker flag", () => {
  assertStringIncludes(
    provisionScript(withDocker(true)),
    "\nWANT_DOCKER=1\n",
  );
  assertStringIncludes(
    provisionScript(withDocker(false)),
    "\nWANT_DOCKER=0\n",
  );
});

Deno.test("provisionScript: the pre-flight refuses a docker host without /etc/systemd/system, and only when WANT_DOCKER is 1", () => {
  // The check is in every script and gated at run time by WANT_DOCKER, as the systemctl check is.
  for (const docker of [true, false]) {
    assertStringIncludes(
      provisionScript(withDocker(docker)),
      '"$WANT_DOCKER" = 1 ] && [ ! -d /etc/systemd/system ]',
    );
  }
});

Deno.test("provisionScript: each embedded file uses a quoted heredoc, and the delimiter is never inside one", () => {
  const s = provisionScript(INPUT);
  // Seven embedded files, each with an opening and a closing delimiter line.
  assertEquals(occurrences(s, "<<'SWAMP_PATCH_EOF'"), 7);
  assertEquals(occurrences(s, "SWAMP_PATCH_EOF"), 14);
  for (
    const text of [
      aptPeriodicConf(),
      apkPeriodicScript(),
      dockerProducerScript(),
      dockerHelperScript(MANAGED_HEADER),
      dockerProjectsFile(INPUT.dockerProjects, MANAGED_HEADER),
      dockerTimerUnits().service,
      dockerTimerUnits().timer,
    ]
  ) {
    assert(!text.includes("SWAMP_PATCH_EOF"));
  }
});

Deno.test("revokeScript: removes only managed files, then the marked account and the state dir", () => {
  const s = revokeScript(USER);
  assertStringIncludes(s, 'rm -f "$SUDOERS"');
  assertStringIncludes(s, "if marker_ok; then");
  assertStringIncludes(s, 'rm -rf "$STATE_DIR"');
  assertStringIncludes(s, "swamp-patch-docker-inventory.timer");
  assertStringIncludes(s, '{"_kind":"patch-access-revoke"');
  assert(!s.includes("install_file"));
});

Deno.test("revokeScript: deletes the account without its home, checks each step, never uses userdel -r", () => {
  const s = revokeScript(USER);
  assertStringIncludes(s, 'userdel "$PATCH_USER"');
  assertStringIncludes(s, 'deluser "$PATCH_USER"');
  assertStringIncludes(s, 'groupdel "$PATCH_USER"');
  assertStringIncludes(s, 'delgroup "$PATCH_USER"');
  assertStringIncludes(s, 'if ! userdel "$PATCH_USER"; then');
  assertStringIncludes(s, 'if ! rm -rf "$STATE_DIR"; then');
  assert(
    !s.includes("userdel -r"),
    "revoke must not remove the home with userdel -r",
  );
  assert(
    !s.includes("--remove-home"),
    "revoke must not remove the home with deluser",
  );
});

Deno.test("provisionScript: the account is bound to a random token in its GECOS and the marker", () => {
  const s = provisionScript(INPUT);
  assertStringIncludes(s, "od -An -N16 -tx1 /dev/urandom | tr -d ' \\n'");
  assertStringIncludes(s, "[[ ! $token =~ ^[0-9a-f]{32}$ ]]");
  assertStringIncludes(
    s,
    'comment="swamp-patch (managed by @dmc/patch) token=$token"',
  );
  assertStringIncludes(s, '--comment "$comment"');
  assertStringIncludes(s, '-g "$comment"');
  assertStringIncludes(
    s,
    'printf \'user=%s\\ntoken=%s\\n\' "$PATCH_USER" "$token" | install_file "$MARKER" 0644',
  );
  assertStringIncludes(s, 'getent passwd "$1"');
  assertStringIncludes(s, "if ! marker_ok; then");
  assert(
    !s.includes('cat "$MARKER"'),
    "the marker is no longer compared as one name",
  );
});

Deno.test("provisionScript: refuses early with exit 4, before any change, and uses $BASH_PATH", () => {
  const s = provisionScript(INPUT);
  // Four preflight refusals (no bash, no systemctl or systemd directory for docker, a group
  // name taken), and the sudo pre-flight's refusal to overwrite a foreign file.
  assertEquals(occurrences(s, "exit 4"), 5);
  assertStringIncludes(s, 'BASH_PATH="$(command -v bash || true)"');
  assertStringIncludes(s, '--shell "$BASH_PATH"');
  assertStringIncludes(s, '-s "$BASH_PATH"');
  // The helper's own #!/bin/bash line is not the login shell, so it is left out of the check.
  assert(
    !s.replace(dockerHelperScript(MANAGED_HEADER), "").includes("/bin/bash"),
    "the login shell must come from $BASH_PATH",
  );
  assertStringIncludes(s, 'WANT_DOCKER" = 1 ] && ! command -v systemctl');
  assertStringIncludes(
    s,
    "a group named $PATCH_USER already exists without the account",
  );
  const root = s.indexOf("== root");
  const preflight = s.indexOf("== preflight");
  const account = s.indexOf("== account");
  assert(
    root >= 0 && root < preflight && preflight < account,
    "the preflight runs after the root check and before the account step",
  );
});

const TOKEN = "0123456789abcdef0123456789abcdef";
const GOOD_GECOS = `swamp-patch (managed by @dmc/patch) token=${TOKEN}`;

/**
 * Run marker_ok from the generated identity block, against a marker file (null for none)
 * and a fake GECOS. The real lookup reads getent or /etc/passwd, so the test replaces it.
 * Returns true when the check passes.
 */
async function markerPasses(
  marker: string | null,
  gecos: string,
): Promise<boolean> {
  const dir = await Deno.makeTempDir();
  try {
    const markerPath = `${dir}/managed-user`;
    if (marker !== null) await Deno.writeTextFile(markerPath, marker);
    const file = `${dir}/check.sh`;
    await Deno.writeTextFile(
      file,
      `#!/usr/bin/env bash
set -euo pipefail
MARKER=${shQuote(markerPath)}
PATCH_USER=${shQuote(USER)}
${identityBlock()}
account_gecos() { printf '%s\\n' ${shQuote(gecos)}; }
if marker_ok; then exit 0; fi
exit 1
`,
    );
    const out = await new Deno.Command("bash", { args: [file] }).output();
    return out.code === 0;
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
}

Deno.test("marker_ok: passes when the marker and the GECOS name the same token", async () => {
  assertEquals(
    await markerPasses(`user=${USER}\ntoken=${TOKEN}\n`, GOOD_GECOS),
    true,
  );
});

Deno.test("marker_ok: refuses a missing marker, another user, a bad token, or a GECOS without the token", async () => {
  const good = `user=${USER}\ntoken=${TOKEN}\n`;
  assertEquals(await markerPasses(null, GOOD_GECOS), false);
  assertEquals(
    await markerPasses(`user=other\ntoken=${TOKEN}\n`, GOOD_GECOS),
    false,
  );
  assertEquals(await markerPasses(`user=${USER}\n`, GOOD_GECOS), false);
  assertEquals(
    await markerPasses(`user=${USER}\ntoken=${TOKEN.slice(1)}\n`, GOOD_GECOS),
    false,
  );
  assertEquals(
    await markerPasses(
      `user=${USER}\ntoken=${TOKEN.toUpperCase()}\n`,
      GOOD_GECOS,
    ),
    false,
  );
  assertEquals(
    await markerPasses(good, "swamp-patch (managed by @dmc/patch)"),
    false,
  );
  assertEquals(
    await markerPasses(good, `swamp-patch token=${"f".repeat(32)}`),
    false,
  );
});

Deno.test("marker_ok: the token must be a whole word in the GECOS", async () => {
  const good = `user=${USER}\ntoken=${TOKEN}\n`;
  assertEquals(await markerPasses(good, `${GOOD_GECOS} extra`), true);
  assertEquals(await markerPasses(good, `${GOOD_GECOS}0`), false);
});

Deno.test("aptPeriodicConf and apkPeriodicScript: managed, metadata refresh only", () => {
  assertEquals(
    aptPeriodicConf(),
    `${MANAGED_HEADER}\nAPT::Periodic::Update-Package-Lists "1";\n`,
  );
  assert(!aptPeriodicConf().includes("Unattended"));
  assertEquals(
    apkPeriodicScript(),
    `#!/bin/sh\n${MANAGED_HEADER}\napk update -q >/dev/null 2>&1\n`,
  );
});

Deno.test("dockerTimerUnits: the producer service and its hourly timer", () => {
  const { service, timer } = dockerTimerUnits();
  assertStringIncludes(service, "Type=oneshot");
  assertStringIncludes(service, `ExecStart=${PATHS.dockerProducer}\n`);
  assertStringIncludes(service, "ProtectHome=yes");
  assertStringIncludes(service, "NoNewPrivileges=yes");
  assertStringIncludes(service, "PrivateTmp=yes");
  assertStringIncludes(timer, "OnBootSec=5min");
  assertStringIncludes(timer, "OnUnitActiveSec=1h");
  assertStringIncludes(timer, "RandomizedDelaySec=5min");
  assertStringIncludes(timer, "WantedBy=timers.target");
  assertStringIncludes(service, MANAGED_HEADER);
  assertStringIncludes(timer, MANAGED_HEADER);
});

Deno.test("dockerProducerScript: refuses an output path outside the safe set", () => {
  for (
    const p of [
      "relative/x.json",
      "/var/lib/x y.json",
      "/var/lib/x'y.json",
      "/var/lib/$(id).json",
      "/var/lib/x.json\n",
    ]
  ) {
    assertThrows(() => dockerProducerScript(p));
  }
});

/** A fake docker for the producer: `info` succeeds unless FAKE_DOCKER_INFO=fail. */
async function writeFakeDocker(dir: string): Promise<string> {
  const bin = `${dir}/bin`;
  await Deno.mkdir(bin);
  const path = `${bin}/docker`;
  await Deno.writeTextFile(
    path,
    `#!/usr/bin/env bash
case "$1" in
  --version) echo "Docker version 27.3.1, build abc1234" ;;
  info) [ "\${FAKE_DOCKER_INFO:-ok}" = ok ] ;;
  ps) printf '%s\\n' "$FAKE_NAMES" ;;
  inspect) echo "nginx:1.27" ;;
  image) echo "nginx@${DIGEST_LOCAL}" ;;
  buildx) echo "${DIGEST_REG}" ;;
esac
`,
  );
  await Deno.chmod(path, 0o755);
  return bin;
}

/** Run the producer written for `outPath` with the fake docker first on PATH. */
async function runProducer(
  dir: string,
  outPath: string,
  env: Record<string, string>,
): Promise<Deno.CommandOutput> {
  const bin = await writeFakeDocker(dir);
  const file = `${dir}/producer.sh`;
  await Deno.writeTextFile(file, dockerProducerScript(outPath));
  return await new Deno.Command("bash", {
    args: [file],
    env: { ...env, PATH: `${bin}:${Deno.env.get("PATH") ?? ""}` },
  }).output();
}

Deno.test("dockerProducerScript: two containers give a valid inventory file", async () => {
  const dir = await Deno.makeTempDir();
  try {
    const out = `${dir}/docker-inventory.json`;
    const r = await runProducer(dir, out, { FAKE_NAMES: "web\ndb" });
    assertEquals(r.code, 0, new TextDecoder().decode(r.stderr));
    const text = await Deno.readTextFile(out);
    const parsed = parseDockerFile(btoa(text), new Date());
    assert(parsed.ok, parsed.ok ? "" : parsed.error);
    assertEquals(parsed.dockerEngine, "27.3.1");
    assertEquals(parsed.dockerImages.map((i) => i.container), ["web", "db"]);
    assertEquals(parsed.dockerImages[0], {
      container: "web",
      image: "nginx:1.27",
      localDigest: DIGEST_LOCAL,
      registryDigest: DIGEST_REG,
      updateAvailable: true,
    });
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("dockerProducerScript: a failing docker info gives a null engine and no images", async () => {
  const dir = await Deno.makeTempDir();
  try {
    const out = `${dir}/docker-inventory.json`;
    const r = await runProducer(dir, out, {
      FAKE_NAMES: "web",
      FAKE_DOCKER_INFO: "fail",
    });
    assertEquals(r.code, 0, new TextDecoder().decode(r.stderr));
    const parsed = parseDockerFile(
      btoa(await Deno.readTextFile(out)),
      new Date(),
    );
    assert(parsed.ok, parsed.ok ? "" : parsed.error);
    assertEquals(parsed.dockerEngine, null);
    assertEquals(parsed.dockerImages, []);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("dockerProducerScript: a hostile container name never breaks the JSON", async () => {
  const dir = await Deno.makeTempDir();
  try {
    const hostile = 'we"b\\x';
    const out = `${dir}/docker-inventory.json`;
    const r = await runProducer(dir, out, { FAKE_NAMES: hostile });
    assertEquals(r.code, 0, new TextDecoder().decode(r.stderr));
    const text = await Deno.readTextFile(out);
    const json = JSON.parse(text);
    assertEquals(json.dockerImages[0].container, hostile);
    // The schema's name rule then refuses it; the file is never accepted with it.
    const parsed = parseDockerFile(btoa(text), new Date());
    assert(!parsed.ok);
    assertStringIncludes(parsed.error, "container");
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// Auto OS updates: the scope's files, the pre-flight, and the null (managed) path
// ---------------------------------------------------------------------------

const APT_AUTO_HEAD = [
  MANAGED_HEADER,
  'APT::Periodic::Unattended-Upgrade "1";',
  'Unattended-Upgrade::Automatic-Reboot "false";',
  "#clear Unattended-Upgrade::Origins-Pattern;",
  "#clear Unattended-Upgrade::Allowed-Origins;",
  "Unattended-Upgrade::Origins-Pattern {",
];
const APT_SECURITY_ORIGINS = [
  '  "origin=${distro_id},codename=${distro_codename}-security";',
  '  "origin=${distro_id},archive=${distro_codename}-security";',
];
const APT_BASE_ORIGINS = [
  '  "origin=${distro_id},codename=${distro_codename}";',
  '  "origin=${distro_id},archive=${distro_codename}";',
  '  "origin=${distro_id},codename=${distro_codename}-updates";',
  '  "origin=${distro_id},archive=${distro_codename}-updates";',
];

Deno.test("validateProvisionInput: autoUpdates is null, security or all, and anything else throws", () => {
  for (const autoUpdates of [null, "security", "all"] as const) {
    assertEquals(
      validateProvisionInput({ ...INPUT, autoUpdates }).autoUpdates,
      autoUpdates,
    );
  }
  for (const autoUpdates of ["", "some", "ALL", undefined, true]) {
    assertThrows(() =>
      validateProvisionInput({ ...INPUT, autoUpdates } as never)
    );
    assertThrows(() => provisionScript({ ...INPUT, autoUpdates } as never));
  }
});

Deno.test("aptAutoConf: the exact apt file for security, and for all", () => {
  assertEquals(
    aptAutoConf("security"),
    [...APT_AUTO_HEAD, ...APT_SECURITY_ORIGINS, "};", ""].join("\n"),
  );
  assertEquals(
    aptAutoConf("all"),
    [...APT_AUTO_HEAD, ...APT_SECURITY_ORIGINS, ...APT_BASE_ORIGINS, "};", ""]
      .join("\n"),
  );
});

Deno.test("dnfAutomaticConf and dnfAutoDropInUnit: the exact dnf files for security, and for all", () => {
  assertEquals(
    dnfAutomaticConf("security"),
    `${MANAGED_HEADER}
[commands]
upgrade_type = security
download_updates = yes
apply_updates = yes
reboot = never

[emitters]
emit_via = stdio

[base]
debuglevel = 1
`,
  );
  assertStringIncludes(
    dnfAutomaticConf("all"),
    "\n[commands]\nupgrade_type = default\n",
  );
  assertEquals(
    dnfAutoDropInUnit(),
    `${MANAGED_HEADER}
[Service]
ExecStart=
ExecStart=/usr/bin/dnf-automatic /etc/dnf/swamp-patch-automatic.conf --timer
`,
  );
});

Deno.test("provisionScript auto: the pre-flight exits 5 before any change, and every refusal names its cause", () => {
  for (const autoUpdates of ["security", "all"] as const) {
    const s = provisionScript({ ...INPUT, autoUpdates });
    for (
      const msg of [
        "auto OS updates are refused on a Proxmox node (it needs full-upgrade under @dmc/patch)",
        "unattended-upgrades is not installed: install it first (this script never installs packages)",
        "dnf-automatic is not installed: install it first (this script never installs packages)",
        "auto OS updates are not supported on apk (Alpine)",
        "auto OS updates are not supported on pacman (Arch)",
        "auto OS updates are not supported on this host's package manager",
      ]
    ) {
      assertStringIncludes(s, msg);
    }
    // Six auto refusals, and the sudo pre-flight's own refusal (sudo is needed for the helper).
    assertEquals(occurrences(s, "exit 5"), 7);

    // Every exit 5 sits between the preflight and the account step.
    const preflight = s.indexOf('echo "== preflight"');
    const account = s.indexOf('echo "== account"');
    let at = s.indexOf("exit 5");
    while (at >= 0) {
      assert(
        at > preflight && at < account,
        `exit 5 at ${at} is outside the pre-flight`,
      );
      at = s.indexOf("exit 5", at + 1);
    }

    // The first state change comes after the pre-flight.
    const refusal = s.indexOf("auto OS updates are refused on a Proxmox node");
    const changes = [
      "useradd",
      "addgroup",
      "chpasswd -e",
      'install_file "',
      "gpasswd -d",
      'delgroup "',
      'mkdir -p "$STATE_DIR"',
    ].map((c) => s.indexOf(c)).filter((i) => i >= 0);
    assert(refusal > preflight && refusal < account);
    assert(
      changes.every((i) => i > refusal),
      "a state change comes before the pre-flight",
    );
  }
});

Deno.test("provisionScript auto: installs the scope's files, enables the timer with a guard, and reports the scope", () => {
  const apt = provisionScript({ ...INPUT, autoUpdates: "all" });
  assertStringIncludes(apt, `auto_json='"all"'`);
  assertStringIncludes(
    apt,
    "install_file \"$APT_AUTO\" 0644 <<'SWAMP_PATCH_EOF'\n",
  );
  assertStringIncludes(apt, "systemctl enable --now apt-daily-upgrade.timer");
  assertStringIncludes(apt, '-updates";');
  assertStringIncludes(
    apt,
    `"docker":%s,"autoUpdates":%s,"sudoEntries":[%s],"sudoMissing":[%s]}\\n' "$PATCH_USER" "$created" "$groups_removed" "$cache_refresh" "$docker_on" "$auto_json" "$sudo_granted" "$sudo_missing"`,
  );

  const dnf = provisionScript({ ...INPUT, autoUpdates: "security" });
  assertStringIncludes(dnf, `auto_json='"security"'`);
  assertStringIncludes(
    dnf,
    'mkdir -p "${DNF_AUTO_DROP_IN%/*}"',
  );
  assertStringIncludes(dnf, 'install_file "$DNF_AUTO_CONF" 0644');
  assertStringIncludes(dnf, 'install_file "$DNF_AUTO_DROP_IN" 0644');
  assertStringIncludes(dnf, "systemctl daemon-reload");
  assertStringIncludes(dnf, "systemctl cat dnf-automatic.timer");
  assertStringIncludes(dnf, "systemctl enable --now dnf-automatic.timer");
  assert(!dnf.includes('-updates";'), "security must not list -updates");
});

Deno.test("provisionScript auto: never writes or names the distro's own updater files, or the package's dnf config", () => {
  for (const autoUpdates of ["security", "all"] as const) {
    const s = provisionScript({ ...INPUT, autoUpdates });
    assert(!s.includes("20auto-upgrades"));
    assert(!s.includes("50unattended-upgrades"));
    assert(!s.includes("/etc/dnf/automatic.conf"));
  }
});

Deno.test("provisionScript null: removes the three auto files when they are managed, and reports null", () => {
  const s = provisionScript({ ...INPUT, autoUpdates: null });
  assertStringIncludes(s, 'remove_managed "$APT_AUTO"');
  assertStringIncludes(s, 'remove_managed "$DNF_AUTO_CONF"');
  assertStringIncludes(s, 'remove_managed "$DNF_AUTO_DROP_IN"');
  assertStringIncludes(s, "auto_json=null");
  // Only the sudo pre-flight exits 5 here; the auto pre-flight does not run.
  assertEquals(occurrences(s, "exit 5"), 1);
  assert(!s.includes('install_file "$APT_AUTO"'));
  assert(!s.includes("apt-daily-upgrade.timer"));
  assert(!s.includes('-updates";'));
});

Deno.test("provisionScript auto: every auto script passes bash -n", async () => {
  await assertBashSyntax(
    provisionScript({ ...INPUT, autoUpdates: "security" }),
  );
  await assertBashSyntax(provisionScript({ ...INPUT, autoUpdates: "all" }));
  await assertBashSyntax(provisionScript({ ...INPUT, autoUpdates: null }));
});

Deno.test("revokeScript: removes the auto files only when they carry the managed header", () => {
  const s = revokeScript(USER);
  assertStringIncludes(
    s,
    'for f in "$APT_CONF" "$APK_PERIODIC" "$DOCKER_PRODUCER" "$DOCKER_HELPER" "$DOCKER_PROJECTS" "$UNIT_TIMER" "$UNIT_SERVICE" "$APT_AUTO" "$DNF_AUTO_CONF" "$DNF_AUTO_DROP_IN"; do',
  );
  assertStringIncludes(s, 'if is_managed "$f"; then');
});

Deno.test("provisionScript docker: the helper and the project list are installed root-owned, and the grant names only the helper", () => {
  const s = provisionScript(withDocker(true));
  assertStringIncludes(
    s,
    "install_file \"$DOCKER_HELPER\" 0755 <<'SWAMP_PATCH_EOF'",
  );
  assertStringIncludes(
    s,
    "install_file \"$DOCKER_PROJECTS\" 0644 <<'SWAMP_PATCH_EOF'",
  );
  assertStringIncludes(
    s,
    "sudo_helper docker-helper '/usr/local/libexec/swamp-patch/swamp-patch-docker'",
  );
  // The sudo section runs after the docker section, so the helper exists when its grant is checked.
  assert(s.indexOf('echo "== docker"') < s.indexOf('echo "== sudo"'));
});

Deno.test("provisionScript docker: a host without docker removes the helper and the list, and grants no helper", () => {
  const s = provisionScript(withDocker(false));
  assertStringIncludes(s, 'remove_managed "$DOCKER_HELPER"');
  assertStringIncludes(s, 'remove_managed "$DOCKER_PROJECTS"');
  assert(!s.includes("sudo_helper docker-helper '"), "no helper grant");
  assertStringIncludes(s, 'rmdir "$PROJECTS_DIR"');
});

Deno.test("validateProvisionInput: the helper grant follows docker, and every project is checked", () => {
  assertThrows(
    () =>
      validateProvisionInput({
        ...INPUT,
        sudo: { ...INPUT.sudo, docker: false },
      }),
    Error,
    "sudo.docker must equal docker",
  );
  assertThrows(
    () =>
      validateProvisionInput({
        ...withDocker(false),
        dockerProjects: INPUT.dockerProjects,
      }),
    Error,
    "must be empty when docker is false",
  );
  assertThrows(
    () =>
      validateProvisionInput(
        { ...INPUT, sudo: { osUpgrade: false, reboot: false } } as never,
      ),
    Error,
    "sudo must be { osUpgrade, osCheck, reboot, docker }",
  );
  for (
    const bad of [
      { name: "../x", composeDir: "/srv/x", service: "-" },
      { name: "app", composeDir: "/srv/a b", service: "-" },
      { name: "app", composeDir: "/srv/x", service: "-rf" },
    ]
  ) {
    assertThrows(() =>
      validateProvisionInput({ ...INPUT, dockerProjects: [bad] })
    );
  }
});
