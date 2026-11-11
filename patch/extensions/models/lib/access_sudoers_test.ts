/**
 * Contract tests for the privileged command table (access_sudoers.ts), the sudoers text built
 * from it, and the sudo section of the provision script. The scripts are checked as text and
 * with bash -n. Nothing here runs a privileged command or touches a host.
 */
import {
  assert,
  assertEquals,
  assertMatch,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import {
  FAMILY_PROBES,
  grantNames,
  PRIV_COMMANDS,
  privCommand,
  requiredCommands,
  runtimeCommand,
  runtimeResolveLines,
  shellPaths,
  shellVar,
  sudoersEscape,
  sudoersLine,
  sudoersTemplate,
} from "./access_sudoers.ts";
import { provisionScript, validateProvisionInput } from "./access_artifacts.ts";
import type { ProvisionInput } from "./access_artifacts.ts";
import type { PrivCommand } from "./access_sudoers.ts";

const KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBjngojWT4QUfy2bl78lWkaepNtOZYDlAzZbel8QNoWN swamp-serve";
const USER = "patchq-test";
const MANAGED: ProvisionInput = {
  user: USER,
  publicKey: KEY,
  from: ["192.0.2.131"],
  docker: false,
  autoUpdates: null,
  sudo: { osUpgrade: true, osCheck: true, reboot: true, docker: false },
  dockerProjects: [],
};
const PATHS = {
  env: "/usr/bin/env",
  "apt-get": "/usr/bin/apt-get",
  "systemd-run": "/usr/bin/systemd-run",
};

function occurrences(text: string, value: string): number {
  return text.split(value).length - 1;
}

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

/** The ids of the table, in order. The table is the one list of privileged commands. */
const TABLE_IDS = [
  "apt-update",
  "apt-upgrade",
  "apt-full-upgrade",
  "dnf-upgrade",
  "dnf-check",
  "dnf-check-security",
  "apk-upgrade",
  "pacman-upgrade",
  "reboot",
];

Deno.test("table: the entries, their ids and their capabilities", () => {
  assertEquals(PRIV_COMMANDS.map((c) => c.id), TABLE_IDS);
  for (const c of PRIV_COMMANDS) {
    assertEquals(
      c.capability,
      c.id === "reboot"
        ? "reboot"
        : c.id.startsWith("dnf-check")
        ? "osCheck"
        : "osUpgrade",
      c.id,
    );
  }
});

Deno.test("table: every bin, argument and env pair matches the token rule", () => {
  for (const c of PRIV_COMMANDS) {
    assertMatch(c.bin, /^[a-z][a-z0-9-]*$/, c.id);
    const tokens = [
      ...c.args,
      ...Object.entries(c.env ?? {}).map(([k, v]) => `${k}=${v}`),
    ];
    for (const t of tokens) assertMatch(t, /^[A-Za-z0-9._/:=+-]+$/, c.id);
  }
});

Deno.test("table: the exact argv of each entry", () => {
  const argv = (id: string) =>
    runtimeCommand(privCommand(id), shellPaths(privCommand(id))).join(" ");
  assertEquals(argv("apt-update"), '"$BIN_APT_GET" update -qq');
  assertEquals(
    argv("apt-upgrade"),
    '"$BIN_ENV" DEBIAN_FRONTEND=noninteractive "$BIN_APT_GET" -y upgrade',
  );
  assertEquals(
    argv("apt-full-upgrade"),
    '"$BIN_ENV" DEBIAN_FRONTEND=noninteractive "$BIN_APT_GET" -y full-upgrade',
  );
  assertEquals(argv("dnf-upgrade"), '"$BIN_DNF" -y upgrade');
  assertEquals(argv("dnf-check"), '"$BIN_DNF" -q -C check-update');
  assertEquals(
    argv("dnf-check-security"),
    '"$BIN_DNF" -q -C check-update --security',
  );
  assertEquals(argv("apk-upgrade"), '"$BIN_APK" upgrade');
  assertEquals(argv("pacman-upgrade"), '"$BIN_PACMAN" -Syu --noconfirm');
  assertEquals(
    argv("reboot"),
    '"$BIN_SYSTEMD_RUN" --on-active=3 --timer-property=AccuracySec=100ms systemctl reboot',
  );
});

Deno.test("sudoersEscape: escapes = : , \\ and space", () => {
  assertEquals(
    sudoersEscape("DEBIAN_FRONTEND=noninteractive"),
    "DEBIAN_FRONTEND\\=noninteractive",
  );
  assertEquals(sudoersEscape("a:b,c\\d e"), "a\\:b\\,c\\\\d\\ e");
  assertEquals(sudoersEscape("-y"), "-y");
  assertEquals(sudoersEscape("/usr/bin/x.y+z_1"), "/usr/bin/x.y+z_1");
});

Deno.test("sudoersEscape: throws on every character a sudoers entry must not carry", () => {
  for (
    const ch of [
      "*",
      "?",
      "[",
      "]",
      "!",
      '"',
      "'",
      "#",
      "\n",
      "\t",
      "$",
      ";",
      "&",
      "|",
      "(",
      ")",
      "`",
      "{",
      "}",
      "<",
      ">",
      "~",
      "%",
      "@",
    ]
  ) {
    assertThrows(
      () => sudoersEscape(`a${ch}b`),
      Error,
      "sudoers",
      `char ${JSON.stringify(ch)}`,
    );
  }
  assertThrows(() => sudoersEscape(""));
});

Deno.test("sudoersLine: exact lines for the env entry, a plain entry and the reboot entry", () => {
  assertEquals(
    sudoersLine("swamp-patch", privCommand("apt-upgrade"), PATHS),
    "swamp-patch ALL=(root) NOPASSWD: /usr/bin/env DEBIAN_FRONTEND\\=noninteractive /usr/bin/apt-get -y upgrade",
  );
  assertEquals(
    sudoersLine("swamp-patch", privCommand("apt-update"), PATHS),
    "swamp-patch ALL=(root) NOPASSWD: /usr/bin/apt-get update -qq",
  );
  assertEquals(
    sudoersLine("swamp-patch", privCommand("reboot"), PATHS),
    "swamp-patch ALL=(root) NOPASSWD: /usr/bin/systemd-run --on-active\\=3 --timer-property\\=AccuracySec\\=100ms systemctl reboot",
  );
});

Deno.test("sudoersLine: refuses a relative, globbed or spaced path, a missing path, and a bad user", () => {
  const cmd = privCommand("apt-update");
  for (
    const p of ["apt-get", "/usr/bin/*", "/usr/bin/apt get", "/usr/bin/a'b", ""]
  ) {
    assertThrows(() => sudoersLine("swamp-patch", cmd, { "apt-get": p }));
  }
  assertThrows(() => sudoersLine("swamp-patch", cmd, {}));
  assertThrows(() =>
    sudoersLine("swamp-patch", privCommand("apt-upgrade"), {
      "apt-get": "/usr/bin/apt-get",
    })
  );
  for (const u of ["", "Root", "a b", "x'y", "$(id)", "a,b", "a*"]) {
    assertThrows(
      () => sudoersLine(u, cmd, PATHS),
      Error,
      "login name",
      JSON.stringify(u),
    );
  }
});

Deno.test("sudoersTemplate: the placeholders the provision script fills in, with the escaped words", () => {
  assertEquals(
    sudoersTemplate(privCommand("apt-upgrade")),
    "@env@ DEBIAN_FRONTEND\\=noninteractive @apt-get@ -y upgrade",
  );
  assertEquals(
    sudoersTemplate(privCommand("reboot")),
    "@systemd-run@ --on-active\\=3 --timer-property\\=AccuracySec\\=100ms systemctl reboot",
  );
});

Deno.test('sudoers words: a command with no arguments ends in "", an env command with none does not', () => {
  // sudo reads a command with no arguments as "any arguments"; "" means exactly none.
  const bare: PrivCommand = {
    id: "zero",
    capability: "reboot",
    family: "systemd",
    bin: "systemctl",
    args: [],
  };
  assertEquals(sudoersTemplate(bare), '@systemctl@ ""');
  assertEquals(
    sudoersLine("swamp-patch", bare, { systemctl: "/usr/bin/systemctl" }),
    'swamp-patch ALL=(root) NOPASSWD: /usr/bin/systemctl ""',
  );
  // The runtime runs the bin alone: "" is sudoers syntax, not an argument.
  assertEquals(runtimeCommand(bare, { systemctl: "/usr/bin/systemctl" }), [
    "/usr/bin/systemctl",
  ]);
  // Behind env the bin itself is an argument, so sudo already matches exactly.
  const withEnv: PrivCommand = { ...bare, env: { LANG: "C" } };
  assertEquals(sudoersTemplate(withEnv), "@env@ LANG\\=C @systemctl@");
  // No table entry has zero arguments today; each table line keeps its exact words.
  for (const c of PRIV_COMMANDS) {
    assert(!sudoersTemplate(c).endsWith('""'), c.id);
  }
});

Deno.test("runtimeCommand: the exact words with the paths filled in, and an error for a missing path", () => {
  assertEquals(
    runtimeCommand(privCommand("apt-upgrade"), PATHS),
    [
      "/usr/bin/env",
      "DEBIAN_FRONTEND=noninteractive",
      "/usr/bin/apt-get",
      "-y",
      "upgrade",
    ],
  );
  assertEquals(
    runtimeCommand(privCommand("apt-update"), PATHS),
    ["/usr/bin/apt-get", "update", "-qq"],
  );
  assertThrows(() =>
    runtimeCommand(privCommand("apt-upgrade"), {
      "apt-get": "/usr/bin/apt-get",
    })
  );
});

Deno.test("shell names: the variable of a binary, and its quoted path in the runtime", () => {
  assertEquals(shellVar("apt-get"), "BIN_APT_GET");
  assertEquals(shellVar("systemd-run"), "BIN_SYSTEMD_RUN");
  assertEquals(shellVar("env"), "BIN_ENV");
  assertEquals(shellPaths(privCommand("apt-upgrade")), {
    env: '"$BIN_ENV"',
    "apt-get": '"$BIN_APT_GET"',
  });
  assertEquals(shellPaths(privCommand("apt-update")), {
    "apt-get": '"$BIN_APT_GET"',
  });
});

Deno.test("runtimeResolveLines: each binary of a command resolves to its absolute path, or exits 3", () => {
  assertEquals(runtimeResolveLines([privCommand("apt-upgrade")]), [
    'BIN_ENV="$(abs_cmd env)" || exit 3',
    'BIN_APT_GET="$(abs_cmd apt-get)" || exit 3',
  ]);
});

Deno.test("grantNames: the paths a grant needs, and the family's probes", () => {
  assertEquals(grantNames(privCommand("apt-update")), ["apt-get"]);
  assertEquals(grantNames(privCommand("apt-upgrade")), ["env", "apt-get"]);
  assertEquals(grantNames(privCommand("reboot")), ["systemd-run", "systemctl"]);
  assertEquals(FAMILY_PROBES.apt, ["apt-get"]);
  assertEquals(FAMILY_PROBES.systemd, ["systemd-run", "systemctl"]);
});

Deno.test("requiredCommands: the managed, auto and scan-only matrix", () => {
  const ids = (
    caps: { osUpgrade: boolean; osCheck: boolean; reboot: boolean },
  ) => requiredCommands(caps).map((c) => c.id);
  const checks = ["dnf-check", "dnf-check-security"];
  assertEquals(
    ids({ osUpgrade: true, osCheck: true, reboot: true }),
    TABLE_IDS,
  );
  assertEquals(
    ids({ osUpgrade: true, osCheck: false, reboot: true }),
    TABLE_IDS.filter((id) => !checks.includes(id)),
  );
  assertEquals(ids({ osUpgrade: false, osCheck: true, reboot: true }), [
    ...checks,
    "reboot",
  ]);
  assertEquals(ids({ osUpgrade: false, osCheck: false, reboot: true }), [
    "reboot",
  ]);
  assertEquals(ids({ osUpgrade: false, osCheck: false, reboot: false }), []);
  assertEquals(
    ids({ osUpgrade: true, osCheck: false, reboot: false }).length,
    6,
  );
});

Deno.test("validateProvisionInput: sudo must hold two booleans, and is copied", () => {
  const v = validateProvisionInput(MANAGED);
  assertEquals(v.sudo, {
    osUpgrade: true,
    osCheck: true,
    reboot: true,
    docker: false,
    extra: [],
  });
  assert(v.sudo !== MANAGED.sudo);
  for (
    const sudo of [
      undefined,
      null,
      { osUpgrade: true },
      { osUpgrade: "yes", reboot: true },
      { osUpgrade: true, reboot: 1 },
      // The old shape, without osCheck, is refused: it never grants nothing silently.
      { osUpgrade: true, reboot: true, docker: false },
      { osUpgrade: true, osCheck: "yes", reboot: true, docker: false },
    ]
  ) {
    assertThrows(
      () => validateProvisionInput({ ...MANAGED, sudo } as never),
      Error,
      "sudo must be",
    );
  }
});

Deno.test("validateProvisionInput: osCheck alone is refused, because it would make the host need sudo", () => {
  assertThrows(
    () =>
      validateProvisionInput({
        ...MANAGED,
        sudo: { osUpgrade: false, osCheck: true, reboot: false, docker: false },
      }),
    Error,
    "sudo.osCheck needs another grant",
  );
  // With any other grant it is accepted: the docker helper here.
  const v = validateProvisionInput({
    ...MANAGED,
    docker: true,
    sudo: { osUpgrade: false, osCheck: true, reboot: false, docker: true },
    dockerProjects: [{ name: "app", composeDir: "/srv/app", service: "-" }],
  });
  assertEquals(v.sudo.osCheck, true);
});

// ---- the provision script's sudo section ----

Deno.test("provisionScript sudo: the pre-flight refuses with exit 5 before the first state change", () => {
  const s = provisionScript(MANAGED);
  const block = [
    "if ! command -v sudo >/dev/null 2>&1 || ! command -v visudo >/dev/null 2>&1; then",
    '  echo "sudo is not installed: install it first (this script never installs packages)" >&2',
    "  exit 5",
    "fi",
  ].join("\n");
  assertStringIncludes(s, block);
  assertStringIncludes(
    s,
    'if [ -e "$SUDOERS" ] && ! is_managed "$SUDOERS"; then',
  );
  const preflight = s.indexOf('echo "== preflight"');
  const account = s.indexOf('echo "== account"');
  const at = s.indexOf(block);
  assert(
    preflight < at && at < account,
    "the sudo pre-flight is in the preflight",
  );
  for (
    const change of [
      "useradd",
      "addgroup",
      "chpasswd -e",
      'install_file "$HOME_DIR',
      'mkdir -p "$STATE_DIR"',
    ]
  ) {
    const i = s.indexOf(change);
    assert(
      i < 0 || i > at,
      `a state change (${change}) comes before the pre-flight`,
    );
  }
});

Deno.test("provisionScript sudo: the file is built in a dotted temp name, checked by visudo -cf before the move", () => {
  const s = provisionScript(MANAGED);
  assertStringIncludes(
    s,
    'tmp="$(mktemp "${SUDOERS%/*}/.swamp-patch.XXXXXX")"',
  );
  assertStringIncludes(s, 'chmod 0440 "$tmp"');
  const check = s.indexOf('visudo -cf "$tmp"');
  const move = s.indexOf('mv -f "$tmp" "$SUDOERS"');
  assert(check > 0 && move > check, "visudo -cf runs before the mv");
  const whole = s.indexOf("visudo -c >/dev/null");
  assert(whole > move, "the whole configuration is checked after the move");
  assertStringIncludes(
    s,
    'rm -f "$SUDOERS"\n    echo "the sudo configuration does not parse',
  );
  assertStringIncludes(s, "exit 6");
  const includes = s.indexOf("includedir");
  assert(includes > whole, "the includedir check comes after the whole check");
  assertStringIncludes(s, "/etc/sudoers\\.d[[:space:]]*$' /etc/sudoers");
});

Deno.test("provisionScript sudo: the file header and the Defaults lines use the login name only through its variable", () => {
  const s = provisionScript(MANAGED);
  assertStringIncludes(s, "printf 'Defaults:%s env_reset\\n' \"$PATCH_USER\"");
  assertStringIncludes(s, "printf 'Defaults:%s !setenv\\n' \"$PATCH_USER\"");
  assertStringIncludes(s, "printf '%s\\n' \"$MANAGED\"");
  assertStringIncludes(
    s,
    'printf -v line \'%s ALL=(root) NOPASSWD: %s\\n\' "$PATCH_USER" "$text"',
  );
});

Deno.test("provisionScript sudo: every granted line is a table entry, named by its escaped template", () => {
  const s = provisionScript(MANAGED);
  const grants = [...s.matchAll(/^ {2}sudo_grant (\S+) '([^']*)' (.+)$/gm)];
  assertEquals(grants.map((g) => g[1]), TABLE_IDS);
  for (const g of grants) {
    const cmd = privCommand(g[1]);
    assertEquals(g[2], sudoersTemplate(cmd), g[1]);
    assertEquals(g[3].split(" "), grantNames(cmd), g[1]);
  }
});

Deno.test("provisionScript sudo: a managed login gets the apt entries and the reboot entry, and the user only at the top", () => {
  const s = provisionScript(MANAGED);
  const top = s.slice(0, s.indexOf("\nset -"));
  assertEquals(occurrences(top, USER), 1);
  assertEquals(
    occurrences(s, USER),
    1,
    "the user name is used only through $PATCH_USER",
  );
  assertStringIncludes(s, "if command -v apt-get >/dev/null 2>&1; then");
  assertStringIncludes(s, "if command -v dnf >/dev/null 2>&1; then");
  assertStringIncludes(
    s,
    "if command -v systemd-run >/dev/null 2>&1 || command -v systemctl >/dev/null 2>&1; then",
  );
  assert(!s.includes("NOPASSWD: ALL"));
  assert(
    !/NOPASSWD: (apt-get|dnf|apk|pacman|systemd-run|env)\b/.test(s),
    "no bare name is granted",
  );
});

Deno.test("provisionScript sudo: an auto login grants the reboot and the dnf check entries", () => {
  const s = provisionScript({
    ...MANAGED,
    autoUpdates: "security",
    sudo: { osUpgrade: false, osCheck: true, reboot: true, docker: false },
  });
  const ids = [...s.matchAll(/^ {2}sudo_grant (\S+) /gm)].map((g) => g[1]);
  assertEquals(ids, ["dnf-check", "dnf-check-security", "reboot"]);
  assertStringIncludes(s, 'if [ -n "$sudo_lines" ]; then');
});

Deno.test("provisionScript sudo: a scan-only login removes the managed file and has no sudo pre-flight", () => {
  const s = provisionScript({
    ...MANAGED,
    sudo: { osUpgrade: false, osCheck: false, reboot: false, docker: false },
  });
  assertStringIncludes(s, 'echo "== sudo"');
  assertStringIncludes(s, 'remove_managed "$SUDOERS"');
  assert(!s.includes("NOPASSWD"));
  assert(!s.includes("visudo -cf"));
  assert(!s.includes("sudo is not installed"));
  assert(!s.includes("sudo_grant apt"));
});

Deno.test("provisionScript sudo: the result line names the granted and the missing entries", () => {
  const s = provisionScript(MANAGED);
  assertStringIncludes(
    s,
    '"autoUpdates":%s,"sudoEntries":[%s],"sudoMissing":[%s]}\\n\' "$PATCH_USER" "$created" "$groups_removed" "$cache_refresh" "$docker_on" "$auto_json" "$sudo_granted" "$sudo_missing"',
  );
});

Deno.test("provisionScript sudo: the managed, auto and scan-only scripts pass bash -n", async () => {
  await assertBashSyntax(provisionScript(MANAGED));
  await assertBashSyntax(provisionScript({
    ...MANAGED,
    autoUpdates: "all",
    sudo: { osUpgrade: false, osCheck: true, reboot: true, docker: false },
  }));
  await assertBashSyntax(provisionScript({
    ...MANAGED,
    sudo: { osUpgrade: false, osCheck: false, reboot: false, docker: false },
  }));
});

// ---- plug-in commands (plugin_privileges.ts) in the sudo section ----

const PLUGIN_EXTRA: PrivCommand[] = [
  {
    id: "plugin-1-app",
    capability: "plugin",
    family: "plugin",
    bin: "/opt/myapp/bin/reload",
    args: [],
  },
  {
    id: "plugin-2-app",
    capability: "plugin",
    family: "plugin",
    bin: "myapp-ctl",
    args: ["sync"],
    env: { MYAPP_MODE: "batch" },
  },
];

Deno.test("provisionScript sudo: a scan-only login with plug-in commands gets the pre-flight and the plug-in grants", async () => {
  const s = provisionScript({
    ...MANAGED,
    sudo: {
      osUpgrade: false,
      osCheck: false,
      reboot: false,
      docker: false,
      extra: PLUGIN_EXTRA,
    },
  });
  assertStringIncludes(s, "sudo is not installed");
  assertStringIncludes(s, "plugin_denied() {");
  assertStringIncludes(
    s,
    `plugin_grant plugin-1-app '@/opt/myapp/bin/reload@ ""' '/opt/myapp/bin/reload' '/opt/myapp/bin/reload'`,
  );
  assertStringIncludes(
    s,
    `plugin_grant plugin-2-app '@env@ MYAPP_MODE\\=batch @myapp-ctl@ sync' 'myapp-ctl' 'env' 'myapp-ctl'`,
  );
  assert(!s.includes("sudo_grant apt"));
  assert(
    s.indexOf("sudo is not installed") < s.indexOf('echo "== account"'),
    "the pre-flight comes before the first change",
  );
  await assertBashSyntax(s);
});

Deno.test("provisionScript sudo: no plug-in commands, no plug-in helpers in the script", () => {
  assert(!provisionScript(MANAGED).includes("plugin_denied"));
});

Deno.test("validateProvisionInput: plug-in commands are checked again, and copied", () => {
  const v = validateProvisionInput({
    ...MANAGED,
    sudo: { ...MANAGED.sudo, extra: PLUGIN_EXTRA },
  });
  assertEquals(v.sudo.extra, PLUGIN_EXTRA);
  assert(v.sudo.extra !== PLUGIN_EXTRA);
  for (
    const bad of [
      { ...PLUGIN_EXTRA[0], bin: "bash" },
      { ...PLUGIN_EXTRA[0], args: ["a b"] },
      { ...PLUGIN_EXTRA[0], capability: "osUpgrade" },
      { ...PLUGIN_EXTRA[1], env: { LD_PRELOAD: "/tmp/x.so" } },
    ]
  ) {
    assertThrows(() =>
      provisionScript({
        ...MANAGED,
        sudo: { ...MANAGED.sudo, extra: [bad as PrivCommand] },
      })
    );
  }
});
