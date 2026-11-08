/**
 * Tests for the plug-in privileges contract (plugin_privileges.ts): each rule of the parser is
 * accepted and refused, the provisioner's own check refuses what the parser refuses, and the
 * shell deny check agrees with the TS one. Nothing here touches a host.
 */
import {
  assert,
  assertEquals,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import {
  DENIED_BINS,
  deniedBin,
  deniedEnv,
  MAX_MACHINE_PLUGIN_COMMANDS,
  modelSlug,
  parsePluginPrivileges,
  parseRootArgv,
  pluginDeniedShellFn,
  validatePluginCommands,
} from "./plugin_privileges.ts";
import { sudoersLine, sudoersTemplate } from "./access_sudoers.ts";

const NONE = { commands: [], helpers: [], remoteCode: false };

function decl(commands: unknown[], extra: Record<string, unknown> = {}) {
  return { commands, helpers: [], remoteCode: false, ...extra };
}

function errorsOf(raw: unknown): string[] {
  const r = parsePluginPrivileges("app-updater", raw);
  return r.ok ? [] : r.errors;
}

function refused(raw: unknown, part: string, label = part): void {
  const errors = errorsOf(raw);
  assert(errors.length > 0, `${label}: expected a refusal`);
  assert(
    errors.some((e) => e.includes(part)),
    `${label}: no error mentions ${JSON.stringify(part)}: ${errors.join("; ")}`,
  );
}

Deno.test("parse: an API plug-in with no commands is accepted and grants nothing", () => {
  const r = parsePluginPrivileges("pve-snap", NONE);
  assertEquals(r, {
    ok: true,
    commands: [],
    remoteCode: false,
    remoteSources: [],
  });
});

Deno.test("parse: commands become PrivCommands with plugin ids, capability and family", () => {
  const r = parsePluginPrivileges(
    "My App_Updater",
    decl([
      { argv: ["myapp-update", "--yes"] },
      { argv: ["/opt/myapp/bin/reload"] },
      { argv: ["myapp-ctl", "sync"], env: { MYAPP_MODE: "batch" } },
    ]),
    3,
  );
  assert(r.ok);
  assertEquals(r.commands, [
    {
      id: "plugin-3-my-app-updater",
      capability: "plugin",
      family: "plugin",
      bin: "myapp-update",
      args: ["--yes"],
    },
    {
      id: "plugin-4-my-app-updater",
      capability: "plugin",
      family: "plugin",
      bin: "/opt/myapp/bin/reload",
      args: [],
    },
    {
      id: "plugin-5-my-app-updater",
      capability: "plugin",
      family: "plugin",
      bin: "myapp-ctl",
      args: ["sync"],
      env: { MYAPP_MODE: "batch" },
    },
  ]);
});

Deno.test('parse: the sudoers text of a plug-in command, with "" for no arguments and the env form', () => {
  const r = parsePluginPrivileges(
    "app",
    decl([
      { argv: ["/opt/myapp/bin/reload"] },
      { argv: ["myapp-ctl", "sync"], env: { MYAPP_MODE: "batch" } },
    ]),
  );
  assert(r.ok);
  assertEquals(sudoersTemplate(r.commands[0]), '@/opt/myapp/bin/reload@ ""');
  assertEquals(
    sudoersLine("swamp-patch", r.commands[0], {
      "/opt/myapp/bin/reload": "/opt/myapp/bin/reload",
    }),
    'swamp-patch ALL=(root) NOPASSWD: /opt/myapp/bin/reload ""',
  );
  assertEquals(
    sudoersLine("swamp-patch", r.commands[1], {
      env: "/usr/bin/env",
      "myapp-ctl": "/usr/local/bin/myapp-ctl",
    }),
    "swamp-patch ALL=(root) NOPASSWD: /usr/bin/env MYAPP_MODE\\=batch /usr/local/bin/myapp-ctl sync",
  );
});

Deno.test("parse: the shape is strict", () => {
  refused(null, "declaration", "null");
  refused("x", "declaration", "a string");
  refused({ helpers: [], remoteCode: false }, "commands", "no commands");
  refused({ commands: [], remoteCode: false }, "helpers", "no helpers");
  refused({ commands: [], helpers: [] }, "remoteCode", "no remoteCode");
  refused({ ...NONE, extra: 1 }, "extra", "an unknown key");
  refused(
    decl([{ argv: ["x"], sudo: true }]),
    "sudo",
    "an unknown command key",
  );
  refused({ ...NONE, remoteCode: "yes" }, "remoteCode", "a string remoteCode");
});

Deno.test("parse: at most 16 commands, and argv of 1 to 32 tokens", () => {
  const many = Array.from({ length: 17 }, () => ({ argv: ["myapp"] }));
  refused(decl(many), "at most 16 commands");
  assert(parsePluginPrivileges("a", decl(many.slice(0, 16))).ok);
  refused(decl([{ argv: [] }]), "argv needs at least the bin");
  const long = ["myapp", ...Array.from({ length: 32 }, (_, i) => `a${i}`)];
  refused(decl([{ argv: long }]), "at most 32 tokens");
  assert(parsePluginPrivileges("a", decl([{ argv: long.slice(0, 32) }])).ok);
});

Deno.test("parse: the bin is a bare name or a plain absolute path", () => {
  for (
    const bin of [
      "myapp",
      "my-app_2.1",
      "c++",
      "/usr/local/bin/myapp",
      "/opt/a.b/bin/x+y",
    ]
  ) {
    assert(parsePluginPrivileges("a", decl([{ argv: [bin] }])).ok, bin);
  }
  for (
    const bin of [
      "",
      "-rf",
      ".",
      "..",
      ".hidden",
      "a b",
      "a;id",
      "$(id)",
      "a*",
      "bin/x",
      "x".repeat(65),
      "/usr/bin/",
      "/usr/../bin/x",
      "/usr//bin/x",
      "/usr/./bin/x",
      "/usr/bin/.",
      "/usr/bin/x y",
      "/usr/bin/x'y",
    ]
  ) {
    refused(decl([{ argv: [bin] }]), "argv[0]", JSON.stringify(bin));
  }
});

Deno.test("parse: every denied basename is refused, by name and by path", () => {
  for (const bin of DENIED_BINS) {
    refused(decl([{ argv: [bin] }]), "may not run as root", bin);
    refused(decl([{ argv: [`/usr/bin/${bin}`] }]), "may not run as root", bin);
  }
  for (const bin of ["python3.12", "perl5.36", "node20", "/usr/bin/ruby3.1"]) {
    refused(decl([{ argv: [bin] }]), "may not run as root", bin);
  }
  assert(!deniedBin("pythonic"));
  assert(!deniedBin("/usr/bin/apt-get"));
});

Deno.test("parse: arguments follow the table token rule", () => {
  assert(
    parsePluginPrivileges(
      "a",
      decl([{ argv: ["myapp", "-y", "--mode=fast", "a:b", "x/y", "1.2+3"] }]),
    ).ok,
  );
  for (
    const arg of [
      "",
      "a b",
      "*",
      "a?",
      "[x]",
      "!x",
      "a'b",
      'a"b',
      "#x",
      "a\nb",
      "$(id)",
      "a;b",
      "a\\b",
      "~",
    ]
  ) {
    refused(decl([{ argv: ["myapp", arg] }]), "argv[1]", JSON.stringify(arg));
  }
  refused(decl([{ argv: ["myapp", 3] }]), "argv[1]", "a number");
});

Deno.test("parse: env names, values and count", () => {
  assert(
    parsePluginPrivileges(
      "a",
      decl([{ argv: ["myapp"], env: { MYAPP_X: "1", LANG: "C.UTF-8" } }]),
    ).ok,
  );
  for (const name of ["lower", "1X", "A-B", "A B", "", "X".repeat(65)]) {
    refused(
      decl([{ argv: ["myapp"], env: { [name]: "1" } }]),
      "env",
      JSON.stringify(name),
    );
  }
  for (
    const name of [
      "LD_PRELOAD",
      "LD_LIBRARY_PATH",
      "DYLD_INSERT_LIBRARIES",
      "BASH_ENV",
      "PYTHONPATH",
      "PERL5OPT",
      "RUBYOPT",
      "NODE_OPTIONS",
      "GIT_SSH_COMMAND",
      "PATH",
      "IFS",
      "ENV",
      "SHELLOPTS",
      "PS4",
      "HOME",
      "TMPDIR",
      "SUDO_ASKPASS",
      "EDITOR",
      "VISUAL",
      "PAGER",
    ]
  ) {
    assert(deniedEnv(name), name);
    refused(
      decl([{ argv: ["myapp"], env: { [name]: "1" } }]),
      "may not be set",
      name,
    );
  }
  for (const value of ["", "a b", "$(id)", "a;b", "*"]) {
    refused(
      decl([{ argv: ["myapp"], env: { MYAPP: value } }]),
      "env.MYAPP",
      JSON.stringify(value),
    );
  }
  const nine = Object.fromEntries(
    Array.from({ length: 9 }, (_, i) => [`V${i}`, "1"]),
  );
  refused(decl([{ argv: ["myapp"], env: nine }]), "at most 8 env pairs");
});

Deno.test("parse: helpers must be empty in this release", () => {
  refused(
    { ...NONE, helpers: [{ path: "/usr/local/libexec/x" }] },
    "plug-in helpers are not supported in this release",
  );
});

Deno.test("parse: remoteCode needs remoteSources as owner/repo@ref, and only then", () => {
  const r = parsePluginPrivileges("a", {
    ...NONE,
    remoteCode: true,
    remoteSources: ["acme/updater@v1.2.3", "acme/core@main"],
  });
  assertEquals(r, {
    ok: true,
    commands: [],
    remoteCode: true,
    remoteSources: ["acme/updater@v1.2.3", "acme/core@main"],
  });
  refused({ ...NONE, remoteCode: true }, "remoteSources is required");
  refused(
    { ...NONE, remoteCode: true, remoteSources: [] },
    "at least one source",
  );
  refused(
    { ...NONE, remoteCode: true, remoteSources: ["https://x.example/a"] },
    "remoteSources[0]",
  );
  refused(
    {
      ...NONE,
      remoteCode: true,
      remoteSources: ["acme/a@v1", "acme/a@v1"],
    },
    "names a source twice",
  );
  refused(
    {
      ...NONE,
      remoteCode: true,
      remoteSources: ["a/a@1", "a/b@1", "a/c@1", "a/d@1", "a/e@1"],
    },
    "at most 4 remoteSources",
  );
  refused(
    { ...NONE, remoteSources: ["acme/updater@v1"] },
    "only for remoteCode: true",
  );
  // The single-source key of the first draft is an unknown key now.
  refused(
    { ...NONE, remoteCode: true, remoteSource: "acme/updater@v1" },
    "remoteSource",
  );
});

Deno.test("parse: errors name the model and the place", () => {
  const r = parsePluginPrivileges("pve-snap", decl([{ argv: ["bash"] }]));
  assert(!r.ok);
  assertStringIncludes(
    r.errors[0],
    'privileges of "pve-snap": commands[0].argv[0]',
  );
});

Deno.test("modelSlug: lowercase, dashes, at most 40, never empty", () => {
  assertEquals(modelSlug("My App_Updater"), "my-app-updater");
  assertEquals(modelSlug("--x--"), "x");
  assertEquals(modelSlug("é"), "model");
  assertEquals(modelSlug("a".repeat(50)).length, 40);
  assertEquals(modelSlug(`${"a".repeat(39)}-b`), "a".repeat(39));
});

Deno.test("validatePluginCommands: accepts what the parser gives, and copies it", () => {
  const r = parsePluginPrivileges(
    "app",
    decl([{ argv: ["myapp", "x"], env: { MYAPP: "1" } }, { argv: ["/opt/b"] }]),
  );
  assert(r.ok);
  const v = validatePluginCommands(r.commands);
  assertEquals(v, r.commands);
  assert(v[0] !== r.commands[0]);
  assertEquals(validatePluginCommands([]), []);
});

Deno.test("validatePluginCommands: refuses what the parser would refuse, and bad records", () => {
  const good = {
    id: "plugin-1-app",
    capability: "plugin",
    family: "plugin",
    bin: "myapp",
    args: [],
  };
  assertThrows(() => validatePluginCommands("x"), Error, "must be a list");
  const bad: Array<[string, unknown]> = [
    ["a denied bin", { ...good, bin: "bash" }],
    ["a denied bin by path", { ...good, bin: "/bin/sh" }],
    ["a glob argument", { ...good, args: ["*"] }],
    ["a bad env name", { ...good, env: { LD_PRELOAD: "/x" } }],
    ["a table capability", { ...good, capability: "osUpgrade" }],
    ["a table family", { ...good, family: "apt" }],
    ["a bad id", { ...good, id: "apt-upgrade" }],
    ["an id with a space", { ...good, id: "plugin-1-a b" }],
    ["an unknown key", { ...good, extra: 1 }],
    ["a relative path", { ...good, bin: "bin/x" }],
  ];
  for (const [label, rec] of bad) {
    assertThrows(() => validatePluginCommands([rec]), Error, undefined, label);
  }
  assertThrows(
    () => validatePluginCommands([good, good]),
    Error,
    "listed twice",
  );
  const many = Array.from(
    { length: MAX_MACHINE_PLUGIN_COMMANDS + 1 },
    (_, i) => ({ ...good, id: `plugin-${i + 1}-app` }),
  );
  assertThrows(() => validatePluginCommands(many), Error, "per machine");
  assertEquals(validatePluginCommands(many.slice(1)).length, 64);
});

Deno.test("pluginDeniedShellFn: the shell check agrees with deniedBin", async () => {
  const names = [
    ...DENIED_BINS,
    "python3.12",
    "/usr/bin/vim.basic",
    "/etc/alternatives/editor",
    "myapp",
    "/usr/bin/apt-get",
    "pythonic",
    "shx",
  ];
  const script = `${pluginDeniedShellFn()}
for n in "$@"; do if plugin_denied "$n"; then echo "1 $n"; else echo "0 $n"; fi; done
`;
  const out = await new Deno.Command("bash", {
    args: ["-c", script, "bash", ...names],
    stdout: "piped",
  }).output();
  assert(out.success);
  const lines = new TextDecoder().decode(out.stdout).trim().split("\n");
  assertEquals(
    lines,
    names.map((n) => `${deniedBin(n) ? 1 : 0} ${n}`),
  );
});

Deno.test("parse: arguments and env values may not name a path others can write, or ..", () => {
  for (
    const arg of [
      "/tmp/x.deb",
      "/var/tmp/x",
      "/dev/shm/x",
      "/home/swamp-patch/x",
      "/run/user/1000/x",
      "--file=/tmp/x",
      "a:/tmp/x",
      "../x",
      "/opt/../tmp/x",
      "/tmp",
    ]
  ) {
    refused(decl([{ argv: ["myapp", arg] }]), "may not name a path", arg);
    refused(
      decl([{ argv: ["myapp"], env: { MYAPP: arg } }]),
      "may not name a path",
      `env ${arg}`,
    );
  }
  for (const arg of ["/opt/app/x.conf", "/tmpfoo", "/etc/home/x", "a.b"]) {
    assert(
      parsePluginPrivileges("a", decl([{ argv: ["myapp", arg] }])).ok,
      arg,
    );
  }
});

/** The error of a root argv that parseRootArgv refuses; the test fails when it is accepted. */
function rootError(argv: unknown): string {
  const r = parseRootArgv("plugin-1-health", argv);
  assertEquals(r.ok, false, JSON.stringify(argv));
  return r.ok ? "" : r.error;
}

Deno.test("parseRootArgv: a good absolute argv is a plug-in command, with no env", () => {
  assertEquals(
    parseRootArgv("plugin-1-health", [
      "/usr/local/bin/myhealth",
      "--quiet",
      "--max-age=60",
    ]),
    {
      ok: true,
      command: {
        id: "plugin-1-health",
        capability: "plugin",
        family: "plugin",
        bin: "/usr/local/bin/myhealth",
        args: ["--quiet", "--max-age=60"],
      },
    },
  );
});

Deno.test("parseRootArgv: a bare bin is accepted, with no arguments", () => {
  assertEquals(parseRootArgv("plugin-2-health", ["myhealth"]), {
    ok: true,
    command: {
      id: "plugin-2-health",
      capability: "plugin",
      family: "plugin",
      bin: "myhealth",
      args: [],
    },
  });
});

Deno.test("parseRootArgv: a denied bin is refused, by name and by path", () => {
  for (const argv of [["bash"], ["/usr/bin/python3"]]) {
    const err = rootError(argv);
    assertStringIncludes(err, "argv[0]");
    assertStringIncludes(err, "may not run as root");
  }
});

Deno.test("parseRootArgv: an argument with a space or ; is refused", () => {
  for (const arg of ["a b", "a;id"]) {
    assertStringIncludes(rootError(["myhealth", arg]), "argv[1]");
  }
});

Deno.test("parseRootArgv: an argument under /tmp is refused", () => {
  assertStringIncludes(
    rootError(["myhealth", "/tmp/check.conf"]),
    "may not name a path",
  );
});

Deno.test("parseRootArgv: an empty argv is refused", () => {
  assertStringIncludes(rootError([]), "argv needs at least the bin");
});

Deno.test("parseRootArgv: an id that is not plugin-<n>-<slug> throws", () => {
  assertThrows(
    () => parseRootArgv("apt-upgrade", ["myhealth"]),
    Error,
    "not a plug-in command id: apt-upgrade",
  );
});

Deno.test("parseRootArgv and parsePluginPrivileges: a bin in a directory other accounts can write is refused", () => {
  for (
    const bin of [
      "/tmp/check",
      "/home/dmc/bin/check",
      "/var/tmp/x",
      "/dev/shm/x",
    ]
  ) {
    assertStringIncludes(
      rootError([bin]),
      "argv[0]: the bin may not name a path",
    );
    const p = parsePluginPrivileges("m", {
      commands: [{ argv: [bin] }],
      helpers: [],
      remoteCode: false,
    });
    assertEquals(p.ok, false, bin);
  }
  // A root-owned system path is still a valid bin.
  assertEquals(parseRootArgv("plugin-1-health", ["/usr/sbin/check"]).ok, true);
});
