import {
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import {
  createModelTestContext,
  withMockedCommand,
  withMockedFetch,
} from "jsr:@systeminit/swamp-testing@0.20260604.20";
import { cmpSemver, extractSemver, model } from "./proxmox_community_script.ts";

const CT_SCRIPT = [
  "APP=TestApp",
  'var_cpu="${var_cpu:-2}"',
  'var_ram="${var_ram:-2048}"',
  'var_disk="${var_disk:-10}"',
  'var_os="debian"',
  'var_version="13"',
].join("\n");
const BUILD_FUNC = [
  "recognized: var_cpu var_ram var_disk var_os var_version var_hostname var_ctid var_brg var_nesting",
  "# Container type",
  "var_unprivileged=1",
  "# Resources",
  "var_cpu=1",
  "var_ram=1024",
  "# Advanced Settings",
  "var_nesting=1          # Allow nesting (required for Docker/LXC in CT)",
  "EOF",
].join("\n");
const INSTALL_SCRIPT = [
  "#!/usr/bin/env bash",
  'msg_info "Installing Dependencies"',
  "$STD apt-get install -y curl git postgresql",
  'msg_ok "Installed Dependencies"',
  'msg_info "Installing TestApp"',
  'fetch_and_deploy_gh_release "testapp" "owner/testapp" "prebuild" "latest" "/opt/testapp"',
  'msg_info "Creating Service"',
  "systemctl enable -q --now testapp",
].join("\n");

// The generic test context types globalArgs as Record<string, unknown>; the
// model's execute signatures want the concrete shape. Cast through this alias
// (the context param type is identical across methods).
type Ctx = Parameters<typeof model.methods.checkUpdate.execute>[1];
const asCtx = (c: unknown): Ctx => c as unknown as Ctx;

const baseArgs = {
  sshModel: "my-ssh",
  node: "pve1",
  ctid: 601,
  appName: "TestApp",
  service: "testapp",
  updateCommand: "PHS_SILENT=1 /usr/bin/update",
  versionRegex: "(\\d+\\.\\d+\\.\\d+)",
  // createModelTestContext does not apply Zod defaults, so set the ones the
  // exercised methods read (real swamp fills these from the schema).
  ctScriptBaseUrl:
    "https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main",
  installVars: {},
  installTimeoutSec: 1800,
  healthExpectStatus: 200,
  updateTimeoutSec: 900,
  // Zero timeout so waitForHealth resolves after a single probe (no polling delay).
  healthTimeoutSec: 0,
  pollIntervalSec: 1,
};

/** Build the JSON that `@swamp/ssh exec` prints, embedding remote output + rc. */
function sshOut(out: string, rc = 0): { stdout: string; code: number } {
  return {
    stdout: JSON.stringify({
      dataArtifacts: [{
        attributes: {
          stdout: `${out}\n__SWAMP_RC__=${rc}\n`,
          stderr: "",
          exitCode: rc,
        },
      }],
    }),
    code: 0,
  };
}

/** Extract the `command=` value from a mocked `swamp ... exec` argv. */
function remoteCommand(args: string[]): string {
  const entry = args.find((a) => a.startsWith("command="));
  return entry ? entry.slice("command=".length) : args.join(" ");
}

// ---- Pure helpers -----------------------------------------------------------

Deno.test("extractSemver pulls the first X.Y.Z from noisy version output", () => {
  assertEquals(
    extractSemver(
      "forgejo version 16.0.4+gitea-1.22.0 built with go1.26.8",
      "(\\d+\\.\\d+\\.\\d+)",
    ),
    "16.0.4",
  );
  assertEquals(
    extractSemver("Keycloak 26.2.4", "(\\d+\\.\\d+\\.\\d+)"),
    "26.2.4",
  );
  assertEquals(extractSemver(null, "(\\d+\\.\\d+\\.\\d+)"), null);
  assertEquals(extractSemver("no version here", "(\\d+\\.\\d+\\.\\d+)"), null);
});

Deno.test("cmpSemver orders versions numerically, not lexically", () => {
  assertEquals(cmpSemver("16.0.4", "15.0.0") > 0, true);
  assertEquals(cmpSemver("26.2.4", "26.10.0") < 0, true); // 2 < 10 numerically
  assertEquals(cmpSemver("1.0.0", "1.0.0"), 0);
  assertEquals(cmpSemver("2.0", "2.0.1") < 0, true);
});

// ---- checkUpdate ------------------------------------------------------------

Deno.test("checkUpdate reports updateAvailable when installed < latest", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {
      ...baseArgs,
      versionCommand: "/opt/keycloak/bin/kc.sh --version | head -1",
      releaseApiUrl:
        "https://api.github.com/repos/keycloak/keycloak/releases/latest",
    },
  });

  await withMockedFetch(
    () => new Response(JSON.stringify({ tag_name: "26.7.3" }), { status: 200 }),
    () =>
      withMockedCommand(
        (_cmd, args) =>
          sshOut(
            remoteCommand(args).includes("--version") ? "Keycloak 26.2.4" : "",
          ),
        () => model.methods.checkUpdate.execute({}, asCtx(context)),
      ),
  );

  const data = getWrittenResources()[0].data;
  assertEquals(data.installedVersion, "26.2.4");
  assertEquals(data.latestVersion, "26.7.3");
  assertEquals(data.updateAvailable, true);
});

Deno.test("checkUpdate reports no update when installed == latest", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {
      ...baseArgs,
      versionCommand: "/usr/local/bin/forgejo --version",
      releaseApiUrl:
        "https://codeberg.org/api/v1/repos/forgejo/forgejo/releases/latest",
    },
  });

  await withMockedFetch(
    () =>
      new Response(JSON.stringify({ tag_name: "v16.0.4" }), { status: 200 }),
    () =>
      withMockedCommand(
        () => sshOut("forgejo version 16.0.4+gitea-1.22.0 built with go1.26.8"),
        () => model.methods.checkUpdate.execute({}, asCtx(context)),
      ),
  );

  const data = getWrittenResources()[0].data;
  assertEquals(data.installedVersion, "16.0.4");
  assertEquals(data.latestVersion, "16.0.4");
  assertEquals(data.updateAvailable, false);
});

Deno.test("checkUpdate leaves updateAvailable null when no releaseApiUrl is set", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {
      ...baseArgs,
      versionCommand: "/usr/local/bin/forgejo --version",
    },
  });

  await withMockedCommand(
    () => sshOut("forgejo version 16.0.4"),
    () => model.methods.checkUpdate.execute({}, asCtx(context)),
  );

  const data = getWrittenResources()[0].data;
  assertEquals(data.installedVersion, "16.0.4");
  assertEquals(data.latestVersion, null);
  assertEquals(data.updateAvailable, null);
});

// ---- safeUpdate -------------------------------------------------------------

Deno.test("safeUpdate refuses to update an unhealthy container without force", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: { ...baseArgs, versionCommand: "/bin/app --version" },
  });

  await assertRejects(
    () =>
      withMockedCommand((_cmd, args) => {
        const c = remoteCommand(args);
        if (c.includes("pct status")) return sshOut("status: stopped");
        if (c.includes("--version")) return sshOut("app 1.0.0");
        return sshOut("");
      }, () =>
        model.methods.safeUpdate.execute(
          { force: false, keepSnapshot: true },
          asCtx(context),
        )),
    Error,
    "not healthy before the update",
  );

  const written = getWrittenResources();
  assertEquals(written[written.length - 1].data.outcome, "skipped");
});

Deno.test("safeUpdate rolls back and throws when the app is unhealthy after update", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {
      ...baseArgs,
      versionCommand: "/bin/app --version",
      healthUrl: "https://app.example.test/health",
    },
  });

  // Phase flips as the update, then the rollback, are observed.
  let phase: "before" | "afterUpdate" | "afterRollback" = "before";

  const err = await assertRejects(
    () =>
      withMockedFetch(
        () => {
          // Health URL: healthy before, broken after update, healthy after rollback.
          const status = phase === "afterUpdate" ? 502 : 200;
          return new Response("", { status });
        },
        () =>
          withMockedCommand((_cmd, args) => {
            const c = remoteCommand(args);
            if (c.includes("/usr/bin/update")) {
              phase = "afterUpdate";
              return sshOut("Updated successfully!");
            }
            if (c.includes("pct rollback")) {
              phase = "afterRollback";
              return sshOut("");
            }
            if (c.includes("pct status")) return sshOut("status: running");
            if (c.includes("systemctl is-active")) {
              return sshOut(
                phase === "afterUpdate" ? "failed" : "active",
                phase === "afterUpdate" ? 3 : 0,
              );
            }
            if (c.includes("--version")) return sshOut("app 1.0.0");
            // pct snapshot / stop / start / anything else
            return sshOut("");
          }, () =>
            model.methods.safeUpdate.execute({
              force: false,
              keepSnapshot: true,
            }, asCtx(context))),
      ),
    Error,
  );

  assertStringIncludes((err as Error).message, "rolled back");

  const result = getWrittenResources().at(-1)?.data;
  assertEquals(result?.outcome, "rolled-back");
  assertEquals(result?.rolledBack, true);
  assertEquals(result?.healthyAfter, true); // healthy again post-rollback
});

// ---- discoverApp ------------------------------------------------------------

Deno.test("discoverApp parses app defaults from the ct script and recognized vars from build.func", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: { ...baseArgs, app: "testapp" },
  });

  await withMockedFetch(
    (input: Request) => {
      const url = input.url;
      return new Response(url.includes("build.func") ? BUILD_FUNC : CT_SCRIPT, {
        status: 200,
      });
    },
    () => model.methods.discoverApp.execute({}, asCtx(context)),
  );

  const data = getWrittenResources()[0].data as {
    appDefaults: Record<string, string>;
    recognizedVars: string[];
  };
  assertEquals(data.appDefaults.var_cpu, "2");
  assertEquals(data.appDefaults.var_ram, "2048");
  assertEquals(data.appDefaults.var_os, "debian");
  assertEquals(data.recognizedVars.includes("var_ctid"), true);

  // vars[] enriches names with default + description + group parsed from build.func.
  const vars = (getWrittenResources()[0].data as {
    vars: Array<
      {
        name: string;
        default: string | null;
        description: string | null;
        group: string | null;
      }
    >;
  }).vars;
  const nesting = vars.find((v) => v.name === "var_nesting");
  assertEquals(nesting?.group, "Advanced Settings");
  assertStringIncludes(nesting?.description ?? "", "Allow nesting");
  assertEquals(vars.find((v) => v.name === "var_cpu")?.group, "Resources");
});

Deno.test("status uses serviceActiveCommand for non-systemd (Alpine/OpenRC)", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {
      ...baseArgs,
      service: "valkey",
      serviceActiveCommand: "rc-service valkey status",
      versionCommand: "/usr/bin/valkey-server --version",
    },
  });

  await withMockedCommand((_cmd, args) => {
    const c = remoteCommand(args);
    if (c.includes("pct status")) return sshOut("status: running");
    if (c.includes("rc-service valkey status")) return sshOut("started", 0);
    if (c.includes("systemctl")) return sshOut("not found", 127); // must NOT be used
    if (c.includes("--version")) return sshOut("Valkey server v=9.0.4 sha=0:1");
    return sshOut("");
  }, () => model.methods.status.execute({}, asCtx(context)));

  const data = getWrittenResources()[0].data;
  assertEquals(data.serviceActive, true);
  assertEquals(data.healthy, true);
  assertEquals(data.installedVersion, "9.0.4");
});

// ---- previewInstall ---------------------------------------------------------

Deno.test("previewInstall summarizes provisioning, steps, packages, downloads, and services", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: { ...baseArgs, app: "testapp" },
  });

  await withMockedFetch(
    (input: Request) => {
      const url = input.url;
      const body = url.includes("-install.sh") ? INSTALL_SCRIPT : CT_SCRIPT;
      return new Response(body, { status: 200 });
    },
    () => model.methods.previewInstall.execute({}, asCtx(context)),
  );

  const data = getWrittenResources()[0].data as {
    os: string;
    steps: string[];
    packages: string[];
    downloads: string[];
    services: string[];
    summary: string;
  };
  assertEquals(data.os, "debian");
  assertEquals(data.steps.includes("Installing Dependencies"), true);
  assertEquals(data.packages.includes("curl"), true);
  assertEquals(data.packages.includes("postgresql"), true);
  assertEquals(data.downloads.includes("owner/testapp (github)"), true);
  assertEquals(data.services.includes("testapp"), true);
  assertStringIncludes(data.summary, "installs testapp");
});

Deno.test("discoverApp works with only `app` set (no node/ctid/service)", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {
      sshModel: "my-ssh",
      appName: "TestApp",
      app: "testapp",
      ctScriptBaseUrl:
        "https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main",
    },
  });

  await withMockedFetch(
    (input: Request) =>
      new Response(input.url.includes("build.func") ? BUILD_FUNC : CT_SCRIPT, {
        status: 200,
      }),
    () => model.methods.discoverApp.execute({}, asCtx(context)),
  );

  const data = getWrittenResources()[0].data as {
    appDefaults: Record<string, string>;
  };
  assertEquals(data.appDefaults.var_cpu, "2");
});

Deno.test("manage methods require node/ctid/service", async () => {
  const { context } = createModelTestContext({
    globalArgs: { sshModel: "my-ssh", appName: "TestApp", app: "testapp" },
  });
  await assertRejects(
    () => model.methods.status.execute({}, asCtx(context)),
    Error,
    "requires global args",
  );
});

// ---- install ----------------------------------------------------------------

Deno.test("install refuses when a container already exists at ctid", async () => {
  const { context } = createModelTestContext({
    globalArgs: { ...baseArgs, app: "testapp" },
  });

  await assertRejects(
    () =>
      withMockedCommand(
        (_cmd, args) =>
          remoteCommand(args).includes("pct status")
            ? sshOut("status: stopped", 0)
            : sshOut(""),
        () => model.methods.install.execute({ force: false }, asCtx(context)),
      ),
    Error,
    "already exists at ctid",
  );
});

Deno.test("install provisions a new container and reports it healthy", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {
      ...baseArgs,
      app: "testapp",
      versionCommand: "/bin/app --version",
      installVars: { var_cpu: "2" },
    },
  });

  let installed = false;

  await withMockedFetch(
    (input: Request) => {
      const url = input.url;
      return new Response(url.includes("build.func") ? BUILD_FUNC : CT_SCRIPT, {
        status: 200,
      });
    },
    () =>
      withMockedCommand((_cmd, args) => {
        const c = remoteCommand(args);
        if (c.includes("curl -fsSL")) {
          installed = true; // the install command itself
          return sshOut("Completed successfully!");
        }
        if (c.includes("pct status")) {
          return installed
            ? sshOut("status: running", 0)
            : sshOut("does not exist", 1);
        }
        if (c.includes("systemctl is-active")) return sshOut("active", 0);
        if (c.includes("--version")) return sshOut("app 1.0.0");
        return sshOut("");
      }, () => model.methods.install.execute({ force: false }, asCtx(context))),
  );

  const data = getWrittenResources().at(-1)?.data;
  assertEquals(data?.created, true);
  assertEquals(data?.healthy, true);
  assertEquals(data?.app, "testapp");
  assertEquals(data?.unknownVars, []); // var_cpu is recognized
});

// ---- pre-flight checks ------------------------------------------------------

type CheckName = keyof typeof model.checks;
type CheckCtx = Parameters<typeof model.checks["node-reachable"]["execute"]>[0];

const MUTATING_METHODS = ["install", "safeUpdate", "rollback"];
const READ_ONLY_METHODS = [
  "status",
  "discoverApp",
  "previewInstall",
  "checkUpdate",
];

/** Run one check against stubbed ssh output; returns the result and the remote commands it ran. */
async function runCheck(
  name: CheckName,
  opts: {
    globalArgs?: Record<string, unknown>;
    methodArgs?: Record<string, unknown>;
    handler?: (remote: string) => { stdout: string; code: number };
    /** Defaults to the check's own method; "" models a plain `swamp model validate`. */
    methodName?: string;
  } = {},
) {
  const { context } = createModelTestContext({
    globalArgs: opts.globalArgs ?? { ...baseArgs, app: "testapp" },
  });
  const ctx = {
    ...context,
    methodName: opts.methodName ?? model.checks[name].appliesTo[0],
    unresolvedMethodArgs: opts.methodArgs,
  } as unknown as CheckCtx;
  const remotes: string[] = [];
  const { result } = await withMockedCommand((_cmd, args) => {
    const remote = remoteCommand(args);
    remotes.push(remote);
    return opts.handler ? opts.handler(remote) : sshOut("");
  }, () => model.checks[name].execute(ctx));
  return { result, remotes };
}

const SNAP_LIST = [
  "`-> preupdate-20260913T120500Z 2026-09-13 12:05:00 pre-update",
  " `-> current                                     You are here!",
].join("\n");

Deno.test("every mutating method is covered by at least one check", () => {
  for (const method of MUTATING_METHODS) {
    const covering = Object.values(model.checks).filter((c) =>
      c.appliesTo.includes(method)
    );
    assertEquals(covering.length > 0, true, `${method} has no check`);
    assertEquals(
      covering.some((c) => c.labels.includes("live")),
      true,
      `${method} has no live check`,
    );
  }
});

Deno.test("read-only methods are not covered by any check", () => {
  for (const method of READ_ONLY_METHODS) {
    const covering = Object.values(model.checks).filter((c) =>
      c.appliesTo.includes(method)
    );
    assertEquals(covering.length, 0, `${method} must have no check`);
  }
});

Deno.test("every method is classified as mutating or read-only", () => {
  const known = [...MUTATING_METHODS, ...READ_ONLY_METHODS].sort();
  assertEquals(Object.keys(model.methods).sort(), known);
});

Deno.test("every check has a label and a description", () => {
  for (const check of Object.values(model.checks)) {
    assertEquals(check.labels.length > 0, true);
    assertEquals(check.description.length > 0, true);
  }
});

Deno.test("manage-args-present passes when node, ctid and service are set", async () => {
  const { result, remotes } = await runCheck("manage-args-present");
  assertEquals(result, { pass: true });
  assertEquals(remotes.length, 0); // policy check: no network
});

Deno.test("manage-args-present fails and names the missing args", async () => {
  const { result } = await runCheck("manage-args-present", {
    globalArgs: { sshModel: "my-ssh", appName: "TestApp" },
  });
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors?.[0] ?? "", "node, ctid, service");
  assertStringIncludes(result.errors?.[0] ?? "", "--skip-check");
});

Deno.test("install-app-present passes with app set and fails without", async () => {
  const ok = await runCheck("install-app-present");
  assertEquals(ok.result, { pass: true });
  const bad = await runCheck("install-app-present", {
    globalArgs: { ...baseArgs },
  });
  assertEquals(bad.result.pass, false);
  assertStringIncludes(bad.result.errors?.[0] ?? "", "app");
});

Deno.test("node-reachable passes when pct is found on the node", async () => {
  const { result, remotes } = await runCheck("node-reachable", {
    handler: () => sshOut("/usr/sbin/pct"),
  });
  assertEquals(result, { pass: true });
  assertStringIncludes(remotes[0], "command -v pct");
});

Deno.test("node-reachable fails when pct is missing", async () => {
  const { result } = await runCheck("node-reachable", {
    handler: () => sshOut("", 1),
  });
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors?.[0] ?? "", "pct");
  assertStringIncludes(result.errors?.[0] ?? "", "--skip-check-label live");
});

Deno.test("node-reachable fails when the ssh transport fails", async () => {
  const { result } = await runCheck("node-reachable", {
    handler: () => ({ stdout: "", code: 1 }),
  });
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors?.[0] ?? "", "SSH transport");
  assertStringIncludes(result.errors?.[0] ?? "", "--skip-check-label live");
});

Deno.test("node-reachable fails without running ssh when node is not set", async () => {
  const { result, remotes } = await runCheck("node-reachable", {
    globalArgs: { sshModel: "my-ssh" },
  });
  assertEquals(result.pass, false);
  assertEquals(remotes.length, 0);
});

Deno.test("ctid-free passes when no config file uses the ctid", async () => {
  const { result, remotes } = await runCheck("ctid-free", {
    methodArgs: { force: false },
    handler: () => sshOut(""),
  });
  assertEquals(result, { pass: true });
  assertStringIncludes(remotes[0], "/lxc/601.conf");
  assertStringIncludes(remotes[0], "/qemu-server/601.conf");
});

Deno.test("ctid-free fails when a container already uses the ctid", async () => {
  const { result } = await runCheck("ctid-free", {
    methodArgs: { force: false },
    handler: () => sshOut("/etc/pve/nodes/pve2/lxc/601.conf"),
  });
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors?.[0] ?? "", "601");
  assertStringIncludes(result.errors?.[0] ?? "", "pve2");
  assertStringIncludes(result.errors?.[0] ?? "", "force=true");
});

Deno.test("ctid-free fails when a VM already uses the ctid", async () => {
  const { result } = await runCheck("ctid-free", {
    handler: () => sshOut("/etc/pve/nodes/pve1/qemu-server/601.conf"),
  });
  assertEquals(result.pass, false);
});

Deno.test("ctid-free passes without probing when force=true", async () => {
  const { result, remotes } = await runCheck("ctid-free", {
    methodArgs: { force: true },
    handler: () => sshOut("/etc/pve/nodes/pve1/lxc/601.conf"),
  });
  assertEquals(result, { pass: true });
  assertEquals(remotes.length, 0);
});

Deno.test("ctid-free fails when the ssh transport fails", async () => {
  const { result } = await runCheck("ctid-free", {
    handler: () => ({ stdout: "", code: 1 }),
  });
  assertEquals(result.pass, false);
});

Deno.test("container-exists passes when pct status answers, even for a stopped container", async () => {
  const { result, remotes } = await runCheck("container-exists", {
    handler: () => sshOut("status: stopped", 0),
  });
  assertEquals(result, { pass: true });
  assertEquals(remotes.length, 1); // no service or http probe
});

Deno.test("container-exists fails when the container is not found", async () => {
  const { result } = await runCheck("container-exists", {
    handler: () =>
      sshOut("Configuration file 'nodes/pve1/lxc/601.conf' does not exist", 2),
  });
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors?.[0] ?? "", "601");
  assertStringIncludes(
    result.errors?.[0] ?? "",
    "--skip-check container-exists",
  );
});

Deno.test("container-exists fails when the ssh transport fails", async () => {
  const { result } = await runCheck("container-exists", {
    handler: () => ({ stdout: "", code: 1 }),
  });
  assertEquals(result.pass, false);
});

Deno.test("snapshot-available passes for a named snapshot that exists", async () => {
  const { result } = await runCheck("snapshot-available", {
    methodArgs: { snapshot: "preupdate-20260913T120500Z" },
    handler: () => sshOut(SNAP_LIST),
  });
  assertEquals(result, { pass: true });
});

Deno.test("snapshot-available fails for a named snapshot that does not exist", async () => {
  const { result } = await runCheck("snapshot-available", {
    methodArgs: { snapshot: "nope" },
    handler: () => sshOut(SNAP_LIST),
  });
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors?.[0] ?? "", '"nope"');
  assertStringIncludes(result.errors?.[0] ?? "", "preupdate-20260913T120500Z");
});

Deno.test("snapshot-available passes with no name when a preupdate-* snapshot exists", async () => {
  const { result } = await runCheck("snapshot-available", {
    methodArgs: {},
    handler: () => sshOut(SNAP_LIST),
  });
  assertEquals(result, { pass: true });
});

Deno.test("snapshot-available fails with no name when no preupdate-* snapshot exists", async () => {
  const { result } = await runCheck("snapshot-available", {
    methodArgs: {},
    handler: () => sshOut("`-> manual-1 2026-09-01 10:00:00 by hand"),
  });
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors?.[0] ?? "", "preupdate-*");
});

Deno.test("snapshot-available fails when pct listsnapshot fails", async () => {
  const { result } = await runCheck("snapshot-available", {
    handler: () => sshOut("Configuration file does not exist", 2),
  });
  assertEquals(result.pass, false);
});

Deno.test("method-specific preconditions pass without probing under a plain `swamp model validate` (empty methodName)", async () => {
  // A managed instance: its container exists, it has no app slug, and it has
  // no retained snapshot. Every probe would fail — none may run.
  for (
    const name of [
      "install-app-present",
      "ctid-free",
      "snapshot-available",
    ] as const
  ) {
    const { result, remotes } = await runCheck(name, {
      methodName: "",
      globalArgs: { ...baseArgs },
      handler: () => sshOut("/etc/pve/nodes/pve1/lxc/601.conf", 1),
    });
    assertEquals(result, { pass: true }, name);
    assertEquals(remotes, [], name);
  }
});

Deno.test("method-specific preconditions still gate under `swamp model validate --method <theirs>`", async () => {
  const { result: noApp } = await runCheck("install-app-present", {
    methodName: "install",
    globalArgs: { ...baseArgs },
  });
  assertEquals(noApp.pass, false);
  const { result: taken } = await runCheck("ctid-free", {
    methodName: "install",
    methodArgs: { force: false },
    handler: () => sshOut("/etc/pve/nodes/pve1/lxc/601.conf"),
  });
  assertEquals(taken.pass, false);
  const { result: noSnap } = await runCheck("snapshot-available", {
    methodName: "rollback",
    handler: () => sshOut(" `-> current   You are here!"),
  });
  assertEquals(noSnap.pass, false);
});

Deno.test("rollback checks do not need a healthy or running container (recovery rule)", async () => {
  // A stopped, unhealthy container: every probe says so. The rollback checks
  // must still pass, and must not ask about container or service state.
  const commands: string[] = [];
  const handler = (remote: string) => {
    commands.push(remote);
    if (remote.includes("command -v pct")) return sshOut("/usr/sbin/pct");
    if (remote.includes("pct listsnapshot")) return sshOut(SNAP_LIST);
    return sshOut("status: stopped", 3); // anything else: dead container
  };
  for (const name of ["node-reachable", "snapshot-available"] as const) {
    const { result } = await runCheck(name, { handler });
    assertEquals(result, { pass: true }, name);
  }
  for (const c of commands) {
    assertEquals(/pct status|systemctl|rc-service|curl/.test(c), false, c);
  }
  const rollbackChecks = Object.entries(model.checks).filter(([, c]) =>
    c.appliesTo.includes("rollback")
  ).map(([n]) => n).sort();
  assertEquals(rollbackChecks, [
    "manage-args-present",
    "node-reachable",
    "snapshot-available",
  ]);
});
