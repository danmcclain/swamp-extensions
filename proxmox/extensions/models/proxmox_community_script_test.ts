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
import {
  cmpSemver,
  execFormatProbeShell,
  execFormatRefusal,
  extractSemver,
  model,
  parseUpdateCommand,
  sudoUpdateShell,
  updateNotRun,
  updateScriptProbeShell,
  updateScriptUrls,
  updateUrlRefusal,
  urlFetchShell,
} from "./proxmox_community_script.ts";

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

/**
 * Run safeUpdate against a mocked node and record every remote command.
 * `broken` makes the app unhealthy after the update runs.
 */
async function runSafeUpdate(
  args: { force: boolean; keepSnapshot: boolean; snapshot?: boolean },
  broken: boolean,
) {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {
      ...baseArgs,
      versionCommand: "/bin/app --version",
      healthUrl: "https://app.example.test/health",
    },
  });
  const commands: string[] = [];
  let updated = false;
  let error: Error | null = null;
  try {
    await withMockedFetch(
      () => new Response("", { status: updated && broken ? 502 : 200 }),
      () =>
        withMockedCommand((_cmd, a) => {
          const c = remoteCommand(a);
          commands.push(c);
          if (c.includes("/usr/bin/update")) {
            updated = true;
            return sshOut("Updated successfully!");
          }
          if (c.includes("pct status")) return sshOut("status: running");
          if (c.includes("systemctl is-active")) {
            return updated && broken
              ? sshOut("failed", 3)
              : sshOut("active", 0);
          }
          if (c.includes("--version")) {
            return sshOut(updated ? "app 2.0.0" : "app 1.0.0");
          }
          return sshOut("");
        }, () => model.methods.safeUpdate.execute(args, asCtx(context))),
    );
  } catch (e) {
    error = e as Error;
  }
  return { commands, error, result: getWrittenResources().at(-1)?.data };
}

Deno.test("safeUpdate snapshot:false takes no snapshot, runs the update and keeps a healthy result", async () => {
  const { commands, error, result } = await runSafeUpdate(
    { force: false, keepSnapshot: true, snapshot: false },
    false,
  );
  assertEquals(error, null);
  assertEquals(commands.some((c) => c.includes("pct snapshot")), false);
  assertEquals(commands.some((c) => c.includes("pct delsnapshot")), false);
  assertEquals(commands.some((c) => c.includes("pct rollback")), false);
  assertEquals(commands.some((c) => c.includes("/usr/bin/update")), true);
  assertEquals(result?.outcome, "updated");
  assertEquals(result?.snapshot, null);
  assertEquals(result?.snapshotTaken, false);
  assertEquals(result?.healthyAfter, true);
  assertEquals(result?.rolledBack, false);
});

Deno.test("safeUpdate snapshot:false ignores keepSnapshot:false (no delete command)", async () => {
  const { commands, error, result } = await runSafeUpdate(
    { force: false, keepSnapshot: false, snapshot: false },
    false,
  );
  assertEquals(error, null);
  assertEquals(commands.some((c) => c.includes("pct delsnapshot")), false);
  assertEquals(commands.some((c) => c.includes("pct snapshot")), false);
  assertEquals(result?.snapshot, null);
  assertEquals(result?.snapshotTaken, false);
});

Deno.test("safeUpdate snapshot:false surfaces an unhealthy app as a failure without rollback", async () => {
  const { commands, error, result } = await runSafeUpdate(
    { force: false, keepSnapshot: true, snapshot: false },
    true,
  );
  assertEquals(error instanceof Error, true);
  assertStringIncludes(error!.message, "update failed validation");
  assertStringIncludes(error!.message, "caller owns the snapshot and rollback");
  assertEquals(commands.some((c) => c.includes("pct snapshot")), false);
  assertEquals(commands.some((c) => c.includes("pct rollback")), false);
  assertEquals(commands.some((c) => c.includes("pct stop")), false);
  assertEquals(commands.some((c) => c.includes("/usr/bin/update")), true);
  assertEquals(result?.outcome, "failed");
  assertEquals(result?.rolledBack, false);
  assertEquals(result?.snapshot, null);
  assertEquals(result?.snapshotTaken, false);
  assertEquals(result?.healthyAfter, false);
  assertStringIncludes(String(result?.logs), "caller owns the snapshot");
});

Deno.test("safeUpdate snapshot:false still runs the baseline health gate", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: { ...baseArgs, versionCommand: "/bin/app --version" },
  });
  const commands: string[] = [];
  await assertRejects(
    () =>
      withMockedCommand((_cmd, args) => {
        const c = remoteCommand(args);
        commands.push(c);
        if (c.includes("pct status")) return sshOut("status: stopped");
        return sshOut("");
      }, () =>
        model.methods.safeUpdate.execute(
          { force: false, keepSnapshot: true, snapshot: false },
          asCtx(context),
        )),
    Error,
    "not healthy before the update",
  );
  assertEquals(commands.some((c) => c.includes("/usr/bin/update")), false);
  assertEquals(getWrittenResources().at(-1)?.data.outcome, "skipped");
});

Deno.test("safeUpdate snapshot:true takes a snapshot and keeps it (explicit and default)", async () => {
  for (const snapshot of [true, undefined]) {
    const { commands, error, result } = await runSafeUpdate(
      { force: false, keepSnapshot: true, snapshot },
      false,
    );
    assertEquals(error, null);
    assertEquals(commands.some((c) => c.includes("pct snapshot")), true);
    assertEquals(commands.some((c) => c.includes("pct delsnapshot")), false);
    assertEquals(String(result?.snapshot).startsWith("preupdate-"), true);
    assertEquals(result?.snapshotTaken, true);
    assertEquals(result?.outcome, "updated");
  }
});

Deno.test("safeUpdate snapshot:true with keepSnapshot:false deletes the snapshot", async () => {
  const { commands, result } = await runSafeUpdate(
    { force: false, keepSnapshot: false, snapshot: true },
    false,
  );
  assertEquals(commands.some((c) => c.includes("pct snapshot")), true);
  assertEquals(commands.some((c) => c.includes("pct delsnapshot")), true);
  assertEquals(result?.snapshot, null);
  assertEquals(result?.snapshotTaken, true);
});

Deno.test("safeUpdate snapshot:true rolls back on an unhealthy update", async () => {
  const { commands, error, result } = await runSafeUpdate(
    { force: false, keepSnapshot: true, snapshot: true },
    true,
  );
  assertEquals(error instanceof Error, true);
  assertEquals(commands.some((c) => c.includes("pct rollback")), true);
  assertEquals(result?.outcome, "rolled-back");
  assertEquals(result?.snapshotTaken, true);
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
  "privileges",
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
    "reach-ssh-ready",
    "snapshot-available",
  ]);
});

// ---- reach ssh and nodeModel ------------------------------------------------

const NODE_MODEL = "my-node";
const SNAP = "preupdate-20260913T120500Z";
/** A URL the update script fetches, as the URL probe reports it. */
const CT_URL =
  "https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/ct/app.sh";
/** The container's own app settings for the reach ssh runs below. */
const SSH_APP = {
  versionCommand: "/bin/app --version",
  healthUrl: "https://app.example.test/health",
};

/** baseArgs for reach ssh: no node; the container's own host (ctHost) is reached instead. */
function sshArgs(extra: Record<string, unknown> = {}): Record<string, unknown> {
  const { node: _node, ...rest } = baseArgs;
  return { ...rest, reach: "ssh", ctHost: "ct601", ...extra };
}

/** The `--input` values of a mocked swamp call, in order. */
function mockedInputs(args: string[]): string[] {
  return args.flatMap((a, i) => (args[i - 1] === "--input" ? [a] : []));
}

/** A mocked swamp call as text: `ssh:<host> <remote command>` or `model:<method> <inputs>`. */
function describeCall(args: string[]): string {
  if (args[3] === baseArgs.sshModel) {
    const hosts = args.find((a) => a.startsWith("hosts:json=")) ?? "";
    const [host] = JSON.parse(hosts.slice("hosts:json=".length)) as string[];
    return `ssh:${host} ${remoteCommand(args)}`;
  }
  return `model:${args[4]} ${mockedInputs(args).join(" ")}`;
}

/** The CLI reply for a nodeModel run: one dataArtifact carrying `attributes`. */
function nodeReply(attributes: Record<string, unknown> = {}) {
  return {
    stdout: JSON.stringify({ dataArtifacts: [{ attributes }] }),
    code: 0,
  };
}

/**
 * Run safeUpdate with reach ssh and record every mocked call with describeCall.
 * The app comes back unhealthy after the update when `broken`; a rollbackCt
 * makes it healthy again.
 */
async function runSshSafeUpdate(
  args: { force: boolean; keepSnapshot: boolean; snapshot?: boolean },
  opts: {
    broken?: boolean;
    globalArgs?: Record<string, unknown>;
    // What the exec-format probe of the update bin prints (default: a #! script).
    head?: string;
    // What the update bin reads as (default: the legacy helper with CT_URL).
    script?: string;
    // What the URL fetch prints (default: CT_URL answers 200).
    urls?: string;
    // What the update prints (default: a success line).
    updateOut?: string;
  } = {},
) {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: opts.globalArgs ?? sshArgs(SSH_APP),
  });
  const calls: string[] = [];
  let phase: "before" | "updated" | "rolledBack" = "before";
  let error: Error | null = null;
  try {
    await withMockedFetch(
      () =>
        new Response("", {
          status: phase === "updated" && opts.broken ? 502 : 200,
        }),
      () =>
        withMockedCommand((_cmd, a) => {
          calls.push(describeCall(a));
          if (a[3] !== baseArgs.sshModel) {
            if (a[4] === "rollbackCt") phase = "rolledBack";
            return nodeReply();
          }
          const c = remoteCommand(a);
          if (c.includes("SCRIPT-END")) {
            return sshOut(
              opts.script ??
                scriptOut(`#!/bin/sh\nbash -c "$(curl -fsSL ${CT_URL})"`),
            );
          }
          if (c.includes("URLCHECK-END")) {
            return sshOut(opts.urls ?? `URL 200 ${CT_URL}\nURLCHECK-END`);
          }
          if (c.includes("od -An")) return sshOut(opts.head ?? "HEAD=23212f62");
          if (c.includes("/usr/bin/update")) {
            phase = "updated";
            return sshOut(opts.updateOut ?? "Updated successfully!");
          }
          if (c.includes("{ true; }")) return sshOut("");
          if (c.includes("systemctl is-active")) {
            return phase === "updated" && opts.broken
              ? sshOut("failed", 3)
              : sshOut("active", 0);
          }
          if (c.includes("--version")) {
            return sshOut(phase === "updated" ? "app 2.0.0" : "app 1.0.0");
          }
          return sshOut("");
        }, () => model.methods.safeUpdate.execute(args, asCtx(context))),
    );
  } catch (e) {
    error = e as Error;
  }
  return { calls, error, result: getWrittenResources().at(-1)?.data };
}

Deno.test("reach ssh: parseUpdateCommand reads the default as one exact argv with its env", () => {
  assertEquals(parseUpdateCommand("PHS_SILENT=1 /usr/bin/update"), {
    ok: true,
    argv: ["/usr/bin/update"],
    env: { PHS_SILENT: "1" },
  });
});

Deno.test("reach ssh: parseUpdateCommand refuses shell syntax, relative and dot paths, duplicates and odd arguments", () => {
  for (
    const cmd of [
      "update",
      "PHS_SILENT=1 /usr/bin/update; id",
      "/usr/bin/../bin/sh",
      "/usr//bin/update",
      "A=1 A=2 /usr/bin/update",
      "/usr/bin/update $(id)",
      "/usr/bin/update ../etc",
    ]
  ) {
    assertEquals(parseUpdateCommand(cmd).ok, false, cmd);
  }
});

Deno.test("reach ssh: sudoUpdateShell runs the argv through sudo -n and the env pairs through env", () => {
  const plain = sudoUpdateShell({ argv: ["/usr/bin/update"], env: {} });
  assertEquals(plain.includes("command -v env"), false);
  assertStringIncludes(plain, "sudo -n");
  assertStringIncludes(plain, "'/usr/bin/update'");

  const withEnv = sudoUpdateShell({
    argv: ["/usr/bin/update"],
    env: { PHS_SILENT: "1" },
  });
  assertStringIncludes(withEnv, "command -v env");
  assertStringIncludes(withEnv, "sudo -n");
  assertStringIncludes(withEnv, "'PHS_SILENT=1'");
  assertStringIncludes(withEnv, "'/usr/bin/update'");
});

Deno.test("reach ssh: status probes only ctHost over ssh and reads no snapshots without a nodeModel", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: sshArgs({ versionCommand: "/bin/app --version" }),
  });
  const calls: string[] = [];
  await withMockedCommand((_cmd, args) => {
    calls.push(describeCall(args));
    const c = remoteCommand(args);
    if (c.includes("--version")) return sshOut("app 1.0.0");
    if (c.includes("is-active")) return sshOut("active", 0);
    return sshOut("");
  }, () => model.methods.status.execute({}, asCtx(context)));

  assertEquals(calls.length > 0, true);
  for (const c of calls) {
    assertEquals(c.startsWith("ssh:ct601 "), true, c);
    assertEquals(c.includes("pct "), false, c);
  }
  const data = getWrittenResources()[0].data;
  assertEquals(data.node, "ct601");
  assertEquals(data.running, true);
  assertEquals(data.healthy, true);
  assertEquals(data.snapshots, []);
});

Deno.test("reach ssh: safeUpdate snapshot:false runs one sudo update over ssh, never pct or bash -lc", async () => {
  const { calls, error, result } = await runSshSafeUpdate({
    force: false,
    keepSnapshot: true,
    snapshot: false,
  });
  assertEquals(error, null);
  const updates = calls.filter((c) =>
    c.includes("/usr/bin/update") && !c.includes("od -An")
  );
  assertEquals(updates.length, 1);
  assertStringIncludes(updates[0], "sudo -n");
  assertStringIncludes(updates[0], "'/usr/bin/update'");
  assertEquals(calls.some((c) => c.includes("pct ")), false);
  assertEquals(calls.some((c) => c.includes("bash -lc")), false);
  assertEquals(calls.some((c) => c.startsWith("model:")), false);
  assertEquals(result?.outcome, "updated");
});

Deno.test("nodeModel: reach ssh safeUpdate takes its snapshot through snapshotCt before the update", async () => {
  const { calls, error, result } = await runSshSafeUpdate(
    { force: false, keepSnapshot: true, snapshot: true },
    { globalArgs: sshArgs({ ...SSH_APP, nodeModel: NODE_MODEL }) },
  );
  assertEquals(error, null);
  const snap = calls.findIndex((c) => c.startsWith("model:snapshotCt"));
  const update = calls.findIndex((c) =>
    c.includes("/usr/bin/update") && !c.includes("od -An")
  );
  const probe = calls.findIndex((c) => c.includes("od -An"));
  assertEquals(probe >= 0 && probe < snap, true);
  assertEquals(snap >= 0 && snap < update, true);
  assertStringIncludes(calls[snap], "vmid:json=601");
  assertEquals(calls.some((c) => c.includes("pct ")), false);
  assertEquals(result?.outcome, "updated");
  assertEquals(result?.snapshotTaken, true);
  assertStringIncludes(String(result?.snapshot), "preupdate-");
});

Deno.test("nodeModel: reach ssh safeUpdate rolls back through rollbackCt with start when unhealthy", async () => {
  const { calls, error, result } = await runSshSafeUpdate(
    { force: false, keepSnapshot: true, snapshot: true },
    {
      broken: true,
      globalArgs: sshArgs({ ...SSH_APP, nodeModel: NODE_MODEL }),
    },
  );
  assertStringIncludes(error?.message ?? "", "rolled back");
  const rollbacks = calls.filter((c) => c.startsWith("model:rollbackCt"));
  assertEquals(rollbacks.length, 1);
  assertStringIncludes(rollbacks[0], "vmid:json=601");
  assertStringIncludes(rollbacks[0], "start:json=true");
  assertEquals(result?.outcome, "rolled-back");
  assertEquals(result?.rolledBack, true);
  assertEquals(result?.healthyAfter, true);
});

Deno.test("nodeModel: reach ssh safeUpdate with keepSnapshot:false deletes through deleteCtSnapshot", async () => {
  const { calls, error, result } = await runSshSafeUpdate(
    { force: false, keepSnapshot: false, snapshot: true },
    { globalArgs: sshArgs({ ...SSH_APP, nodeModel: NODE_MODEL }) },
  );
  assertEquals(error, null);
  const deletes = calls.filter((c) => c.startsWith("model:deleteCtSnapshot"));
  assertEquals(deletes.length, 1);
  assertStringIncludes(deletes[0], "vmid:json=601");
  assertEquals(result?.snapshot, null);
  assertEquals(result?.snapshotTaken, true);
});

Deno.test("reach ssh: safeUpdate snapshot:true without a nodeModel refuses before any command", async () => {
  const { context } = createModelTestContext({
    globalArgs: sshArgs(SSH_APP),
  });
  const calls: string[] = [];
  await assertRejects(
    () =>
      withMockedCommand((_cmd, args) => {
        calls.push(describeCall(args));
        return sshOut("");
      }, () =>
        model.methods.safeUpdate.execute(
          { force: false, keepSnapshot: true, snapshot: true },
          asCtx(context),
        )),
    Error,
    "only through nodeModel",
  );
  assertEquals(calls, []);
});

Deno.test("reach ssh: safeUpdate with an updateCommand that is not an exact argv refuses before any command", async () => {
  const { context } = createModelTestContext({
    globalArgs: sshArgs({ ...SSH_APP, updateCommand: "update; id" }),
  });
  const calls: string[] = [];
  await assertRejects(
    () =>
      withMockedCommand((_cmd, args) => {
        calls.push(describeCall(args));
        return sshOut("");
      }, () =>
        model.methods.safeUpdate.execute(
          { force: false, keepSnapshot: true },
          asCtx(context),
        )),
    Error,
    "updateCommand must be",
  );
  assertEquals(calls, []);
});

Deno.test("nodeModel: reach pct safeUpdate snapshots through snapshotCt, not pct snapshot", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {
      ...baseArgs,
      versionCommand: "/bin/app --version",
      nodeModel: NODE_MODEL,
    },
  });
  const calls: string[] = [];
  let updated = false;
  await withMockedCommand((_cmd, args) => {
    calls.push(describeCall(args));
    if (args[3] !== baseArgs.sshModel) return nodeReply();
    const c = remoteCommand(args);
    if (c.includes("/usr/bin/update")) {
      updated = true;
      return sshOut("Updated successfully!");
    }
    if (c.includes("pct status")) return sshOut("status: running");
    if (c.includes("systemctl is-active")) return sshOut("active", 0);
    if (c.includes("--version")) {
      return sshOut(updated ? "app 2.0.0" : "app 1.0.0");
    }
    return sshOut("");
  }, () =>
    model.methods.safeUpdate.execute(
      { force: false, keepSnapshot: true, snapshot: true },
      asCtx(context),
    ));

  assertEquals(calls.some((c) => c.includes("pct snapshot")), false);
  assertEquals(calls.some((c) => c.startsWith("model:snapshotCt")), true);
  const data = getWrittenResources().at(-1)?.data;
  assertEquals(data?.outcome, "updated");
  assertEquals(data?.snapshotTaken, true);
});

Deno.test("reach ssh: rollback without a nodeModel refuses before any command", async () => {
  const { context } = createModelTestContext({
    globalArgs: sshArgs(SSH_APP),
  });
  const calls: string[] = [];
  await assertRejects(
    () =>
      withMockedCommand((_cmd, args) => {
        calls.push(describeCall(args));
        return sshOut("");
      }, () => model.methods.rollback.execute({}, asCtx(context))),
    Error,
    "only through nodeModel",
  );
  assertEquals(calls, []);
});

Deno.test("nodeModel: reach ssh rollback lists through listCtSnapshots, rolls back with start, then checks health", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: sshArgs({ ...SSH_APP, nodeModel: NODE_MODEL }),
  });
  const calls: string[] = [];
  // SSH_APP sets a healthUrl, so the post-rollback health probe needs a 200.
  await withMockedFetch(
    () => new Response("", { status: 200 }),
    () =>
      withMockedCommand((_cmd, args) => {
        calls.push(describeCall(args));
        if (args[3] !== baseArgs.sshModel) {
          return args[4] === "listCtSnapshots"
            ? nodeReply({ snapshots: [{ name: SNAP }] })
            : nodeReply();
        }
        const c = remoteCommand(args);
        if (c.includes("--version")) return sshOut("app 1.0.0");
        if (c.includes("is-active")) return sshOut("active", 0);
        return sshOut("");
      }, () => model.methods.rollback.execute({}, asCtx(context))),
  );

  const rollbacks = calls.filter((c) => c.startsWith("model:rollbackCt"));
  assertEquals(rollbacks, [
    `model:rollbackCt vmid:json=601 name=${SNAP} start:json=true`,
  ]);
  const listed = calls.findIndex((c) => c.startsWith("model:listCtSnapshots"));
  assertEquals(listed >= 0 && listed < calls.indexOf(rollbacks[0]), true);
  assertEquals(calls.some((c) => c.includes("pct ")), false);
  assertEquals(getWrittenResources().at(-1)?.data.healthy, true);
});

Deno.test("reach ssh: install refuses before any command, since it needs pct", async () => {
  const { context } = createModelTestContext({
    globalArgs: sshArgs({ app: "testapp" }),
  });
  const calls: string[] = [];
  await assertRejects(
    () =>
      withMockedCommand((_cmd, args) => {
        calls.push(describeCall(args));
        return sshOut("");
      }, () => model.methods.install.execute({ force: false }, asCtx(context))),
    Error,
    "it needs reach pct",
  );
  assertEquals(calls, []);
});

Deno.test("reach ssh: privileges declares the default update as one sudo argv with its env", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: sshArgs(),
  });
  const calls: string[] = [];
  await withMockedCommand((_cmd, args) => {
    calls.push(describeCall(args));
    return sshOut("");
  }, () => model.methods.privileges.execute({}, asCtx(context)));

  assertEquals(calls, []); // read-only: runs nothing on any host
  const written = getWrittenResources();
  assertEquals(written.length, 1);
  assertEquals(written[0].specName, "privileges");
  assertEquals(written[0].data, {
    commands: [{ argv: ["/usr/bin/update"], env: { PHS_SILENT: "1" } }],
    helpers: [],
    remoteCode: true,
    remoteSources: [
      "community-scripts/ProxmoxVE@main",
      "community-scripts/core@main",
    ],
  });
});

Deno.test("reach ssh: privileges leaves env out when the update command has no env pairs", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: sshArgs({ updateCommand: "/usr/bin/update" }),
  });
  await withMockedCommand(
    () => sshOut(""),
    () => model.methods.privileges.execute({}, asCtx(context)),
  );

  const data = getWrittenResources()[0].data as {
    commands: Array<Record<string, unknown>>;
  };
  assertEquals(data.commands, [{ argv: ["/usr/bin/update"] }]);
  assertEquals("env" in data.commands[0], false);
});

Deno.test("reach ssh: privileges refuses reach pct, which no sudo grant covers", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: { ...baseArgs },
  });
  await assertRejects(
    () => model.methods.privileges.execute({}, asCtx(context)),
    Error,
    "no sudo grant covers",
  );
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("reach ssh: privileges accepts only ctHost as its host", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: sshArgs(),
  });
  await assertRejects(
    () => model.methods.privileges.execute({ host: "pve1" }, asCtx(context)),
    Error,
    'asked for host "pve1"',
  );
  assertEquals(getWrittenResources().length, 0);

  await withMockedCommand(
    () => sshOut(""),
    () => model.methods.privileges.execute({ host: "ct601" }, asCtx(context)),
  );
  assertEquals(getWrittenResources().length, 1);
});

Deno.test("reach ssh: privileges refuses an updateCommand that is not an exact argv", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: sshArgs({ updateCommand: "update" }),
  });
  await assertRejects(
    () => model.methods.privileges.execute({}, asCtx(context)),
    Error,
    "updateCommand must be",
  );
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("reach ssh: reach-ssh-ready refuses an update that sudo cannot grant or a snapshot with no nodeModel", async () => {
  const badCommand = await runCheck("reach-ssh-ready", {
    globalArgs: sshArgs({ updateCommand: "update" }),
    methodArgs: { snapshot: false },
  });
  assertEquals(badCommand.result.pass, false);
  assertStringIncludes(
    badCommand.result.errors?.[0] ?? "",
    "updateCommand must be",
  );

  // safeUpdate takes a snapshot unless snapshot is false.
  const noSnap = await runCheck("reach-ssh-ready", {
    globalArgs: sshArgs(),
    methodArgs: {},
  });
  assertEquals(noSnap.result.pass, false);
  assertStringIncludes(
    noSnap.result.errors?.[0] ?? "",
    "only through nodeModel",
  );

  const rollback = await runCheck("reach-ssh-ready", {
    methodName: "rollback",
    globalArgs: sshArgs(),
  });
  assertEquals(rollback.result.pass, false);
  assertStringIncludes(
    rollback.result.errors?.[0] ?? "",
    "only through nodeModel",
  );

  const install = await runCheck("reach-ssh-ready", {
    methodName: "install",
    globalArgs: sshArgs({ nodeModel: NODE_MODEL }),
  });
  assertEquals(install.result.pass, false);
  assertStringIncludes(
    install.result.errors?.[0] ?? "",
    "install creates the container with pct",
  );
});

Deno.test("reach ssh: reach-ssh-ready passes for a sound definition and under plain validate", async () => {
  const pct = await runCheck("reach-ssh-ready", {
    globalArgs: { ...baseArgs },
  });
  assertEquals(pct.result, { pass: true });

  const noSnapshot = await runCheck("reach-ssh-ready", {
    globalArgs: sshArgs(),
    methodArgs: { snapshot: false },
  });
  assertEquals(noSnapshot.result, { pass: true });

  const withNode = await runCheck("reach-ssh-ready", {
    methodName: "rollback",
    globalArgs: sshArgs({ nodeModel: NODE_MODEL }),
  });
  assertEquals(withNode.result, { pass: true });

  const validate = await runCheck("reach-ssh-ready", {
    methodName: "",
    globalArgs: sshArgs(),
  });
  assertEquals(validate.result, { pass: true });
});

Deno.test("reach ssh: manage-args-present needs ctHost and does not need node", async () => {
  const ok = await runCheck("manage-args-present", { globalArgs: sshArgs() });
  assertEquals(ok.result, { pass: true });
  assertEquals(ok.remotes.length, 0);

  const bad = await runCheck("manage-args-present", {
    globalArgs: {
      sshModel: "my-ssh",
      appName: "TestApp",
      reach: "ssh",
      ctid: 601,
      service: "testapp",
    },
  });
  assertEquals(bad.result.pass, false);
  assertStringIncludes(
    bad.result.errors?.[0] ?? "",
    "Global arg(s) not set: ctHost.",
  );
});

Deno.test("reach ssh: container-exists probes true on ctHost over ssh", async () => {
  const up = await runCheck("container-exists", {
    globalArgs: sshArgs(),
    handler: () => sshOut("", 0),
  });
  assertEquals(up.result, { pass: true });
  assertEquals(up.remotes.length, 1);
  assertStringIncludes(up.remotes[0], "{ true; }");
  assertEquals(up.remotes[0].includes("pct "), false);

  const down = await runCheck("container-exists", {
    globalArgs: sshArgs(),
    handler: () => sshOut("", 1),
  });
  assertEquals(down.result.pass, false);
  assertStringIncludes(down.result.errors?.[0] ?? "", "ct601");

  const transport = await runCheck("container-exists", {
    globalArgs: sshArgs(),
    handler: () => ({ stdout: "", code: 1 }),
  });
  assertEquals(transport.result.pass, false);
});

Deno.test("reach ssh: node-reachable passes without a node when no nodeModel is set", async () => {
  const { result, remotes } = await runCheck("node-reachable", {
    globalArgs: sshArgs(),
  });
  assertEquals(result, { pass: true });
  assertEquals(remotes, []);
});

Deno.test("nodeModel: node-reachable lists the CT's snapshots through the nodeModel", async () => {
  const listed = await runCheck("node-reachable", {
    globalArgs: sshArgs({ nodeModel: NODE_MODEL }),
    handler: () => nodeReply({ snapshots: [{ name: SNAP }] }),
  });
  assertEquals(listed.result, { pass: true });
  assertEquals(listed.remotes.length, 1);
  assertStringIncludes(listed.remotes[0], "listCtSnapshots");

  const failed = await runCheck("node-reachable", {
    globalArgs: sshArgs({ nodeModel: NODE_MODEL }),
    handler: () => ({ stdout: "", code: 1 }),
  });
  assertEquals(failed.result.pass, false);
  assertStringIncludes(failed.result.errors?.[0] ?? "", NODE_MODEL);
});

Deno.test("nodeModel: snapshot-available checks a named snapshot through listCtSnapshots", async () => {
  const present = await runCheck("snapshot-available", {
    globalArgs: sshArgs({ nodeModel: NODE_MODEL }),
    methodName: "rollback",
    methodArgs: { snapshot: SNAP },
    handler: () => nodeReply({ snapshots: [{ name: SNAP }] }),
  });
  assertEquals(present.result, { pass: true });
  assertStringIncludes(present.remotes[0], "listCtSnapshots");

  const absent = await runCheck("snapshot-available", {
    globalArgs: sshArgs({ nodeModel: NODE_MODEL }),
    methodName: "rollback",
    methodArgs: { snapshot: "nope" },
    handler: () => nodeReply({ snapshots: [{ name: SNAP }] }),
  });
  assertEquals(absent.result.pass, false);
  assertStringIncludes(absent.result.errors?.[0] ?? "", '"nope"');
  assertStringIncludes(absent.result.errors?.[0] ?? "", SNAP);
});

Deno.test("reach ssh: snapshot-available refuses without a nodeModel and runs no command", async () => {
  const { result, remotes } = await runCheck("snapshot-available", {
    globalArgs: sshArgs(),
    methodName: "rollback",
    methodArgs: { snapshot: SNAP },
  });
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors?.[0] ?? "", "only through nodeModel");
  assertEquals(remotes, []);
});

Deno.test("reach ssh: execFormatRefusal accepts #! and ELF, refuses anything else (fail closed)", () => {
  const bin = "/usr/bin/update";
  assertEquals(execFormatRefusal(bin, "HEAD=23212f62\n__SWAMP_RC__=0"), null);
  assertEquals(execFormatRefusal(bin, "HEAD=7f454c46\n"), null);
  assertStringIncludes(
    execFormatRefusal(bin, "HEAD=62617368\n") ?? "",
    "no #! line",
  );
  assertStringIncludes(execFormatRefusal(bin, "MISSING\n") ?? "", "not a file");
  assertStringIncludes(
    execFormatRefusal(bin, "") ?? "",
    "could not read the start",
  );
  assertStringIncludes(
    execFormatRefusal(bin, "HEAD=7f454c4600\n") ?? "",
    "no #! line",
  );
  // A one-byte file (just "#") is not a #! line.
  assertStringIncludes(execFormatRefusal(bin, "HEAD=23\n") ?? "", "no #! line");
});

Deno.test("reach ssh: execFormatProbeShell reads the start of real files in a real shell", async () => {
  const dir = await Deno.makeTempDir();
  try {
    const files: Record<string, Uint8Array> = {
      "hashbang": new TextEncoder().encode("#!/bin/sh\necho hi\n"),
      "noshebang": new TextEncoder().encode('bash -c "$(curl -fsSL x)"\n'),
      "elf": new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01]),
      "it's quoted": new TextEncoder().encode("#!/bin/sh\n"),
    };
    for (const [n, b] of Object.entries(files)) {
      await Deno.writeFile(`${dir}/${n}`, b);
    }
    const run = async (bin: string) => {
      const out = await new Deno.Command("sh", {
        args: ["-c", execFormatProbeShell(bin)],
        stdout: "piped",
      }).output();
      return execFormatRefusal(bin, new TextDecoder().decode(out.stdout));
    };
    assertEquals(await run(`${dir}/hashbang`), null);
    assertEquals(await run(`${dir}/elf`), null);
    assertEquals(await run(`${dir}/it's quoted`), null);
    assertStringIncludes((await run(`${dir}/noshebang`)) ?? "", "no #! line");
    assertStringIncludes((await run(`${dir}/absent`)) ?? "", "not a file");
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("reach ssh: safeUpdate refuses before the snapshot when the update bin has no #! line", async () => {
  const { calls, error } = await runSshSafeUpdate(
    { force: false, keepSnapshot: true, snapshot: true },
    {
      globalArgs: sshArgs({ ...SSH_APP, nodeModel: NODE_MODEL }),
      head: "HEAD=62617368",
    },
  );
  assertStringIncludes(error?.message ?? "", "safeUpdate refused");
  assertStringIncludes(error?.message ?? "", "no #! line");
  assertEquals(calls.some((c) => c.startsWith("model:snapshotCt")), false);
  assertEquals(
    calls.some((c) => c.includes("/usr/bin/update") && !c.includes("od -An")),
    false,
  );
});

/** The generated community-scripts helper, as forgejo's CT has it since 2026. */
const GENERATED_HELPER = [
  "#!/usr/bin/env bash",
  "# Community-Scripts update entrypoint (generated - do not edit by hand).",
  'export SCRIPT_SLUG="forgejo"',
  'export UPDATE_SCRIPT_NAME="forgejo"',
  'export COMMUNITY_SCRIPTS_URL="https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main"',
  'export COMMUNITY_SCRIPTS_CORE_URL="https://raw.githubusercontent.com/community-scripts/core/main"',
  'export COMMUNITY_SCRIPTS_WEBSITE_URL="https://community-scripts.org"',
  "# Pull the shared helper; if it cannot be fetched, fall back to the legacy direct pull.",
  '_cs_helper="$(curl -fsSL --connect-timeout 10 "${COMMUNITY_SCRIPTS_CORE_URL}/misc/update.sh" 2>/dev/null)"',
  'if [[ -n "$_cs_helper" ]]; then',
  '  bash -c "$_cs_helper"',
  "else",
  '  bash -c "$(curl -fsSL "${COMMUNITY_SCRIPTS_URL}/ct/${UPDATE_SCRIPT_NAME}.sh")"',
  "fi",
].join("\n");
const CORE_UPDATE =
  "https://raw.githubusercontent.com/community-scripts/core/main/misc/update.sh";
const FORGEJO_CT =
  "https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/ct/forgejo.sh";

/** updateScriptProbeShell's output for this script text. */
function scriptOut(text: string): string {
  return text.split("\n").map((l) => `L:${l}`).join("\n") + "\nSCRIPT-END";
}

Deno.test("reach ssh: updateScriptUrls reads the URL of the legacy one-line helper", () => {
  assertEquals(
    updateScriptUrls(
      "/usr/bin/update",
      scriptOut(`#!/bin/sh\nbash -c "$(curl -fsSL ${CT_URL})"`),
    ),
    { ok: true, urls: [CT_URL], skipped: [] },
  );
});

Deno.test("reach ssh: updateScriptUrls resolves the generated helper's URLs from its own exports", () => {
  // Not the bare base URLs of the export lines (no curl there), and not $_cs_helper.
  assertEquals(
    updateScriptUrls("/usr/bin/update", scriptOut(GENERATED_HELPER)),
    { ok: true, urls: [CORE_UPDATE, FORGEJO_CT], skipped: [] },
  );
});

Deno.test("reach ssh: updateScriptUrls expands defaults, skips what it cannot resolve, and ignores comments", () => {
  const r = updateScriptUrls(
    "/u",
    scriptOut([
      "B=https://x.test/base",
      'curl -fsSL "${C:-https://x.test/default}/a.sh"',
      'curl -fsSL "${B:-https://x.test/default}/b.sh"',
      'curl -fsSL "$B/c.sh" "${UNSET}/d.sh"',
      'R="$(date)"',
      'curl -fsSL "${R}/e.sh"',
      "# curl https://x.test/commented.sh",
      "wget -qO- 'https://x.test/w.sh'",
      "echo https://x.test/not-fetched.sh",
    ].join("\n")),
  );
  assertEquals(r, {
    ok: true,
    urls: [
      "https://x.test/default/a.sh",
      "https://x.test/base/b.sh",
      "https://x.test/base/c.sh",
      "https://x.test/w.sh",
    ],
    skipped: ["${UNSET}/d.sh", "${R}/e.sh"],
  });
});

Deno.test("reach ssh: updateScriptUrls fails closed on output it cannot trust", () => {
  const refusal = (out: string) => {
    const r = updateScriptUrls("/usr/bin/update", out);
    return r.ok ? "" : r.refusal;
  };
  assertEquals(updateScriptUrls("/u", "ELF\nSCRIPT-END"), {
    ok: true,
    urls: [],
    skipped: [],
  });
  assertStringIncludes(refusal(`L:curl ${CT_URL}`), "could not read");
  assertStringIncludes(refusal("UNREADABLE\nSCRIPT-END"), "could not read");
  assertStringIncludes(refusal("TOOBIG\nSCRIPT-END"), "larger than");
  assertStringIncludes(
    refusal(scriptOut("curl https://x.test/{a}.sh")),
    "cannot fetch safely",
  );
  assertStringIncludes(
    refusal(
      scriptOut(
        Array.from({ length: 9 }, (_, i) => `curl https://x.test/${i}`).join(
          "\n",
        ),
      ),
    ),
    "more than 8 URLs",
  );
  // A script line that reads like a mark is still a script line.
  assertStringIncludes(refusal("L:SCRIPT-END"), "could not read");
});

Deno.test("reach ssh: updateUrlRefusal passes when each URL answers 2xx (fail closed)", () => {
  const bin = "/usr/bin/update";
  const urls = [CT_URL, CORE_UPDATE];
  const out = (body: string) => `${body}\nURLCHECK-END\n__SWAMP_RC__=0`;
  assertEquals(
    updateUrlRefusal(
      bin,
      out(`URL 200 ${CT_URL}\nURL 206 ${CORE_UPDATE}`),
      urls,
    ),
    null,
  );
  assertStringIncludes(
    updateUrlRefusal(
      bin,
      out(`URL 200 ${CT_URL}\nURL 404 ${CORE_UPDATE}`),
      urls,
    ) ??
      "",
    `${CORE_UPDATE}, which ${bin} fetches and runs, answered HTTP 404`,
  );
  assertStringIncludes(
    updateUrlRefusal(
      bin,
      out(`URL 000 ${CT_URL}\nURL 200 ${CORE_UPDATE}`),
      urls,
    ) ??
      "",
    "did not answer",
  );
  assertStringIncludes(
    updateUrlRefusal(
      bin,
      out(`URL 301 ${CT_URL}\nURL 200 ${CORE_UPDATE}`),
      urls,
    ) ??
      "",
    "answered HTTP 301",
  );
  assertStringIncludes(
    updateUrlRefusal(bin, out(`URL 200 ${CT_URL}`), urls) ?? "",
    `no answer for ${CORE_UPDATE}`,
  );
  assertStringIncludes(
    updateUrlRefusal(bin, `URL 200 ${CT_URL}\nURL 200 ${CORE_UPDATE}`, urls) ??
      "",
    "could not check",
  );
  assertStringIncludes(
    updateUrlRefusal(bin, out("NOCURL"), urls) ?? "",
    "has no curl",
  );
  assertStringIncludes(
    updateUrlRefusal(bin, out(`URL 2xx ${CT_URL}`), urls) ?? "",
    "could not read the URL check",
  );
});

Deno.test("reach ssh: updateNotRun finds a curl error or a removed-script line, and nothing else", () => {
  assertEquals(
    updateNotRun("curl: (22) The requested URL returned error: 404\n"),
    "curl: (22) The requested URL returned error: 404",
  );
  assertEquals(
    updateNotRun("Updating\ncurl: (6) Could not resolve host: x.test\ndone"),
    "curl: (6) Could not resolve host: x.test",
  );
  assertEquals(
    updateNotRun(
      " \x1b[01;31m✘\x1b[0m forgejo: this script has been removed from community-scripts.\n",
    ),
    "✘ forgejo: this script has been removed from community-scripts.",
  );
  assertEquals(
    updateNotRun(" ✘ No update script found for 'x' (https://x.test/ct/x.sh)"),
    "✘ No update script found for 'x' (https://x.test/ct/x.sh)",
  );
  assertEquals(updateNotRun("Updated successfully!\n"), null);
  assertEquals(updateNotRun("fetching with curl: ok\n"), null);
});

Deno.test("reach ssh: the URL check reads and fetches real scripts in a real shell", async () => {
  const dir = await Deno.makeTempDir();
  try {
    // A fake curl on PATH: 404 for a URL with "gone" in it, 200 for the rest. It records each
    // URL it is given.
    await Deno.mkdir(`${dir}/bin`);
    await Deno.writeTextFile(
      `${dir}/bin/curl`,
      [
        "#!/bin/sh",
        'for a; do u="$a"; done',
        'echo "$u" >> "$CURL_LOG"',
        'case "$u" in *gone*) printf 404 ;; *) printf 200 ;; esac',
      ].join("\n") + "\n",
    );
    await Deno.chmod(`${dir}/bin/curl`, 0o755);
    const files: Record<string, Uint8Array> = {
      "generated": new TextEncoder().encode(GENERATED_HELPER + "\n"),
      // The legacy helper, with no #! line and no newline at the end.
      "legacy-gone": new TextEncoder().encode(
        'bash -c "$(curl -fsSL https://x.test/ct/gone.sh)"',
      ),
      "query": new TextEncoder().encode("curl 'https://x.test/a?b'\n"),
      "star": new TextEncoder().encode("curl 'https://x.test/a?b*'\n"),
      "elf": new Uint8Array([
        0x7f,
        0x45,
        0x4c,
        0x46,
        ...new TextEncoder().encode(" curl https://x.test/gone"),
      ]),
      "big": new TextEncoder().encode("#".repeat(65537)),
    };
    for (const [n, b] of Object.entries(files)) {
      await Deno.writeFile(`${dir}/${n}`, b);
    }
    const sh = async (script: string, log: string) =>
      new TextDecoder().decode(
        (await new Deno.Command("sh", {
          args: ["-c", script],
          cwd: dir,
          env: { PATH: `${dir}/bin:${Deno.env.get("PATH")}`, CURL_LOG: log },
          stdout: "piped",
        }).output()).stdout,
      );
    const check = async (bin: string) => {
      const log = `${dir}/curl.log`;
      await Deno.writeTextFile(log, "");
      const found = updateScriptUrls(
        bin,
        await sh(updateScriptProbeShell(bin), log),
      );
      if (!found.ok) return { refusal: found.refusal, fetched: [] as string[] };
      const refusal = found.urls.length === 0 ? null : updateUrlRefusal(
        bin,
        await sh(urlFetchShell(found.urls), log),
        found.urls,
      );
      return {
        refusal,
        fetched: (await Deno.readTextFile(log)).split("\n").filter(Boolean),
      };
    };
    assertEquals(await check(`${dir}/generated`), {
      refusal: null,
      fetched: [CORE_UPDATE, FORGEJO_CT],
    });
    const gone = await check(`${dir}/legacy-gone`);
    assertStringIncludes(
      gone.refusal ?? "",
      "https://x.test/ct/gone.sh, which",
    );
    assertEquals(await check(`${dir}/query`), {
      refusal: null,
      fetched: ["https://x.test/a?b"],
    });
    assertStringIncludes(
      (await check(`${dir}/star`)).refusal ?? "",
      "cannot fetch safely",
    );
    assertEquals(await check(`${dir}/elf`), { refusal: null, fetched: [] });
    assertStringIncludes(
      (await check(`${dir}/big`)).refusal ?? "",
      "larger than",
    );
    assertStringIncludes(
      (await check(`${dir}/absent`)).refusal ?? "",
      "could not read",
    );
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("reach ssh: safeUpdate refuses before the snapshot when a URL the update runs is gone", async () => {
  const { calls, error } = await runSshSafeUpdate(
    { force: false, keepSnapshot: true, snapshot: true },
    {
      globalArgs: sshArgs({ ...SSH_APP, nodeModel: NODE_MODEL }),
      urls: `URL 404 ${CT_URL}\nURLCHECK-END`,
    },
  );
  assertStringIncludes(error?.message ?? "", "safeUpdate refused");
  assertStringIncludes(error?.message ?? "", "answered HTTP 404");
  assertEquals(calls.some((c) => c.startsWith("model:snapshotCt")), false);
  assertEquals(
    calls.some((c) => c.includes("/usr/bin/update") && !c.includes("od -An")),
    false,
  );
});

Deno.test("reach ssh: safeUpdate fetches the generated helper's resolved URLs before the snapshot", async () => {
  const { calls, error, result } = await runSshSafeUpdate(
    { force: false, keepSnapshot: true, snapshot: true },
    {
      globalArgs: sshArgs({ ...SSH_APP, nodeModel: NODE_MODEL }),
      script: scriptOut(GENERATED_HELPER),
      urls: `URL 200 ${CORE_UPDATE}\nURL 200 ${FORGEJO_CT}\nURLCHECK-END`,
    },
  );
  assertEquals(error, null);
  const fetch = calls.findIndex((c) => c.includes("URLCHECK-END"));
  const snap = calls.findIndex((c) => c.startsWith("model:snapshotCt"));
  assertEquals(fetch >= 0 && fetch < snap, true);
  assertStringIncludes(calls[fetch], `'${CORE_UPDATE}'`);
  assertStringIncludes(calls[fetch], `'${FORGEJO_CT}'`);
  assertEquals(result?.outcome, "updated");
});

Deno.test("reach ssh: safeUpdate rolls back when the update output has a curl error at rc 0", async () => {
  const { calls, error, result } = await runSshSafeUpdate(
    { force: false, keepSnapshot: true, snapshot: true },
    {
      globalArgs: sshArgs({ ...SSH_APP, nodeModel: NODE_MODEL }),
      updateOut: "curl: (22) The requested URL returned error: 404",
    },
  );
  assertStringIncludes(error?.message ?? "", "rolled back");
  assertStringIncludes(error?.message ?? "", "curl: (22)");
  assertEquals(
    calls.filter((c) => c.startsWith("model:rollbackCt")).length,
    1,
  );
  assertEquals(result?.outcome, "rolled-back");
  assertStringIncludes(String(result?.logs), "did not run fully");
});

Deno.test("reach ssh: safeUpdate rolls back when the helper says the app script was removed", async () => {
  const { error, result } = await runSshSafeUpdate(
    { force: false, keepSnapshot: true, snapshot: true },
    {
      globalArgs: sshArgs({ ...SSH_APP, nodeModel: NODE_MODEL }),
      updateOut:
        " ✘ app: this script has been removed from community-scripts.\n   There is no update to install.",
    },
  );
  assertStringIncludes(error?.message ?? "", "removed from community-scripts");
  assertEquals(result?.outcome, "rolled-back");
});

Deno.test("reach ssh: safeUpdate snapshot:false records a curl error as failed, not no-change", async () => {
  const { error, result } = await runSshSafeUpdate(
    { force: false, keepSnapshot: true, snapshot: false },
    { updateOut: "curl: (22) The requested URL returned error: 404" },
  );
  assertStringIncludes(error?.message ?? "", "curl");
  assertEquals(result?.outcome, "failed");
});
