import {
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import {
  createModelTestContext,
  withMockedCommand,
  withMockedFetch,
} from "jsr:@systeminit/swamp-testing";
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
  sshModel: "infra-ssh",
  node: "fort",
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
      sshModel: "infra-ssh",
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
    globalArgs: { sshModel: "infra-ssh", appName: "TestApp", app: "testapp" },
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
