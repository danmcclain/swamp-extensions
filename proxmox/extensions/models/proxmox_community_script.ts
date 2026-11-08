/**
 * Manage Proxmox VE community-scripts LXC containers with a safe, atomic update:
 * snapshot the container, run the in-container `update` helper, validate that the
 * app comes back healthy, and roll back to the snapshot automatically if it does
 * not.
 *
 * All Proxmox operations run on the hypervisor node via `pct` (snapshot / exec /
 * rollback). Because the PVE API cannot run a command *inside* an LXC, shell
 * access to the node is required. Rather than opening its own SSH connection,
 * this model delegates to a `@swamp/ssh` model instance (named by `sshModel`,
 * required): it shells out to `swamp model method run <sshModel> exec`
 * so SSH transport, auth, and host-key handling live in one place.
 *
 * With `reach: "ssh"` the model never needs the node: it reaches the container
 * itself (`ctHost`, a host in the sshModel) as a non-root login. Health and
 * version probes run as that login; the update runs as ONE exact command through
 * `sudo -n` (the `privileges` method declares it, so @dmc/patch can grant just
 * that); snapshots, rollbacks and deletes go through `nodeModel`, a
 * @dmc/proxmox/node model with a limited API token. Install stays pct only.
 *
 * Prerequisites for the consumer:
 *   - the `@swamp/ssh` extension installed and an instance configured whose host
 *     list includes the PVE node named by `node`;
 *   - the `swamp` binary on PATH (override with the `SWAMP_BIN` env var);
 *   - the target LXC created by the Proxmox VE community-scripts project (it
 *     provides the in-container `/usr/bin/update` helper).
 *
 * One model instance == one container.
 *
 * @module
 */
import { z } from "npm:zod@4";

/** Minimal LogTape-style logger supplied by swamp as `context.logger`. */
type Logger = {
  debug(message: string, props?: Record<string, unknown>): void;
  info(message: string, props?: Record<string, unknown>): void;
  warn(message: string, props?: Record<string, unknown>): void;
  error(message: string, props?: Record<string, unknown>): void;
};

const SWAMP_BIN = Deno.env.get("SWAMP_BIN") ?? "swamp";
const RC_SENTINEL = "__SWAMP_RC__";

const GlobalArgsSchema = z.object({
  sshModel: z.string().min(1).describe(
    "Name of the @swamp/ssh model instance used to reach the PVE node (required, no default)",
  ),
  node: z.string().min(1).optional().describe(
    'Fleet host name (a host in the sshModel) of the PVE hypervisor running the container, e.g. "pve1". Required with reach pct for every method except discoverApp/previewInstall (which only read the community-scripts sources).',
  ),
  reach: z.enum(["pct", "ssh"]).default("pct").describe(
    "How the container is reached: pct (default) runs every command as root through pct on `node`; ssh reaches the container itself (`ctHost`) as a non-root login, runs the update through `sudo -n` with one exact command (see the privileges method), and takes snapshots only through `nodeModel`",
  ),
  ctHost: z.string().min(1).optional().describe(
    "With reach ssh: the container's own host name in the sshModel (required there)",
  ),
  nodeModel: z.string().min(1).optional().describe(
    "A @dmc/proxmox/node model whose API token may snapshot this CT. When set, snapshots, rollbacks, deletes and snapshot lists go through its snapshotCt / rollbackCt / deleteCtSnapshot / listCtSnapshots instead of pct. With reach ssh it is the only way to take a snapshot",
  ),
  ctid: z.number().int().positive().optional().describe(
    "LXC container ID, e.g. 601. Required for every method except discoverApp/previewInstall.",
  ),
  appName: z.string().default("app").describe(
    'Human-readable app name for logs/output, e.g. "Forgejo"',
  ),
  service: z.string().min(1).optional().describe(
    'systemd unit inside the container to health-check, e.g. "forgejo". Required for every method except discoverApp/previewInstall.',
  ),
  serviceActiveCommand: z.string().optional().describe(
    'Command run inside the container (via `sh -c`) whose exit 0 means the service is up. Overrides the default `systemctl is-active <service>` — set this for non-systemd containers, e.g. Alpine/OpenRC: "rc-service <service> status".',
  ),
  updateCommand: z.string().default("PHS_SILENT=1 /usr/bin/update").describe(
    "Command run inside the container (via `bash -lc`) to perform the update. Default runs the community-scripts helper in forced-silent mode (PHS_SILENT=1) so it never prompts. Add `var_ignore_os_mismatch=1` here to bypass the OS-version guard. With reach ssh it is not run by a shell: it must be `[NAME=value ...] /absolute/bin [args]` (values A-Za-z0-9._/:=+-), and runs as exactly that argv through `sudo -n` (env pairs through env).",
  ),
  versionCommand: z.string().optional().describe(
    'Optional command run inside the container to capture a version string before/after, e.g. "forgejo --version"',
  ),
  versionRegex: z.string().default("(\\d+\\.\\d+\\.\\d+)").describe(
    "Regex (first capture group) used to extract a comparable semver from the versionCommand output and the release tag",
  ),
  releaseApiUrl: z.string().url().optional().describe(
    "Optional release API URL whose JSON `tag_name` is the latest upstream version, e.g. https://codeberg.org/api/v1/repos/forgejo/forgejo/releases/latest . When set, status/checkUpdate report whether an update is available.",
  ),
  osManaged: z.boolean().default(false).describe(
    "True when the app binary is delivered by the container's OS package manager (apk/apt/dnf), " +
      "not by this updater fetching an upstream release. When true, `latestVersion` is the package " +
      "manager's available candidate (the actionable update), the releaseApiUrl version is reported " +
      "separately as `upstreamVersion` (informational drift), and `updateAvailable` compares installed " +
      "against the package candidate — so an upstream release the repo doesn't ship isn't flagged installable.",
  ),
  packageName: z.string().optional().describe(
    "OS package to query for the available version when osManaged (apk/apt-cache/dnf). Defaults to `app` then `service`.",
  ),
  healthUrl: z.string().url().optional().describe(
    "Optional HTTP(S) URL probed from the swamp host after update to confirm the app is serving",
  ),
  healthExpectStatus: z.number().int().default(200).describe(
    "HTTP status the healthUrl must return to be considered healthy",
  ),
  updateTimeoutSec: z.number().int().default(900).describe(
    "Seconds allowed for the in-container update command to finish",
  ),
  healthTimeoutSec: z.number().int().default(180).describe(
    "Seconds to wait for the app to become healthy again after update",
  ),
  pollIntervalSec: z.number().int().default(5).describe(
    "Seconds between health polls",
  ),
  app: z.string().optional().describe(
    'community-scripts app slug for the `install` method, e.g. "forgejo" (resolves to <ctScriptBaseUrl>/ct/<app>.sh). Only LXC (ct/*.sh) scripts support headless install; VM (vm/*.sh) scripts are interactive-only — use @dmc/proxmox/vm createFromImage instead.',
  ),
  ctScriptBaseUrl: z.string().url().default(
    "https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main",
  ).describe(
    "Base URL for community-scripts; the LXC script is <ctScriptBaseUrl>/ct/<app>.sh and build.func is <ctScriptBaseUrl>/misc/build.func",
  ),
  installVars: z.record(z.string(), z.string()).default({}).describe(
    'Freeform community-scripts var_* overrides passed as env to the install (e.g. {"var_cpu":"2","var_ram":"2048","var_disk":"10","var_hostname":"forgejo"}). Keys must match var_[a-z0-9_]+. Validated (warn-only) against the var_* names discovered in build.func; the app\'s own defaults come from its ct script.',
  ),
  installTimeoutSec: z.number().int().default(1800).describe(
    "Seconds allowed for the community-scripts install to finish (downloads + builds)",
  ),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

/** Global args with the container-management fields guaranteed present. `node` is
 *  set with reach pct, `ctHost` with reach ssh. */
type ManageArgs = GlobalArgs & { ctid: number; service: string };

/** True when the container is reached over ssh (reach ssh) rather than pct. */
function viaSsh(ga: GlobalArgs): boolean {
  return ga.reach === "ssh";
}

/** The global args a managed container needs for its reach: node (pct) or ctHost (ssh),
 *  plus ctid and service. */
function missingManageArgs(ga: GlobalArgs): string[] {
  const missing: string[] = [];
  if (viaSsh(ga)) {
    if (!ga.ctHost) missing.push("ctHost");
  } else if (!ga.node) missing.push("node");
  if (ga.ctid === undefined) missing.push("ctid");
  if (!ga.service) missing.push("service");
  return missing;
}

/** Where the container is reached, for records and logs: the node (pct) or ctHost (ssh). */
function placeOf(ga: ManageArgs): string {
  return (viaSsh(ga) ? ga.ctHost : ga.node) ?? "";
}

/**
 * Assert the container-management global args (node or ctHost, ctid, service) are
 * set, and narrow the type. discoverApp/previewInstall don't call this — they only
 * read the community-scripts sources and need just `app`.
 */
function requireManage(ga: GlobalArgs): ManageArgs {
  const missing = missingManageArgs(ga);
  if (missing.length > 0) {
    throw new Error(
      `This method requires global args: ${
        missing.join(", ")
      }. (discoverApp and previewInstall only need \`app\`.)`,
    );
  }
  return ga as ManageArgs;
}

const SnapshotSchema = z.object({
  name: z.string(),
  description: z.string().nullable(),
});

const StateSchema = z.object({
  name: z.string(),
  node: z.string(),
  ctid: z.number(),
  running: z.boolean(),
  serviceActive: z.boolean(),
  version: z.string().nullable(),
  installedVersion: z.string().nullable(),
  latestVersion: z.string().nullable(),
  upstreamVersion: z.string().nullable(),
  updateAvailable: z.boolean().nullable(),
  osManaged: z.boolean(),
  healthy: z.boolean(),
  healthUrl: z.string().nullable(),
  httpStatus: z.number().nullable(),
  snapshots: z.array(SnapshotSchema),
  checkedAt: z.iso.datetime(),
});

const UpdateResultSchema = z.object({
  name: z.string(),
  node: z.string(),
  ctid: z.number(),
  outcome: z.enum(["updated", "no-change", "rolled-back", "skipped", "failed"]),
  /** Snapshot name, or null when none is kept or none was taken. */
  snapshot: z.string().nullable(),
  /** False when the caller passed `snapshot: false` (the caller owns the snapshot). */
  snapshotTaken: z.boolean().default(true),
  healthyBefore: z.boolean(),
  healthyAfter: z.boolean(),
  beforeVersion: z.string().nullable(),
  afterVersion: z.string().nullable(),
  versionChanged: z.boolean(),
  rolledBack: z.boolean(),
  updateOutput: z.string(),
  logs: z.string(),
  timestamp: z.iso.datetime(),
});

const UpdateCheckSchema = z.object({
  name: z.string(),
  node: z.string(),
  ctid: z.number(),
  installedVersion: z.string().nullable(),
  latestVersion: z.string().nullable(),
  upstreamVersion: z.string().nullable(),
  updateAvailable: z.boolean().nullable(),
  osManaged: z.boolean(),
  checkedAt: z.iso.datetime(),
});

const InstallResultSchema = z.object({
  name: z.string(),
  node: z.string(),
  ctid: z.number(),
  app: z.string(),
  scriptUrl: z.string(),
  created: z.boolean(),
  running: z.boolean(),
  serviceActive: z.boolean(),
  healthy: z.boolean(),
  httpStatus: z.number().nullable(),
  version: z.string().nullable(),
  unknownVars: z.array(z.string()),
  output: z.string(),
  logs: z.string(),
  timestamp: z.iso.datetime(),
});

const DiscoverySchema = z.object({
  name: z.string(),
  app: z.string(),
  scriptUrl: z.string(),
  appDefaults: z.record(z.string(), z.string()),
  recognizedVars: z.array(z.string()),
  vars: z.array(z.object({
    name: z.string(),
    default: z.string().nullable(),
    description: z.string().nullable(),
    group: z.string().nullable(),
  })),
  checkedAt: z.iso.datetime(),
});

const PreviewSchema = z.object({
  name: z.string(),
  app: z.string(),
  ctScriptUrl: z.string(),
  installScriptUrl: z.string(),
  os: z.string().nullable(),
  version: z.string().nullable(),
  cpu: z.string().nullable(),
  ram: z.string().nullable(),
  disk: z.string().nullable(),
  unprivileged: z.string().nullable(),
  tags: z.string().nullable(),
  exposedPort: z.string().nullable(),
  steps: z.array(z.string()),
  packages: z.array(z.string()),
  downloads: z.array(z.string()),
  services: z.array(z.string()),
  summary: z.string(),
  checkedAt: z.iso.datetime(),
});

/** Result of a single remote command run on the PVE node. */
interface NodeResult {
  rc: number;
  out: string;
  stderr: string;
}

/**
 * Run a shell command on the PVE node through the `@swamp/ssh` fleet model.
 *
 * The remote command is wrapped so it always exits 0 and self-reports its real
 * return code on the last line (`__SWAMP_RC__=<n>`). This is required because
 * `@swamp/ssh` treats a non-zero remote exit as a method failure and throws,
 * which would make it impossible to read the output of probes that legitimately
 * return non-zero (e.g. `systemctl is-active` on a stopped unit).
 */
async function nodeExec(
  ga: ManageArgs,
  repoDir: string,
  command: string,
  timeoutSec: number,
): Promise<NodeResult> {
  if (!ga.node) {
    throw new Error(
      viaSsh(ga)
        ? "reach ssh never runs a command on the node; this step needs reach pct"
        : "global arg node is not set",
    );
  }
  return await sshExec(ga, "node", ga.node, repoDir, command, timeoutSec);
}

/** Run a command inside the container: as the ssh login on ctHost (reach ssh), or as root
 *  through `pct exec <ctid> --` on the node (reach pct). `argv` is a shell word list that
 *  is safe both ways (pct exec runs it without a shell; ssh runs it through the login's
 *  shell). */
async function ctExec(
  ga: ManageArgs,
  repoDir: string,
  argv: string,
  timeoutSec: number,
): Promise<NodeResult> {
  if (viaSsh(ga)) {
    return await sshExec(
      ga,
      "container",
      ga.ctHost!,
      repoDir,
      argv,
      timeoutSec,
    );
  }
  return await nodeExec(
    ga,
    repoDir,
    `pct exec ${ga.ctid} -- ${argv}`,
    timeoutSec,
  );
}

/** Run a shell command on one host of the sshModel (the node, or the container itself). */
async function sshExec(
  ga: GlobalArgs,
  what: "node" | "container",
  host: string,
  repoDir: string,
  command: string,
  timeoutSec: number,
): Promise<NodeResult> {
  const wrapped = `{ ${command}; } 2>&1; printf '\\n${RC_SENTINEL}=%s\\n' "$?"`;
  // @ts-ignore - Deno API
  const proc = new Deno.Command(SWAMP_BIN, {
    args: [
      "model",
      "method",
      "run",
      ga.sshModel,
      "exec",
      "--json",
      "--quiet",
      "--repo-dir",
      repoDir,
      "--input",
      `hosts:json=[${JSON.stringify(host)}]`,
      "--input",
      `command=${wrapped}`,
      "--input",
      "captureOutput:json=true",
      "--input",
      `timeoutSec:json=${timeoutSec}`,
    ],
    stdout: "piped",
    stderr: "piped",
  });
  const result = await proc.output();
  const stdout = new TextDecoder().decode(result.stdout);
  const stderr = new TextDecoder().decode(result.stderr);
  if (result.code !== 0) {
    // Non-zero here means the transport itself failed (host unreachable,
    // Tailscale re-auth needed, model error) — the remote command can't fail
    // the CLI because we wrapped it to always exit 0.
    throw new Error(
      `SSH transport to ${what} "${host}" via ${ga.sshModel} failed (exit ${result.code}): ${
        stderr.slice(-800)
      }`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error(
      `Could not parse ${ga.sshModel} exec output: ${stdout.slice(-800)}`,
    );
  }
  const attrs = (parsed as {
    dataArtifacts?: Array<
      { attributes?: { stdout?: string; stderr?: string; exitCode?: number } }
    >;
  }).dataArtifacts?.[0]?.attributes;
  const raw = attrs?.stdout ?? "";
  const match = raw.match(new RegExp(`${RC_SENTINEL}=(\\d+)\\s*$`));
  const rc = match ? parseInt(match[1], 10) : (attrs?.exitCode ?? -1);
  const out = match ? raw.slice(0, match.index).replace(/\n$/, "") : raw;
  return { rc, out: out.trim(), stderr: attrs?.stderr ?? "" };
}

/** True when the container runs: `pct status <ctid>` says running (reach pct), or the
 *  container answers over ssh (reach ssh; a failed transport is "not running", since a
 *  container that is starting or rolled back does not answer yet). */
async function isRunning(ga: ManageArgs, repoDir: string): Promise<boolean> {
  if (viaSsh(ga)) {
    try {
      return (await ctExec(ga, repoDir, "true", 30)).rc === 0;
    } catch {
      return false;
    }
  }
  const r = await nodeExec(ga, repoDir, `pct status ${ga.ctid}`, 30);
  return /status:\s*running/i.test(r.out);
}

/** The result of one run of another swamp model through the CLI. */
type ModelRun =
  | { ok: true; attributes: Record<string, unknown> | null }
  | { ok: false; error: string };

/** Run a method of the `nodeModel` (a @dmc/proxmox/node instance) through the swamp CLI.
 *  Never throws: a failed run comes back as `ok: false` with the CLI's error output. */
async function nodeModelRun(
  ga: GlobalArgs,
  repoDir: string,
  method: string,
  inputs: Record<string, string | number | boolean>,
): Promise<ModelRun> {
  if (!ga.nodeModel) return { ok: false, error: "nodeModel is not set" };
  const args = [
    "model",
    "method",
    "run",
    ga.nodeModel,
    method,
    "--json",
    "--quiet",
    "--repo-dir",
    repoDir,
  ];
  for (const [k, v] of Object.entries(inputs)) {
    args.push(
      "--input",
      typeof v === "string" ? `${k}=${v}` : `${k}:json=${JSON.stringify(v)}`,
    );
  }
  try {
    // @ts-ignore - Deno API
    const proc = new Deno.Command(SWAMP_BIN, {
      args,
      stdout: "piped",
      stderr: "piped",
    });
    const result = await proc.output();
    const stdout = new TextDecoder().decode(result.stdout);
    if (result.code !== 0) {
      const stderr = new TextDecoder().decode(result.stderr);
      return {
        ok: false,
        error: `${ga.nodeModel} ${method} failed (exit ${result.code}): ${
          (stderr || stdout).slice(-600)
        }`,
      };
    }
    const parsed = JSON.parse(stdout) as {
      dataArtifacts?: Array<{ attributes?: Record<string, unknown> }>;
    };
    return {
      ok: true,
      attributes: parsed.dataArtifacts?.[0]?.attributes ?? null,
    };
  } catch (err) {
    return {
      ok: false,
      error: `${ga.nodeModel} ${method}: ${(err as Error).message}`,
    };
  }
}

/**
 * True when the service is active inside the container. Uses
 * `serviceActiveCommand` (exit 0 == active) when set — for non-systemd
 * containers such as Alpine/OpenRC (`rc-service <svc> status`) — otherwise
 * defaults to `systemctl is-active <service>`.
 */
async function isServiceActive(
  ga: ManageArgs,
  repoDir: string,
): Promise<boolean> {
  if (ga.serviceActiveCommand) {
    const r = await ctExec(
      ga,
      repoDir,
      `sh -c ${shSingleQuote(ga.serviceActiveCommand)}`,
      30,
    );
    return r.rc === 0;
  }
  const r = await ctExec(
    ga,
    repoDir,
    `systemctl is-active ${shSingleQuote(ga.service)}`,
    30,
  );
  return r.rc === 0 && r.out.split("\n").pop()?.trim() === "active";
}

/** Capture the app version string via the configured versionCommand, or null. */
async function readVersion(
  ga: ManageArgs,
  repoDir: string,
): Promise<string | null> {
  if (!ga.versionCommand) return null;
  // Non-login shell (`sh -c`, not `-lc`) so the container's /etc/profile.d MOTD
  // banner is NOT sourced — the banner would otherwise inject lines (e.g. an IP
  // address) that the semver regex could match. Because there is no banner,
  // versionCommand must use absolute paths (PATH is minimal). Keep the last
  // non-empty line so a command that emits a single clean version line works
  // regardless of any leading noise.
  try {
    const r = await ctExec(
      ga,
      repoDir,
      `sh -c ${shSingleQuote(ga.versionCommand)}`,
      60,
    );
    if (r.rc !== 0) return null;
    const lines = r.out.split("\n").map((l) => l.trim()).filter((l) =>
      l.length > 0
    );
    return lines.length > 0 ? lines[lines.length - 1] : null;
  } catch {
    // A slow/failed version probe must not crash status/checkUpdate.
    return null;
  }
}

/** Probe the optional health URL from the swamp host. Returns null when unset. */
async function probeHttp(ga: GlobalArgs): Promise<number | null> {
  if (!ga.healthUrl) return null;
  try {
    const res = await fetch(ga.healthUrl, {
      redirect: "manual",
      signal: AbortSignal.timeout(15000),
    });
    // Drain the body so the connection can close.
    await res.body?.cancel();
    return res.status;
  } catch {
    return 0;
  }
}

/** Extract a comparable semver (first capture group) from a version string. */
export function extractSemver(
  raw: string | null,
  regex: string,
): string | null {
  if (!raw) return null;
  const m = raw.match(new RegExp(regex));
  return m ? (m[1] ?? m[0]) : null;
}

/** Compare dotted numeric versions. Returns -1, 0, or 1 (a vs b). */
export function cmpSemver(a: string, b: string): number {
  const pa = a.split(".").map((n) => parseInt(n, 10) || 0);
  const pb = b.split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/** Fetch the latest upstream version from the configured release API (JSON `tag_name`). */
async function fetchLatestVersion(ga: GlobalArgs): Promise<string | null> {
  if (!ga.releaseApiUrl) return null;
  try {
    const res = await fetch(ga.releaseApiUrl, {
      headers: { "accept": "application/json" },
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) {
      await res.body?.cancel();
      return null;
    }
    const body = await res.json() as { tag_name?: string };
    return extractSemver(body.tag_name ?? null, ga.versionRegex);
  } catch {
    return null;
  }
}

/**
 * The available candidate version of the app's OS package (apk / apt / dnf), or
 * null. Used when osManaged so `latestVersion` reflects what the package manager
 * can actually install, not an upstream release the repo doesn't ship.
 */
async function packageManagerVersion(
  ga: ManageArgs,
  repoDir: string,
): Promise<string | null> {
  const pkg = ga.packageName ?? ga.app ?? ga.service;
  if (!pkg) return null;
  const cmd = `if command -v apk >/dev/null 2>&1; then apk policy ${pkg}; ` +
    `elif command -v apt-cache >/dev/null 2>&1; then apt-cache policy ${pkg}; ` +
    `elif command -v dnf >/dev/null 2>&1; then dnf --quiet list ${pkg} 2>/dev/null; fi`;
  try {
    const r = await ctExec(
      ga,
      repoDir,
      `sh -c ${shSingleQuote(cmd)}`,
      60,
    );
    if (r.rc !== 0) return null;
    // Return the highest semver in the output (the candidate the manager would install).
    const versions = [...r.out.matchAll(/(\d+\.\d+\.\d+)/g)].map((m) => m[1]);
    if (versions.length === 0) return null;
    versions.sort(cmpSemver);
    return versions[versions.length - 1];
  } catch {
    return null;
  }
}

/**
 * Compute update availability. For a fetch-managed app (default), `latestVersion`
 * is the upstream release (releaseApiUrl) and drives `updateAvailable`. For an
 * osManaged app, `latestVersion` is the OS package manager's candidate (the
 * actionable update) and the upstream release is reported separately as
 * `upstreamVersion` (informational drift). Never guesses — nulls when unknown.
 */
async function computeUpdate(
  ga: ManageArgs,
  rawVersion: string | null,
  repoDir: string,
): Promise<
  {
    installedVersion: string | null;
    latestVersion: string | null;
    upstreamVersion: string | null;
    updateAvailable: boolean | null;
    osManaged: boolean;
  }
> {
  const installedVersion = extractSemver(rawVersion, ga.versionRegex);
  const upstream = await fetchLatestVersion(ga);
  let latestVersion: string | null;
  let upstreamVersion: string | null;
  let updateAvailable: boolean | null = null;
  if (ga.osManaged) {
    latestVersion = await packageManagerVersion(ga, repoDir);
    upstreamVersion = upstream; // informational drift
    if (installedVersion && latestVersion) {
      updateAvailable = cmpSemver(latestVersion, installedVersion) > 0;
    }
  } else {
    latestVersion = upstream; // the upstream release IS what gets installed
    upstreamVersion = null;
    if (installedVersion && latestVersion) {
      updateAvailable = cmpSemver(latestVersion, installedVersion) > 0;
    }
  }
  return {
    installedVersion,
    latestVersion,
    upstreamVersion,
    updateAvailable,
    osManaged: ga.osManaged,
  };
}

/** Best-effort fetch of a text resource (script, build.func). Null on any error. */
async function fetchText(url: string): Promise<string | null> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) {
      await res.body?.cancel();
      return null;
    }
    return await res.text();
  } catch {
    return null;
  }
}

/**
 * Discover, by reading the community-scripts sources, (a) the app's own default
 * `var_*` settings from its ct script header and (b) the universe of `var_*`
 * names that build.func recognizes. Used to validate freeform installVars and to
 * surface what is configurable without hand-maintaining a list.
 */
/** Parse an app's ct script header for its default `var_*` settings. */
function parseAppDefaults(script: string): Record<string, string> {
  const appDefaults: Record<string, string> = {};
  // App scripts declare defaults like: var_cpu="${var_cpu:-2}"
  for (
    const m of script.matchAll(
      /^\s*(var_[a-z0-9_]+)="?\$\{[^:]*:-([^}"']*)\}/gm,
    )
  ) {
    appDefaults[m[1]] = m[2];
  }
  // ...and plain assignments like: var_os="debian"
  for (
    const m of script.matchAll(
      /^\s*(var_[a-z0-9_]+)=["']?([A-Za-z0-9._-]+)["']?\s*$/gm,
    )
  ) {
    if (!(m[1] in appDefaults)) appDefaults[m[1]] = m[2];
  }
  return appDefaults;
}

/** Per-var documentation parsed from build.func's default.vars template. */
interface VarDoc {
  description: string | null;
  group: string | null;
}

/**
 * Parse build.func's `default.vars` scaffold for per-`var_*` docs: the section
 * headers (`# Resources`, `# Network`, `# Advanced Settings`, …) become `group`,
 * and inline `# ...` comments after a `var_x=` line become `description`. Bounded
 * to the template block so unrelated `var_x=` assignments elsewhere in build.func
 * don't pollute the groups. Best-effort — missing docs are left null.
 */
function parseVarDocs(buildFunc: string): Record<string, VarDoc> {
  const out: Record<string, VarDoc> = {};
  const start = buildFunc.indexOf("# Container type");
  if (start === -1) return out;
  const rest = buildFunc.slice(start);
  const end = rest.indexOf("\nEOF");
  const block = end === -1 ? rest : rest.slice(0, end);

  let group: string | null = null;
  for (const raw of block.split("\n")) {
    const line = raw.trim();
    if (line.length === 0) continue;
    // Section header: a comment with no '=' and no var_ reference.
    const header = line.match(/^#\s*([A-Za-z][A-Za-z0-9 /()+.,'-]*)$/);
    if (header && !line.includes("var_") && !line.includes("=")) {
      group = header[1].trim();
      continue;
    }
    // A var line (possibly commented out), with an optional inline description.
    const v = line.match(
      /^#?\s*(var_[a-z0-9_]+)\s*=[^#\n]*?(?:#\s*(.+?))?\s*$/,
    );
    if (v) {
      const name = v[1];
      const desc = v[2] ? v[2].trim() : null;
      if (!(name in out)) out[name] = { description: desc, group };
      else if (desc && !out[name].description) out[name].description = desc;
    }
  }
  return out;
}

async function discoverVars(
  baseUrl: string,
  app: string,
): Promise<{
  appDefaults: Record<string, string>;
  recognizedVars: string[];
  varDocs: Record<string, VarDoc>;
}> {
  const script = await fetchText(`${baseUrl}/ct/${app}.sh`);
  const appDefaults = script ? parseAppDefaults(script) : {};
  const buildFunc = await fetchText(`${baseUrl}/misc/build.func`);
  const recognized = new Set<string>();
  const varDocs = buildFunc ? parseVarDocs(buildFunc) : {};
  if (buildFunc) {
    for (const m of buildFunc.matchAll(/\bvar_[a-z0-9_]+\b/g)) {
      recognized.add(m[0]);
    }
  }
  return { appDefaults, recognizedVars: [...recognized].sort(), varDocs };
}

/** Distinct, order-preserving list. */
function uniq(items: string[]): string[] {
  return [...new Set(items.filter((s) => s.length > 0))];
}

/**
 * Inspect an app's ct + install scripts and summarize what installing it will
 * do — provisioning defaults, the narrated steps (msg_info), packages, release
 * downloads, and services — WITHOUT running anything. Best-effort parsing:
 * fields are empty when not found, never fabricated.
 */
async function summarizeInstall(
  baseUrl: string,
  app: string,
): Promise<{
  ctScriptUrl: string;
  installScriptUrl: string;
  os: string | null;
  version: string | null;
  cpu: string | null;
  ram: string | null;
  disk: string | null;
  unprivileged: string | null;
  tags: string | null;
  exposedPort: string | null;
  steps: string[];
  packages: string[];
  downloads: string[];
  services: string[];
  summary: string;
}> {
  const ctScriptUrl = `${baseUrl}/ct/${app}.sh`;
  const installScriptUrl = `${baseUrl}/install/${app}-install.sh`;
  const ct = await fetchText(ctScriptUrl);
  const inst = await fetchText(installScriptUrl);
  const d = ct ? parseAppDefaults(ct) : {};

  // Exposed port from the ct footer, e.g. echo -e "...http://${IP}:3000..."
  const portMatch = ct?.match(/\$\{?IP\}?:(\d{2,5})/);
  const exposedPort = portMatch ? portMatch[1] : null;

  const steps: string[] = [];
  const packages: string[] = [];
  const downloads: string[] = [];
  const services: string[] = [];

  if (inst) {
    // The scripts narrate their own steps.
    for (const m of inst.matchAll(/msg_info\s+"([^"]+)"/g)) steps.push(m[1]);
    // Package installs (apt/apt-get/dnf ... install -y <pkgs>).
    for (
      const m of inst.matchAll(
        /(?:apt(?:-get)?|dnf|yum|apk)\s+(?:-[^\s]+\s+)*(?:install|add)\s+(?:-[^\s]+\s+)*([^\n&|;]+)/g,
      )
    ) {
      for (const tok of m[1].split(/\s+/)) {
        if (
          /^[a-z0-9][a-z0-9._+-]*$/i.test(tok) && !tok.startsWith("-") &&
          tok !== "y"
        ) {
          packages.push(tok);
        }
      }
    }
    // Release downloads via the community-scripts helpers.
    for (
      const m of inst.matchAll(
        /fetch_and_deploy_(gh|codeberg)_release\s+"[^"]*"\s+"([^"]+)"/g,
      )
    ) {
      downloads.push(`${m[2]} (${m[1] === "gh" ? "github" : "codeberg"})`);
    }
    // Services enabled/started.
    for (
      const m of inst.matchAll(
        /systemctl\s+(?:-[^\s]+\s+)*(?:enable|start|restart)\s+(?:-[^\s]+\s+)*([a-zA-Z0-9@._-]+)/g,
      )
    ) {
      services.push(m[1].replace(/\.service$/, ""));
    }
  }

  const os = d.var_os ?? null;
  const version = d.var_version ?? null;
  const cpu = d.var_cpu ?? null;
  const ram = d.var_ram ?? null;
  const disk = d.var_disk ?? null;
  const unprivileged = d.var_unprivileged ?? null;
  const tags = d.var_tags ?? null;

  const provisioning = [
    os && version ? `${os} ${version}` : os,
    unprivileged === "0" ? "privileged LXC" : "unprivileged LXC",
    [cpu && `${cpu} CPU`, ram && `${ram}MB RAM`, disk && `${disk}GB disk`]
      .filter(Boolean).join(" / "),
  ].filter(Boolean).join(", ");

  const summaryParts = [
    `Provisions a ${
      provisioning || "community-scripts LXC"
    } and installs ${app}.`,
  ];
  if (steps.length) {
    summaryParts.push(
      `Steps: ${steps.slice(0, 8).join("; ")}${steps.length > 8 ? "; …" : ""}.`,
    );
  }
  if (uniq(downloads).length) {
    summaryParts.push(`Fetches: ${uniq(downloads).join(", ")}.`);
  }
  if (uniq(services).length) {
    summaryParts.push(`Services: ${uniq(services).join(", ")}.`);
  }
  if (exposedPort) summaryParts.push(`Listens on port ${exposedPort}.`);
  if (!inst) {
    summaryParts.push(
      `(Could not fetch ${installScriptUrl} — in-container steps unknown.)`,
    );
  }

  return {
    ctScriptUrl,
    installScriptUrl,
    os,
    version,
    cpu,
    ram,
    disk,
    unprivileged,
    tags,
    exposedPort,
    steps,
    packages: uniq(packages),
    downloads: uniq(downloads),
    services: uniq(services),
    summary: summaryParts.join(" "),
  };
}

/** Composite health: running + service active + (if configured) HTTP status matches. */
async function checkHealth(
  ga: ManageArgs,
  repoDir: string,
): Promise<
  {
    healthy: boolean;
    running: boolean;
    serviceActive: boolean;
    httpStatus: number | null;
  }
> {
  const running = await isRunning(ga, repoDir);
  const serviceActive = running ? await isServiceActive(ga, repoDir) : false;
  const httpStatus = await probeHttp(ga);
  const httpOk = ga.healthUrl ? httpStatus === ga.healthExpectStatus : true;
  return {
    healthy: running && serviceActive && httpOk,
    running,
    serviceActive,
    httpStatus,
  };
}

/** Wait until healthy or the timeout elapses. */
async function waitForHealth(
  ga: ManageArgs,
  repoDir: string,
  log: (m: string) => void,
): Promise<
  {
    healthy: boolean;
    running: boolean;
    serviceActive: boolean;
    httpStatus: number | null;
  }
> {
  const deadline = Date.now() + ga.healthTimeoutSec * 1000;
  let last = await checkHealth(ga, repoDir);
  while (!last.healthy && Date.now() < deadline) {
    log(
      `not healthy yet (running=${last.running} service=${last.serviceActive} http=${
        last.httpStatus ?? "n/a"
      }), waiting ${ga.pollIntervalSec}s`,
    );
    await new Promise((r) => setTimeout(r, ga.pollIntervalSec * 1000));
    last = await checkHealth(ga, repoDir);
  }
  return last;
}

/** Parse `pct listsnapshot` output into snapshot entries (skips "current"). */
function parseSnapshots(out: string): Array<z.infer<typeof SnapshotSchema>> {
  const snaps: Array<z.infer<typeof SnapshotSchema>> = [];
  for (const line of out.split("\n")) {
    // Lines look like: "`-> preupdate-20260913  2026-09-13 ...  description"
    const m = line.match(/([A-Za-z0-9_.-]+)\s+\d{4}-\d{2}-\d{2}/);
    if (m && m[1] !== "current") {
      snaps.push({ name: m[1], description: null });
    }
  }
  return snaps;
}

/** How this container's snapshots are taken: through `nodeModel` (the Proxmox API), else
 *  pct on the node (reach pct only). Null with reach ssh and no nodeModel: no snapshots. */
function snapshotsVia(ga: GlobalArgs): "api" | "pct" | null {
  if (ga.nodeModel) return "api";
  return viaSsh(ga) ? null : "pct";
}

/** Why a snapshot step cannot run here, or null when it can. */
function snapshotRefusal(ga: GlobalArgs): string | null {
  return snapshotsVia(ga) === null
    ? "reach ssh takes snapshots only through nodeModel (a @dmc/proxmox/node model with a snapshot token); set nodeModel, or pass snapshot=false when the caller owns the snapshot"
    : null;
}

/** List container snapshots: `listCtSnapshots` on the nodeModel, or `pct listsnapshot`.
 *  The API list throws when the node model fails. With no way to snapshot, the list is
 *  empty. */
async function listSnapshots(
  ga: ManageArgs,
  repoDir: string,
): Promise<Array<z.infer<typeof SnapshotSchema>>> {
  const via = snapshotsVia(ga);
  if (via === null) return [];
  if (via === "api") {
    const r = await nodeModelRun(ga, repoDir, "listCtSnapshots", {
      vmid: ga.ctid,
    });
    if (!r.ok) throw new Error(r.error);
    const list = r.attributes?.snapshots;
    if (!Array.isArray(list)) {
      throw new Error(`${ga.nodeModel} listCtSnapshots wrote no snapshot list`);
    }
    return list.flatMap((s) => {
      const name = (s as { name?: unknown })?.name;
      return typeof name === "string" && name !== "current"
        ? [{ name, description: null }]
        : [];
    });
  }
  const r = await nodeExec(ga, repoDir, `pct listsnapshot ${ga.ctid}`, 30);
  return parseSnapshots(r.out);
}

/** Take a snapshot: `snapshotCt` on the nodeModel, or `pct snapshot`. Returns rc 0 on
 *  success, with the failure text in `out` otherwise. */
async function takeSnapshot(
  ga: ManageArgs,
  repoDir: string,
  name: string,
): Promise<NodeResult> {
  const description = `swamp safeUpdate pre-update ${ga.appName}`;
  if (snapshotsVia(ga) === "api") {
    const r = await nodeModelRun(ga, repoDir, "snapshotCt", {
      vmid: ga.ctid,
      name,
      description,
    });
    return r.ok
      ? { rc: 0, out: "", stderr: "" }
      : { rc: 1, out: r.error, stderr: "" };
  }
  return await nodeExec(
    ga,
    repoDir,
    `pct snapshot ${ga.ctid} ${name} --description ${
      shSingleQuote(description)
    }`,
    120,
  );
}

/** Delete a snapshot: `deleteCtSnapshot` on the nodeModel, or `pct delsnapshot`. */
async function deleteSnapshot(
  ga: ManageArgs,
  repoDir: string,
  name: string,
): Promise<NodeResult> {
  if (snapshotsVia(ga) === "api") {
    const r = await nodeModelRun(ga, repoDir, "deleteCtSnapshot", {
      vmid: ga.ctid,
      name,
    });
    return r.ok
      ? { rc: 0, out: "", stderr: "" }
      : { rc: 1, out: r.error, stderr: "" };
  }
  return await nodeExec(ga, repoDir, `pct delsnapshot ${ga.ctid} ${name}`, 120);
}

type HealthResult = Awaited<ReturnType<typeof checkHealth>>;

/**
 * Stop (if running), roll the container back to a snapshot, start it again, and
 * wait for health. Never throws — reports failure via the returned `rolledBack`
 * flag and `failure` message so the caller can decide how to surface it. This is
 * the recovery path, so it must be robust even when the node is misbehaving.
 */
async function rollbackTo(
  ga: ManageArgs,
  repoDir: string,
  snap: string,
  log: (m: string) => void,
): Promise<{ rolledBack: boolean; restored: HealthResult; failure?: string }> {
  const dead: HealthResult = {
    healthy: false,
    running: false,
    serviceActive: false,
    httpStatus: null,
  };
  try {
    if (snapshotsVia(ga) === "api") {
      // Proxmox stops the CT for the rollback; start: true brings it up again.
      const rb = await nodeModelRun(ga, repoDir, "rollbackCt", {
        vmid: ga.ctid,
        name: snap,
        start: true,
      });
      if (!rb.ok) {
        return { rolledBack: false, restored: dead, failure: rb.error };
      }
      log(`Rolled back to ${snap} through ${ga.nodeModel}; container started`);
      const restored = await waitForHealth(ga, repoDir, log);
      return { rolledBack: true, restored };
    }
    const refusal = snapshotRefusal(ga);
    if (refusal) return { rolledBack: false, restored: dead, failure: refusal };
    if (await isRunning(ga, repoDir)) {
      log(`Stopping container before rollback`);
      await nodeExec(ga, repoDir, `pct stop ${ga.ctid}`, 120);
    }
    const rb = await nodeExec(
      ga,
      repoDir,
      `pct rollback ${ga.ctid} ${snap}`,
      300,
    );
    if (rb.rc !== 0) {
      return { rolledBack: false, restored: dead, failure: rb.out.slice(-800) };
    }
    log(`Rolled back to ${snap}; starting container`);
    await nodeExec(ga, repoDir, `pct start ${ga.ctid}`, 120);
    const restored = await waitForHealth(ga, repoDir, log);
    return { rolledBack: true, restored };
  } catch (err) {
    return {
      rolledBack: false,
      restored: dead,
      failure: (err as Error).message,
    };
  }
}

/** Single-quote a string for safe use inside a POSIX shell command. */
function shSingleQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/**
 * The git sources the community-scripts `/usr/bin/update` helper fetches and runs as root:
 * the app script (`ct/<app>.sh`) from ProxmoxVE, and the shared code from core. Since 2026 the
 * generated helper first runs `core/misc/update.sh`, and every `ct/<app>.sh` sources
 * `core/build.func`, which loads more files from core.
 */
export const COMMUNITY_SCRIPTS_SOURCES: readonly string[] = [
  "community-scripts/ProxmoxVE@main",
  "community-scripts/core@main",
];

const UPDATE_ENV =
  /^([A-Za-z_][A-Za-z0-9_]{0,63})=([A-Za-z0-9._/:=+-]{1,256})$/;
const UPDATE_BIN = /^\/[A-Za-z0-9._/+-]+$/;
const UPDATE_ARG = /^[A-Za-z0-9._/:=+-]{1,256}$/;

/** The update command as an exact argv, for reach ssh (sudo grants one argv, not a shell). */
export type UpdateArgv =
  | { ok: true; argv: string[]; env: Record<string, string> }
  | { ok: false; error: string };

/**
 * Parse `updateCommand` for reach ssh: `[NAME=value ...] /absolute/bin [args]`, split on
 * whitespace, with no shell syntax. Each env value and argument uses only
 * A-Za-z0-9._/:=+- ; the bin is an absolute path with no `.` or `..` segment and no `//`.
 */
export function parseUpdateCommand(cmd: string): UpdateArgv {
  const tokens = cmd.trim().split(/\s+/).filter((t) => t.length > 0);
  const env: Record<string, string> = {};
  let i = 0;
  for (; i < tokens.length; i++) {
    const m = tokens[i].match(UPDATE_ENV);
    if (!m) break;
    if (m[1] in env) {
      return { ok: false, error: `updateCommand sets ${m[1]} twice` };
    }
    env[m[1]] = m[2];
  }
  if (Object.keys(env).length > 8) {
    return { ok: false, error: "updateCommand sets more than 8 env pairs" };
  }
  const bin = tokens[i];
  if (
    !bin || !UPDATE_BIN.test(bin) || bin.includes("//") ||
    bin.split("/").some((s) => s === "." || s === "..") || bin.endsWith("/")
  ) {
    return {
      ok: false,
      error:
        "with reach ssh, updateCommand must be [NAME=value ...] /absolute/bin [args] with no shell syntax",
    };
  }
  const args = tokens.slice(i + 1);
  if (args.length > 31) {
    return { ok: false, error: "updateCommand has more than 31 arguments" };
  }
  const bad = args.find((a) => !UPDATE_ARG.test(a) || a.includes(".."));
  if (bad !== undefined) {
    return {
      ok: false,
      error: `updateCommand argument "${
        bad.slice(0, 40)
      }" uses characters outside A-Za-z0-9._/:=+- or ..`,
    };
  }
  return { ok: true, argv: [bin, ...args], env };
}

/**
 * The shell text that runs the parsed update as exactly that argv: through `sudo -n` unless
 * the login is root, with the env pairs through env (resolved to an absolute path, as the
 * sudoers entry names it). Never calls `exit`, so the exec wrapper still reports the rc.
 */
export function sudoUpdateShell(
  u: { argv: string[]; env: Record<string, string> },
): string {
  const words = [
    ...Object.entries(u.env).map(([k, v]) => shSingleQuote(`${k}=${v}`)),
    ...u.argv.map(shSingleQuote),
  ].join(" ");
  const sudo = `if [ "$(id -u)" = 0 ]; then S=""; else S="sudo -n"; fi`;
  if (Object.keys(u.env).length === 0) return `${sudo}; $S ${words}`;
  return `${sudo}; E=$(command -v env); case "$E" in /*) $S "$E" ${words} ;; *) echo "env not found"; (exit 127) ;; esac`;
}

/**
 * The shell text that prints the first 4 bytes of the update's bin as hex, or MISSING. Reads
 * only. execve runs a file that starts with `#!` (2321) or is ELF (7f454c46). A script with
 * neither runs only when the caller falls back to /bin/sh on ENOEXEC: glibc's execvp does,
 * but busybox env on musl (Alpine) does not, so under sudo it fails with "Exec format error"
 * (rc 126). The community-scripts `/usr/bin/update` has no `#!` line.
 */
export function execFormatProbeShell(bin: string): string {
  const q = shSingleQuote(bin);
  return `if [ -f ${q} ]; then printf 'HEAD='; head -c 4 ${q} | od -An -tx1 | tr -d ' \\n'; echo; else echo MISSING; fi`;
}

/** The verdict on execFormatProbeShell's output: null when execve can run the bin, else why
 *  not (fail closed: output that does not parse is a refusal). */
export function execFormatRefusal(bin: string, out: string): string | null {
  if (/^MISSING$/m.test(out)) return `${bin} is not a file on ctHost`;
  const m = out.match(/^HEAD=([0-9a-f]*)$/m);
  if (!m) return `could not read the start of ${bin} on ctHost`;
  if (m[1].startsWith("2321") || m[1] === "7f454c46") return null;
  return `${bin} has no #! line and is not an ELF binary, so sudo cannot run it through env (busybox env on Alpine gives "Exec format error"); make "#!/bin/sh" its first line on ctHost`;
}

/** The most URLs the pre-update check fetches from one update script. */
const UPDATE_URL_MAX = 8;
/** The largest update script the pre-update check reads. */
const UPDATE_SCRIPT_MAX_BYTES = 65536;
/** A URL the pre-update check may fetch: http(s), and no character a shell or curl treats
 *  in a special way. */
const LITERAL_URL = /^https?:\/\/[A-Za-z0-9._~:/?#@!&+,;=%-]+$/;

/**
 * The shell text that prints the update's bin for the pre-update URL check, as the login,
 * with no root: each line with `L:` in front, or `ELF` for a binary, `UNREADABLE` or
 * `TOOBIG` (over UPDATE_SCRIPT_MAX_BYTES), and `SCRIPT-END` last. updateScriptUrls reads it.
 */
export function updateScriptProbeShell(bin: string): string {
  const q = shSingleQuote(bin);
  return [
    `H=$(head -c 4 ${q} 2>/dev/null | od -An -tx1 | tr -d ' \\n')`,
    `N=$(wc -c < ${q} 2>/dev/null | tr -d ' ')`,
    `if [ "$H" = 7f454c46 ]; then echo ELF`,
    `elif [ -z "$N" ]; then echo UNREADABLE`,
    `elif [ "$N" -gt ${UPDATE_SCRIPT_MAX_BYTES} ]; then echo TOOBIG`,
    `else sed 's/^/L:/' ${q}; echo; fi`,
    `echo SCRIPT-END`,
  ].join("\n");
}

/** The URLs an update script fetches, or why the check refuses. */
export type UpdateScriptUrls =
  | { ok: true; urls: string[]; skipped: string[] }
  | { ok: false; refusal: string };

/**
 * The URLs that the update script (updateScriptProbeShell's output) fetches with curl or wget.
 * The community-scripts helper builds them from its own assignments
 * (`export COMMUNITY_SCRIPTS_CORE_URL="https://..."`, then `"${COMMUNITY_SCRIPTS_CORE_URL}/misc/update.sh"`),
 * so `$NAME`, `${NAME}` and `${NAME:-default}` are expanded from the literal assignments in
 * the script (the last one wins). A URL that still has an expansion in it is `skipped`: the
 * check cannot resolve it, and the update output check still sees its failure. Fail closed:
 * output with no SCRIPT-END line, an unreadable or too large script, a URL with characters
 * outside LITERAL_URL, or more than UPDATE_URL_MAX URLs is a refusal.
 */
export function updateScriptUrls(bin: string, out: string): UpdateScriptUrls {
  const lines = out.split("\n");
  const marks = lines.filter((l) => !l.startsWith("L:")).map((l) => l.trim());
  if (!marks.includes("SCRIPT-END")) {
    return { ok: false, refusal: `could not read ${bin} on ctHost` };
  }
  if (marks.includes("ELF")) return { ok: true, urls: [], skipped: [] };
  if (marks.includes("UNREADABLE")) {
    return { ok: false, refusal: `could not read ${bin} on ctHost` };
  }
  if (marks.includes("TOOBIG")) {
    return {
      ok: false,
      refusal:
        `${bin} is larger than ${UPDATE_SCRIPT_MAX_BYTES} bytes; the check does not read it`,
    };
  }
  const script = lines.filter((l) => l.startsWith("L:")).map((l) =>
    l.slice(2).trim()
  ).filter((l) => l.length > 0 && !l.startsWith("#"));
  const vars = new Map<string, string>();
  for (const l of script) {
    const m = l.match(
      /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"$`\\]*)"|'([^']*)'|([^\s"'$`\;&|()<>]*))\s*(?:#.*)?$/,
    );
    if (m) vars.set(m[1], m[2] ?? m[3] ?? m[4] ?? "");
  }
  const expand = (t: string): string | null => {
    let unresolved = false;
    const v = t.replace(
      /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)/g,
      (
        _m,
        a: string | undefined,
        d: string | undefined,
        b: string | undefined,
      ) => {
        const val = vars.get((a ?? b)!);
        if (d !== undefined) return val ? val : d;
        if (val !== undefined) return val;
        unresolved = true;
        return "";
      },
    );
    return unresolved || v.includes("$") ? null : v;
  };
  const TOKEN =
    /(?:https?:\/\/|\$\{[A-Za-z_][A-Za-z0-9_]*(?::-[^}]*)?\}|\$[A-Za-z_][A-Za-z0-9_]*)[^\s"'()<>|;`\\]*/g;
  const urls: string[] = [];
  const skipped: string[] = [];
  for (const l of script) {
    if (!/\b(?:curl|wget)\b/.test(l)) continue;
    for (const t of l.match(TOKEN) ?? []) {
      const v = expand(t);
      if (v === null) {
        if (!skipped.includes(t)) skipped.push(t);
        continue;
      }
      if (!/^https?:\/\//.test(v)) continue;
      if (!LITERAL_URL.test(v)) {
        return {
          ok: false,
          refusal: `${bin} fetches a URL the check cannot fetch safely: ${
            v.slice(0, 120)
          }`,
        };
      }
      if (!urls.includes(v)) urls.push(v);
    }
  }
  if (urls.length > UPDATE_URL_MAX) {
    return {
      ok: false,
      refusal:
        `${bin} fetches more than ${UPDATE_URL_MAX} URLs; the check does not fetch them all`,
    };
  }
  return { ok: true, urls, skipped };
}

/**
 * The shell text that fetches each URL on ctHost, as the login, with no root, and prints
 * `URL <http code> <url>` (000 when curl cannot connect), or `NOCURL`, then URLCHECK-END.
 * Each URL is one single-quoted word, so the shell expands nothing in it.
 */
export function urlFetchShell(urls: readonly string[]): string {
  return [
    `if command -v curl >/dev/null 2>&1; then`,
    `  for u in ${urls.map(shSingleQuote).join(" ")}; do`,
    `    c=$(curl -sS -L -o /dev/null --max-time 20 -w '%{http_code}' "$u" 2>/dev/null) || true`,
    `    echo "URL \${c:-000} $u"`,
    `  done`,
    `else echo NOCURL; fi`,
    `echo URLCHECK-END`,
  ].join("\n");
}

/** The verdict on urlFetchShell's output for these URLs: null when each one answered 2xx,
 *  else why not. Fail closed: no URLCHECK-END line, no curl, a line that does not parse, or
 *  a URL with no answer line is a refusal. */
export function updateUrlRefusal(
  bin: string,
  out: string,
  urls: readonly string[],
): string | null {
  const lines = out.split("\n").map((l) => l.trim());
  if (!lines.includes("URLCHECK-END")) {
    return `could not check the URLs that ${bin} fetches on ctHost`;
  }
  if (lines.includes("NOCURL")) {
    return `${bin} fetches ${urls[0]}, but ctHost has no curl`;
  }
  const codes = new Map<string, string>();
  for (const l of lines) {
    if (!l.startsWith("URL ")) continue;
    const m = l.match(/^URL (\d{3}) (\S+)$/);
    if (!m) return `could not read the URL check of ${bin} on ctHost`;
    codes.set(m[2], m[1]);
  }
  for (const u of urls) {
    const c = codes.get(u);
    if (c === undefined) {
      return `the URL check of ${bin} has no answer for ${u}`;
    }
    if (!/^2\d\d$/.test(c)) {
      const why = c === "000" ? "did not answer" : `answered HTTP ${c}`;
      return `${u}, which ${bin} fetches and runs, ${why} from ctHost`;
    }
  }
  return null;
}

/** Lines in the update output that show the update did not run, even at rc 0. */
const UPDATE_NOT_RUN: readonly RegExp[] = [
  // A failed fetch: `bash -c "$(curl -fsSL <url>)"` then runs an empty script.
  /^curl: \(\d+\).*$/m,
  // core/misc/update.sh, when community-scripts.org says the app script was removed.
  /^.*has been removed from community-scripts.*$/m,
  // core/misc/update.sh, when no ct/<app>.sh (or a renamed one) exists.
  /^.*No update script found for .*$/m,
];

/** The first update-output line that shows the community-scripts update did not run (a curl
 *  error, or the helper saying the app script is gone), or null. These runs can exit 0, so
 *  the line is then the only sign. Fail closed: any such line is a failure. */
export function updateNotRun(out: string): string | null {
  // deno-lint-ignore no-control-regex
  const plain = out.replace(/\x1b\[[0-9;]*m/g, "");
  for (const re of UPDATE_NOT_RUN) {
    const m = plain.match(re);
    if (m) return m[0].trim().slice(0, 300);
  }
  return null;
}

/** Timestamp-based snapshot name, e.g. preupdate-20260913T120500Z. */
function snapshotName(): string {
  const iso = new Date().toISOString().replace(/[-:]/g, "").replace(
    /\.\d+Z$/,
    "Z",
  );
  return `preupdate-${iso}`;
}

// ---- Pre-flight checks ------------------------------------------------------
//
// swamp runs these before the mutating methods they list in `appliesTo`. They
// are cheap, read-only probes. Labels: `policy` = static rule about the
// definition (no network); `live` = asks the real node over ssh. A user skips
// them with `--skip-check <name>`, `--skip-check-label <label>` or
// `--skip-checks`.
//
// RECOVERY RULE: the checks for `rollback` must not need the container to be
// running or healthy. A broken container is the reason to roll back.

/** The part of swamp's check context these checks read. */
interface CheckContext {
  globalArgs: GlobalArgs;
  repoDir: string;
  /** The selected method; empty for a plain `swamp model validate <name>`. */
  methodName?: string;
  /** Method args merged over global args (raw, before expression resolution). */
  unresolvedMethodArgs?: Record<string, unknown>;
}

/** Result shape swamp expects from a check. */
interface CheckResult {
  pass: boolean;
  errors?: string[];
}

/** Seconds allowed for one check probe on the node. */
const CHECK_PROBE_TIMEOUT_SEC = 30;

const SKIP_LIVE_HINT = "Fix the cause, or skip with --skip-check-label live.";

/** Names of the global args a live check needs but the definition lacks. */
function missingNodeArgs(ga: GlobalArgs): string[] {
  const missing: string[] = [];
  if (!ga.node) missing.push("node");
  if (ga.ctid === undefined) missing.push("ctid");
  return missing;
}

type NodeProbe =
  | { ok: true; res: NodeResult }
  | { ok: false; errors: string[] };

/**
 * Run one read-only command on the node for a check. Never throws: a missing
 * global arg or a failed ssh transport comes back as `ok: false` with an error
 * that says what failed and how to skip the check.
 */
async function probeNode(
  ctx: CheckContext,
  command: string,
): Promise<NodeProbe> {
  const missing = missingNodeArgs(ctx.globalArgs);
  if (missing.length > 0) {
    return {
      ok: false,
      errors: [
        `Global arg(s) not set: ${
          missing.join(", ")
        }. Set them in the model definition (see check manage-args-present).`,
      ],
    };
  }
  try {
    const res = await nodeExec(
      ctx.globalArgs as ManageArgs,
      ctx.repoDir,
      command,
      CHECK_PROBE_TIMEOUT_SEC,
    );
    return { ok: true, res };
  } catch (err) {
    return {
      ok: false,
      errors: [`${(err as Error).message} ${SKIP_LIVE_HINT}`],
    };
  }
}

/** Run one read-only command in the container over ssh (reach ssh) for a check. Never
 *  throws, like probeNode. */
async function probeCt(
  ctx: CheckContext,
  command: string,
): Promise<NodeProbe> {
  const missing = missingManageArgs(ctx.globalArgs).filter((a) =>
    a !== "service"
  );
  if (missing.length > 0) {
    return {
      ok: false,
      errors: [
        `Global arg(s) not set: ${
          missing.join(", ")
        }. Set them in the model definition (see check manage-args-present).`,
      ],
    };
  }
  try {
    const res = await ctExec(
      ctx.globalArgs as ManageArgs,
      ctx.repoDir,
      command,
      CHECK_PROBE_TIMEOUT_SEC,
    );
    return { ok: true, res };
  } catch (err) {
    return {
      ok: false,
      errors: [`${(err as Error).message} ${SKIP_LIVE_HINT}`],
    };
  }
}

/** The CT's snapshot names for a check, through the nodeModel or pct on the node. */
async function probeSnapshotNames(
  ctx: CheckContext,
): Promise<{ ok: true; names: string[] } | { ok: false; errors: string[] }> {
  const ga = ctx.globalArgs;
  const ctid = ga.ctid;
  const refusal = snapshotRefusal(ga);
  if (refusal) return { ok: false, errors: [`${refusal}.`] };
  if (snapshotsVia(ga) === "api") {
    if (ctid === undefined) {
      return { ok: false, errors: ["Global arg ctid is not set."] };
    }
    try {
      const names = (await listSnapshots(ga as ManageArgs, ctx.repoDir)).map((
        s,
      ) => s.name);
      return { ok: true, names };
    } catch (err) {
      return {
        ok: false,
        errors: [
          `Could not list snapshots of container ${ctid} through ${ga.nodeModel}: ${
            (err as Error).message.slice(0, 300)
          }. ${SKIP_LIVE_HINT}`,
        ],
      };
    }
  }
  const probe = await probeNode(ctx, `pct listsnapshot ${ctid}`);
  if (!probe.ok) return probe;
  if (probe.res.rc !== 0) {
    return {
      ok: false,
      errors: [
        `Could not list snapshots of container ${ctid} on node "${ga.node}" (${
          probe.res.out.slice(0, 200)
        }). Fix node or ctid, or skip with --skip-check snapshot-available.`,
      ],
    };
  }
  return { ok: true, names: parseSnapshots(probe.res.out).map((s) => s.name) };
}

/** A string method arg, or undefined when absent or still an unresolved expression. */
function stringArg(
  ctx: CheckContext,
  name: string,
): string | undefined {
  const v = ctx.unresolvedMethodArgs?.[name];
  return typeof v === "string" && v.length > 0 && !v.includes("${{")
    ? v
    : undefined;
}

/**
 * True only when `method` is the method being run (or validated with
 * `--method`). A plain `swamp model validate <name>` runs every check with an
 * empty methodName; method-specific preconditions that contradict a managed
 * instance's normal state (the container exists, no app slug, no retained
 * snapshot) must pass there, or validation could never succeed.
 */
function selected(ctx: CheckContext, method: string): boolean {
  return ctx.methodName === method;
}

const CHECK_METHODS = ["install", "safeUpdate", "rollback"];

const checks = {
  "manage-args-present": {
    description:
      "Verify the definition sets node (reach pct) or ctHost (reach ssh), ctid and service — every mutating method needs them to reach the container",
    labels: ["policy"],
    appliesTo: CHECK_METHODS,
    execute: (context: CheckContext): Promise<CheckResult> => {
      const missing = missingManageArgs(context.globalArgs);
      return Promise.resolve(
        missing.length === 0 ? { pass: true } : {
          pass: false,
          errors: [
            `Global arg(s) not set: ${
              missing.join(", ")
            }. Set them in the model definition, or skip with --skip-check manage-args-present.`,
          ],
        },
      );
    },
  },
  "install-app-present": {
    description:
      "Verify the definition sets the community-scripts app slug that install needs. Only evaluated when install is the selected method.",
    labels: ["policy"],
    appliesTo: ["install"],
    execute: (context: CheckContext): Promise<CheckResult> =>
      Promise.resolve(
        !selected(context, "install") || context.globalArgs.app
          ? { pass: true }
          : {
            pass: false,
            errors: [
              'Global arg "app" is not set. Set the community-scripts slug (for example "forgejo") in the model definition, or skip with --skip-check install-app-present.',
            ],
          },
      ),
  },
  "reach-ssh-ready": {
    description:
      "With reach ssh: updateCommand is an exact argv that sudo can grant ([NAME=value ...] /absolute/bin [args]), and a nodeModel is set when the selected method needs a snapshot (rollback, or safeUpdate without snapshot=false). Passes with reach pct.",
    labels: ["policy"],
    appliesTo: ["safeUpdate", "rollback", "install"],
    execute: (context: CheckContext): Promise<CheckResult> => {
      const ga = context.globalArgs;
      if (!viaSsh(ga)) return Promise.resolve({ pass: true });
      const errors: string[] = [];
      if (selected(context, "install")) {
        errors.push(
          "install creates the container with pct on the node; it needs reach pct.",
        );
      }
      const u = parseUpdateCommand(ga.updateCommand);
      if (!u.ok) errors.push(`${u.error}.`);
      const needsSnapshot = selected(context, "rollback") ||
        (selected(context, "safeUpdate") &&
          context.unresolvedMethodArgs?.snapshot !== false);
      const refusal = needsSnapshot ? snapshotRefusal(ga) : null;
      if (refusal) errors.push(`${refusal}.`);
      return Promise.resolve(
        errors.length === 0 ? { pass: true } : {
          pass: false,
          errors: errors.map((e) =>
            `${e} Fix the definition, or skip with --skip-check reach-ssh-ready.`
          ),
        },
      );
    },
  },
  "node-reachable": {
    description:
      "Verify the PVE node answers over the ssh model and has the pct tool (reach pct), or that the nodeModel lists the CT's snapshots (reach ssh with a nodeModel; reach ssh without one uses no node). Does not look inside the container, so it is safe before a rollback.",
    labels: ["live"],
    appliesTo: CHECK_METHODS,
    execute: async (context: CheckContext): Promise<CheckResult> => {
      if (viaSsh(context.globalArgs)) {
        if (!context.globalArgs.nodeModel) return { pass: true };
        const listed = await probeSnapshotNames(context);
        return listed.ok
          ? { pass: true }
          : { pass: false, errors: listed.errors };
      }
      const probe = await probeNode(context, "command -v pct");
      if (!probe.ok) return { pass: false, errors: probe.errors };
      if (probe.res.rc !== 0) {
        return {
          pass: false,
          errors: [
            `Node "${context.globalArgs.node}" answered over ssh but the pct tool was not found. Check that the node is a Proxmox VE host. ${SKIP_LIVE_HINT}`,
          ],
        };
      }
      return { pass: true };
    },
  },
  "ctid-free": {
    description:
      "Verify no container or VM already uses this ctid anywhere in the cluster, so install does not collide. Passes when install is run with force=true. Only evaluated when install is the selected method.",
    labels: ["live"],
    appliesTo: ["install"],
    execute: async (context: CheckContext): Promise<CheckResult> => {
      if (!selected(context, "install")) return { pass: true };
      if (context.unresolvedMethodArgs?.force === true) return { pass: true };
      const ctid = context.globalArgs.ctid;
      const probe = await probeNode(
        context,
        `ls /etc/pve/nodes/*/lxc/${ctid}.conf /etc/pve/nodes/*/qemu-server/${ctid}.conf 2>/dev/null; true`,
      );
      if (!probe.ok) return { pass: false, errors: probe.errors };
      const used = probe.res.out.split("\n").map((l) => l.trim()).filter((l) =>
        l.endsWith(".conf")
      );
      if (used.length > 0) {
        return {
          pass: false,
          errors: [
            `ctid ${ctid} is already in use (${
              used.join(", ")
            }). Pick another ctid, run install with force=true, or skip with --skip-check ctid-free.`,
          ],
        };
      }
      return { pass: true };
    },
  },
  "container-exists": {
    description:
      "Verify the container answers to pct status on the node (reach pct), or answers over ssh on ctHost (reach ssh). Does not need the app or the container to be healthy: safeUpdate has its own baseline and rollback logic.",
    labels: ["live"],
    appliesTo: ["safeUpdate"],
    execute: async (context: CheckContext): Promise<CheckResult> => {
      const ctid = context.globalArgs.ctid;
      if (viaSsh(context.globalArgs)) {
        const answered = await probeCt(context, "true");
        if (!answered.ok) return { pass: false, errors: answered.errors };
        return answered.res.rc === 0 ? { pass: true } : {
          pass: false,
          errors: [
            `Container ${ctid} did not answer over ssh on "${context.globalArgs.ctHost}" (rc ${answered.res.rc}). Fix ctHost, or skip with --skip-check container-exists.`,
          ],
        };
      }
      const probe = await probeNode(context, `pct status ${ctid}`);
      if (!probe.ok) return { pass: false, errors: probe.errors };
      if (probe.res.rc !== 0) {
        return {
          pass: false,
          errors: [
            `Container ${ctid} was not found on node "${context.globalArgs.node}" (${
              probe.res.out.slice(0, 200)
            }). Fix node or ctid in the definition, or skip with --skip-check container-exists.`,
          ],
        };
      }
      return { pass: true };
    },
  },
  "snapshot-available": {
    description:
      "Verify the snapshot to roll back to exists for the ctid: the named snapshot, or at least one preupdate-* snapshot when none is named. Does not need the container to be running or healthy. Only evaluated when rollback is the selected method.",
    labels: ["live"],
    appliesTo: ["rollback"],
    execute: async (context: CheckContext): Promise<CheckResult> => {
      if (!selected(context, "rollback")) return { pass: true };
      const ctid = context.globalArgs.ctid;
      const listed = await probeSnapshotNames(context);
      if (!listed.ok) return { pass: false, errors: listed.errors };
      const names = listed.names;
      const requested = stringArg(context, "snapshot");
      if (requested) {
        if (!names.includes(requested)) {
          return {
            pass: false,
            errors: [
              `Snapshot "${requested}" does not exist for container ${ctid}. Existing snapshots: ${
                names.join(", ") || "none"
              }. Pass a snapshot that exists, or skip with --skip-check snapshot-available.`,
            ],
          };
        }
        return { pass: true };
      }
      if (!names.some((n) => n.startsWith("preupdate-"))) {
        return {
          pass: false,
          errors: [
            `No preupdate-* snapshot exists for container ${ctid} (snapshots: ${
              names.join(", ") || "none"
            }). Pass an explicit snapshot name, or skip with --skip-check snapshot-available.`,
          ],
        };
      }
      return { pass: true };
    },
  },
};

/** The privileges declaration, exactly the keys @dmc/patch accepts (it parses strictly). */
const PrivilegesSchema = z.object({
  commands: z.array(z.object({
    argv: z.array(z.string()),
    env: z.record(z.string(), z.string()).optional(),
  })),
  helpers: z.array(z.unknown()),
  remoteCode: z.boolean(),
  remoteSources: z.array(z.string()).optional(),
});

/** Model definition: manage a PVE community-scripts LXC with safe updates. */
export const model = {
  type: "@dmc/proxmox/community-script",
  version: "2026.11.03.1",
  upgrades: [
    {
      toVersion: "2026.09.30.1",
      description:
        "Add osManaged and packageName (defaulted); sshModel is now required (no default)",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.11.03.1",
      description:
        "Add reach (default pct), ctHost and nodeModel; node is needed only with reach pct",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  globalArguments: GlobalArgsSchema,
  resources: {
    "state": {
      description: "Observed container + app health state",
      schema: StateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    "update": {
      description: "Result of a safeUpdate run",
      schema: UpdateResultSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    "updateCheck": {
      description:
        "Installed vs latest upstream version and whether an update is available",
      schema: UpdateCheckSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    "install": {
      description: "Result of an install run",
      schema: InstallResultSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    "discovery": {
      description: "Discovered app defaults and recognized var_* names",
      schema: DiscoverySchema,
      lifetime: "infinite" as const,
      garbageCollection: 5,
    },
    "preview": {
      description:
        "Pre-install summary of what the community-scripts install will do",
      schema: PreviewSchema,
      lifetime: "infinite" as const,
      garbageCollection: 5,
    },
    "privileges": {
      description:
        "The root commands the update needs (the @dmc/patch privileges contract)",
      schema: PrivilegesSchema,
      lifetime: "infinite" as const,
      garbageCollection: 5,
    },
  },
  checks,
  methods: {
    status: {
      description:
        "Report container running state, service health, version, and snapshots",
      arguments: z.object({}),
      execute: async (_args: unknown, context: {
        globalArgs: GlobalArgs;
        repoDir: string;
        logger: Logger;
        writeResource: (
          spec: string,
          instance: string,
          data: unknown,
        ) => Promise<unknown>;
      }) => {
        const ga = requireManage(context.globalArgs);
        context.logger.info("Checking status of container {ctid} on {node}", {
          ctid: ga.ctid,
          node: placeOf(ga),
        });
        const health = await checkHealth(ga, context.repoDir);
        const version = await readVersion(ga, context.repoDir);
        const upd = await computeUpdate(ga, version, context.repoDir);
        const snapshots = await listSnapshots(ga, context.repoDir);
        const handle = await context.writeResource("state", "state", {
          name: ga.appName,
          node: placeOf(ga),
          ctid: ga.ctid,
          running: health.running,
          serviceActive: health.serviceActive,
          version,
          installedVersion: upd.installedVersion,
          latestVersion: upd.latestVersion,
          upstreamVersion: upd.upstreamVersion,
          updateAvailable: upd.updateAvailable,
          osManaged: upd.osManaged,
          healthy: health.healthy,
          healthUrl: ga.healthUrl ?? null,
          httpStatus: health.httpStatus,
          snapshots,
          checkedAt: new Date().toISOString(),
        });
        context.logger.info(
          "Status of container {ctid} on {node}: healthy={healthy} running={running} version={version}",
          {
            ctid: ga.ctid,
            node: placeOf(ga),
            healthy: health.healthy,
            running: health.running,
            version,
          },
        );
        return { dataHandles: [handle] };
      },
    },
    discoverApp: {
      description:
        "Read-only: discover the community-scripts app's default var_* settings (from its ct script) and the var_* names build.func recognizes, to help compose installVars. Requires `app`.",
      arguments: z.object({}),
      execute: async (_args: unknown, context: {
        globalArgs: GlobalArgs;
        repoDir: string;
        logger: Logger;
        writeResource: (
          spec: string,
          instance: string,
          data: unknown,
        ) => Promise<unknown>;
      }) => {
        const ga = context.globalArgs;
        if (!ga.app) {
          throw new Error("`app` global arg is required for discoverApp");
        }
        context.logger.info("Discovering variables for app {app}", {
          app: ga.app,
        });
        const { appDefaults, recognizedVars, varDocs } = await discoverVars(
          ga.ctScriptBaseUrl,
          ga.app,
        );
        const vars = recognizedVars.map((name) => ({
          name,
          default: appDefaults[name] ?? null,
          description: varDocs[name]?.description ?? null,
          group: varDocs[name]?.group ?? null,
        }));
        const handle = await context.writeResource("discovery", "discovery", {
          name: ga.appName,
          app: ga.app,
          scriptUrl: `${ga.ctScriptBaseUrl}/ct/${ga.app}.sh`,
          appDefaults,
          recognizedVars,
          vars,
          checkedAt: new Date().toISOString(),
        });
        context.logger.info(
          "Discovered {varCount} recognized variables for app {app}",
          { varCount: recognizedVars.length, app: ga.app },
        );
        return { dataHandles: [handle] };
      },
    },
    previewInstall: {
      description:
        "Read-only: inspect the community-scripts ct + install scripts for `app` and summarize what installing it will do (provisioning defaults, narrated steps, packages, release downloads, services, exposed port) — run this before `install`. Requires `app`.",
      arguments: z.object({}),
      execute: async (_args: unknown, context: {
        globalArgs: GlobalArgs;
        repoDir: string;
        logger: Logger;
        writeResource: (
          spec: string,
          instance: string,
          data: unknown,
        ) => Promise<unknown>;
      }) => {
        const ga = context.globalArgs;
        if (!ga.app) {
          throw new Error("`app` global arg is required for previewInstall");
        }
        context.logger.info("Previewing install of app {app}", { app: ga.app });
        const s = await summarizeInstall(ga.ctScriptBaseUrl, ga.app);
        const handle = await context.writeResource("preview", "preview", {
          name: ga.appName,
          app: ga.app,
          ...s,
          checkedAt: new Date().toISOString(),
        });
        context.logger.info(
          "Previewed install of app {app}: {stepCount} steps, {packageCount} packages",
          {
            app: ga.app,
            stepCount: s.steps.length,
            packageCount: s.packages.length,
          },
        );
        return { dataHandles: [handle] };
      },
    },
    install: {
      description:
        "Provision a NEW community-scripts LXC headlessly at `ctid` (PHS_SILENT=1 mode=default, var_ctid pinned, installVars as env), then verify it comes up healthy. LXC only — VM (vm/*.sh) scripts are interactive-only; use @dmc/proxmox/vm createFromImage for VMs.",
      arguments: z.object({
        force: z.boolean().default(false).describe(
          "Proceed even if a container already exists at ctid (community-scripts will refuse to overwrite, but this bypasses the pre-check)",
        ),
      }),
      execute: async (args: { force: boolean }, context: {
        globalArgs: GlobalArgs;
        repoDir: string;
        logger: Logger;
        writeResource: (
          spec: string,
          instance: string,
          data: unknown,
        ) => Promise<unknown>;
      }) => {
        const ga = requireManage(context.globalArgs);
        const repoDir = context.repoDir;
        if (viaSsh(ga)) {
          throw new Error(
            "install creates the container with pct on the node; it needs reach pct",
          );
        }
        if (!ga.app) {
          throw new Error(
            '`app` global arg is required for install (the community-scripts slug, e.g. "forgejo")',
          );
        }
        const logs: string[] = [];
        const log = (m: string) => {
          logs.push(`[${new Date().toISOString()}] ${m}`);
          context.logger.info("{message}", { message: m });
        };
        const scriptUrl = `${ga.ctScriptBaseUrl}/ct/${ga.app}.sh`;
        context.logger.info(
          "Installing app {app} as container {ctid} on {node}",
          { app: ga.app, ctid: ga.ctid, node: ga.node },
        );

        // 1. Refuse to touch an existing container.
        const pre = await nodeExec(ga, repoDir, `pct status ${ga.ctid}`, 30);
        if (pre.rc === 0 && !args.force) {
          throw new Error(
            `A container already exists at ctid ${ga.ctid} on ${ga.node} (${pre.out.trim()}). Refusing to install over it; use force=true or pick a different ctid.`,
          );
        }

        // 2. Summarize what the install will do (recorded for review).
        const preview = await summarizeInstall(ga.ctScriptBaseUrl, ga.app);
        log(`Pre-install summary: ${preview.summary}`);

        // 3. Validate installVars keys, discovering the recognized set from build.func.
        const { recognizedVars } = await discoverVars(
          ga.ctScriptBaseUrl,
          ga.app,
        );
        const unknownVars: string[] = [];
        for (const key of Object.keys(ga.installVars)) {
          if (!/^var_[a-z0-9_]+$/.test(key)) {
            throw new Error(
              `Invalid installVars key "${key}": must match var_[a-z0-9_]+`,
            );
          }
          if (recognizedVars.length > 0 && !recognizedVars.includes(key)) {
            unknownVars.push(key);
            log(
              `warning: installVars key "${key}" is not recognized by build.func`,
            );
          }
        }

        // 3. Build the headless install command.
        const env = [
          "PHS_SILENT=1",
          "mode=default",
          `var_ctid=${ga.ctid}`,
          ...Object.entries(ga.installVars).map(([k, v]) =>
            `${k}=${shSingleQuote(v)}`
          ),
        ].join(" ");
        const cmd = `${env} bash -c "$(curl -fsSL ${
          shSingleQuote(scriptUrl)
        })"`;

        log(
          `Installing ${ga.app} as ctid ${ga.ctid} on ${ga.node} from ${scriptUrl}`,
        );
        const res = await nodeExec(ga, repoDir, cmd, ga.installTimeoutSec);
        log(`install command exited rc=${res.rc}`);

        // 4. Verify the container exists and comes up healthy.
        const created =
          (await nodeExec(ga, repoDir, `pct status ${ga.ctid}`, 30)).rc === 0;
        const health = created ? await waitForHealth(ga, repoDir, log) : {
          healthy: false,
          running: false,
          serviceActive: false,
          httpStatus: null,
        };
        const version = created ? await readVersion(ga, repoDir) : null;
        log(
          `post-install: created=${created} running=${health.running} service=${health.serviceActive} http=${
            health.httpStatus ?? "n/a"
          } version=${version ?? "n/a"}`,
        );

        const handle = await context.writeResource("install", "install", {
          name: ga.appName,
          node: ga.node,
          ctid: ga.ctid,
          app: ga.app,
          scriptUrl,
          created,
          running: health.running,
          serviceActive: health.serviceActive,
          healthy: health.healthy,
          httpStatus: health.httpStatus,
          version,
          unknownVars,
          output: res.out,
          logs: logs.join("\n"),
          timestamp: new Date().toISOString(),
        });

        if (!created || res.rc !== 0) {
          context.logger.error(
            "Install of {app} did not produce container {ctid} (install rc {rc}, created={created})",
            { app: ga.app, ctid: ga.ctid, rc: res.rc, created },
          );
          throw new Error(
            `Install of ${ga.app} did not produce a container at ctid ${ga.ctid} (install rc ${res.rc}, created=${created}). Output tail: ${
              res.out.slice(-800)
            } [data: ${(handle as { name?: string })?.name}]`,
          );
        }
        if (!health.healthy) {
          context.logger.error(
            "Installed {app} as container {ctid} but it is not healthy",
            { app: ga.app, ctid: ga.ctid },
          );
          throw new Error(
            `Installed ${ga.app} at ctid ${ga.ctid} but it is not healthy (running=${health.running} service=${health.serviceActive} http=${
              health.httpStatus ?? "n/a"
            }). The container was left in place for inspection. [data: ${
              (handle as { name?: string })?.name
            }]`,
          );
        }
        context.logger.info(
          "Installed app {app} as container {ctid} on {node}: healthy={healthy} version={version}",
          {
            app: ga.app,
            ctid: ga.ctid,
            node: placeOf(ga),
            healthy: health.healthy,
            version,
          },
        );
        return { dataHandles: [handle] };
      },
    },
    checkUpdate: {
      description:
        "Report whether an upstream update is available (installed version vs releaseApiUrl tag), without changing anything",
      arguments: z.object({}),
      execute: async (_args: unknown, context: {
        globalArgs: GlobalArgs;
        repoDir: string;
        logger: Logger;
        writeResource: (
          spec: string,
          instance: string,
          data: unknown,
        ) => Promise<unknown>;
      }) => {
        const ga = requireManage(context.globalArgs);
        context.logger.info(
          "Checking for updates to container {ctid} on {node}",
          { ctid: ga.ctid, node: placeOf(ga) },
        );
        const version = await readVersion(ga, context.repoDir);
        const upd = await computeUpdate(ga, version, context.repoDir);
        const handle = await context.writeResource(
          "updateCheck",
          "updateCheck",
          {
            name: ga.appName,
            node: placeOf(ga),
            ctid: ga.ctid,
            installedVersion: upd.installedVersion,
            latestVersion: upd.latestVersion,
            upstreamVersion: upd.upstreamVersion,
            updateAvailable: upd.updateAvailable,
            osManaged: upd.osManaged,
            checkedAt: new Date().toISOString(),
          },
        );
        context.logger.info(
          "Update check for container {ctid} on {node}: installed={installed} latest={latest} updateAvailable={updateAvailable}",
          {
            ctid: ga.ctid,
            node: placeOf(ga),
            installed: upd.installedVersion,
            latest: upd.latestVersion,
            updateAvailable: upd.updateAvailable,
          },
        );
        return { dataHandles: [handle] };
      },
    },
    safeUpdate: {
      description:
        "Snapshot the container, run the in-container update, validate health, and roll back to the snapshot if the app does not come back healthy (pass snapshot=false to skip the snapshot and rollback when the caller owns them)",
      arguments: z.object({
        force: z.boolean().default(false).describe(
          "Proceed even if the container is not healthy before the update",
        ),
        keepSnapshot: z.boolean().default(true).describe(
          "Keep the pre-update snapshot after a successful update (false deletes it). Ignored when snapshot is false",
        ),
        snapshot: z.boolean().default(true).describe(
          "Take a pre-update snapshot and roll back to it on failure (default). Pass false when the caller already holds its own snapshot and owns the rollback (for example @dmc/patch safeOsUpdate): no snapshot is taken, keepSnapshot is ignored, the update and health gate still run, and an unhealthy result is reported as a failure without any rollback",
        ),
      }),
      execute: async (
        args: { force: boolean; keepSnapshot: boolean; snapshot?: boolean },
        context: {
          globalArgs: GlobalArgs;
          repoDir: string;
          logger: Logger;
          writeResource: (
            spec: string,
            instance: string,
            data: unknown,
          ) => Promise<unknown>;
        },
      ) => {
        const ga = requireManage(context.globalArgs);
        const repoDir = context.repoDir;
        // Fail closed before any probe: reach ssh runs only an exact argv through sudo,
        // and takes a snapshot only through nodeModel.
        const wantSnapshot = args.snapshot !== false;
        const sshUpdate = viaSsh(ga)
          ? parseUpdateCommand(ga.updateCommand)
          : null;
        if (sshUpdate && !sshUpdate.ok) {
          throw new Error(`safeUpdate refused: ${sshUpdate.error}`);
        }
        const snapRefused = wantSnapshot ? snapshotRefusal(ga) : null;
        if (snapRefused) throw new Error(`safeUpdate refused: ${snapRefused}`);
        const logs: string[] = [];
        const log = (m: string) => {
          logs.push(`[${new Date().toISOString()}] ${m}`);
          context.logger.info("{message}", { message: m });
        };
        context.logger.info(
          "Starting safe update of {appName} (container {ctid} on {node})",
          { appName: ga.appName, ctid: ga.ctid, node: placeOf(ga) },
        );

        const writeResult = (data: z.infer<typeof UpdateResultSchema>) =>
          context.writeResource("update", "update", data);

        // 1. Baseline health.
        log(
          `Checking baseline health of ${ga.appName} (ctid ${ga.ctid} on ${
            placeOf(ga)
          })`,
        );
        const before = await checkHealth(ga, repoDir);
        const beforeVersion = await readVersion(ga, repoDir);
        log(
          `baseline: running=${before.running} service=${before.serviceActive} http=${
            before.httpStatus ?? "n/a"
          } version=${beforeVersion ?? "n/a"}`,
        );
        if (!before.healthy && !args.force) {
          const handle = await writeResult({
            name: ga.appName,
            node: placeOf(ga),
            ctid: ga.ctid,
            outcome: "skipped",
            snapshot: null,
            snapshotTaken: false,
            healthyBefore: false,
            healthyAfter: false,
            beforeVersion,
            afterVersion: beforeVersion,
            versionChanged: false,
            rolledBack: false,
            updateOutput: "",
            logs: logs.join("\n"),
            timestamp: new Date().toISOString(),
          });
          context.logger.error(
            "Refusing to update {appName}: not healthy before the update",
            { appName: ga.appName },
          );
          throw new Error(
            `Refusing to update: ${ga.appName} is not healthy before the update (running=${before.running} service=${before.serviceActive} http=${
              before.httpStatus ?? "n/a"
            }). Re-run with force=true to override. [data written: ${
              (handle as { name?: string })?.name
            }]`,
          );
        }

        // reach ssh: refuse before the snapshot when execve cannot run the update's bin
        // (no #! line, not ELF) — it would fail under sudo with rc 126 after the snapshot.
        if (sshUpdate?.ok) {
          const bin = sshUpdate.argv[0];
          const probe = await ctExec(
            ga,
            repoDir,
            execFormatProbeShell(bin),
            30,
          );
          const refused = execFormatRefusal(bin, probe.out);
          if (refused) {
            log(`refused: ${refused}`);
            throw new Error(`safeUpdate refused: ${refused}`);
          }
          // Refuse when a URL the update fetches and runs is gone: the community-scripts
          // helper then exits 0 with no change, and the run would look like "no-change".
          const script = await ctExec(
            ga,
            repoDir,
            updateScriptProbeShell(bin),
            30,
          );
          const found = updateScriptUrls(bin, script.out);
          if (!found.ok) {
            log(`refused: ${found.refusal}`);
            throw new Error(`safeUpdate refused: ${found.refusal}`);
          }
          for (const u of found.skipped) {
            log(
              `not checked (it has an expansion the check cannot resolve): ${u}`,
            );
          }
          if (found.urls.length > 0) {
            const fetched = await ctExec(
              ga,
              repoDir,
              urlFetchShell(found.urls),
              30 + 25 * found.urls.length,
            );
            const refused = updateUrlRefusal(bin, fetched.out, found.urls);
            if (refused) {
              log(`refused: ${refused}`);
              throw new Error(`safeUpdate refused: ${refused}`);
            }
            log(`checked: ${found.urls.join(", ")} answer from ctHost`);
          }
        }

        // 2. Snapshot — skipped when the caller passes `snapshot: false` (it
        //    holds its own snapshot and owns the rollback).
        let snap: string | null = null;
        if (wantSnapshot) {
          const name = snapshotName();
          log(
            `Creating snapshot ${name}${
              ga.nodeModel ? ` through ${ga.nodeModel}` : ""
            }`,
          );
          const snapRes = await takeSnapshot(ga, repoDir, name);
          if (snapRes.rc !== 0) {
            context.logger.error(
              "Snapshot {snapshot} of container {ctid} failed (rc {rc})",
              { snapshot: name, ctid: ga.ctid, rc: snapRes.rc },
            );
            throw new Error(
              `Snapshot failed (rc ${snapRes.rc}): ${snapRes.out.slice(-800)}`,
            );
          }
          snap = name;
          log(`Snapshot created`);
        } else {
          log(
            `snapshot=false: taking no snapshot; the caller owns the snapshot and any rollback`,
          );
          context.logger.info(
            "Skipping snapshot of container {ctid}: caller owns the snapshot and rollback",
            { ctid: ga.ctid },
          );
        }

        // 3–4. Run the update and validate health. Anything that throws in this
        //       region (transport failure, update timeout, probe error) must
        //       still funnel into the rollback path below — the snapshot exists,
        //       so we are obligated to restore it.
        let updateOutput = "";
        let updateRc = -1;
        let after: HealthResult = {
          healthy: false,
          running: false,
          serviceActive: false,
          httpStatus: null,
        };
        let afterVersion: string | null = beforeVersion;
        let updateError: string | null = null;
        try {
          // reach ssh: the exact argv through sudo -n (no shell, so the sudoers entry
          // can name it). reach pct: through `bash -lc` so env-var prefixes
          // (PHS_SILENT=1) and PATH resolution work; `pct exec -- <cmd>` alone execs
          // directly, no shell.
          let updateRes: NodeResult;
          if (sshUpdate?.ok) {
            log(
              `Running update over ssh on ${ga.ctHost}: sudo -n ${
                [
                  ...Object.entries(sshUpdate.env).map(([k, v]) =>
                    `env ${k}=${v}`
                  ),
                  ...sshUpdate.argv,
                ].join(" ")
              }`,
            );
            updateRes = await ctExec(
              ga,
              repoDir,
              sudoUpdateShell(sshUpdate),
              ga.updateTimeoutSec,
            );
          } else {
            log(
              `Running update: pct exec ${ga.ctid} -- bash -lc '${ga.updateCommand}'`,
            );
            updateRes = await nodeExec(
              ga,
              repoDir,
              `pct exec ${ga.ctid} -- bash -lc ${
                shSingleQuote(ga.updateCommand)
              }`,
              ga.updateTimeoutSec,
            );
          }
          updateOutput = updateRes.out;
          updateRc = updateRes.rc;
          log(`update command exited rc=${updateRc}`);
          // A curl error, or the helper saying the app script is gone, means the update
          // did not run, even at rc 0 (the community-scripts helper then runs an empty
          // script, or stops with exit 0). Roll back: the update may have stopped part
          // of the way.
          const notRun = updateNotRun(updateOutput);
          if (notRun) {
            throw new Error(
              `the update output shows that the update did not run fully: ${notRun}`,
            );
          }

          log(`Validating health (timeout ${ga.healthTimeoutSec}s)`);
          after = await waitForHealth(ga, repoDir, log);
          afterVersion = await readVersion(ga, repoDir);
          log(
            `post-update: running=${after.running} service=${after.serviceActive} http=${
              after.httpStatus ?? "n/a"
            } version=${afterVersion ?? "n/a"}`,
          );
        } catch (err) {
          updateError = (err as Error).message;
          log(
            `update/validation phase errored: ${updateError} — will roll back`,
          );
        }

        const versionChanged = !!beforeVersion && !!afterVersion &&
          beforeVersion !== afterVersion;

        // 5a. Healthy and the update reported success → keep. Optionally prune.
        if (!updateError && after.healthy && updateRc === 0) {
          if (snap !== null && !args.keepSnapshot) {
            log(`Deleting snapshot ${snap}`);
            const del = await deleteSnapshot(ga, repoDir, snap);
            if (del.rc !== 0) {
              log(`warning: could not delete snapshot: ${del.out.slice(-300)}`);
            }
          }
          const handle = await writeResult({
            name: ga.appName,
            node: placeOf(ga),
            ctid: ga.ctid,
            outcome: versionChanged ? "updated" : "no-change",
            snapshot: snap !== null && args.keepSnapshot ? snap : null,
            snapshotTaken: snap !== null,
            healthyBefore: before.healthy,
            healthyAfter: true,
            beforeVersion,
            afterVersion,
            versionChanged,
            rolledBack: false,
            updateOutput,
            logs: logs.join("\n"),
            timestamp: new Date().toISOString(),
          });
          context.logger.info(
            "Safe update of {appName} finished: outcome={outcome} version={beforeVersion} -> {afterVersion}",
            {
              appName: ga.appName,
              outcome: versionChanged ? "updated" : "no-change",
              beforeVersion,
              afterVersion,
            },
          );
          return { dataHandles: [handle] };
        }

        // 5b-0. No snapshot (snapshot=false): nothing to roll back to. Record
        //       and surface the failure; the caller owns snapshot and rollback.
        if (snap === null) {
          log(
            `Update did not leave ${ga.appName} healthy — no snapshot was taken (snapshot=false); the caller owns the snapshot and rollback`,
          );
          const handle = await writeResult({
            name: ga.appName,
            node: placeOf(ga),
            ctid: ga.ctid,
            outcome: "failed",
            snapshot: null,
            snapshotTaken: false,
            healthyBefore: before.healthy,
            healthyAfter: after.healthy,
            beforeVersion,
            afterVersion,
            versionChanged: false,
            rolledBack: false,
            updateOutput: updateError
              ? `${updateOutput}\n[update error] ${updateError}`
              : updateOutput,
            logs: logs.join("\n"),
            timestamp: new Date().toISOString(),
          });
          context.logger.error(
            "Update of {appName} failed validation; no snapshot was taken, the caller owns the snapshot and rollback (healthy: {healthy})",
            { appName: ga.appName, healthy: after.healthy },
          );
          throw new Error(
            `${ga.appName} update failed validation (healthy=${after.healthy}, update rc=${updateRc})${
              updateError ? `: ${updateError.slice(0, 300)}` : ""
            }. No snapshot was taken (snapshot=false): the caller owns the snapshot and rollback. [data: ${
              (handle as { name?: string })?.name
            }]`,
          );
        }

        // 5b. Anything else (unhealthy, non-zero update, or thrown error) → roll back.
        log(
          `Update did not leave ${ga.appName} healthy — rolling back to ${snap}`,
        );
        const { rolledBack, restored, failure } = await rollbackTo(
          ga,
          repoDir,
          snap,
          log,
        );
        const handle = await writeResult({
          name: ga.appName,
          node: placeOf(ga),
          ctid: ga.ctid,
          outcome: "rolled-back",
          snapshot: snap,
          snapshotTaken: true,
          healthyBefore: before.healthy,
          healthyAfter: restored.healthy,
          beforeVersion,
          afterVersion,
          versionChanged: false,
          rolledBack,
          updateOutput: updateError
            ? `${updateOutput}\n[update error] ${updateError}`
            : updateOutput,
          logs: logs.join("\n"),
          timestamp: new Date().toISOString(),
        });
        if (!rolledBack) {
          context.logger.error(
            "Update of {appName} failed and rollback to {snapshot} failed; manual intervention needed",
            { appName: ga.appName, snapshot: snap },
          );
          throw new Error(
            `Update failed AND rollback failed. Container ${ga.ctid} may be stopped — MANUAL INTERVENTION NEEDED. Snapshot ${snap} is intact. Detail: ${
              failure ?? "unknown"
            } [data: ${(handle as { name?: string })?.name}]`,
          );
        }
        context.logger.warn(
          "Update of {appName} failed validation; rolled back to {snapshot} (healthy after rollback: {healthy})",
          { appName: ga.appName, snapshot: snap, healthy: restored.healthy },
        );
        throw new Error(
          `${ga.appName} update failed validation and was rolled back to snapshot ${snap} (post-rollback healthy=${restored.healthy})${
            updateError ? `: ${updateError.slice(0, 300)}` : ""
          }. [data: ${(handle as { name?: string })?.name}]`,
        );
      },
    },
    privileges: {
      description:
        "Declare the root commands the update needs, for @dmc/patch (the privileges({ host }) contract). Read-only: runs nothing on any host. reach ssh: the update as one exact argv run through sudo -n; it fetches and runs community-scripts code from ProxmoxVE and core, so remoteCode is true with both as remoteSources. reach pct: refused, because pct runs every command as root on the node and no sudo grant covers that.",
      arguments: z.object({
        host: z.string().optional().describe(
          "The @dmc/patch machine that asks; when set it must equal ctHost",
        ),
      }),
      execute: async (args: { host?: string }, context: {
        globalArgs: GlobalArgs;
        logger: Logger;
        writeResource: (
          spec: string,
          instance: string,
          data: unknown,
        ) => Promise<unknown>;
      }) => {
        const ga = context.globalArgs;
        if (!viaSsh(ga)) {
          throw new Error(
            "privileges: reach pct runs the update as root through pct on the node, which no sudo grant covers; use reach ssh, or accept it in @dmc/patch with an unsafe.privilegedUpdater record",
          );
        }
        if (!ga.ctHost) {
          throw new Error("privileges: reach ssh needs ctHost");
        }
        if (args.host !== undefined && args.host !== ga.ctHost) {
          throw new Error(
            `privileges: asked for host "${args.host}", but this model updates ctHost "${ga.ctHost}"`,
          );
        }
        const u = parseUpdateCommand(ga.updateCommand);
        if (!u.ok) throw new Error(`privileges: ${u.error}`);
        const command = Object.keys(u.env).length > 0
          ? { argv: u.argv, env: u.env }
          : { argv: u.argv };
        const handle = await context.writeResource("privileges", "privileges", {
          commands: [command],
          helpers: [],
          remoteCode: true,
          remoteSources: [...COMMUNITY_SCRIPTS_SOURCES],
        });
        context.logger.info(
          "Declared one sudo command for {host}: {argv}",
          { host: ga.ctHost, argv: u.argv.join(" ") },
        );
        return { dataHandles: [handle] };
      },
    },
    rollback: {
      description:
        "Roll the container back to a snapshot (named, or the most recent preupdate-* snapshot)",
      arguments: z.object({
        snapshot: z.string().optional().describe(
          "Snapshot name to roll back to; defaults to the most recent preupdate-* snapshot",
        ),
      }),
      execute: async (args: { snapshot?: string }, context: {
        globalArgs: GlobalArgs;
        repoDir: string;
        logger: Logger;
        writeResource: (
          spec: string,
          instance: string,
          data: unknown,
        ) => Promise<unknown>;
      }) => {
        const ga = requireManage(context.globalArgs);
        const repoDir = context.repoDir;
        const refusal = snapshotRefusal(ga);
        if (refusal) throw new Error(`rollback refused: ${refusal}`);
        const logs: string[] = [];
        const log = (m: string) => {
          logs.push(`[${new Date().toISOString()}] ${m}`);
          context.logger.info("{message}", { message: m });
        };
        context.logger.info(
          "Rolling back container {ctid} on {node}",
          { ctid: ga.ctid, node: placeOf(ga) },
        );

        let target = args.snapshot;
        if (!target) {
          const snaps = await listSnapshots(ga, repoDir);
          const pre = snaps.filter((s) => s.name.startsWith("preupdate-"))
            .sort();
          if (pre.length === 0) {
            context.logger.error(
              "No preupdate-* snapshot found for container {ctid}",
              { ctid: ga.ctid },
            );
            throw new Error(
              `No preupdate-* snapshot found for ctid ${ga.ctid}; pass an explicit snapshot name`,
            );
          }
          target = pre[pre.length - 1].name;
        }
        log(`Rolling back ctid ${ga.ctid} to ${target}`);
        const { rolledBack, restored: health, failure } = await rollbackTo(
          ga,
          repoDir,
          target,
          log,
        );
        if (!rolledBack) {
          context.logger.error(
            "Rollback of container {ctid} to {snapshot} failed",
            { ctid: ga.ctid, snapshot: target },
          );
          throw new Error(
            `Rollback to ${target} failed: ${failure ?? "unknown"}`,
          );
        }
        const rbVersion = await readVersion(ga, repoDir);
        const rbUpd = await computeUpdate(ga, rbVersion, context.repoDir);
        const handle = await context.writeResource("state", "state", {
          name: ga.appName,
          node: placeOf(ga),
          ctid: ga.ctid,
          running: health.running,
          serviceActive: health.serviceActive,
          version: rbVersion,
          installedVersion: rbUpd.installedVersion,
          latestVersion: rbUpd.latestVersion,
          upstreamVersion: rbUpd.upstreamVersion,
          updateAvailable: rbUpd.updateAvailable,
          osManaged: rbUpd.osManaged,
          healthy: health.healthy,
          healthUrl: ga.healthUrl ?? null,
          httpStatus: health.httpStatus,
          snapshots: await listSnapshots(ga, repoDir),
          checkedAt: new Date().toISOString(),
        });
        context.logger.info(
          "Rolled back container {ctid} to {snapshot}: healthy={healthy}",
          { ctid: ga.ctid, snapshot: target, healthy: health.healthy },
        );
        return { dataHandles: [handle] };
      },
    },
  },
};
