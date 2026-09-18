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
 * default `infra-ssh`): it shells out to `swamp model method run <sshModel> exec`
 * so SSH transport, auth, and host-key handling live in one place.
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

const SWAMP_BIN = Deno.env.get("SWAMP_BIN") ?? "swamp";
const RC_SENTINEL = "__SWAMP_RC__";

const GlobalArgsSchema = z.object({
  sshModel: z.string().default("infra-ssh").describe(
    "Name of the @swamp/ssh model instance used to reach the PVE node",
  ),
  node: z.string().min(1).optional().describe(
    'Fleet host name (a host in the sshModel) of the PVE hypervisor running the container, e.g. "fort". Required for every method except discoverApp/previewInstall (which only read the community-scripts sources).',
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
    "Command run inside the container (via `bash -lc`) to perform the update. Default runs the community-scripts helper in forced-silent mode (PHS_SILENT=1) so it never prompts. Add `var_ignore_os_mismatch=1` here to bypass the OS-version guard.",
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

/** Global args with the container-management fields guaranteed present. */
type ManageArgs = GlobalArgs & { node: string; ctid: number; service: string };

/**
 * Assert the container-management global args (node/ctid/service) are set, and
 * narrow the type. discoverApp/previewInstall don't call this — they only read
 * the community-scripts sources and need just `app`.
 */
function requireManage(ga: GlobalArgs): ManageArgs {
  const missing: string[] = [];
  if (!ga.node) missing.push("node");
  if (ga.ctid === undefined) missing.push("ctid");
  if (!ga.service) missing.push("service");
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
  updateAvailable: z.boolean().nullable(),
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
  outcome: z.enum(["updated", "no-change", "rolled-back", "skipped"]),
  snapshot: z.string().nullable(),
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
  updateAvailable: z.boolean().nullable(),
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
      `hosts:json=[${JSON.stringify(ga.node)}]`,
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
      `SSH transport to node "${ga.node}" via ${ga.sshModel} failed (exit ${result.code}): ${
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

/** True when `pct status <ctid>` reports the container running. */
async function isRunning(ga: ManageArgs, repoDir: string): Promise<boolean> {
  const r = await nodeExec(ga, repoDir, `pct status ${ga.ctid}`, 30);
  return /status:\s*running/i.test(r.out);
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
    const r = await nodeExec(
      ga,
      repoDir,
      `pct exec ${ga.ctid} -- sh -c ${shSingleQuote(ga.serviceActiveCommand)}`,
      30,
    );
    return r.rc === 0;
  }
  const r = await nodeExec(
    ga,
    repoDir,
    `pct exec ${ga.ctid} -- systemctl is-active ${shSingleQuote(ga.service)}`,
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
    const r = await nodeExec(
      ga,
      repoDir,
      `pct exec ${ga.ctid} -- sh -c ${shSingleQuote(ga.versionCommand)}`,
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
 * Compute update availability: installed version (from versionCommand output)
 * vs latest upstream release. Returns nulls when the inputs aren't configured or
 * can't be determined — never guesses.
 */
async function computeUpdate(
  ga: GlobalArgs,
  rawVersion: string | null,
): Promise<
  {
    installedVersion: string | null;
    latestVersion: string | null;
    updateAvailable: boolean | null;
  }
> {
  const installedVersion = extractSemver(rawVersion, ga.versionRegex);
  const latestVersion = await fetchLatestVersion(ga);
  let updateAvailable: boolean | null = null;
  if (installedVersion && latestVersion) {
    updateAvailable = cmpSemver(latestVersion, installedVersion) > 0;
  }
  return { installedVersion, latestVersion, updateAvailable };
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

/** List container snapshots via `pct listsnapshot`. */
async function listSnapshots(
  ga: ManageArgs,
  repoDir: string,
): Promise<Array<z.infer<typeof SnapshotSchema>>> {
  const r = await nodeExec(ga, repoDir, `pct listsnapshot ${ga.ctid}`, 30);
  const snaps: Array<z.infer<typeof SnapshotSchema>> = [];
  for (const line of r.out.split("\n")) {
    // Lines look like: "`-> preupdate-20260913  2026-09-13 ...  description"
    const m = line.match(/([A-Za-z0-9_.-]+)\s+\d{4}-\d{2}-\d{2}/);
    if (m && m[1] !== "current") {
      snaps.push({ name: m[1], description: null });
    }
  }
  return snaps;
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

/** Timestamp-based snapshot name, e.g. preupdate-20260913T120500Z. */
function snapshotName(): string {
  const iso = new Date().toISOString().replace(/[-:]/g, "").replace(
    /\.\d+Z$/,
    "Z",
  );
  return `preupdate-${iso}`;
}

/** Model definition: manage a PVE community-scripts LXC with safe updates. */
export const model = {
  type: "@dmc/proxmox/community-script",
  version: "2026.09.13.1",
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
  },
  methods: {
    status: {
      description:
        "Report container running state, service health, version, and snapshots",
      arguments: z.object({}),
      execute: async (_args: unknown, context: {
        globalArgs: GlobalArgs;
        repoDir: string;
        writeResource: (
          spec: string,
          instance: string,
          data: unknown,
        ) => Promise<unknown>;
      }) => {
        const ga = requireManage(context.globalArgs);
        const health = await checkHealth(ga, context.repoDir);
        const version = await readVersion(ga, context.repoDir);
        const upd = await computeUpdate(ga, version);
        const snapshots = await listSnapshots(ga, context.repoDir);
        const handle = await context.writeResource("state", "state", {
          name: ga.appName,
          node: ga.node,
          ctid: ga.ctid,
          running: health.running,
          serviceActive: health.serviceActive,
          version,
          installedVersion: upd.installedVersion,
          latestVersion: upd.latestVersion,
          updateAvailable: upd.updateAvailable,
          healthy: health.healthy,
          healthUrl: ga.healthUrl ?? null,
          httpStatus: health.httpStatus,
          snapshots,
          checkedAt: new Date().toISOString(),
        });
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
        const s = await summarizeInstall(ga.ctScriptBaseUrl, ga.app);
        const handle = await context.writeResource("preview", "preview", {
          name: ga.appName,
          app: ga.app,
          ...s,
          checkedAt: new Date().toISOString(),
        });
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
        writeResource: (
          spec: string,
          instance: string,
          data: unknown,
        ) => Promise<unknown>;
      }) => {
        const ga = requireManage(context.globalArgs);
        const repoDir = context.repoDir;
        if (!ga.app) {
          throw new Error(
            '`app` global arg is required for install (the community-scripts slug, e.g. "forgejo")',
          );
        }
        const logs: string[] = [];
        const log = (m: string) =>
          logs.push(`[${new Date().toISOString()}] ${m}`);
        const scriptUrl = `${ga.ctScriptBaseUrl}/ct/${ga.app}.sh`;

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
          throw new Error(
            `Install of ${ga.app} did not produce a container at ctid ${ga.ctid} (install rc ${res.rc}, created=${created}). Output tail: ${
              res.out.slice(-800)
            } [data: ${(handle as { name?: string })?.name}]`,
          );
        }
        if (!health.healthy) {
          throw new Error(
            `Installed ${ga.app} at ctid ${ga.ctid} but it is not healthy (running=${health.running} service=${health.serviceActive} http=${
              health.httpStatus ?? "n/a"
            }). The container was left in place for inspection. [data: ${
              (handle as { name?: string })?.name
            }]`,
          );
        }
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
        writeResource: (
          spec: string,
          instance: string,
          data: unknown,
        ) => Promise<unknown>;
      }) => {
        const ga = requireManage(context.globalArgs);
        const version = await readVersion(ga, context.repoDir);
        const upd = await computeUpdate(ga, version);
        const handle = await context.writeResource(
          "updateCheck",
          "updateCheck",
          {
            name: ga.appName,
            node: ga.node,
            ctid: ga.ctid,
            installedVersion: upd.installedVersion,
            latestVersion: upd.latestVersion,
            updateAvailable: upd.updateAvailable,
            checkedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    safeUpdate: {
      description:
        "Snapshot the container, run the in-container update, validate health, and roll back to the snapshot if the app does not come back healthy",
      arguments: z.object({
        force: z.boolean().default(false).describe(
          "Proceed even if the container is not healthy before the update",
        ),
        keepSnapshot: z.boolean().default(true).describe(
          "Keep the pre-update snapshot after a successful update (false deletes it)",
        ),
      }),
      execute: async (
        args: { force: boolean; keepSnapshot: boolean },
        context: {
          globalArgs: GlobalArgs;
          repoDir: string;
          writeResource: (
            spec: string,
            instance: string,
            data: unknown,
          ) => Promise<unknown>;
        },
      ) => {
        const ga = requireManage(context.globalArgs);
        const repoDir = context.repoDir;
        const logs: string[] = [];
        const log = (m: string) => {
          logs.push(`[${new Date().toISOString()}] ${m}`);
        };

        const writeResult = (data: z.infer<typeof UpdateResultSchema>) =>
          context.writeResource("update", "update", data);

        // 1. Baseline health.
        log(
          `Checking baseline health of ${ga.appName} (ctid ${ga.ctid} on ${ga.node})`,
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
            node: ga.node,
            ctid: ga.ctid,
            outcome: "skipped",
            snapshot: null,
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
          throw new Error(
            `Refusing to update: ${ga.appName} is not healthy before the update (running=${before.running} service=${before.serviceActive} http=${
              before.httpStatus ?? "n/a"
            }). Re-run with force=true to override. [data written: ${
              (handle as { name?: string })?.name
            }]`,
          );
        }

        // 2. Snapshot.
        const snap = snapshotName();
        log(`Creating snapshot ${snap}`);
        const snapRes = await nodeExec(
          ga,
          repoDir,
          `pct snapshot ${ga.ctid} ${snap} --description ${
            shSingleQuote(`swamp safeUpdate pre-update ${ga.appName}`)
          }`,
          120,
        );
        if (snapRes.rc !== 0) {
          throw new Error(
            `Snapshot failed (rc ${snapRes.rc}): ${snapRes.out.slice(-800)}`,
          );
        }
        log(`Snapshot created`);

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
          // Run through `bash -lc` so env-var prefixes (PHS_SILENT=1) and PATH
          // resolution work; `pct exec -- <cmd>` alone execs directly, no shell.
          log(
            `Running update: pct exec ${ga.ctid} -- bash -lc '${ga.updateCommand}'`,
          );
          const updateRes = await nodeExec(
            ga,
            repoDir,
            `pct exec ${ga.ctid} -- bash -lc ${
              shSingleQuote(ga.updateCommand)
            }`,
            ga.updateTimeoutSec,
          );
          updateOutput = updateRes.out;
          updateRc = updateRes.rc;
          log(`update command exited rc=${updateRc}`);

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
          if (!args.keepSnapshot) {
            log(`Deleting snapshot ${snap}`);
            const del = await nodeExec(
              ga,
              repoDir,
              `pct delsnapshot ${ga.ctid} ${snap}`,
              120,
            );
            if (del.rc !== 0) {
              log(`warning: could not delete snapshot: ${del.out.slice(-300)}`);
            }
          }
          const handle = await writeResult({
            name: ga.appName,
            node: ga.node,
            ctid: ga.ctid,
            outcome: versionChanged ? "updated" : "no-change",
            snapshot: args.keepSnapshot ? snap : null,
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
          return { dataHandles: [handle] };
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
          node: ga.node,
          ctid: ga.ctid,
          outcome: "rolled-back",
          snapshot: snap,
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
          throw new Error(
            `Update failed AND rollback failed. Container ${ga.ctid} may be stopped — MANUAL INTERVENTION NEEDED. Snapshot ${snap} is intact. Detail: ${
              failure ?? "unknown"
            } [data: ${(handle as { name?: string })?.name}]`,
          );
        }
        throw new Error(
          `${ga.appName} update failed validation and was rolled back to snapshot ${snap} (post-rollback healthy=${restored.healthy}). [data: ${
            (handle as { name?: string })?.name
          }]`,
        );
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
        writeResource: (
          spec: string,
          instance: string,
          data: unknown,
        ) => Promise<unknown>;
      }) => {
        const ga = requireManage(context.globalArgs);
        const repoDir = context.repoDir;
        const logs: string[] = [];
        const log = (m: string) =>
          logs.push(`[${new Date().toISOString()}] ${m}`);

        let target = args.snapshot;
        if (!target) {
          const snaps = await listSnapshots(ga, repoDir);
          const pre = snaps.filter((s) => s.name.startsWith("preupdate-"))
            .sort();
          if (pre.length === 0) {
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
          throw new Error(
            `Rollback to ${target} failed: ${failure ?? "unknown"}`,
          );
        }
        const rbVersion = await readVersion(ga, repoDir);
        const rbUpd = await computeUpdate(ga, rbVersion);
        const handle = await context.writeResource("state", "state", {
          name: ga.appName,
          node: ga.node,
          ctid: ga.ctid,
          running: health.running,
          serviceActive: health.serviceActive,
          version: rbVersion,
          installedVersion: rbUpd.installedVersion,
          latestVersion: rbUpd.latestVersion,
          updateAvailable: rbUpd.updateAvailable,
          healthy: health.healthy,
          healthUrl: ga.healthUrl ?? null,
          httpStatus: health.httpStatus,
          snapshots: await listSnapshots(ga, repoDir),
          checkedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
  },
};
