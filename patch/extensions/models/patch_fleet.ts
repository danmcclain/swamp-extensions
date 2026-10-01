/**
 * @dmc/patch/fleet — a decorated machine inventory for scanning and safely updating
 * a fleet. One model instance holds the machines; `scan` fans out over them.
 *
 * Host access is delegated to an `@swamp/ssh` model instance named by `sshModel`
 * (required, no default) — the same delegation pattern `@dmc/proxmox/community-script`
 * uses. This keeps the extension agentless and generic (consumers point `sshModel` at
 * their own fleet). LXC/CT apps reuse `@dmc/proxmox/community-script` by reference.
 *
 * @module
 */
import { z } from "npm:zod@4";

const SWAMP_BIN = Deno.env.get("SWAMP_BIN") ?? "swamp";
const RC_SENTINEL = "__SWAMP_RC__";
/**
 * Bundled agentless collector (bash). Shipped to each host as base64 over ssh/pct.
 * Generated verbatim from the collector script so the package is self-contained.
 */
export const COLLECTOR_SCRIPT: string = [
  "#!/usr/bin/env bash",
  "# patch-inventory.sh — agentless patch/update collector for one host.",
  "#",
  "# Detects the OS package manager and prints a SINGLE JSON object to stdout with",
  "# pending-update / security / total-package / needs-reboot stats. All diagnostics",
  "# go to stderr so stdout is pure JSON (the @dmc/patch/fleet `scan` method parses it).",
  "#",
  "# Bundled in @dmc/patch/fleet as COLLECTOR_SCRIPT and run by its `scan` method",
  "# through the configured @swamp/ssh model (or `pct exec` for containers).",
  "#",
  "# NOTE: the ssh model feeds this script to `bash` on the host's STDIN. Any command",
  "# that reads stdin (e.g. an interactive dnf prompt) would otherwise swallow the",
  "# rest of the script, so all work runs inside main() with stdin < /dev/null.",
  "#",
  "# Root is not required: counts come from simulate/read-only paths. Package-cache",
  "# refresh uses passwordless sudo when available, otherwise the existing cache.",
  "set -u",
  "",
  "log() { printf '%s\\n' \"$*\" >&2; }",
  "",
  "# Minimal JSON string escaper (backslash, double-quote, strip control chars).",
  "jesc() { printf '%s' \"${1-}\" | sed -e 's/\\\\/\\\\\\\\/g' -e 's/\"/\\\\\"/g' | tr -d '\\000-\\037'; }",
  "",
  'SUDO=""',
  'if [ "$(id -u)" != "0" ] && command -v sudo >/dev/null 2>&1; then',
  '  SUDO="sudo -n"',
  "fi",
  "",
  "# Outputs set by the collectors.",
  'pkg_mgr="unknown"',
  'updates="null"; security="null"; total="null"',
  'needs_reboot="false"; reason_json="null"',
  "# apt-only: how the pending updates apply.",
  'held_back="null"       # pkgs a plain `apt upgrade` keeps back (need dist-upgrade)',
  'removals="null"        # pkgs `apt dist-upgrade` would REMOVE',
  'dist_required="null"   # true if plain upgrade is insufficient (held back or removals)',
  "# docker (only on hosts running the engine): engine version + per-container image drift.",
  'docker_engine="null"   # docker engine version string, or null if no engine',
  'docker_json="null"     # JSON array of running containers vs registry, or null',
  "",
  'set_reason() { reason_json="\\"$(jesc "$1")\\""; }',
  "",
  "# Reboot needed if the running kernel differs from the newest installed kernel",
  "# image in /boot (matches PatchMon; catches Proxmox/apt kernels that don't drop",
  "# /var/run/reboot-required). Sets needs_reboot/reason as a side effect.",
  "kernel_compare() {",
  "  local running newest",
  '  running="$(uname -r)"',
  "  newest=\"$(ls -1 /boot/vmlinuz-* 2>/dev/null | sed 's#.*/vmlinuz-##' | sort -V | tail -1)\"",
  '  if [ -n "$newest" ] && [ "$newest" != "$running" ]; then',
  '    needs_reboot="true"',
  '    [ "$reason_json" = "null" ] && set_reason "kernel mismatch: running $running, installed $newest"',
  "  fi",
  "}",
  "",
  "collect_apt() {",
  '  pkg_mgr="apt"',
  '  $SUDO apt-get update -qq >/dev/null 2>&1 || log "apt-get update skipped/failed (using existing cache)"',
  "  local plain dist plain_inst dist_inst dist_remv",
  "  # Plain `upgrade` never installs/removes; `dist-upgrade` does. Comparing the two",
  "  # tells us whether the pending updates need a dist-upgrade (held-back / removals).",
  '  plain="$(apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null || true)"',
  '  dist="$(apt-get -s -o Debug::NoLocking=true dist-upgrade 2>/dev/null || true)"',
  "  plain_inst=\"$(printf '%s\\n' \"$plain\" | grep -c '^Inst' || true)\"",
  "  dist_inst=\"$(printf '%s\\n' \"$dist\" | grep -c '^Inst' || true)\"",
  "  dist_remv=\"$(printf '%s\\n' \"$dist\" | grep -c '^Remv' || true)\"",
  '  [ -z "$plain_inst" ] && plain_inst=0',
  '  [ -z "$dist_inst" ] && dist_inst=0',
  '  [ -z "$dist_remv" ] && dist_remv=0',
  "  # updatesCount = full upgradable set (dist-upgrade Inst), matching PatchMon.",
  '  updates="$dist_inst"',
  "  security=\"$(printf '%s\\n' \"$dist\" | grep '^Inst' | grep -ciE '(-security|Security:)' || true)\"",
  '  [ -z "$security" ] && security=0',
  '  held_back=$(( dist_inst - plain_inst )); [ "$held_back" -lt 0 ] && held_back=0',
  '  removals="$dist_remv"',
  '  if [ "$held_back" -gt 0 ] || [ "$removals" -gt 0 ]; then dist_required="true"; else dist_required="false"; fi',
  "  total=\"$(dpkg-query -f '.\\n' -W 2>/dev/null | wc -l | tr -d ' ')\"",
  '  [ -z "$total" ] && total=0',
  "  if [ -f /var/run/reboot-required ]; then",
  '    needs_reboot="true"',
  "    if [ -r /var/run/reboot-required.pkgs ]; then",
  "      set_reason \"packages requiring reboot: $(tr '\\n' ',' < /var/run/reboot-required.pkgs | sed 's/,$//')\"",
  "    else",
  '      set_reason "$(head -1 /var/run/reboot-required 2>/dev/null)"',
  "    fi",
  "  fi",
  "  kernel_compare",
  "}",
  "",
  "collect_dnf() {",
  '  pkg_mgr="dnf"',
  "  local co",
  '  co="$($SUDO dnf -q check-update 2>/dev/null || true)"',
  "  updates=\"$(printf '%s\\n' \"$co\" | grep -cE '^[A-Za-z0-9._+-]+\\.[A-Za-z0-9_]+[[:space:]]' || true)\"",
  "  # --security filters check-update to packages with a security update (a clean",
  "  # subset of updates), unlike `updateinfo list` which repeats a package per advisory.",
  "  security=\"$($SUDO dnf -q check-update --security 2>/dev/null | grep -cE '^[A-Za-z0-9._+-]+\\.[A-Za-z0-9_]+[[:space:]]' || true)\"",
  "  total=\"$(rpm -qa 2>/dev/null | wc -l | tr -d ' ')\"",
  '  [ -z "$updates" ] && updates=0',
  '  [ -z "$security" ] && security=0',
  '  [ -z "$total" ] && total=0',
  "  # Prefer needs-restarting (dnf-utils) for the reboot flag; fall back to kernels.",
  "  if command -v needs-restarting >/dev/null 2>&1; then",
  "    if ! $SUDO needs-restarting -r >/dev/null 2>&1; then",
  '      needs_reboot="true"; set_reason "needs-restarting: reboot required"',
  "    fi",
  "  fi",
  '  [ "$needs_reboot" = "false" ] && kernel_compare',
  "}",
  "",
  "collect_apk() {",
  '  pkg_mgr="apk"',
  '  $SUDO apk update -q >/dev/null 2>&1 || log "apk update skipped/failed (using existing cache)"',
  "  updates=\"$(apk version -l '<' 2>/dev/null | grep -c '<' || true)\"",
  '  security="null"   # Alpine has no distinct security channel',
  "  total=\"$(apk info 2>/dev/null | wc -l | tr -d ' ')\"",
  '  [ -z "$updates" ] && updates=0',
  '  [ -z "$total" ] && total=0',
  "  if apk version -l '<' 2>/dev/null | grep -q '^linux-'; then",
  '    needs_reboot="true"; set_reason "kernel package update available"',
  "  fi",
  "}",
  "",
  "# Container image drift: for each running container, compare the local image digest",
  "# (RepoDigests, i.e. the digest it was pulled at) against the registry digest for its",
  "# tag (buildx imagetools inspect). updateAvailable=true when they differ, null when it",
  "# can't be determined (locally-built image, private/unreachable registry). Independent",
  "# of the OS package sections; sets docker_engine + docker_json only.",
  "collect_docker() {",
  "  command -v docker >/dev/null 2>&1 || return 0",
  "  $SUDO docker info >/dev/null 2>&1 || return 0",
  "  local ver; ver=\"$(docker --version 2>/dev/null | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1)\"",
  '  [ -n "$ver" ] && docker_engine="\\"$ver\\""',
  '  local items="" c ref local_dig local_sha reg_sha upd item',
  "  while IFS= read -r c; do",
  '    [ -z "$c" ] && continue',
  '    ref="$($SUDO docker inspect "$c" --format \'{{.Config.Image}}\' 2>/dev/null)"',
  '    [ -z "$ref" ] && continue',
  '    local_dig="$($SUDO docker image inspect "$ref" --format \'{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}\' 2>/dev/null)"',
  '    local_sha="${local_dig##*@}"; case "$local_sha" in sha256:*) ;; *) local_sha="" ;; esac',
  "    reg_sha=\"$($SUDO docker buildx imagetools inspect \"$ref\" --format '{{.Manifest.Digest}}' 2>/dev/null | grep -oE 'sha256:[0-9a-f]+' | head -1)\"",
  '    upd="null"',
  '    if [ -n "$local_sha" ] && [ -n "$reg_sha" ]; then',
  '      [ "$local_sha" = "$reg_sha" ] && upd="false" || upd="true"',
  "    fi",
  '    item="{\\"container\\":\\"$(jesc "$c")\\",\\"image\\":\\"$(jesc "$ref")\\",\\"localDigest\\":\\"$(jesc "$local_sha")\\",\\"registryDigest\\":\\"$(jesc "$reg_sha")\\",\\"updateAvailable\\":$upd}"',
  '    items="${items:+$items,}$item"',
  "  done <<DOCKER_PS",
  "$($SUDO docker ps --format '{{.Names}}' 2>/dev/null)",
  "DOCKER_PS",
  '  docker_json="[$items]"',
  "}",
  "",
  "main() {",
  '  local os_type="Unknown" os_version="Unknown" os_id="" os_like=""',
  "  if [ -r /etc/os-release ]; then",
  "    # shellcheck disable=SC1091",
  "    . /etc/os-release",
  '    os_type="${NAME:-Unknown}"; os_version="${VERSION_ID:-Unknown}"',
  '    os_id="${ID:-}"; os_like="${ID_LIKE:-}"',
  "  fi",
  "  local hostname_val scanned_at",
  '  hostname_val="$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo unknown)"',
  '  scanned_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"',
  "",
  '  if command -v apt-get >/dev/null 2>&1 && { [ "$os_id" = "debian" ] || [ "$os_id" = "ubuntu" ] || case " $os_like " in *" debian "*) true;; *) false;; esac; }; then',
  "    collect_apt",
  "  elif command -v dnf >/dev/null 2>&1; then",
  "    collect_dnf",
  "  elif command -v apk >/dev/null 2>&1; then",
  "    collect_apk",
  "  else",
  '    log "no supported package manager found (apt/dnf/apk)"',
  "  fi",
  "",
  "  collect_docker",
  "",
  '  printf \'{"_kind":"patch-inventory","schemaVersion":3,"hostname":"%s","osType":"%s","osVersion":"%s","packageManager":"%s","updatesCount":%s,"securityUpdatesCount":%s,"heldBackCount":%s,"removalsCount":%s,"distUpgradeRequired":%s,"totalPackages":%s,"needsReboot":%s,"rebootReason":%s,"dockerEngine":%s,"dockerImages":%s,"scannedAt":"%s"}\\n\' \\',
  '    "$(jesc "$hostname_val")" "$(jesc "$os_type")" "$(jesc "$os_version")" "$pkg_mgr" \\',
  '    "$updates" "$security" "$held_back" "$removals" "$dist_required" \\',
  '    "$total" "$needs_reboot" "$reason_json" "$docker_engine" "$docker_json" "$scanned_at"',
  "}",
  "",
  "# stdin from /dev/null so nothing in main() can consume the piped script body.",
  "main </dev/null",
].join("\n") + "\n";

const DockerCfg = z.object({
  composePath: z.string().optional().describe(
    "compose dir on the host, for safeUpdate",
  ),
  service: z.string().optional().describe(
    "compose service / container name to target",
  ),
  healthUrl: z.string().url().optional().describe(
    "URL probed from the swamp host after update",
  ),
  healthExpectStatus: z.number().int().default(200),
}).describe("Presence marks this machine as a docker host to inspect/update");

// A user-definable health check. Several may be listed; the machine is healthy
// only when every check passes. Each runs on the machine's own transport
// (http from the swamp host; service/command via ssh or pct exec).
const HealthCheck = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("http"),
    label: z.string().optional().describe(
      "Human-readable description for logs/reports",
    ),
    url: z.string().url().describe("Probed from the swamp host"),
    expectStatus: z.number().int().default(200),
    timeoutSec: z.number().int().default(10),
  }),
  z.object({
    type: z.literal("service"),
    label: z.string().optional(),
    name: z.string().min(1).describe(
      "systemctl is-active <name> (exit 0 = healthy)",
    ),
  }),
  z.object({
    type: z.literal("command"),
    label: z.string().optional(),
    run: z.string().min(1).describe(
      "Arbitrary command run in the machine; exit 0 = healthy",
    ),
    timeoutSec: z.number().int().default(30),
  }),
]);

const Machine = z.object({
  host: z.string().min(1).describe("Host name in the sshModel"),
  os: z.boolean().default(true).describe("Collect OS package status"),
  health: z.array(HealthCheck).default([]).describe(
    "Health checks used as the healthyAfter verdict for OS update / reboot / docker. " +
      "Every listed check must pass. Empty = reachability fallback. A source:community-script " +
      "CT with no checks derives them from its updater model (healthUrl + service).",
  ),
  reach: z.enum(["ssh", "pct"]).optional().describe(
    "How to run the OS scan: ssh (via sshModel) or pct (via the node, for CTs). " +
      "Unset = try ssh, fall back to pct when it fails and a proxmox ref exists.",
  ),
  docker: DockerCfg.optional(),
  ct: z.object({
    proxmoxNode: z.string().min(1).describe("Proxmox node the CT runs on"),
    ctid: z.number().int().describe("Proxmox CT (LXC) id"),
  }).optional().describe(
    "Marks a Proxmox CT and its location for pct exec — scan, OS update (with capture), and reboot. " +
      "A plain CT needs only this; no app source required.",
  ),
  source: z.object({
    type: z.enum(["community-script"]).describe("App update mechanism"),
    model: z.string().min(1).describe(
      "The updater instance (e.g. a @dmc/proxmox/community-script)",
    ),
  }).optional().describe(
    "Optional in-CT app updater on top of the OS lifecycle: version check + safe app update. " +
      "Its presence is what triggers app-update delegation — not merely being a CT.",
  ),
  proxmox: z.object({
    model: z.string().min(1).describe(
      "A @dmc/proxmox/community-script instance name",
    ),
  }).optional().describe(
    "DEPRECATED — use `ct` (location) + `source` (app updater). Legacy field that supplied BOTH the " +
      "CT node/ctid and the community-script app updater from one reference; still honoured as a fallback.",
  ),
  vm: z.object({
    proxmoxNode: z.string().min(1).describe(
      "Proxmox node model that can snapshot this VM",
    ),
    vmid: z.number().int().describe("Proxmox VM id"),
  }).optional().describe(
    "Marks a Proxmox VM so an OS update can snapshot it first",
  ),
});

const GlobalArgs = z.object({
  sshModel: z.string().min(1).describe(
    "Name of the @swamp/ssh model instance used to reach hosts (required — no default)",
  ),
  proxmoxNodes: z.array(z.string()).default([]).describe(
    "Optional @keeb/proxmox/node / @dmc/proxmox model names, for VM/CT discovery in `import`",
  ),
  machines: z.array(Machine).default([]).describe("The decorated fleet"),
});

const DockerImage = z.object({
  container: z.string(),
  image: z.string(),
  localDigest: z.string(),
  registryDigest: z.string(),
  updateAvailable: z.boolean().nullable(),
});

const Inventory = z.object({
  hostname: z.string(),
  osType: z.string(),
  osVersion: z.string(),
  packageManager: z.string(),
  updatesCount: z.number().nullable(),
  securityUpdatesCount: z.number().nullable(),
  heldBackCount: z.number().nullable(),
  removalsCount: z.number().nullable(),
  distUpgradeRequired: z.boolean().nullable(),
  totalPackages: z.number().nullable(),
  needsReboot: z.boolean(),
  rebootReason: z.string().nullable(),
  dockerEngine: z.string().nullable(),
  dockerImages: z.array(DockerImage).nullable(),
  reachMethod: z.enum(["ssh", "pct"]).nullable().describe(
    "How this host was scanned",
  ),
  health: z.object({
    healthy: z.boolean(),
    checks: z.array(
      z.object({ label: z.string(), ok: z.boolean(), detail: z.string() }),
    ),
  }).nullable().describe(
    "Health-check verdict, or null when no checks are defined",
  ),
  error: z.string().nullable(),
  scannedAt: z.string(),
});

const Seed = z.object({
  source: z.string(),
  machineCount: z.number(),
  yaml: z.string(),
  checkedAt: z.string(),
});

const UpdateResult = z.object({
  host: z.string(),
  service: z.string().nullable(),
  outcome: z.enum([
    "updated",
    "no-change",
    "rolled-back",
    "unhealthy",
    "skipped",
  ]),
  imageChanged: z.boolean(),
  healthyAfter: z.boolean(),
  rolledBack: z.boolean(),
  containers: z.array(
    z.object({
      ref: z.string(),
      beforeImage: z.string(),
      afterImage: z.string(),
    }),
  ),
  logs: z.string(),
  timestamp: z.string(),
});

const OsUpdateResult = z.object({
  host: z.string(),
  kind: z.enum(["vm", "ct", "bare-metal"]),
  mode: z.enum(["safe", "full"]),
  outcome: z.enum([
    "updated",
    "no-change",
    "rolled-back",
    "failed",
    "delegated",
    "skipped-unhealthy",
  ]),
  snapshot: z.string().nullable(),
  snapshotKept: z.boolean(),
  beforeUpdates: z.number().nullable(),
  afterUpdates: z.number().nullable(),
  healthyAfter: z.boolean(),
  rolledBack: z.boolean(),
  needsReboot: z.boolean(),
  logs: z.string(),
  timestamp: z.string(),
});

const RebootResult = z.object({
  host: z.string(),
  via: z.enum(["ssh", "pct"]),
  outcome: z.enum(["rebooted", "skipped", "failed", "timeout", "unhealthy"]),
  neededReboot: z.boolean().nullable(),
  confirmed: z.boolean(),
  needsRebootAfter: z.boolean().nullable(),
  waited: z.boolean(),
  logs: z.string(),
  timestamp: z.string(),
});

const PkgChange = z.object({
  name: z.string(),
  from: z.string().nullable(),
  to: z.string().nullable(),
});

// Append-only per-run audit record. Each run is written under a UNIQUE name
// (run-<host>-<ts>) so runs accumulate as separate handles that
// `swamp data list` / `swamp data query` can list and filter across the fleet.
const ImageChange = z.object({
  ref: z.string(),
  from: z.string().nullable(),
  to: z.string().nullable(),
});

const RunRecord = z.object({
  runId: z.string(),
  action: z.enum(["osUpdate", "docker", "reboot", "rollback"]),
  host: z.string(),
  outcome: z.string(),
  beforeUpdates: z.number().nullable(),
  afterUpdates: z.number().nullable(),
  packages: z.array(PkgChange).nullable(),
  packagesChanged: z.number().nullable(),
  images: z.array(ImageChange).nullable(),
  imagesChanged: z.number().nullable(),
  snapshot: z.string().nullable(),
  rolledBack: z.boolean(),
  needsReboot: z.boolean().nullable(),
  timestamp: z.string(),
});

/** Build the unique run-record name for one run (action + host + time). */
export function runName(action: string, host: string, ts: string): string {
  return `run-${action}-${host}-${ts.replace(/[:.]/g, "-")}`;
}

// Tracks the lifecycle of a pre-update Proxmox VM snapshot: it is kept through
// the reboot, health-verified, and only pruned after a retention window.
const SnapshotRecord = z.object({
  host: z.string(),
  kind: z.enum(["vm", "ct"]).default("vm").describe(
    "vm → node-model snapshot API; ct → pct snapshot on the node host",
  ),
  vmid: z.number().describe("VM id, or CT id when kind=ct"),
  proxmoxNode: z.string().describe(
    "node model (vm) or ssh host running pct (ct)",
  ),
  name: z.string(),
  reason: z.string(),
  createdAt: z.string(),
  retainUntil: z.string(),
  healthConfirmed: z.boolean(),
  rebootRequired: z.boolean(),
  rebootConfirmed: z.boolean(),
  status: z.enum(["active", "pruned"]),
  prunedAt: z.string().nullable(),
});

const PruneResult = z.object({
  scannedAt: z.string(),
  kind: z.enum(["snapshots", "images"]),
  dryRun: z.boolean(),
  pruned: z.array(
    z.object({
      host: z.string(),
      name: z.string(),
      detail: z.string().nullable(),
    }),
  ),
  kept: z.array(
    z.object({ host: z.string(), name: z.string(), reason: z.string() }),
  ),
});

// A previous docker image kept as a rollback point after a safeUpdate, retired
// by pruneImages on the same retention timeline as snapshots.
const RetainedImage = z.object({
  host: z.string(),
  ref: z.string(),
  imageId: z.string(),
  replacedBy: z.string(),
  service: z.string().nullable(),
  reason: z.string(),
  createdAt: z.string(),
  retainUntil: z.string(),
  healthConfirmed: z.boolean(),
  status: z.enum(["active", "pruned"]),
  prunedAt: z.string().nullable(),
});

/** Minimal LogTape-style logger supplied by swamp as `context.logger`. */
type Logger = {
  debug(message: string, props?: Record<string, unknown>): void;
  info(message: string, props?: Record<string, unknown>): void;
  warn(message: string, props?: Record<string, unknown>): void;
  error(message: string, props?: Record<string, unknown>): void;
};

/** Extension-author-facing method context (subset of swamp's MethodContext). */
type Ctx = {
  globalArgs: z.infer<typeof GlobalArgs>;
  repoDir: string;
  logger: Logger;
  definition: {
    id: string;
    name: string;
    version: number;
    tags: Record<string, string>;
  };
  writeResource: (
    specName: string,
    name: string,
    data: unknown,
  ) => Promise<{ name: string }>;
  readResource: (
    name: string,
    version?: number,
  ) => Promise<Record<string, unknown> | null>;
  readModelData: (
    modelName: string,
    specName?: string,
  ) => Promise<
    Array<
      { name: string; isLatest: boolean; attributes: Record<string, unknown> }
    >
  >;
};

const DEFAULT_RETENTION_HOURS = 168; // 7 days

/** Parsed result of one host from the ssh model's `script` method. */
export interface HostRun {
  host: string;
  stdout: string;
  exitCode: number;
}

/** Run `swamp model method run <sshModel> script` (fan-out) and return per-host output. */
export async function runScript(
  sshModel: string,
  hosts: string[],
  script: string,
  timeoutSec: number,
  repoDir: string,
): Promise<HostRun[]> {
  // @ts-ignore Deno API
  const proc = new Deno.Command(SWAMP_BIN, {
    args: [
      "model",
      "method",
      "run",
      sshModel,
      "script",
      "--json",
      "--quiet",
      "--repo-dir",
      repoDir,
      "--input",
      `hosts:json=${JSON.stringify(hosts)}`,
      "--input",
      "interpreter=bash",
      "--input",
      `script=${script}`,
      "--input",
      "captureOutput:json=true",
      "--input",
      `timeoutSec:json=${timeoutSec}`,
    ],
    stdout: "piped",
    stderr: "piped",
  });
  const out = await proc.output();
  const stdout = new TextDecoder().decode(out.stdout);
  // The method throws (non-zero) when ANY host fails, but still prints the JSON with
  // the successful hosts' artifacts — so parse stdout regardless of exit code.
  let parsed: {
    dataArtifacts?: Array<{ attributes?: Record<string, unknown> }>;
  };
  try {
    parsed = JSON.parse(stdout);
  } catch {
    const stderr = new TextDecoder().decode(out.stderr);
    throw new Error(
      `Could not parse ${sshModel} script output: ${
        (stdout || stderr).slice(-800)
      }`,
    );
  }
  return (parsed.dataArtifacts ?? [])
    .map((a) => a.attributes ?? {})
    .filter((at) => typeof at.host === "string")
    .map((at) => ({
      host: at.host as string,
      stdout: (at.stdout as string) ?? "",
      exitCode: (at.exitCode as number) ?? -1,
    }));
}

/** Best-effort fire of `swamp model method run <model> <method>`. */
async function runModelMethod(
  model: string,
  method: string,
  repoDir: string,
): Promise<boolean> {
  // @ts-ignore Deno API
  const proc = new Deno.Command(SWAMP_BIN, {
    args: [
      "model",
      "method",
      "run",
      model,
      method,
      "--json",
      "--quiet",
      "--repo-dir",
      repoDir,
    ],
    stdout: "piped",
    stderr: "piped",
  });
  const out = await proc.output();
  return out.code === 0;
}

/** Outcome of one `swamp model method run` call: success flag plus the output tails. */
export interface MethodRunResult {
  ok: boolean;
  rc: number;
  stdout: string;
  stderr: string;
}

/** Run `swamp model method run <model> <method> --input k:json=<v>…`; no logging. */
async function execModelMethodInput(
  model: string,
  method: string,
  input: Record<string, unknown>,
  repoDir: string,
): Promise<MethodRunResult> {
  const inputArgs: string[] = [];
  for (const [k, v] of Object.entries(input)) {
    inputArgs.push("--input", `${k}:json=${JSON.stringify(v)}`);
  }
  // @ts-ignore Deno API
  const proc = new Deno.Command(SWAMP_BIN, {
    args: [
      "model",
      "method",
      "run",
      model,
      method,
      "--json",
      "--quiet",
      "--repo-dir",
      repoDir,
      ...inputArgs,
    ],
    stdout: "piped",
    stderr: "piped",
  });
  const out = await proc.output();
  return {
    ok: out.code === 0,
    rc: out.code,
    stdout: new TextDecoder().decode(out.stdout).slice(-1000),
    stderr: new TextDecoder().decode(out.stderr).slice(-1000),
  };
}

/** Fire `swamp model method run <model> <method> --input k:json=<v>…`; returns success. */
async function runModelMethodInput(
  model: string,
  method: string,
  input: Record<string, unknown>,
  repoDir: string,
  logger: Logger,
): Promise<boolean> {
  const res = await execModelMethodInput(model, method, input, repoDir);
  if (!res.ok) {
    logger.warn("{model} {method} failed with rc {rc}: {stderr}", {
      model,
      method,
      rc: res.rc,
      stderr: res.stderr.slice(-300),
    });
  }
  return res.ok;
}

/** True when a failed run says the method does not know the argument `name`.
 *  swamp prints "Unknown method input(s): <names>. Valid inputs are: …". */
export function isUnknownArgumentError(
  res: MethodRunResult,
  name: string,
): boolean {
  if (res.ok) return false;
  const text = `${res.stderr}\n${res.stdout}`;
  // Only the part before "Valid inputs" lists the rejected names.
  const rejected = text.split(/valid inputs/i)[0];
  return /unknown|unrecognized/i.test(rejected) &&
    new RegExp(`\\b${name}\\b`).test(rejected);
}

/** Run the community-script source's `safeUpdate` for a CT whose snapshot @dmc/patch
 *  already owns: passes `{ snapshot: false }` so the source takes no snapshot of its own.
 *  An older source (@dmc/proxmox < 2026.10.01.1) rejects that argument; then retry ONCE
 *  with no arguments. Any other failure is returned as is, never retried. */
export async function runSourceSafeUpdate(
  src: string,
  repoDir: string,
  logger: Logger,
): Promise<boolean> {
  const first = await execModelMethodInput(
    src,
    "safeUpdate",
    { snapshot: false },
    repoDir,
  );
  if (first.ok) return true;
  if (!isUnknownArgumentError(first, "snapshot")) {
    logger.warn("{model} {method} failed with rc {rc}: {stderr}", {
      model: src,
      method: "safeUpdate",
      rc: first.rc,
      stderr: first.stderr.slice(-300),
    });
    return false;
  }
  logger.warn(
    "{model} safeUpdate does not support snapshot:false (needs @dmc/proxmox >= 2026.10.01.1), so it took its own extra snapshot",
    { model: src },
  );
  return await runModelMethod(src, "safeUpdate", repoDir);
}

/** Run one shell command on a single host via `<sshModel> exec`; returns rc + output.
 *  The command is wrapped to always exit 0 and self-report its rc (like community-script). */
export async function nodeExec(
  sshModel: string,
  host: string,
  command: string,
  timeoutSec: number,
  repoDir: string,
): Promise<{ rc: number; out: string }> {
  const wrapped = `{ ${command}; } 2>&1; printf '\\n${RC_SENTINEL}=%s\\n' "$?"`;
  // @ts-ignore Deno API
  const proc = new Deno.Command(SWAMP_BIN, {
    args: [
      "model",
      "method",
      "run",
      sshModel,
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
  const res = await proc.output();
  const stdout = new TextDecoder().decode(res.stdout);
  if (res.code !== 0) {
    throw new Error(
      `ssh transport to ${host} via ${sshModel} failed: ${
        new TextDecoder().decode(res.stderr).slice(-400)
      }`,
    );
  }
  const attrs = (JSON.parse(stdout) as {
    dataArtifacts?: Array<
      { attributes?: { stdout?: string; exitCode?: number } }
    >;
  }).dataArtifacts?.[0]?.attributes ?? {};
  const raw = attrs.stdout ?? "";
  const m = raw.match(new RegExp(`${RC_SENTINEL}=(\\d+)\\s*$`));
  const rc = m ? parseInt(m[1], 10) : (attrs.exitCode ?? -1);
  const out = m ? raw.slice(0, m.index).replace(/\s+$/, "") : raw;
  return { rc, out };
}

/** Pull the single marker JSON line out of merged stdout. */
export function markerLine(stdout: string, kind: string): string | null {
  const needle = `"_kind":"${kind}"`;
  for (const line of stdout.split("\n")) {
    const t = line.trim();
    if (t.startsWith("{") && t.includes(needle)) return t;
  }
  return null;
}

/** UTF-8-safe base64 (the collector's comments contain non-Latin1 chars). */
export function utf8b64(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export interface MachineShape {
  host: string;
  ct?: { proxmoxNode: string; ctid: number };
  source?: { type: string; model: string };
  proxmox?: { model: string };
  vm?: { proxmoxNode: string; vmid: number };
  reach?: "ssh" | "pct";
  health?: Array<z.infer<typeof HealthCheck>>;
}

/** True when a machine is a Proxmox CT (new `ct`, or legacy pct/proxmox ref). */
export function isCtMachine(m: MachineShape): boolean {
  return !!m.ct || (!m.vm && (m.reach === "pct" || !!m.proxmox?.model));
}

/** The community-script app-updater instance for a machine, or null. */
export function appSource(m: MachineShape): string | null {
  if (m.source?.type === "community-script") return m.source.model;
  if (m.proxmox?.model) return m.proxmox.model; // legacy
  return null;
}

/** Resolve a CT's node + ctid: from `ct`, else legacy (read from the proxmox model). */
export async function ctLocation(
  m: MachineShape,
  repoDir: string,
): Promise<{ node: string; ctid: number }> {
  if (m.ct) return { node: m.ct.proxmoxNode, ctid: m.ct.ctid };
  const model = m.proxmox?.model;
  if (!model) {
    throw new Error(
      `${m.host}: no CT location (need a \`ct\` decoration or legacy proxmox.model)`,
    );
  }
  // @ts-ignore Deno API
  const out = await new Deno.Command(SWAMP_BIN, {
    args: ["model", "get", model, "--json", "--quiet", "--repo-dir", repoDir],
    stdout: "piped",
    stderr: "piped",
  }).output();
  const ga = (JSON.parse(new TextDecoder().decode(out.stdout)) as {
    globalArguments?: { node?: string; ctid?: number };
  }).globalArguments ?? {};
  if (!ga.node || !ga.ctid) throw new Error(`${model}: no node/ctid`);
  return { node: ga.node, ctid: ga.ctid };
}

/** The effective health checks for a machine: its own `health`, else derived from a
 *  community-script `source` (its healthUrl + service), else empty (reachability). */
export async function resolveHealthChecks(
  m: MachineShape,
  repoDir: string,
): Promise<Array<z.infer<typeof HealthCheck>>> {
  if (m.health && m.health.length) return m.health;
  const src = appSource(m);
  if (!src) return [];
  // @ts-ignore Deno API
  const out = await new Deno.Command(SWAMP_BIN, {
    args: ["model", "get", src, "--json", "--quiet", "--repo-dir", repoDir],
    stdout: "piped",
    stderr: "piped",
  }).output();
  if (out.code !== 0) return [];
  const ga = (JSON.parse(new TextDecoder().decode(out.stdout)) as {
    globalArguments?: {
      healthUrl?: string;
      healthExpectStatus?: number;
      service?: string;
    };
  }).globalArguments ?? {};
  const checks: Array<z.infer<typeof HealthCheck>> = [];
  if (ga.healthUrl) {
    checks.push({
      type: "http",
      label: `${src} app HTTP`,
      url: ga.healthUrl,
      expectStatus: ga.healthExpectStatus ?? 200,
      timeoutSec: 10,
    });
  }
  if (ga.service) {
    checks.push({
      type: "service",
      label: `${ga.service} active`,
      name: ga.service,
    });
  }
  return checks;
}

/** Run a shell snippet on a machine via its transport: pct exec for a CT, ssh otherwise. */
async function runOnMachine(
  m: MachineShape,
  sshModel: string,
  snippet: string,
  timeoutSec: number,
  repoDir: string,
): Promise<{ rc: number; out: string }> {
  if (isCtMachine(m) && !m.vm) {
    const { node, ctid } = await ctLocation(m, repoDir);
    const runs = await runScript(
      sshModel,
      [node],
      `pct exec ${ctid} -- bash -c "echo '${
        utf8b64(snippet)
      }' | base64 -d | bash"`,
      timeoutSec,
      repoDir,
    );
    const r = runs.find((x) => x.host === node) ?? runs[0];
    return { rc: r?.exitCode ?? -1, out: r?.stdout ?? "" };
  }
  return await nodeExec(sshModel, m.host, snippet, timeoutSec, repoDir);
}

export interface HealthResult {
  healthy: boolean;
  results: Array<{ label: string; ok: boolean; detail: string }>;
}

/** The inventory record's `health` field for a verdict (null when no checks ran). */
export function inventoryHealth(
  h: HealthResult | null,
): { healthy: boolean; checks: HealthResult["results"] } | null {
  return h ? { healthy: h.healthy, checks: h.results } : null;
}

/** Evaluate a machine's health checks (all must pass). Empty list ⇒ healthy=true. */
export async function evalHealth(
  m: MachineShape,
  checks: Array<z.infer<typeof HealthCheck>>,
  sshModel: string,
  repoDir: string,
): Promise<HealthResult> {
  const results: HealthResult["results"] = [];
  for (const c of checks) {
    let ok = false;
    let detail = "";
    let label = c.label ?? "";
    if (c.type === "http") {
      if (!label) label = `http ${c.expectStatus} ${c.url}`;
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), c.timeoutSec * 1000);
      try {
        const res = await fetch(c.url, {
          signal: ctrl.signal,
          redirect: "manual",
        });
        ok = res.status === c.expectStatus;
        detail = `status ${res.status}`;
      } catch (e) {
        detail = `fetch failed: ${(e as Error).message.slice(0, 60)}`;
      } finally {
        clearTimeout(timer);
      }
    } else if (c.type === "service") {
      if (!label) label = `service ${c.name} active`;
      // Init-agnostic: systemd (is-active) OR OpenRC (rc-service status, for Alpine).
      const r = await runOnMachine(
        m,
        sshModel,
        `systemctl is-active ${c.name} >/dev/null 2>&1 || rc-service ${c.name} status >/dev/null 2>&1`,
        30,
        repoDir,
      );
      ok = r.rc === 0;
      detail = ok ? "active" : `not active (rc ${r.rc})`;
    } else {
      if (!label) label = `command: ${c.run.slice(0, 40)}`;
      const r = await runOnMachine(m, sshModel, c.run, c.timeoutSec, repoDir);
      ok = r.rc === 0;
      detail = `rc ${r.rc}`;
    }
    results.push({ label, ok, detail });
  }
  return { healthy: results.every((r) => r.ok), results };
}

/** Timing of the post-update health re-checks. Tests shrink it; the defaults are real. */
export const healthPolling: {
  intervalMs: number;
  sleep: (ms: number) => Promise<void>;
  now: () => number;
} = {
  intervalMs: 10_000,
  sleep: (ms) => new Promise<void>((r) => setTimeout(r, ms)),
  now: () => Date.now(),
};

/** Evaluate health, and while it is unhealthy re-evaluate every `intervalMs` (10 s)
 *  until it is healthy or `graceSec` has elapsed. Returns the final result. Each failed
 *  attempt is logged at info with the failing labels. `graceSec` 0 = one evaluation.
 *  A `docker-ce` upgrade restarts every container, so the first check can read
 *  unhealthy for a good update. Do NOT use this for a pre-flight check. */
export async function evalHealthWithGrace(
  evaluate: () => Promise<HealthResult>,
  graceSec: number,
  logger: Logger,
  timing: Pick<typeof healthPolling, "intervalMs" | "sleep" | "now"> =
    healthPolling,
): Promise<HealthResult> {
  const deadline = timing.now() + graceSec * 1000;
  for (let attempt = 1;; attempt++) {
    const res = await evaluate();
    if (res.healthy) return res;
    logger.info("health attempt {attempt} failed: {labels}", {
      attempt,
      labels: res.results.filter((r) => !r.ok).map((r) => r.label).join("; "),
    });
    const remainingMs = deadline - timing.now();
    if (remainingMs <= 0) return res;
    await timing.sleep(Math.min(timing.intervalMs, remainingMs));
  }
}

// ---------------------------------------------------------------------------
// Pre-flight checks. swamp runs them before a method, never inside it.
// A user skips one with `--skip-check <name>`, a whole group with
// `--skip-check-label <label>` (policy | live), or all with `--skip-checks`.
// ---------------------------------------------------------------------------

/** What a check receives from swamp (subset of the check context). */
export interface CheckCtx {
  globalArgs: z.infer<typeof GlobalArgs>;
  repoDir: string;
  methodName?: string;
  /** Method arguments merged with the global arguments. Not in the swamp docs, so optional. */
  unresolvedMethodArgs?: Record<string, unknown>;
}

export interface CheckResult {
  pass: boolean;
  errors?: string[];
}

const PASS: CheckResult = { pass: true };

function fail(...errors: string[]): CheckResult {
  return { pass: false, errors };
}

/** The text that tells a user how to skip a check. */
function skipHint(name: string, label: "policy" | "live"): string {
  return `To skip this check: --skip-check ${name} (or --skip-check-label ${label}).`;
}

/** One method argument as a check sees it; undefined when it is absent or still a CEL expression. */
export function checkArg(ctx: CheckCtx, key: string): unknown {
  const v = ctx.unresolvedMethodArgs?.[key];
  if (typeof v === "string" && (v === "" || v.includes("${{"))) {
    return undefined;
  }
  return v;
}

/** The `host` argument of the method about to run, or undefined when checks cannot see it. */
export function checkHost(ctx: CheckCtx): string | undefined {
  const h = checkArg(ctx, "host");
  return typeof h === "string" ? h : undefined;
}

/** The named machine, or undefined. A check passes quietly when it is undefined. */
function checkMachine(
  ctx: CheckCtx,
): { host: string; machine: Machine } | null {
  const host = checkHost(ctx);
  if (host === undefined) return null;
  const machine = ctx.globalArgs.machines.find((m) => m.host === host);
  return machine ? { host, machine } : null;
}

type Machine = z.infer<typeof Machine>;

/** Names of the snapshots of a VM, from the node model's read-only `listVmSnapshots`. */
export async function vmSnapshotNames(
  nodeModel: string,
  vmid: number,
  repoDir: string,
): Promise<string[] | null> {
  // @ts-ignore Deno API
  const out = await new Deno.Command(SWAMP_BIN, {
    args: [
      "model",
      "method",
      "run",
      nodeModel,
      "listVmSnapshots",
      "--json",
      "--quiet",
      "--repo-dir",
      repoDir,
      "--input",
      `vmid:json=${vmid}`,
    ],
    stdout: "piped",
    stderr: "piped",
  }).output();
  if (out.code !== 0) {
    throw new Error(
      new TextDecoder().decode(out.stderr).slice(-300) || `rc ${out.code}`,
    );
  }
  try {
    const parsed = JSON.parse(new TextDecoder().decode(out.stdout)) as {
      dataArtifacts?: Array<
        { attributes?: { snapshots?: Array<{ name?: string }> } }
      >;
    };
    const list = parsed.dataArtifacts?.[0]?.attributes?.snapshots;
    if (!Array.isArray(list)) return null;
    return list.map((s) => s.name ?? "").filter((n) => n && n !== "current");
  } catch {
    return null; // the node answered, but the list is not readable
  }
}

/** `policy` — the `host` argument names a machine in the fleet. */
export function checkHostInFleet(ctx: CheckCtx): CheckResult {
  const host = checkHost(ctx);
  if (host === undefined) return PASS; // prune without a host filter, or no input yet
  if (ctx.globalArgs.machines.some((m) => m.host === host)) return PASS;
  const known = ctx.globalArgs.machines.map((m) => m.host).join(", ") ||
    "(none)";
  return fail(
    `No machine "${host}" in globalArguments.machines. Known machines: ${known}. ` +
      `Fix the host name, or add the machine to the fleet. ${
        skipHint("host-in-fleet", "policy")
      }`,
  );
}

/** `policy` — the machine has a `docker` block (safeUpdate works on compose hosts only). */
export function checkDockerConfigured(ctx: CheckCtx): CheckResult {
  const found = checkMachine(ctx);
  if (!found) return PASS; // host-in-fleet reports an unknown host
  if (found.machine.docker) return PASS;
  return fail(
    `Machine "${found.host}" has no \`docker\` block, so safeUpdate has nothing to update. ` +
      `Add docker: { composePath, service } to the machine, or use safeOsUpdate. ${
        skipHint("docker-configured", "policy")
      }`,
  );
}

/** `live` — the machine answers: ssh `true`, or `pct status` on the node for a CT. */
export async function checkHostReachable(ctx: CheckCtx): Promise<CheckResult> {
  const found = checkMachine(ctx);
  if (!found) return PASS;
  const { host, machine } = found;
  const { sshModel } = ctx.globalArgs;
  // safeUpdate always reaches the docker host over ssh; the others follow the OS path.
  const viaPct = ctx.methodName !== "safeUpdate" && !machine.vm &&
    isCtMachine(machine);
  try {
    if (viaPct) {
      const { node, ctid } = await ctLocation(machine, ctx.repoDir);
      const r = await nodeExec(
        sshModel,
        node,
        `pct status ${ctid}`,
        30,
        ctx.repoDir,
      );
      if (r.rc !== 0 || !/status:\s*running/.test(r.out)) {
        return fail(
          `CT "${host}" (ctid ${ctid}) is not running on node "${node}" ` +
            `(pct status rc ${r.rc}). Start the CT or fix its ct decoration. ${
              skipHint("host-reachable", "live")
            }`,
        );
      }
      return PASS;
    }
    const r = await nodeExec(sshModel, host, "true", 30, ctx.repoDir);
    if (r.rc !== 0) {
      return fail(
        `Host "${host}" did not answer over ${sshModel} (rc ${r.rc}). ` +
          `Bring the host up or fix its ssh access. ${
            skipHint("host-reachable", "live")
          }`,
      );
    }
    return PASS;
  } catch (e) {
    return fail(
      `Host "${host}" is not reachable: ${
        (e as Error).message.slice(0, 300)
      }. ` +
        `Bring the host up or fix its transport. ${
          skipHint("host-reachable", "live")
        }`,
    );
  }
}

/** `live` — the machine's own health checks pass now. No checks resolved = nothing to gate. */
export async function checkBaselineHealthy(
  ctx: CheckCtx,
): Promise<CheckResult> {
  const found = checkMachine(ctx);
  if (!found) return PASS;
  const { host, machine } = found;
  try {
    const health = await resolveHealthChecks(machine, ctx.repoDir);
    if (!health.length) return PASS;
    const res = await evalHealth(
      machine,
      health,
      ctx.globalArgs.sshModel,
      ctx.repoDir,
    );
    if (res.healthy) return PASS;
    const bad = res.results.filter((r) => !r.ok).map((r) =>
      `${r.label} (${r.detail})`
    ).join("; ");
    return fail(
      `Machine "${host}" is unhealthy before the update. Failing health check(s): ${bad}. ` +
        `Fix the machine first, so a later rollback does not hide an old fault. ${
          skipHint("baseline-healthy", "live")
        }`,
    );
  } catch (e) {
    return fail(
      `Could not evaluate the health checks of "${host}": ${
        (e as Error).message.slice(0, 300)
      }. ${skipHint("baseline-healthy", "live")}`,
    );
  }
}

/** `live` — the VM/CT location resolves, its node answers, and (rollback) a snapshot exists. */
export async function checkSnapshotTargetResolves(
  ctx: CheckCtx,
): Promise<CheckResult> {
  const found = checkMachine(ctx);
  if (!found) return PASS;
  const { host, machine } = found;
  const hint = skipHint("snapshot-target-resolves", "live");
  const isCt = !machine.vm && isCtMachine(machine);
  if (!machine.vm && !isCt) return PASS; // bare metal: nothing to snapshot
  const wanted = checkArg(ctx, "snapshot");
  const needSnapshot = ctx.methodName === "rollback";
  let names: string[] | null = null;
  let where: string;
  try {
    if (machine.vm) {
      const { proxmoxNode, vmid } = machine.vm;
      where = `VM ${vmid} via node model "${proxmoxNode}"`;
      names = await vmSnapshotNames(proxmoxNode, vmid, ctx.repoDir);
    } else {
      const { node, ctid } = await ctLocation(machine, ctx.repoDir);
      where = `CT ${ctid} on node "${node}"`;
      const r = await nodeExec(
        ctx.globalArgs.sshModel,
        node,
        `pct listsnapshot ${ctid}`,
        30,
        ctx.repoDir,
      );
      if (r.rc !== 0) {
        return fail(
          `Machine "${host}": ${where} did not answer (pct listsnapshot rc ${r.rc}). ` +
            `Fix the ct decoration or the node. ${hint}`,
        );
      }
      names = [...r.out.matchAll(/->\s*(\S+)/g)].map((m) => m[1]).filter((n) =>
        n !== "current"
      );
    }
  } catch (e) {
    return fail(
      `Machine "${host}": the snapshot target did not resolve: ${
        (e as Error).message.slice(0, 300)
      }. Fix the vm/ct decoration or the node. ${hint}`,
    );
  }
  if (needSnapshot && names !== null) {
    if (typeof wanted === "string" && !names.includes(wanted)) {
      return fail(
        `Machine "${host}": ${where} has no snapshot named "${wanted}" ` +
          `(found: ${
            names.join(", ") || "none"
          }). Pick an existing snapshot. ${hint}`,
      );
    }
    if (typeof wanted !== "string" && names.length === 0) {
      return fail(
        `Machine "${host}": ${where} has no snapshot to roll back to. ${hint}`,
      );
    }
  }
  return PASS;
}

/** @dmc/patch/fleet model. */
export const model = {
  type: "@dmc/patch/fleet",
  version: "2026.10.01.1",
  upgrades: [
    {
      toVersion: "2026.10.01.1",
      description:
        "Version bump, no globalArguments schema change (adds the healthGraceSec method argument and single-snapshot CT updates)",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  globalArguments: GlobalArgs,
  resources: {
    inventory: {
      description: "Per-machine OS + docker patch status",
      schema: Inventory,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    seed: {
      description: "A suggested machines block produced by `import`",
      schema: Seed,
      lifetime: "infinite" as const,
      garbageCollection: 3,
    },
    update: {
      description: "Result of a safeUpdate run",
      schema: UpdateResult,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    osUpdate: {
      description:
        "Result of a safeOsUpdate run (snapshot-guarded host OS update)",
      schema: OsUpdateResult,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    reboot: {
      description: "Result of a reboot run",
      schema: RebootResult,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    run: {
      description:
        "Append-only audit record, one per run (osUpdate / docker / reboot), uniquely named so runs accumulate for `swamp data list` / `swamp data query`.",
      schema: RunRecord,
      lifetime: "infinite" as const,
      garbageCollection: 1000,
    },
    snapshot: {
      description:
        "Lifecycle of a pre-update VM snapshot: kept through the reboot, health-verified, pruned only after a retention window by pruneSnapshots.",
      schema: SnapshotRecord,
      lifetime: "infinite" as const,
      garbageCollection: 1000,
    },
    image: {
      description:
        "A previous docker image kept as a rollback point after safeUpdate; retired by pruneImages after a retention window (same timeline as snapshots).",
      schema: RetainedImage,
      lifetime: "infinite" as const,
      garbageCollection: 1000,
    },
    prune: {
      description: "Result of a pruneSnapshots / pruneImages run",
      schema: PruneResult,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
  },
  checks: {
    "host-in-fleet": {
      description:
        "The host argument names a machine in globalArguments.machines (prune methods: only when a host filter is given)",
      labels: ["policy"],
      appliesTo: [
        "safeUpdate",
        "safeOsUpdate",
        "reboot",
        "rollback",
        "pruneSnapshots",
        "pruneImages",
      ],
      execute: (context: CheckCtx) =>
        Promise.resolve(checkHostInFleet(context)),
    },
    "docker-configured": {
      description: "The machine has a docker block, which safeUpdate needs",
      labels: ["policy"],
      appliesTo: ["safeUpdate"],
      execute: (context: CheckCtx) =>
        Promise.resolve(checkDockerConfigured(context)),
    },
    "host-reachable": {
      description:
        "The machine answers: ssh `true` through the sshModel, or `pct status` on the node for a CT. Not run for rollback, because a broken host is why you roll back",
      labels: ["live"],
      appliesTo: ["safeUpdate", "safeOsUpdate", "reboot"],
      execute: (context: CheckCtx) => checkHostReachable(context),
    },
    "baseline-healthy": {
      description:
        "The machine's health checks pass before the update (passes when the machine resolves no health checks). Not run for reboot or rollback, because those can be the fix",
      labels: ["live"],
      appliesTo: ["safeUpdate", "safeOsUpdate"],
      execute: (context: CheckCtx) => checkBaselineHealthy(context),
    },
    "snapshot-target-resolves": {
      description:
        "The VM/CT snapshot target resolves and its Proxmox node answers; for rollback, a snapshot also exists. A machine with no vm/ct passes",
      labels: ["live"],
      appliesTo: ["safeOsUpdate", "rollback", "pruneSnapshots"],
      execute: (context: CheckCtx) => checkSnapshotTargetResolves(context),
    },
  },
  methods: {
    scan: {
      description:
        "Fan out over the fleet: collect OS + docker image-drift per machine, and fire community-script checkUpdate for proxmox-referenced machines.",
      arguments: z.object({}),
      execute: async (_args: unknown, context: {
        globalArgs: z.infer<typeof GlobalArgs>;
        repoDir: string;
        logger: Logger;
        writeResource: (
          spec: string,
          name: string,
          data: unknown,
        ) => Promise<{ name: string }>;
      }) => {
        const { sshModel, machines } = context.globalArgs;
        const repoDir = context.repoDir;
        context.logger.info("Scanning {count} machines via {sshModel}", {
          count: machines.length,
          sshModel,
        });
        const collector = COLLECTOR_SCRIPT;
        const collectorB64 = utf8b64(collector);

        const handles: Array<{ name: string }> = [];
        const scannedAt = new Date().toISOString();

        const errorInv = (h: string, error: string) => ({
          hostname: h,
          osType: "Unknown",
          osVersion: "Unknown",
          packageManager: "unknown",
          updatesCount: null,
          securityUpdatesCount: null,
          heldBackCount: null,
          removalsCount: null,
          distUpgradeRequired: null,
          totalPackages: null,
          needsReboot: false,
          rebootReason: null,
          dockerEngine: null,
          dockerImages: null,
          reachMethod: null,
          health: null,
          error,
          scannedAt,
        });

        // Run the collector INSIDE a CT via `pct exec` on its node. The CT's location
        // comes from its `ct` decoration (or, legacy, the referenced proxmox model).
        const scanPct = async (m: MachineShape): Promise<string | null> => {
          const { node, ctid } = await ctLocation(m, repoDir);
          const wrapped =
            `pct exec ${ctid} -- bash -c "echo '${collectorB64}' | base64 -d | bash"`;
          const runs = await runScript(sshModel, [node], wrapped, 240, repoDir);
          const r = runs.find((x) => x.host === node) ?? runs[0];
          return r ? markerLine(r.stdout, "patch-inventory") : null;
        };

        // Per machine: reach=ssh (default) tries SSH then falls back to pct when a
        // proxmox ref exists; reach=pct goes straight to pct. reachMethod records which
        // worked. Per-machine (not fan-out) so one unreachable host can't sink the run.
        for (const m of machines) {
          if (m.os === false) continue;
          const h = m.host;
          let line: string | null = null;
          let method: "ssh" | "pct" | null = null;
          let err = "";

          if (m.reach !== "pct") {
            try {
              const runs = await runScript(
                sshModel,
                [h],
                collector,
                240,
                repoDir,
              );
              const r = runs.find((x) => x.host === h) ?? runs[0];
              line = r ? markerLine(r.stdout, "patch-inventory") : null;
              if (line) method = "ssh";
              else err = `no inventory${r ? ` (exit ${r.exitCode})` : ""}`;
            } catch (e) {
              err = `ssh: ${(e as Error).message.slice(0, 90)}`;
            }
          }
          if (!line && isCtMachine(m)) {
            try {
              line = await scanPct(m);
              if (line) method = "pct";
              else {err = err
                  ? `${err}; pct: no inventory`
                  : "pct: no inventory";}
            } catch (e) {
              err = `${err ? err + "; " : ""}pct: ${
                (e as Error).message.slice(0, 90)
              }`;
            }
          }

          // Evaluate health checks (own, or derived from a community-script source).
          let health: {
            healthy: boolean;
            checks: Array<{ label: string; ok: boolean; detail: string }>;
          } | null = null;
          try {
            const checks = await resolveHealthChecks(m, repoDir);
            if (checks.length) {
              const hres = await evalHealth(m, checks, sshModel, repoDir);
              health = { healthy: hres.healthy, checks: hres.results };
            }
          } catch { /* health stays null */ }

          if (line) {
            handles.push(
              await context.writeResource(
                "inventory",
                h,
                {
                  ...(JSON.parse(line) as Record<string, unknown>),
                  reachMethod: method,
                  health,
                  error: null,
                },
              ),
            );
          } else {
            handles.push(
              await context.writeResource("inventory", h, {
                ...errorInv(h, err || "unreachable"),
                health,
              }),
            );
          }
        }

        // Fire checkUpdate on each machine's app source (community-script) for fresh
        // data the report reads; best-effort, never fails the scan.
        for (const m of machines) {
          const src = appSource(m);
          if (src) await runModelMethod(src, "checkUpdate", repoDir);
        }

        context.logger.info(
          "Scanned {count} machines via {sshModel}: wrote {records} inventory records",
          { count: machines.length, sshModel, records: handles.length },
        );
        return { dataHandles: handles };
      },
    },

    import: {
      description:
        "Emit a suggested `machines` block seeded from the sshModel host list (and, later, Proxmox guests) to paste into globalArguments and decorate.",
      arguments: z.object({}),
      execute: async (_args: unknown, context: {
        globalArgs: z.infer<typeof GlobalArgs>;
        repoDir: string;
        logger: Logger;
        writeResource: (
          spec: string,
          name: string,
          data: unknown,
        ) => Promise<{ name: string }>;
      }) => {
        const { sshModel, proxmoxNodes } = context.globalArgs;
        const repoDir = context.repoDir;
        context.logger.info(
          "Seeding machines from {sshModel} and {nodeCount} Proxmox nodes",
          { sshModel, nodeCount: proxmoxNodes.length },
        );
        const dec = new TextDecoder();
        const swamp = (args: string[]) =>
          // @ts-ignore Deno API
          new Deno.Command(SWAMP_BIN, {
            args: [...args, "--quiet", "--repo-dir", repoDir],
            stdout: "piped",
            stderr: "piped",
          }).output();

        // 1) Discover Proxmox guests first, indexed by name (so ssh hosts can be decorated).
        interface Guest {
          type: "qemu" | "lxc";
          vmid: number;
          node: string;
          ip: string | null;
          pnode: string;
        }
        const guests = new Map<string, Guest>();
        const notes: string[] = [];
        for (const pnode of proxmoxNodes) {
          try {
            await swamp([
              "model",
              "method",
              "run",
              pnode,
              "listGuests",
              "--json",
            ]);
            const gout = await swamp([
              "data",
              "get",
              pnode,
              "guests",
              "--json",
            ]);
            const content =
              (JSON.parse(dec.decode(gout.stdout)) as { content?: unknown })
                .content;
            const parsed = typeof content === "string"
              ? JSON.parse(content)
              : content;
            const gs = (parsed as {
              guests?: Array<
                {
                  type: string;
                  vmid: number;
                  name: string;
                  node: string;
                  ip: string | null;
                }
              >;
            })?.guests ?? [];
            for (const g of gs) {
              if (g.type === "qemu" || g.type === "lxc") {
                guests.set(g.name, {
                  type: g.type,
                  vmid: g.vmid,
                  node: g.node,
                  ip: g.ip,
                  pnode,
                });
              }
            }
            notes.push(`# Proxmox ${pnode}: ${gs.length} guests`);
          } catch (e) {
            notes.push(
              `# Proxmox ${pnode} discovery failed: ${
                (e as Error).message.slice(0, 100)
              }`,
            );
          }
        }

        // Emit one decorated machine block, using the guest map for vm/proxmox marks.
        const seen = new Set<string>();
        const lines = ["machines:"];
        const emit = (name: string, tags: string[] = [], comment = "") => {
          if (seen.has(name)) return;
          seen.add(name);
          const g = guests.get(name);
          lines.push(
            `  - host: ${name}${comment ? `   # ${comment}` : ""}`,
            `    os: true`,
          );
          if (tags.includes("docker")) {
            lines.push(
              `    docker: {}   # set composePath / service / healthUrl`,
            );
          }
          if (g?.type === "qemu") {
            lines.push(
              `    vm:   # Proxmox VM — snapshot before OS update`,
              `      proxmoxNode: ${g.pnode}`,
              `      vmid: ${g.vmid}`,
            );
          }
          if (g?.type === "lxc") {
            lines.push(
              `    reach: pct`,
              `    ct:   # Proxmox CT — OS update via pct exec (captured)`,
              `      proxmoxNode: ${g.pnode}`,
              `      ctid: ${g.vmid}`,
              `    # source:   # optional app updater on top of the OS lifecycle`,
              `    #   type: community-script`,
              `    #   model: ${name}   # a @dmc/proxmox/community-script instance`,
            );
          }
        };

        // 2) ssh model host list (decorated from discovery).
        let sshHosts: Array<{ name: string; tags?: string[] }> = [];
        try {
          sshHosts = (JSON.parse(
            dec.decode(
              (await swamp(["model", "get", sshModel, "--json"])).stdout,
            ),
          ) as {
            globalArguments?: {
              hosts?: Array<{ name: string; tags?: string[] }>;
            };
          }).globalArguments?.hosts ?? [];
        } catch (e) {
          lines.push(
            `  # sshModel ${sshModel} read failed: ${
              (e as Error).message.slice(0, 100)
            }`,
          );
        }
        const sshNames = new Set(sshHosts.map((h) => h.name));
        for (const h of sshHosts) emit(h.name, h.tags ?? []);

        // 3) Discovered guests not already in the ssh model → new machines + ssh suggestions.
        const newSshHosts: Array<{ name: string; ip: string }> = [];
        if (guests.size > 0) {
          lines.push(
            `  # --- from Proxmox discovery ---`,
            ...notes.map((n) => `  ${n}`),
          );
        }
        for (const [name, g] of guests) {
          if (sshNames.has(name)) continue;
          emit(
            name,
            [],
            `${g.type === "qemu" ? "VM" : "CT"} ${g.vmid}, ${
              g.ip ? `ip ${g.ip}` : "no ip — agent off?"
            }`,
          );
          if (g.ip) newSshHosts.push({ name, ip: g.ip });
        }

        if (newSshHosts.length > 0) {
          lines.push(
            "",
            `# Discovered guests not in ${sshModel}. Add these to its host list so the`,
            `# fleet can SSH them (adjust user/tags; CTs also need sshd, else use pct exec):`,
            "#   hosts:",
          );
          for (const h of newSshHosts) {
            lines.push(`#     - name: ${h.name}`, `#       address: ${h.ip}`);
          }
        }

        const yaml = lines.join("\n") + "\n";
        const handle = await context.writeResource("seed", "seed", {
          source: proxmoxNodes.length
            ? `${sshModel} + proxmox(${proxmoxNodes.join(",")})`
            : sshModel,
          machineCount: seen.size,
          yaml,
          checkedAt: new Date().toISOString(),
        });
        context.logger.info("Seeded {count} machines:\n{yaml}", {
          count: seen.size,
          yaml,
        });
        return { dataHandles: [handle] };
      },
    },

    safeUpdate: {
      description:
        "Health-checked, rollback-capable docker update for one machine: record image ids, pull + up -d, wait for health, roll back to the prior image on failure.",
      arguments: z.object({
        host: z.string().min(1).describe(
          "Machine (host) to update — must have a `docker` decoration",
        ),
        service: z.string().optional().describe(
          "Override the machine's docker.service",
        ),
        healthTimeoutSec: z.number().int().default(120),
        pollIntervalSec: z.number().int().default(5),
        rollbackOnFailure: z.boolean().default(true),
        retentionHours: z.number().int().default(DEFAULT_RETENTION_HOURS)
          .describe(
            "How long the previous image is kept as a rollback point before pruneImages may delete it (default 7 days). Old images are never pruned inline.",
          ),
      }),
      execute: async (args: {
        host: string;
        service?: string;
        healthTimeoutSec: number;
        pollIntervalSec: number;
        rollbackOnFailure: boolean;
        retentionHours: number;
      }, context: Ctx) => {
        const { sshModel, machines } = context.globalArgs;
        const repoDir = context.repoDir;
        const machine = machines.find((m) => m.host === args.host);
        if (!machine?.docker) {
          throw new Error(`machine "${args.host}" has no docker decoration`);
        }
        const dcfg = machine.docker;
        const svc = args.service ?? dcfg.service ?? null;
        const svcArg = svc ? ` ${svc}` : "";
        const cd = dcfg.composePath ? `cd ${dcfg.composePath} && ` : "";
        const logs: string[] = [];
        const log = (m: string) => {
          logs.push(m);
          context.logger.info("[safeUpdate {host}] {message}", {
            host: args.host,
            message: m,
          });
        };
        context.logger.info(
          "Starting docker update of {service} on {host}",
          { service: svc, host: args.host },
        );
        const ex = (cmd: string, t = 60) =>
          nodeExec(sshModel, args.host, cmd, t, repoDir);
        const runTs = new Date().toISOString();
        // Append-only audit record for this docker run, including which container
        // images changed (from → to). Full detail also lives in `update-<host>`.
        const writeRun = (
          outcome: string,
          rolledBack: boolean,
          images: Array<z.infer<typeof ImageChange>> | null = null,
        ) =>
          context.writeResource("run", runName("docker", args.host, runTs), {
            runId: `docker-${args.host}-${runTs.replace(/[:.]/g, "-")}`,
            action: "docker",
            host: args.host,
            outcome,
            beforeUpdates: null,
            afterUpdates: null,
            packages: null,
            packagesChanged: null,
            images,
            imagesChanged: images ? images.length : null,
            snapshot: null,
            rolledBack,
            needsReboot: null,
            timestamp: runTs,
          });

        const idsOf = async (): Promise<string[]> =>
          (await ex(`${cd}docker compose ps -q${svcArg}`)).out.split("\n").map((
            s,
          ) => s.trim()).filter(Boolean);
        const snapshot = async (
          ids: string[],
        ): Promise<Map<string, string>> => {
          const map = new Map<string, string>();
          for (const id of ids) {
            const r = await ex(
              `docker inspect ${id} --format '{{.Config.Image}}|{{.Image}}'`,
            );
            const [ref, img] = r.out.trim().split("|");
            if (ref && img) map.set(ref, img);
          }
          return map;
        };
        // health: true=healthy, false=failed, null=not yet
        const health = async (): Promise<boolean | null> => {
          if (dcfg.healthUrl) {
            const ctrl = new AbortController();
            const t = setTimeout(() => ctrl.abort(), 8000);
            try {
              const r = await fetch(dcfg.healthUrl, {
                signal: ctrl.signal,
                redirect: "manual",
              });
              return r.status === dcfg.healthExpectStatus ? true : null;
            } catch {
              return null;
            } finally {
              clearTimeout(t);
            }
          }
          const ids = await idsOf();
          if (ids.length === 0) return false;
          for (const id of ids) {
            const r = await ex(
              `docker inspect ${id} --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}'`,
            );
            const [status, hs] = r.out.trim().split("|");
            if (status === "exited" || status === "dead") return false;
            if (hs === "unhealthy") return false;
            if (status !== "running" || hs === "starting") return null;
          }
          return true;
        };

        const beforeIds = await idsOf();
        if (beforeIds.length === 0) {
          log("no running containers — nothing to update");
          const handle = await context.writeResource(
            "update",
            `update-${args.host}`,
            {
              host: args.host,
              service: svc,
              outcome: "skipped",
              imageChanged: false,
              healthyAfter: false,
              rolledBack: false,
              containers: [],
              logs: logs.join("\n"),
              timestamp: new Date().toISOString(),
            },
          );
          context.logger.info(
            "Docker update of {host} finished: outcome={outcome}",
            { host: args.host, outcome: "skipped" },
          );
          return { dataHandles: [handle, await writeRun("skipped", false)] };
        }
        const before = await snapshot(beforeIds);
        log(
          `before: ${
            [...before.entries()].map(([r, i]) => `${r}=${i.slice(0, 19)}`)
              .join(", ")
          }`,
        );

        const up = await ex(
          `${cd}docker compose pull${svcArg} && docker compose up -d${svcArg}`,
          300,
        );
        if (up.rc !== 0) {
          log(`pull/up failed (rc ${up.rc}) — nothing changed`);
          const handle = await context.writeResource(
            "update",
            `update-${args.host}`,
            {
              host: args.host,
              service: svc,
              outcome: "unhealthy",
              imageChanged: false,
              healthyAfter: false,
              rolledBack: false,
              containers: [...before.entries()].map(([ref, img]) => ({
                ref,
                beforeImage: img,
                afterImage: img,
              })),
              logs: logs.join("\n"),
              timestamp: new Date().toISOString(),
            },
          );
          context.logger.info(
            "Docker update of {host} finished: outcome={outcome}",
            { host: args.host, outcome: "unhealthy" },
          );
          return { dataHandles: [handle, await writeRun("unhealthy", false)] };
        }

        const after = await snapshot(await idsOf());
        const imageChanged = [...after.entries()].some(([ref, img]) =>
          before.get(ref) !== img
        );
        log(
          imageChanged
            ? "image(s) changed — waiting for health"
            : "no image change — waiting for health",
        );

        const deadline = Date.now() + args.healthTimeoutSec * 1000;
        let healthyAfter = false;
        for (;;) {
          const h = await health();
          if (h === true) {
            healthyAfter = true;
            break;
          }
          if (Date.now() >= deadline) break;
          await new Promise((r) => setTimeout(r, args.pollIntervalSec * 1000));
        }

        let outcome: z.infer<typeof UpdateResult>["outcome"];
        let rolledBack = false;
        if (healthyAfter) {
          outcome = imageChanged ? "updated" : "no-change";
          log(`healthy (${outcome})`);
          // Old images are NOT pruned inline; they are retained as rollback points
          // and retired later by pruneImages (see the retained-image records below).
        } else if (args.rollbackOnFailure) {
          log("unhealthy — rolling back to previous image(s)");
          for (const [ref, oldImg] of before.entries()) {
            await ex(`docker tag ${oldImg} ${ref}`);
          }
          await ex(`${cd}docker compose up -d --force-recreate${svcArg}`, 300);
          rolledBack = true;
          outcome = "rolled-back";
          log(
            (await health()) === true
              ? "rolled back; healthy again"
              : "rolled back; not confirmed healthy",
          );
        } else {
          outcome = "unhealthy";
          log("unhealthy — rollback disabled");
        }

        const handle = await context.writeResource(
          "update",
          `update-${args.host}`,
          {
            host: args.host,
            service: svc,
            outcome,
            imageChanged,
            healthyAfter,
            rolledBack,
            containers: [...before.entries()].map(([ref, img]) => ({
              ref,
              beforeImage: img,
              afterImage: after.get(ref) ?? img,
            })),
            logs: logs.join("\n"),
            timestamp: new Date().toISOString(),
          },
        );
        // Record only the containers whose image actually changed.
        const imageChanges = [...before.entries()]
          .filter(([ref, img]) => (after.get(ref) ?? img) !== img)
          .map(([ref, img]) => ({ ref, from: img, to: after.get(ref) ?? img }));
        const dataHandles = [
          handle,
          await writeRun(outcome, rolledBack, imageChanges),
        ];
        // On a healthy update, retain each replaced image as a rollback point on
        // the same retention timeline as snapshots; pruneImages retires them later.
        if (healthyAfter && !rolledBack && imageChanges.length) {
          const retainUntil = new Date(
            new Date(runTs).getTime() + args.retentionHours * 3600 * 1000,
          ).toISOString();
          for (const c of imageChanges) {
            dataHandles.push(
              await context.writeResource(
                "image",
                `image-${args.host}-${runTs.replace(/[:.]/g, "-")}-${
                  c.ref.replace(/[^A-Za-z0-9]/g, "_")
                }`,
                {
                  host: args.host,
                  ref: c.ref,
                  imageId: c.from,
                  replacedBy: c.to,
                  service: svc,
                  reason: "safeUpdate",
                  createdAt: runTs,
                  retainUntil,
                  healthConfirmed: true,
                  status: "active",
                  prunedAt: null,
                },
              ),
            );
          }
          log(
            `retained ${imageChanges.length} old image(s) until ${retainUntil}`,
          );
        }
        context.logger.info(
          "Docker update of {host} finished: outcome={outcome} rolledBack={rolledBack}",
          { host: args.host, outcome, rolledBack },
        );
        return { dataHandles };
      },
    },
    safeOsUpdate: {
      description:
        "Snapshot-guarded OS update for one machine. Proxmox VM (vm decoration): snapshot via the node model → upgrade over ssh → re-scan; roll back the snapshot when the host does not return healthy. Proxmox CT (proxmox decoration): delegate to the community-script safeUpdate. Bare metal: plain safe upgrade, no snapshot. Reboot is never automatic.",
      arguments: z.object({
        host: z.string().min(1).describe("Machine (host) to update"),
        mode: z.enum(["safe", "full"]).default("safe").describe(
          "apt: safe = `upgrade` (never removes), full = `full-upgrade`. dnf/apk always upgrade.",
        ),
        retentionHours: z.number().int().default(DEFAULT_RETENTION_HOURS)
          .describe(
            "How long the pre-update VM snapshot is retained as a rollback point before pruneSnapshots may delete it (default 7 days). The snapshot is never auto-deleted.",
          ),
        rollbackOnFailure: z.boolean().default(true).describe(
          "Roll back when the machine is unhealthy after the upgrade",
        ),
        healthGraceSec: z.number().int().min(0).default(120).describe(
          "Grace window for the post-update health check. While the machine is unhealthy, re-check every 10 s until healthy or this many seconds have passed (a docker-ce upgrade restarts every container). 0 = check once.",
        ),
      }),
      execute: async (args: {
        host: string;
        mode: "safe" | "full";
        retentionHours: number;
        rollbackOnFailure: boolean;
        healthGraceSec: number;
      }, context: Ctx) => {
        const { sshModel, machines } = context.globalArgs;
        const repoDir = context.repoDir;
        const machine = machines.find((m) => m.host === args.host);
        if (!machine) throw new Error(`no machine "${args.host}" in the fleet`);
        const logs: string[] = [];
        const log = (m: string) => {
          logs.push(m);
          context.logger.info("[safeOsUpdate {host}] {message}", {
            host: args.host,
            message: m,
          });
        };
        context.logger.info("Starting OS update ({mode}) of {host}", {
          mode: args.mode,
          host: args.host,
        });

        // Health checks (machine's own, or derived from a community-script source).
        // The BEFORE-update gate is the `baseline-healthy` pre-flight check (bypass
        // with `--skip-check baseline-healthy`); here they judge the result only.
        const checks = await resolveHealthChecks(machine, repoDir);
        // After an update: health verdict. With checks → evalHealth; else reachability.
        // Last post-update verdict, written into the refreshed inventory record.
        let lastHealth: HealthResult | null = null;
        const afterHealthy = async (reachable: boolean): Promise<boolean> => {
          if (!checks.length) return reachable;
          const h = await evalHealthWithGrace(
            () => evalHealth(machine, checks, sshModel, repoDir),
            args.healthGraceSec,
            context.logger,
          );
          lastHealth = h;
          log(
            `post-update health: ${
              h.results.map((r) => `${r.ok ? "✓" : "✗"} ${r.label}`).join("; ")
            }`,
          );
          return h.healthy;
        };

        // Shared OS-update pieces (both the CT-via-pct and VM/bare-via-ssh paths).
        // upScript works as root (pct exec) or via sudo -n (ssh non-root).
        const aptMode = args.mode === "full" ? "full-upgrade" : "upgrade";
        // DEBIAN_FRONTEND is exported (not inlined after $SUDO) so it never lands in
        // command position — `$SUDO VAR=val cmd` breaks when $SUDO is non-empty.
        const upScript = [
          `export DEBIAN_FRONTEND=noninteractive`,
          `SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo -n"`,
          `if command -v apt-get >/dev/null 2>&1; then`,
          `  $SUDO apt-get update -qq && $SUDO apt-get -y ${aptMode}`,
          `elif command -v dnf >/dev/null 2>&1; then`,
          `  $SUDO dnf -y upgrade`,
          `elif command -v apk >/dev/null 2>&1; then`,
          `  $SUDO apk upgrade`,
          `else echo "no known package manager" >&2; exit 3; fi`,
        ].join("\n");
        const pkgCmd =
          `if command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n'; ` +
          `elif command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='\${Package}\\t\${Version}\\n'; ` +
          `elif command -v apk >/dev/null 2>&1; then apk info -v | sed 's/-\\([^-]*-r[0-9][0-9]*\\)$/\\t\\1/'; fi`;
        const parseManifest = (out: string): Map<string, string> => {
          const m = new Map<string, string>();
          for (const ln of out.split("\n")) {
            const t = ln.trim();
            if (!t) continue;
            const tab = t.indexOf("\t");
            if (tab > 0) m.set(t.slice(0, tab), t.slice(tab + 1));
            else m.set(t, "");
          }
          return m;
        };
        const diffPkgs = (b: Map<string, string>, a: Map<string, string>) => {
          const names = new Set<string>([...b.keys(), ...a.keys()]);
          const out: Array<z.infer<typeof PkgChange>> = [];
          for (const n of names) {
            const from = b.get(n) ?? null;
            const to = a.get(n) ?? null;
            if (from !== to) out.push({ name: n, from, to });
          }
          out.sort((x, y) => x.name.localeCompare(y.name));
          return out;
        };
        const collector = COLLECTOR_SCRIPT;

        // ---- CT: snapshot-guarded OS update inside the container via pct (captured),
        // plus the optional app updater (community-script) on top — one snapshot guards both. ----
        if (isCtMachine(machine) && !machine.vm) {
          const { node, ctid } = await ctLocation(machine, repoDir);
          const collectorB64 = utf8b64(collector);
          // Ship a shell snippet into the CT via pct, piped as a script (like scanCt) to
          // avoid the nested-quote breakage of `pct exec -- sh -c "..."` through exec.
          const ctExec = async (
            snippet: string,
            t: number,
          ): Promise<{ rc: number; out: string }> => {
            const runs = await runScript(
              sshModel,
              [node],
              `pct exec ${ctid} -- bash -c "echo '${
                utf8b64(snippet)
              }' | base64 -d | bash"`,
              t,
              repoDir,
            );
            const r = runs.find((x) => x.host === node) ?? runs[0];
            return { rc: r?.exitCode ?? -1, out: r?.stdout ?? "" };
          };
          const scanCt = async (): Promise<
            z.infer<typeof Inventory> | null
          > => {
            try {
              const runs = await runScript(
                sshModel,
                [node],
                `pct exec ${ctid} -- bash -c "echo '${collectorB64}' | base64 -d | bash"`,
                240,
                repoDir,
              );
              const r = runs.find((x) => x.host === node) ?? runs[0];
              const line = r ? markerLine(r.stdout, "patch-inventory") : null;
              return line
                ? JSON.parse(line) as z.infer<typeof Inventory>
                : null;
            } catch {
              return null;
            }
          };
          const pct = (opArgs: string, t = 300) =>
            nodeExec(sshModel, node, `pct ${opArgs}`, t, repoDir);

          const before = await scanCt();
          if (!before) {
            throw new Error(
              `CT "${args.host}" (ctid ${ctid}) not reachable via pct — cannot update`,
            );
          }
          log(
            `before: ${
              before.updatesCount ?? "?"
            } updates (${before.packageManager}) via pct`,
          );
          const beforePkgs = parseManifest((await ctExec(pkgCmd, 120)).out);

          // Snapshot the CT up front (guards the OS update AND the app update on top).
          const snapCreatedAt = new Date().toISOString();
          const snap = `preupdate-${snapCreatedAt.replace(/[:.]/g, "-")}`;
          log(`snapshot ${snap} (ctid ${ctid}) via pct on ${node}`);
          const s = await pct(`snapshot ${ctid} ${snap}`);
          if (s.rc !== 0) {
            throw new Error(
              `pct snapshot failed for ctid ${ctid} (rc ${s.rc}) — aborting update`,
            );
          }

          log(`upgrading CT (${args.mode}) via pct`);
          const up = await ctExec(upScript, 1800);
          log(`upgrade rc ${up.rc}`);

          // App updater (community-script) on top — only when a source is configured.
          const src = appSource(machine);
          let appNote = "";
          if (src) {
            // This method owns the snapshot (taken above) and the rollback, so the
            // source must not take a second, untracked snapshot.
            const ok = await runSourceSafeUpdate(src, repoDir, context.logger);
            appNote = `; app ${src}: ${ok ? "ok" : "failed"}`;
            log(`app source ${src} safeUpdate: ${ok ? "ok" : "failed"}`);
          }

          const after = await scanCt();
          const reachable = after !== null;
          const healthy = await afterHealthy(reachable);
          const pkgs = reachable
            ? diffPkgs(
              beforePkgs,
              parseManifest((await ctExec(pkgCmd, 120)).out),
            )
            : null;
          if (pkgs) log(`packages changed: ${pkgs.length}`);

          let ctOutcome: z.infer<typeof OsUpdateResult>["outcome"];
          let rolledBack = false;
          if (!healthy) {
            log(`unhealthy after update — rolling back to ${snap}`);
            rolledBack = (await pct(`rollback ${ctid} ${snap}`)).rc === 0;
            ctOutcome = "rolled-back";
            log(
              rolledBack
                ? `rolled back to ${snap}`
                : `ROLLBACK FAILED — snapshot ${snap} kept`,
            );
          } else if (up.rc !== 0) {
            ctOutcome = "failed"; // upgrade failed but CT is up — no rollback, snapshot retained
            log(
              "upgrade command failed — CT healthy, no rollback; snapshot retained",
            );
          } else {
            ctOutcome =
              (before.updatesCount ?? 0) !== (after!.updatesCount ?? 0)
                ? "updated"
                : "no-change";
          }

          const runTs = new Date().toISOString();
          const retainUntil = new Date(
            new Date(snapCreatedAt).getTime() +
              args.retentionHours * 3600 * 1000,
          ).toISOString();
          const dataHandles = [
            await context.writeResource("osUpdate", `os-update-${args.host}`, {
              host: args.host,
              kind: "ct",
              mode: args.mode,
              outcome: ctOutcome,
              snapshot: snap,
              snapshotKept: !rolledBack,
              beforeUpdates: before.updatesCount ?? null,
              afterUpdates: after?.updatesCount ?? null,
              healthyAfter: healthy,
              rolledBack,
              needsReboot: after?.needsReboot ?? false,
              logs: logs.join("\n") + appNote,
              timestamp: runTs,
            }),
            await context.writeResource(
              "run",
              runName("osUpdate", args.host, runTs),
              {
                runId: `osUpdate-${args.host}-${runTs.replace(/[:.]/g, "-")}`,
                action: "osUpdate",
                host: args.host,
                outcome: ctOutcome,
                beforeUpdates: before.updatesCount ?? null,
                afterUpdates: after?.updatesCount ?? null,
                packages: pkgs,
                packagesChanged: pkgs ? pkgs.length : null,
                images: null,
                imagesChanged: null,
                snapshot: snap,
                rolledBack,
                needsReboot: after?.needsReboot ?? null,
                timestamp: runTs,
              },
            ),
          ];
          // Track the CT snapshot for retention/prune (unless a rollback already consumed it).
          if (!rolledBack) {
            dataHandles.push(
              await context.writeResource(
                "snapshot",
                `snap-${args.host}-${snapCreatedAt.replace(/[:.]/g, "-")}`,
                {
                  host: args.host,
                  kind: "ct",
                  vmid: ctid,
                  proxmoxNode: node,
                  name: snap,
                  reason: "safeOsUpdate",
                  createdAt: snapCreatedAt,
                  retainUntil,
                  healthConfirmed: healthy,
                  rebootRequired: after?.needsReboot ?? false,
                  rebootConfirmed: false,
                  status: "active",
                  prunedAt: null,
                },
              ),
            );
            log(`snapshot ${snap} retained until ${retainUntil}`);
          }
          if (after) {
            dataHandles.push(
              await context.writeResource("inventory", args.host, {
                ...after,
                reachMethod: "pct",
                // After a rollback the restored state is unchecked: leave it to the next scan.
                health: rolledBack ? null : inventoryHealth(lastHealth),
                error: null,
              }),
            );
          }
          context.logger.info(
            "OS update of {host} finished: outcome={outcome} rolledBack={rolledBack}",
            { host: args.host, outcome: ctOutcome, rolledBack },
          );
          return { dataHandles };
        }

        // ---- VM / bare metal: OS upgrade over ssh, snapshot-guarded for VMs ----
        const isVm = !!machine.vm;
        const scanHost = async (): Promise<
          z.infer<typeof Inventory> | null
        > => {
          let runs: HostRun[] = [];
          try {
            runs = await runScript(
              sshModel,
              [args.host],
              collector,
              240,
              repoDir,
            );
          } catch {
            return null;
          }
          const r = runs.find((x) => x.host === args.host) ?? runs[0];
          if (!r) return null;
          const line = markerLine(r.stdout, "patch-inventory");
          if (!line) return null;
          try {
            return JSON.parse(line) as z.infer<typeof Inventory>;
          } catch {
            return null;
          }
        };

        const before = await scanHost();
        if (!before) {
          throw new Error(
            `host "${args.host}" is not ssh-reachable — cannot update`,
          );
        }
        log(
          `before: ${
            before.updatesCount ?? "?"
          } updates (${before.packageManager})`,
        );

        let snap: string | null = null;
        let snapCreatedAt: string | null = null;
        if (isVm) {
          snapCreatedAt = new Date().toISOString();
          snap = `preupdate-${snapCreatedAt.replace(/[:.]/g, "-")}`;
          log(
            `snapshot ${snap} (vmid ${machine.vm!.vmid}) via ${
              machine.vm!.proxmoxNode
            }`,
          );
          const s = await runModelMethodInput(
            machine.vm!.proxmoxNode,
            "snapshotVm",
            { vmid: machine.vm!.vmid, name: snap },
            repoDir,
            context.logger,
          );
          if (!s) {
            throw new Error(
              `snapshot failed on ${machine.vm!.proxmoxNode} for vmid ${
                machine.vm!.vmid
              } — aborting update`,
            );
          }
        }

        // Installed-package manifest over ssh, for the before/after diff (shared pkgCmd/parse).
        const manifest = async (): Promise<Map<string, string>> => {
          try {
            return parseManifest(
              (await nodeExec(sshModel, args.host, pkgCmd, 120, repoDir)).out,
            );
          } catch {
            return new Map();
          }
        };
        const beforePkgs = await manifest();

        log(`upgrading (${args.mode})`);
        const up = await nodeExec(sshModel, args.host, upScript, 1800, repoDir);
        log(`upgrade rc ${up.rc}`);

        let outcome: z.infer<typeof OsUpdateResult>["outcome"];
        let rolledBack = false;
        // Snapshots are never auto-deleted here — they are retained as a rollback
        // point and only removed later by pruneSnapshots after the retention window.
        const snapshotKept = isVm && !!snap;
        const after = await scanHost();
        const healthy = await afterHealthy(after !== null);

        if (up.rc !== 0) {
          // The upgrade command failed but the host is still up — do NOT roll back.
          outcome = "failed";
          log(
            "upgrade command failed — host left as-is, no rollback; snapshot retained",
          );
        } else if (healthy) {
          outcome = (before.updatesCount ?? 0) !== (after?.updatesCount ?? 0)
            ? "updated"
            : "no-change";
          log(`healthy after (${after?.updatesCount ?? "?"} updates left)`);
        } else if (isVm && snap && args.rollbackOnFailure) {
          log(`unhealthy after upgrade — rolling back to ${snap}`);
          rolledBack = await runModelMethodInput(
            machine.vm!.proxmoxNode,
            "rollbackVm",
            { vmid: machine.vm!.vmid, name: snap },
            repoDir,
            context.logger,
          );
          outcome = "rolled-back";
          log(
            rolledBack
              ? `rolled back to ${snap}`
              : `ROLLBACK FAILED — snapshot ${snap} kept for manual recovery`,
          );
        } else {
          outcome = "failed";
          log(
            isVm
              ? "unhealthy — rollback disabled; snapshot retained"
              : "unhealthy after upgrade (bare metal, no snapshot)",
          );
        }

        // What changed: diff the installed-package manifest before vs after.
        let pkgs: Array<z.infer<typeof PkgChange>> | null = null;
        if (after) {
          pkgs = diffPkgs(beforePkgs, await manifest());
          log(`packages changed: ${pkgs.length}`);
        }

        const runTs = new Date().toISOString();
        const dataHandles = [
          await context.writeResource("osUpdate", `os-update-${args.host}`, {
            host: args.host,
            kind: isVm ? "vm" : "bare-metal",
            mode: args.mode,
            outcome,
            snapshot: snap,
            snapshotKept,
            beforeUpdates: before.updatesCount ?? null,
            afterUpdates: after?.updatesCount ?? null,
            healthyAfter: healthy,
            rolledBack,
            needsReboot: after?.needsReboot ?? false,
            logs: logs.join("\n"),
            timestamp: runTs,
          }),
          // Append-only audit record for this run (includes the package diff).
          await context.writeResource(
            "run",
            runName("osUpdate", args.host, runTs),
            {
              runId: `osUpdate-${args.host}-${runTs.replace(/[:.]/g, "-")}`,
              action: "osUpdate",
              host: args.host,
              outcome,
              beforeUpdates: before.updatesCount ?? null,
              afterUpdates: after?.updatesCount ?? null,
              packages: pkgs,
              packagesChanged: pkgs ? pkgs.length : null,
              images: null,
              imagesChanged: null,
              snapshot: snap,
              rolledBack,
              needsReboot: after?.needsReboot ?? null,
              timestamp: runTs,
            },
          ),
        ];
        // Track the snapshot lifecycle: kept as a rollback point, health-verified
        // by the post-upgrade re-scan, pruned later by pruneSnapshots.
        if (isVm && snap && snapCreatedAt) {
          const retainUntil = new Date(
            new Date(snapCreatedAt).getTime() +
              args.retentionHours * 3600 * 1000,
          ).toISOString();
          dataHandles.push(
            await context.writeResource(
              "snapshot",
              `snap-${args.host}-${snapCreatedAt.replace(/[:.]/g, "-")}`,
              {
                host: args.host,
                kind: "vm",
                vmid: machine.vm!.vmid,
                proxmoxNode: machine.vm!.proxmoxNode,
                name: snap,
                reason: "safeOsUpdate",
                createdAt: snapCreatedAt,
                retainUntil,
                healthConfirmed: healthy,
                rebootRequired: after?.needsReboot ?? false,
                rebootConfirmed: false,
                status: "active",
                prunedAt: null,
              },
            ),
          );
          log(`snapshot ${snap} retained until ${retainUntil}`);
        }
        // Refresh the inventory resource from the post-update scan so needsReboot
        // (and update counts) are current for the reboot guard and the report.
        if (after) {
          dataHandles.push(
            await context.writeResource("inventory", args.host, {
              ...after,
              reachMethod: "ssh",
              // After a rollback the restored state is unchecked: leave it to the next scan.
              health: rolledBack ? null : inventoryHealth(lastHealth),
              error: null,
            }),
          );
        }
        context.logger.info(
          "OS update of {host} finished: outcome={outcome} rolledBack={rolledBack}",
          { host: args.host, outcome, rolledBack },
        );
        return { dataHandles };
      },
    },
    reboot: {
      description:
        "Gracefully reboot one machine. ssh hosts (VM / bare metal) → `systemctl reboot` over sshModel (scheduled with systemd-run so the call returns before the link drops); Proxmox CTs (reach=pct) → `pct reboot <ctid>` on the node. Guarded on the last scan's needsReboot unless force. Optionally waits for the host to return and re-scans to confirm needsReboot cleared.",
      arguments: z.object({
        host: z.string().min(1).describe("Machine (host) to reboot"),
        force: z.boolean().default(false).describe(
          "Reboot even when needsReboot is false / unknown",
        ),
        wait: z.boolean().default(true).describe(
          "Wait for the host to return, then re-scan to confirm",
        ),
        waitTimeoutSec: z.number().int().default(300),
        healthGraceSec: z.number().int().min(0).default(120).describe(
          "Grace window for the post-reboot health detection. While the machine is unhealthy, re-check every 10 s until healthy or this many seconds have passed. 0 = check once.",
        ),
      }),
      execute: async (args: {
        host: string;
        force: boolean;
        wait: boolean;
        waitTimeoutSec: number;
        healthGraceSec: number;
      }, context: Ctx) => {
        const { sshModel, machines } = context.globalArgs;
        const repoDir = context.repoDir;
        const machine = machines.find((m) => m.host === args.host);
        if (!machine) throw new Error(`no machine "${args.host}" in the fleet`);
        const logs: string[] = [];
        const log = (m: string) => {
          logs.push(m);
          context.logger.info("[reboot {host}] {message}", {
            host: args.host,
            message: m,
          });
        };
        context.logger.info("Starting reboot of {host} (force={force})", {
          host: args.host,
          force: args.force,
        });
        const ts = new Date().toISOString();
        const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

        const usePct = !machine.vm && isCtMachine(machine);
        const via: "ssh" | "pct" = usePct ? "pct" : "ssh";

        // Append-only audit record for this reboot run.
        const writeRun = (outcome: string, needsRebootAfter: boolean | null) =>
          context.writeResource("run", runName("reboot", args.host, ts), {
            runId: `reboot-${args.host}-${ts.replace(/[:.]/g, "-")}`,
            action: "reboot",
            host: args.host,
            outcome,
            beforeUpdates: null,
            afterUpdates: null,
            packages: null,
            packagesChanged: null,
            images: null,
            imagesChanged: null,
            snapshot: null,
            rolledBack: false,
            needsReboot: needsRebootAfter,
            timestamp: ts,
          });

        // node + ctid for the pct path (from the `ct` decoration, or legacy proxmox ref).
        const ctInfo = () => ctLocation(machine, repoDir);

        // collector, UTF-8-safe base64 for the pct re-scan path (mirrors scan)
        const collector = COLLECTOR_SCRIPT;
        const collectorB64 = utf8b64(collector);
        const scanNow = async (): Promise<z.infer<typeof Inventory> | null> => {
          try {
            if (via === "pct") {
              const { node, ctid } = await ctInfo();
              const wrapped =
                `pct exec ${ctid} -- bash -c "echo '${collectorB64}' | base64 -d | bash"`;
              const runs = await runScript(
                sshModel,
                [node],
                wrapped,
                240,
                repoDir,
              );
              const r = runs.find((x) => x.host === node) ?? runs[0];
              const line = r ? markerLine(r.stdout, "patch-inventory") : null;
              return line
                ? JSON.parse(line) as z.infer<typeof Inventory>
                : null;
            }
            const runs = await runScript(
              sshModel,
              [args.host],
              collector,
              240,
              repoDir,
            );
            const r = runs.find((x) => x.host === args.host) ?? runs[0];
            const line = r ? markerLine(r.stdout, "patch-inventory") : null;
            return line ? JSON.parse(line) as z.infer<typeof Inventory> : null;
          } catch {
            return null;
          }
        };

        // Guard: read the last scan's needsReboot (this instance's own inventory) unless forced.
        let neededReboot: boolean | null = null;
        if (!args.force) {
          const inv = await context.readResource(args.host);
          neededReboot = inv ? !!inv.needsReboot : null;
          if (neededReboot === false) {
            log(
              "last scan shows needsReboot=false — skipping (use force to override)",
            );
            const handle = await context.writeResource(
              "reboot",
              `reboot-${args.host}`,
              {
                host: args.host,
                via,
                outcome: "skipped",
                neededReboot: false,
                confirmed: true,
                needsRebootAfter: false,
                waited: false,
                logs: logs.join("\n"),
                timestamp: ts,
              },
            );
            context.logger.info(
              "Reboot of {host} finished: outcome={outcome}",
              { host: args.host, outcome: "skipped" },
            );
            return { dataHandles: [handle, await writeRun("skipped", false)] };
          }
          log(
            neededReboot === null
              ? "needsReboot unknown — proceeding"
              : "needsReboot=true — proceeding",
          );
        }

        // Fire the reboot.
        let cmdRc: number;
        if (via === "pct") {
          const { node, ctid } = await ctInfo();
          log(`pct reboot ${ctid} on ${node}`);
          const r = await nodeExec(
            sshModel,
            node,
            `pct reboot ${ctid}`,
            180,
            repoDir,
          );
          cmdRc = r.rc;
        } else {
          // Schedule via systemd-run so the exec call returns cleanly before sshd dies.
          const cmd = `SUDO=""; [ "$(id -u)" != 0 ] && SUDO="sudo -n"; ` +
            `$SUDO systemd-run --on-active=3 --timer-property=AccuracySec=100ms systemctl reboot`;
          log("scheduling systemctl reboot (+3s) over ssh");
          const r = await nodeExec(sshModel, args.host, cmd, 30, repoDir);
          cmdRc = r.rc;
        }
        log(`reboot command rc ${cmdRc}`);
        if (cmdRc !== 0) {
          const handle = await context.writeResource(
            "reboot",
            `reboot-${args.host}`,
            {
              host: args.host,
              via,
              outcome: "failed",
              neededReboot,
              confirmed: false,
              needsRebootAfter: null,
              waited: false,
              logs: logs.join("\n"),
              timestamp: new Date().toISOString(),
            },
          );
          context.logger.info(
            "Reboot of {host} finished: outcome={outcome}",
            { host: args.host, outcome: "failed" },
          );
          return { dataHandles: [handle, await writeRun("failed", null)] };
        }

        // Wait for the host to return and confirm.
        let confirmed = false;
        let needsRebootAfter: boolean | null = null;
        let confirmInv: z.infer<typeof Inventory> | null = null;
        if (args.wait) {
          await sleep(via === "ssh" ? 15000 : 5000); // let it actually go down first
          const deadline = Date.now() + args.waitTimeoutSec * 1000;
          for (;;) {
            const inv = await scanNow();
            if (inv) {
              confirmed = true;
              needsRebootAfter = !!inv.needsReboot;
              confirmInv = inv;
              break;
            }
            if (Date.now() >= deadline) break;
            await sleep(10000);
          }
          log(
            confirmed
              ? `host answered again (needsReboot=${needsRebootAfter})`
              : "host did not return within the wait timeout",
          );
        }

        // Post-reboot health is DETECTION ONLY — a reboot cannot be rolled back
        // (the disk is unchanged). Recovery is a deliberate `rollback` to the
        // retained pre-update snapshot, never automatic here.
        const checks = await resolveHealthChecks(machine, repoDir);
        let appHealthy: boolean | null = null;
        let rebootHealth: HealthResult | null = null;
        if (confirmed && checks.length) {
          const h = await evalHealthWithGrace(
            () => evalHealth(machine, checks, sshModel, repoDir),
            args.healthGraceSec,
            context.logger,
          );
          appHealthy = h.healthy;
          rebootHealth = h;
          log(
            `post-reboot health: ${
              h.results.map((r) => `${r.ok ? "✓" : "✗"} ${r.label}`).join("; ")
            }`,
          );
        }
        const outcome: z.infer<typeof RebootResult>["outcome"] = !args.wait
          ? "rebooted"
          : !confirmed
          ? "timeout"
          : (appHealthy === false ? "unhealthy" : "rebooted");

        if (outcome === "unhealthy") {
          const snap =
            (await context.readModelData(context.definition.name, "snapshot"))
              .filter((d) =>
                d.isLatest && d.attributes.host === args.host &&
                d.attributes.status === "active"
              )
              .map((d) => d.attributes.name as string)[0];
          log(
            `⚠️ UNHEALTHY after reboot — no auto-rollback. ${
              snap
                ? `Recover deliberately: rollback host=${args.host} (reverts to snapshot ${snap})`
                : "no retained snapshot to roll back to"
            }`,
          );
        }

        const dh = [
          await context.writeResource("reboot", `reboot-${args.host}`, {
            host: args.host,
            via,
            outcome,
            neededReboot,
            confirmed,
            needsRebootAfter,
            waited: args.wait,
            logs: logs.join("\n"),
            timestamp: new Date().toISOString(),
          }),
          await writeRun(outcome, needsRebootAfter),
        ];
        // Refresh the inventory from the post-reboot confirming scan so needsReboot
        // (and the status report) reflect the rebooted host.
        if (confirmInv) {
          dh.push(
            await context.writeResource("inventory", args.host, {
              ...confirmInv,
              reachMethod: via,
              health: inventoryHealth(rebootHealth),
              error: null,
            }),
          );
        }
        // On a confirmed-healthy reboot, mark this host's active snapshot(s)
        // reboot-confirmed so pruneSnapshots can retire them after retention.
        if (outcome === "rebooted" && confirmed && needsRebootAfter === false) {
          const snaps =
            (await context.readModelData(context.definition.name, "snapshot"))
              .filter((d) =>
                d.isLatest && d.attributes.host === args.host &&
                d.attributes.status === "active"
              );
          for (const s of snaps) {
            dh.push(
              await context.writeResource("snapshot", s.name, {
                ...s.attributes,
                healthConfirmed: true,
                rebootConfirmed: true,
              }),
            );
          }
          if (snaps.length) {
            log(`marked ${snaps.length} snapshot(s) reboot-confirmed`);
          }
        }
        context.logger.info(
          "Reboot of {host} finished: outcome={outcome} confirmed={confirmed}",
          { host: args.host, outcome, confirmed },
        );
        return { dataHandles: dh };
      },
    },
    rollback: {
      description:
        "Deliberately revert a machine to a retained pre-update snapshot (VM snapshot rollback / pct rollback). The explicit recovery for an update or reboot that left the host unhealthy — a reboot itself cannot be rolled back. Reverts to the newest active snapshot for the host unless `snapshot` is given.",
      arguments: z.object({
        host: z.string().min(1).describe("Machine (host) to roll back"),
        snapshot: z.string().optional().describe(
          "Snapshot name; default = newest active retained snapshot",
        ),
      }),
      execute: async (
        args: { host: string; snapshot?: string },
        context: Ctx,
      ) => {
        const { sshModel, machines } = context.globalArgs;
        const repoDir = context.repoDir;
        const machine = machines.find((m) => m.host === args.host);
        if (!machine) throw new Error(`no machine "${args.host}" in the fleet`);
        const logs: string[] = [];
        const log = (m: string) => {
          logs.push(m);
          context.logger.info("[rollback {host}] {message}", {
            host: args.host,
            message: m,
          });
        };
        context.logger.info("Starting rollback of {host}", {
          host: args.host,
        });

        // Find the target snapshot record (this host, active), newest first.
        const recs =
          (await context.readModelData(context.definition.name, "snapshot"))
            .filter((d) =>
              d.isLatest && d.attributes.host === args.host &&
              d.attributes.status === "active"
            )
            .map((d) => ({
              name: d.name,
              a: d.attributes as unknown as z.infer<typeof SnapshotRecord>,
            }))
            .sort((x, y) => y.a.createdAt.localeCompare(x.a.createdAt));
        const target = args.snapshot
          ? recs.find((r) => r.a.name === args.snapshot)
          : recs[0];
        if (!target) {
          throw new Error(
            `no retained snapshot for "${args.host}"${
              args.snapshot ? ` named ${args.snapshot}` : ""
            } to roll back to`,
          );
        }
        const a = target.a;
        log(
          `rolling back ${a.kind} ${a.vmid} to snapshot ${a.name} (via ${a.proxmoxNode})`,
        );

        const ok = a.kind === "ct"
          ? (await nodeExec(
            sshModel,
            a.proxmoxNode,
            `pct rollback ${a.vmid} ${a.name}`,
            300,
            repoDir,
          )).rc === 0
          : await runModelMethodInput(
            a.proxmoxNode,
            "rollbackVm",
            {
              vmid: a.vmid,
              name: a.name,
            },
            repoDir,
            context.logger,
          );
        log(ok ? `rolled back to ${a.name}` : `ROLLBACK FAILED for ${a.name}`);

        // Best-effort health verdict after the revert.
        const checks = await resolveHealthChecks(machine, repoDir);
        let healthy: boolean | null = null;
        if (ok && checks.length) {
          const h = await evalHealth(machine, checks, sshModel, repoDir);
          healthy = h.healthy;
          log(
            `post-rollback health: ${
              h.results.map((r) => `${r.ok ? "✓" : "✗"} ${r.label}`).join("; ")
            }`,
          );
        }

        const runTs = new Date().toISOString();
        const handle = await context.writeResource(
          "run",
          runName("rollback", args.host, runTs),
          {
            runId: `rollback-${args.host}-${runTs.replace(/[:.]/g, "-")}`,
            action: "rollback",
            host: args.host,
            outcome: !ok
              ? "failed"
              : healthy === false
              ? "unhealthy"
              : "rolled-back",
            beforeUpdates: null,
            afterUpdates: null,
            packages: null,
            packagesChanged: null,
            images: null,
            imagesChanged: null,
            snapshot: a.name,
            rolledBack: ok,
            needsReboot: null,
            timestamp: runTs,
          },
        );
        context.logger.info(
          "Rollback of {host} finished: rolledBack={rolledBack} healthy={healthy}",
          { host: args.host, rolledBack: ok, healthy },
        );
        return { dataHandles: [handle] };
      },
    },
    pruneSnapshots: {
      description:
        "Delete retained pre-update VM snapshots that are past their retention window, health-confirmed, reboot-confirmed (when the update needed a reboot), AND pass a fresh healthcheck now. Nothing else deletes snapshots. Use dryRun to preview.",
      arguments: z.object({
        host: z.string().optional().describe(
          "Limit to one host (default: all tracked snapshots)",
        ),
        dryRun: z.boolean().default(false).describe(
          "Report what would be pruned without deleting",
        ),
        requireRebootConfirmed: z.boolean().default(true).describe(
          "Require rebootConfirmed for snapshots whose update needed a reboot",
        ),
      }),
      execute: async (
        args: {
          host?: string;
          dryRun: boolean;
          requireRebootConfirmed: boolean;
        },
        context: Ctx,
      ) => {
        const { sshModel } = context.globalArgs;
        const repoDir = context.repoDir;
        context.logger.info(
          "Pruning retained snapshots (host={host} dryRun={dryRun})",
          { host: args.host ?? "all", dryRun: args.dryRun },
        );
        const now = Date.now();
        const scannedAt = new Date().toISOString();
        const collector = COLLECTOR_SCRIPT;
        // Final live gate: host answers a scan AND no reboot is pending.
        const healthyNow = async (host: string): Promise<boolean> => {
          try {
            const runs = await runScript(
              sshModel,
              [host],
              collector,
              240,
              repoDir,
            );
            const r = runs.find((x) => x.host === host) ?? runs[0];
            const line = r ? markerLine(r.stdout, "patch-inventory") : null;
            if (!line) return false;
            return (JSON.parse(line) as z.infer<typeof Inventory>)
              .needsReboot === false;
          } catch {
            return false;
          }
        };

        const records =
          (await context.readModelData(context.definition.name, "snapshot"))
            .filter((d) =>
              d.isLatest && d.attributes.status === "active" &&
              (!args.host || d.attributes.host === args.host)
            );

        const pruned: Array<
          { host: string; name: string; detail: string | null }
        > = [];
        const kept: Array<{ host: string; name: string; reason: string }> = [];
        const handles: Array<{ name: string }> = [];

        for (const d of records) {
          const a = d.attributes as unknown as z.infer<typeof SnapshotRecord>;
          const rebootOk = !a.rebootRequired || a.rebootConfirmed ||
            !args.requireRebootConfirmed;
          if (!a.healthConfirmed) {
            kept.push({
              host: a.host,
              name: a.name,
              reason: "not health-confirmed",
            });
            continue;
          }
          if (!rebootOk) {
            kept.push({
              host: a.host,
              name: a.name,
              reason: "reboot not confirmed",
            });
            continue;
          }
          if (now < new Date(a.retainUntil).getTime()) {
            kept.push({
              host: a.host,
              name: a.name,
              reason: `retained until ${a.retainUntil}`,
            });
            continue;
          }
          if (!(await healthyNow(a.host))) {
            kept.push({
              host: a.host,
              name: a.name,
              reason: "host not healthy now",
            });
            continue;
          }
          if (args.dryRun) {
            pruned.push({
              host: a.host,
              name: a.name,
              detail: `${a.kind}:${a.vmid}`,
            });
            continue;
          }
          const ok = a.kind === "ct"
            ? (await nodeExec(
              sshModel,
              a.proxmoxNode,
              `pct delsnapshot ${a.vmid} ${a.name}`,
              180,
              repoDir,
            )).rc === 0
            : await runModelMethodInput(
              a.proxmoxNode,
              "deleteVmSnapshot",
              {
                vmid: a.vmid,
                name: a.name,
              },
              repoDir,
              context.logger,
            );
          if (!ok) {
            kept.push({
              host: a.host,
              name: a.name,
              reason: "delete call failed",
            });
            continue;
          }
          handles.push(
            await context.writeResource("snapshot", d.name, {
              ...a,
              status: "pruned",
              prunedAt: scannedAt,
            }),
          );
          pruned.push({ host: a.host, name: a.name, detail: `vmid:${a.vmid}` });
        }

        handles.push(
          await context.writeResource(
            "prune",
            `prune-snapshots-${scannedAt.replace(/[:.]/g, "-")}`,
            {
              scannedAt,
              kind: "snapshots",
              dryRun: args.dryRun,
              pruned,
              kept,
            },
          ),
        );
        context.logger.info(
          "Snapshots: {action} {prunedCount}, kept {keptCount}",
          {
            action: args.dryRun ? "would prune" : "pruned",
            prunedCount: pruned.length,
            keptCount: kept.length,
          },
        );
        return { dataHandles: handles };
      },
    },
    pruneImages: {
      description:
        "Delete retained previous docker images that are past their retention window and pass a fresh healthcheck (host reachable, old image no longer in use). Same retention timeline as snapshots. Use dryRun to preview.",
      arguments: z.object({
        host: z.string().optional().describe(
          "Limit to one host (default: all tracked images)",
        ),
        dryRun: z.boolean().default(false).describe(
          "Report what would be pruned without deleting",
        ),
      }),
      execute: async (
        args: { host?: string; dryRun: boolean },
        context: Ctx,
      ) => {
        const { sshModel } = context.globalArgs;
        const repoDir = context.repoDir;
        context.logger.info(
          "Pruning retained images (host={host} dryRun={dryRun})",
          { host: args.host ?? "all", dryRun: args.dryRun },
        );
        const now = Date.now();
        const scannedAt = new Date().toISOString();
        // Reachability gate: the docker host answers a trivial command.
        const reachable = async (host: string): Promise<boolean> => {
          try {
            return (await nodeExec(
              sshModel,
              host,
              "docker version --format '{{.Server.Version}}'",
              30,
              repoDir,
            )).rc === 0;
          } catch {
            return false;
          }
        };

        const records =
          (await context.readModelData(context.definition.name, "image"))
            .filter((d) =>
              d.isLatest && d.attributes.status === "active" &&
              (!args.host || d.attributes.host === args.host)
            );

        const pruned: Array<
          { host: string; name: string; detail: string | null }
        > = [];
        const kept: Array<{ host: string; name: string; reason: string }> = [];
        const handles: Array<{ name: string }> = [];

        for (const d of records) {
          const a = d.attributes as unknown as z.infer<typeof RetainedImage>;
          if (now < new Date(a.retainUntil).getTime()) {
            kept.push({
              host: a.host,
              name: a.ref,
              reason: `retained until ${a.retainUntil}`,
            });
            continue;
          }
          if (!(await reachable(a.host))) {
            kept.push({
              host: a.host,
              name: a.ref,
              reason: "host not reachable now",
            });
            continue;
          }
          if (args.dryRun) {
            pruned.push({
              host: a.host,
              name: a.ref,
              detail: a.imageId.slice(0, 19),
            });
            continue;
          }
          // `docker rmi` by id is inherently safe: it refuses if the image is still in use.
          const rm = await nodeExec(
            sshModel,
            a.host,
            `docker rmi ${a.imageId}`,
            60,
            repoDir,
          );
          if (rm.rc !== 0) {
            kept.push({
              host: a.host,
              name: a.ref,
              reason: "rmi failed (in use or missing)",
            });
            continue;
          }
          handles.push(
            await context.writeResource("image", d.name, {
              ...a,
              status: "pruned",
              prunedAt: scannedAt,
            }),
          );
          pruned.push({
            host: a.host,
            name: a.ref,
            detail: a.imageId.slice(0, 19),
          });
        }

        handles.push(
          await context.writeResource(
            "prune",
            `prune-images-${scannedAt.replace(/[:.]/g, "-")}`,
            {
              scannedAt,
              kind: "images",
              dryRun: args.dryRun,
              pruned,
              kept,
            },
          ),
        );
        context.logger.info(
          "Images: {action} {prunedCount}, kept {keptCount}",
          {
            action: args.dryRun ? "would prune" : "pruned",
            prunedCount: pruned.length,
            keptCount: kept.length,
          },
        );
        return { dataHandles: handles };
      },
    },
  },
};

export { RC_SENTINEL };
