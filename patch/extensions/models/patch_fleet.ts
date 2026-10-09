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

// The swamp CLI, used only by `checkSwamp` (pre-flight checks get no runModel).
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
  kind: z.enum(["snapshots", "images", "retired"]),
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

/** Metadata of one stored record, as `dataRepository.findAllForModel` returns it (latest version). */
type OwnDataMeta = {
  name: string;
  version: number;
  tags: Record<string, string>;
  /** True for a deletion marker. */
  isDeleted?: boolean;
};

/** Extension-author-facing method context (subset of swamp's MethodContext). Other
 *  models are reached through `runModel` / `readModelData` / `definitionRepository`
 *  (see `methodSwamp`). */
type Ctx = SwampMethodCtx & {
  globalArgs: z.infer<typeof GlobalArgs>;
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
  /** Opaque model type token; the data repository needs it with the model id. */
  modelType: unknown;
  /** The model id (never renamed), under which all records of this model are stored. */
  modelId: string;
  /** Low-level data API. Own records are read here, by model id (see `readOwnRecords`). */
  dataRepository: {
    findAllForModel(type: unknown, modelId: string): Promise<OwnDataMeta[]>;
    getContent(
      type: unknown,
      modelId: string,
      dataName: string,
      version?: number,
    ): Promise<Uint8Array | null>;
  };
  /** Remove every version of one stored resource. A no-op when it is absent. */
  deleteResource: (instanceName: string) => Promise<void>;
};

/** One record of this model, in the shape `readModelData` returned. */
export interface OwnRecord {
  name: string;
  isLatest: boolean;
  attributes: Record<string, unknown>;
}

/**
 * Read this model's OWN records by model id. `context.readModelData(name, spec)`
 * matches the `modelName` tag that swamp stamps on a record when it is written.
 * After a model rename, every older record carries the old name and
 * `readModelData` can not see it. The model id never changes, so this reads
 * `dataRepository.findAllForModel(modelType, modelId)` (latest version of each
 * name), keeps the records whose `specName` tag is one of `specs`, and parses
 * their JSON. Deleted records and records that are not valid JSON are skipped.
 * `readModelData` stays for reading OTHER models only.
 */
export async function readOwnRecords(
  context: Pick<Ctx, "dataRepository" | "modelType" | "modelId">,
  specs: string | readonly string[],
): Promise<Array<OwnRecord & { specName: string }>> {
  const wanted = new Set(typeof specs === "string" ? [specs] : specs);
  const dec = new TextDecoder();
  const out: Array<OwnRecord & { specName: string }> = [];
  const metas = await context.dataRepository.findAllForModel(
    context.modelType,
    context.modelId,
  );
  for (const m of metas) {
    const specName = m.tags?.specName ?? "";
    if (!wanted.has(specName) || m.isDeleted) continue;
    const raw = await context.dataRepository.getContent(
      context.modelType,
      context.modelId,
      m.name,
      m.version,
    );
    if (!raw) continue;
    try {
      const attributes = JSON.parse(dec.decode(raw));
      if (attributes && typeof attributes === "object") {
        out.push({ name: m.name, isLatest: true, attributes, specName });
      }
    } catch { /* not JSON: skip */ }
  }
  return out;
}

/** The latest records of one spec of this model. */
async function readOwnSpec(
  context: Pick<Ctx, "dataRepository" | "modelType" | "modelId">,
  spec: string,
): Promise<OwnRecord[]> {
  return await readOwnRecords(context, spec);
}

const DEFAULT_RETENTION_HOURS = 168; // 7 days

// ---------------------------------------------------------------------------
// Reaching other models. Methods use swamp's in-process API (`context.runModel`,
// `context.readModelData`, `context.definitionRepository`). Pre-flight checks get
// no `runModel` from swamp, so the live checks fall back to the swamp CLI.
// ---------------------------------------------------------------------------

/** Outcome of running another model's method. `artifacts` = attributes of the resources it wrote. */
export interface RunOutcome {
  ok: boolean;
  artifacts: Array<Record<string, unknown>>;
  error: string;
}

/** How this model reaches other models: `methodSwamp` in methods, `checkSwamp` in checks. */
export interface SwampApi {
  run(
    model: string,
    method: string,
    args?: Record<string, unknown>,
  ): Promise<RunOutcome>;
  /** Latest records of another model's spec (methods only; undefined in checks). */
  readData?(
    model: string,
    spec: string,
  ): Promise<Array<{ name: string; attributes: Record<string, unknown> }>>;
  /** Raw globalArguments of a definition, or null when it does not exist. */
  globalArguments(model: string): Promise<Record<string, unknown> | null>;
}

/** The part of swamp's definition repository this model uses. */
type DefinitionLookup = {
  findByNameGlobal(
    name: string,
  ): Promise<{ definition: { globalArguments: unknown } } | null>;
};

/** What `context.runModel` returns (subset): it never throws. */
type RunModelResult =
  | {
    ok: true;
    resources: Array<{ name: string; attributes?: Record<string, unknown> }>;
  }
  | { ok: false; error: { message: string } };

/** The parts of swamp's method context that reach other models. */
export type SwampMethodCtx = {
  runModel?: (opts: {
    definition: string;
    method: string;
    arguments?: Record<string, unknown>;
  }) => Promise<RunModelResult>;
  readModelData?: (
    modelName: string,
    specName?: string,
  ) => Promise<Array<{ name: string; attributes?: Record<string, unknown> }>>;
  definitionRepository?: DefinitionLookup;
};

/** The last `n` characters of a message. */
function tail(s: string, n: number): string {
  return s.length > n ? s.slice(-n) : s;
}

/** Raw globalArguments of a definition through the definition repository; null when absent. */
async function definitionGlobals(
  repo: DefinitionLookup | undefined,
  name: string,
): Promise<Record<string, unknown> | null> {
  if (!repo) return null;
  const found = await repo.findByNameGlobal(name);
  if (!found) return null;
  const ga = found.definition.globalArguments;
  return ga && typeof ga === "object" ? ga as Record<string, unknown> : {};
}

/** The SwampApi of a method: swamp's in-process `runModel` / `readModelData` / definitions. */
export function methodSwamp(context: SwampMethodCtx): SwampApi {
  const api: SwampApi = {
    run: async (model, method, args = {}) => {
      if (!context.runModel) {
        return {
          ok: false,
          artifacts: [],
          error: "context.runModel is not available in this execution",
        };
      }
      let res: RunModelResult;
      try {
        res = await context.runModel({
          definition: model,
          method,
          ...(Object.keys(args).length ? { arguments: args } : {}),
        });
      } catch (e) { // runModel returns failures; this guards a broken host API
        return { ok: false, artifacts: [], error: (e as Error).message };
      }
      return res.ok
        ? {
          ok: true,
          artifacts: res.resources.map((r) => r.attributes ?? {}),
          error: "",
        }
        : { ok: false, artifacts: [], error: res.error.message };
    },
    globalArguments: (model) =>
      definitionGlobals(context.definitionRepository, model),
  };
  const read = context.readModelData;
  if (read) {
    api.readData = async (model, spec) =>
      (await read(model, spec)).map((r) => ({
        name: r.name,
        attributes: r.attributes ?? {},
      }));
  }
  return api;
}

/** The argv of `swamp model method run <model> <method> --json --quiet --repo-dir <dir> --input …`.
 *  A string value is passed as `k=<v>`, any other value as `k:json=<JSON>`. Each
 *  value is one argv element: no shell is involved. */
export function methodRunArgv(
  model: string,
  method: string,
  args: Record<string, unknown>,
  repoDir: string,
): string[] {
  const argv = [
    "model",
    "method",
    "run",
    model,
    method,
    "--json",
    "--quiet",
    "--repo-dir",
    repoDir,
  ];
  for (const [k, v] of Object.entries(args)) {
    argv.push(
      "--input",
      typeof v === "string" ? `${k}=${v}` : `${k}:json=${JSON.stringify(v)}`,
    );
  }
  return argv;
}

/** The SwampApi of a pre-flight check. swamp gives checks no `runModel`, so `run` starts
 *  `swamp model method run` as a subprocess (the model's only one). Definitions are
 *  read in-process from `definitionRepository`. There is no `readData`. */
export function checkSwamp(
  ctx: { repoDir: string; definitionRepository?: DefinitionLookup },
): SwampApi {
  return {
    run: async (model, method, args = {}) => {
      // A check has no context.runModel (swamp builds the check context without it),
      // and the live checks must still reach hosts through the ssh / node models.
      // swamp-quality-ignore deno-command: checks get no runModel
      const out = await new Deno.Command(SWAMP_BIN, {
        args: methodRunArgv(model, method, args, ctx.repoDir),
        stdout: "piped",
        stderr: "piped",
      }).output();
      const stdout = new TextDecoder().decode(out.stdout);
      const stderr = new TextDecoder().decode(out.stderr);
      // A failing fan-out (one host exits non-zero) still prints the artifacts of
      // the hosts that ran, so parse stdout whatever the exit code is.
      let artifacts: Array<Record<string, unknown>> = [];
      let parseError = "";
      try {
        const parsed = JSON.parse(stdout) as {
          dataArtifacts?: Array<{ attributes?: Record<string, unknown> }>;
        };
        artifacts = (parsed.dataArtifacts ?? []).map((a) => a.attributes ?? {});
      } catch {
        parseError = `could not parse ${model} ${method} output: ${
          tail(stdout.trim(), 300)
        }`;
      }
      const ok = out.code === 0;
      return {
        ok,
        artifacts,
        error: ok ? parseError : tail(stderr.trim() || parseError, 1000),
      };
    },
    globalArguments: (model) =>
      definitionGlobals(ctx.definitionRepository, model),
  };
}

/** Run another model's method; when it fails, warn `{model} {method} failed: {error}`. */
async function runLogged(
  swamp: SwampApi,
  model: string,
  method: string,
  args: Record<string, unknown>,
  logger: Logger,
): Promise<boolean> {
  const res = await swamp.run(model, method, args);
  if (!res.ok) {
    logger.warn("{model} {method} failed: {error}", {
      model,
      method,
      error: tail(res.error, 300),
    });
  }
  return res.ok;
}

/** Parsed result of one host from the ssh model's `script` method. */
export interface HostRun {
  host: string;
  stdout: string;
  exitCode: number;
}

/** Per-host results of one `<sshModel> script` call, plus the call's own verdict. */
export interface ScriptOutcome {
  runs: HostRun[];
  ok: boolean;
  error: string;
}

/**
 * The fresh `runResult` records of a failed `<sshModel> <method>` call. The ssh model
 * writes one record per host (`run-<method>-<host>`) BEFORE it fails the call when a
 * host exits non-zero, but `runModel` then returns no handles. So read the records
 * back: only those of the requested hosts, and only those started at or after `since`
 * (just before the call), so a result of an earlier run is never used.
 * Residual risk: a second run of the same method on the same host through the same
 * ssh model at the same time can write a record that is read here instead.
 */
export async function freshRunResults(
  swamp: SwampApi,
  sshModel: string,
  method: string,
  hosts: string[],
  since: number,
): Promise<Array<Record<string, unknown>>> {
  if (!swamp.readData) return [];
  let records: Array<{ name: string; attributes: Record<string, unknown> }>;
  try {
    records = await swamp.readData(sshModel, "runResult");
  } catch {
    return [];
  }
  const wanted = new Set(hosts.map((h) => `run-${method}-${h}`));
  return records.filter((r) => {
    const started = r.attributes.startedAt;
    return wanted.has(r.name) && typeof started === "string" &&
      Date.parse(started) >= since;
  }).map((r) => r.attributes);
}

/** Run `<sshModel> script` (fan-out) and return per-host output and the call's verdict.
 *  Throws only when the call failed and no host result can be found. */
export async function runScriptOutcome(
  sshModel: string,
  hosts: string[],
  script: string,
  timeoutSec: number,
  swamp: SwampApi,
): Promise<ScriptOutcome> {
  const t0 = Date.now();
  const res = await swamp.run(sshModel, "script", {
    hosts,
    interpreter: "bash",
    script,
    captureOutput: true,
    timeoutSec,
  });
  let artifacts = res.artifacts;
  if (!res.ok && artifacts.length === 0) {
    artifacts = await freshRunResults(swamp, sshModel, "script", hosts, t0);
  }
  if (!res.ok && artifacts.length === 0) {
    throw new Error(
      `${sshModel} script failed: ${tail(res.error || "no output", 800)}`,
    );
  }
  const runs = artifacts
    .filter((at) => typeof at.host === "string")
    .map((at) => ({
      host: at.host as string,
      stdout: (at.stdout as string) ?? "",
      exitCode: (at.exitCode as number) ?? -1,
    }));
  return { runs, ok: res.ok, error: res.error };
}

/** Run `<sshModel> script` (fan-out) and return per-host output. A host that failed
 *  is still returned with its exit code; a host with no result is missing. */
export async function runScript(
  sshModel: string,
  hosts: string[],
  script: string,
  timeoutSec: number,
  swamp: SwampApi,
): Promise<HostRun[]> {
  return (await runScriptOutcome(sshModel, hosts, script, timeoutSec, swamp))
    .runs;
}

/** True when a failed run says the method does not know the argument `name`. The CLI
 *  says "Unknown method input(s): <names>. Valid inputs are: …"; `runModel` says
 *  "Unknown argument(s): <names>. Valid arguments are: …". */
export function isUnknownArgumentError(
  res: RunOutcome,
  name: string,
): boolean {
  if (res.ok) return false;
  // Only the part before "Valid inputs" / "Valid arguments" lists the rejected names.
  const rejected = res.error.split(/valid (?:inputs|arguments)/i)[0];
  return /unknown|unrecognized/i.test(rejected) &&
    new RegExp(`\\b${name}\\b`).test(rejected);
}

/** Run the community-script source's `safeUpdate` for a CT whose snapshot @dmc/patch
 *  already owns: passes `{ snapshot: false }` so the source takes no snapshot of its own.
 *  An older source (@dmc/proxmox < 2026.10.01.1) rejects that argument; then retry ONCE
 *  with no arguments. Any other failure is returned as is, never retried. */
export async function runSourceSafeUpdate(
  src: string,
  swamp: SwampApi,
  logger: Logger,
): Promise<boolean> {
  const first = await swamp.run(src, "safeUpdate", { snapshot: false });
  if (first.ok) return true;
  if (!isUnknownArgumentError(first, "snapshot")) {
    logger.warn("{model} {method} failed: {error}", {
      model: src,
      method: "safeUpdate",
      error: tail(first.error, 300),
    });
    return false;
  }
  logger.warn(
    "{model} safeUpdate does not support snapshot:false (needs @dmc/proxmox >= 2026.10.01.1), so it took its own extra snapshot",
    { model: src },
  );
  return await runLogged(swamp, src, "safeUpdate", {}, logger);
}

/** Run one shell command on a single host via `<sshModel> exec`; returns rc + output.
 *  The command is wrapped to always exit 0 and self-report its rc (like community-script). */
export async function nodeExec(
  sshModel: string,
  host: string,
  command: string,
  timeoutSec: number,
  swamp: SwampApi,
): Promise<{ rc: number; out: string }> {
  const wrapped = `{ ${command}; } 2>&1; printf '\\n${RC_SENTINEL}=%s\\n' "$?"`;
  const res = await swamp.run(sshModel, "exec", {
    hosts: [host],
    command: wrapped,
    captureOutput: true,
    timeoutSec,
  });
  if (!res.ok) {
    throw new Error(
      `ssh transport to ${host} via ${sshModel} failed: ${
        tail(res.error, 400)
      }`,
    );
  }
  const attrs = (res.artifacts[0] ?? {}) as {
    stdout?: string;
    exitCode?: number;
  };
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

/** Resolve a CT's node + ctid: from `ct`, else legacy (read from the proxmox model's
 *  globalArguments). */
export async function ctLocation(
  m: MachineShape,
  swamp: SwampApi,
): Promise<{ node: string; ctid: number }> {
  if (m.ct) return { node: m.ct.proxmoxNode, ctid: m.ct.ctid };
  const model = m.proxmox?.model;
  if (!model) {
    throw new Error(
      `${m.host}: no CT location (need a \`ct\` decoration or legacy proxmox.model)`,
    );
  }
  const ga = await swamp.globalArguments(model);
  const node = ga?.node;
  const ctid = ga?.ctid;
  if (!node || !ctid) throw new Error(`${model}: no node/ctid`);
  return { node: String(node), ctid: Number(ctid) };
}

/** The effective health checks for a machine: its own `health`, else derived from a
 *  community-script `source` (its healthUrl + service), else empty (reachability). */
export async function resolveHealthChecks(
  m: MachineShape,
  swamp: SwampApi,
): Promise<Array<z.infer<typeof HealthCheck>>> {
  if (m.health && m.health.length) return m.health;
  const src = appSource(m);
  if (!src) return [];
  const ga = (await swamp.globalArguments(src)) as {
    healthUrl?: string;
    healthExpectStatus?: number;
    service?: string;
  } | null;
  if (!ga) return [];
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

/** Run a (multi-line) shell script on a machine via its transport: `pct exec` on the
 *  node for a CT, the ssh model's `script` method otherwise. One model call. */
async function runOnMachine(
  m: MachineShape,
  sshModel: string,
  script: string,
  timeoutSec: number,
  swamp: SwampApi,
): Promise<{ rc: number; out: string }> {
  let host = m.host;
  let body = script;
  if (isCtMachine(m) && !m.vm) {
    const { node, ctid } = await ctLocation(m, swamp);
    host = node;
    body = `pct exec ${ctid} -- bash -c "echo '${
      utf8b64(script)
    }' | base64 -d | bash"`;
  }
  const runs = await runScript(sshModel, [host], body, timeoutSec, swamp);
  const r = runs.find((x) => x.host === host) ?? runs[0];
  return { rc: r?.exitCode ?? -1, out: r?.stdout ?? "" };
}

/** The marker a health batch prints after check `i`: `@@PATCH-HC <i> rc=<rc>`. */
const HC_MARKER = "@@PATCH-HC";

/**
 * One shell script that runs every given check snippet in turn. Each snippet runs in
 * its own subshell on its own lines, so a bare `exit` in a check ends only that check.
 * Its stdin is /dev/null (the ssh model feeds the script itself on stdin) and its
 * output goes to /dev/null: only the rc counts. After check `i` the script prints
 * `@@PATCH-HC <i> rc=<rc>`.
 */
export function healthBatchScript(snippets: string[]): string {
  return snippets.map((s, i) =>
    `(\n${s}\n) </dev/null >/dev/null 2>&1\necho "${HC_MARKER} ${i} rc=$?"`
  ).join("\n") + "\n";
}

/** The rc of each check from a health batch's output, by check index. */
export function parseHealthBatch(stdout: string): Map<number, number> {
  const rcs = new Map<number, number>();
  for (const m of stdout.matchAll(/^@@PATCH-HC (\d+) rc=(\d+)\s*$/gm)) {
    rcs.set(parseInt(m[1], 10), parseInt(m[2], 10));
  }
  return rcs;
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

/** Evaluate a machine's health checks (all must pass). Empty list ⇒ healthy=true.
 *  http checks run from the swamp host. ALL service + command checks run in ONE shell
 *  call on the machine (see `healthBatchScript`). A check whose result is missing
 *  from the output fails with the detail "no result". */
export async function evalHealth(
  m: MachineShape,
  checks: Array<z.infer<typeof HealthCheck>>,
  sshModel: string,
  swamp: SwampApi,
): Promise<HealthResult> {
  // The shell checks, in order: their batch index is their position in this list.
  const shell = checks.filter((c) => c.type !== "http");
  let rcs = new Map<number, number>();
  if (shell.length) {
    const snippets = shell.map((c) =>
      c.type === "service"
        // Init-agnostic: systemd (is-active) OR OpenRC (rc-service status, for Alpine).
        ? `systemctl is-active ${c.name} >/dev/null 2>&1 || rc-service ${c.name} status >/dev/null 2>&1`
        : (c as { run: string }).run
    );
    const timeoutSec = shell.reduce(
      (t, c) => t + (c.type === "command" ? c.timeoutSec : 30),
      0,
    );
    const r = await runOnMachine(
      m,
      sshModel,
      healthBatchScript(snippets),
      timeoutSec,
      swamp,
    );
    rcs = parseHealthBatch(r.out);
  }
  const results: HealthResult["results"] = [];
  let si = 0; // index of the next shell check in the batch
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
    } else {
      if (!label) {
        label = c.type === "service"
          ? `service ${c.name} active`
          : `command: ${c.run.slice(0, 40)}`;
      }
      const rc = rcs.get(si++);
      if (rc === undefined) {
        detail = "no result";
      } else {
        ok = rc === 0;
        detail = c.type === "service"
          ? (ok ? "active" : `not active (rc ${rc})`)
          : `rc ${rc}`;
      }
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
  /** Definitions, read in-process (checks get no runModel; see `checkSwamp`). */
  definitionRepository: DefinitionLookup;
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
  swamp: SwampApi,
): Promise<string[] | null> {
  const res = await swamp.run(nodeModel, "listVmSnapshots", { vmid });
  if (!res.ok) {
    throw new Error(
      tail(res.error, 300) || `${nodeModel} listVmSnapshots failed`,
    );
  }
  const list = res.artifacts[0]?.snapshots;
  // null: the node answered, but the list is not readable
  if (!Array.isArray(list)) return null;
  return list.map((s) => (s as { name?: string })?.name ?? "").filter((n) =>
    n && n !== "current"
  );
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

/**
 * `policy` — the `host` argument of `clearRetired` is NOT in the fleet. This is the
 * opposite of `host-in-fleet`: clearRetired only removes hosts the fleet no longer lists.
 */
export function checkHostRetired(ctx: CheckCtx): CheckResult {
  const host = checkHost(ctx);
  if (host === undefined) return PASS; // no host filter, or no input yet
  if (!ctx.globalArgs.machines.some((m) => m.host === host)) return PASS;
  return fail(
    `Host "${host}" is still in globalArguments.machines, so it is not retired. ` +
      `Remove it from the fleet first, then run clearRetired. ${
        skipHint("host-retired", "policy")
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
  const swamp = checkSwamp(ctx);
  try {
    if (viaPct) {
      const { node, ctid } = await ctLocation(machine, swamp);
      const r = await nodeExec(
        sshModel,
        node,
        `pct status ${ctid}`,
        30,
        swamp,
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
    const r = await nodeExec(sshModel, host, "true", 30, swamp);
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
  const swamp = checkSwamp(ctx);
  try {
    const health = await resolveHealthChecks(machine, swamp);
    if (!health.length) return PASS;
    const res = await evalHealth(
      machine,
      health,
      ctx.globalArgs.sshModel,
      swamp,
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
  const swamp = checkSwamp(ctx);
  let names: string[] | null = null;
  let where: string;
  try {
    if (machine.vm) {
      const { proxmoxNode, vmid } = machine.vm;
      where = `VM ${vmid} via node model "${proxmoxNode}"`;
      names = await vmSnapshotNames(proxmoxNode, vmid, swamp);
    } else {
      const { node, ctid } = await ctLocation(machine, swamp);
      where = `CT ${ctid} on node "${node}"`;
      const r = await nodeExec(
        ctx.globalArgs.sshModel,
        node,
        `pct listsnapshot ${ctid}`,
        30,
        swamp,
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

// ---------------------------------------------------------------------------
// Retired machines: hosts that have stored records but are no longer in
// globalArguments.machines. `clearRetired` removes their records.
// ---------------------------------------------------------------------------

/** The resource specs whose records belong to one host (never prune, seed or report). */
export const HOST_SPECS = [
  "inventory",
  "update",
  "osUpdate",
  "reboot",
  "run",
  "snapshot",
  "image",
] as const;
export type HostSpec = typeof HOST_SPECS[number];

/** The specs that hold current status. `keepHistory` still deletes these. */
const STATUS_SPECS: readonly HostSpec[] = [
  "inventory",
  "update",
  "osUpdate",
  "reboot",
];

/**
 * The host a stored record belongs to. An inventory record is named by its host.
 * Every other record carries `attributes.host`. A name prefix is never used, so
 * `node` can not match a record of `node2`. Returns null when the host is unknown.
 */
export function recordHost(
  spec: HostSpec,
  name: string,
  attributes: Record<string, unknown>,
): string | null {
  if (spec === "inventory") return name || null;
  const h = attributes.host;
  return typeof h === "string" && h !== "" ? h : null;
}

/** One stored record that belongs to a host. */
export interface HostRecord {
  host: string;
  spec: HostSpec;
  name: string;
  attributes: Record<string, unknown>;
}

/** Read every host-owned record of this model (latest version of each name). */
export async function readHostRecords(
  context: Pick<Ctx, "dataRepository" | "modelType" | "modelId">,
): Promise<HostRecord[]> {
  const out: HostRecord[] = [];
  for (const d of await readOwnRecords(context, HOST_SPECS)) {
    const spec = d.specName as HostSpec;
    const host = recordHost(spec, d.name, d.attributes);
    if (host !== null) {
      out.push({ host, spec, name: d.name, attributes: d.attributes });
    }
  }
  return out;
}

/** The hosts that have stored records but are not in the fleet. */
export function retiredHosts(
  records: HostRecord[],
  fleetHosts: string[],
): string[] {
  const fleet = new Set(fleetHosts);
  return [...new Set(records.map((r) => r.host))].filter((h) => !fleet.has(h))
    .sort();
}

/** One planned or done action on a record of a retired host. */
export interface RetiredEntry {
  host: string;
  name: string;
  spec: HostSpec;
}

/** What `clearRetired` does with the records of the retired hosts. */
export interface RetiredPlan {
  remove: RetiredEntry[];
  keep: Array<RetiredEntry & { reason: string }>;
}

/** Decide, per record, whether `clearRetired` removes or keeps it. Pure. */
export function planRetiredClear(
  records: HostRecord[],
  hosts: string[],
  opts: { keepHistory: boolean; force: boolean },
): RetiredPlan {
  const plan: RetiredPlan = { remove: [], keep: [] };
  const wanted = new Set(hosts);
  const sorted = records.filter((r) => wanted.has(r.host)).sort((a, b) =>
    a.host.localeCompare(b.host) || a.spec.localeCompare(b.spec) ||
    a.name.localeCompare(b.name)
  );
  for (const r of sorted) {
    const e = { host: r.host, name: r.name, spec: r.spec };
    const retention = r.spec === "snapshot" || r.spec === "image";
    if (STATUS_SPECS.includes(r.spec)) {
      plan.remove.push(e);
    } else if (retention && r.attributes.status === "active") {
      if (opts.force) plan.remove.push(e);
      else {
        plan.keep.push({
          ...e,
          reason:
            `active ${r.spec} record: the ${
              r.spec === "snapshot" ? "snapshot" : "image"
            } may still exist, so deleting the record would orphan it. ` +
            "Prune it first, or use force=true",
        });
      }
    } else if (opts.keepHistory) {
      plan.keep.push({ ...e, reason: "history kept (keepHistory=true)" });
    } else {
      plan.remove.push(e);
    }
  }
  return plan;
}

// ---------------------------------------------------------------------------
// Scan fan-out. swamp allows at most 100 `runModel` calls in one method run, so
// `scan` batches: ONE ssh `script` call for every ssh host, ONE call per Proxmox
// node for its CTs, ONE shell call per machine for its health checks.
// ---------------------------------------------------------------------------

/** The text of swamp's error when a method run has used up its `runModel` calls. */
export const INVOCATION_CAP_TEXT = "Maximum cross-model invocation count";

/** swamp's limit of `runModel` calls in one method run (MAX_INVOCATION_BREADTH). */
export const INVOCATION_CAP = 100;

/**
 * The node-side script that runs the collector in each CT of one node in turn.
 * The collector is sent once (base64, in a shell variable). Each CT's output is
 * delimited by `@@PATCH-CT <ctid> BEGIN` and `@@PATCH-CT <ctid> END rc=<rc>`.
 * `pct exec` reads /dev/null, because the ssh model feeds this script on stdin.
 */
export function ctBatchScript(ctids: number[], collectorB64: string): string {
  const lines = [`PATCH_COLLECTOR='${collectorB64}'`];
  for (const ctid of ctids) {
    lines.push(
      `echo "@@PATCH-CT ${ctid} BEGIN"`,
      `pct exec ${ctid} -- bash -c "echo '\${PATCH_COLLECTOR}' | base64 -d | bash" </dev/null`,
      // printf starts a new line, so the marker is found even after output with no newline.
      `printf '\\n@@PATCH-CT %s END rc=%s\\n' ${ctid} "$?"`,
    );
  }
  return lines.join("\n") + "\n";
}

/** Split a CT batch's output into each CT's section. `rc` is null when the END
 *  marker is missing (the run was cut short). A CT with no BEGIN marker is absent. */
export function parseCtSections(
  stdout: string,
): Map<number, { out: string; rc: number | null }> {
  const sections = new Map<number, { out: string; rc: number | null }>();
  let cur: { ctid: number; lines: string[] } | null = null;
  const close = (rc: number | null) => {
    if (cur) sections.set(cur.ctid, { out: cur.lines.join("\n"), rc });
    cur = null;
  };
  for (const line of stdout.split("\n")) {
    const begin = line.match(/^@@PATCH-CT (\d+) BEGIN\s*$/);
    if (begin) {
      close(null);
      cur = { ctid: parseInt(begin[1], 10), lines: [] };
      continue;
    }
    const end = line.match(/^@@PATCH-CT (\d+) END rc=(\d+)\s*$/);
    if (end) {
      if (cur && cur.ctid === parseInt(end[1], 10)) {
        close(parseInt(end[2], 10));
      }
      continue;
    }
    if (cur) cur.lines.push(line);
  }
  close(null);
  return sections;
}

/** @dmc/patch/fleet model. */
export const model = {
  type: "@dmc/patch/fleet",
  version: "2026.10.09.1",
  upgrades: [
    {
      toVersion: "2026.10.01.1",
      description:
        "Version bump, no globalArguments schema change (adds the healthGraceSec method argument and single-snapshot CT updates)",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.10.09.1",
      description:
        "Version bump, no globalArguments schema change (adds the clearRetired method; reads own data by model id)",
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
    "host-retired": {
      description:
        "The host argument of clearRetired is not in globalArguments.machines (clearRetired removes only hosts the fleet no longer lists)",
      labels: ["policy"],
      appliesTo: ["clearRetired"],
      execute: (context: CheckCtx) =>
        Promise.resolve(checkHostRetired(context)),
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
      execute: async (
        _args: unknown,
        context: SwampMethodCtx & {
          globalArgs: z.infer<typeof GlobalArgs>;
          logger: Logger;
          writeResource: (
            spec: string,
            name: string,
            data: unknown,
          ) => Promise<{ name: string }>;
        },
      ) => {
        const { sshModel, machines } = context.globalArgs;
        context.logger.info("Scanning {count} machines via {sshModel}", {
          count: machines.length,
          sshModel,
        });
        // Count the model calls, and notice when swamp's per-run cap is reached.
        const base = methodSwamp(context);
        let calls = 0;
        let capHit = false;
        const swamp: SwampApi = {
          ...base,
          run: async (model, method, args) => {
            calls++;
            const res = await base.run(model, method, args);
            if (res.error.includes(INVOCATION_CAP_TEXT)) capHit = true;
            return res;
          },
        };
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

        // Per machine: reach=ssh (default) tries SSH then falls back to pct when a
        // CT location exists; reach=pct goes straight to pct. reachMethod records
        // which worked. A failure of one host or node never sinks the others.
        const scanned = machines.filter((m) => m.os !== false);
        const lines = new Map<string, { line: string; via: "ssh" | "pct" }>();
        const errs = new Map<string, string>();
        const addErr = (h: string, e: string) =>
          errs.set(h, errs.has(h) ? `${errs.get(h)}; ${e}` : e);

        // 1) ONE ssh `script` call runs the collector on every ssh host.
        const sshHosts = scanned.filter((m) => m.reach !== "pct").map((m) =>
          m.host
        );
        if (sshHosts.length) {
          try {
            const res = await runScriptOutcome(
              sshModel,
              sshHosts,
              collector,
              240,
              swamp,
            );
            for (const h of sshHosts) {
              // A one-host call keeps the old fallback to the only result.
              const r = res.runs.find((x) => x.host === h) ??
                (sshHosts.length === 1 ? res.runs[0] : undefined);
              const line = r ? markerLine(r.stdout, "patch-inventory") : null;
              if (line) lines.set(h, { line, via: "ssh" });
              else if (r) addErr(h, `no inventory (exit ${r.exitCode})`);
              else if (!res.ok) addErr(h, `ssh: ${tail(res.error, 90)}`);
              else addErr(h, "no inventory");
            }
          } catch (e) {
            for (const h of sshHosts) {
              addErr(h, `ssh: ${(e as Error).message.slice(0, 90)}`);
            }
          }
        }

        // 2) CTs with no inventory yet go to pct, grouped by node: ONE call per node
        // runs the collector in each of its CTs (see ctBatchScript).
        const byNode = new Map<string, Array<{ host: string; ctid: number }>>();
        for (const m of scanned) {
          if (lines.has(m.host) || !isCtMachine(m)) continue;
          try {
            const { node, ctid } = await ctLocation(m, swamp);
            byNode.set(node, [...(byNode.get(node) ?? []), {
              host: m.host,
              ctid,
            }]);
          } catch (e) {
            addErr(m.host, `pct: ${(e as Error).message.slice(0, 90)}`);
          }
        }
        for (const [node, cts] of byNode) {
          try {
            const res = await runScriptOutcome(
              sshModel,
              [node],
              ctBatchScript(cts.map((c) => c.ctid), collectorB64),
              240 * cts.length,
              swamp,
            );
            const r = res.runs.find((x) => x.host === node) ?? res.runs[0];
            const sections = parseCtSections(r?.stdout ?? "");
            for (const { host, ctid } of cts) {
              const sec = sections.get(ctid);
              const line = sec ? markerLine(sec.out, "patch-inventory") : null;
              if (line) lines.set(host, { line, via: "pct" });
              else if (!r && !res.ok) {
                addErr(host, `pct: ${tail(res.error, 90)}`);
              } else {
                addErr(
                  host,
                  `pct: no inventory${
                    sec?.rc !== null && sec?.rc !== undefined
                      ? ` (exit ${sec.rc})`
                      : ""
                  }`,
                );
              }
            }
          } catch (e) {
            for (const { host } of cts) {
              addErr(host, `pct: ${(e as Error).message.slice(0, 90)}`);
            }
          }
        }
        context.logger.info(
          "Collected inventory: {ssh} ssh host(s) in one call, {cts} CT(s) on {nodes} node(s) via pct",
          {
            ssh: sshHosts.length,
            cts: [...byNode.values()].reduce((n, c) => n + c.length, 0),
            nodes: byNode.size,
          },
        );

        // 3) Health checks (own, or derived from a community-script source): one
        // shell call per machine for its service + command checks.
        for (const m of scanned) {
          const h = m.host;
          let health: {
            healthy: boolean;
            checks: Array<{ label: string; ok: boolean; detail: string }>;
          } | null = null;
          try {
            const checks = await resolveHealthChecks(m, swamp);
            if (checks.length) {
              const hres = await evalHealth(m, checks, sshModel, swamp);
              health = { healthy: hres.healthy, checks: hres.results };
            }
          } catch { /* health stays null */ }

          const found = lines.get(h);
          if (found) {
            handles.push(
              await context.writeResource(
                "inventory",
                h,
                {
                  ...(JSON.parse(found.line) as Record<string, unknown>),
                  reachMethod: found.via,
                  health,
                  error: null,
                },
              ),
            );
          } else {
            handles.push(
              await context.writeResource("inventory", h, {
                ...errorInv(h, errs.get(h) || "unreachable"),
                health,
              }),
            );
          }
        }

        // 4) Fire checkUpdate on each machine's app source (community-script) for
        // fresh data the report reads; best-effort, never fails the scan.
        for (const m of machines) {
          const src = appSource(m);
          if (src) {
            await runLogged(swamp, src, "checkUpdate", {}, context.logger);
          }
        }

        if (capHit) {
          context.logger.warn(
            "swamp's cap of {cap} model calls per method run was reached while scanning {count} machines, so later calls failed. Split the fleet over more fleet models",
            { cap: INVOCATION_CAP, count: machines.length },
          );
        }
        context.logger.info(
          "Scanned {count} machines via {sshModel}: wrote {records} inventory records in {calls} model calls",
          {
            count: machines.length,
            sshModel,
            records: handles.length,
            calls,
          },
        );
        return { dataHandles: handles };
      },
    },

    import: {
      description:
        "Emit a suggested `machines` block seeded from the sshModel host list (and, later, Proxmox guests) to paste into globalArguments and decorate.",
      arguments: z.object({}),
      execute: async (
        _args: unknown,
        context: SwampMethodCtx & {
          globalArgs: z.infer<typeof GlobalArgs>;
          logger: Logger;
          writeResource: (
            spec: string,
            name: string,
            data: unknown,
          ) => Promise<{ name: string }>;
        },
      ) => {
        const { sshModel, proxmoxNodes } = context.globalArgs;
        const swamp = methodSwamp(context);
        context.logger.info(
          "Seeding machines from {sshModel} and {nodeCount} Proxmox nodes",
          { sshModel, nodeCount: proxmoxNodes.length },
        );

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
            const res = await swamp.run(pnode, "listGuests");
            if (!res.ok) throw new Error(res.error || "listGuests failed");
            // listGuests writes the `guests` resource; its attributes hold the list.
            const found = res.artifacts.find((a) => Array.isArray(a.guests));
            const gs = (found?.guests ?? []) as Array<
              {
                type: string;
                vmid: number;
                name: string;
                node: string;
                ip: string | null;
              }
            >;
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
          const ga = await swamp.globalArguments(sshModel);
          if (!ga) throw new Error(`no model named ${sshModel}`);
          const hosts = ga.hosts;
          sshHosts = Array.isArray(hosts)
            ? hosts as Array<{ name: string; tags?: string[] }>
            : [];
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
        const swamp = methodSwamp(context);
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
          nodeExec(sshModel, args.host, cmd, t, swamp);
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
        const swamp = methodSwamp(context);
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
        const checks = await resolveHealthChecks(machine, swamp);
        // After an update: health verdict. With checks → evalHealth; else reachability.
        // Last post-update verdict, written into the refreshed inventory record.
        let lastHealth: HealthResult | null = null;
        const afterHealthy = async (reachable: boolean): Promise<boolean> => {
          if (!checks.length) return reachable;
          const h = await evalHealthWithGrace(
            () => evalHealth(machine, checks, sshModel, swamp),
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
          const { node, ctid } = await ctLocation(machine, swamp);
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
              swamp,
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
                swamp,
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
            nodeExec(sshModel, node, `pct ${opArgs}`, t, swamp);

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
            const ok = await runSourceSafeUpdate(src, swamp, context.logger);
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
              swamp,
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
          const s = await runLogged(
            swamp,
            machine.vm!.proxmoxNode,
            "snapshotVm",
            { vmid: machine.vm!.vmid, name: snap },
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
              (await nodeExec(sshModel, args.host, pkgCmd, 120, swamp)).out,
            );
          } catch {
            return new Map();
          }
        };
        const beforePkgs = await manifest();

        log(`upgrading (${args.mode})`);
        const up = await nodeExec(sshModel, args.host, upScript, 1800, swamp);
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
          rolledBack = await runLogged(
            swamp,
            machine.vm!.proxmoxNode,
            "rollbackVm",
            { vmid: machine.vm!.vmid, name: snap },
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
        const swamp = methodSwamp(context);
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
        const ctInfo = () => ctLocation(machine, swamp);

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
                swamp,
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
              swamp,
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
            swamp,
          );
          cmdRc = r.rc;
        } else {
          // Schedule via systemd-run so the exec call returns cleanly before sshd dies.
          const cmd = `SUDO=""; [ "$(id -u)" != 0 ] && SUDO="sudo -n"; ` +
            `$SUDO systemd-run --on-active=3 --timer-property=AccuracySec=100ms systemctl reboot`;
          log("scheduling systemctl reboot (+3s) over ssh");
          const r = await nodeExec(sshModel, args.host, cmd, 30, swamp);
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
        const checks = await resolveHealthChecks(machine, swamp);
        let appHealthy: boolean | null = null;
        let rebootHealth: HealthResult | null = null;
        if (confirmed && checks.length) {
          const h = await evalHealthWithGrace(
            () => evalHealth(machine, checks, sshModel, swamp),
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
          const snap = (await readOwnSpec(context, "snapshot"))
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
          const snaps = (await readOwnSpec(context, "snapshot"))
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
        const swamp = methodSwamp(context);
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
        const recs = (await readOwnSpec(context, "snapshot"))
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
            swamp,
          )).rc === 0
          : await runLogged(
            swamp,
            a.proxmoxNode,
            "rollbackVm",
            {
              vmid: a.vmid,
              name: a.name,
            },
            context.logger,
          );
        log(ok ? `rolled back to ${a.name}` : `ROLLBACK FAILED for ${a.name}`);

        // Best-effort health verdict after the revert.
        const checks = await resolveHealthChecks(machine, swamp);
        let healthy: boolean | null = null;
        if (ok && checks.length) {
          const h = await evalHealth(machine, checks, sshModel, swamp);
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
        const swamp = methodSwamp(context);
        context.logger.info(
          "Pruning retained snapshots (host={host} dryRun={dryRun})",
          { host: args.host ?? "all", dryRun: args.dryRun },
        );
        const now = Date.now();
        const scannedAt = new Date().toISOString();
        const collector = COLLECTOR_SCRIPT;
        // Final live gate: host answers a scan AND no reboot is pending. The scan
        // goes the machine's own way: pct on its node for a CT (a CT often has no
        // ssh), ssh otherwise.
        const healthyNow = async (m: MachineShape): Promise<boolean> => {
          try {
            const r = await runOnMachine(m, sshModel, collector, 240, swamp);
            const line = markerLine(r.out, "patch-inventory");
            if (!line) return false;
            return (JSON.parse(line) as z.infer<typeof Inventory>)
              .needsReboot === false;
          } catch {
            return false;
          }
        };

        const records = (await readOwnSpec(context, "snapshot"))
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
          const machine = context.globalArgs.machines.find((m) =>
            m.host === a.host
          );
          if (!machine) {
            kept.push({
              host: a.host,
              name: a.name,
              reason: "host not in the fleet",
            });
            continue;
          }
          if (!(await healthyNow(machine))) {
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
              swamp,
            )).rc === 0
            : await runLogged(
              swamp,
              a.proxmoxNode,
              "deleteVmSnapshot",
              {
                vmid: a.vmid,
                name: a.name,
              },
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
        const swamp = methodSwamp(context);
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
              swamp,
            )).rc === 0;
          } catch {
            return false;
          }
        };

        const records = (await readOwnSpec(context, "image"))
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
            swamp,
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
    clearRetired: {
      description:
        "Remove the stored records of retired machines: hosts with records that are no longer in globalArguments.machines. dryRun defaults to TRUE, so a bare run only previews. Status records (inventory and last update, os-update, reboot results) and run history are deleted; ACTIVE snapshot/image records are kept (they track real snapshots/images) unless force=true. keepHistory keeps run and pruned retention records.",
      arguments: z.object({
        host: z.string().min(1).optional().describe(
          "One retired host (default: every retired host)",
        ),
        dryRun: z.boolean().default(true).describe(
          "Report what would be deleted without deleting (default true)",
        ),
        keepHistory: z.boolean().default(false).describe(
          "Keep run records and pruned snapshot/image records; delete only status records",
        ),
        force: z.boolean().default(false).describe(
          "Also delete ACTIVE snapshot/image records (the snapshots/images themselves are not touched)",
        ),
      }),
      execute: async (
        args: {
          host?: string;
          dryRun: boolean;
          keepHistory: boolean;
          force: boolean;
        },
        context: Ctx,
      ) => {
        context.logger.info(
          "Clearing retired machines (host={host} dryRun={dryRun} keepHistory={keepHistory} force={force})",
          {
            host: args.host ?? "all",
            dryRun: args.dryRun,
            keepHistory: args.keepHistory,
            force: args.force,
          },
        );
        const fleetHosts = context.globalArgs.machines.map((m) => m.host);
        if (fleetHosts.length === 0) {
          throw new Error(
            "globalArguments.machines is empty, so every host would look retired. " +
              "Refusing to delete anything. Fix the fleet definition first.",
          );
        }
        if (args.host !== undefined && fleetHosts.includes(args.host)) {
          throw new Error(
            `Host "${args.host}" is in globalArguments.machines, so it is not retired. Nothing was deleted.`,
          );
        }
        const records = await readHostRecords(context);
        const retired = retiredHosts(records, fleetHosts);
        if (args.host !== undefined && !retired.includes(args.host)) {
          throw new Error(
            `No stored records for host "${args.host}", so there is nothing to clear. ` +
              `Retired hosts: ${
                retired.join(", ") || "(none)"
              }. Nothing was deleted.`,
          );
        }
        const targets = args.host !== undefined ? [args.host] : retired;
        const plan = planRetiredClear(records, targets, {
          keepHistory: args.keepHistory,
          force: args.force,
        });

        const pruned: Array<
          { host: string; name: string; detail: string | null }
        > = [];
        const kept: Array<{ host: string; name: string; reason: string }> = [];
        for (const e of plan.remove) {
          if (!args.dryRun) {
            try {
              await context.deleteResource(e.name);
            } catch (err) {
              kept.push({
                host: e.host,
                name: e.name,
                reason: `delete failed: ${
                  (err as Error).message.slice(0, 200)
                }`,
              });
              continue;
            }
          }
          pruned.push({ host: e.host, name: e.name, detail: e.spec });
        }
        for (const k of plan.keep) {
          kept.push({ host: k.host, name: k.name, reason: k.reason });
          if (k.spec === "snapshot" || k.spec === "image") {
            context.logger.warn(
              "Kept active {spec} record {name} of retired host {host}",
              { spec: k.spec, name: k.name, host: k.host },
            );
          }
        }
        for (const host of targets) {
          context.logger.info(
            "Retired host {host}: {action} {prunedCount} record(s), kept {keptCount}",
            {
              host,
              action: args.dryRun ? "would delete" : "deleted",
              prunedCount: pruned.filter((p) => p.host === host).length,
              keptCount: kept.filter((p) => p.host === host).length,
            },
          );
        }

        const scannedAt = new Date().toISOString();
        const handle = await context.writeResource(
          "prune",
          `prune-retired-${scannedAt.replace(/[:.]/g, "-")}`,
          { scannedAt, kind: "retired", dryRun: args.dryRun, pruned, kept },
        );
        context.logger.info(
          "Retired machines: {action} {prunedCount} record(s) of {hostCount} host(s), kept {keptCount}",
          {
            action: args.dryRun ? "would delete" : "deleted",
            prunedCount: pruned.length,
            hostCount: targets.length,
            keptCount: kept.length,
          },
        );
        return { dataHandles: [handle] };
      },
    },
  },
};

export { RC_SENTINEL };
