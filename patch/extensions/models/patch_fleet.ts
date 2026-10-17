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
      "Every listed check must pass. Empty = reachability fallback. A machine with no checks " +
      "but a `source` updater derives them from that updater model's healthUrl + service globalArgs.",
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
  // ── Pluggable app updater ───────────────────────────────────────────────
  // `source.model` names ANY model instance that implements the updater
  // contract; @dmc/patch delegates to it by name via runModel and never needs
  // its type. Consumers add their own update mechanism without changing
  // @dmc/patch. Updater contract — the referenced model MUST expose:
  //   • checkUpdate()                   — `scan` fires this to report availability.
  //   • safeUpdate({ snapshot?: bool }) — guarded app update. When @dmc/patch
  //       owns the snapshot it passes { snapshot: false } so the updater takes
  //       none of its own; an updater that ignores the arg still works.
  // Optional, for health derivation when the machine lists no `health`:
  //   • globalArguments.healthUrl / healthExpectStatus / service
  source: z.object({
    type: z.string().min(1).optional().describe(
      'Optional label for the update mechanism (e.g. "community-script", ' +
        '"swamp-binary"). Documentation only — @dmc/patch does not branch on it.',
    ),
    model: z.string().min(1).describe(
      "The updater model instance to delegate to. ANY model that implements the " +
        "updater contract works: a `checkUpdate` method, a `safeUpdate({ snapshot? })` " +
        "method, and optionally `healthUrl`/`healthExpectStatus`/`service` globalArgs " +
        "for health derivation. E.g. a @dmc/proxmox/community-script instance.",
    ),
  }).optional().describe(
    "Optional app updater on top of the OS lifecycle: version check + safe app " +
      "update, delegated to `source.model`. Its presence is what triggers " +
      "app-update delegation — not merely being a CT. The model is reached by name; " +
      "its type is irrelevant, so you can plug in your own updater.",
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
  // ── Pluggable snapshotter ───────────────────────────────────────────────
  // Snapshot, rollback and cleanup act on ONE artifact, so they are ONE contract:
  // whatever takes a snapshot must also roll it back and delete it. @dmc/patch ships
  // two built-in snapshotters — proxmox-vm (the `vm` node model) and proxmox-ct
  // (`pct` on the CT's node) — and `snapshotter.model` plugs in any other, reached by
  // name via runModel. Snapshotter contract — the referenced model MUST expose:
  //   • snapshot({ host, name })       — take a snapshot named `name` of `host`.
  //   • rollback({ host, name })       — revert `host` to that snapshot.
  //   • deleteSnapshot({ host, name }) — remove it (pruneSnapshots, after retention).
  //   • listSnapshots({ host })        — write one resource whose attributes hold
  //                                      `snapshots: [{ name }]` (pre-flight check).
  // @dmc/patch chooses every name (`preupdate-<timestamp>`); the model must be able to
  // find a snapshot again by that name. Success = the method run succeeds.
  snapshotter: z.object({
    model: z.string().min(1).describe(
      "The snapshotter model instance. ANY model that implements the snapshotter " +
        "contract works: snapshot({ host, name }), rollback({ host, name }), " +
        "deleteSnapshot({ host, name }), and listSnapshots({ host }) writing a resource " +
        "with `snapshots: [{ name }]`. @dmc/patch chooses the snapshot names.",
    ),
  }).optional().describe(
    "Optional pluggable snapshot guard for safeOsUpdate, rollback and pruneSnapshots. " +
      "When set it replaces the built-in proxmox-vm / proxmox-ct snapshotter, and it " +
      "also lets a bare-metal machine be snapshot-guarded. The record of each snapshot " +
      "remembers the snapshotter, so rollback and cleanup reach the one that took it.",
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

// Which snapshotter implementation owns a snapshot, and where it lives. Persisted on
// the SnapshotRecord, because `rollback` and `pruneSnapshots` run later, from the
// record — and only the implementation that took a snapshot can roll it back or delete it.
const SnapshotterRefSchema = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("proxmox-vm"),
    node: z.string().describe("Proxmox node model that holds the VM"),
    vmid: z.number().int(),
  }),
  z.object({
    kind: z.literal("proxmox-ct"),
    node: z.string().describe(
      "ssh host (in sshModel) that runs pct for the CT",
    ),
    ctid: z.number().int(),
  }),
  z.object({
    kind: z.literal("model"),
    model: z.string().describe(
      "Snapshotter model instance (implements the snapshotter contract)",
    ),
  }),
]);

// Tracks the lifecycle of a pre-update snapshot (from any snapshotter): it is kept
// through the reboot, health-verified, and only pruned after a retention window.
const SnapshotRecord = z.object({
  host: z.string(),
  kind: z.enum(["vm", "ct", "model"]).default("vm").describe(
    "vm → node-model snapshot API; ct → pct snapshot on the node host; " +
      "model → a pluggable snapshotter model (see `snapshotter`)",
  ),
  vmid: z.number().nullable().describe(
    "VM id, or CT id when kind=ct; null when kind=model",
  ),
  proxmoxNode: z.string().nullable().describe(
    "node model (vm) or ssh host running pct (ct); null when kind=model",
  ),
  snapshotter: SnapshotterRefSchema.optional().describe(
    "The implementation that took this snapshot; `rollback` and `pruneSnapshots` " +
      "dispatch to it. Absent on records written before snapshotters were pluggable — " +
      "those map from kind/vmid/proxmoxNode.",
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

/** Run a `source` updater's `safeUpdate`. When @dmc/patch already owns the snapshot
 *  (the default) it passes `{ snapshot: false }` so the updater takes no snapshot of its
 *  own. An older updater (e.g. @dmc/proxmox < 2026.10.01.1) rejects that argument; then
 *  retry ONCE with no arguments. Any other failure is returned as is, never retried.
 *  With `patchOwnsSnapshot: false` (an unguarded machine — no snapshotter) it calls
 *  `safeUpdate` with no arguments, so the updater may guard itself. */
export async function runSourceSafeUpdate(
  src: string,
  swamp: SwampApi,
  logger: Logger,
  opts: { patchOwnsSnapshot?: boolean } = {},
): Promise<boolean> {
  if (opts.patchOwnsSnapshot === false) {
    return await runLogged(swamp, src, "safeUpdate", {}, logger);
  }
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
  source?: { type?: string; model: string };
  proxmox?: { model: string };
  vm?: { proxmoxNode: string; vmid: number };
  snapshotter?: { model: string };
  reach?: "ssh" | "pct";
  health?: Array<z.infer<typeof HealthCheck>>;
}

/** True when a machine is a Proxmox CT (new `ct`, or legacy pct/proxmox ref). */
export function isCtMachine(m: MachineShape): boolean {
  return !!m.ct || (!m.vm && (m.reach === "pct" || !!m.proxmox?.model));
}

/** The app-updater model instance for a machine, or null. Any `source.model` is
 *  honoured regardless of `source.type` (the type is a documentation label only),
 *  so consumers can plug in their own updater. The legacy `proxmox.model` ref is
 *  still accepted as a fallback. */
export function appSource(m: MachineShape): string | null {
  if (m.source?.model) return m.source.model;
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

// ---------------------------------------------------------------------------
// Transports — how @dmc/patch reaches ONE machine.
//
// Two implementations sit behind the `Transport` interface; the machine's decorations
// choose one (`transportFor`):
//   • ssh — the host itself, through the ssh model's `script` (multi-line) and `exec`
//           (one command) methods.
//   • pct — a Proxmox CT, through `pct` on its node over the ssh model (a CT often has
//           no ssh of its own). Scripts are shipped base64-encoded into `pct exec`.
// safeOsUpdate, reboot, the health checks, pruneSnapshots' live gate and the
// host-reachable check reach a machine only through a Transport; none of them branches
// on ssh-vs-pct. `scan` keeps its own batched fan-out (one call for every ssh host, one
// per node) to stay under swamp's runModel call budget.
// ---------------------------------------------------------------------------

/** Lists the installed packages, one `name<TAB>version` line each (rpm / dpkg / apk). */
export const PKG_MANIFEST_CMD =
  `if command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n'; ` +
  `elif command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='\${Package}\\t\${Version}\\n'; ` +
  `elif command -v apk >/dev/null 2>&1; then apk info -v | sed 's/-\\([^-]*-r[0-9][0-9]*\\)$/\\t\\1/'; fi`;

/** The installed-package manifest from PKG_MANIFEST_CMD's output: name → version. */
export function parseManifest(out: string): Map<string, string> {
  const m = new Map<string, string>();
  for (const ln of out.split("\n")) {
    const t = ln.trim();
    if (!t) continue;
    const tab = t.indexOf("\t");
    if (tab > 0) m.set(t.slice(0, tab), t.slice(tab + 1));
    else m.set(t, "");
  }
  return m;
}

/** The packages that differ between two manifests (added, removed or changed), by name. */
export function diffPkgs(
  b: Map<string, string>,
  a: Map<string, string>,
): Array<z.infer<typeof PkgChange>> {
  const names = new Set<string>([...b.keys(), ...a.keys()]);
  const out: Array<z.infer<typeof PkgChange>> = [];
  for (const n of names) {
    const from = b.get(n) ?? null;
    const to = a.get(n) ?? null;
    if (from !== to) out.push({ name: n, from, to });
  }
  out.sort((x, y) => x.name.localeCompare(y.name));
  return out;
}

/** Reboot over ssh, scheduled with systemd-run so the exec call returns before sshd dies. */
const SSH_REBOOT_CMD = `SUDO=""; [ "$(id -u)" != 0 ] && SUDO="sudo -n"; ` +
  `$SUDO systemd-run --on-active=3 --timer-property=AccuracySec=100ms systemctl reboot`;

/** How @dmc/patch reaches one machine. */
export interface Transport {
  via: "ssh" | "pct";
  /** Where the commands run, for logs and errors. */
  where: string;
  /** Appended to some log lines: "" over ssh, " via pct" for a CT. */
  note: string;
  /** Why an update cannot start when the machine does not answer a scan. */
  notReachable: string;
  /** The CT's location (pct only): the built-in proxmox-ct snapshotter needs it. */
  ct?: { node: string; ctid: number };
  /** Run a multi-line script on the machine (one model call). */
  script(
    body: string,
    timeoutSec: number,
  ): Promise<{ rc: number; out: string }>;
  /** Run one command on the machine. */
  exec(
    command: string,
    timeoutSec: number,
  ): Promise<{ rc: number; out: string }>;
  /** The machine's patch inventory from the bundled collector; null when it does not answer. */
  scan(): Promise<z.infer<typeof Inventory> | null>;
  /** The installed-package manifest; null when it cannot be read (unknown is never
   *  reported as an empty list, which would fake a diff). */
  packages(): Promise<Map<string, string> | null>;
  /** Pre-flight reachability: null when the machine answers, else why not. */
  probe(): Promise<string | null>;
  /** What `reboot` logs before it starts the reboot. */
  rebootLabel: string;
  /** Start a reboot; resolves with the command's exit code. */
  reboot(): Promise<number>;
  /** How long to wait after the reboot command before the first probe. */
  rebootSettleMs: number;
}

/** What a transport needs to reach a machine. */
export interface TransportDeps {
  sshModel: string;
  swamp: SwampApi;
}

/** The patch inventory from a collector run; null when there is no answer, no marker
 *  line, or no valid JSON. */
async function scanWith(
  script: Transport["script"],
): Promise<z.infer<typeof Inventory> | null> {
  try {
    const { out } = await script(COLLECTOR_SCRIPT, 240);
    const line = markerLine(out, "patch-inventory");
    return line ? JSON.parse(line) as z.infer<typeof Inventory> : null;
  } catch {
    return null;
  }
}

/** The installed-package manifest through `run`; null when it cannot be read — the
 *  run fails or exits non-zero. An audit detail never aborts an update, and an unknown
 *  list is never passed off as an empty one (that would fake the package diff). */
async function packagesWith(
  run: Transport["exec"],
): Promise<Map<string, string> | null> {
  try {
    const r = await run(PKG_MANIFEST_CMD, 120);
    return r.rc === 0 ? parseManifest(r.out) : null;
  } catch {
    return null;
  }
}

/** One `<sshModel> script` run on one host: its exit code and stdout. */
async function scriptOnHost(
  sshModel: string,
  host: string,
  body: string,
  timeoutSec: number,
  swamp: SwampApi,
): Promise<{ rc: number; out: string }> {
  const runs = await runScript(sshModel, [host], body, timeoutSec, swamp);
  const r = runs.find((x) => x.host === host) ?? runs[0];
  return { rc: r?.exitCode ?? -1, out: r?.stdout ?? "" };
}

/** Reach a host over ssh. */
export function sshTransport(host: string, deps: TransportDeps): Transport {
  const { sshModel, swamp } = deps;
  const script = (body: string, timeoutSec: number) =>
    scriptOnHost(sshModel, host, body, timeoutSec, swamp);
  const exec = (command: string, timeoutSec: number) =>
    nodeExec(sshModel, host, command, timeoutSec, swamp);
  return {
    via: "ssh",
    where: `host "${host}" over ${sshModel}`,
    note: "",
    notReachable: `host "${host}" is not ssh-reachable`,
    script,
    exec,
    scan: () => scanWith(script),
    packages: () => packagesWith(exec),
    probe: async () => {
      const r = await exec("true", 30);
      return r.rc === 0
        ? null
        : `Host "${host}" did not answer over ${sshModel} (rc ${r.rc}). ` +
          `Bring the host up or fix its ssh access.`;
    },
    rebootLabel: "scheduling systemctl reboot (+3s) over ssh",
    reboot: async () => (await exec(SSH_REBOOT_CMD, 30)).rc,
    rebootSettleMs: 15000,
  };
}

/** Reach a Proxmox CT through `pct` on its node. A CT has no exec channel of its own,
 *  so a single command is shipped the same way as a script. */
export function pctTransport(
  host: string,
  ct: { node: string; ctid: number },
  deps: TransportDeps,
): Transport {
  const { sshModel, swamp } = deps;
  const { node, ctid } = ct;
  const onNode = (command: string, timeoutSec: number) =>
    nodeExec(sshModel, node, command, timeoutSec, swamp);
  const script = (body: string, timeoutSec: number) =>
    scriptOnHost(
      sshModel,
      node,
      `pct exec ${ctid} -- bash -c "echo '${
        utf8b64(body)
      }' | base64 -d | bash"`,
      timeoutSec,
      swamp,
    );
  return {
    via: "pct",
    where: `CT ${ctid} on node "${node}"`,
    note: " via pct",
    notReachable: `CT "${host}" (ctid ${ctid}) not reachable via pct`,
    ct,
    script,
    exec: script,
    scan: () => scanWith(script),
    packages: () => packagesWith(script),
    probe: async () => {
      const r = await onNode(`pct status ${ctid}`, 30);
      return r.rc === 0 && /status:\s*running/.test(r.out)
        ? null
        : `CT "${host}" (ctid ${ctid}) is not running on node "${node}" ` +
          `(pct status rc ${r.rc}). Start the CT or fix its ct decoration.`;
    },
    rebootLabel: `pct reboot ${ctid} on ${node}`,
    reboot: async () => (await onNode(`pct reboot ${ctid}`, 180)).rc,
    rebootSettleMs: 5000,
  };
}

/** Which transport a machine uses, from its decorations alone (no lookup): pct for a CT
 *  that is not also a VM, ssh otherwise. */
export function transportVia(m: MachineShape): "ssh" | "pct" {
  return isCtMachine(m) && !m.vm ? "pct" : "ssh";
}

/** The transport for a machine. A CT's location is resolved here (a legacy CT reads it
 *  from its proxmox model). */
export async function transportFor(
  m: MachineShape,
  deps: TransportDeps,
): Promise<Transport> {
  if (transportVia(m) === "pct") {
    return pctTransport(m.host, await ctLocation(m, deps.swamp), deps);
  }
  return sshTransport(m.host, deps);
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
    const transport = await transportFor(m, { sshModel, swamp });
    const r = await transport.script(healthBatchScript(snippets), timeoutSec);
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
        // We only need the status; cancel the body so the connection does not
        // leak (also satisfies the test leak sanitizer).
        await res.body?.cancel();
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

/** Snapshot names from a read-only list method whose first resource holds
 *  `snapshots: [{ name }]` (Proxmox's `current` pseudo-snapshot is dropped). Throws when
 *  the run fails; null when the model answered but the list is not readable. */
async function listedSnapshotNames(
  model: string,
  method: string,
  args: Record<string, unknown>,
  swamp: SwampApi,
): Promise<string[] | null> {
  const res = await swamp.run(model, method, args);
  if (!res.ok) {
    throw new Error(tail(res.error, 300) || `${model} ${method} failed`);
  }
  const list = res.artifacts[0]?.snapshots;
  // null: the model answered, but the list is not readable
  if (!Array.isArray(list)) return null;
  return list.map((s) => (s as { name?: string })?.name ?? "").filter((n) =>
    n && n !== "current"
  );
}

/** Names of the snapshots of a VM, from the node model's read-only `listVmSnapshots`. */
export function vmSnapshotNames(
  nodeModel: string,
  vmid: number,
  swamp: SwampApi,
): Promise<string[] | null> {
  return listedSnapshotNames(nodeModel, "listVmSnapshots", { vmid }, swamp);
}

// ---------------------------------------------------------------------------
// Snapshotters — the pluggable snapshot lifecycle.
//
// Snapshot, rollback and cleanup act on one artifact, so ONE implementation owns all
// three. Three implementations sit behind the `Snapshotter` interface:
//   • proxmox-vm — the `vm` node model: snapshotVm / rollbackVm / deleteVmSnapshot /
//                  listVmSnapshots (built in).
//   • proxmox-ct — `pct snapshot|rollback|delsnapshot|listsnapshot` on the CT's node,
//                  over the ssh model (built in).
//   • model      — any model named by a machine's `snapshotter.model`, driven by name
//                  through runModel with the snapshotter contract (the extension point).
// safeOsUpdate picks the implementation from the machine's decorations
// (`snapshotterRefFor`). The SnapshotRecord persists that choice, and `rollback` /
// `pruneSnapshots` dispatch from the record (`snapshotterRefFromRecord`), so a snapshot
// is always rolled back and deleted by the implementation that took it.
// ---------------------------------------------------------------------------

/** Which implementation owns a snapshot, and where. */
export type SnapshotterRef = z.infer<typeof SnapshotterRefSchema>;

/** One snapshot backend. @dmc/patch chooses every snapshot name. snapshot / rollback /
 *  delete report the outcome as a boolean (a broken ssh transport may still throw);
 *  the caller decides whether to abort the update or keep the record. */
export interface Snapshotter {
  ref: SnapshotterRef;
  /** Where the snapshots live, for logs and check messages. */
  where: string;
  snapshot(name: string): Promise<boolean>;
  rollback(name: string): Promise<boolean>;
  delete(name: string): Promise<boolean>;
  /** Snapshot names; null when the backend answered but the list is unreadable.
   *  Throws when the backend does not answer. */
  list(): Promise<string[] | null>;
}

/** What a snapshotter needs to reach its backend. */
export interface SnapshotterDeps {
  sshModel: string;
  swamp: SwampApi;
  /** The machine — passed to a model snapshotter, so one instance can serve many machines. */
  host: string;
  /** Receives warnings about failed model runs. Checks pass none (they only list). */
  logger?: Logger;
}

const SILENT_LOGGER: Logger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
};

/** The snapshotter a machine uses now, from its decorations. An explicit
 *  `snapshotter.model` wins; else the built-in proxmox-vm (`vm`); else proxmox-ct when
 *  the caller passes the CT's resolved location; else null — no snapshot guard. */
export function snapshotterRefFor(
  m: MachineShape,
  ct?: { node: string; ctid: number },
): SnapshotterRef | null {
  if (m.snapshotter?.model) {
    return { kind: "model", model: m.snapshotter.model };
  }
  if (m.vm) {
    return { kind: "proxmox-vm", node: m.vm.proxmoxNode, vmid: m.vm.vmid };
  }
  if (ct) return { kind: "proxmox-ct", node: ct.node, ctid: ct.ctid };
  return null;
}

/** The snapshotter that took a recorded snapshot. Records written before snapshotters
 *  were pluggable carry no `snapshotter`; they map from kind/vmid/proxmoxNode. */
export function snapshotterRefFromRecord(
  a: z.infer<typeof SnapshotRecord>,
): SnapshotterRef {
  if (a.snapshotter) return a.snapshotter;
  if (a.vmid === null || a.proxmoxNode === null) {
    throw new Error(
      `snapshot record ${a.name} of ${a.host} names no snapshotter and no Proxmox location`,
    );
  }
  return a.kind === "ct"
    ? { kind: "proxmox-ct", node: a.proxmoxNode, ctid: a.vmid }
    : { kind: "proxmox-vm", node: a.proxmoxNode, vmid: a.vmid };
}

/** The location fields of a SnapshotRecord for a snapshotter: the ref itself, plus the
 *  plain kind/vmid/proxmoxNode that reports and older readers of Proxmox records use. */
export function snapshotRecordLocation(ref: SnapshotterRef): {
  kind: "vm" | "ct" | "model";
  vmid: number | null;
  proxmoxNode: string | null;
  snapshotter: SnapshotterRef;
} {
  switch (ref.kind) {
    case "proxmox-vm":
      return {
        kind: "vm",
        vmid: ref.vmid,
        proxmoxNode: ref.node,
        snapshotter: ref,
      };
    case "proxmox-ct":
      return {
        kind: "ct",
        vmid: ref.ctid,
        proxmoxNode: ref.node,
        snapshotter: ref,
      };
    case "model":
      return { kind: "model", vmid: null, proxmoxNode: null, snapshotter: ref };
  }
}

/** The error that aborts an update when the pre-update snapshot fails. */
export function snapshotFailedMessage(
  ref: SnapshotterRef,
  host: string,
): string {
  switch (ref.kind) {
    case "proxmox-vm":
      return `snapshot failed on ${ref.node} for vmid ${ref.vmid} — aborting update`;
    case "proxmox-ct":
      return `pct snapshot failed for ctid ${ref.ctid} on ${ref.node} — aborting update`;
    case "model":
      return `snapshotter model "${ref.model}" failed to snapshot ${host} — aborting update`;
  }
}

/** The implementation behind a snapshotter ref. The built-in ones issue exactly the
 *  Proxmox calls they always have; the model one drives the snapshotter contract. */
export function snapshotterFor(
  ref: SnapshotterRef,
  deps: SnapshotterDeps,
): Snapshotter {
  const { sshModel, swamp, host } = deps;
  const logger = deps.logger ?? SILENT_LOGGER;
  switch (ref.kind) {
    case "proxmox-vm": {
      const { node, vmid } = ref;
      const call = (method: string, name: string) =>
        runLogged(swamp, node, method, { vmid, name }, logger);
      return {
        ref,
        where: `VM ${vmid} via node model "${node}"`,
        snapshot: (name) => call("snapshotVm", name),
        rollback: (name) => call("rollbackVm", name),
        delete: (name) => call("deleteVmSnapshot", name),
        list: () => vmSnapshotNames(node, vmid, swamp),
      };
    }
    case "proxmox-ct": {
      const { node, ctid } = ref;
      const pct = (op: string, timeoutSec: number) =>
        nodeExec(sshModel, node, `pct ${op}`, timeoutSec, swamp);
      const ok = async (op: string, timeoutSec: number) =>
        (await pct(op, timeoutSec)).rc === 0;
      return {
        ref,
        where: `CT ${ctid} on node "${node}"`,
        snapshot: (name) => ok(`snapshot ${ctid} ${name}`, 300),
        rollback: (name) => ok(`rollback ${ctid} ${name}`, 300),
        delete: (name) => ok(`delsnapshot ${ctid} ${name}`, 180),
        list: async () => {
          const r = await pct(`listsnapshot ${ctid}`, 30);
          if (r.rc !== 0) throw new Error(`pct listsnapshot rc ${r.rc}`);
          return [...r.out.matchAll(/->\s*(\S+)/g)].map((m) => m[1]).filter(
            (n) => n !== "current",
          );
        },
      };
    }
    case "model": {
      const { model } = ref;
      const call = (method: string, name: string) =>
        runLogged(swamp, model, method, { host, name }, logger);
      return {
        ref,
        where: `snapshotter model "${model}" (host ${host})`,
        snapshot: (name) => call("snapshot", name),
        rollback: (name) => call("rollback", name),
        delete: (name) => call("deleteSnapshot", name),
        list: () =>
          listedSnapshotNames(model, "listSnapshots", { host }, swamp),
      };
    }
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
  const deps = { sshModel: ctx.globalArgs.sshModel, swamp: checkSwamp(ctx) };
  try {
    // safeUpdate always reaches the docker host over ssh; the others follow the OS path.
    const transport = ctx.methodName === "safeUpdate"
      ? sshTransport(host, deps)
      : await transportFor(machine, deps);
    const why = await transport.probe();
    return why === null
      ? PASS
      : fail(`${why} ${skipHint("host-reachable", "live")}`);
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

/** `live` — the machine's snapshotter (a pluggable model, or the built-in VM node model /
 *  CT pct) answers a list, and (rollback) a snapshot exists. */
export async function checkSnapshotTargetResolves(
  ctx: CheckCtx,
): Promise<CheckResult> {
  const found = checkMachine(ctx);
  if (!found) return PASS;
  const { host, machine } = found;
  const hint = skipHint("snapshot-target-resolves", "live");
  const isCt = !machine.vm && isCtMachine(machine);
  // No snapshot guard (bare metal without a snapshotter): nothing to resolve.
  if (!machine.snapshotter && !machine.vm && !isCt) return PASS;
  const wanted = checkArg(ctx, "snapshot");
  const needSnapshot = ctx.methodName === "rollback";
  const swamp = checkSwamp(ctx);
  let names: string[] | null = null;
  let where = "the snapshot target";
  try {
    // The CT location is only needed for the built-in pct snapshotter.
    const ct = !machine.snapshotter && isCt
      ? await ctLocation(machine, swamp)
      : undefined;
    const snapper = snapshotterFor(snapshotterRefFor(machine, ct)!, {
      sshModel: ctx.globalArgs.sshModel,
      swamp,
      host,
    });
    where = snapper.where;
    names = await snapper.list();
  } catch (e) {
    return fail(
      `Machine "${host}": ${where} did not resolve: ${
        (e as Error).message.slice(0, 300)
      }. Fix the vm/ct/snapshotter decoration or the node. ${hint}`,
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
  version: "2026.10.16.1",
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
    {
      toVersion: "2026.10.16.1",
      description:
        "Additive globalArguments change, no migration needed: `source.type` is now an " +
        "optional label (any model that implements the updater contract can be a " +
        "`source`, on any machine kind), and machines take an optional pluggable " +
        "`snapshotter`. Snapshot records gain a `snapshotter` field; older records map " +
        "from kind/vmid/proxmoxNode. Internally every per-machine operation reaches its " +
        "machine through one ssh / pct Transport.",
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
        "Lifecycle of a pre-update snapshot (from any snapshotter, recorded in `snapshotter`): kept through the reboot, health-verified, pruned only after a retention window by pruneSnapshots, through the snapshotter that took it.",
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
              const healthy = r.status === dcfg.healthExpectStatus;
              // Cancel the body so the connection does not leak.
              await r.body?.cancel();
              return healthy ? true : null;
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
        "Snapshot-guarded OS update for one machine: snapshot → upgrade → re-scan → " +
        "health verdict → roll back the snapshot when the machine does not return healthy. " +
        "The snapshot guard is pluggable: a `snapshotter` decoration names any model that " +
        "implements the snapshotter contract (it also guards bare metal); otherwise a " +
        "Proxmox VM (vm decoration) is snapshotted via its node model and a Proxmox CT " +
        "(ct decoration) via pct, and bare metal is upgraded unguarded. VMs and bare metal " +
        "upgrade over ssh; CTs via pct exec. An app updater (`source`) runs on top for any " +
        "machine kind, under the same snapshot: it is called with snapshot:false when " +
        "@dmc/patch took the snapshot, and with no arguments on an unguarded machine. " +
        "Reboot is never automatic.",
      arguments: z.object({
        host: z.string().min(1).describe("Machine (host) to update"),
        mode: z.enum(["safe", "full"]).default("safe").describe(
          "apt: safe = `upgrade` (never removes), full = `full-upgrade`. dnf/apk always upgrade.",
        ),
        retentionHours: z.number().int().default(DEFAULT_RETENTION_HOURS)
          .describe(
            "How long the pre-update snapshot is retained as a rollback point before pruneSnapshots may delete it (default 7 days). The snapshot is never auto-deleted.",
          ),
        rollbackOnFailure: z.boolean().default(true).describe(
          "Roll back to the pre-update snapshot when the machine is unhealthy after the " +
            "update, whatever the upgrade's exit code. Applies to every machine kind that " +
            "has a snapshot guard. false = keep the unhealthy machine as-is (outcome failed).",
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

        // Reach the machine (pct on its node for a CT, ssh otherwise) and pick its
        // snapshot guard: an explicit `snapshotter`, else the built-in proxmox-vm (`vm`)
        // or proxmox-ct (a CT), else none — bare metal is upgraded unguarded. From here
        // one flow serves every machine kind.
        const transport = await transportFor(machine, { sshModel, swamp });
        const snapRef = snapshotterRefFor(machine, transport.ct);
        const snapper = snapRef
          ? snapshotterFor(snapRef, {
            sshModel,
            swamp,
            host: args.host,
            logger: context.logger,
          })
          : null;
        const kind: z.infer<typeof OsUpdateResult>["kind"] =
          transport.via === "pct" ? "ct" : machine.vm ? "vm" : "bare-metal";

        const before = await transport.scan();
        if (!before) {
          throw new Error(`${transport.notReachable} — cannot update`);
        }
        log(
          `before: ${
            before.updatesCount ?? "?"
          } updates (${before.packageManager})${transport.note}`,
        );

        // Snapshot up front: it guards the OS update AND the app update on top.
        let snap: string | null = null;
        let snapCreatedAt: string | null = null;
        if (snapper) {
          snapCreatedAt = new Date().toISOString();
          snap = `preupdate-${snapCreatedAt.replace(/[:.]/g, "-")}`;
          log(`snapshot ${snap} (${snapper.where})`);
          if (!(await snapper.snapshot(snap))) {
            throw new Error(snapshotFailedMessage(snapper.ref, args.host));
          }
        }

        const beforePkgs = await transport.packages();

        log(`upgrading (${args.mode})${transport.note}`);
        const up = await transport.exec(upScript, 1800);
        log(`upgrade rc ${up.rc}`);

        // App updater on top — only when a `source` is configured. The snapshot above
        // (if any) guards both, so the updater is told not to take its own; an
        // unguarded machine lets the updater decide.
        const src = appSource(machine);
        let appNote = "";
        if (src) {
          const ok = await runSourceSafeUpdate(src, swamp, context.logger, {
            patchOwnsSnapshot: !!snapper,
          });
          appNote = `; app ${src}: ${ok ? "ok" : "failed"}`;
          log(`app source ${src} safeUpdate: ${ok ? "ok" : "failed"}`);
        }

        const after = await transport.scan();
        const healthy = await afterHealthy(after !== null);

        // What the update changed — read before any rollback, so a rolled-back run still
        // records it, and a machine is never read while it is being restored. When
        // either list is unreadable, record no diff rather than a misleading one.
        let pkgs: Array<z.infer<typeof PkgChange>> | null = null;
        if (after) {
          const afterPkgs = await transport.packages();
          if (beforePkgs && afterPkgs) {
            pkgs = diffPkgs(beforePkgs, afterPkgs);
            log(`packages changed: ${pkgs.length}`);
          } else {
            log("package list unreadable — no package diff recorded");
          }
        }

        // Outcome — health first, the same for every machine kind:
        //   unhealthy + snapshot + rollbackOnFailure → roll back       → rolled-back
        //   unhealthy, otherwise                     → keep as-is      → failed
        //   healthy, but the upgrade command failed  → no rollback     → failed
        //   healthy                                  → updated / no-change
        // An unhealthy machine is rolled back whatever the upgrade's exit code.
        let outcome: z.infer<typeof OsUpdateResult>["outcome"];
        let rolledBack = false;
        if (!healthy && snapper && snap && args.rollbackOnFailure) {
          log(`unhealthy after upgrade — rolling back to ${snap}`);
          rolledBack = await snapper.rollback(snap);
          outcome = "rolled-back";
          log(
            rolledBack
              ? `rolled back to ${snap}`
              : `ROLLBACK FAILED — snapshot ${snap} kept for manual recovery`,
          );
        } else if (!healthy) {
          outcome = "failed";
          log(
            snapper
              ? "unhealthy — rollback disabled; snapshot retained"
              : "unhealthy after upgrade (bare metal, no snapshot)",
          );
        } else if (up.rc !== 0) {
          outcome = "failed";
          log(
            `upgrade command failed — machine healthy, no rollback${
              snapper ? "; snapshot retained" : ""
            }`,
          );
        } else {
          // `after` can be null while health checks pass (the rescan failed, the app
          // answers): count it as no updates left.
          outcome = (before.updatesCount ?? 0) !== (after?.updatesCount ?? 0)
            ? "updated"
            : "no-change";
          log(`healthy after (${after?.updatesCount ?? "?"} updates left)`);
        }

        const runTs = new Date().toISOString();
        const dataHandles = [
          await context.writeResource("osUpdate", `os-update-${args.host}`, {
            host: args.host,
            kind,
            mode: args.mode,
            outcome,
            snapshot: snap,
            // A rollback reverts to the snapshot; it does not delete it.
            snapshotKept: !!snapper && !!snap,
            beforeUpdates: before.updatesCount ?? null,
            afterUpdates: after?.updatesCount ?? null,
            healthyAfter: healthy,
            rolledBack,
            needsReboot: after?.needsReboot ?? false,
            logs: logs.join("\n") + appNote,
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
        // Track the snapshot for retention / prune — also after a rollback: rolling back
        // does not delete the snapshot, and an untracked snapshot is never pruned.
        if (snapper && snap && snapCreatedAt) {
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
                ...snapshotRecordLocation(snapper.ref),
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
        // Refresh the inventory from the post-update scan so needsReboot (and the update
        // counts) are current for the reboot guard and the report.
        if (after) {
          dataHandles.push(
            await context.writeResource("inventory", args.host, {
              ...after,
              reachMethod: transport.via,
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

        // From the decorations alone: a skipped reboot records it without a CT lookup.
        const via = transportVia(machine);

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

        // Fire the reboot: `pct reboot` on the node for a CT, systemd-run over ssh otherwise.
        // The transport (and a CT's location) is resolved only now, past the guard.
        const transport = await transportFor(machine, { sshModel, swamp });
        log(transport.rebootLabel);
        const cmdRc = await transport.reboot();
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
          await sleep(transport.rebootSettleMs); // let it actually go down first
          const deadline = Date.now() + args.waitTimeoutSec * 1000;
          for (;;) {
            const inv = await transport.scan();
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
        "Deliberately revert a machine to a retained pre-update snapshot, through the snapshotter that took it (recorded on the snapshot: built-in VM node model / CT pct, or a pluggable `snapshotter` model). The explicit recovery for an update or reboot that left the host unhealthy — a reboot itself cannot be rolled back. Reverts to the newest active snapshot for the host unless `snapshot` is given.",
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
        // Roll back through the snapshotter that TOOK this snapshot (from the record),
        // not whatever the machine is decorated with now.
        const snapper = snapshotterFor(snapshotterRefFromRecord(a), {
          sshModel,
          swamp,
          host: args.host,
          logger: context.logger,
        });
        log(`rolling back to snapshot ${a.name} (${snapper.where})`);

        const ok = await snapper.rollback(a.name);
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
        "Delete retained pre-update snapshots that are past their retention window, health-confirmed, reboot-confirmed (when the update needed a reboot), AND pass a fresh healthcheck now. Each one is deleted through the snapshotter that took it (recorded on the snapshot: built-in VM node model / CT pct, or a pluggable `snapshotter` model's deleteSnapshot). Nothing else deletes snapshots. Use dryRun to preview.",
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
        // Final live gate: the machine answers a scan over its own transport (pct on its
        // node for a CT, which often has no ssh) AND no reboot is pending.
        const healthyNow = async (m: MachineShape): Promise<boolean> => {
          try {
            const transport = await transportFor(m, { sshModel, swamp });
            return (await transport.scan())?.needsReboot === false;
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
          // Delete through the snapshotter that TOOK this snapshot (from the record). A
          // record that names none is kept with the reason; the others still prune.
          let ref: SnapshotterRef;
          try {
            ref = snapshotterRefFromRecord(a);
          } catch (e) {
            kept.push({
              host: a.host,
              name: a.name,
              reason: (e as Error).message,
            });
            continue;
          }
          const label = ref.kind === "model" ? `model:${ref.model}` : null;
          if (args.dryRun) {
            pruned.push({
              host: a.host,
              name: a.name,
              detail: label ?? `${a.kind}:${a.vmid}`,
            });
            continue;
          }
          const ok = await snapshotterFor(ref, {
            sshModel,
            swamp,
            host: a.host,
            logger: context.logger,
          }).delete(a.name);
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
          pruned.push({
            host: a.host,
            name: a.name,
            detail: label ?? `vmid:${a.vmid}`,
          });
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
