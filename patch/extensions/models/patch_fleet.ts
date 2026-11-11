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
import {
  AcceptedRisk,
  AccessProfile,
  SourceAddr,
  TrustRemote,
  Unsafe,
  unsafeRecord,
} from "./lib/access_policy.ts";
import type { AccessProfileT, UnsafeT } from "./lib/access_policy.ts";
import {
  authorizedKeysLine,
  provisionScript,
  revokeScript,
  shQuote,
} from "./lib/access_artifacts.ts";
import type { ProvisionInput } from "./lib/access_artifacts.ts";
import { dockerProjectName, helperArgv } from "./lib/docker_helper.ts";
import type { DockerProject, HelperSub } from "./lib/docker_helper.ts";
import {
  MAX_PLUGIN_COMMANDS,
  parsePluginPrivileges,
  parseRootArgv,
} from "./lib/plugin_privileges.ts";
import {
  FAMILY_PROBES,
  privCommand,
  RUNTIME_ABS_FN,
  runtimeCommand,
  runtimeLine,
  runtimeResolveLines,
  shellPaths,
  sudoersTemplate,
} from "./lib/access_sudoers.ts";
import type { PrivCommand } from "./lib/access_sudoers.ts";
import {
  evaluateAudit,
  rootProbeScript,
  userProbeScript,
} from "./lib/access_audit.ts";
import type { Finding, Severity } from "./lib/access_audit.ts";
import {
  capabilitiesFor,
  effectivePolicy,
  OS_AUTO_SCOPES,
  OS_UPDATE_POLICIES,
  osRefusal,
} from "./lib/os_policy.ts";
import {
  parseDockerFile,
  validateDockerImages,
} from "./lib/docker_inventory.ts";
import {
  parsePending,
  PENDING_LIMIT,
  PendingUpdate,
} from "./lib/pending_updates.ts";
import type { PendingUpdateT } from "./lib/pending_updates.ts";

// The swamp CLI, used only by `checkSwamp` (pre-flight checks get no runModel).
const SWAMP_BIN = Deno.env.get("SWAMP_BIN") ?? "swamp";
const RC_SENTINEL = "__SWAMP_RC__";

/** Lists the installed packages, one `name<TAB>version` line each (rpm / dpkg / apk /
 *  pacman). pacman comes last: Debian ships an unrelated `pacman` game. The collector
 *  embeds this exact command (as `pkg_manifest`), so the packages hash it reports and
 *  the model's package diff read the same list. */
export const PKG_MANIFEST_CMD =
  `if command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n'; ` +
  `elif command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='\${Package}\\t\${Version}\\n'; ` +
  `elif command -v apk >/dev/null 2>&1; then apk info -v | sed 's/-\\([^-]*-r[0-9][0-9]*\\)$/\\t\\1/'; ` +
  `elif command -v pacman >/dev/null 2>&1; then pacman -Q | tr ' ' '\\t'; fi`;

/**
 * The collector's root dnf checks, word for word the table entries the access login is
 * granted (access_sudoers.ts: dnf-check, dnf-check-security), with dnf's absolute path in
 * `$BIN_DNF` (the same variable the upgrade script uses). sudo matches the path and the
 * arguments exactly.
 */
const DNF_CHECK_ARGV = runtimeCommand(
  privCommand("dnf-check"),
  shellPaths(privCommand("dnf-check")),
).join(" ");
const DNF_CHECK_SECURITY_ARGV = runtimeCommand(
  privCommand("dnf-check-security"),
  shellPaths(privCommand("dnf-check-security")),
).join(" ");

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
  "# Root is used only for dnf's cache-only check, through two exact sudo grants (see",
  "# dnf_root_check). Counts come from read-only or simulate paths and from the",
  "# existing package cache. Each host refreshes its own cache with its local timers",
  "# (pve-daily-update, apt-daily, dnf-makecache, an apk timer). This collector never",
  "# refreshes the cache: it reports the cache age instead, so a stale cache shows.",
  "set -u",
  "",
  "log() { printf '%s\\n' \"$*\" >&2; }",
  "",
  "# Minimal JSON string escaper (backslash, double-quote, strip control chars).",
  "jesc() { printf '%s' \"${1-}\" | sed -e 's/\\\\/\\\\\\\\/g' -e 's/\"/\\\\\"/g' | tr -d '\\000-\\037'; }",
  "",
  "# Base64 of $1 on one line (GNU base64 -w0, else any base64 with the newlines removed).",
  'b64() { local o; o="$(printf \'%s\' "${1-}" | base64 -w0 2>/dev/null)" || o="$(printf \'%s\' "${1-}" | base64 | tr -d \'\\n\')"; printf \'%s\' "$o"; }',
  "",
  "# The lines of the pending list: at most 5000, more than the model keeps, so it can tell",
  "# that a list was cut. The text goes out base64; the model parses and checks it.",
  "pending_lines() { printf '%s\\n' \"${1-}\" | head -n 5000; }",
  "",
  '# dnf check-update\'s list without its "Obsoleting Packages" section, which repeats',
  "# packages the list already has.",
  "dnf_list() { printf '%s\\n' \"${1-}\" | sed '/^Obsoleting Packages/,$d'; }",
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
  'docker_source="none"   # where docker_json came from: socket, file or none',
  'docker_file_b64=""     # base64 of the root-written docker inventory (file source only)',
  'cache_age="null"       # hours since the package cache was refreshed, or null if unknown',
  "dnf_user_cache=0       # 1 when dnf answered from its per-user cache (dnf4 fallback)",
  'packages_hash="null"   # sha256 of the sorted package manifest (a JSON string), or null',
  'pending_b64=""         # base64 of the pending-update lines the count reads ("" = none read)',
  'pending_sec_b64=""     # base64 of the security list (dnf --security, arch-audit), or ""',
  "",
  'set_reason() { reason_json="\\"$(jesc "$1")\\""; }',
  "",
  "# Newest mtime (epoch seconds) of the given paths; empty when none exist.",
  'newest_mtime() { stat -c %Y "$@" 2>/dev/null | sort -n | tail -1; }',
  "",
  "# Cache age in whole hours from an epoch mtime. An empty or non-integer argument",
  "# leaves cache_age alone; a future mtime counts as 0.",
  "set_cache_age() {",
  '  case "${1-}" in ""|*[!0-9]*) return 0 ;; esac',
  "  cache_age=$(( ($(date +%s) - $1) / 3600 ))",
  '  [ "$cache_age" -lt 0 ] && cache_age=0',
  "  return 0",
  "}",
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
  "  local plain dist plain_inst dist_inst dist_remv",
  '  set_cache_age "$(newest_mtime /var/lib/apt/lists/*Release)"',
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
  '  pending_b64="$(b64 "$(pending_lines "$(printf \'%s\\n\' "$dist" | grep \'^Inst\')")")"',
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
  "# dnf check-update as root, on root's system cache (-C: no download, no change), when",
  "# this login is not root and sudo grants exactly that command. Root's dnf checks each",
  "# cached repo signature (repo_gpgcheck) with root's keyring; libdnf 4 cannot do that for",
  "# a login without root (it makes its gpg home under /run/user), so such a repo fails the",
  "# whole check there. $1 is empty or --security. Sets dnf_out and returns dnf's exit code;",
  "# returns 1 without running anything when the grant is not there.",
  "dnf_root_check() {",
  "  local BIN_DNF rc",
  '  [ "$(id -u)" -ne 0 ] || return 1',
  '  BIN_DNF="$(command -v dnf 2>/dev/null)" || return 1',
  '  case "$BIN_DNF" in /*) ;; *) return 1 ;; esac',
  '  if [ "${1-}" = "--security" ]; then',
  `    sudo -n -l ${DNF_CHECK_SECURITY_ARGV} >/dev/null 2>&1 || return 1`,
  `    dnf_out="$(sudo -n ${DNF_CHECK_SECURITY_ARGV} 2>/dev/null)"`,
  "    rc=$?",
  "  else",
  `    sudo -n -l ${DNF_CHECK_ARGV} >/dev/null 2>&1 || return 1`,
  `    dnf_out="$(sudo -n ${DNF_CHECK_ARGV} 2>/dev/null)"`,
  "    rc=$?",
  "  fi",
  '  return "$rc"',
  "}",
  "",
  "# dnf check-update, read-only. First as root through dnf_root_check, when granted. Then",
  "# as this login on the system cache (-C); when that fails, on dnf4's per-user cache,",
  "# which needs no root. Sets dnf_out (the list) and returns dnf's exit code (0 = none,",
  "# 100 = updates). dnf_user_cache=1 when the per-user retry answered. It runs in the",
  "# current shell, never in $(...), so the flag survives the call.",
  "dnf_check() {",
  "  local rc",
  '  dnf_root_check "${1-}"',
  "  rc=$?",
  '  if [ "$rc" -eq 0 ] || [ "$rc" -eq 100 ]; then return "$rc"; fi',
  '  dnf_out="$(dnf -q -C check-update "$@" 2>/dev/null)"',
  "  rc=$?",
  '  if [ "$rc" -ne 0 ] && [ "$rc" -ne 100 ]; then',
  '    dnf_out="$(dnf -q check-update "$@" 2>/dev/null)"',
  "    rc=$?",
  '    if [ "$rc" -eq 0 ] || [ "$rc" -eq 100 ]; then dnf_user_cache=1; fi',
  "  fi",
  '  return "$rc"',
  "}",
  "",
  "collect_dnf() {",
  '  pkg_mgr="dnf"',
  "  local rc",
  "  dnf_check; rc=$?",
  '  if [ "$rc" -eq 0 ] || [ "$rc" -eq 100 ]; then',
  '    updates="$(dnf_list "$dnf_out" | grep -cE \'^[A-Za-z0-9._+-]+\\.[A-Za-z0-9_]+[[:space:]]\' || true)"',
  '    pending_b64="$(b64 "$(pending_lines "$(dnf_list "$dnf_out")")")"',
  "  else",
  '    updates="null"; log "dnf check-update failed (rc $rc)"',
  "  fi",
  "  # --security filters check-update to packages with a security update (a clean",
  "  # subset of updates), unlike `updateinfo list` which repeats a package per advisory.",
  "  dnf_check --security; rc=$?",
  '  if [ "$rc" -eq 0 ] || [ "$rc" -eq 100 ]; then',
  '    security="$(dnf_list "$dnf_out" | grep -cE \'^[A-Za-z0-9._+-]+\\.[A-Za-z0-9_]+[[:space:]]\' || true)"',
  '    pending_sec_b64="$(b64 "$(dnf_list "$dnf_out")")"',
  "  else",
  '    security="null"; log "dnf check-update --security failed (rc $rc)"',
  "  fi",
  '  if [ "$dnf_user_cache" = "1" ]; then cache_age=0; else',
  '    set_cache_age "$(newest_mtime /var/cache/dnf/*/repodata/repomd.xml /var/cache/libdnf5/*/repodata/repomd.xml)"',
  "  fi",
  "  total=\"$(rpm -qa 2>/dev/null | wc -l | tr -d ' ')\"",
  '  [ -z "$updates" ] && updates=0',
  '  [ -z "$security" ] && security=0',
  '  [ -z "$total" ] && total=0',
  "  # Prefer needs-restarting (dnf-utils) for the reboot flag; fall back to kernels.",
  "  if command -v needs-restarting >/dev/null 2>&1; then",
  "    if ! needs-restarting -r >/dev/null 2>&1; then",
  '      needs_reboot="true"; set_reason "needs-restarting: reboot required"',
  "    fi",
  "  fi",
  '  [ "$needs_reboot" = "false" ] && kernel_compare',
  "}",
  "",
  "collect_apk() {",
  '  pkg_mgr="apk"',
  '  set_cache_age "$(newest_mtime /var/cache/apk/APKINDEX.*.tar.gz)"',
  "  local list",
  "  list=\"$(apk version -l '<' 2>/dev/null)\"",
  "  updates=\"$(printf '%s\\n' \"$list\" | grep -c '<' || true)\"",
  '  pending_b64="$(b64 "$(pending_lines "$(printf \'%s\\n\' "$list" | grep \'<\')")")"',
  '  security="null"   # Alpine has no distinct security channel',
  "  total=\"$(apk info 2>/dev/null | wc -l | tr -d ' ')\"",
  '  [ -z "$updates" ] && updates=0',
  '  [ -z "$total" ] && total=0',
  "  if printf '%s\\n' \"$list\" | grep -q '^linux-'; then",
  '    needs_reboot="true"; set_reason "kernel package update available"',
  "  fi",
  "}",
  "",
  "# Arch: never `pacman -Sy` here — syncing the db without upgrading invites partial",
  "# upgrades. checkupdates (pacman-contrib; it also needs fakeroot) syncs a private copy",
  "# of the db instead",
  "# (exit 2 = nothing to update); without it, fall back to the existing sync db.",
  "collect_pacman() {",
  '  pkg_mgr="pacman"',
  '  set_cache_age "$(newest_mtime /var/lib/pacman/sync/*.db)"',
  "  local list rc running",
  "  if command -v checkupdates >/dev/null 2>&1; then",
  '    list="$(checkupdates 2>/dev/null)"; rc=$?',
  '    [ "$rc" -eq 2 ] && { list=""; rc=0; }',
  "  else",
  "    rc=1",
  "  fi",
  '  if [ "$rc" -ne 0 ]; then',
  '    log "checkupdates unavailable or failed (it needs pacman-contrib and fakeroot); using the existing sync db"',
  '    list="$(pacman -Qu 2>/dev/null || true)"',
  "  fi",
  "  updates=\"$(printf '%s\\n' \"$list\" | grep -v '\\[ignored\\]' | grep -c . || true)\"",
  '  pending_b64="$(b64 "$(pending_lines "$list")")"',
  "  # arch-audit (optional) lists installed packages with a fixed advisory.",
  "  if command -v arch-audit >/dev/null 2>&1; then",
  "    local audit",
  '    audit="$(arch-audit -u -q 2>/dev/null)"',
  '    security="$(printf \'%s\\n\' "$audit" | grep -c . || true)"',
  '    pending_sec_b64="$(b64 "$audit")"',
  '    [ -z "$security" ] && security=0',
  "  fi",
  "  total=\"$(pacman -Qq 2>/dev/null | wc -l | tr -d ' ')\"",
  '  [ -z "$updates" ] && updates=0',
  '  [ -z "$total" ] && total=0',
  "  # A kernel upgrade removes the running kernel's module tree. /boot/vmlinuz-linux",
  "  # carries no version, so kernel_compare does not apply. A container runs the host's",
  "  # kernel, so its own module tree (if any) says nothing: no verdict there.",
  '  running="$(uname -r)"',
  '  if ! systemd-detect-virt -cq 2>/dev/null && [ -n "$(ls -A /usr/lib/modules 2>/dev/null)" ] &&',
  '     [ ! -d "/usr/lib/modules/$running" ]; then',
  '    needs_reboot="true"; set_reason "running kernel $running is no longer installed"',
  "  fi",
  "}",
  "",
  "# Docker inventory written by a root timer on the host (see lib/docker_inventory.ts).",
  "# This user only reads that file. Its base64 goes out on one line, never the raw text.",
  "read_docker_file() {",
  "  local f=/var/lib/swamp-patch/docker-inventory.json",
  '  if [ -r "$f" ]; then',
  '    docker_source="file"',
  '    docker_file_b64="$(base64 -w0 < "$f" 2>/dev/null || base64 < "$f" | tr -d \'\\n\')"',
  "  else",
  '    docker_source="none"',
  "  fi",
  "}",
  "",
  "# Container image drift: for each running container, compare the local image digest",
  "# (RepoDigests, i.e. the digest it was pulled at) against the registry digest for its",
  "# tag (buildx imagetools inspect). updateAvailable=true when they differ, null when it",
  "# can't be determined (locally-built image, private/unreachable registry). Independent",
  "# of the OS package sections; sets docker_engine + docker_json only. When the socket",
  "# is not usable, read_docker_file takes the root-written inventory instead.",
  "collect_docker() {",
  "  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then",
  '    docker_source="socket"',
  "  else",
  "    read_docker_file",
  "    return 0",
  "  fi",
  "  local ver; ver=\"$(docker --version 2>/dev/null | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1)\"",
  '  [ -n "$ver" ] && docker_engine="\\"$ver\\""',
  '  local items="" c ref local_dig local_sha reg_sha upd item',
  "  while IFS= read -r c; do",
  '    [ -z "$c" ] && continue',
  '    ref="$(docker inspect "$c" --format \'{{.Config.Image}}\' 2>/dev/null)"',
  '    [ -z "$ref" ] && continue',
  '    local_dig="$(docker image inspect "$ref" --format \'{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}\' 2>/dev/null)"',
  '    local_sha="${local_dig##*@}"; case "$local_sha" in sha256:*) ;; *) local_sha="" ;; esac',
  "    reg_sha=\"$(docker buildx imagetools inspect \"$ref\" --format '{{.Manifest.Digest}}' 2>/dev/null | grep -oE 'sha256:[0-9a-f]+' | head -1)\"",
  '    upd="null"',
  '    if [ -n "$local_sha" ] && [ -n "$reg_sha" ]; then',
  '      [ "$local_sha" = "$reg_sha" ] && upd="false" || upd="true"',
  "    fi",
  '    item="{\\"container\\":\\"$(jesc "$c")\\",\\"image\\":\\"$(jesc "$ref")\\",\\"localDigest\\":\\"$(jesc "$local_sha")\\",\\"registryDigest\\":\\"$(jesc "$reg_sha")\\",\\"updateAvailable\\":$upd}"',
  '    items="${items:+$items,}$item"',
  "  done <<DOCKER_PS",
  "$(docker ps --format '{{.Names}}' 2>/dev/null)",
  "DOCKER_PS",
  '  docker_json="[$items]"',
  "}",
  "",
  "# The installed-package manifest: PKG_MANIFEST_CMD, the same command the @dmc/patch",
  "# model runs for its package diff. Its output is never shipped, only the hash below.",
  "pkg_manifest() { " + PKG_MANIFEST_CMD + "; }",
  "",
  "# sha256 of the manifest sorted in the C locale, as a JSON string; null when the",
  "# manifest command fails or prints nothing, or no 64-digit digest comes out (no sha256sum).",
  "collect_packages_hash() {",
  "  local out digest",
  '  out="$(pkg_manifest 2>/dev/null)" || return 0',
  '  [ -n "$out" ] || return 0',
  '  digest="$(printf \'%s\\n\' "$out" | LC_ALL=C sort | sha256sum 2>/dev/null | cut -c1-64)"',
  '  if [ "${#digest}" -eq 64 ] && [ -z "$(printf \'%s\' "$digest" | tr -d \'0-9a-f\')" ]; then',
  '    packages_hash="\\"$digest\\""',
  "  fi",
  "}",
  "",
  "main() {",
  '  local os_type="Unknown" os_version="Unknown" os_id="" os_like=""',
  "  if [ -r /etc/os-release ]; then",
  "    # shellcheck disable=SC1091",
  "    . /etc/os-release",
  "    # A rolling release (Arch) has no VERSION_ID, only BUILD_ID=rolling.",
  '    os_type="${NAME:-Unknown}"; os_version="${VERSION_ID:-${BUILD_ID:-Unknown}}"',
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
  "  elif command -v pacman >/dev/null 2>&1; then",
  "    collect_pacman",
  "  else",
  '    log "no supported package manager found (apt/dnf/apk/pacman)"',
  "  fi",
  "",
  "  collect_docker",
  "",
  "  collect_packages_hash",
  "",
  "  local uid",
  '  uid="$(id -u 2>/dev/null)"',
  "  case \"$uid\" in '' | *[!0-9]*) uid=null ;; esac",
  '  printf \'{"_kind":"patch-inventory","schemaVersion":6,"hostname":"%s","osType":"%s","osVersion":"%s","packageManager":"%s","updatesCount":%s,"securityUpdatesCount":%s,"heldBackCount":%s,"removalsCount":%s,"distUpgradeRequired":%s,"totalPackages":%s,"needsReboot":%s,"rebootReason":%s,"dockerEngine":%s,"dockerImages":%s,"cacheAgeHours":%s,"uid":%s,"dockerSource":"%s","dockerFileB64":"%s","packagesHash":%s,"pendingB64":"%s","pendingSecurityB64":"%s","scannedAt":"%s"}\\n\' \\',
  '    "$(jesc "$hostname_val")" "$(jesc "$os_type")" "$(jesc "$os_version")" "$pkg_mgr" \\',
  '    "$updates" "$security" "$held_back" "$removals" "$dist_required" \\',
  '    "$total" "$needs_reboot" "$reason_json" "$docker_engine" "$docker_json" \\',
  '    "$cache_age" "$uid" "$docker_source" "$docker_file_b64" "$packages_hash" "$pending_b64" "$pending_sec_b64" "$scanned_at"',
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

/** A Proxmox node name, as @dmc/proxmox accepts it. */
const PVE_NODE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$/;

// A user-definable health check. Several may be listed; the machine is healthy
// only when every check passes. Each runs on the machine's own transport
// (http and proxmox-cluster from the swamp host; service/command via ssh or pct exec).
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
    name: z.string().regex(/^[A-Za-z0-9@._:+-]+$/).describe(
      "A systemd unit or OpenRC service: healthy when `systemctl is-active <name>` passes, or OpenRC's rc-status shows it started (read without root; a crashed daemon is not started)",
    ),
  }),
  z.object({
    type: z.literal("proxmox-cluster"),
    label: z.string().optional(),
    nodeModel: z.string().min(1).describe(
      "A @dmc/proxmox/node model, run from the swamp host: its clusterHealth method reads " +
        "/cluster/status with its own API token, which needs Sys.Audit on / (ensureSnapshotAccess " +
        "with clusterAudit). Nothing runs on the machine and the login gets no secret",
    ),
    node: z.string().regex(PVE_NODE_NAME_RE).optional().describe(
      "The Proxmox node to judge (default: the machine's host). Healthy when the cluster " +
        "lists it online and, in a cluster, has quorum",
    ),
  }),
  z.object({
    type: z.literal("command"),
    label: z.string().optional(),
    run: z.string().min(1).optional().describe(
      "Shell command run in the machine as the login; exit 0 = healthy. Not with privileged",
    ),
    privileged: z.boolean().default(false).describe(
      "The check needs root: it runs `argv` through sudo -n, and needs an " +
        "unsafe.privilegedHealth acceptance record. provisionAccess grants exactly that argv",
    ),
    argv: z.array(z.string()).min(1).optional().describe(
      "A privileged check's exact argv (bin first), with the rules of a plug-in command: " +
        "no shells, interpreters or runners, and arguments of letters, digits and . _ / : = + - only",
    ),
    timeoutSec: z.number().int().default(30),
  }),
]).superRefine((c, ctx) => {
  if (c.type !== "command") return;
  if (c.privileged) {
    if (c.argv === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["argv"],
        message: "a privileged check needs argv",
      });
    }
    if (c.run !== undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["run"],
        message: "a privileged check runs argv, not a shell command",
      });
    }
  } else {
    if (c.run === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["run"],
        message: "a command check needs run",
      });
    }
    if (c.argv !== undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["argv"],
        message: "argv is only for a privileged check",
      });
    }
  }
});

// Who may change a host's OS packages and reboots (see lib/os_policy.ts for the rules).
const OsUpdatePolicy = z.enum(OS_UPDATE_POLICIES);
const OsAutoScope = z.enum(OS_AUTO_SCOPES);

const Machine = z.object({
  host: z.string().min(1).describe("Host name in the sshModel"),
  os: z.boolean().default(true).describe("Collect OS package status"),
  osUpdatePolicy: OsUpdatePolicy.optional().describe(
    "Who may change this host's OS packages and reboots. managed (fleet default): " +
      "@dmc/patch scans, upgrades (safeOsUpdate) and reboots. auto: the host's own updater " +
      "installs OS updates, so @dmc/patch scans and reboots but never upgrades. scan-only: " +
      "@dmc/patch only scans; upgrades and reboots are refused, even with force. " +
      "Absent = inherit globalArguments.osUpdatePolicy.",
  ),
  osAutoScope: OsAutoScope.optional().describe(
    "What the host's own updater installs when the effective osUpdatePolicy is auto: " +
      "security (security updates only) or all. Only valid on an auto machine; setting it " +
      "while the effective policy is managed or scan-only is a configuration error.",
  ),
  health: z.array(HealthCheck).default([]).describe(
    "Health checks used as the healthyAfter verdict for OS update / reboot / docker. " +
      "Every listed check must pass. Empty = reachability fallback. A machine with no checks " +
      "but a `source` updater derives them from that updater model's healthUrl + service globalArgs.",
  ),
  reach: z.enum(["ssh", "pct"]).optional().describe(
    "How to reach the machine: ssh (default, via sshModel) or pct (root in a Proxmox " +
      "container via its node; needs an unsafe.pctExec acceptance record). " +
      "There is no fallback between them.",
  ),
  docker: DockerCfg.optional(),
  ct: z.object({
    proxmoxNode: z.string().min(1).optional().describe(
      "ssh host (in sshModel) of the Proxmox node the CT runs on; pct needs it (reach pct, or the built-in pct snapshots)",
    ),
    ctid: z.number().int().describe("Proxmox CT (LXC) id"),
    nodeModel: z.string().min(1).optional().describe(
      "A @dmc/proxmox/node model whose API token may snapshot this CT: snapshots, rollbacks and deletes go through its snapshotCt / rollbackCt / deleteCtSnapshot / listCtSnapshots, on whichever node the CT runs now. No ssh or root on the node.",
    ),
  }).refine((c) => c.proxmoxNode !== undefined || c.nodeModel !== undefined, {
    message:
      "ct needs nodeModel (API snapshots) or proxmoxNode (pct on the node)",
  }).optional().describe(
    "Marks a Proxmox CT and its location. It is reached over ssh, like a VM, unless it has an " +
      "unsafe.pctExec record: then scan, OS update and reboot go through pct exec on " +
      "proxmoxNode. Its snapshots go through nodeModel (the Proxmox API); without nodeModel " +
      "the built-in CT snapshots run pct on the node and need that record too, and without " +
      "either an OS update needs a snapshotter model. No app source required.",
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
  // (`pct` on the CT's node, only with unsafe.pctExec) — and `snapshotter.model`
  // plugs in any other, reached by name via runModel. Snapshotter contract — the
  // referenced model MUST expose:
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
  // ── Pluggable OS updater ────────────────────────────────────────────────
  // The OS package layer: scan for pending updates, upgrade, list installed packages.
  // Built in: the bundled collector + apt/dnf/apk/pacman over the machine's transport.
  // `osUpdater.model` plugs in any other, reached by name via runModel. OS updater
  // contract — the referenced model MUST expose:
  //   • scanOs({ host })          — write one resource with the inventory fields:
  //                                 `updatesCount` (number|null) and `needsReboot`
  //                                 (bool) are required, the rest optional.
  //   • upgradeOs({ host, mode }) — apply the OS updates (`mode` is safe|full).
  //   • listPackages({ host })    — write one resource with
  //                                 `packages: [{ name, version }]` (for the diff).
  // Success = the method run succeeds. Snapshot, health, reboot and the app `source`
  // stay with @dmc/patch, around the model's upgrade.
  osUpdater: z.object({
    model: z.string().min(1).describe(
      "The OS updater model instance. ANY model that implements the OS updater " +
        "contract works: scanOs({ host }) writing a resource with updatesCount + " +
        "needsReboot (other inventory fields optional), upgradeOs({ host, mode }), and " +
        "listPackages({ host }) writing a resource with `packages: [{ name, version }]`.",
    ),
  }).optional().describe(
    "Optional pluggable OS package layer for scan, safeOsUpdate, reboot and " +
      "pruneSnapshots. When set it replaces the bundled collector and the built-in " +
      "apt/dnf/apk/pacman upgrade. Health checks and reboots still use the machine's " +
      "ssh / pct transport.",
  ),
  unsafe: Unsafe.optional().describe(
    "Explicitly accepted unsafe paths for this machine. Each present key is an acceptance " +
      "record (reason, acceptedBy, acceptedAt, reviewBy) and is reported as an accepted risk. " +
      "Absent = the safe default.",
  ),
  trustRemote: z.array(TrustRemote).default([]).describe(
    "Accepted trust in code fetched at run time by this machine's updater " +
      "(e.g. community-scripts/ProxmoxVE@main).",
  ),
  acceptedRisks: z.array(AcceptedRisk).default([]).describe(
    "Audit findings accepted for this host, by finding id. Still reported, under accepted risks.",
  ),
  from: z.array(SourceAddr).min(1).optional().describe(
    "Per-machine override of access.from (e.g. a host reached through NAT).",
  ),
}).superRefine((m, ctx) => {
  // An explicit non-auto policy on this machine makes osAutoScope a contradiction. An
  // inherited one is checked where the policy is resolved (effectivePolicy), at use.
  if (
    m.osAutoScope !== undefined &&
    (m.osUpdatePolicy === "managed" || m.osUpdatePolicy === "scan-only")
  ) {
    ctx.addIssue({
      code: "custom",
      path: ["osAutoScope"],
      message:
        `osAutoScope applies only when osUpdatePolicy is auto, but this machine sets osUpdatePolicy: ${m.osUpdatePolicy}`,
    });
  }
});

const GlobalArgs = z.object({
  sshModel: z.string().min(1).describe(
    "Name of the @swamp/ssh model instance used to reach hosts (required — no default)",
  ),
  proxmoxNodes: z.array(z.string()).default([]).describe(
    "Optional @dmc/proxmox/node model names, for VM/CT discovery in `import`",
  ),
  osUpdatePolicy: OsUpdatePolicy.default("managed").describe(
    "The fleet default osUpdatePolicy. A machine's own osUpdatePolicy overrides it.",
  ),
  osAutoScope: OsAutoScope.default("security").describe(
    "The fleet default osAutoScope, used by a machine whose effective policy is auto.",
  ),
  machines: z.array(Machine).default([]).describe("The decorated fleet"),
  access: AccessProfile.optional().describe(
    "The unprivileged login used to reach the fleet, and the root-capable model that provisions it. Required by the access methods.",
  ),
}).superRefine((g, ctx) => {
  // A machine that inherits a non-auto fleet policy cannot carry osAutoScope. Caught here,
  // at validation, so a bad machine is not found only when a method reaches it.
  g.machines.forEach((m, i) => {
    if (
      m.osAutoScope !== undefined && m.osUpdatePolicy === undefined &&
      g.osUpdatePolicy !== "auto"
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["machines", i, "osAutoScope"],
        message:
          `osAutoScope applies only when osUpdatePolicy is auto, but ${m.host} inherits osUpdatePolicy: ${g.osUpdatePolicy} from the fleet`,
      });
    }
  });
});

const DockerImage = z.object({
  container: z.string(),
  image: z.string(),
  localDigest: z.string(),
  registryDigest: z.string(),
  updateAvailable: z.boolean().nullable(),
});

/** A packages hash: sha256 as 64 lowercase hex characters. */
const PKG_HASH = /^[0-9a-f]{64}$/;

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
  dockerSource: z.enum([
    "none",
    "socket",
    "socket-invalid",
    "file",
    "file-invalid",
  ])
    .nullable().optional().describe(
      "Where the docker inventory came from: the docker socket, a root-written file, none, or a source whose items failed validation (socket-invalid, file-invalid: then dockerImages is null)",
    ),
  dockerFileAgeHours: z.number().nullable().optional().describe(
    "Hours since the root-written docker inventory file was generated (dockerSource file only)",
  ),
  cacheAgeHours: z.number().nullable().optional().describe(
    "Hours since the package cache was last refreshed by the host's own timers (null = unknown)",
  ),
  uid: z.number().int().nullable().optional().describe(
    "The uid the collector ran as",
  ),
  reachMethod: z.enum(["ssh", "pct"]).nullable().describe(
    "How this host was scanned (null when an osUpdater model scanned it)",
  ),
  acceptedRisksUsed: z.array(z.string()).default([]).describe(
    "Acceptance records this scan relied on, e.g. unsafe.pctExec",
  ),
  securityFindings: z.array(z.string()).default([]).describe(
    "Security findings from the scan itself, e.g. root-login-unaccepted",
  ),
  osUpdater: z.string().nullable().optional().describe(
    "The osUpdater model that scanned this host; null/absent = the bundled collector",
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
  packagesHash: z.string().regex(PKG_HASH).nullable().default(null).describe(
    "sha256 of the sorted installed-package manifest, as read by this scan (null = unknown: no collector hash, or an osUpdater model, which has none in this release)",
  ),
  packagesBaseline: z.string().regex(PKG_HASH).nullable().default(null)
    .describe(
      "The last package hash @dmc/patch saw for this host, carried across reads that could not produce one",
    ),
  packagesChangedOutsidePatch: z.boolean().nullable().default(null).describe(
    "true when this scan found the package set changed since @dmc/patch last saw it (the host's own updater, a person, another tool); null = unknown",
  ),
  lastOutsideChangeAt: z.string().nullable().default(null).describe(
    "When a scan last found an outside change (ISO time), carried until the next one",
  ),
  pendingUpdates: z.array(PendingUpdate).max(PENDING_LIMIT).nullable().default(
    null,
  ).describe(
    "The packages updatesCount counts, by name: installed and new version, repository and security flag where the package manager reports them (null = unknown: no list read, a list that did not parse or did not match the count, or an osUpdater model)",
  ),
  pendingUpdatesTruncated: z.boolean().default(false).describe(
    "true when the host had more pending updates than pendingUpdates keeps (the count is still exact)",
  ),
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
  acceptedRisksUsed: z.array(z.string()).default([]).describe(
    "Acceptance records this run relied on, e.g. unsafe.privilegedUpdater or trustRemote:<source>",
  ),
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
    kind: z.literal("proxmox-ct-api"),
    node: z.string().describe(
      "Proxmox node model whose API token snapshots the CT",
    ),
    ctid: z.number().int(),
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
    "vm → node-model snapshot API; ct → node-model CT snapshot API or pct snapshot on the node host; " +
      "model → a pluggable snapshotter model (see `snapshotter`)",
  ),
  vmid: z.number().nullable().describe(
    "VM id, or CT id when kind=ct; null when kind=model",
  ),
  proxmoxNode: z.string().nullable().describe(
    "node model (vm, or ct through the API) or ssh host running pct (ct); null when kind=model",
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

// What an osUpdater model's `scanOs` must write. Only the two fields every caller reads
// are required; the rest default, so a minimal OS updater stays minimal.
const OsScanResult = z.object({
  hostname: z.string().optional(),
  osType: z.string().default("Unknown"),
  osVersion: z.string().default("Unknown"),
  packageManager: z.string().default("unknown"),
  updatesCount: z.number().int().min(0).nullable(),
  securityUpdatesCount: z.number().int().min(0).nullable().default(null),
  heldBackCount: z.number().int().min(0).nullable().default(null),
  removalsCount: z.number().int().min(0).nullable().default(null),
  distUpgradeRequired: z.boolean().nullable().default(null),
  totalPackages: z.number().int().min(0).nullable().default(null),
  needsReboot: z.boolean(),
  rebootReason: z.string().nullable().default(null),
  dockerEngine: z.string().nullable().default(null),
  dockerImages: z.array(DockerImage).nullable().default(null),
  scannedAt: z.string().optional(),
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

// The swamp-patch access login. The plan is the rendered access for one host; a run is
// the append-only record of one host in provisionAccess or revokeAccess.
const AccessPlan = z.object({
  host: z.string(),
  user: z.string(),
  keyLine: z.string(),
  from: z.array(z.string()),
  docker: z.boolean(),
  provisionScriptSha256: z.string(),
  revokeScriptSha256: z.string(),
  provisionScript: z.string(),
  generatedAt: z.string(),
});

const AccessRun = z.object({
  host: z.string(),
  action: z.enum(["provision", "revoke"]),
  dryRun: z.boolean(),
  ok: z.boolean(),
  exitCode: z.number().nullable(),
  outcome: z.enum([
    "applied",
    "dry-run",
    "refused-takeover",
    "refused-preflight",
    "failed",
    "skipped",
  ]),
  result: z.unknown().nullable(),
  detail: z.string(),
  scriptSha256: z.string(),
  sudo: z.boolean(),
  ranAt: z.string(),
});

// The access audit. auditAccess writes one accessAudit record per host: the findings of the
// two probes, the accepted risks they matched, and whether the host passed the failOn level.
const FailOn = z.enum(["none", "high", "critical"]);
const AuditFinding = z.object({
  id: z.string(),
  severity: z.enum(["critical", "high", "warning", "info"]),
  message: z.string(),
}).strict();
const Count = z.number().int().min(0);
const AccessAudit = z.object({
  host: z.string(),
  auditedAt: z.string(),
  ok: z.boolean(),
  findings: z.array(AuditFinding),
  acceptedRisks: z.array(AuditFinding.extend({
    record: z.object({
      reason: z.string(),
      acceptedBy: z.string(),
      acceptedAt: z.string(),
      reviewBy: z.string(),
    }).loose(),
  })),
  summary: z.object({
    critical: Count,
    high: Count,
    warning: Count,
    info: Count,
    accepted: Count,
    overdue: Count,
  }).strict(),
  userProbe: z.unknown().nullable(),
  rootProbe: z.unknown().nullable(),
  userProbeError: z.string().nullable(),
  rootProbeError: z.string().nullable(),
  pluginGrants: z.array(z.string()).default([]).describe(
    "The sudoers text of the commands the machine's plugged models declare (privileges), with @name@ where each path goes: part of the expected grants",
  ),
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
  /** Set only when the record has it: ssh's own errors (exit 255) are only here. */
  stderr?: string;
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
 *  Throws only when the call failed and no host result can be found. `sudo` is passed
 *  to the call only when true. */
export async function runScriptOutcome(
  sshModel: string,
  hosts: string[],
  script: string,
  timeoutSec: number,
  swamp: SwampApi,
  sudo = false,
): Promise<ScriptOutcome> {
  const t0 = Date.now();
  const res = await swamp.run(sshModel, "script", {
    hosts,
    interpreter: "bash",
    script,
    captureOutput: true,
    timeoutSec,
    ...(sudo ? { sudo: true } : {}),
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
    .map((at): HostRun => ({
      host: at.host as string,
      stdout: (at.stdout as string) ?? "",
      exitCode: (at.exitCode as number) ?? -1,
      ...(typeof at.stderr === "string" ? { stderr: at.stderr } : {}),
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
  ct?: { proxmoxNode?: string; ctid: number; nodeModel?: string };
  source?: { type?: string; model: string };
  proxmox?: { model: string };
  vm?: { proxmoxNode: string; vmid: number };
  snapshotter?: { model: string };
  osUpdater?: { model: string };
  reach?: "ssh" | "pct";
  health?: Array<z.infer<typeof HealthCheck>>;
  unsafe?: UnsafeT;
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

/** Resolve a CT's node + ctid for pct: from `ct`, else legacy (read from the proxmox
 *  model's globalArguments). A `ct` with only a nodeModel has no node for pct. */
export async function ctLocation(
  m: MachineShape,
  swamp: SwampApi,
): Promise<{ node: string; ctid: number }> {
  if (m.ct) {
    if (!m.ct.proxmoxNode) {
      throw new Error(
        `${m.host}: pct needs ct.proxmoxNode (the ssh host of the CT's node)`,
      );
    }
    return { node: m.ct.proxmoxNode, ctid: m.ct.ctid };
  }
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
//   • pct — a Proxmox CT with an unsafe.pctExec record (root in the container), through
//           `pct` on its node over the ssh model. Scripts are shipped base64-encoded into
//           `pct exec`. Containers without the record are reached over ssh; pct is never
//           a fallback. The built-in CT snapshots (`pct snapshot` on the node) need the same record.
// safeOsUpdate, reboot, the health checks, pruneSnapshots' live gate and the
// host-reachable check reach a machine only through a Transport; none of them branches
// on ssh-vs-pct. `scan` keeps its own batched fan-out (one call for every ssh host, one
// per node) to stay under swamp's runModel call budget.
// ---------------------------------------------------------------------------

/** The built-in OS upgrade, for the package manager the machine has. Works as root
 *  (pct exec) or through `sudo -n` (ssh as non-root). apt honours `mode` (safe =
 *  `upgrade`, never removes; full = `full-upgrade`); dnf, apk and pacman always do a
 *  full upgrade (pacman supports no other kind). */
export function osUpgradeScript(mode: "safe" | "full"): string {
  // Every command is a table entry (access_sudoers.ts), run by the absolute path that
  // `command -v` finds on this host: the sudoers entry names that same path, and sudo matches
  // the argv exactly. DEBIAN_FRONTEND comes from the table's env entry, through /usr/bin/env.
  const upgrade = mode === "full" ? "apt-full-upgrade" : "apt-upgrade";
  const families: Array<{
    family: "apt" | "dnf" | "apk" | "pacman";
    ids: string[];
  }> = [
    { family: "apt", ids: ["apt-update", upgrade] },
    { family: "dnf", ids: ["dnf-upgrade"] },
    { family: "apk", ids: ["apk-upgrade"] },
    { family: "pacman", ids: ["pacman-upgrade"] },
  ];
  const lines = [
    `SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo -n"`,
    RUNTIME_ABS_FN,
  ];
  families.forEach(({ family, ids }, i) => {
    const cmds = ids.map(privCommand);
    lines.push(
      `${i === 0 ? "if" : "elif"} command -v ${
        FAMILY_PROBES[family][0]
      } >/dev/null 2>&1; then`,
    );
    for (const l of runtimeResolveLines(cmds)) lines.push(`  ${l}`);
    lines.push(`  ${cmds.map(runtimeLine).join(" && ")}`);
  });
  lines.push(`else echo "no known package manager" >&2; exit 3; fi`);
  return lines.join("\n");
}

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

/** Reboot over ssh, scheduled with systemd-run so the exec call returns before sshd dies.
 *  The command is the table's reboot entry (access_sudoers.ts), run by its absolute path. */
export const SSH_REBOOT_CMD = [
  `SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo -n"`,
  RUNTIME_ABS_FN,
  ...runtimeResolveLines([privCommand("reboot")]),
  runtimeLine(privCommand("reboot")),
].join("\n");

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

/** The package-set fields of one inventory record. */
export interface PackageState {
  packagesHash: string | null;
  packagesBaseline: string | null;
  packagesChangedOutsidePatch: boolean | null;
  lastOutsideChangeAt: string | null;
}

/** The packages hash of a value, or null when it is not one (an unknown value is null). */
export function packagesHashOf(v: unknown): string | null {
  return typeof v === "string" && PKG_HASH.test(v) ? v : null;
}

/**
 * Whether the package set changed outside @dmc/patch since @dmc/patch last saw it.
 *
 * `prev` is the host's previous inventory record (null when there is none). `currentHash`
 * is this read's hash, null when the read could not produce one. The verdict is null when
 * either side is unknown, so an unknown read never reads as "unchanged". The baseline is
 * the last hash @dmc/patch saw: this read's hash, or the carried one when this read has
 * none. A record written before packagesBaseline existed has only packagesHash, which
 * serves as the baseline.
 */
export function outsidePackageChange(
  prev: {
    packagesHash?: unknown;
    packagesBaseline?: unknown;
    lastOutsideChangeAt?: unknown;
  } | null,
  currentHash: unknown,
  nowIso: string,
): PackageState {
  const now = packagesHashOf(currentHash);
  const prevBaseline = packagesHashOf(
    prev?.packagesBaseline ?? prev?.packagesHash,
  );
  const changed = now !== null && prevBaseline !== null
    ? now !== prevBaseline
    : null;
  const carried = typeof prev?.lastOutsideChangeAt === "string"
    ? prev.lastOutsideChangeAt
    : null;
  return {
    packagesHash: now,
    packagesBaseline: now ?? prevBaseline,
    packagesChangedOutsidePatch: changed,
    lastOutsideChangeAt: changed === true ? nowIso : carried,
  };
}

/**
 * The package-set fields of a safeOsUpdate record.
 *
 * The outside-change verdict reads `beforeHash`, the package set just before the update,
 * against the previous record: a change that happened before this update is flagged. The
 * baseline and packagesHash describe the state the update leaves behind (`finalHash`), so
 * @dmc/patch's own upgrade never reads as an outside change on the next scan. When that
 * state is unknown, the baseline is carried: the last hash @dmc/patch saw (the before
 * read's, when it had one).
 */
export function updatedPackageState(
  prev: {
    packagesHash?: unknown;
    packagesBaseline?: unknown;
    lastOutsideChangeAt?: unknown;
  } | null,
  beforeHash: unknown,
  finalHash: unknown,
  nowIso: string,
): PackageState {
  const verdict = outsidePackageChange(prev, beforeHash, nowIso);
  const left = packagesHashOf(finalHash);
  return {
    packagesHash: left,
    packagesBaseline: left ?? verdict.packagesBaseline,
    packagesChangedOutsidePatch: verdict.packagesChangedOutsidePatch,
    lastOutsideChangeAt: verdict.lastOutsideChangeAt,
  };
}

/**
 * The pending updates of one collector line, by name. Only parsePending's result is
 * stored, never the base64. The list is unknown (null) when the collector read none (a
 * line before schemaVersion 6, or a failed count), when it does not parse, or when it
 * disagrees with the count the collector made from the same lines. No updates is [].
 */
export function pendingFromCollector(
  inv: Record<string, unknown>,
  pendingB64: unknown,
  pendingSecurityB64: unknown,
  logger?: Logger,
): {
  pendingUpdates: PendingUpdateT[] | null;
  pendingUpdatesTruncated: boolean;
} {
  const unknown = { pendingUpdates: null, pendingUpdatesTruncated: false };
  if (typeof pendingB64 !== "string") return unknown;
  // A failed count is null, and then the collector read no list. An empty string with a
  // count is an empty list (the shell drops the only newline): the count check below
  // still holds it to 0.
  if (typeof inv.updatesCount !== "number") return unknown;
  // The security list was read exactly when the collector has a security count (dnf
  // --security, arch-audit); "" is then no security update. Without one, security is unknown.
  const sec = typeof inv.securityUpdatesCount === "number"
    ? (typeof pendingSecurityB64 === "string" ? pendingSecurityB64 : "")
    : null;
  const parsed = parsePending(
    String(inv.packageManager ?? ""),
    pendingB64,
    sec,
  );
  if (!parsed.ok) {
    logger?.warn("pending update list rejected: {error}", {
      error: parsed.error,
    });
    return unknown;
  }
  if (!parsed.truncated && parsed.items.length !== inv.updatesCount) {
    logger?.warn(
      "pending update list rejected: {items} entries, but the count is {count}",
      { items: parsed.items.length, count: inv.updatesCount },
    );
    return unknown;
  }
  return {
    pendingUpdates: parsed.items,
    pendingUpdatesTruncated: parsed.truncated,
  };
}

/** The inventory stored for one collector line. A schemaVersion 4 line has no packagesHash;
 *  the writers set the package-set fields from the verdict, so it stores as unknown.
 *  A `file` docker inventory is checked by parseDockerFile here, and only its result is
 *  kept: the base64 itself is never stored, and a file that fails the check gives
 *  `file-invalid` with no images. The pending list is handled the same way
 *  (pendingFromCollector). */
function inventoryFromCollector(
  line: string,
  logger?: Logger,
): Record<string, unknown> {
  const { dockerFileB64, pendingB64, pendingSecurityB64, ...raw } = JSON.parse(
    line,
  ) as Record<string, unknown>;
  const inv: Record<string, unknown> = {
    ...raw,
    ...pendingFromCollector(raw, pendingB64, pendingSecurityB64, logger),
  };
  if (inv.dockerSource === "file") {
    const parsed = parseDockerFile(String(dockerFileB64 ?? ""), new Date());
    if (parsed.ok) {
      return {
        ...inv,
        dockerEngine: parsed.dockerEngine,
        dockerImages: parsed.dockerImages,
        dockerFileAgeHours: parsed.ageHours,
      };
    }
    logger?.warn("docker inventory file rejected: {error}", {
      error: parsed.error,
    });
    return {
      ...inv,
      dockerSource: "file-invalid",
      dockerImages: null,
      dockerFileAgeHours: null,
    };
  }
  // The socket items were never checked before. A schemaVersion 3 line has no
  // dockerSource but does carry dockerImages, so it is checked too. A null list (no
  // engine) is left alone.
  const fromSocket = inv.dockerSource === "socket" ||
    inv.dockerSource === undefined;
  if (!fromSocket || !Array.isArray(inv.dockerImages)) return inv;
  const checked = validateDockerImages(inv.dockerImages);
  if (checked.ok) return inv;
  logger?.warn("docker inventory from the socket rejected: {error}", {
    error: checked.error,
  });
  return { ...inv, dockerSource: "socket-invalid", dockerImages: null };
}

/** The patch inventory from a collector run; null when there is no answer, no marker
 *  line, or no valid JSON. */
async function scanWith(
  script: Transport["script"],
): Promise<z.infer<typeof Inventory> | null> {
  try {
    const { out } = await script(COLLECTOR_SCRIPT, 240);
    const line = markerLine(out, "patch-inventory");
    return line
      ? inventoryFromCollector(line) as z.infer<typeof Inventory>
      : null;
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

/** The refusal for a machine that asks for pct (`reach: "pct"`) without an
 *  unsafe.pctExec acceptance record; null otherwise. pct is root in the container, so it
 *  is never a fallback: the machine is refused, not moved to pct. */
export function pctRefusal(m: MachineShape): string | null {
  if (m.reach !== "pct" || unsafeRecord(m, "pctExec") !== null) return null;
  return `machine "${m.host}" asks for pct (root in the container) but has no unsafe.pctExec acceptance record — add one (reason, acceptedBy, acceptedAt, reviewBy) or reach it over ssh`;
}

/** The refusal for the built-in CT snapshotter on a machine; null when it may run. It runs
 *  `pct snapshot|rollback|delsnapshot` as root on the CT's node, the same root access as pct
 *  exec, so it needs the same unsafe.pctExec record. A CT reached over ssh without the
 *  record gets no root on its node: it needs ct.nodeModel or a snapshotter model instead. */
export function pctSnapshotRefusal(m: MachineShape): string | null {
  if (unsafeRecord(m, "pctExec") !== null) return null;
  return `CT "${m.host}": the built-in pct snapshots run pct as root on its node, which needs an unsafe.pctExec acceptance record — add ct.nodeModel (snapshots through the Proxmox API), a snapshotter model, or the record`;
}

/** True when a machine's snapshots run pct on its node: a CT (not also a VM) with no
 *  snapshotter model and no ct.nodeModel. Only then is its pct location resolved, and only
 *  then does it need the unsafe.pctExec record for its snapshots. */
export function usesPctSnapshots(m: MachineShape): boolean {
  return !m.vm && isCtMachine(m) && !m.snapshotter?.model && !m.ct?.nodeModel;
}

/** Which transport a machine uses, from its decorations alone (no lookup): pct only for a
 *  CT that is not also a VM and has an unsafe.pctExec record; ssh otherwise. */
export function transportVia(m: MachineShape): "ssh" | "pct" {
  return isCtMachine(m) && !m.vm && unsafeRecord(m, "pctExec") !== null
    ? "pct"
    : "ssh";
}

/** The transport for a machine. A CT's location is resolved here (a legacy CT reads it
 *  from its proxmox model). A refused machine throws its pctRefusal: it never falls back
 *  to ssh or to pct. */
export async function transportFor(
  m: MachineShape,
  deps: TransportDeps,
): Promise<Transport> {
  const refusal = pctRefusal(m);
  if (refusal) throw new Error(refusal);
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

/** The fields of a @dmc/proxmox/node `clusterHealth` record that the verdict reads. */
const ClusterHealthRecord = z.object({
  node: z.string(),
  clustered: z.boolean(),
  quorate: z.boolean().nullable(),
  nodeListed: z.boolean(),
  nodeOnline: z.boolean(),
  nodesOnline: z.number(),
  nodesTotal: z.number(),
  healthy: z.boolean(),
  problems: z.array(z.string()),
});

/** A proxmox-cluster check: run the node model's clusterHealth for `node` from the swamp
 *  host and judge its record. Fails closed: a failed run, no record for the node, more than
 *  one, or a record that does not parse is unhealthy. Healthy needs the model's own verdict
 *  AND the facts behind it: listed, online, and quorate in a cluster (quorate null only for
 *  a standalone node), with no problem listed. */
export async function proxmoxClusterVerdict(
  model: string,
  node: string,
  swamp: SwampApi,
): Promise<{ ok: boolean; detail: string }> {
  let res: RunOutcome;
  try {
    res = await swamp.run(model, "clusterHealth", { node });
  } catch (e) {
    return {
      ok: false,
      detail: `${model} clusterHealth failed: ${
        tail((e as Error).message, 120)
      }`,
    };
  }
  if (!res.ok) {
    return {
      ok: false,
      detail: `${model} clusterHealth failed: ${tail(res.error, 120)}`,
    };
  }
  const records = res.artifacts.flatMap((a) => {
    const p = ClusterHealthRecord.safeParse(a);
    return p.success && p.data.node === node ? [p.data] : [];
  });
  if (records.length !== 1) {
    return {
      ok: false,
      detail: records.length === 0
        ? `${model} clusterHealth gave no readable record for ${node}`
        : `${model} clusterHealth gave ${records.length} records for ${node}`,
    };
  }
  const h = records[0];
  const quorumOk = h.clustered ? h.quorate === true : h.quorate === null;
  const ok = h.healthy && h.nodeListed && h.nodeOnline && quorumOk &&
    h.problems.length === 0;
  if (ok) {
    return {
      ok,
      detail: `online, ${
        h.clustered ? "quorate" : "standalone"
      } (${h.nodesOnline}/${h.nodesTotal} nodes online)`,
    };
  }
  const why = h.problems.length
    ? h.problems.join("; ")
    : `listed ${h.nodeListed}, online ${h.nodeOnline}, quorate ${h.quorate}`;
  return { ok, detail: tail(why, 200) };
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
  // The shell checks, in order: their batch index is their position in this list. A
  // privileged check that may not run is left out of the batch and fails with the reason.
  const refusedChecks = new Map<z.infer<typeof HealthCheck>, string>();
  const snippet = (c: z.infer<typeof HealthCheck>): string | null => {
    if (c.type === "service") {
      // Init-agnostic: systemd (is-active) OR OpenRC (Alpine). Not `rc-service <name>
      // status`: it runs the service's init script, which may need root (valkey's checks
      // that it can read its config). rc-status reads OpenRC's state without root and
      // shows a dead daemon as crashed. The name is restricted by the schema.
      return `systemctl is-active '${c.name}' >/dev/null 2>&1 || rc-status -a -f ini 2>/dev/null | awk -v s='${c.name}' '$1 == s && $2 == "=" && $3 == "started" { f = 1 } END { exit !f }'`;
    }
    if (c.type !== "command") return null;
    if (!c.privileged) return c.run ?? "false";
    const p = privilegedHealthCommand(m, c);
    if (!p.ok) {
      refusedChecks.set(c, p.error);
      return null;
    }
    // The exact argv the sudoers entry grants, by its absolute path on the host.
    return [
      `SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo -n"`,
      RUNTIME_ABS_FN,
      ...runtimeResolveLines([p.command]),
      runtimeLine(p.command),
    ].join("\n");
  };
  const batch = checks.flatMap((c) => {
    const s = snippet(c);
    return s === null ? [] : [{ c, s }];
  });
  const batchIndex = new Map(batch.map(({ c }, i) => [c, i]));
  let rcs = new Map<number, number>();
  if (batch.length) {
    const timeoutSec = batch.reduce(
      (t, { c }) => t + (c.type === "command" ? c.timeoutSec : 30),
      0,
    );
    const transport = await transportFor(m, { sshModel, swamp });
    const r = await transport.script(
      healthBatchScript(batch.map(({ s }) => s)),
      timeoutSec,
    );
    rcs = parseHealthBatch(r.out);
  }
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
        // We only need the status; cancel the body so the connection does not
        // leak (also satisfies the test leak sanitizer).
        await res.body?.cancel();
      } catch (e) {
        detail = `fetch failed: ${(e as Error).message.slice(0, 60)}`;
      } finally {
        clearTimeout(timer);
      }
    } else if (c.type === "proxmox-cluster") {
      const node = c.node ?? m.host;
      if (!label) label = `proxmox cluster: ${node} online and quorate`;
      ({ ok, detail } = await proxmoxClusterVerdict(c.nodeModel, node, swamp));
    } else {
      if (!label) {
        label = c.type === "service"
          ? `service ${c.name} active`
          : c.privileged
          ? `privileged: ${(c.argv ?? []).join(" ").slice(0, 40)}`
          : `command: ${(c.run ?? "").slice(0, 40)}`;
      }
      const refused = refusedChecks.get(c);
      const bi = batchIndex.get(c);
      const rc = bi === undefined ? undefined : rcs.get(bi);
      if (refused !== undefined) {
        detail = `refused: ${refused}`;
      } else if (rc === undefined) {
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
// three. Four implementations sit behind the `Snapshotter` interface:
//   • proxmox-vm — the `vm` node model: snapshotVm / rollbackVm / deleteVmSnapshot /
//                  listVmSnapshots (built in).
//   • proxmox-ct-api — the `ct.nodeModel` node model: snapshotCt / rollbackCt /
//                  deleteCtSnapshot / listCtSnapshots through the Proxmox API (built in).
//   • proxmox-ct — `pct snapshot|rollback|delsnapshot|listsnapshot` on the CT's node,
//                  over the ssh model (built in; only for a machine with an
//                  unsafe.pctExec record, see pctSnapshotRefusal).
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
 *  `snapshotter.model` wins; else the built-in proxmox-vm (`vm`); else proxmox-ct-api
 *  (`ct.nodeModel`); else proxmox-ct when the caller passes the CT's resolved pct
 *  location; else null — no snapshot guard. */
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
  if (m.ct?.nodeModel) {
    return { kind: "proxmox-ct-api", node: m.ct.nodeModel, ctid: m.ct.ctid };
  }
  if (ct) return { kind: "proxmox-ct", node: ct.node, ctid: ct.ctid };
  return null;
}

/** The node model whose API token takes a machine's snapshots, and the guest; null when no
 *  node model does (a snapshotter model, pct, or no guard). Follows snapshotterRefFor. */
export function snapshotTokenTarget(
  m: MachineShape,
): { model: string; guest: { type: "vm" | "ct"; vmid: number } } | null {
  const ref = snapshotterRefFor(m);
  if (ref?.kind === "proxmox-vm") {
    return { model: ref.node, guest: { type: "vm", vmid: ref.vmid } };
  }
  if (ref?.kind === "proxmox-ct-api") {
    return { model: ref.node, guest: { type: "ct", vmid: ref.ctid } };
  }
  return null;
}

/** The node models a machine's own proxmox-cluster health checks read through. */
export function clusterCheckModels(m: MachineShape): string[] {
  return [
    ...new Set(
      (m.health ?? []).flatMap((c) =>
        c.type === "proxmox-cluster" ? [c.nodeModel] : []
      ),
    ),
  ];
}

/** One entry per node model a machine uses: the one behind its snapshots (with the guest)
 *  and the ones its proxmox-cluster checks read through. Sys.Audit on / is required for a
 *  model this machine's check uses, allowed for one another machine of `fleet` checks
 *  through, and extra otherwise. */
export function apiTokenUses(
  m: MachineShape,
  fleet: MachineShape[],
): Array<{
  model: string;
  guest: { type: "vm" | "ct"; vmid: number } | null;
  clusterAudit: "required" | "allowed" | "extra";
}> {
  const snap = snapshotTokenTarget(m);
  const own = new Set(clusterCheckModels(m));
  const fleetChecks = new Set(fleet.flatMap(clusterCheckModels));
  const models = new Set([...(snap ? [snap.model] : []), ...own]);
  return [...models].map((model) => ({
    model,
    guest: snap?.model === model ? snap.guest : null,
    clusterAudit: own.has(model)
      ? "required"
      : fleetChecks.has(model)
      ? "allowed"
      : "extra",
  }));
}

/** Each distinct node model's `permissions` answer (the effective privileges of its own
 *  token), read once per model. A failed run or a missing record is kept as the error. */
export async function readTokenPermissions(
  models: string[],
  swamp: SwampApi,
): Promise<Map<string, { paths: unknown; error: string | null }>> {
  const out = new Map<string, { paths: unknown; error: string | null }>();
  for (const model of new Set(models)) {
    try {
      const res = await swamp.run(model, "permissions", {});
      if (!res.ok) {
        out.set(model, {
          paths: null,
          error: tail(res.error, 200) || `${model} permissions failed`,
        });
        continue;
      }
      const paths = res.artifacts[0]?.paths;
      out.set(
        model,
        paths === undefined
          ? { paths: null, error: "no permissions record" }
          : { paths, error: null },
      );
    } catch (e) {
      out.set(model, { paths: null, error: (e as Error).message });
    }
  }
  return out;
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
    case "proxmox-ct-api":
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
    case "proxmox-ct-api":
      return `snapshot failed on ${ref.node} for ctid ${ref.ctid} — aborting update`;
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
    case "proxmox-ct-api": {
      // vmid is the node model's name for the guest id. Proxmox stops a CT to roll it
      // back; start: true brings it up again for the health checks that follow.
      const { node, ctid } = ref;
      return {
        ref,
        where: `CT ${ctid} via node model "${node}"`,
        snapshot: (name) =>
          runLogged(swamp, node, "snapshotCt", { vmid: ctid, name }, logger),
        rollback: (name) =>
          runLogged(
            swamp,
            node,
            "rollbackCt",
            { vmid: ctid, name, start: true },
            logger,
          ),
        delete: (name) =>
          runLogged(
            swamp,
            node,
            "deleteCtSnapshot",
            { vmid: ctid, name },
            logger,
          ),
        list: () =>
          listedSnapshotNames(node, "listCtSnapshots", { vmid: ctid }, swamp),
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

// ---------------------------------------------------------------------------
// OS updaters — the pluggable OS package layer.
//
// Two implementations sit behind the `OsUpdater` interface:
//   • built-in — the bundled collector, `osUpgradeScript` (apt/dnf/apk/pacman) and
//                PKG_MANIFEST_CMD, run over the machine's Transport.
//   • model    — any model named by a machine's `osUpdater.model`, driven by name
//                through runModel with the OS updater contract (the extension point).
// safeOsUpdate, reboot's confirming scan and pruneSnapshots' live gate go through
// `osUpdaterFor`. `scan` keeps its batched collector fan-out for built-in machines and
// calls `scanOs` once per model machine.
// ---------------------------------------------------------------------------

/** One OS package backend for one machine. */
export interface OsUpdater {
  /** The osUpdater model, or null for the built-in one. */
  model: string | null;
  /** Appended to log lines: the transport note, or the model. */
  note: string;
  /** The machine's patch inventory; null when it does not answer. */
  scan(): Promise<z.infer<typeof Inventory> | null>;
  /** Apply the OS updates; rc 0 = success. */
  upgrade(mode: "safe" | "full"): Promise<{ rc: number; out: string }>;
  /** The installed-package manifest; null when it cannot be read. */
  packages(): Promise<Map<string, string> | null>;
}

/** An osUpdater model's `scanOs` result as an inventory, or the reason it is not one. */
export async function modelOsScan(
  model: string,
  host: string,
  swamp: SwampApi,
): Promise<{ inv: z.infer<typeof Inventory> | null; error: string }> {
  const res = await swamp.run(model, "scanOs", { host });
  if (!res.ok) {
    return { inv: null, error: tail(res.error, 300) || "scanOs failed" };
  }
  const parsed = OsScanResult.safeParse(res.artifacts[0] ?? null);
  if (!parsed.success) {
    return {
      inv: null,
      error: `scanOs wrote no valid inventory: ${
        parsed.error.issues.slice(0, 3).map((i) =>
          `${i.path.join(".") || "(resource)"}: ${i.message}`
        ).join("; ")
      }`,
    };
  }
  const s = parsed.data;
  return {
    inv: {
      ...s,
      hostname: s.hostname ?? host,
      reachMethod: null,
      acceptedRisksUsed: [],
      securityFindings: [],
      osUpdater: model,
      health: null,
      error: null,
      // No packages hash from an osUpdater model in this release, so the outside-change
      // verdict is unknown here; the writer (scan, safeOsUpdate, reboot) sets the real one.
      packagesHash: null,
      packagesBaseline: null,
      packagesChangedOutsidePatch: null,
      lastOutsideChangeAt: null,
      // The osUpdater contract (scanOs) gives counts only: no list of names.
      pendingUpdates: null,
      pendingUpdatesTruncated: false,
      scannedAt: s.scannedAt ?? new Date().toISOString(),
    },
    error: "",
  };
}

/** The OS updater a machine uses: its `osUpdater.model`, else the built-in one over
 *  `transport`. */
export function osUpdaterFor(
  m: MachineShape,
  transport: Transport,
  deps: { swamp: SwampApi; logger?: Logger },
): OsUpdater {
  const model = m.osUpdater?.model;
  if (!model) {
    return {
      model: null,
      note: transport.note,
      scan: () => transport.scan(),
      upgrade: (mode) => transport.exec(osUpgradeScript(mode), 1800),
      packages: () => transport.packages(),
    };
  }
  const { swamp } = deps;
  const logger = deps.logger ?? SILENT_LOGGER;
  const host = m.host;
  return {
    model,
    note: ` via osUpdater "${model}"`,
    scan: async () => {
      const { inv, error } = await modelOsScan(model, host, swamp);
      if (!inv) {
        logger.warn("{model} scanOs of {host} failed: {error}", {
          model,
          host,
          error,
        });
      }
      return inv;
    },
    upgrade: async (mode) => {
      const ok = await runLogged(
        swamp,
        model,
        "upgradeOs",
        { host, mode },
        logger,
      );
      return { rc: ok ? 0 : 1, out: "" };
    },
    // Like the built-in manifest: unreadable is null, never an empty list.
    packages: async () => {
      const res = await swamp.run(model, "listPackages", { host });
      const list = res.ok ? res.artifacts[0]?.packages : undefined;
      if (!Array.isArray(list)) return null;
      const out = new Map<string, string>();
      for (const p of list as Array<{ name?: unknown; version?: unknown }>) {
        if (typeof p?.name !== "string" || !p.name) return null;
        out.set(p.name, typeof p.version === "string" ? p.version : "");
      }
      return out;
    },
  };
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

/** `live` — the machine answers: ssh `true`, or `pct status` on the node for a CT with an
 *  unsafe.pctExec record. */
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

/**
 * The login an @swamp/ssh definition uses for one host: the host entry's transport.user,
 * else the default transport.user. Null when the definition, the host entry or the user
 * cannot be read, so the login is unknown.
 */
async function sshLogin(
  repo: DefinitionLookup | undefined,
  sshModel: string,
  host: string,
): Promise<string | null> {
  let ga: Record<string, unknown> | null;
  try {
    ga = await definitionGlobals(repo, sshModel);
  } catch {
    return null;
  }
  if (!ga) return null;
  const hosts = Array.isArray(ga.hosts)
    ? ga.hosts as Array<{ name?: unknown; transport?: { user?: unknown } }>
    : [];
  const entry = hosts.find((h) => h?.name === host);
  if (!entry) return null;
  const defaults = ga.transport as { user?: unknown } | undefined;
  const user = entry.transport?.user ?? defaults?.user;
  return typeof user === "string" && user !== "" ? user : null;
}

/**
 * `policy` — the machine reaches its host only through an accepted path. A pct machine
 * (or any machine that asks for pct) needs an unsafe.pctExec record; a root ssh login
 * needs an unsafe.rootSsh record. safeUpdate always uses ssh, so only the login applies
 * to it. An unreadable login fails closed.
 */
export async function checkRestrictedTransport(
  ctx: CheckCtx,
): Promise<CheckResult> {
  const found = checkMachine(ctx);
  if (!found) return PASS;
  const { host, machine } = found;
  const sshModel = ctx.globalArgs.sshModel;
  const hint = skipHint("restricted-transport", "policy");
  const isSafeUpdate = ctx.methodName === "safeUpdate";
  if (!isSafeUpdate) {
    const refusal = pctRefusal(machine);
    if (refusal) return fail(`${refusal}. ${hint}`);
  }
  // The login is read for the host the transport really uses: the machine itself over
  // ssh, or its node for a pct CT (pct runs over the node's ssh login).
  let loginHost = host;
  let node: string | null = null;
  if (!isSafeUpdate && transportVia(machine) === "pct") {
    try {
      node = (await ctLocation(machine, checkSwamp(ctx))).node;
      loginHost = node;
    } catch (e) {
      return fail(
        `Could not find the Proxmox node of "${host}": ${
          (e as Error).message.slice(0, 200)
        }. ${hint}`,
      );
    }
  }
  const login = await sshLogin(ctx.definitionRepository, sshModel, loginHost);
  if (login === null) {
    return fail(
      `Could not read the ssh login for "${loginHost}" from ${sshModel}: its definition, ` +
        `its host entry or its user cannot be read, so the login is unknown. ` +
        `Check that ${sshModel} lists "${loginHost}" in hosts. ${hint}`,
    );
  }
  if (login === "root" && unsafeRecord(machine, "rootSsh") === null) {
    return fail(
      node === null
        ? `machine "${host}" logs in as root through ${sshModel} but has no unsafe.rootSsh ` +
          `acceptance record — use an unprivileged login (access.user) or add the record. ${hint}`
        : `machine "${host}" is reached through pct on node "${node}", which logs in as root ` +
          `through ${sshModel}, but has no unsafe.rootSsh acceptance record — use an ` +
          `unprivileged login for the node or add the record. ${hint}`,
    );
  }
  return PASS;
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

/** `live` — the machine's snapshotter (a pluggable model, the built-in VM / CT node model,
 *  or CT pct, only with unsafe.pctExec) answers a list, and (rollback) a snapshot exists. */
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
  const pctSnaps = usesPctSnapshots(machine);
  if (pctSnaps) {
    const refusal = pctSnapshotRefusal(machine);
    if (refusal) return fail(`${refusal}. ${hint}`);
  }
  const wanted = checkArg(ctx, "snapshot");
  const needSnapshot = ctx.methodName === "rollback";
  const swamp = checkSwamp(ctx);
  let names: string[] | null = null;
  let where = "the snapshot target";
  try {
    // The CT location is only needed for the built-in pct snapshotter.
    const ct = pctSnaps ? await ctLocation(machine, swamp) : undefined;
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

// ---------------------------------------------------------------------------
// Plug-in privileges (lib/plugin_privileges.ts). A plugged model declares the root commands
// it needs with `privileges({ host })`. pluginPrivilegesFor is the one place that asks,
// validates and applies the rules; provisioning, the audit, the `privileges-declared` check
// and the safeOsUpdate guard all use it.
//   • An app updater (`source`, or the legacy `proxmox`) and an `osUpdater` must declare,
//     unless the machine has an unsafe.privilegedUpdater record: then a missing or failing
//     declaration grants nothing, and the record is an accepted risk used.
//   • A `snapshotter` always declares: there is no unsafe key for it. One that works through
//     an API declares no commands.
//   • `remoteCode: true` needs a trustRemote record for each source in remoteSources, with or
//     without unsafe.privilegedUpdater.
// ---------------------------------------------------------------------------

/** The part a plugged model plays for a machine. "health" is the machine's own privileged
 *  health checks (healthPrivilegesFor): not a model, but granted and checked the same way. */
export type PluginRole = "updater" | "osUpdater" | "snapshotter" | "health";

/** The distinct plugged models of a machine, each with its roles, in role order. */
export function pluggedModels(
  m: MachineShape,
): Array<{ model: string; roles: PluginRole[] }> {
  const out: Array<{ model: string; roles: PluginRole[] }> = [];
  const add = (model: string | null | undefined, role: PluginRole) => {
    if (!model) return;
    const known = out.find((x) => x.model === model);
    if (!known) out.push({ model, roles: [role] });
    else if (!known.roles.includes(role)) known.roles.push(role);
  };
  // appSource is the updater that runs: `source`, else the legacy `proxmox`.
  add(appSource(m), "updater");
  add(m.osUpdater?.model, "osUpdater");
  add(m.snapshotter?.model, "snapshotter");
  return out;
}

/** What one plugged model of a machine may run, or why it is refused. */
export interface ModelPrivileges {
  model: string;
  roles: PluginRole[];
  commands: PrivCommand[];
  errors: string[];
  acceptedRisksUsed: string[];
  remote: Array<{ model: string; source: string }>;
}

/** What a machine's plugged models may run, in all, and per model. */
export interface PluginPrivileges {
  commands: PrivCommand[];
  errors: string[];
  acceptedRisksUsed: string[];
  remote: Array<{ model: string; source: string }>;
  models: ModelPrivileges[];
}

function combinePrivileges(models: ModelPrivileges[]): PluginPrivileges {
  return {
    commands: models.flatMap((x) => x.commands),
    errors: models.flatMap((x) => x.errors),
    acceptedRisksUsed: [...new Set(models.flatMap((x) => x.acceptedRisksUsed))],
    remote: models.flatMap((x) => x.remote),
    models,
  };
}

/** Only the plugged models that play one of these roles: the ones a method will use. */
export function privilegesForRoles(
  p: PluginPrivileges,
  roles: readonly PluginRole[],
): PluginPrivileges {
  return combinePrivileges(
    p.models.filter((x) => x.roles.some((r) => roles.includes(r))),
  );
}

/**
 * Ask each distinct plugged model of a machine once for `privileges({ host })`, validate the
 * answer, and apply the rules above. Never throws for a plug-in's answer: a refusal is an
 * error in the result, and a caller that sees errors must not grant or run anything.
 */
export async function pluginPrivilegesFor(
  machine: MachineShape & { trustRemote?: ReadonlyArray<{ source: string }> },
  swamp: SwampApi,
): Promise<PluginPrivileges> {
  const excused = unsafeRecord(machine, "privilegedUpdater") !== null;
  const trusted = new Set((machine.trustRemote ?? []).map((t) => t.source));
  const models: ModelPrivileges[] = [];
  let next = 1;
  for (const { model, roles } of pluggedModels(machine)) {
    const entry: ModelPrivileges = {
      model,
      roles,
      commands: [],
      errors: [],
      acceptedRisksUsed: [],
      remote: [],
    };
    models.push(entry);
    const res = await swamp.run(model, "privileges", { host: machine.host });
    const raw = res.ok ? res.artifacts[0] ?? null : null;
    const didNotRun = `privileges of "${model}" did not run: ${
      tail(res.error, 200) || "failed"
    }`;
    const parsed = res.ok
      ? parsePluginPrivileges(model, raw, next)
      : { ok: false as const, errors: [didNotRun] };
    // What the plug-in says about remote code, even in an answer that does not parse: an
    // unsafe record excuses a missing declaration, never untrusted remote code.
    const remoteSources = parsed.ok ? parsed.remoteSources : remoteClaim(raw);
    const untrusted = remoteSources.filter((s) => !trusted.has(s));
    if (untrusted.length > 0) {
      entry.errors.push(
        `"${model}" runs remote code from ${
          untrusted.join(", ")
        }, but the machine has no trustRemote record with ${
          untrusted.length === 1 ? "that source" : "those sources"
        }`,
      );
      continue;
    }
    if (!parsed.ok) {
      // A snapshotter has no unsafe key: it always declares.
      if (roles.includes("snapshotter") || !excused) {
        entry.errors.push(...parsed.errors);
        continue;
      }
      entry.acceptedRisksUsed.push("unsafe.privilegedUpdater");
    } else {
      entry.commands = parsed.commands;
      next += parsed.commands.length;
    }
    for (const source of remoteSources) {
      entry.acceptedRisksUsed.push(`trustRemote:${source}`);
      entry.remote.push({ model, source });
    }
  }
  const health = healthPrivilegesFor(machine, next);
  if (health !== null) models.push(health);
  return combinePrivileges(models);
}

/** The name the privileged health checks go by in errors and in the per-model list. */
const HEALTH_CHECKS = "health checks";

type CommandCheck = Extract<z.infer<typeof HealthCheck>, { type: "command" }>;

/** True for a health check that runs as root. */
function isPrivilegedCheck(c: z.infer<typeof HealthCheck>): c is CommandCheck {
  return c.type === "command" && c.privileged === true;
}

/** True when the machine lists a health check that runs as root. */
export function hasPrivilegedHealth(m: MachineShape): boolean {
  return (m.health ?? []).some(isPrivilegedCheck);
}

/** A check's name in messages: its label, else its position in the machine's list. */
function checkName(c: z.infer<typeof HealthCheck>, i: number): string {
  return c.label ? `"${c.label}"` : `health[${i}]`;
}

/**
 * The root command of one privileged health check as the runtime runs it, or why it may not
 * run: the machine needs an unsafe.privilegedHealth record, and the argv must pass the rules
 * of a plug-in command. Checked again at every run, because the checks before it can be skipped.
 */
export function privilegedHealthCommand(
  m: MachineShape,
  c: CommandCheck,
): { ok: true; command: PrivCommand } | { ok: false; error: string } {
  if (unsafeRecord(m, "privilegedHealth") === null) {
    return {
      ok: false,
      error:
        "a privileged check needs an unsafe.privilegedHealth acceptance record",
    };
  }
  const parsed = parseRootArgv("plugin-1-health", c.argv);
  return parsed.ok
    ? parsed
    : { ok: false, error: `privileged check ${parsed.error}` };
}

/**
 * The root commands of a machine's privileged health checks (`privileged: true`), numbered
 * from `first` like plug-in commands, so they are granted, audited and refused the same way;
 * null when the machine has none. Every one needs the machine's unsafe.privilegedHealth record
 * (an accepted risk used), and passes the plug-in command rules. Any error refuses them all.
 */
export function healthPrivilegesFor(
  m: MachineShape,
  first = 1,
): ModelPrivileges | null {
  const checks = (m.health ?? []).map((c, i) => ({ c, i })).filter(({ c }) =>
    isPrivilegedCheck(c)
  );
  if (checks.length === 0) return null;
  const entry: ModelPrivileges = {
    model: HEALTH_CHECKS,
    roles: ["health"],
    commands: [],
    errors: [],
    acceptedRisksUsed: [],
    remote: [],
  };
  if (unsafeRecord(m, "privilegedHealth") === null) {
    entry.errors.push(
      `${HEALTH_CHECKS}: ${
        checks.map(({ c, i }) => checkName(c, i)).join(", ")
      } ${
        checks.length === 1 ? "is" : "are"
      } privileged, but the machine has no unsafe.privilegedHealth acceptance record`,
    );
    return entry;
  }
  if (checks.length > MAX_PLUGIN_COMMANDS) {
    entry.errors.push(
      `${HEALTH_CHECKS}: at most ${MAX_PLUGIN_COMMANDS} privileged checks per machine`,
    );
    return entry;
  }
  checks.forEach(({ c, i }, k) => {
    const parsed = parseRootArgv(
      `plugin-${first + k}-health`,
      (c as CommandCheck).argv,
    );
    if (parsed.ok) entry.commands.push(parsed.command);
    else {entry.errors.push(
        `${HEALTH_CHECKS}: ${checkName(c, i)}: ${parsed.error}`,
      );}
  });
  if (entry.errors.length > 0) entry.commands = [];
  else entry.acceptedRisksUsed.push("unsafe.privilegedHealth");
  return entry;
}

/**
 * The remote sources an answer that did not parse still claims, when remoteCode is true: the
 * strings in remoteSources, and a string remoteSource (the key before the list). An entry that
 * is not a string, or no source at all, adds "(unnamed)", which is never trusted. Anything
 * else claims none.
 */
export function remoteClaim(raw: unknown): string[] {
  if (typeof raw !== "object" || raw === null) return [];
  const r = raw as {
    remoteCode?: unknown;
    remoteSource?: unknown;
    remoteSources?: unknown;
  };
  if (r.remoteCode !== true) return [];
  const out: string[] = [];
  if (Array.isArray(r.remoteSources)) {
    for (const s of r.remoteSources) {
      out.push(typeof s === "string" ? s : "(unnamed)");
    }
  } else if (r.remoteSources !== undefined) out.push("(unnamed)");
  if (typeof r.remoteSource === "string") out.push(r.remoteSource);
  else if (r.remoteSource !== undefined) out.push("(unnamed)");
  return out.length > 0 ? [...new Set(out)] : ["(unnamed)"];
}

// ---------------------------------------------------------------------------
// The swamp-patch access login. renderAccess, provisionAccess and revokeAccess reach a
// host only through access.provisionSshModel, a root-capable login that must differ from
// sshModel. auditAccess probes a host as the patch login through sshModel and as root
// through provisionSshModel, and never changes it. scan, safeUpdate, reboot and the rest
// never use provisionSshModel.
// ---------------------------------------------------------------------------

type AccessAction = "provision" | "revoke";
type AccessOutcome = z.infer<typeof AccessRun>["outcome"];

/** One selected machine and the input its access is rendered from. */
export interface AccessTarget {
  host: string;
  input: ProvisionInput;
}

/**
 * The access profile, and the machines a method acts on: every machine when `hostsArg` is
 * absent or empty, else the named ones in fleet order. Throws when `access` is not set,
 * when its provisioning model is sshModel, or when a named host is not in the fleet.
 */
export function accessTargets(
  globalArgs: z.infer<typeof GlobalArgs>,
  hostsArg?: string[],
): { access: AccessProfileT; targets: AccessTarget[] } {
  const { access, sshModel, machines } = globalArgs;
  if (!access) {
    throw new Error(
      "access is not configured: add access { user, publicKey, from, provisionSshModel } to globalArguments",
    );
  }
  if (access.provisionSshModel === sshModel) {
    throw new Error(
      `access.provisionSshModel must differ from sshModel ("${sshModel}"): the patch login must not be able to provision itself`,
    );
  }
  const named = hostsArg ?? [];
  const known = new Set(machines.map((m) => m.host));
  const unknown = named.filter((h) => !known.has(h));
  if (unknown.length > 0) {
    throw new Error(
      `No machine ${
        unknown.map((h) => `"${h}"`).join(", ")
      } in globalArguments.machines`,
    );
  }
  const selected = named.length > 0
    ? machines.filter((m) => named.includes(m.host))
    : machines;
  return {
    access,
    targets: selected.map((m) => {
      // The one place the OS policy is read for access: capabilitiesFor throws on a bad policy.
      const caps = capabilitiesFor(m, globalArgs);
      return {
        host: m.host,
        input: {
          user: access.user,
          publicKey: access.publicKey,
          from: m.from ?? access.from,
          docker: caps.docker,
          autoUpdates: caps.autoUpdates,
          sudo: {
            osUpgrade: caps.osUpgrade,
            osCheck: caps.osCheck,
            reboot: caps.reboot,
            docker: caps.docker,
          },
          dockerProjects: dockerProjectsFor(m),
        },
      };
    }),
  };
}

/**
 * accessTargets with each machine's plug-in commands (pluginPrivilegesFor) added to its sudo
 * input, so the required set is the table's commands and the plug-ins' together. A machine
 * whose plug-ins have errors is not a target: it is listed in `refused` with the errors, and
 * must not be provisioned.
 */
export async function accessTargetsWithPlugins(
  globalArgs: z.infer<typeof GlobalArgs>,
  hostsArg: string[] | undefined,
  swamp: SwampApi,
): Promise<{
  access: AccessProfileT;
  targets: AccessTarget[];
  refused: Array<{ host: string; errors: string[] }>;
}> {
  const { access, targets } = accessTargets(globalArgs, hostsArg);
  const kept: AccessTarget[] = [];
  const refused: Array<{ host: string; errors: string[] }> = [];
  for (const t of targets) {
    const machine = globalArgs.machines.find((m) => m.host === t.host)!;
    const p = await pluginPrivilegesFor(machine, swamp);
    if (p.errors.length > 0) {
      refused.push({ host: t.host, errors: p.errors });
      continue;
    }
    kept.push({
      host: t.host,
      input: { ...t.input, sudo: { ...t.input.sudo, extra: p.commands } },
    });
  }
  return { access, targets: kept, refused };
}

/** The error a run throws for machines whose plug-in privileges are refused. */
function pluginRefusalMessage(
  refused: Array<{ host: string; errors: string[] }>,
): string {
  return `plug-in privileges refused on ${
    refused.map((r) => `${r.host} (${r.errors.join("; ")})`).join(", ")
  }`;
}

/**
 * The compose project the docker helper may run for a machine: one, named from its compose
 * directory, when the docker block has a composePath. A docker block without one has none, and
 * the runtime refuses to reach it through the helper.
 */
export function dockerProjectsFor(m: {
  docker?: { composePath?: string; service?: string } | null;
}): DockerProject[] {
  const d = m.docker;
  if (!d || !d.composePath) return [];
  return [{
    name: dockerProjectName(d.composePath),
    composeDir: d.composePath,
    service: d.service ?? "-",
  }];
}

/**
 * One helper call as the runtime runs it: `sudo -n`, then the helper's fixed path, the
 * subcommand and its arguments, each shell-quoted. Both safeUpdate and pruneImages build their
 * helper calls here, so the argv that runs is the argv that lib/docker_helper.ts validates.
 */
export function helperLine(sub: HelperSub, ...args: string[]): string {
  return `sudo -n ${helperArgv(sub, ...args).map(shQuote).join(" ")}`;
}

/**
 * The helper's project for a machine: its compose directory's name. Throws when the machine has
 * no composePath, because the helper can only run a project it lists.
 */
export function helperProject(
  host: string,
  composePath: string | undefined,
): string {
  if (!composePath) {
    throw new Error(
      `machine "${host}" has no docker composePath: a login that is not root reaches docker through swamp-patch-docker, which runs one compose project, so add composePath`,
    );
  }
  return dockerProjectName(composePath);
}

/** One container of a docker project, as safeUpdate reads it: its image ref and id, state and health. */
export interface DockerContainer {
  ref: string;
  imageId: string;
  status: string;
  health: string;
}

/**
 * The rows of `swamp-patch-docker inspect`: one `id|configImage|imageId|state|health` line per
 * container. Any other line (docker's own warnings, merged into the output) is skipped; a row is
 * recognised by its hex container id.
 */
export function parseInspectRows(out: string): DockerContainer[] {
  const rows: DockerContainer[] = [];
  for (const raw of out.split("\n")) {
    const m = raw.trim().match(
      /^[0-9a-f]{12,64}\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)$/,
    );
    if (m) {
      rows.push({ ref: m[1], imageId: m[2], status: m[3], health: m[4] });
    }
  }
  return rows;
}

/** The unique name of one accessRun record: its action, host and run time. */
function accessRunName(action: AccessAction, host: string, ts: string): string {
  return `access-${action}-${host}-${ts.replace(/[:.]/g, "-")}`;
}

/** Hex SHA-256 of a text. The scripts are recorded by digest, next to their text. */
async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * The accessPlan record of each target, named by host: the rendered authorized_keys line
 * and both scripts, with their digests. Contacts no host.
 */
async function writeAccessPlans(
  context: Ctx,
  access: AccessProfileT,
  targets: AccessTarget[],
): Promise<Array<{ name: string }>> {
  const generatedAt = new Date().toISOString();
  const revokeScriptSha256 = await sha256Hex(revokeScript(access.user));
  const handles: Array<{ name: string }> = [];
  for (const { host, input } of targets) {
    const script = provisionScript(input);
    handles.push(
      // Not the bare host name: inventory records use it, and reports that pick the
      // latest record by name would let a newer plan hide a host's inventory.
      await context.writeResource("accessPlan", `access-plan-${host}`, {
        host,
        user: input.user,
        keyLine: authorizedKeysLine(input.publicKey, input.from),
        from: input.from,
        docker: input.docker,
        provisionScriptSha256: await sha256Hex(script),
        revokeScriptSha256,
        provisionScript: script,
        generatedAt,
      }),
    );
  }
  return handles;
}

/** The parsed result line of one action in a host's stdout, or null when there is none. */
function accessResult(action: AccessAction, stdout: string): unknown {
  const line = markerLine(stdout, `patch-access-${action}`);
  if (line === null) return null;
  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
}

/**
 * The outcome of one host. Exit 0 with a result line is applied. Only provision reads
 * exit 3 (a foreign account is never taken over), exit 4 (preflight refused) and exit 5
 * (a pre-flight refused: the host cannot take auto updates, or sudo is missing, and nothing
 * was changed). Exit 6 is failed, not refused: the sudoers step found that its grants do
 * not parse or are not included, and it removed what it had installed, so the host is not
 * left with a grant it did not check. Anything else is failed.
 */
function accessOutcome(
  action: AccessAction,
  exitCode: number,
  hasResult: boolean,
): AccessOutcome {
  if (exitCode === 0 && hasResult) return "applied";
  if (action === "provision" && exitCode === 3) return "refused-takeover";
  if (action === "provision" && (exitCode === 4 || exitCode === 5)) {
    return "refused-preflight";
  }
  return "failed";
}

/** One host of an access method, and the script it runs. */
interface AccessJob {
  host: string;
  script: string;
  scriptSha256: string;
}

/** What one host's accessRun record says about its run. */
interface AccessHostResult {
  outcome: AccessOutcome;
  exitCode: number | null;
  result: unknown;
  detail: string;
  sudo: boolean;
}

const NOT_REACHED: AccessHostResult = {
  outcome: "failed",
  exitCode: null,
  result: null,
  detail: "not reached",
  sudo: false,
};

/**
 * The shared flow of provisionAccess and revokeAccess. A dry run contacts no host and
 * writes a dry-run record per host. A real run reads each host's login from
 * provisionSshModel: an unreadable login is skipped, a root login runs the script as is,
 * and any other login runs it under sudo. Hosts with the same script and sudo share one
 * script call. Every host gets its accessRun record before the run throws, which it does
 * when a host was refused or failed. A `refused` host (its plug-in privileges did not pass)
 * is never contacted, in a dry run too: its record is refused-preflight with the errors.
 */
async function runAccess(
  context: Ctx,
  action: AccessAction,
  jobs: AccessJob[],
  provisionSshModel: string,
  dryRun: boolean,
  refused: Array<{ host: string; errors: string[] }> = [],
): Promise<Array<{ name: string }>> {
  const ranAt = new Date().toISOString();
  const swamp = methodSwamp(context);
  const results = new Map<string, AccessHostResult>();
  if (dryRun) {
    for (const job of jobs) {
      results.set(job.host, {
        outcome: "dry-run",
        exitCode: null,
        result: null,
        detail: "dry run: no host was contacted",
        sudo: false,
      });
    }
  } else {
    // One group per distinct script and sudo flag: each group is one script call.
    const groups = new Map<
      string,
      { sudo: boolean; script: string; jobs: AccessJob[] }
    >();
    for (const job of jobs) {
      const login = await sshLogin(
        context.definitionRepository,
        provisionSshModel,
        job.host,
      );
      if (login === null) {
        results.set(job.host, {
          outcome: "skipped",
          exitCode: null,
          result: null,
          detail: `login cannot be read from ${provisionSshModel}`,
          sudo: false,
        });
        continue;
      }
      const sudo = login !== "root";
      const key = `${job.scriptSha256} ${sudo}`;
      const group = groups.get(key) ?? { sudo, script: job.script, jobs: [] };
      group.jobs.push(job);
      groups.set(key, group);
    }
    for (const group of groups.values()) {
      const hosts = group.jobs.map((j) => j.host);
      try {
        const res = await runScriptOutcome(
          provisionSshModel,
          hosts,
          group.script,
          300,
          swamp,
          group.sudo,
        );
        for (const host of hosts) {
          const run = res.runs.find((r) => r.host === host);
          if (!run) {
            results.set(host, {
              outcome: "failed",
              exitCode: null,
              result: null,
              detail: `no result for this host from ${provisionSshModel}`,
              sudo: group.sudo,
            });
            continue;
          }
          const result = accessResult(action, run.stdout);
          results.set(host, {
            outcome: accessOutcome(action, run.exitCode, result !== null),
            exitCode: run.exitCode,
            result,
            detail: tail(run.stdout, 400),
            sudo: group.sudo,
          });
        }
      } catch (e) {
        for (const host of hosts) {
          results.set(host, {
            outcome: "failed",
            exitCode: null,
            result: null,
            detail: tail((e as Error).message, 400),
            sudo: group.sudo,
          });
        }
      }
    }
  }

  for (const r of refused) {
    results.set(r.host, {
      outcome: "refused-preflight",
      exitCode: null,
      result: null,
      detail: tail(`plug-in privileges: ${r.errors.join("; ")}`, 400),
      sudo: false,
    });
  }
  const all: AccessJob[] = [
    ...jobs,
    ...refused.map((r) => ({ host: r.host, script: "", scriptSha256: "" })),
  ];

  const handles: Array<{ name: string }> = [];
  const bad: string[] = [];
  for (const job of all) {
    const r = results.get(job.host) ?? NOT_REACHED;
    const done = r.outcome === "applied" || r.outcome === "dry-run";
    handles.push(
      await context.writeResource(
        "accessRun",
        accessRunName(action, job.host, ranAt),
        {
          host: job.host,
          action,
          dryRun,
          ok: done,
          exitCode: r.exitCode,
          outcome: r.outcome,
          result: r.result,
          detail: r.detail,
          scriptSha256: job.scriptSha256,
          sudo: r.sudo,
          ranAt,
        },
      ),
    );
    if (!done) {
      context.logger.warn("{action} on {host}: {outcome}: {detail}", {
        action,
        host: job.host,
        outcome: r.outcome,
        detail: r.detail,
      });
    }
    // Anything but applied (or a dry run) fails the run, a skipped host included: a run
    // that reports success while a host has no access would hide the gap.
    if (!done) bad.push(`${job.host} (${r.outcome})`);
  }
  if (bad.length > 0) {
    throw new Error(
      `access ${action} refused or failed on ${
        bad.join(", ")
      }; the accessRun records hold the detail`,
    );
  }
  return handles;
}

/** How serious each severity is. A run fails on a finding at or above its failOn level. */
const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  warning: 1,
  high: 2,
  critical: 3,
};
const FAIL_ON_RANK: Record<z.infer<typeof FailOn>, number> = {
  none: Infinity,
  high: SEVERITY_RANK.high,
  critical: SEVERITY_RANK.critical,
};

/** The findings at or above the failOn level. `none` matches none of them. */
function failingFindings(
  findings: Finding[],
  failOn: z.infer<typeof FailOn>,
): Finding[] {
  return findings.filter((f) =>
    SEVERITY_RANK[f.severity] >= FAIL_ON_RANK[failOn]
  );
}

/** What one probe gave one host: its parsed JSON line, or the error the audit records. */
interface ProbeOutcome {
  probe: unknown;
  error: string | null;
}

/**
 * The parsed probe line of one host's run. When there is no line, or it is not JSON, the
 * error is the exit code and the last 300 characters of stdout and of stderr (where ssh
 * says why it could not log in). No run: no result.
 */
export function probeOutcome(
  kind: string,
  run: HostRun | undefined,
): ProbeOutcome {
  if (run === undefined) {
    return { probe: null, error: "no result for this host" };
  }
  const line = markerLine(run.stdout, kind);
  if (line !== null) {
    try {
      return { probe: JSON.parse(line), error: null };
    } catch {
      // Not JSON: the error below is recorded instead.
    }
  }
  const out = tail(run.stdout.trim(), 300);
  const err = tail((run.stderr ?? "").trim(), 300);
  const parts = err === "" ? [out] : [out, `stderr: ${err}`];
  const detail = parts.filter((s) => s !== "").join("; ");
  return { probe: null, error: `exit ${run.exitCode}: ${detail}` };
}

/**
 * The user probe: one `<sshModel> script` call over every selected host, as the patch login
 * and without sudo. A call that throws gives every host its error.
 */
async function runUserProbe(
  sshModel: string,
  hosts: string[],
  swamp: SwampApi,
): Promise<Map<string, ProbeOutcome>> {
  const outcomes = new Map<string, ProbeOutcome>();
  try {
    const res = await runScriptOutcome(
      sshModel,
      hosts,
      userProbeScript(),
      60,
      swamp,
    );
    for (const host of hosts) {
      outcomes.set(
        host,
        probeOutcome(
          "patch-access-user-probe",
          res.runs.find((r) => r.host === host),
        ),
      );
    }
  } catch (e) {
    for (const host of hosts) {
      outcomes.set(host, {
        probe: null,
        error: tail((e as Error).message, 300),
      });
    }
  }
  return outcomes;
}

/**
 * The root probe, through provisionSshModel. Each host's login is read from that model: a
 * login that cannot be read is not contacted, a root login runs the script as is, and any
 * other login runs it under sudo. Hosts with the same sudo flag share one script call.
 */
async function runRootProbe(
  context: Ctx,
  access: AccessProfileT,
  hosts: string[],
): Promise<Map<string, ProbeOutcome>> {
  const { provisionSshModel } = access;
  const swamp = methodSwamp(context);
  const script = rootProbeScript(access.user, access.publicKey);
  const outcomes = new Map<string, ProbeOutcome>();
  const groups = new Map<boolean, string[]>();
  for (const host of hosts) {
    const login = await sshLogin(
      context.definitionRepository,
      provisionSshModel,
      host,
    );
    if (login === null) {
      outcomes.set(host, {
        probe: null,
        error: `login cannot be read from ${provisionSshModel}`,
      });
      continue;
    }
    const sudo = login !== "root";
    groups.set(sudo, [...(groups.get(sudo) ?? []), host]);
  }
  for (const [sudo, group] of groups) {
    try {
      const res = await runScriptOutcome(
        provisionSshModel,
        group,
        script,
        120,
        swamp,
        sudo,
      );
      for (const host of group) {
        outcomes.set(
          host,
          probeOutcome(
            "patch-access-root-probe",
            res.runs.find((r) => r.host === host),
          ),
        );
      }
    } catch (e) {
      for (const host of group) {
        outcomes.set(host, {
          probe: null,
          error: tail((e as Error).message, 300),
        });
      }
    }
  }
  return outcomes;
}

/**
 * `policy` — the access methods have an `access` profile whose provisionSshModel is not
 * sshModel (the patch login must not be able to provision itself), and every `hosts` they
 * name is in the fleet.
 */
export function checkAccessConfigured(ctx: CheckCtx): CheckResult {
  const { access, sshModel, machines } = ctx.globalArgs;
  const hint = skipHint("access-configured", "policy");
  if (!access) {
    return fail(
      `access is not configured: add access { user, publicKey, from, provisionSshModel } to globalArguments. ${hint}`,
    );
  }
  if (access.provisionSshModel === sshModel) {
    return fail(
      `access.provisionSshModel must differ from sshModel ("${sshModel}"): the patch login must not be able to provision itself. ${hint}`,
    );
  }
  const hosts = checkArg(ctx, "hosts");
  if (Array.isArray(hosts)) {
    const missing = hosts.filter((h) =>
      typeof h === "string" && !h.includes("${{") &&
      !machines.some((m) => m.host === h)
    );
    if (missing.length > 0) {
      return fail(
        `No machine ${
          missing.map((h) => `"${h}"`).join(", ")
        } in globalArguments.machines. Fix the host name, or add the machine to the fleet. ${hint}`,
      );
    }
  }
  return PASS;
}

/**
 * The plugged models each method uses. safeUpdate (docker) uses none. The access methods use
 * every plugged model, because their grants are the plug-ins' declarations.
 */
const METHOD_PLUGIN_ROLES: Record<string, readonly PluginRole[]> = {
  safeOsUpdate: ["updater", "osUpdater", "snapshotter", "health"],
  rollback: ["snapshotter"],
  pruneSnapshots: ["snapshotter", "osUpdater"],
  renderAccess: ["updater", "osUpdater", "snapshotter", "health"],
  provisionAccess: ["updater", "osUpdater", "snapshotter", "health"],
  auditAccess: ["updater", "osUpdater", "snapshotter", "health"],
};

/** The access methods: they act on `hosts` (default every machine), not on one `host`. */
const ACCESS_METHODS = ["renderAccess", "provisionAccess", "auditAccess"];

/**
 * `policy` — every plugged model the method will use declares its privileges, and passes
 * the rules of pluginPrivilegesFor. For a host method the machine of `host`; for an access
 * method every selected machine.
 */
export async function checkPrivilegesDeclared(
  ctx: CheckCtx,
): Promise<CheckResult> {
  const method = ctx.methodName ?? "";
  const roles = METHOD_PLUGIN_ROLES[method] ?? [];
  let machines: Machine[];
  if (ACCESS_METHODS.includes(method)) {
    const hosts = checkArg(ctx, "hosts");
    const named = Array.isArray(hosts) && hosts.length > 0
      ? hosts.filter((h): h is string => typeof h === "string")
      : null;
    // An unknown host is access-configured's finding, not this one's.
    machines = ctx.globalArgs.machines.filter((m) =>
      named === null || named.includes(m.host)
    );
  } else {
    const found = checkMachine(ctx);
    machines = found ? [found.machine] : [];
  }
  const swamp = checkSwamp(ctx);
  const problems: string[] = [];
  for (const machine of machines) {
    if (pluggedModels(machine).length === 0 && !hasPrivilegedHealth(machine)) {
      continue;
    }
    const p = privilegesForRoles(
      await pluginPrivilegesFor(machine, swamp),
      roles,
    );
    if (p.errors.length > 0) {
      problems.push(`${machine.host}: ${p.errors.join("; ")}`);
    }
  }
  if (problems.length === 0) return PASS;
  return fail(
    `Plug-in privileges refused: ${problems.join(" | ")}. ` +
      `Each plugged model must answer privileges({ host }) with { commands, helpers: [], remoteCode }; ` +
      `an app updater or osUpdater without it needs an unsafe.privilegedUpdater record, and remote code needs a trustRemote record for each of its sources. ` +
      `A privileged health check needs an unsafe.privilegedHealth record and an argv that passes the plug-in command rules. ${
        skipHint("privileges-declared", "policy")
      }`,
  );
}

/** @dmc/patch/fleet model. */
export const model = {
  type: "@dmc/patch/fleet",
  version: "2026.11.11.2",
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
    {
      toVersion: "2026.10.25.1",
      description:
        "Additive globalArguments change, no migration needed: machines take an optional " +
        "pluggable `osUpdater` (any model that implements scanOs / upgradeOs / " +
        "listPackages). The built-in OS layer adds pacman (Arch). Inventory records gain " +
        "an optional `osUpdater` field.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.11.07.1",
      description:
        "Restricted access. New optional globalArguments: `access`, `osUpdatePolicy`, " +
        "`osAutoScope`; per machine `unsafe`, `trustRemote`, `acceptedRisks`, " +
        "`osUpdatePolicy`, `osAutoScope`, `ct.nodeModel`, and `proxmox-cluster` / " +
        "privileged `command` health checks. No migration is done, but some " +
        "definitions need changes: `reach: pct` needs an `unsafe.pctExec` record, a root " +
        "login needs `unsafe.rootSsh`, a CT snapshot needs `ct.nodeModel` (or " +
        "`unsafe.pctExec` and a root node login), a `service` check name may use only " +
        "A-Za-z0-9@._:+-, and plugged models must declare `privileges` (or the machine " +
        "needs `unsafe.privilegedUpdater`). See the README's upgrade notes.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.11.11.1",
      description:
        "Version bump, no globalArguments schema change. dnf hosts get two read-only " +
        "sudo entries (`dnf -q -C check-update`, with and without `--security`) when the " +
        "login has another grant, and the scan uses them: re-run provisionAccess.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.11.11.2",
      description:
        "Version bump, no globalArguments schema change. The inventory lists the pending " +
        "updates by name (pendingUpdates); earlier records have none (null) until the next " +
        "scan. dnf counts no longer include the Obsoleting Packages section twice.",
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
    accessPlan: {
      description:
        "The rendered swamp-patch access login of one host: the authorized_keys line, the provisioning and revoke scripts, with their SHA-256 digests",
      schema: AccessPlan,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    accessRun: {
      description:
        "Append-only record of one host in provisionAccess or revokeAccess: dry run, applied, refused, skipped or failed, with the script digest and the result",
      schema: AccessRun,
      lifetime: "infinite" as const,
      garbageCollection: 100,
    },
    accessAudit: {
      description:
        "The read-only audit of one host's swamp-patch access login (auditAccess): the findings of the user and root probes, the accepted risks they matched, the summary counts, and whether the host passed the failOn level",
      schema: AccessAudit,
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
        "The machine answers: ssh `true` through the sshModel, or `pct status` on the node for a CT with an unsafe.pctExec record. Not run for rollback, because a broken host is why you roll back",
      labels: ["live"],
      appliesTo: ["safeUpdate", "safeOsUpdate", "reboot"],
      execute: (context: CheckCtx) => checkHostReachable(context),
    },
    "restricted-transport": {
      description:
        "The machine reaches its host only through an accepted path: a pct machine needs an unsafe.pctExec record, and a root ssh login needs an unsafe.rootSsh record. The login is read from the sshModel's hosts; an unreadable login fails",
      labels: ["policy"],
      appliesTo: ["safeUpdate", "safeOsUpdate", "reboot", "rollback"],
      execute: (context: CheckCtx) => checkRestrictedTransport(context),
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
        "The VM/CT snapshot target resolves and its Proxmox node answers; for rollback, a snapshot also exists. A CT with ct.nodeModel lists through that node model (the Proxmox API); a CT without nodeModel or a snapshotter needs an unsafe.pctExec record (the built-in pct snapshots run pct as root on its node). A machine with no vm/ct passes",
      labels: ["live"],
      appliesTo: ["safeOsUpdate", "rollback", "pruneSnapshots"],
      execute: (context: CheckCtx) => checkSnapshotTargetResolves(context),
    },
    "access-configured": {
      description:
        "The access methods have an `access` profile whose provisionSshModel differs from sshModel (the patch login must not provision itself), and the `hosts` they name are in the fleet",
      labels: ["policy"],
      appliesTo: [
        "renderAccess",
        "provisionAccess",
        "revokeAccess",
        "auditAccess",
      ],
      execute: (context: CheckCtx) =>
        Promise.resolve(checkAccessConfigured(context)),
    },
    "privileges-declared": {
      description:
        "Every plugged model the method uses (app updater, osUpdater, snapshotter) answers privileges({ host }) with a valid declaration: its root commands become sudoers grants. An app updater or osUpdater without one needs an unsafe.privilegedUpdater record; a snapshotter always declares; remote code needs a trustRemote record for each of its sources. A privileged health check needs an unsafe.privilegedHealth record and a valid argv. Machines without plugged models or privileged checks pass",
      labels: ["policy"],
      appliesTo: [
        "safeOsUpdate",
        "rollback",
        "pruneSnapshots",
        "renderAccess",
        "provisionAccess",
        "auditAccess",
      ],
      execute: (context: CheckCtx) => checkPrivilegesDeclared(context),
    },
  },
  methods: {
    scan: {
      description:
        "Fan out over the fleet: collect OS + docker image-drift per machine (the bundled collector, or `scanOs` of the machine's osUpdater model), and fire checkUpdate on every app `source`.",
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
          readResource: (
            name: string,
            version?: number,
          ) => Promise<Record<string, unknown> | null>;
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
          acceptedRisksUsed: [],
          securityFindings: [],
          health: null,
          error,
          scannedAt,
        });

        // Per machine: one transport, no fallback. ssh (default) runs the collector over
        // ssh; a CT with an unsafe.pctExec record runs it through pct on its node. A
        // machine that asks for pct without that record is refused: it gets an error
        // record and is not contacted. reachMethod records the transport that worked.
        // A failure of one host or node never sinks the others.
        const scanned = machines.filter((m) => m.os !== false);
        const lines = new Map<string, { line: string; via: "ssh" | "pct" }>();
        const errs = new Map<string, string>();
        const addErr = (h: string, e: string) =>
          errs.set(h, errs.has(h) ? `${errs.get(h)}; ${e}` : e);

        // A machine with an `osUpdater` model is scanned by that model (step 2b), never
        // by the bundled collector.
        const collected = scanned.filter((m) => !m.osUpdater);
        const refused = new Set<string>();
        for (const m of collected) {
          const why = pctRefusal(m);
          if (why) {
            refused.add(m.host);
            addErr(m.host, why);
          }
        }

        // Before any contact, the login the transport reaches the host with is read from the
        // ssh definition. A pct CT is checked on its node, because pct runs over the node's
        // login, but the unsafe.rootSsh record that counts is the CT's own. An unknown login
        // is refused, and so is a root login without that record. A refused machine is never
        // contacted, so it gets no health checks either.
        const logins = new Map<string, string | null>();
        const loginOf = async (target: string): Promise<string | null> => {
          if (!logins.has(target)) {
            logins.set(
              target,
              await sshLogin(context.definitionRepository, sshModel, target),
            );
          }
          return logins.get(target) ?? null;
        };
        // Machines that log in as root with their own unsafe.rootSsh record.
        const rootRisk = new Set<string>();
        for (const m of collected) {
          if (refused.has(m.host)) continue;
          let target = m.host;
          if (transportVia(m) === "pct") {
            try {
              target = (await ctLocation(m, swamp)).node;
            } catch (e) {
              refused.add(m.host);
              addErr(m.host, `pct: ${(e as Error).message.slice(0, 90)}`);
              continue;
            }
          }
          const login = await loginOf(target);
          if (login === null) {
            refused.add(m.host);
            addErr(
              m.host,
              `refused: the ssh login for "${target}" cannot be read from ${sshModel}, so a root login cannot be ruled out`,
            );
          } else if (login === "root") {
            if (unsafeRecord(m, "rootSsh") === null) {
              refused.add(m.host);
              addErr(
                m.host,
                `refused: logs in as root through ${sshModel} (host "${target}") without an unsafe.rootSsh acceptance record — use an unprivileged login (access.user) or add the record`,
              );
            } else {
              rootRisk.add(m.host);
            }
          }
        }

        // 1) ONE ssh `script` call runs the collector on every ssh host (a refused
        // machine is not one).
        const sshHosts = collected.filter((m) =>
          transportVia(m) === "ssh" && !refused.has(m.host)
        ).map((m) => m.host);
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

        // 2) The pct machines (a CT with an unsafe.pctExec record), grouped by node: ONE
        // call per node runs the collector in each of its CTs (see ctBatchScript). An ssh
        // failure of a CT is never retried through pct.
        const byNode = new Map<string, Array<{ host: string; ctid: number }>>();
        for (const m of collected) {
          if (transportVia(m) !== "pct" || refused.has(m.host)) continue;
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
        // 2b) ONE `scanOs` call per machine with an osUpdater model.
        const modelInvs = new Map<string, z.infer<typeof Inventory>>();
        const modelScanned = scanned.filter((m) => m.osUpdater);
        for (const m of modelScanned) {
          const model = m.osUpdater!.model;
          const { inv, error } = await modelOsScan(model, m.host, swamp);
          if (inv) modelInvs.set(m.host, inv);
          else addErr(m.host, `osUpdater ${model}: ${tail(error, 120)}`);
        }
        context.logger.info(
          "Collected inventory: {ssh} ssh host(s) in one call, {cts} CT(s) on {nodes} node(s) via pct, {models} host(s) via osUpdater models",
          {
            ssh: sshHosts.length,
            cts: [...byNode.values()].reduce((n, c) => n + c.length, 0),
            nodes: byNode.size,
            models: modelScanned.length,
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
            // A refused machine is not contacted, so it gets no health checks either.
            const checks = refused.has(h)
              ? []
              : await resolveHealthChecks(m, swamp);
            if (checks.length) {
              const hres = await evalHealth(m, checks, sshModel, swamp);
              health = { healthy: hres.healthy, checks: hres.results };
            }
          } catch { /* health stays null */ }

          const found = lines.get(h);
          const modelInv = modelInvs.get(h);
          // The previous record of this host: the package-set verdict reads its baseline.
          const prev = await context.readResource(h);
          if (modelInv) {
            // An osUpdater model's scan has no packages hash in this release: the read is
            // unknown (null), so the verdict is null and the baseline is carried.
            handles.push(
              await context.writeResource("inventory", h, {
                ...modelInv,
                health,
                ...outsidePackageChange(prev, null, scannedAt),
              }),
            );
          } else if (found) {
            const inv = inventoryFromCollector(found.line, context.logger);
            // uid 0 over ssh without an unsafe.rootSsh record is a finding. Through pct it is
            // expected: root in the container is what pctExec accepts.
            const rootUnaccepted = found.via === "ssh" && inv.uid === 0 &&
              unsafeRecord(m, "rootSsh") === null;
            if (rootUnaccepted) {
              context.logger.warn(
                "{host} ran the collector as uid 0 over ssh without an unsafe.rootSsh record (root-login-unaccepted)",
                { host: h },
              );
            }
            handles.push(
              await context.writeResource(
                "inventory",
                h,
                {
                  ...inv,
                  reachMethod: found.via,
                  acceptedRisksUsed: [
                    ...(found.via === "pct" ? ["unsafe.pctExec"] : []),
                    ...(rootRisk.has(h) ? ["unsafe.rootSsh"] : []),
                  ],
                  securityFindings: rootUnaccepted
                    ? ["root-login-unaccepted"]
                    : [],
                  osUpdater: null,
                  health,
                  error: null,
                  ...outsidePackageChange(
                    prev,
                    packagesHashOf(inv.packagesHash),
                    scannedAt,
                  ),
                },
              ),
            );
          } else {
            handles.push(
              await context.writeResource("inventory", h, {
                ...errorInv(h, errs.get(h) || "unreachable"),
                osUpdater: m.osUpdater?.model ?? null,
                health,
                // No read, so no hash: the verdict is unknown and the baseline is carried.
                ...outsidePackageChange(prev, null, scannedAt),
              }),
            );
          }
        }

        // 4) Fire checkUpdate on each machine's app source (community-script) for
        // fresh data the report reads; best-effort, never fails the scan. A refused
        // machine is not contacted, so its source is not asked either.
        for (const m of machines) {
          const src = appSource(m);
          if (src && !refused.has(m.host)) {
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
              `    ct:   # Proxmox CT — location`,
              `      proxmoxNode: ${g.pnode}`,
              `      ctid: ${g.vmid}`,
              `      # nodeModel: <@dmc/proxmox/node model>   # snapshots through the Proxmox API (else pct with unsafe.pctExec)`,
              `    # reached over ssh; to use pct instead add unsafe.pctExec (reason, acceptedBy, acceptedAt, reviewBy)`,
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
            `# fleet can SSH them (adjust user/tags; CTs also need sshd, or add unsafe.pctExec to reach one through pct):`,
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
        // A root login runs docker directly. Any other login (or one that cannot be read) reaches
        // docker only through the root-owned helper, so it needs the machine's compose project.
        const login = await sshLogin(
          context.definitionRepository,
          sshModel,
          args.host,
        );
        const project = login === "root"
          ? null
          : helperProject(args.host, dcfg.composePath);
        if (
          project !== null && args.service !== undefined &&
          args.service !== dcfg.service
        ) {
          throw new Error(
            `machine "${args.host}": a service override (${args.service}) cannot go through swamp-patch-docker, which runs the service in its project list (${
              dcfg.service ?? "all services"
            })`,
          );
        }
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

        // The project's containers, one row each. Through the helper it is one `inspect` call; a
        // root login gets the direct `compose ps` and `inspect` commands it always had.
        const containers = async (): Promise<DockerContainer[]> => {
          if (project !== null) {
            const r = await ex(helperLine("inspect", project), 60);
            if (r.rc !== 0) {
              throw new Error(
                `swamp-patch-docker inspect failed (rc ${r.rc}): ${
                  tail(r.out, 300)
                }`,
              );
            }
            return parseInspectRows(r.out);
          }
          const ids = (await ex(`${cd}docker compose ps -q${svcArg}`)).out
            .split("\n").map((s) => s.trim()).filter(Boolean);
          const rows: DockerContainer[] = [];
          for (const id of ids) {
            const r = await ex(
              `docker inspect ${id} --format '{{.Config.Image}}|{{.Image}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}'`,
            );
            const [ref = "", imageId = "", status = "", health = ""] = r.out
              .trim().split("|");
            rows.push({ ref, imageId, status, health });
          }
          return rows;
        };
        const snapshotOf = (rows: DockerContainer[]): Map<string, string> => {
          const map = new Map<string, string>();
          for (const r of rows) {
            if (r.ref && r.imageId) map.set(r.ref, r.imageId);
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
          const rows = await containers();
          if (rows.length === 0) return false;
          for (const r of rows) {
            if (r.status === "exited" || r.status === "dead") return false;
            if (r.health === "unhealthy") return false;
            if (r.status !== "running" || r.health === "starting") return null;
          }
          return true;
        };
        // The new images: pull, then up -d (through the helper, or directly for a root login).
        const pullUp = () =>
          project !== null ? ex(helperLine("update", project), 300) : ex(
            `${cd}docker compose pull${svcArg} && docker compose up -d${svcArg}`,
            300,
          );
        // Puts every image of `oldImages` back. The helper restores one ref at a time, and the
        // direct path tags them all and then recreates once, as it always did.
        const rollBack = async (oldImages: Map<string, string>) => {
          if (project !== null) {
            for (const [ref, oldImg] of oldImages) {
              const r = await ex(
                helperLine("restore", project, ref, oldImg),
                300,
              );
              if (r.rc !== 0) {
                log(`restore of ${ref} failed (rc ${r.rc})`);
              }
            }
            return;
          }
          for (const [ref, oldImg] of oldImages) {
            await ex(`docker tag ${oldImg} ${ref}`);
          }
          await ex(`${cd}docker compose up -d --force-recreate${svcArg}`, 300);
        };

        const beforeRows = await containers();
        if (beforeRows.length === 0) {
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
        const before = snapshotOf(beforeRows);
        log(
          `before: ${
            [...before.entries()].map(([r, i]) => `${r}=${i.slice(0, 19)}`)
              .join(", ")
          }`,
        );

        const up = await pullUp();
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

        const after = snapshotOf(await containers());
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
          await rollBack(before);
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
        "(ct decoration) with pct on its node, and bare metal is upgraded unguarded. VMs, " +
        "containers and bare metal are reached over ssh; pct (root in the container) is used " +
        "only for a CT with an unsafe.pctExec record. An app updater (`source`) runs on top for any " +
        "machine kind, under the same snapshot: it is called with snapshot:false when " +
        "@dmc/patch took the snapshot, and with no arguments on an unguarded machine. " +
        "The OS package layer is pluggable too: an `osUpdater` decoration names any model " +
        "that implements the OS updater contract (scanOs / upgradeOs / listPackages); " +
        "otherwise the built-in apt/dnf/apk/pacman upgrade runs. Reboot is never automatic. " +
        "Refused, before any change, unless the machine's effective osUpdatePolicy is managed " +
        "and os is not false (auto: the host upgrades itself; scan-only: never upgraded).",
      arguments: z.object({
        host: z.string().min(1).describe("Machine (host) to update"),
        mode: z.enum(["safe", "full"]).default("safe").describe(
          "apt: safe = `upgrade` (never removes), full = `full-upgrade`. dnf/apk/pacman always do a full upgrade. Passed to an osUpdater model's upgradeOs as is.",
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
        // Fail closed before any side effect: no snapshot, no connection, no upgrade unless
        // the OS policy allows it. An inconsistent policy throws here too.
        const refusal = osRefusal("safeOsUpdate", machine, context.globalArgs);
        if (refusal) throw new Error(refusal);
        // The plugged models this update runs must pass their privileges, before any side
        // effect too: the privileges-declared check can be skipped.
        const plugins = privilegesForRoles(
          await pluginPrivilegesFor(machine, swamp),
          METHOD_PLUGIN_ROLES.safeOsUpdate,
        );
        if (plugins.errors.length > 0) {
          throw new Error(
            `safeOsUpdate of ${args.host} refused: plug-in privileges: ${
              plugins.errors.join("; ")
            }`,
          );
        }
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

        // Reach the machine (pct on its node for a CT with an unsafe.pctExec record, ssh
        // otherwise). The transport and the snapshot guard are chosen separately: an
        // explicit `snapshotter`, else the built-in proxmox-vm (`vm`), proxmox-ct-api
        // (`ct.nodeModel`) or proxmox-ct (a CT with an unsafe.pctExec record, snapshotted
        // with pct on its node), else none — bare metal is upgraded unguarded. A CT is
        // never upgraded unguarded: one with no snapshotter, no nodeModel and no record, or
        // whose location cannot be resolved, aborts the update before any change. From here
        // one flow serves every machine kind.
        const transport = await transportFor(machine, { sshModel, swamp });
        const isCt = !machine.vm && isCtMachine(machine);
        const pctSnaps = usesPctSnapshots(machine);
        if (pctSnaps) {
          const refusal = pctSnapshotRefusal(machine);
          if (refusal) {
            throw new Error(`safeOsUpdate of ${args.host} refused: ${refusal}`);
          }
        }
        const ct = pctSnaps ? await ctLocation(machine, swamp) : undefined;
        const snapRef = snapshotterRefFor(machine, ct);
        const snapper = snapRef
          ? snapshotterFor(snapRef, {
            sshModel,
            swamp,
            host: args.host,
            logger: context.logger,
          })
          : null;
        const kind: z.infer<typeof OsUpdateResult>["kind"] = isCt
          ? "ct"
          : machine.vm
          ? "vm"
          : "bare-metal";
        // The OS package layer: an explicit `osUpdater` model, else the built-in one.
        const os = osUpdaterFor(machine, transport, {
          swamp,
          logger: context.logger,
        });

        const before = await os.scan();
        if (!before) {
          throw new Error(
            os.model
              ? `osUpdater "${os.model}" could not scan ${args.host} — cannot update`
              : `${transport.notReachable} — cannot update`,
          );
        }
        log(
          `before: ${
            before.updatesCount ?? "?"
          } updates (${before.packageManager})${os.note}`,
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

        const beforePkgs = await os.packages();

        log(`upgrading (${args.mode})${os.note}`);
        const up = await os.upgrade(args.mode);
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

        const after = await os.scan();
        const healthy = await afterHealthy(after !== null);

        // What the update changed — read before any rollback, so a rolled-back run still
        // records it, and a machine is never read while it is being restored. When
        // either list is unreadable, record no diff rather than a misleading one.
        let pkgs: Array<z.infer<typeof PkgChange>> | null = null;
        if (after) {
          const afterPkgs = await os.packages();
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

        // After a rollback the post-update scan describes the state that was rolled back,
        // not the machine: read the restored machine once. A failed read leaves its hash
        // unknown, and the record then carries the baseline (see updatedPackageState).
        const restored = rolledBack && after ? await os.scan() : null;
        const leftBehind = rolledBack ? restored : after;

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
              acceptedRisksUsed: plugins.acceptedRisksUsed,
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
          const prev = await context.readResource(args.host);
          dataHandles.push(
            await context.writeResource("inventory", args.host, {
              ...after,
              reachMethod: os.model ? null : transport.via,
              acceptedRisksUsed: [
                ...new Set([
                  ...(after.acceptedRisksUsed ?? []),
                  ...plugins.acceptedRisksUsed,
                ]),
              ],
              osUpdater: os.model,
              securityFindings: [],
              // After a rollback the restored state is unchecked: leave it to the next scan.
              health: rolledBack ? null : inventoryHealth(lastHealth),
              error: null,
              ...updatedPackageState(
                prev,
                before.packagesHash,
                leftBehind?.packagesHash,
                runTs,
              ),
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
        "Gracefully reboot one machine. ssh hosts (VM / bare metal) → `systemctl reboot` over sshModel (scheduled with systemd-run so the call returns before the link drops); containers reached over ssh, or with an unsafe.pctExec record through pct → `pct reboot <ctid>` on the node. Guarded on the last scan's needsReboot unless force. Optionally waits for the host to return and re-scans to confirm needsReboot cleared. Refused, even with force, when the machine's effective osUpdatePolicy is scan-only.",
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
        // Fail closed before any side effect, and before force can skip the guard: a
        // scan-only machine (or os false) is never rebooted.
        const refusal = osRefusal("reboot", machine, context.globalArgs);
        if (refusal) throw new Error(refusal);
        // The health checks after the reboot must be able to run: a privileged one without
        // its record or with a refused argv stops the reboot before it starts.
        const health = healthPrivilegesFor(machine);
        if (health !== null && health.errors.length > 0) {
          throw new Error(
            `reboot of ${args.host} refused: ${health.errors.join("; ")}`,
          );
        }
        let healthRan = false;
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
            // A privileged health check is an accepted risk used only when the checks ran.
            acceptedRisksUsed: healthRan ? health?.acceptedRisksUsed ?? [] : [],
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

        // Wait for the host to return and confirm, through its OS updater's scan.
        const os = osUpdaterFor(machine, transport, { swamp });
        let confirmed = false;
        let needsRebootAfter: boolean | null = null;
        let confirmInv: z.infer<typeof Inventory> | null = null;
        if (args.wait) {
          await sleep(transport.rebootSettleMs); // let it actually go down first
          const deadline = Date.now() + args.waitTimeoutSec * 1000;
          for (;;) {
            const inv = await os.scan();
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
          healthRan = true;
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
          const prev = await context.readResource(args.host);
          dh.push(
            await context.writeResource("inventory", args.host, {
              ...confirmInv,
              reachMethod: os.model ? null : via,
              osUpdater: os.model,
              securityFindings: [],
              health: inventoryHealth(rebootHealth),
              error: null,
              ...outsidePackageChange(
                prev,
                packagesHashOf(confirmInv.packagesHash),
                new Date().toISOString(),
              ),
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
        healthGraceSec: z.number().int().min(0).default(120).describe(
          "Grace window for the post-rollback health check. A rolled-back machine boots again, so while it is unhealthy, re-check every 10 s until healthy or this many seconds have passed. 0 = check once.",
        ),
      }),
      execute: async (
        args: { host: string; snapshot?: string; healthGraceSec: number },
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
        // not whatever the machine is decorated with now. A pct snapshot still needs the
        // machine's unsafe.pctExec record: the rollback runs pct as root on the node.
        const ref = snapshotterRefFromRecord(a);
        if (ref.kind === "proxmox-ct") {
          const refusal = pctSnapshotRefusal(machine);
          if (refusal) {
            throw new Error(`rollback of ${args.host} refused: ${refusal}`);
          }
        }
        const snapper = snapshotterFor(ref, {
          sshModel,
          swamp,
          host: args.host,
          logger: context.logger,
        });
        log(`rolling back to snapshot ${a.name} (${snapper.where})`);

        const ok = await snapper.rollback(a.name);
        log(ok ? `rolled back to ${a.name}` : `ROLLBACK FAILED for ${a.name}`);

        // Best-effort health verdict after the revert. The machine was just started
        // from the snapshot and its services may still be starting: allow the grace
        // window, as after an update.
        const checks = await resolveHealthChecks(machine, swamp);
        let healthy: boolean | null = null;
        if (ok && checks.length) {
          const h = await evalHealthWithGrace(
            () => evalHealth(machine, checks, sshModel, swamp),
            args.healthGraceSec,
            context.logger,
          );
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
        // Final live gate: the machine answers a scan through its OS updater (over its own
        // transport — ssh, or pct on its node for a CT with an unsafe.pctExec record —
        // unless an osUpdater model scans it) AND no reboot is pending.
        const healthyNow = async (m: MachineShape): Promise<boolean> => {
          try {
            const transport = await transportFor(m, { sshModel, swamp });
            const os = osUpdaterFor(m, transport, { swamp });
            return (await os.scan())?.needsReboot === false;
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
          const pctRefused = ref.kind === "proxmox-ct"
            ? pctSnapshotRefusal(machine)
            : null;
          if (pctRefused) {
            kept.push({ host: a.host, name: a.name, reason: pctRefused });
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
        const { sshModel, machines } = context.globalArgs;
        const swamp = methodSwamp(context);
        context.logger.info(
          "Pruning retained images (host={host} dryRun={dryRun})",
          { host: args.host ?? "all", dryRun: args.dryRun },
        );
        const now = Date.now();
        const scannedAt = new Date().toISOString();
        // How one host's docker is reached, read once per host: a root login runs docker directly;
        // any other login runs it through the helper, which needs the host's compose project.
        const routes = new Map<
          string,
          { project: string | null } | { refused: string }
        >();
        const routeOf = async (
          host: string,
        ): Promise<{ project: string | null } | { refused: string }> => {
          const known = routes.get(host);
          if (known !== undefined) return known;
          let route: { project: string | null } | { refused: string };
          const login = await sshLogin(
            context.definitionRepository,
            sshModel,
            host,
          );
          const m = machines.find((x) => x.host === host);
          if (login === "root") {
            route = { project: null };
          } else if (!m) {
            route = { refused: "the host is no longer in the fleet" };
          } else {
            try {
              route = { project: helperProject(host, m.docker?.composePath) };
            } catch (e) {
              route = { refused: (e as Error).message };
            }
          }
          routes.set(host, route);
          return route;
        };
        // Reachability gate: the docker host answers a trivial command (through the helper, `ps`,
        // for a login that is not root).
        const reachable = async (
          host: string,
          project: string | null,
        ): Promise<boolean> => {
          try {
            const line = project === null
              ? "docker version --format '{{.Server.Version}}'"
              : helperLine("ps", project);
            return (await nodeExec(sshModel, host, line, 30, swamp)).rc === 0;
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
          const route = await routeOf(a.host);
          if ("refused" in route) {
            kept.push({ host: a.host, name: a.ref, reason: route.refused });
            continue;
          }
          if (!(await reachable(a.host, route.project))) {
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
          // `docker rmi` by id is inherently safe: it refuses if the image is still in use. The
          // helper's `prune` runs the same `docker rmi` after it checks the id's form.
          let rmLine: string;
          if (route.project === null) {
            rmLine = `docker rmi ${a.imageId}`;
          } else {
            try {
              rmLine = helperLine("prune", a.imageId);
            } catch {
              kept.push({
                host: a.host,
                name: a.ref,
                reason: "the image id is not one swamp-patch-docker accepts",
              });
              continue;
            }
          }
          const rm = await nodeExec(sshModel, a.host, rmLine, 60, swamp);
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
    renderAccess: {
      description:
        "Render the swamp-patch access login of each selected machine into an accessPlan record: the authorized_keys line (one key, restricted by from=), and the provisioning and revoke scripts with their digests. The sudoers grants include what the machine's plugged models declare with privileges({ host }). Contacts no host and does not use sshModel. A machine whose plug-in privileges are refused gets no plan, and fails the run after the others are written.",
      arguments: z.object({
        hosts: z.array(z.string()).optional().describe(
          "Limit to these hosts (default: every machine)",
        ),
      }),
      execute: async (args: { hosts?: string[] }, context: Ctx) => {
        const { access, targets, refused } = await accessTargetsWithPlugins(
          context.globalArgs,
          args.hosts,
          methodSwamp(context),
        );
        context.logger.info("Rendering the access plan of {count} machine(s)", {
          count: targets.length,
        });
        const handles = await writeAccessPlans(context, access, targets);
        if (refused.length > 0) throw new Error(pluginRefusalMessage(refused));
        return { dataHandles: handles };
      },
    },
    provisionAccess: {
      description:
        "Install the swamp-patch access login on each selected machine through access.provisionSshModel, which must differ from sshModel. " +
        "The login gets one key, restricted by from=, is kept out of root, sudo and docker groups, and refuses to take over an account it did not create. " +
        "Its sudoers grants are the table's commands and what the machine's plugged models declare with privileges({ host }); a machine whose plug-in privileges are refused is not contacted (refused-preflight). " +
        "Dry run unless dryRun is false; a dry run contacts no host. Every host gets an accessRun record. A refused or failed host fails the run after all hosts are tried.",
      arguments: z.object({
        hosts: z.array(z.string()).optional().describe(
          "Limit to these hosts (default: every machine)",
        ),
        dryRun: z.boolean().default(true).describe(
          "Write the plans and a dry-run record per host, and contact no host (default true)",
        ),
      }),
      execute: async (
        args: { hosts?: string[]; dryRun: boolean },
        context: Ctx,
      ) => {
        const { access, targets, refused } = await accessTargetsWithPlugins(
          context.globalArgs,
          args.hosts,
          methodSwamp(context),
        );
        // Only an explicit false applies. A missing value is a dry run.
        const dryRun = args.dryRun !== false;
        const jobs: AccessJob[] = [];
        for (const { host, input } of targets) {
          const script = provisionScript(input);
          jobs.push({ host, script, scriptSha256: await sha256Hex(script) });
        }
        context.logger.info(
          "provisionAccess ({mode}) of {count} machine(s) through {model}",
          {
            mode: dryRun ? "dry run" : "apply",
            count: targets.length,
            model: access.provisionSshModel,
          },
        );
        const plans = await writeAccessPlans(context, access, targets);
        const runs = await runAccess(
          context,
          "provision",
          jobs,
          access.provisionSshModel,
          dryRun,
          refused,
        );
        return { dataHandles: [...plans, ...runs] };
      },
    },
    revokeAccess: {
      description:
        "Remove the swamp-patch access login from each selected machine through access.provisionSshModel, which must differ from sshModel. Only what @dmc/patch installed goes: the account and its group when the marker and token show that it made them, the sudoers grant, the managed cache and docker files. Dry run unless dryRun is false; a dry run contacts no host. Every host gets an accessRun record. A failed host fails the run after all hosts are tried.",
      arguments: z.object({
        hosts: z.array(z.string()).optional().describe(
          "Limit to these hosts (default: every machine)",
        ),
        dryRun: z.boolean().default(true).describe(
          "Write a dry-run record per host, and contact no host (default true)",
        ),
      }),
      execute: async (
        args: { hosts?: string[]; dryRun: boolean },
        context: Ctx,
      ) => {
        const { access, targets } = accessTargets(
          context.globalArgs,
          args.hosts,
        );
        // Only an explicit false applies. A missing value is a dry run.
        const dryRun = args.dryRun !== false;
        const script = revokeScript(access.user);
        const scriptSha256 = await sha256Hex(script);
        const jobs: AccessJob[] = targets.map(({ host }) => ({
          host,
          script,
          scriptSha256,
        }));
        context.logger.info(
          "revokeAccess ({mode}) of {count} machine(s) through {model}",
          {
            mode: dryRun ? "dry run" : "apply",
            count: targets.length,
            model: access.provisionSshModel,
          },
        );
        const runs = await runAccess(
          context,
          "revoke",
          jobs,
          access.provisionSshModel,
          dryRun,
        );
        return { dataHandles: runs };
      },
    },
    auditAccess: {
      description:
        "Read-only audit of the swamp-patch access login on each selected machine. Probes each host as the patch login (through sshModel, no sudo) and as root (through access.provisionSshModel), " +
        "reads the effective privileges of the API token behind each VM / CT snapshot and each proxmox-cluster health check (the node model's permissions method, once per model: api-token-extra critical, api-token-missing and api-token-unread high; " +
        "Sys.Audit on / without propagation is allowed only for a model some machine's proxmox-cluster check uses, and required on that machine), " +
        "evaluates the findings with the machine's accepted risks, and writes one accessAudit record per host. Never changes a host. After every host is written, the run fails when a host has a finding at or above failOn (none never fails).",
      arguments: z.object({
        hosts: z.array(z.string()).optional().describe(
          "Limit to these hosts (default: every machine)",
        ),
        failOn: FailOn.default("high").describe(
          "Fail the run when a host has a finding at or above this severity, after every host is written; none never fails (default high, so a host whose probes did not run also fails)",
        ),
      }),
      execute: async (
        args: { hosts?: string[]; failOn?: z.infer<typeof FailOn> },
        context: Ctx,
      ) => {
        // An unknown state must not pass: probe-failed / probe-invalid are high.
        const failOn = args.failOn ?? "high";
        const { access, targets } = accessTargets(
          context.globalArgs,
          args.hosts,
        );
        const { sshModel } = context.globalArgs;
        const hosts = targets.map((t) => t.host);
        if (hosts.length === 0) {
          context.logger.info(
            "auditAccess: no machines selected, nothing to audit",
            {},
          );
          return { dataHandles: [] };
        }
        const machines = context.globalArgs.machines.filter((m) =>
          hosts.includes(m.host)
        );
        // The OS policy is resolved before any probe: an inconsistent one is a config error.
        // autoUpdates and the sudo capabilities are what accessTargets provisions, so the
        // audit checks that same scope and that same required set.
        const policies = new Map(
          machines.map((m) => {
            const caps = capabilitiesFor(m, context.globalArgs);
            return [m.host, {
              policy: effectivePolicy(m, context.globalArgs).policy,
              autoUpdates: caps.autoUpdates,
              sudo: {
                osUpgrade: caps.osUpgrade,
                osCheck: caps.osCheck,
                reboot: caps.reboot,
              },
            }];
          }),
        );
        const swamp = methodSwamp(context);
        const userProbes = await runUserProbe(sshModel, hosts, swamp);
        const rootProbes = await runRootProbe(context, access, hosts);
        // The API tokens each machine uses (snapshots, proxmox-cluster checks), read once
        // per node model. Sys.Audit on / is judged against the whole fleet's checks.
        const tokenUses = new Map(
          machines.map((m) => [
            m.host,
            apiTokenUses(m, context.globalArgs.machines),
          ]),
        );
        const tokenPerms = await readTokenPermissions(
          [...tokenUses.values()].flatMap((uses) => uses.map((u) => u.model)),
          swamp,
        );
        const now = new Date();
        context.logger.info("Auditing the access of {count} machine(s)", {
          count: machines.length,
        });
        const handles: Array<{ name: string }> = [];
        const failed: string[] = [];
        for (const machine of machines) {
          const { host } = machine;
          const user = userProbes.get(host)!;
          const root = rootProbes.get(host)!;
          // Part of the expected grants. A refused plug-in adds nothing here; the
          // privileges-declared check reports it.
          const plugins = await pluginPrivilegesFor(machine, swamp);
          const audit = await evaluateAudit({
            host,
            user: access.user,
            publicKey: access.publicKey,
            from: machine.from ?? access.from,
            docker: !!machine.docker,
            userProbe: user.probe,
            userProbeError: user.error,
            rootProbe: root.probe,
            rootProbeError: root.error,
            machine: {
              unsafe: machine.unsafe,
              trustRemote: machine.trustRemote,
              acceptedRisks: machine.acceptedRisks,
              osUpdatePolicy: policies.get(host)?.policy,
              autoUpdates: policies.get(host)?.autoUpdates,
              dockerProjects: dockerProjectsFor(machine),
              pluginCommands: plugins.commands,
              sudo: policies.get(host)?.sudo,
              apiTokens: (tokenUses.get(host) ?? []).map((u) => ({
                ...u,
                ...tokenPerms.get(u.model)!,
              })),
            },
            now,
          });
          const failing = failingFindings(audit.findings, failOn);
          handles.push(
            await context.writeResource("accessAudit", `access-audit-${host}`, {
              host,
              auditedAt: now.toISOString(),
              ok: failing.length === 0,
              findings: audit.findings,
              acceptedRisks: audit.acceptedRisks,
              summary: audit.summary,
              userProbe: user.probe,
              rootProbe: root.probe,
              userProbeError: user.error,
              rootProbeError: root.error,
              pluginGrants: plugins.commands.map(sudoersTemplate),
            }),
          );
          const s = audit.summary;
          context.logger.info(
            "access audit of {host}: {critical} critical, {high} high, {warning} warning, {info} info, {accepted} accepted, {overdue} overdue",
            {
              host,
              critical: s.critical,
              high: s.high,
              warning: s.warning,
              info: s.info,
              accepted: s.accepted,
              overdue: s.overdue,
            },
          );
          for (const f of audit.findings) {
            if (f.severity === "critical" || f.severity === "high") {
              context.logger.warn("{host} {id}: {message}", {
                host,
                id: f.id,
                message: f.message,
              });
            }
          }
          if (failing.length > 0) {
            failed.push(`${host}: ${failing.map((f) => f.id).join(", ")}`);
          }
        }
        if (failed.length > 0) {
          throw new Error(
            `access audit failed on ${
              failed.join("; ")
            }; the accessAudit records hold the detail`,
          );
        }
        return { dataHandles: handles };
      },
    },
  },
};

export { RC_SENTINEL };
