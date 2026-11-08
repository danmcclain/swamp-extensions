/**
 * The access audit for the swamp-patch login. An audit only READS.
 *
 * Two probes gather facts. The user probe runs as the patch login and takes no input.
 * The root probe runs as root through the provisioning model, and takes only the user and
 * the one public key, both validated here. Each probe prints one JSON line. evaluateAudit
 * is pure: it parses the probe output with strict schemas, derives findings with
 * severities, and matches the machine's accepted risks to findings by id. Nothing here
 * runs a probe or writes a file.
 *
 * @module
 */
import { z } from "npm:zod@4";
import { AccessProfile, isOverdue, UNSAFE_KEYS } from "./access_policy.ts";
import type {
  AcceptanceRecordT,
  AcceptedRiskT,
  TrustRemoteT,
  UnsafeT,
} from "./access_policy.ts";
import {
  apkPeriodicScript,
  aptAutoConf,
  aptPeriodicConf,
  authorizedKeysLine,
  dnfAutoDropInUnit,
  dnfAutomaticConf,
  dockerProducerScript,
  dockerTimerUnits,
  identityBlock,
  MANAGED_HEADER,
  PATHS,
  shQuote,
} from "./access_artifacts.ts";
import { OS_AUTO_SCOPES } from "./os_policy.ts";
import type { OsAutoScope } from "./os_policy.ts";
import { dockerHelperScript, dockerProjectsFile } from "./docker_helper.ts";
import type { DockerProject } from "./docker_helper.ts";
import {
  FAMILY_PROBES,
  requiredCommands,
  requiredHelpers,
  sudoersTemplate,
} from "./access_sudoers.ts";
import type { PrivCommand } from "./access_sudoers.ts";
import { auditApiToken } from "./api_token_audit.ts";
import type { ApiTokenInput } from "./api_token_audit.ts";

/** The family probes as `family:command` words, for the root probe's loop. */
const FAMILY_PROBE_WORDS = Object.entries(FAMILY_PROBES)
  .flatMap(([family, probes]) => probes.map((p) => `${family}:${p}`))
  .join(" ");

const SSH_DIR = `${PATHS.home}/.ssh`;
const AUTH_KEYS_PATH = `${SSH_DIR}/authorized_keys`;
const SUDOERS_DIR = "/etc/sudoers.d";
const SYSTEMD_DIR = "/etc/systemd/system";
const HOST_GROUPS = [
  "docker",
  "wheel",
  "sudo",
  "admin",
  "adm",
  "lxd",
  "disk",
] as const;
const ROOT_GROUPS = [...HOST_GROUPS, "root"] as const;

/** The fixed paths both probes read, as shell-quoted assignments. */
const PATH_VARS: [string, string][] = [
  ["MANAGED", MANAGED_HEADER],
  ["MARKER", PATHS.marker],
  ["STATE_DIR", PATHS.stateDir],
  ["HOME_DIR", PATHS.home],
  ["SSH_DIR", SSH_DIR],
  ["AUTH_KEYS", AUTH_KEYS_PATH],
  ["LIBEXEC", PATHS.libexec],
  ["DOCKER_PRODUCER", PATHS.dockerProducer],
  ["DOCKER_HELPER", PATHS.dockerHelper],
  ["DOCKER_PROJECTS", PATHS.dockerProjects],
  ["PROJECTS_DIR", PATHS.projectsDir],
  ["APT_CONF", PATHS.aptConf],
  ["APK_PERIODIC", PATHS.apkPeriodic],
  ["SUDOERS", PATHS.sudoers],
  ["UNIT_SERVICE", PATHS.unitService],
  ["UNIT_TIMER", PATHS.unitTimer],
  ["APT_AUTO", PATHS.aptAuto],
  ["DNF_AUTO_CONF", PATHS.dnfAutoConf],
  ["DNF_AUTO_DROP_IN", PATHS.dnfAutoDropIn],
  ["SUDOERS_DIR", SUDOERS_DIR],
  ["SYSTEMD_DIR", SYSTEMD_DIR],
];

function pathAssignments(): string {
  return PATH_VARS.map(([name, value]) => `${name}=${shQuote(value)}\n`).join(
    "",
  );
}

/** The JSON helpers both probes use: a string, an integer or null. */
const JSON_HELPERS =
  `# Minimal JSON string escaper (backslash, double-quote, strip control chars).
jesc() { printf '%s' "\${1-}" | sed -e 's/\\\\/\\\\\\\\/g' -e 's/"/\\\\"/g' | tr -d '\\000-\\037'; }
# One JSON string.
jstr() { printf '"%s"' "$(jesc "$1")"; }
# An integer as JSON, or null when the value is not all digits.
jnum() { case "\${1-}" in '' | *[!0-9]*) printf null ;; *) printf '%s' "$1" ;; esac; }
`;

/**
 * The user probe, run as the patch login. It takes no input and writes nothing. The write
 * checks use test -w, and sudo and docker run only to report what they allow. It prints
 * one JSON line. There is no set -e, so every check runs even when an earlier one fails.
 */
export function userProbeScript(): string {
  return `#!/usr/bin/env bash
# Read-only probe, run as the swamp-patch login. It takes no input and writes nothing.
${pathAssignments()}${JSON_HELPERS}
# true or false from test -w on the path in $1.
writable() { if test -w "$1"; then printf true; else printf false; fi; }

user_name="$(id -un 2>/dev/null)"
read -r -a GROUPS <<<"$(id -nG 2>/dev/null)"
groups_json=""
for g in "\${GROUPS[@]}"; do groups_json="\${groups_json:+$groups_json,}$(jstr "$g")"; done

sudo_list=null
sudo_true_rc=""
if command -v sudo >/dev/null 2>&1; then
  sudo_out="$(sudo -n -l 2>&1)"
  sudo_rc=$?
  sudo -n true >/dev/null 2>&1
  sudo_true_rc=$?
  sudo_list="$(printf '{"rc":%s,"out":%s}' "$(jnum "$sudo_rc")" "$(jstr "\${sudo_out:0:2000}")")"
fi

docker_rc=""
if command -v docker >/dev/null 2>&1; then
  docker info >/dev/null 2>&1
  docker_rc=$?
fi

writes="$(printf '{"authorizedKeys":%s,"sshDir":%s,"marker":%s,"stateDir":%s,"libexec":%s,"dockerProducer":%s,"sudoersDir":%s,"unitService":%s,"unitTimer":%s,"aptConf":%s,"apkPeriodic":%s,"aptAuto":%s,"dnfAutoConf":%s,"dnfAutoDropIn":%s,"dockerHelper":%s,"dockerProjects":%s}' "$(writable "$AUTH_KEYS")" "$(writable "$SSH_DIR")" "$(writable "$MARKER")" "$(writable "$STATE_DIR")" "$(writable "$LIBEXEC")" "$(writable "$DOCKER_PRODUCER")" "$(writable "$SUDOERS_DIR")" "$(writable "$UNIT_SERVICE")" "$(writable "$UNIT_TIMER")" "$(writable "$APT_CONF")" "$(writable "$APK_PERIODIC")" "$(writable "$APT_AUTO")" "$(writable "$DNF_AUTO_CONF")" "$(writable "$DNF_AUTO_DROP_IN")" "$(writable "$DOCKER_HELPER")" "$(writable "$DOCKER_PROJECTS")")"

printf '{"_kind":"patch-access-user-probe","user":%s,"uid":%s,"groups":[%s],"sudoList":%s,"sudoTrueRc":%s,"dockerRc":%s,"canWrite":%s}\\n' "$(jstr "$user_name")" "$(jnum "$(id -u 2>/dev/null)")" "$groups_json" "$sudo_list" "$(jnum "$sudo_true_rc")" "$(jnum "$docker_rc")" "$writes"
`;
}

/**
 * The root probe, run as root through the provisioning model. The user and the public key
 * are validated here and shell-quoted in the assignments at the top. The rest of the script
 * uses only those variables. It writes nothing and prints one JSON line of facts.
 */
export function rootProbeScript(user: string, publicKey: string): string {
  if (
    typeof user !== "string" ||
    !AccessProfile.shape.user.safeParse(user).success
  ) {
    throw new Error(
      "the access user must be 1-32 characters of a-z, 0-9, _ or -, start with a-z or _, and not be root or toor",
    );
  }
  if (
    typeof publicKey !== "string" ||
    !AccessProfile.shape.publicKey.safeParse(publicKey).success
  ) {
    throw new Error("the access key must be one ed25519 public key");
  }
  return `#!/usr/bin/env bash
# Read-only probe, run as root through the provisioning model. It writes nothing and
# prints one JSON line of facts. The evaluator decides what the facts mean. There is no
# set -e, so every fact is collected even when an earlier one is missing.
PATCH_USER=${shQuote(user)}
PUBLIC_KEY=${shQuote(publicKey)}
KEY_BLOB="$(printf '%s\\n' "$PUBLIC_KEY" | awk '{ print $2 }')"
${pathAssignments()}
${identityBlock()}
${JSON_HELPERS}
# The passwd field $1 of the patch login, from getent or /etc/passwd.
passwd_field() {
  if command -v getent >/dev/null 2>&1; then
    getent passwd "$PATCH_USER" | cut -d: -f"$1"
  else
    awk -F: -v u="$PATCH_USER" -v n="$1" '$1 == u { print $n; exit }' /etc/passwd
  fi
}

# The owner, group and mode of the path in $1, as stat reports them. Empty when missing.
stat_fields() { stat -c '%U %G %a' "$1" 2>/dev/null; }

# {owner, group, mode} of the path in $1, or null when it does not exist.
owned() {
  local owner group mode
  read -r owner group mode <<<"$(stat_fields "$1")"
  if [ -z "$mode" ]; then printf null; return 0; fi
  printf '{"owner":%s,"group":%s,"mode":%s}' "$(jstr "$owner")" "$(jstr "$group")" "$(jstr "$mode")"
}

# A sha256 as a JSON string, or null unless the value is 64 lowercase hex digits.
hex_or_null() {
  if [ "\${#1}" -eq 64 ] && [ -z "$(printf '%s' "$1" | tr -d '0-9a-f')" ]; then
    printf '"%s"' "$1"
  else
    printf null
  fi
}

# One managed file as JSON: whether it exists, its owner, group and mode, the sha256 of its
# content, and whether it carries the managed header.
managed() {
  local owner group mode hash="" header=false
  read -r owner group mode <<<"$(stat_fields "$1")"
  if [ -z "$mode" ]; then
    printf '{"path":%s,"exists":false,"owner":null,"group":null,"mode":null,"sha256":null,"hasManagedHeader":false}' "$(jstr "$1")"
    return 0
  fi
  hash="$(sha256sum "$1" 2>/dev/null | cut -d' ' -f1)"
  if grep -qF "$MANAGED" "$1" 2>/dev/null; then header=true; fi
  printf '{"path":%s,"exists":true,"owner":%s,"group":%s,"mode":%s,"sha256":%s,"hasManagedHeader":%s}' "$(jstr "$1")" "$(jstr "$owner")" "$(jstr "$group")" "$(jstr "$mode")" "$(hex_or_null "$hash")" "$header"
}

# True when systemd reports the unit in $1 as enabled.
unit_enabled() {
  command -v systemctl >/dev/null 2>&1 && [ "$(systemctl is-enabled "$1" 2>/dev/null)" = enabled ]
}

# Newest mtime (epoch seconds) of the given paths; empty when none exist.
newest_mtime() { stat -c %Y "$@" 2>/dev/null | sort -n | tail -1; }

account_json='{"exists":false,"markerOk":false,"shadowLocked":null,"shell":null,"gecos":null}'
if id -u "$PATCH_USER" >/dev/null 2>&1; then
  if marker_ok; then marker_json=true; else marker_json=false; fi
  locked=null
  if [ -r /etc/shadow ]; then
    case "$(awk -F: -v u="$PATCH_USER" '$1 == u { print $2; exit }' /etc/shadow)" in
      '!'* | '*') locked=true ;;
      *) locked=false ;;
    esac
  fi
  account_json="$(printf '{"exists":true,"markerOk":%s,"shadowLocked":%s,"shell":%s,"gecos":%s}' "$marker_json" "$locked" "$(jstr "$(passwd_field 7)")" "$(jstr "$(account_gecos "$PATCH_USER")")")"
fi

read -r -a UGROUPS <<<"$(id -nG "$PATCH_USER" 2>/dev/null)"
ugroups_json=""
for g in "\${UGROUPS[@]}"; do ugroups_json="\${ugroups_json:+$ugroups_json,}$(jstr "$g")"; done

ak_total=0
ak_json=""
while IFS= read -r line; do
  ak_total=$((ak_total + 1))
  if [ "$ak_total" -le 20 ]; then ak_json="\${ak_json:+$ak_json,}$(jstr "$line")"; fi
done < <(grep -vE '^[[:space:]]*(#|$)' "$AUTH_KEYS" 2>/dev/null)
ak_obj="$(printf '{"lines":[%s],"total":%s,"file":%s,"dir":%s,"home":%s}' "$ak_json" "$ak_total" "$(owned "$AUTH_KEYS")" "$(owned "$SSH_DIR")" "$(owned "$HOME_DIR")")"

root_has_key=false
for f in /root/.ssh/authorized_keys /root/.ssh/authorized_keys2; do
  if [ -f "$f" ] && awk -v b="$KEY_BLOB" '{ for (i = 1; i <= NF; i++) if ($i == b) found = 1 } END { exit !found }' "$f"; then
    root_has_key=true
  fi
done

managed_json="$(managed "$MARKER"),$(managed "$DOCKER_PRODUCER"),$(managed "$UNIT_SERVICE"),$(managed "$UNIT_TIMER"),$(managed "$APT_CONF"),$(managed "$APK_PERIODIC"),$(managed "$SUDOERS"),$(managed "$APT_AUTO"),$(managed "$DNF_AUTO_CONF"),$(managed "$DNF_AUTO_DROP_IN"),$(managed "$DOCKER_HELPER"),$(managed "$DOCKER_PROJECTS")"
dirs_json="$(printf '{"stateDir":%s,"libexec":%s,"sudoersDir":%s,"systemdDir":%s,"projectsDir":%s}' "$(owned "$STATE_DIR")" "$(owned "$LIBEXEC")" "$(owned "$SUDOERS_DIR")" "$(owned "$SYSTEMD_DIR")" "$(owned "$PROJECTS_DIR")")"

# Lines that name the patch login or one of its groups, or that start with ALL. The name
# match is a plain substring, so it can flag a longer name but never misses the login's.
GREP_ARGS=(-e "$PATCH_USER")
for g in "\${UGROUPS[@]}"; do GREP_ARGS+=(-e "%$g"); done
sudo_rules=""
for f in /etc/sudoers /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  # Our own file is compared line by line below (sudoersFile).
  [ "$f" = "$SUDOERS" ] && continue
  hits="$( { grep -nF "\${GREP_ARGS[@]}" "$f"; grep -nE '^[[:space:]]*ALL[[:space:]]' "$f"; } 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#' | sort -t: -k1,1n -u | head -n 10)"
  [ -z "$hits" ] && continue
  lines_json=""
  while IFS= read -r h; do lines_json="\${lines_json:+$lines_json,}$(jstr "$h")"; done <<<"$hits"
  sudo_rules="\${sudo_rules:+$sudo_rules,}$(printf '{"file":%s,"lines":[%s]}' "$(jstr "$f")" "$lines_json")"
done

family=unknown
if command -v pveversion >/dev/null 2>&1; then
  family=pve
elif [ -f /etc/debian_version ]; then
  family=apt
elif command -v dnf >/dev/null 2>&1; then
  family=dnf
elif [ -f /etc/alpine-release ]; then
  family=apk
fi

# Is the package cache refreshed by a timer on this host?
refresh=false
case "$family" in
  pve) refresh=true ;;
  apt)
    if apt-config dump 2>/dev/null | grep -qF 'APT::Periodic::Update-Package-Lists "1";' && unit_enabled apt-daily.timer; then refresh=true; fi
    ;;
  dnf)
    if unit_enabled dnf-makecache.timer; then refresh=true; fi
    ;;
  apk)
    if [ -f "$APK_PERIODIC" ] && grep -qx crond /proc/[0-9]*/comm 2>/dev/null; then refresh=true; fi
    ;;
esac

# Age of the package cache in whole hours, from the same files the collector reads.
newest=""
case "$family" in
  pve | apt) newest="$(newest_mtime /var/lib/apt/lists/*Release)" ;;
  dnf) newest="$(newest_mtime /var/cache/dnf/*/repodata/repomd.xml /var/cache/libdnf5/*/repodata/repomd.xml)" ;;
  apk) newest="$(newest_mtime /var/cache/apk/APKINDEX.*.tar.gz)" ;;
esac
age_json=null
case "$newest" in
  '' | *[!0-9]*) ;;
  *)
    age=$(( ($(date +%s) - newest) / 3600 ))
    [ "$age" -lt 0 ] && age=0
    age_json=$age
    ;;
esac

# Do unattended updates install on their own?
auto_install=false
case "$family" in
  pve | apt)
    if apt-config dump 2>/dev/null | grep -qF 'APT::Periodic::Unattended-Upgrade "1";' && dpkg-query -W -f='\${Status}' unattended-upgrades 2>/dev/null | grep -qx 'install ok installed'; then auto_install=true; fi
    ;;
  dnf)
    if { unit_enabled dnf-automatic.timer || unit_enabled dnf-automatic-install.timer; } && grep -qE '^[[:space:]]*apply_updates[[:space:]]*=[[:space:]]*yes' /etc/dnf/automatic.conf 2>/dev/null; then auto_install=true; fi
    # Or the timer runs our own config: our drop-in names it, and that config applies updates.
    if unit_enabled dnf-automatic.timer && grep -qF "$MANAGED" "$DNF_AUTO_DROP_IN" 2>/dev/null && grep -qxF "ExecStart=/usr/bin/dnf-automatic $DNF_AUTO_CONF --timer" "$DNF_AUTO_DROP_IN" 2>/dev/null && grep -qF "$MANAGED" "$DNF_AUTO_CONF" 2>/dev/null && grep -qE '^[[:space:]]*apply_updates[[:space:]]*=[[:space:]]*yes' "$DNF_AUTO_CONF" 2>/dev/null; then auto_install=true; fi
    ;;
esac

# The scope our auto-update file installs, read from the managed file that carries it:
# security or all. Null when no managed auto-update file is present.
auto_scope=null
if [ -f "$APT_AUTO" ] && grep -qF "$MANAGED" "$APT_AUTO" 2>/dev/null; then
  if grep -qF -- '-updates";' "$APT_AUTO"; then auto_scope='"all"'; else auto_scope='"security"'; fi
elif [ -f "$DNF_AUTO_CONF" ] && grep -qF "$MANAGED" "$DNF_AUTO_CONF" 2>/dev/null; then
  if grep -qxF 'upgrade_type = default' "$DNF_AUTO_CONF"; then auto_scope='"all"'; elif grep -qxF 'upgrade_type = security' "$DNF_AUTO_CONF"; then auto_scope='"security"'; fi
fi

export LC_ALL=C
# The lines of our own sudoers file, for the evaluator to compare with the required set.
# Only the empty lines and the exact managed header are left out: in sudoers a line that
# starts with # can be a directive (#include) or a user id (#1000), so it is kept. A line
# with a character that is not printable ASCII (a tab, a control character) or longer than
# 1000 characters is replaced by a fixed text that never matches a required entry.
sf_total=0
sf_json=""
sf_exists=false
if [ -f "$SUDOERS" ]; then
  sf_exists=true
  while IFS= read -r line || [ -n "$line" ]; do
    [ -z "$line" ] && continue
    [ "$line" = "$MANAGED" ] && continue
    sf_total=$((sf_total + 1))
    [ "$sf_total" -le 128 ] || continue
    if [ "\${#line}" -gt 1000 ] || [[ $line == *[![:print:]]* ]]; then
      line='<unreadable line>'
    fi
    sf_json="\${sf_json:+$sf_json,}$(jstr "$line")"
  done <"$SUDOERS"
fi
sudoers_file="$(printf '{"exists":%s,"lines":[%s],"total":%s}' "$sf_exists" "$sf_json" "$sf_total")"

# The command families on this host, found as the provision script finds them.
sudo_families=""
for fam_probe in ${FAMILY_PROBE_WORDS}; do
  fam="\${fam_probe%%:*}"
  command -v "\${fam_probe#*:}" >/dev/null 2>&1 || continue
  case ",$sudo_families," in *",\\"$fam\\","*) continue ;; esac
  sudo_families="\${sudo_families:+$sudo_families,}\\"$fam\\""
done

# The compose projects the docker helper runs as root, read from its project list: each real
# directory (symlinks followed), the directories above it, and the entries in it that a
# non-root account could change. scanOk is false when the directory is missing or find fails.
compose_json=""
if [ -f "$DOCKER_PROJECTS" ]; then
  n=0
  while IFS=$'\\t' read -r cname cdir _; do
    case "$cname" in '' | '#'*) continue ;; esac
    n=$((n + 1))
    [ "$n" -le 20 ] || break
    [[ $cdir =~ ^/[A-Za-z0-9._/-]+$ ]] || continue
    rdir="$(readlink -f "$cdir" 2>/dev/null)" || rdir=""
    [[ $rdir =~ ^/[A-Za-z0-9._/-]*$ ]] || rdir=""
    chain=""
    real_owned=null
    scan_ok=false
    unsafe_json=""
    unsafe_total=0
    if [ -n "$rdir" ]; then
      real_owned="$(owned "$rdir")"
      d="\${rdir%/*}"
      while [ -n "$d" ]; do
        chain="\${chain:+$chain,}$(printf '{"path":%s,"owned":%s}' "$(jstr "$d")" "$(owned "$d")")"
        d="\${d%/*}"
      done
      chain="\${chain:+$chain,}$(printf '{"path":"/","owned":%s}' "$(owned /)")"
      if [ -d "$rdir" ] && found="$(find -L "$rdir" -mindepth 1 -maxdepth 1 \\( ! -user root -o -perm -020 -o -perm -002 \\) -print 2>/dev/null)"; then
        scan_ok=true
        while IFS= read -r f; do
          [ -n "$f" ] || continue
          unsafe_total=$((unsafe_total + 1))
          if [ "$unsafe_total" -le 10 ]; then unsafe_json="\${unsafe_json:+$unsafe_json,}$(jstr "\${f##*/}")"; fi
        done <<<"$found"
      fi
    fi
    compose_json="\${compose_json:+$compose_json,}$(printf '{"name":%s,"dir":%s,"realDir":%s,"owned":%s,"chain":[%s],"scanOk":%s,"unsafe":[%s],"unsafeTotal":%s}' "$(jstr "$cname")" "$(jstr "$cdir")" "$(jstr "$rdir")" "$real_owned" "$chain" "$scan_ok" "$unsafe_json" "$unsafe_total")"
  done <"$DOCKER_PROJECTS"
fi

host_groups=""
for g in docker wheel sudo admin adm lxd disk; do
  IFS=',' read -r -a MEMBERS <<<"$(group_members "$g")"
  members=""
  for m in "\${MEMBERS[@]}"; do members="\${members:+$members,}$(jstr "$m")"; done
  host_groups="\${host_groups:+$host_groups,}$(printf '"%s":[%s]' "$g" "$members")"
done

printf '{"_kind":"patch-access-root-probe","account":%s,"groupsOfUser":[%s],"authorizedKeys":%s,"rootHasKey":%s,"managedFiles":[%s],"dirs":%s,"sudoRules":[%s],"cache":{"family":"%s","refreshOn":%s,"ageHours":%s,"autoInstall":%s,"autoScope":%s},"hostGroups":{%s},"dockerSocket":%s,"sudoersFile":%s,"sudoFamilies":[%s],"compose":[%s]}\\n' "$account_json" "$ugroups_json" "$ak_obj" "$root_has_key" "$managed_json" "$dirs_json" "$sudo_rules" "$family" "$refresh" "$age_json" "$auto_install" "$auto_scope" "$host_groups" "$(owned /var/run/docker.sock)" "$sudoers_file" "$sudo_families" "$compose_json"
`;
}

// ---------------------------------------------------------------------------
// Findings evaluator
// ---------------------------------------------------------------------------

export type Severity = "critical" | "high" | "warning" | "info";
export interface Finding {
  id: string;
  severity: Severity;
  message: string;
}

export interface AuditInput {
  host: string;
  user: string;
  publicKey: string;
  from: string[];
  docker: boolean;
  /** The parsed user probe JSON, or null when the probe did not run. */
  userProbe: unknown;
  userProbeError: string | null;
  /** The parsed root probe JSON, or null when the probe did not run. */
  rootProbe: unknown;
  rootProbeError: string | null;
  machine: {
    unsafe?: UnsafeT;
    trustRemote?: TrustRemoteT[];
    acceptedRisks?: AcceptedRiskT[];
    osUpdatePolicy?: string;
    /**
     * The scope the access provisioning writes for this machine (capabilitiesFor().autoUpdates):
     * null when the machine is managed, or when it is auto with os off.
     */
    autoUpdates?: OsAutoScope | null;
    /**
     * The compose projects the docker helper's list must name (accessTargets derives them from
     * the docker block). Only compared when the machine has docker; none when absent.
     */
    dockerProjects?: DockerProject[];
    /**
     * The commands the machine's plugged models declare (pluginPrivilegesFor): part of the
     * sudoers entries the host is expected to have.
     */
    pluginCommands?: PrivCommand[];
    /**
     * The sudo capabilities the access provisioning grants (capabilitiesFor()): with
     * pluginCommands, the required set our sudoers file is compared with. None when absent.
     */
    sudo?: { osUpgrade: boolean; reboot: boolean };
    /**
     * The Proxmox API tokens this machine uses, one entry per node model: the one behind
     * its snapshots (vm.proxmoxNode or ct.nodeModel) and the ones its proxmox-cluster
     * health checks read through, each with its permissions answer. None when the machine
     * uses no node model.
     */
    apiTokens?: ApiTokenInput[];
  };
  now: Date;
}

export interface AuditResult {
  findings: Finding[];
  acceptedRisks: Array<Finding & { record: AcceptanceRecordT }>;
  summary: Record<Severity, number> & { accepted: number; overdue: number };
}

const Mode = z.string().regex(/^[0-7]{3,4}$/);
const Sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const Owned = z.object({
  owner: z.string(),
  group: z.string(),
  mode: Mode,
}).strict();
type OwnedT = z.infer<typeof Owned>;

const UserProbe = z.object({
  _kind: z.literal("patch-access-user-probe"),
  user: z.string(),
  uid: z.number().int().min(0).nullable(),
  groups: z.array(z.string()),
  sudoList: z.object({
    rc: z.number().int().min(0),
    out: z.string(),
  }).strict().nullable(),
  sudoTrueRc: z.number().int().min(0).nullable(),
  dockerRc: z.number().int().min(0).nullable(),
  canWrite: z.object({
    authorizedKeys: z.boolean(),
    sshDir: z.boolean(),
    marker: z.boolean(),
    stateDir: z.boolean(),
    libexec: z.boolean(),
    dockerProducer: z.boolean(),
    sudoersDir: z.boolean(),
    unitService: z.boolean(),
    unitTimer: z.boolean(),
    aptConf: z.boolean(),
    apkPeriodic: z.boolean(),
    aptAuto: z.boolean(),
    dnfAutoConf: z.boolean(),
    dnfAutoDropIn: z.boolean(),
    dockerHelper: z.boolean(),
    dockerProjects: z.boolean(),
  }).strict(),
}).strict();

const Members = z.array(z.string());
const RootProbe = z.object({
  _kind: z.literal("patch-access-root-probe"),
  account: z.object({
    exists: z.boolean(),
    markerOk: z.boolean(),
    shadowLocked: z.boolean().nullable(),
    shell: z.string().nullable(),
    gecos: z.string().nullable(),
  }).strict(),
  groupsOfUser: z.array(z.string()),
  authorizedKeys: z.object({
    lines: z.array(z.string()).max(20),
    total: z.number().int().min(0),
    file: Owned.nullable(),
    dir: Owned.nullable(),
    home: Owned.nullable(),
  }).strict(),
  rootHasKey: z.boolean(),
  managedFiles: z.array(
    z.object({
      path: z.string(),
      exists: z.boolean(),
      owner: z.string().nullable(),
      group: z.string().nullable(),
      mode: Mode.nullable(),
      sha256: Sha256.nullable(),
      hasManagedHeader: z.boolean(),
    }).strict(),
  ),
  dirs: z.object({
    stateDir: Owned.nullable(),
    libexec: Owned.nullable(),
    sudoersDir: Owned.nullable(),
    systemdDir: Owned.nullable(),
    projectsDir: Owned.nullable(),
  }).strict(),
  sudoRules: z.array(
    z.object({
      file: z.string(),
      lines: z.array(z.string()).max(10),
    }).strict(),
  ),
  cache: z.object({
    family: z.enum(["pve", "apt", "dnf", "apk", "unknown"]),
    refreshOn: z.boolean(),
    ageHours: z.number().int().min(0).nullable(),
    autoInstall: z.boolean(),
    autoScope: z.enum(OS_AUTO_SCOPES).nullable(),
  }).strict(),
  hostGroups: z.object({
    docker: Members,
    wheel: Members,
    sudo: Members,
    admin: Members,
    adm: Members,
    lxd: Members,
    disk: Members,
  }).strict(),
  dockerSocket: Owned.nullable(),
  sudoersFile: z.object({
    exists: z.boolean(),
    lines: z.array(z.string()).max(128),
    total: z.number().int().min(0),
  }).strict(),
  sudoFamilies: z.array(z.enum(["apt", "dnf", "apk", "pacman", "systemd"])),
  compose: z.array(
    z.object({
      name: z.string(),
      dir: z.string(),
      realDir: z.string(),
      owned: Owned.nullable(),
      chain: z.array(
        z.object({ path: z.string(), owned: Owned.nullable() }).strict(),
      ),
      scanOk: z.boolean(),
      unsafe: z.array(z.string()).max(10),
      unsafeTotal: z.number().int().min(0),
    }).strict(),
  ).max(20),
}).strict();
type RootProbeT = z.infer<typeof RootProbe>;

type Add = (id: string, severity: Severity, message: string) => void;

function clip(s: string): string {
  const one = s.replace(/\s+/g, " ").trim();
  return one.length > 200 ? `${one.slice(0, 200)}...` : one;
}

/**
 * Parse one probe. A probe that did not run, or that reports an error, gives probe-failed.
 * Output that does not match its schema gives probe-invalid. Either way it gives null, and
 * nothing is derived from it.
 */
function readProbe<T extends z.ZodType>(
  schema: T,
  which: "user" | "root",
  raw: unknown,
  error: string | null,
  add: Add,
): z.infer<T> | null {
  if (raw === null || raw === undefined || error) {
    const why = error ? clip(error) : "it returned no output";
    add(
      `probe-failed:${which}`,
      "high",
      `the ${which} probe did not run: ${why}`,
    );
    return null;
  }
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    add(
      `probe-invalid:${which}`,
      "high",
      `the ${which} probe output does not match its expected shape`,
    );
    return null;
  }
  return parsed.data as z.infer<T>;
}

/** The low two octal digits are group and other: true when either can write. */
function groupOrOtherWritable(mode: string): boolean {
  const [group, other] = mode.slice(-2).split("").map(Number);
  return ((group & 2) | (other & 2)) !== 0;
}

function unsafeOwned(o: { owner: string; mode: string }): boolean {
  return o.owner !== "root" || groupOrOtherWritable(o.mode);
}

/** A from= entry broader than /24 (IPv4) or /64 (IPv6). A bare address is narrow. */
function broadSource(from: string): boolean {
  const [addr, len] = from.split("/");
  if (len === undefined) return false;
  const bits = Number(len);
  return addr.includes(":") ? bits < 64 : bits < 24;
}

/**
 * True when a line carries the access key and lacks from= or one of the four no-* options.
 * The options are the tokens before the key type, which sits just before the key blob.
 */
function unrestrictedKeyLine(line: string, blob: string): boolean {
  const tokens = line.trim().split(/\s+/);
  const at = tokens.indexOf(blob);
  if (at === -1) return false;
  const opts = tokens.slice(0, Math.max(0, at - 1)).join(" ");
  const hasFrom = /(^|[ ,])from="[^"]+"/.test(opts);
  const hasNoOpts = [
    "no-port-forwarding",
    "no-agent-forwarding",
    "no-X11-forwarding",
    "no-pty",
  ].every((o) => new RegExp(`(^|[ ,])${o}($|[ ,])`).test(opts));
  return !(hasFrom && hasNoOpts);
}

/**
 * True when `path` is what the provision script may write for the name `name`: the name
 * itself when it is absolute, else a plain absolute path whose last segment is the name
 * (what `command -v` prints). No `.` or `..` segment, no `//`, no trailing `/`.
 */
function grantedPath(name: string, path: string): boolean {
  if (
    path.includes("//") || path.endsWith("/") || /(^|\/)\.\.?(\/|$)/.test(path)
  ) {
    return false;
  }
  return name.startsWith("/") ? path === name : path.split("/").pop() === name;
}

/**
 * A test for the command text of one sudoers entry: the template (sudoersTemplate) with each
 * `@name@` filled in by an absolute path that grantedPath accepts, the same path for every
 * place the same name stands. Every other character must be the template's own.
 */
function templateMatcher(template: string): (text: string) => boolean {
  const parts = template.split(/@([^@\s]+)@/);
  const names: string[] = [];
  let src = "^";
  parts.forEach((part, k) => {
    if (k % 2 === 0) {
      src += part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    } else {
      names.push(part);
      src += "(/[A-Za-z0-9._/+-]+)";
    }
  });
  const re = new RegExp(`${src}$`);
  return (text) => {
    const m = re.exec(text);
    if (!m) return false;
    const seen = new Map<string, string>();
    return names.every((name, k) => {
      const path = m[k + 1];
      const before = seen.get(name);
      if (before !== undefined && before !== path) return false;
      seen.set(name, path);
      return grantedPath(name, path);
    });
  };
}

/** One entry of the required set, and what cannot run without it. */
interface RequiredGrant {
  id: string;
  /** Only needed when the root probe found this family on the host; null: always needed. */
  family: string | null;
  blocks: string;
  matches: (text: string) => boolean;
}

/**
 * The sudoers entries this machine may have: the table entries for its capabilities, the
 * docker helper when it has docker, and the plugged models' declared commands.
 */
function requiredGrants(i: AuditInput): RequiredGrant[] {
  const caps = i.machine.sudo ?? { osUpgrade: false, reboot: false };
  const commands = requiredCommands(caps).map((c): RequiredGrant => ({
    id: c.id,
    family: c.family,
    blocks: c.capability === "reboot"
      ? "safeOsUpdate cannot reboot"
      : "safeOsUpdate cannot update the OS",
    matches: templateMatcher(sudoersTemplate(c)),
  }));
  const helpers = requiredHelpers({ docker: i.docker }).map((
    g,
  ): RequiredGrant => ({
    id: g.id,
    family: null,
    blocks: "safeUpdate and pruneImages cannot run",
    matches: (text) => text === g.path,
  }));
  const plugins = (i.machine.pluginCommands ?? []).map((c): RequiredGrant => ({
    id: c.id,
    family: null,
    blocks:
      "the command fails (a plugged model's, or a privileged health check's)",
    matches: templateMatcher(sudoersTemplate(c)),
  }));
  return [...commands, ...helpers, ...plugins];
}

/**
 * Compare our sudoers file with the required set. Each line must be one of the two Defaults
 * lines or the grant of a required entry; any other line is privilege-extra (critical). A
 * required entry of a family the host has (or with no family) and no line is
 * privilege-missing, which names what cannot run. The two Defaults lines must be there when
 * any grant is.
 */
function checkGrants(i: AuditInput, rp: RootProbeT, add: Add): void {
  const required = requiredGrants(i);
  const prefix = `${i.user} ALL=(root) NOPASSWD: `;
  const defaults = [
    `Defaults:${i.user} env_reset`,
    `Defaults:${i.user} !setenv`,
  ];
  const file = rp.sudoersFile;
  const present = new Set<string>();
  let grants = 0;
  for (const line of file.lines) {
    if (defaults.includes(line)) continue;
    const text = line.startsWith(prefix) ? line.slice(prefix.length) : null;
    const hit = text === null
      ? undefined
      : required.find((r) => r.matches(text));
    if (hit) {
      present.add(hit.id);
      grants += 1;
      continue;
    }
    // The whole line is the id (the probe sends at most 1000 printable characters), so two
    // lines with the same start stay two findings.
    add(
      `privilege-extra:${line}`,
      "critical",
      `${PATHS.sudoers} has a line that is not in the required set: ${
        clip(line)
      }`,
    );
  }
  if (file.total > file.lines.length) {
    add(
      "privilege-extra:unread",
      "critical",
      `${PATHS.sudoers} has ${file.total} lines; only ${file.lines.length} were read`,
    );
  }
  if (grants > 0 && !defaults.every((d) => file.lines.includes(d))) {
    add(
      "privilege-defaults-missing",
      "high",
      `${PATHS.sudoers} grants commands without both Defaults lines (env_reset, !setenv)`,
    );
  }
  const families = new Set<string>(rp.sudoFamilies);
  for (const r of required) {
    if (present.has(r.id)) continue;
    if (r.family !== null && !families.has(r.family)) continue;
    add(
      `privilege-missing:${r.id}`,
      "warning",
      `${PATHS.sudoers} has no grant for ${r.id}: ${r.blocks}`,
    );
  }
}

/**
 * The docker helper runs each listed compose project as root. A non-root account that can
 * change the project directory, an entry in it, or a directory above it can change what root
 * runs: compose-writable (high). A directory that is missing is compose-missing (warning); a
 * directory the probe could not scan is compose-unreadable (high).
 */
function checkCompose(rp: RootProbeT, add: Add): void {
  for (const c of rp.compose) {
    if (c.owned === null) {
      add(
        `compose-missing:${c.dir}`,
        "warning",
        `the docker project ${c.name} lists ${c.dir}, which does not exist`,
      );
      continue;
    }
    if (!c.scanOk) {
      add(
        `compose-unreadable:${c.dir}`,
        "high",
        `the probe could not read the entries of ${c.realDir}`,
      );
    }
    const open = [
      ...c.chain.filter((d) => d.owned !== null && unsafeOwned(d.owned)).map((
        d,
      ) => d.path),
      ...(unsafeOwned(c.owned) ? [c.realDir] : []),
      ...c.unsafe.map((name) => `${c.realDir}/${name}`),
    ];
    if (open.length > 0 || c.unsafeTotal > 0) {
      const more = c.unsafeTotal > c.unsafe.length
        ? ` and ${c.unsafeTotal - c.unsafe.length} more`
        : "";
      add(
        `compose-writable:${c.dir}`,
        "high",
        `the docker helper runs ${c.dir} as root, but an account other than root can change ${
          open.join(", ")
        }${more}`,
      );
    }
  }
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * The sha256 of each managed file the generators write. Marker and sudoers have none. The
 * auto-update files are expected only for a machine whose scope is set: a managed machine
 * has none, so none is compared (auto-install-conflict covers a leftover that installs).
 */
async function expectedDigests(
  autoScope: OsAutoScope | null,
  docker: boolean,
  projects: DockerProject[],
): Promise<Record<string, string>> {
  const texts: Record<string, string> = {
    [PATHS.aptConf]: aptPeriodicConf(),
    [PATHS.apkPeriodic]: apkPeriodicScript(),
    [PATHS.dockerProducer]: dockerProducerScript(),
    [PATHS.dockerHelper]: dockerHelperScript(MANAGED_HEADER),
    [PATHS.unitService]: dockerTimerUnits().service,
    [PATHS.unitTimer]: dockerTimerUnits().timer,
  };
  if (docker) {
    texts[PATHS.dockerProjects] = dockerProjectsFile(projects, MANAGED_HEADER);
  }
  if (autoScope !== null) {
    texts[PATHS.aptAuto] = aptAutoConf(autoScope);
    texts[PATHS.dnfAutoConf] = dnfAutomaticConf(autoScope);
    texts[PATHS.dnfAutoDropIn] = dnfAutoDropInUnit();
  }
  const out: Record<string, string> = {};
  for (const [path, text] of Object.entries(texts)) {
    out[path] = await sha256Hex(text);
  }
  return out;
}

/**
 * Turn the two probes into findings, then match the machine's accepted risks. The probes
 * are parsed here, so the caller passes raw JSON. The expected digests use crypto.subtle,
 * which is why this is async. The result is deterministic for the same input.
 *
 * An accepted risk whose `finding` equals a produced finding id moves that finding to
 * `acceptedRisks`, keeping its severity. A second record for the same id is redundant and
 * is ignored. A record that matches no finding is reported as acceptance-stale, unless a
 * probe failed or was invalid: the host state is unknown then, so the record may match a
 * finding that the missing probe would have produced.
 */
export async function evaluateAudit(i: AuditInput): Promise<AuditResult> {
  const found = new Map<string, Finding>();
  const add: Add = (id, severity, message) => {
    if (!found.has(id)) found.set(id, { id, severity, message });
  };

  for (const f of i.from) {
    if (broadSource(f)) {
      add(
        `from-broad:${f}`,
        "high",
        `from entry ${f} is broader than /24 (IPv4) or /64 (IPv6)`,
      );
    }
  }

  const up = readProbe(UserProbe, "user", i.userProbe, i.userProbeError, add);
  const rp = readProbe(RootProbe, "root", i.rootProbe, i.rootProbeError, add);
  const digests = await expectedDigests(
    i.machine.autoUpdates ?? null,
    i.docker,
    i.machine.dockerProjects ?? [],
  );

  if (up) {
    if (up.uid === 0) {
      add(
        "login-is-root",
        "critical",
        `the user probe ran as uid 0 (${up.user}), not as the patch login ${i.user}`,
      );
    } else if (up.user !== i.user) {
      add(
        "probe-wrong-user",
        "high",
        `the user probe ran as ${up.user}, not as the patch login ${i.user}`,
      );
    }
    if (up.dockerRc === 0) {
      add(
        "docker-socket-access",
        "critical",
        "the patch login runs docker info, so it can reach the docker socket",
      );
    }
    // No required entry is `true`: a login that runs it as root has a grant beyond the set.
    // The grants themselves are compared with the required set in checkGrants.
    if (up.sudoTrueRc === 0) {
      add(
        "privilege-unrestricted",
        "critical",
        "the patch login runs sudo -n true, so its grants go beyond the required set",
      );
    }
    if (up.canWrite.authorizedKeys || up.canWrite.sshDir) {
      add(
        "authorized-keys-writable",
        "critical",
        `the patch login can write ${AUTH_KEYS_PATH} or its directory`,
      );
    }
    const userWrites: Array<[boolean, string]> = [
      [up.canWrite.marker, PATHS.marker],
      [up.canWrite.stateDir, PATHS.stateDir],
      [up.canWrite.libexec, PATHS.libexec],
      [up.canWrite.dockerProducer, PATHS.dockerProducer],
      [up.canWrite.sudoersDir, SUDOERS_DIR],
      [up.canWrite.unitService, PATHS.unitService],
      [up.canWrite.unitTimer, PATHS.unitTimer],
      [up.canWrite.aptConf, PATHS.aptConf],
      [up.canWrite.apkPeriodic, PATHS.apkPeriodic],
      [up.canWrite.aptAuto, PATHS.aptAuto],
      [up.canWrite.dnfAutoConf, PATHS.dnfAutoConf],
      [up.canWrite.dnfAutoDropIn, PATHS.dnfAutoDropIn],
      [up.canWrite.dockerHelper, PATHS.dockerHelper],
      [up.canWrite.dockerProjects, PATHS.dockerProjects],
    ];
    for (const [can, path] of userWrites) {
      if (can) {
        add(
          `managed-file-writable:${path}`,
          "critical",
          `the patch login can write ${path}`,
        );
      }
    }
  }

  // Group membership comes from either probe that ran. Both name the same account.
  const groups = new Set<string>([
    ...(up?.groups ?? []),
    ...(rp?.groupsOfUser ?? []),
  ]);
  for (const g of ROOT_GROUPS) {
    if (groups.has(g)) {
      add(
        `group-root-equivalent:${g}`,
        g === "adm" ? "high" : "critical",
        `the patch login is in group ${g}, which is root-equivalent on this host`,
      );
    }
  }

  if (rp) {
    const acct = rp.account;
    if (!acct.exists) {
      add(
        "account-missing",
        "high",
        `the account ${i.user} does not exist on this host`,
      );
    } else {
      if (!acct.markerOk) {
        add(
          "account-not-managed",
          "high",
          `the account ${i.user} exists but its marker or GECOS token does not match @dmc/patch`,
        );
      }
      if (acct.shadowLocked === false) {
        add(
          "password-not-locked",
          "high",
          `the password of ${i.user} is not locked`,
        );
      }
    }

    const expected = authorizedKeysLine(i.publicKey, i.from);
    const blob = i.publicKey.split(" ")[1];
    const lines = rp.authorizedKeys.lines;
    if (!lines.includes(expected)) {
      add(
        "key-missing",
        "high",
        `${AUTH_KEYS_PATH} has no line for the access key`,
      );
    }
    const others = lines.filter((l) => l !== expected).length +
      (rp.authorizedKeys.total - lines.length);
    if (others > 0) {
      add(
        "authorized-keys-extra",
        "high",
        `${AUTH_KEYS_PATH} has ${others} line(s) other than the access key line`,
      );
    }
    if (lines.some((l) => unrestrictedKeyLine(l, blob))) {
      add(
        "authorized-keys-unrestricted",
        "high",
        `a line in ${AUTH_KEYS_PATH} for the access key has no from= or lacks a no-* option`,
      );
    }
    const ak = rp.authorizedKeys;
    const akOwned: Array<[OwnedT | null, string]> = [
      [ak.file, AUTH_KEYS_PATH],
      [ak.dir, SSH_DIR],
      [ak.home, PATHS.home],
    ];
    for (const [o, path] of akOwned) {
      if (o !== null && unsafeOwned(o)) {
        add(
          "authorized-keys-writable",
          "critical",
          `${path} is not owned by root or is writable by its group or others`,
        );
      }
    }

    if (rp.rootHasKey) {
      add(
        "root-accepts-key",
        "critical",
        "root's authorized_keys accepts the access key",
      );
    }

    for (const m of rp.managedFiles) {
      if (!m.exists || m.owner === null || m.mode === null) continue;
      if (unsafeOwned({ owner: m.owner, mode: m.mode })) {
        add(
          `managed-file-writable:${m.path}`,
          "critical",
          `${m.path} is not owned by root or is writable by its group or others`,
        );
      }
      const want: string | undefined = digests[m.path];
      if (want !== undefined && m.sha256 !== null && m.sha256 !== want) {
        add(
          `managed-file-drift:${m.path}`,
          "high",
          `${m.path} differs from the content @dmc/patch writes`,
        );
      }
    }
    const dirs: Array<[OwnedT | null, string]> = [
      [rp.dirs.stateDir, PATHS.stateDir],
      [rp.dirs.libexec, PATHS.libexec],
      [rp.dirs.sudoersDir, SUDOERS_DIR],
      [rp.dirs.systemdDir, SYSTEMD_DIR],
      [rp.dirs.projectsDir, PATHS.projectsDir],
    ];
    for (const [o, path] of dirs) {
      if (o !== null && unsafeOwned(o)) {
        add(
          `managed-file-writable:${path}`,
          "critical",
          `${path} is not owned by root or is writable by its group or others`,
        );
      }
    }

    if (i.docker) {
      const producer = rp.managedFiles.find((m) =>
        m.path === PATHS.dockerProducer
      );
      const timer = rp.managedFiles.find((m) => m.path === PATHS.unitTimer);
      if (!producer?.exists || !timer?.exists) {
        add(
          "docker-producer-missing",
          "warning",
          `docker is wanted, but ${PATHS.dockerProducer} or ${PATHS.unitTimer} is missing`,
        );
      }
      const helper = rp.managedFiles.find((m) => m.path === PATHS.dockerHelper);
      const projects = rp.managedFiles.find((m) =>
        m.path === PATHS.dockerProjects
      );
      if (!helper?.exists || !projects?.exists) {
        add(
          "docker-helper-missing",
          "warning",
          `docker is wanted, but ${PATHS.dockerHelper} or ${PATHS.dockerProjects} is missing: safeUpdate and pruneImages cannot run`,
        );
      }
    }

    for (const g of HOST_GROUPS) {
      for (const member of rp.hostGroups[g]) {
        if (member !== i.user && member !== "root") {
          add(
            `host-group:${g}:${member}`,
            "info",
            `${member} is in group ${g} on this host`,
          );
        }
      }
    }

    // Rules in any file but ours (the probe leaves ours out; checkGrants compares it).
    for (const r of rp.sudoRules) {
      const broad = r.lines.some((l) =>
        /(^|[^A-Za-z0-9_])ALL([^A-Za-z0-9_]|$)/.test(l)
      );
      add(
        `privilege-foreign:${r.file}`,
        broad ? "critical" : "high",
        `${r.file} has a rule that names the patch login or one of its groups`,
      );
    }
    checkGrants(i, rp, add);
    checkCompose(rp, add);
    // sudo lists grants, but no sudoers file shows one: they come from elsewhere (LDAP, sssd).
    if (
      up !== null && up.sudoList !== null && up.sudoList.rc === 0 &&
      /may run/.test(up.sudoList.out) && rp.sudoersFile.lines.length === 0 &&
      rp.sudoRules.length === 0
    ) {
      add(
        "privilege-foreign:sudo-list",
        "high",
        "sudo -l lists grants for the patch login, but no sudoers file on the host has one",
      );
    }

    if (rp.cache.refreshOn === false) {
      add(
        "cache-refresh-off",
        "warning",
        `the package cache is not refreshed by a local timer (family ${rp.cache.family})`,
      );
    }
    if (rp.cache.ageHours !== null && rp.cache.ageHours > 48) {
      add(
        "cache-stale",
        "warning",
        `the package cache is ${rp.cache.ageHours} hours old`,
      );
    }
    if (rp.cache.autoInstall && i.machine.osUpdatePolicy !== "auto") {
      add(
        "auto-install-conflict",
        "warning",
        "unattended updates install on their own, but the OS update policy is not auto",
      );
    }
    if (i.machine.osUpdatePolicy === "auto" && !rp.cache.autoInstall) {
      add(
        "auto-install-off",
        "warning",
        "the OS update policy is auto, but the host does not install updates on its own",
      );
    }
    const wantScope = i.machine.autoUpdates ?? null;
    if (
      wantScope !== null && rp.cache.autoScope !== null &&
      rp.cache.autoScope !== wantScope
    ) {
      add(
        "auto-scope-mismatch",
        "warning",
        `the auto-update file installs ${rp.cache.autoScope} updates, but this machine's auto scope is ${wantScope}`,
      );
    }
  }

  for (const t of i.machine.apiTokens ?? []) auditApiToken(t, add);

  // Accepted risks. The catalog ids are fixed before any move, so a record is matched only
  // against findings the probes produced.
  const catalogIds = new Set(found.keys());
  const accepted: AuditResult["acceptedRisks"] = [];
  let overdueCount = 0;
  const flagOverdue = (id: string, rec: { reviewBy: string }) => {
    if (isOverdue(rec, i.now)) {
      overdueCount += 1;
      add(
        `acceptance-overdue:${id}`,
        "warning",
        `the accepted risk ${id} is past its review date`,
      );
    }
  };

  for (const key of UNSAFE_KEYS) {
    const rec = i.machine.unsafe?.[key];
    if (!rec) continue;
    const id = `unsafe:${key}`;
    accepted.push({
      id,
      severity: "warning",
      message: `the unsafe path ${key} is enabled for this machine`,
      record: rec,
    });
    flagOverdue(id, rec);
  }

  for (const t of i.machine.trustRemote ?? []) {
    const id = `trust-remote:${t.source}`;
    accepted.push({
      id,
      severity: "info",
      message:
        `code fetched from ${t.source} at run time is trusted for this machine`,
      record: t,
    });
    flagOverdue(id, t);
  }

  // A record is stale only when both probes ran: a failed or invalid probe leaves the host
  // state unknown, so no verdict is given on the record.
  const complete = up !== null && rp !== null;
  for (const r of i.machine.acceptedRisks ?? []) {
    if (catalogIds.has(r.finding)) {
      const f = found.get(r.finding);
      if (f) {
        found.delete(r.finding);
        accepted.push({ ...f, record: r });
      }
    } else if (complete) {
      add(
        `acceptance-stale:${r.finding}`,
        "info",
        `the accepted risk ${r.finding} matches no finding`,
      );
    }
    flagOverdue(r.finding, r);
  }

  const findings = [...found.values()];
  const summary: AuditResult["summary"] = {
    critical: 0,
    high: 0,
    warning: 0,
    info: 0,
    accepted: accepted.length,
    overdue: overdueCount,
  };
  for (const f of findings) summary[f.severity] += 1;
  return { findings, acceptedRisks: accepted, summary };
}
