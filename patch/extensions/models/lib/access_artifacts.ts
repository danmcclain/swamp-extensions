/**
 * Generators for the root-side artifacts of the swamp-patch access login.
 *
 * Every function here returns TEXT. Nothing is run and nothing is written. The
 * provisioning model installs the scripts on a host, and they run as root there.
 *
 * Two rules keep the output safe. First, every input is validated again here, even
 * though the schemas already checked it. Second, every value that reaches a script is
 * single-quoted with shQuote, and inside the scripts the inputs are used only through
 * double-quoted shell variables. No input reaches a script in any other way.
 *
 * @module
 */
import { AccessProfile, isSourceAddr } from "./access_policy.ts";
import { OS_AUTO_SCOPES } from "./os_policy.ts";
import type { OsAutoScope } from "./os_policy.ts";
import {
  FAMILY_PROBES,
  grantNames,
  requiredCommands,
  requiredHelpers,
  sudoersTemplate,
} from "./access_sudoers.ts";
import type { PrivCommand } from "./access_sudoers.ts";
import {
  pluginDeniedShellFn,
  validatePluginCommands,
} from "./plugin_privileges.ts";
import {
  DOCKER_HELPER_PATH,
  DOCKER_PROJECTS_DIR,
  DOCKER_PROJECTS_PATH,
  dockerHelperScript,
  dockerProjectsFile,
  validateDockerProjects,
} from "./docker_helper.ts";
import type { DockerProject } from "./docker_helper.ts";

/** The header of every file this module writes. Revoke removes only files that carry it. */
export const MANAGED_HEADER =
  "# Managed by @dmc/patch (swamp-patch access). Do not edit; re-run provisionAccess.";

/** Fixed locations on the host. */
export const PATHS = {
  stateDir: "/var/lib/swamp-patch",
  home: "/var/lib/swamp-patch/home",
  marker: "/var/lib/swamp-patch/managed-user",
  dockerInventory: "/var/lib/swamp-patch/docker-inventory.json",
  libexec: "/usr/local/libexec/swamp-patch",
  dockerProducer: "/usr/local/libexec/swamp-patch/docker-inventory",
  /** The root-owned helper that the login runs through sudo for every docker call (docker_helper.ts). */
  dockerHelper: DOCKER_HELPER_PATH,
  /** The project list the helper reads, and the directory it must sit in. */
  dockerProjects: DOCKER_PROJECTS_PATH,
  projectsDir: DOCKER_PROJECTS_DIR,
  aptConf: "/etc/apt/apt.conf.d/20swamp-patch",
  apkPeriodic: "/etc/periodic/daily/swamp-patch-apk-update",
  sudoers: "/etc/sudoers.d/swamp-patch",
  unitService: "/etc/systemd/system/swamp-patch-docker-inventory.service",
  unitTimer: "/etc/systemd/system/swamp-patch-docker-inventory.timer",
  /** Auto OS updates (apt): the unattended-upgrades origins. Sorts after 50unattended-upgrades. */
  aptAuto: "/etc/apt/apt.conf.d/52swamp-patch-auto",
  /** Auto OS updates (dnf): our own dnf-automatic config. The package's config is never touched. */
  dnfAutoConf: "/etc/dnf/swamp-patch-automatic.conf",
  /** Auto OS updates (dnf): the drop-in that points dnf-automatic.service at dnfAutoConf. */
  dnfAutoDropIn:
    "/etc/systemd/system/dnf-automatic.service.d/50-swamp-patch.conf",
} as const;

/** POSIX single-quoting: the result is one shell word that expands to `s` exactly. */
export function shQuote(s: string): string {
  if (/[\0\n\r]/.test(s)) {
    throw new Error(
      "a shell value must not contain NUL, newline or carriage return",
    );
  }
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/**
 * The authorized_keys line for the access key: the source addresses, then the options
 * that turn off forwarding, a pty and the user rc, then the one key.
 */
export function authorizedKeysLine(publicKey: string, from: string[]): string {
  if (
    typeof publicKey !== "string" ||
    !AccessProfile.shape.publicKey.safeParse(publicKey).success
  ) {
    throw new Error("the access key must be one ed25519 public key");
  }
  if (
    !Array.isArray(from) || from.length === 0 ||
    !from.every((a) => typeof a === "string" && isSourceAddr(a))
  ) {
    throw new Error(
      "from must list one or more IP addresses or CIDR ranges (not /0)",
    );
  }
  return `from="${
    from.join(",")
  }",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc ${publicKey}`;
}

/**
 * What provisionAccess asks for: the login, its one key, where it may log in from, docker,
 * and the OS auto-update scope. `autoUpdates` is what the host's own updater installs
 * (security or all), or null when @dmc/patch manages the OS updates itself. It comes from
 * capabilitiesFor, so it is the one place the policy is read.
 */
export interface ProvisionInput {
  user: string;
  publicKey: string;
  from: string[];
  docker: boolean;
  autoUpdates: OsAutoScope | null;
  /**
   * Which privileged commands the login needs (see access_sudoers.ts). `osUpgrade` is the
   * managed upgrade, `reboot` every policy but scan-only, `docker` the helper (docker machines
   * only, whatever the OS policy). All false grants nothing. `docker` must equal `docker` above.
   * `extra` is what the machine's plugged models declare (lib/plugin_privileges.ts); absent or
   * empty grants nothing more. Every entry is validated again here: the provisioner does not
   * trust its caller either.
   */
  sudo: {
    osUpgrade: boolean;
    reboot: boolean;
    docker: boolean;
    extra?: PrivCommand[];
  };
  /**
   * The compose projects the docker helper may run on this host: one per machine with a
   * compose directory, and none otherwise. Must be empty when `docker` is false.
   */
  dockerProjects: DockerProject[];
}

function checkUser(user: unknown): string {
  if (
    typeof user !== "string" ||
    !AccessProfile.shape.user.safeParse(user).success
  ) {
    throw new Error(
      "the access user must be 1-32 characters of a-z, 0-9, _ or -, start with a-z or _, and not be root or toor",
    );
  }
  return user;
}

/** Check every field again, then return a copy. Throws on the first problem. */
export function validateProvisionInput(i: ProvisionInput): ProvisionInput {
  checkUser(i.user);
  authorizedKeysLine(i.publicKey, i.from);
  if (typeof i.docker !== "boolean") {
    throw new Error("docker must be true or false");
  }
  if (
    i.autoUpdates !== null &&
    !(OS_AUTO_SCOPES as readonly unknown[]).includes(i.autoUpdates)
  ) {
    throw new Error('autoUpdates must be null, "security" or "all"');
  }
  if (
    typeof i.sudo !== "object" || i.sudo === null ||
    typeof i.sudo.osUpgrade !== "boolean" ||
    typeof i.sudo.reboot !== "boolean" ||
    typeof i.sudo.docker !== "boolean"
  ) {
    throw new Error(
      "sudo must be { osUpgrade, reboot, docker } with true or false",
    );
  }
  if (i.sudo.docker !== i.docker) {
    throw new Error("sudo.docker must equal docker");
  }
  const extra = validatePluginCommands(i.sudo.extra ?? []);
  const dockerProjects = validateDockerProjects(i.dockerProjects);
  if (!i.docker && dockerProjects.length > 0) {
    throw new Error("dockerProjects must be empty when docker is false");
  }
  return {
    user: i.user,
    publicKey: i.publicKey,
    from: [...i.from],
    docker: i.docker,
    autoUpdates: i.autoUpdates,
    sudo: {
      osUpgrade: i.sudo.osUpgrade,
      reboot: i.sudo.reboot,
      docker: i.sudo.docker,
      extra,
    },
    dockerProjects,
  };
}

/** apt: refresh the package lists daily. Metadata only; never unattended upgrades. */
export function aptPeriodicConf(): string {
  return `${MANAGED_HEADER}\nAPT::Periodic::Update-Package-Lists "1";\n`;
}

/** apk: refresh the index daily from the periodic directory. Metadata only. */
export function apkPeriodicScript(): string {
  return `#!/bin/sh\n${MANAGED_HEADER}\napk update -q >/dev/null 2>&1\n`;
}

/**
 * apt, auto: the host's unattended-upgrades install these origins. The #clear lines drop the
 * package's own lists (50unattended-upgrades is read first), so exactly these origins apply.
 * `security` is the security suites; `all` adds the base and -updates suites. The
 * ${distro_id} and ${distro_codename} are unattended-upgrades variables: they must reach the
 * file as written, so these strings are plain text, never template-expanded here.
 */
export function aptAutoConf(scope: OsAutoScope): string {
  const origins = [
    "origin=${distro_id},codename=${distro_codename}-security",
    "origin=${distro_id},archive=${distro_codename}-security",
  ];
  if (scope === "all") {
    origins.push(
      "origin=${distro_id},codename=${distro_codename}",
      "origin=${distro_id},archive=${distro_codename}",
      "origin=${distro_id},codename=${distro_codename}-updates",
      "origin=${distro_id},archive=${distro_codename}-updates",
    );
  }
  return `${MANAGED_HEADER}
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "false";
#clear Unattended-Upgrade::Origins-Pattern;
#clear Unattended-Upgrade::Allowed-Origins;
Unattended-Upgrade::Origins-Pattern {
${origins.map((o) => `  "${o}";`).join("\n")}
};
`;
}

/**
 * dnf, auto: a complete dnf-automatic config of our own. `security` installs security
 * updates only; `all` installs every update (upgrade_type default). Downloads and applies
 * them, and never reboots: a reboot stays with @dmc/patch.
 */
export function dnfAutomaticConf(scope: OsAutoScope): string {
  return `${MANAGED_HEADER}
[commands]
upgrade_type = ${scope === "all" ? "default" : "security"}
download_updates = yes
apply_updates = yes
reboot = never

[emitters]
emit_via = stdio

[base]
debuglevel = 1
`;
}

/** dnf, auto: the drop-in that makes dnf-automatic.service read our config, not the package's. */
export function dnfAutoDropInUnit(): string {
  return `${MANAGED_HEADER}
[Service]
ExecStart=
ExecStart=/usr/bin/dnf-automatic ${PATHS.dnfAutoConf} --timer
`;
}

const HEREDOC = "SWAMP_PATCH_EOF";

/** One bash block that writes `content` to the path held in `$destVar`, from a quoted heredoc. */
function installBlock(destVar: string, mode: string, content: string): string {
  if (content.includes(HEREDOC)) {
    throw new Error(`embedded file content must not contain ${HEREDOC}`);
  }
  const body = content.endsWith("\n") ? content : `${content}\n`;
  return `install_file "$${destVar}" ${mode} <<'${HEREDOC}'\n${body}${HEREDOC}\n`;
}

/** The fixed paths and the managed header, each as a shell-quoted variable. */
function constantsBlock(): string {
  const vars: [string, string][] = [
    ["MANAGED", MANAGED_HEADER],
    ["STATE_DIR", PATHS.stateDir],
    ["HOME_DIR", PATHS.home],
    ["MARKER", PATHS.marker],
    ["DOCKER_INVENTORY", PATHS.dockerInventory],
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
  ];
  return vars.map(([name, value]) => `${name}=${shQuote(value)}\n`).join("");
}

/**
 * The root-run producer for the docker inventory. It writes `outPath` atomically (a
 * temp file in the same directory, then mv), in the DockerInventoryFile format. Docker
 * absent or `docker info` failing gives a null engine and no images. Stops at 500 items.
 * The path is fixed in production; the parameter exists so tests can write elsewhere.
 */
export function dockerProducerScript(
  outPath: string = PATHS.dockerInventory,
): string {
  if (!/^\/[A-Za-z0-9._\/-]+$/.test(outPath)) {
    throw new Error(
      "the docker inventory path may contain only A-Z a-z 0-9 . _ / -",
    );
  }
  return `#!/usr/bin/env bash
${MANAGED_HEADER}
# Writes the docker inventory that the patch collector reads. Runs as root from a
# systemd timer. It takes no arguments and no environment input.
set -u
umask 022

OUT=${shQuote(outPath)}

# Minimal JSON string escaper (backslash, double-quote, strip control chars).
jesc() { printf '%s' "\${1-}" | sed -e 's/\\\\/\\\\\\\\/g' -e 's/"/\\\\"/g' | tr -d '\\000-\\037'; }

engine=null
items=""
count=0
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  ver="$(docker --version 2>/dev/null | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1)"
  if [ -n "$ver" ]; then engine="$(printf '"%s"' "$ver")"; fi
  while IFS= read -r c; do
    [ -z "$c" ] && continue
    [ "$count" -ge 500 ] && break
    ref="$(docker inspect "$c" --format '{{.Config.Image}}' 2>/dev/null)"
    [ -z "$ref" ] && continue
    local_dig="$(docker image inspect "$ref" --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}' 2>/dev/null)"
    local_sha="\${local_dig##*@}"
    case "$local_sha" in sha256:*) ;; *) local_sha="" ;; esac
    reg_sha="$(docker buildx imagetools inspect "$ref" --format '{{.Manifest.Digest}}' 2>/dev/null | grep -oE 'sha256:[0-9a-f]+' | head -1)"
    upd=null
    if [ -n "$local_sha" ] && [ -n "$reg_sha" ]; then
      if [ "$local_sha" = "$reg_sha" ]; then upd=false; else upd=true; fi
    fi
    item="$(printf '{"container":"%s","image":"%s","localDigest":"%s","registryDigest":"%s","updateAvailable":%s}' "$(jesc "$c")" "$(jesc "$ref")" "$(jesc "$local_sha")" "$(jesc "$reg_sha")" "$upd")"
    items="\${items:+$items,}$item"
    count=$((count + 1))
  done <<DOCKER_PS
$(docker ps --format '{{.Names}}' 2>/dev/null)
DOCKER_PS
fi

gen="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
tmp="$(mktemp "\${OUT%/*}/.docker-inventory.XXXXXX")" || exit 1
if printf '{"schemaVersion":1,"generatedAt":"%s","dockerEngine":%s,"dockerImages":[%s]}\\n' "$gen" "$engine" "$items" >"$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$OUT"; then
  exit 0
fi
rm -f "$tmp"
exit 1
`;
}

/** The docker producer's systemd units: a oneshot service, and an hourly timer for it. */
export function dockerTimerUnits(): { service: string; timer: string } {
  return {
    service: `${MANAGED_HEADER}
[Unit]
Description=swamp-patch docker inventory (root producer)

[Service]
Type=oneshot
ExecStart=${PATHS.dockerProducer}
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
`,
    timer: `${MANAGED_HEADER}
[Unit]
Description=Refresh the swamp-patch docker inventory hourly

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
RandomizedDelaySec=5min

[Install]
WantedBy=timers.target
`,
  };
}

/**
 * Bash helpers that read the marker and the account. Both generated scripts embed this
 * block, so the takeover check in provision and the delete check in revoke are one code.
 * The marker holds `user=<name>` and `token=<token>`. The account counts as ours only when
 * its GECOS field carries that token.
 */
export function identityBlock(): string {
  return `# The marker field named by $1 (user or token). Empty when the marker lacks it.
marker_field() {
  [ -f "$MARKER" ] || return 0
  sed -n "s/^$1=//p" "$MARKER"
}

# The GECOS field of the account named by $1, from getent, or from /etc/passwd without it.
account_gecos() {
  if command -v getent >/dev/null 2>&1; then
    getent passwd "$1" | cut -d: -f5
  else
    awk -F: -v u="$1" '$1 == u { print $5; exit }' /etc/passwd
  fi
}

# True when the marker names $PATCH_USER with a 32-hex token, and the account's GECOS
# carries that same token as a whole word. The caller checks that the account exists.
marker_ok() {
  local m_user m_token gecos
  m_user="$(marker_field user)"
  m_token="$(marker_field token)"
  [ "$m_user" = "$PATCH_USER" ] || return 1
  [[ $m_token =~ ^[0-9a-f]{32}$ ]] || return 1
  gecos="$(account_gecos "$PATCH_USER")"
  [[ $gecos =~ token=$m_token([^0-9a-f]|$) ]]
}

# True when a group named by $1 exists, from getent, or from /etc/group without it.
group_exists() {
  if command -v getent >/dev/null 2>&1; then
    getent group "$1" >/dev/null 2>&1
  else
    awk -F: -v g="$1" '$1 == g { found = 1 } END { exit !found }' /etc/group
  fi
}

# The member list (field 4) of the group named by $1. Empty when it has no members.
group_members() {
  if command -v getent >/dev/null 2>&1; then
    getent group "$1" | cut -d: -f4
  else
    awk -F: -v g="$1" '$1 == g { print $4; exit }' /etc/group
  fi
}
`;
}

/**
 * Auto, pre-flight: refuse before the script changes anything when this host cannot take
 * auto OS updates (exit 5). It sets auto_family to apt or dnf for the auto section. The
 * script never installs a package: the updater must already be there.
 */
function autoPreflightBlock(): string {
  return `if [ -e /etc/pve ] || command -v pveversion >/dev/null 2>&1; then
  echo "auto OS updates are refused on a Proxmox node (it needs full-upgrade under @dmc/patch)" >&2
  exit 5
fi
if command -v apt-get >/dev/null 2>&1; then
  auto_family=apt
  if ! command -v unattended-upgrade >/dev/null 2>&1; then
    echo "unattended-upgrades is not installed: install it first (this script never installs packages)" >&2
    exit 5
  fi
elif command -v dnf >/dev/null 2>&1; then
  auto_family=dnf
  if [ ! -x /usr/bin/dnf-automatic ]; then
    echo "dnf-automatic is not installed: install it first (this script never installs packages)" >&2
    exit 5
  fi
elif [ -f /etc/alpine-release ]; then
  echo "auto OS updates are not supported on apk (Alpine)" >&2
  exit 5
elif command -v pacman >/dev/null 2>&1; then
  echo "auto OS updates are not supported on pacman (Arch)" >&2
  exit 5
else
  echo "auto OS updates are not supported on this host's package manager" >&2
  exit 5
fi
`;
}

/**
 * Auto: install the scope's config for the family the pre-flight found, enable the updater's
 * timer the way the cache section enables its own, and report the scope in the result line.
 * The pre-flight has already run, so an unknown family here is a bug, and it stops the run.
 */
function autoInstallBlock(scope: OsAutoScope): string {
  return `echo "== auto"
auto_json=${shQuote(JSON.stringify(scope))}
case "$auto_family" in
  apt)
    ${installBlock("APT_AUTO", "0644", aptAutoConf(scope))}
    if command -v systemctl >/dev/null 2>&1 && systemctl cat apt-daily-upgrade.timer >/dev/null 2>&1; then
      systemctl enable --now apt-daily-upgrade.timer
    fi
    ;;
  dnf)
    mkdir -p "\${DNF_AUTO_DROP_IN%/*}"
    chown root:root "\${DNF_AUTO_DROP_IN%/*}"
    chmod 0755 "\${DNF_AUTO_DROP_IN%/*}"
    ${installBlock("DNF_AUTO_CONF", "0644", dnfAutomaticConf(scope))}
    ${installBlock("DNF_AUTO_DROP_IN", "0644", dnfAutoDropInUnit())}
    if command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload
      if systemctl cat dnf-automatic.timer >/dev/null 2>&1; then
        systemctl enable --now dnf-automatic.timer
      fi
    fi
    ;;
  *)
    echo "internal error: no auto family was checked" >&2
    exit 1
    ;;
esac
`;
}

/**
 * Not auto: remove the three files this module wrote, when they carry the managed header. The
 * timers that the auto section enabled stay enabled. They are not disabled here: the distro's
 * apt-daily-upgrade.timer is needed by its own updates, and with our files gone the host's
 * own configuration applies again.
 */
function autoRemoveBlock(): string {
  return `echo "== auto"
auto_json=null
auto_dropin_was=false
if is_managed "$DNF_AUTO_DROP_IN"; then auto_dropin_was=true; fi
remove_managed "$APT_AUTO"
remove_managed "$DNF_AUTO_CONF"
remove_managed "$DNF_AUTO_DROP_IN"
if [ "$auto_dropin_was" = true ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
fi
`;
}

/**
 * Sudo, pre-flight: when the login needs a grant, refuse before any change if sudo or visudo
 * is missing (exit 5), and if a file this module did not write sits at the sudoers path (exit
 * 4). The script never installs sudo.
 */
function sudoPreflightBlock(): string {
  return `if ! command -v sudo >/dev/null 2>&1 || ! command -v visudo >/dev/null 2>&1; then
  echo "sudo is not installed: install it first (this script never installs packages)" >&2
  exit 5
fi
if [ -e "$SUDOERS" ] && ! is_managed "$SUDOERS"; then
  echo "refusing to overwrite $SUDOERS: it was not created by @dmc/patch" >&2
  exit 4
fi
`;
}

/** The sudo families, in the order the provision script checks them. */
const SUDO_FAMILIES: PrivCommand["family"][] = [
  "apt",
  "dnf",
  "apk",
  "pacman",
  "systemd",
];

/**
 * Sudo, helpers: the checks that decide whether a path may be granted. A path is granted when
 * it is absolute and plain, its link (if any) and its target are plain, every directory above
 * them is root-owned and not group- or world-writable, and the target is a root-owned regular
 * file that is not group- or world-writable. Nothing is granted by name alone.
 */
const SUDO_HELPERS =
  `# True when the octal mode in $1 has no group- or world-write bit. A mode that is not
# octal digits (stat failed or printed something else) is never trusted.
no_gw() {
  [[ $1 =~ ^[0-7]+$ ]] || return 1
  (( (8#$1 & 8#022) == 0 ))
}

# True when $1 is a directory that root owns and no other account may write. Symlinks are followed.
trusted_dir() {
  local m
  [ -d "$1" ] && [ -O "$1" ] || return 1
  m="$(stat -L -c %a "$1" 2>/dev/null)" || return 1
  no_gw "$m"
}

# True when $1 is a regular file that root owns, is not a symlink, and no other account may write.
trusted_file() {
  local m
  [ -f "$1" ] && [ ! -L "$1" ] && [ -O "$1" ] || return 1
  m="$(stat -c %a "$1" 2>/dev/null)" || return 1
  no_gw "$m"
}

# True when every directory above $1 is trusted, the root included.
trusted_chain() {
  local d="\${1%/*}"
  [ -n "$d" ] || d="/"
  while :; do
    trusted_dir "$d" || return 1
    [ "$d" = "/" ] && return 0
    d="\${d%/*}"
    [ -n "$d" ] || d="/"
  done
}

# Prints the absolute path of the command $1 when a sudoers entry may name it, and returns 0.
# Otherwise returns 1 and prints nothing.
sudo_path() {
  local p real re='^/[A-Za-z0-9._/+-]+$'
  p="$(command -v "$1" 2>/dev/null)" || return 1
  [[ $p =~ $re ]] || return 1
  real="$(readlink -f "$p" 2>/dev/null)" || return 1
  [[ $real =~ $re ]] || return 1
  trusted_chain "$p" && trusted_chain "$real" && trusted_file "$real" || return 1
  printf '%s\\n' "$p"
}

# Adds one entry. $1 is its id, $2 its sudoers text with @name@ where each absolute path goes,
# and the rest are the names it needs. A name that fails sudo_path leaves the entry out: the
# entry is listed in sudoMissing and never granted.
sudo_grant() {
  local id="$1" text="$2" name p line
  shift 2
  for name in "$@"; do
    if ! p="$(sudo_path "$name")"; then
      echo "sudo: $id is not granted: $name is not a plain root-owned command" >&2
      sudo_missing="\${sudo_missing:+$sudo_missing,}$(jstr "$id")"
      return 0
    fi
    # The quotes make the placeholder literal: a name never acts as a pattern.
    text="\${text//"@$name@"/$p}"
  done
  printf -v line '%s ALL=(root) NOPASSWD: %s\\n' "$PATCH_USER" "$text"
  sudo_lines="$sudo_lines$line"
  sudo_granted="\${sudo_granted:+$sudo_granted,}$(jstr "$id")"
}

# Adds one helper entry, with no arguments. $1 is its id, $2 the root-owned file it names. The file
# must pass the checks a command passes: a plain absolute path, not a symlink, and every directory
# above it root-owned and not writable by others. Otherwise the entry is listed in sudoMissing.
sudo_helper() {
  local id="$1" p="$2" line
  if [[ $p =~ ^/[A-Za-z0-9._/+-]+$ ]] && trusted_chain "$p" && trusted_file "$p"; then
    printf -v line '%s ALL=(root) NOPASSWD: %s\\n' "$PATCH_USER" "$p"
    sudo_lines="$sudo_lines$line"
    sudo_granted="\${sudo_granted:+$sudo_granted,}$(jstr "$id")"
  else
    echo "sudo: $id is not granted: $p is not a plain root-owned file" >&2
    sudo_missing="\${sudo_missing:+$sudo_missing,}$(jstr "$id")"
  fi
}
`;

/**
 * Sudo, install: write the grants to a temp file in the sudoers directory (its name has a dot,
 * which sudo ignores, so a half-written file is never read), check it with visudo, then move
 * it into place. The whole configuration must still parse, and /etc/sudoers must include the
 * directory. Any failure removes the file and exits 6. With no grants the managed file goes.
 */
const SUDO_INSTALL = `if [ -n "$sudo_lines" ]; then
  tmp="$(mktemp "\${SUDOERS%/*}/.swamp-patch.XXXXXX")"
  {
    printf '%s\\n' "$MANAGED"
    printf 'Defaults:%s env_reset\\n' "$PATCH_USER"
    printf 'Defaults:%s !setenv\\n' "$PATCH_USER"
    printf '%s' "$sudo_lines"
  } >"$tmp"
  chown root:root "$tmp"
  chmod 0440 "$tmp"
  if ! visudo -cf "$tmp" >/dev/null; then
    rm -f "$tmp"
    echo "the sudoers entries do not parse: nothing was installed" >&2
    exit 6
  fi
  mv -f "$tmp" "$SUDOERS"
  if ! visudo -c >/dev/null; then
    rm -f "$SUDOERS"
    echo "the sudo configuration does not parse with $SUDOERS: that file was removed" >&2
    exit 6
  fi
  if ! grep -qE '^[#@]includedir[[:space:]]+/etc/sudoers\\.d[[:space:]]*$' /etc/sudoers; then
    rm -f "$SUDOERS"
    echo "sudoers.d is not included by /etc/sudoers: the grant was removed" >&2
    exit 6
  fi
else
  remove_managed "$SUDOERS"
fi
`;

/**
 * Sudo, plug-in commands: before the usual grant, the bin is resolved and refused when the
 * path or the real file it points to has a denied basename (plugin_privileges.ts). A harmless
 * name such as `editor` can be a link to vim, so the TS check of the declared name is not
 * enough. A bin that does not resolve goes on to sudo_grant, which lists it as missing.
 */
const PLUGIN_HELPERS = `${pluginDeniedShellFn()}
# Adds one plug-in entry. $1 is its id, $2 its sudoers text, $3 the bin it runs, and the rest
# the names it needs (as for sudo_grant).
plugin_grant() {
  local id="$1" text="$2" p real
  p="$(command -v "$3" 2>/dev/null)" || p=""
  if [ -n "$p" ]; then
    real="$(readlink -f "$p" 2>/dev/null)" || real="$p"
    if plugin_denied "$p" || plugin_denied "$real"; then
      echo "sudo: $id is not granted: $3 is a command a plug-in may not run as root" >&2
      sudo_missing="\${sudo_missing:+$sudo_missing,}$(jstr "$id")"
      return 0
    fi
  fi
  shift 3
  sudo_grant "$id" "$text" "$@"
}
`;

/** True when the login needs at least one sudoers entry. */
function needsSudo(sudo: ProvisionInput["sudo"]): boolean {
  return requiredCommands(sudo).length > 0 ||
    requiredHelpers(sudo).length > 0 || (sudo.extra ?? []).length > 0;
}

/**
 * The sudo section: the grants this login needs, each checked on this host, then installed.
 * The entries come from the table (access_sudoers.ts) and from the plugged models' validated
 * declarations as escaped text; the script only fills in the absolute paths it has checked. A
 * family that the host does not have grants nothing.
 */
function sudoSection(sudo: ProvisionInput["sudo"]): string {
  const head = `echo "== sudo"
sudo_lines=""
sudo_granted=""
sudo_missing=""
`;
  const required = requiredCommands(sudo);
  const helpers = requiredHelpers(sudo);
  const extra = sudo.extra ?? [];
  if (!needsSudo(sudo)) {
    return `${head}remove_managed "$SUDOERS"\n`;
  }
  const pluginLines = extra.map((c) =>
    `plugin_grant ${c.id} ${shQuote(sudoersTemplate(c))} ${shQuote(c.bin)} ${
      grantNames(c).map(shQuote).join(" ")
    }`
  );
  const helperLines = helpers.map((g) =>
    `sudo_helper ${g.id} ${shQuote(g.path)}`
  );
  const grants = SUDO_FAMILIES.flatMap((family) => {
    const cmds = required.filter((c) => c.family === family);
    if (cmds.length === 0) return [];
    const present = FAMILY_PROBES[family]
      .map((p) => `command -v ${p} >/dev/null 2>&1`)
      .join(" || ");
    return [
      `if ${present}; then`,
      ...cmds.map((c) =>
        `  sudo_grant ${c.id} ${shQuote(sudoersTemplate(c))} ${
          grantNames(c).join(" ")
        }`
      ),
      "fi",
    ];
  });
  return `${head}${SUDO_HELPERS}${extra.length > 0 ? PLUGIN_HELPERS : ""}${
    [...grants, ...pluginLines, ...helperLines].join("\n")
  }\n${SUDO_INSTALL}`;
}

/**
 * The idempotent root script that provisions the access login. The inputs are
 * shell-quoted in the assignments at the top; the rest of the script uses only those
 * variables. Each step prints one `== <step>` line. The last stdout line is JSON.
 */
export function provisionScript(input: ProvisionInput): string {
  const v = validateProvisionInput(input);
  const keyLine = authorizedKeysLine(v.publicKey, v.from);
  const autoPreflight = v.autoUpdates === null ? "" : autoPreflightBlock();
  const sudoPreflight = needsSudo(v.sudo) ? sudoPreflightBlock() : "";
  const autoSection = v.autoUpdates === null
    ? autoRemoveBlock()
    : autoInstallBlock(v.autoUpdates);
  return `#!/usr/bin/env bash
${MANAGED_HEADER}
# Provisions the swamp-patch access login. Runs as root on the host and is idempotent.
# Each input is shell-quoted in the assignments below. The rest of the script uses
# only these variables, in double quotes.
PATCH_USER=${shQuote(v.user)}
KEY_LINE=${shQuote(keyLine)}
WANT_DOCKER=${v.docker ? 1 : 0}
${constantsBlock()}set -euo pipefail
umask 022

# Write stdin to the file in $1, as root:root with mode $2. The temp file is in the
# same directory, so mv replaces the target in one step.
install_file() {
  local tmp
  tmp="$(mktemp "\${1%/*}/.swamp-patch.XXXXXX")"
  cat >"$tmp"
  chown root:root "$tmp"
  chmod "$2" "$tmp"
  mv -f "$tmp" "$1"
}

# True when the file in $1 exists and carries the managed header.
is_managed() { [ -f "$1" ] && grep -qF "$MANAGED" "$1"; }

# Remove the file in $1 when it carries the managed header.
remove_managed() {
  if is_managed "$1"; then
    rm -f "$1"
    echo "removed $1"
  fi
}

${identityBlock()}
# One JSON string. The values passed here are fixed names.
jstr() { printf '"%s"' "$1"; }

echo "== root"
if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root" >&2
  exit 1
fi

echo "== preflight"
BASH_PATH="$(command -v bash || true)"
if [ -z "$BASH_PATH" ]; then
  echo "no bash on this host: the access login needs bash as its login shell" >&2
  exit 4
fi
if [ "$WANT_DOCKER" = 1 ] && ! command -v systemctl >/dev/null 2>&1; then
  echo "docker inventory needs systemd: this host has no systemctl, and OpenRC is not supported for docker" >&2
  exit 4
fi
if [ "$WANT_DOCKER" = 1 ] && [ ! -d /etc/systemd/system ]; then
  echo "docker inventory needs /etc/systemd/system for its timer, and this host does not have it" >&2
  exit 4
fi
if ! id "$PATCH_USER" >/dev/null 2>&1 && group_exists "$PATCH_USER"; then
  echo "a group named $PATCH_USER already exists without the account" >&2
  exit 4
fi
${autoPreflight}${sudoPreflight}
echo "== account"
created=false
if id "$PATCH_USER" >/dev/null 2>&1; then
  if ! marker_ok; then
    echo "refusing to take over existing account $PATCH_USER" >&2
    exit 3
  fi
else
  # The token binds the marker to this account: it is also in the account's GECOS field.
  token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \\n')"
  if [[ ! $token =~ ^[0-9a-f]{32}$ ]]; then
    echo "could not make a 32-hex token from /dev/urandom" >&2
    exit 1
  fi
  comment="swamp-patch (managed by @dmc/patch) token=$token"
  mkdir -p "$STATE_DIR"
  chown root:root "$STATE_DIR"
  chmod 0755 "$STATE_DIR"
  if command -v useradd >/dev/null 2>&1; then
    useradd --system --home-dir "$HOME_DIR" --create-home --shell "$BASH_PATH" --user-group --comment "$comment" "$PATCH_USER"
  else
    addgroup -S "$PATCH_USER"
    adduser -S -D -h "$HOME_DIR" -s "$BASH_PATH" -g "$comment" -G "$PATCH_USER" "$PATCH_USER"
  fi
  printf 'user=%s\\ntoken=%s\\n' "$PATCH_USER" "$token" | install_file "$MARKER" 0644
  created=true
fi

# No password: the shadow field is exactly "*", which no password matches. Not "!" (passwd
# -l): an sshd built without PAM (Alpine) treats a "!" field as a locked account and refuses
# the key login too. With PAM, "*" works the same as "!". Anything else stops here.
shadow_field() { awk -F: -v u="$PATCH_USER" '$1 == u { print $2; exit }' /etc/shadow; }
if [ "$(shadow_field)" != '*' ]; then
  printf '%s:*\\n' "$PATCH_USER" | chpasswd -e >/dev/null 2>&1 || true
  if [ "$(shadow_field)" != '*' ]; then
    echo "could not set the password field of $PATCH_USER to * (no password)" >&2
    exit 1
  fi
fi

# Drop the login from every group that grants root or docker access.
groups_removed=""
member_of=" $(id -nG "$PATCH_USER") "
for g in docker wheel sudo admin adm lxd disk root; do
  case "$member_of" in
    *" $g "*) ;;
    *) continue ;;
  esac
  if command -v gpasswd >/dev/null 2>&1; then
    gpasswd -d "$PATCH_USER" "$g" >/dev/null
  else
    delgroup "$PATCH_USER" "$g" >/dev/null
  fi
  echo "removed $PATCH_USER from group $g"
  groups_removed="\${groups_removed:+$groups_removed,}$(jstr "$g")"
done

echo "== key"
mkdir -p "$HOME_DIR/.ssh"
chown root:root "$HOME_DIR" "$HOME_DIR/.ssh"
chmod 0755 "$HOME_DIR" "$HOME_DIR/.ssh"
printf '%s\\n' "$KEY_LINE" | install_file "$HOME_DIR/.ssh/authorized_keys" 0644

echo "== cache"
cache_refresh=none
if command -v pveversion >/dev/null 2>&1; then
  cache_refresh=pve
  echo "pve-daily-update refreshes the lists"
elif [ -f /etc/debian_version ]; then
  ${installBlock("APT_CONF", "0644", aptPeriodicConf())}
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now apt-daily.timer
  fi
  cache_refresh=apt
elif command -v dnf >/dev/null 2>&1; then
  if command -v systemctl >/dev/null 2>&1 && systemctl cat dnf-makecache.timer >/dev/null 2>&1; then
    systemctl enable --now dnf-makecache.timer
  fi
  cache_refresh=dnf
elif [ -f /etc/alpine-release ]; then
  ${installBlock("APK_PERIODIC", "0755", apkPeriodicScript())}
  if ! grep -qx crond /proc/[0-9]*/comm 2>/dev/null; then
    echo "warning: no crond process runs, so the apk index is not refreshed daily" >&2
  fi
  cache_refresh=apk
fi

${autoSection}
echo "== docker"
docker_on=false
if [ "$WANT_DOCKER" = 1 ]; then
  mkdir -p "$LIBEXEC"
  chown root:root "$LIBEXEC"
  chmod 0755 "$LIBEXEC"
  mkdir -p "$PROJECTS_DIR"
  chown root:root "$PROJECTS_DIR"
  chmod 0755 "$PROJECTS_DIR"
  ${installBlock("DOCKER_PRODUCER", "0755", dockerProducerScript())}
  ${installBlock("DOCKER_HELPER", "0755", dockerHelperScript(MANAGED_HEADER))}
  ${
    installBlock(
      "DOCKER_PROJECTS",
      "0644",
      dockerProjectsFile(v.dockerProjects, MANAGED_HEADER),
    )
  }
  ${installBlock("UNIT_SERVICE", "0644", dockerTimerUnits().service)}
  ${installBlock("UNIT_TIMER", "0644", dockerTimerUnits().timer)}
  systemctl daemon-reload
  systemctl enable --now swamp-patch-docker-inventory.timer
  "$DOCKER_PRODUCER"
  chmod 0755 "$STATE_DIR"
  chmod 0644 "$DOCKER_INVENTORY"
  docker_on=true
else
  if is_managed "$UNIT_TIMER" && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now swamp-patch-docker-inventory.timer
  fi
  remove_managed "$UNIT_TIMER"
  remove_managed "$UNIT_SERVICE"
  remove_managed "$DOCKER_PRODUCER"
  remove_managed "$DOCKER_HELPER"
  remove_managed "$DOCKER_PROJECTS"
  if [ -d "$PROJECTS_DIR" ]; then
    rmdir "$PROJECTS_DIR" 2>/dev/null || true
  fi
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
  fi
fi

${sudoSection(v.sudo)}
printf '{"_kind":"patch-access-provision","user":"%s","created":%s,"groupsRemoved":[%s],"cacheRefresh":"%s","docker":%s,"autoUpdates":%s,"sudoEntries":[%s],"sudoMissing":[%s]}\\n' "$PATCH_USER" "$created" "$groups_removed" "$cache_refresh" "$docker_on" "$auto_json" "$sudo_granted" "$sudo_missing"
`;
}

/**
 * The idempotent root script that removes the access login. It removes only what this
 * module installed: the sudoers file, the managed cache, auto-update and docker files, the account
 * and its group when the marker and token show this module made them, and the state
 * directory. The last stdout line is JSON.
 */
export function revokeScript(user: string): string {
  const name = checkUser(user);
  return `#!/usr/bin/env bash
${MANAGED_HEADER}
# Removes the swamp-patch access login and the files this module installed. Runs as
# root on the host and is idempotent. The input is shell-quoted in the assignment below.
PATCH_USER=${shQuote(name)}
${constantsBlock()}set -euo pipefail
umask 022

# True when the file in $1 exists and carries the managed header.
is_managed() { [ -f "$1" ] && grep -qF "$MANAGED" "$1"; }

${identityBlock()}
# One JSON string. The values passed here are paths or fixed names.
jstr() { printf '"%s"' "$1"; }

# Record one removed item for the result line.
removed=""
note() { removed="\${removed:+$removed,}$(jstr "$1")"; }

# True when the state dir holds nothing but the marker, the home and the docker inventory.
state_dir_clean() {
  local entry
  for entry in "$STATE_DIR"/* "$STATE_DIR"/.[!.]* "$STATE_DIR"/..?*; do
    if [ ! -e "$entry" ] && [ ! -L "$entry" ]; then continue; fi
    case "$entry" in
      "$MARKER" | "$HOME_DIR" | "$DOCKER_INVENTORY") ;;
      *) return 1 ;;
    esac
  done
  return 0
}

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root" >&2
  exit 1
fi

if [ -e "$SUDOERS" ]; then
  rm -f "$SUDOERS"
  echo "removed $SUDOERS"
  note "$SUDOERS"
fi

# Stop the timer before its files go.
if is_managed "$UNIT_TIMER" && command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now swamp-patch-docker-inventory.timer
fi
# The auto-update files go too. The distro's update timers stay as they are: with these
# files gone, the host's own configuration applies again (see provisionScript).
for f in "$APT_CONF" "$APK_PERIODIC" "$DOCKER_PRODUCER" "$DOCKER_HELPER" "$DOCKER_PROJECTS" "$UNIT_TIMER" "$UNIT_SERVICE" "$APT_AUTO" "$DNF_AUTO_CONF" "$DNF_AUTO_DROP_IN"; do
  if is_managed "$f"; then
    rm -f "$f"
    echo "removed $f"
    note "$f"
  fi
done
# The directory of the project list goes only when nothing else is in it.
if [ -d "$PROJECTS_DIR" ]; then
  rmdir "$PROJECTS_DIR" 2>/dev/null || true
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
fi

# The account goes only when the marker and its token show that this module made it. Its
# home is not removed here: the state dir holds the home, and that goes last.
kept_account=false
if id "$PATCH_USER" >/dev/null 2>&1; then
  if marker_ok; then
    if command -v userdel >/dev/null 2>&1; then
      if ! userdel "$PATCH_USER"; then
        echo "could not delete account $PATCH_USER: userdel failed; kept the marker and $STATE_DIR" >&2
        exit 1
      fi
    elif ! deluser "$PATCH_USER"; then
      echo "could not delete account $PATCH_USER: deluser failed; kept the marker and $STATE_DIR" >&2
      exit 1
    fi
    echo "removed account $PATCH_USER"
    note "account:$PATCH_USER"
  else
    echo "left account $PATCH_USER in place: not created by @dmc/patch" >&2
    kept_account=true
  fi
fi

# The group goes only when no foreign account was kept, the group has no members, and the
# marker names this user.
if [ "$kept_account" = false ] && group_exists "$PATCH_USER" && [ -z "$(group_members "$PATCH_USER")" ] && [ "$(marker_field user)" = "$PATCH_USER" ]; then
  if command -v groupdel >/dev/null 2>&1; then
    if ! groupdel "$PATCH_USER"; then
      echo "could not delete group $PATCH_USER" >&2
      exit 1
    fi
  elif ! delgroup "$PATCH_USER"; then
    echo "could not delete group $PATCH_USER" >&2
    exit 1
  fi
  echo "removed group $PATCH_USER"
  note "group:$PATCH_USER"
fi

# With a foreign account left, the state dir goes only when nothing else is in it.
if [ "$kept_account" = true ] && ! state_dir_clean; then
  echo "left $STATE_DIR in place: it holds files other than the marker, home and docker inventory" >&2
else
  if [ -e "$MARKER" ]; then
    if ! rm -f "$MARKER"; then
      echo "could not remove $MARKER" >&2
      exit 1
    fi
    echo "removed $MARKER"
    note "$MARKER"
  fi
  if [ -e "$STATE_DIR" ]; then
    if ! rm -rf "$STATE_DIR"; then
      echo "could not remove $STATE_DIR" >&2
      exit 1
    fi
    echo "removed $STATE_DIR"
    note "$STATE_DIR"
  fi
fi

printf '{"_kind":"patch-access-revoke","user":"%s","removed":[%s]}\\n' "$PATCH_USER" "$removed"
`;
}
