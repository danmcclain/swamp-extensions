/**
 * The privileged commands that @dmc/patch may run as root on a host through `sudo -n`, and
 * the sudoers entries that grant them. One table is the single source of truth: the runtime
 * scripts (osUpgradeScript and the reboot command in patch_fleet.ts) run exactly these argv,
 * and the provision script grants exactly these argv. Pure: no I/O, nothing is run.
 *
 * Every entry is an exact argv. There are no wildcards and no shells, and a caller cannot
 * choose a value: a word that is not in the table is never granted. The runtime resolves
 * each binary to its absolute path on the host (`command -v`), and the sudoers entry names
 * that same path, so sudo matches the entry by path and by arguments.
 *
 * @module
 */
import { DOCKER_HELPER_PATH } from "./docker_helper.ts";

/**
 * One privileged command. `bin` is resolved on the host; `env` is fixed environment. The
 * `plugin` capability and family are for commands a plugged model declares
 * (lib/plugin_privileges.ts): they go through the same sudoers writer, with no family probe
 * (the provision script resolves the bin directly).
 */
export interface PrivCommand {
  id: string;
  capability: "osUpgrade" | "osCheck" | "reboot" | "plugin";
  family: "apt" | "dnf" | "apk" | "pacman" | "systemd" | "plugin";
  bin: string;
  args: string[];
  env?: Record<string, string>;
}

/** The commands @dmc/patch may run as root. The contract tests read this table. */
export const PRIV_COMMANDS: readonly PrivCommand[] = [
  {
    id: "apt-update",
    capability: "osUpgrade",
    family: "apt",
    bin: "apt-get",
    args: ["update", "-qq"],
  },
  {
    id: "apt-upgrade",
    capability: "osUpgrade",
    family: "apt",
    bin: "apt-get",
    args: ["-y", "upgrade"],
    env: { DEBIAN_FRONTEND: "noninteractive" },
  },
  {
    id: "apt-full-upgrade",
    capability: "osUpgrade",
    family: "apt",
    bin: "apt-get",
    args: ["-y", "full-upgrade"],
    env: { DEBIAN_FRONTEND: "noninteractive" },
  },
  {
    id: "dnf-upgrade",
    capability: "osUpgrade",
    family: "dnf",
    bin: "dnf",
    args: ["-y", "upgrade"],
  },
  // The read-only update check, on root's own cache (-C): no download, no change. Root's
  // dnf checks each cached repo signature (repo_gpgcheck) with root's keyring. libdnf 4 cannot
  // do that for a login without root: it makes its gpg home under /run/user, which only root
  // may write. The scan uses these when granted, and its unprivileged checks otherwise.
  {
    id: "dnf-check",
    capability: "osCheck",
    family: "dnf",
    bin: "dnf",
    args: ["-q", "-C", "check-update"],
  },
  {
    id: "dnf-check-security",
    capability: "osCheck",
    family: "dnf",
    bin: "dnf",
    args: ["-q", "-C", "check-update", "--security"],
  },
  {
    id: "apk-upgrade",
    capability: "osUpgrade",
    family: "apk",
    bin: "apk",
    args: ["upgrade"],
  },
  {
    id: "pacman-upgrade",
    capability: "osUpgrade",
    family: "pacman",
    bin: "pacman",
    args: ["-Syu", "--noconfirm"],
  },
  {
    id: "reboot",
    capability: "reboot",
    family: "systemd",
    bin: "systemd-run",
    args: [
      "--on-active=3",
      "--timer-property=AccuracySec=100ms",
      "systemctl",
      "reboot",
    ],
  },
];

/**
 * The commands whose presence means a family is on the host. A family counts as present when
 * any of its probes resolves. Each entry of a present family then needs all of its own paths.
 */
export const FAMILY_PROBES: Record<PrivCommand["family"], readonly string[]> = {
  apt: ["apt-get"],
  dnf: ["dnf"],
  apk: ["apk"],
  pacman: ["pacman"],
  systemd: ["systemd-run", "systemctl"],
  // A plug-in command names its own bin, so there is no family to probe.
  plugin: [],
};

/** Every argv token of the table (arguments and env pairs) must match this. */
export const TABLE_TOKEN = /^[A-Za-z0-9._/:=+-]+$/;
/** An absolute path the sudoers file may name. */
const ABS_PATH = /^\/[A-Za-z0-9._/+-]+$/;
/** A login name the sudoers file may name (the same rule as the access user). */
const SUDO_USER = /^[a-z_][a-z0-9_-]{0,31}$/;
/** The characters a sudoers command word may carry; the escaped ones are the punctuation. */
const SUDOERS_WORD_CHAR = /^[A-Za-z0-9._/:=+,\\ -]$/;

/** The table entry with this id. Throws for an unknown id. */
export function privCommand(id: string): PrivCommand {
  const cmd = PRIV_COMMANDS.find((c) => c.id === id);
  if (!cmd) throw new Error(`no privileged command named ${id}`);
  return cmd;
}

/**
 * The names of the binaries a command runs by path: env (when it has env) and the bin. The
 * runtime resolves these; a grant also needs the family's other probes (see grantNames).
 */
export function pathNames(cmd: PrivCommand): string[] {
  return cmd.env ? ["env", cmd.bin] : [cmd.bin];
}

/** Every name a grant of this entry needs on the host: its paths and its family's probes. */
export function grantNames(cmd: PrivCommand): string[] {
  return [...new Set([...pathNames(cmd), ...FAMILY_PROBES[cmd.family]])];
}

/** The shell variable that holds a binary's absolute path in the runtime scripts. */
export function shellVar(name: string): string {
  return `BIN_${name.toUpperCase().replace(/[^A-Z0-9]/g, "_")}`;
}

/** The runtime's words for each path name: a quoted shell variable, filled in on the host. */
export function shellPaths(cmd: PrivCommand): Record<string, string> {
  return Object.fromEntries(
    pathNames(cmd).map((n) => [n, `"$${shellVar(n)}"`]),
  );
}

/**
 * The argv of a command, each slot marked by whether it names a binary. Pure table data:
 * the env pairs come first (behind env), then the bin, then the arguments.
 */
interface Slot {
  /** The binary name the slot stands for, or null for a fixed word. */
  bin: string | null;
  word: string;
}

function checkTable(cmd: PrivCommand): void {
  const tokens = [
    cmd.bin,
    ...cmd.args,
    ...Object.entries(cmd.env ?? {}).map(([k, v]) => `${k}=${v}`),
  ];
  for (const t of tokens) {
    if (!TABLE_TOKEN.test(t)) {
      throw new Error(
        `privileged command ${cmd.id}: token "${t}" is not allowed`,
      );
    }
  }
}

function slots(cmd: PrivCommand): Slot[] {
  checkTable(cmd);
  const out: Slot[] = [];
  if (cmd.env) {
    out.push({ bin: "env", word: "env" });
    for (const [k, v] of Object.entries(cmd.env)) {
      out.push({ bin: null, word: `${k}=${v}` });
    }
  }
  out.push({ bin: cmd.bin, word: cmd.bin });
  for (const a of cmd.args) out.push({ bin: null, word: a });
  return out;
}

/**
 * The sudoers text of one word of a command. Backslash escapes `\`, `,`, `:`, `=` and the
 * space. Every other character is refused, so `*`, `?`, `[`, `]`, `!`, quotes, `#` and a
 * newline can never reach a sudoers file.
 */
export function sudoersEscape(token: string): string {
  if (typeof token !== "string" || token.length === 0) {
    throw new Error("a sudoers command word must not be empty");
  }
  for (const ch of token) {
    if (!SUDOERS_WORD_CHAR.test(ch)) {
      throw new Error(
        `a sudoers command word may not contain ${JSON.stringify(ch)}`,
      );
    }
  }
  return token.replace(/[\\,:= ]/g, (c) => `\\${c}`);
}

/**
 * The sudoers words of a command. A sudoers command with no arguments allows ANY arguments, so
 * a command that sudo runs with none ends in `""`, which sudo reads as exactly none. An entry
 * with env always has arguments (the pairs and the bin), so it never gets `""`: there sudo
 * would require a literal `""` argument. Helper grants never come through here: their "any
 * arguments" is deliberate (the helper is the gate).
 */
function sudoersWords(
  cmd: PrivCommand,
  pathOf: (name: string) => string,
): string[] {
  const words = slots(cmd).map((s) =>
    s.bin === null ? sudoersEscape(s.word) : pathOf(s.bin)
  );
  if (words.length === 1) words.push('""');
  return words;
}

/**
 * The exact words the runtime runs after `sudo -n`, with `paths` filled in: each binary's
 * absolute path, then the env pairs and the arguments as the table gives them. Built from the
 * same slots as sudoersLine, so the two cannot drift.
 */
export function runtimeCommand(
  cmd: PrivCommand,
  paths: Record<string, string>,
): string[] {
  return slots(cmd).map((s) => {
    if (s.bin === null) return s.word;
    const p = paths[s.bin];
    if (p === undefined) {
      throw new Error(`privileged command ${cmd.id}: no path for ${s.bin}`);
    }
    return p;
  });
}

/**
 * One sudoers line that grants `user` exactly this command, as root and without a password.
 * Every binary path must be absolute and plain (it is checked), and every argument is escaped.
 */
export function sudoersLine(
  user: string,
  cmd: PrivCommand,
  paths: Record<string, string>,
): string {
  if (typeof user !== "string" || !SUDO_USER.test(user)) {
    throw new Error("a sudoers grant needs a plain login name");
  }
  const words = sudoersWords(cmd, (name) => {
    const p = paths[name];
    if (p === undefined || !ABS_PATH.test(p)) {
      throw new Error(
        `privileged command ${cmd.id}: ${name} needs an absolute path, not ${
          JSON.stringify(p ?? null)
        }`,
      );
    }
    return p;
  });
  return `${user} ALL=(root) NOPASSWD: ${words.join(" ")}`;
}

/**
 * The sudoers command text of one entry, with `@name@` where each absolute path goes. The
 * provision script fills the placeholders in on the host, after each path has been checked.
 */
export function sudoersTemplate(cmd: PrivCommand): string {
  return sudoersWords(cmd, (name) => `@${name}@`).join(" ");
}

/**
 * The entries a host with these capabilities needs: every entry of each capability it has.
 * The provision script keeps only the families present on the host.
 */
export function requiredCommands(caps: {
  osUpgrade: boolean;
  osCheck: boolean;
  reboot: boolean;
}): PrivCommand[] {
  return PRIV_COMMANDS.filter((c) =>
    (c.capability === "osUpgrade" && caps.osUpgrade) ||
    (c.capability === "osCheck" && caps.osCheck) ||
    (c.capability === "reboot" && caps.reboot)
  );
}

/**
 * A grant of one root-owned helper file, with no arguments. The helper validates its own
 * arguments (lib/docker_helper.ts), so sudo allows any arguments to this path and nothing else.
 * It is a sibling of PRIV_COMMANDS because it is not a command the runtime resolves with
 * `command -v`: the path is fixed, and the provision script checks the file itself.
 */
export interface HelperGrant {
  id: "docker-helper";
  capability: "docker";
  path: string;
}

/** The helper grants. The contract tests read this table. */
export const HELPER_GRANTS: readonly HelperGrant[] = [
  {
    id: "docker-helper",
    capability: "docker",
    path: DOCKER_HELPER_PATH,
  },
];

/** The helper grants a host with these capabilities needs. */
export function requiredHelpers(caps: { docker: boolean }): HelperGrant[] {
  return HELPER_GRANTS.filter((g) => g.capability === "docker" && caps.docker);
}

/**
 * The runtime's resolution lines for these commands: one `BIN_X="$(abs_cmd x)"` per binary
 * name, each failing the script (exit 3) when the name has no absolute path on the host.
 */
export function runtimeResolveLines(cmds: PrivCommand[]): string[] {
  const names = [...new Set(cmds.flatMap(pathNames))];
  return names.map((n) => `${shellVar(n)}="$(abs_cmd ${n})" || exit 3`);
}

/** The runtime's shell function that prints a command's absolute path, or fails. */
export const RUNTIME_ABS_FN = `abs_cmd() {
  local p
  p="$(command -v "$1" 2>/dev/null)" || p=""
  case "$p" in
    /*) printf '%s\\n' "$p" ;;
    *) echo "no absolute path for $1 on this host" >&2; return 1 ;;
  esac
}`;

/** One privileged command as the runtime runs it: `$SUDO` (empty as root), then the argv. */
export function runtimeLine(cmd: PrivCommand): string {
  return `$SUDO ${runtimeCommand(cmd, shellPaths(cmd)).join(" ")}`;
}
