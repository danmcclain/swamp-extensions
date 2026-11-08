/**
 * The privileges a plugged model declares: the `privileges({ host })` contract.
 *
 * A plugged model (a source or proxmox updater, an osUpdater, a snapshotter) may expose
 * `privileges({ host })`, which writes ONE resource with the root commands it needs. Those
 * commands become sudoers grants, so everything the plug-in returns is untrusted input: this
 * module validates it strictly and fails closed. Pure: no I/O, nothing is run.
 *
 * @module
 */
import { z } from "npm:zod@4";
import { TABLE_TOKEN } from "./access_sudoers.ts";
import type { PrivCommand } from "./access_sudoers.ts";
import { TrustSource } from "./access_policy.ts";

/** At most this many commands per plugged model. */
export const MAX_PLUGIN_COMMANDS = 16;
/** At most this many plug-in commands per machine: four plugged models of 16 each. */
export const MAX_MACHINE_PLUGIN_COMMANDS = 4 * MAX_PLUGIN_COMMANDS;
/** At most this many argv tokens per command, the bin included. */
const MAX_ARGV = 32;
/** At most this many env pairs per command. */
const MAX_ENV = 8;
/** At most this many remote sources per plugged model. */
export const MAX_REMOTE_SOURCES = 4;

/** A bare command name, resolved on the host with `command -v`. Never starts with - or a dot. */
const BARE_BIN = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;
/** An absolute path. `..`, `//`, a `.` segment and a trailing `/` are refused on top of this rule. */
const ABS_BIN = /^\/[A-Za-z0-9._/+-]+$/;
const ENV_NAME = /^[A-Z][A-Z0-9_]{0,63}$/;
/** The id of a plug-in command: `plugin-<n>-<slug>`, safe to write in a shell word. */
const PLUGIN_ID = /^plugin-[1-9][0-9]{0,3}-[a-z0-9-]{1,40}$/;

/**
 * Basenames a plug-in may never run as root: shells, privilege tools, interpreters, commands
 * that run another command, editors and pagers (and their alias names), copy and archive
 * tools. A plug-in that needs one declares a helper later. The provision script checks this
 * list again against the real path each bin resolves to on the host (see
 * pluginDeniedShellFn), because a harmless name can be a link to one of these.
 */
export const DENIED_BINS: readonly string[] = [
  // shells
  "sh",
  "bash",
  "rbash",
  "dash",
  "zsh",
  "ksh",
  "mksh",
  "ash",
  "csh",
  "tcsh",
  "fish",
  "busybox",
  // privilege and namespace tools
  "env",
  "sudo",
  "sudoedit",
  "su",
  "doas",
  "pkexec",
  "runuser",
  "setpriv",
  "nsenter",
  "unshare",
  "chroot",
  "capsh",
  "sg",
  "newgrp",
  "systemd-run",
  "systemctl",
  "start-stop-daemon",
  // commands that run another command
  "timeout",
  "nice",
  "ionice",
  "chrt",
  "taskset",
  "stdbuf",
  "setsid",
  "nohup",
  "flock",
  "time",
  "watch",
  "script",
  "expect",
  "strace",
  "ltrace",
  "gdb",
  // interpreters
  "python",
  "python3",
  "perl",
  "ruby",
  "node",
  "deno",
  "php",
  "lua",
  "tclsh",
  "awk",
  "gawk",
  "mawk",
  "sed",
  "find",
  "xargs",
  // editors and pagers
  "vi",
  "vim",
  "vim.basic",
  "vim.tiny",
  "nvim",
  "view",
  "ex",
  "ed",
  "emacs",
  "nano",
  "editor",
  "sensible-editor",
  "less",
  "more",
  "pager",
  "sensible-pager",
  "man",
  // remote and copy tools
  "ssh",
  "scp",
  "rsync",
  "tar",
  "dd",
  "cp",
  "mv",
  "install",
  "chmod",
  "chown",
  "ln",
  "tee",
];

/** Versioned forms of the interpreters above (python3.12, perl5.36, node20 and so on). */
const DENIED_VERSIONED =
  /^(python|perl|ruby|node|php|lua|tclsh|awk|gawk|mawk)[0-9.]+$/;

/** Environment names a plug-in command may not set: loader, shell, interpreter and identity variables. */
const DENIED_ENV_PREFIXES = [
  "LD_",
  "DYLD_",
  "BASH_",
  "PYTHON",
  "PERL",
  "RUBY",
  "NODE_",
  "GIT_",
];
const DENIED_ENV = [
  "PATH",
  "IFS",
  "ENV",
  "SHELLOPTS",
  "PS4",
  "HOME",
  "TMPDIR",
  "SUDO_ASKPASS",
  "EDITOR",
  "VISUAL",
  "PAGER",
];

/** The basename of a bin, or the bin itself when it has no slash. */
function basename(bin: string): string {
  return bin.split("/").pop() ?? bin;
}

/** True when a bin's basename is one a plug-in may not run as root. */
export function deniedBin(bin: string): boolean {
  const base = basename(bin);
  return DENIED_BINS.includes(base) || DENIED_VERSIONED.test(base);
}

/** True when an env name is one a plug-in command may not set. */
export function deniedEnv(name: string): boolean {
  return DENIED_ENV.includes(name) ||
    DENIED_ENV_PREFIXES.some((p) => name.startsWith(p));
}

/**
 * The provision script's shell function `plugin_denied <path>`: true when the basename of the
 * path is on the deny list. The list is plain words of the table token rule, so it is written
 * into the script as it is.
 */
export function pluginDeniedShellFn(): string {
  const words = DENIED_BINS.join(" ");
  return `# True when the basename of $1 is a command a plug-in may never run as root.
plugin_denied() {
  local base="\${1##*/}" w re='${DENIED_VERSIONED.source}'
  for w in ${words}; do
    [ "$base" = "$w" ] && return 0
  done
  [[ $base =~ $re ]]
}
`;
}

/** A plain argv token: the table rule, which excludes the empty string. */
const Token = z.string().regex(
  TABLE_TOKEN,
  "must be letters, digits and . _ / : = + - only",
);

function checkArgv(argv: string[], ctx: z.RefinementCtx): void {
  const bin = argv[0] ?? "";
  const absolute = ABS_BIN.test(bin) && !bin.includes("..") &&
    !bin.includes("//") && !bin.endsWith("/") && !/\/\.(\/|$)/.test(bin);
  if (!BARE_BIN.test(bin) && !absolute) {
    ctx.addIssue({
      code: "custom",
      path: [0],
      message:
        "the bin must be a bare command name, or an absolute path with no .. or //",
    });
  } else if (deniedBin(bin)) {
    ctx.addIssue({
      code: "custom",
      path: [0],
      message: `${
        basename(bin)
      } may not run as root through a plug-in (shells, interpreters, runners, editors, privilege and copy tools are refused)`,
    });
  } else if (writablePath(bin)) {
    // The patch login could put its own program there. The provision script refuses such a
    // bin too (trusted_chain); this rule refuses it before anything reaches the host.
    ctx.addIssue({
      code: "custom",
      path: [0],
      message: `the bin ${WRITABLE_MESSAGE}`,
    });
  }
  argv.forEach((t, i) => {
    if (i > 0 && !Token.safeParse(t).success) {
      ctx.addIssue({
        code: "custom",
        path: [i],
        message: `${
          JSON.stringify(t)
        } must be letters, digits and . _ / : = + - only`,
      });
    } else if (i > 0 && writablePath(t)) {
      ctx.addIssue({ code: "custom", path: [i], message: WRITABLE_MESSAGE });
    }
  });
}

/**
 * A path in a directory that other accounts can write, or with `..`. A root command that reads
 * such a file runs what the patch login put there (`dpkg -i /tmp/x.deb`). Defence in depth
 * only: a relative argument resolves in the caller's directory, and no rule here can know
 * what a command does with its arguments.
 */
const WRITABLE_PATH = /(^|[=:])\/(tmp|var\/tmp|dev\/shm|home|run\/user)(\/|$)/;
const WRITABLE_MESSAGE =
  "may not name a path with .. or under /tmp, /var/tmp, /dev/shm, /home or /run/user";

function writablePath(token: string): boolean {
  return token.includes("..") || WRITABLE_PATH.test(token);
}

function checkEnv(
  env: Record<string, string>,
  ctx: z.RefinementCtx,
): void {
  const names = Object.keys(env);
  if (names.length > MAX_ENV) {
    ctx.addIssue({
      code: "custom",
      message: `at most ${MAX_ENV} env pairs per command`,
    });
  }
  for (const name of names) {
    if (deniedEnv(name)) {
      ctx.addIssue({
        code: "custom",
        path: [name],
        message: `${name} may not be set for a plug-in command`,
      });
    } else if (writablePath(env[name])) {
      ctx.addIssue({ code: "custom", path: [name], message: WRITABLE_MESSAGE });
    }
  }
}

const EnvName = z.string().regex(
  ENV_NAME,
  "env names are A-Z, 0-9 and _ (starting with A-Z, at most 64)",
);

/** One command as a plug-in declares it: argv (bin first), and optional fixed env. */
const PluginCommand = z.object({
  argv: z.array(z.string()).min(1, "argv needs at least the bin").max(
    MAX_ARGV,
    `argv has at most ${MAX_ARGV} tokens`,
  ).superRefine(checkArgv),
  env: z.record(EnvName, Token).superRefine(checkEnv).optional(),
}).strict();

/** The whole `privileges({ host })` result. Strict: an unknown key is an error. */
export const PluginPrivileges = z.object({
  commands: z.array(PluginCommand).max(
    MAX_PLUGIN_COMMANDS,
    `at most ${MAX_PLUGIN_COMMANDS} commands`,
  ),
  helpers: z.array(z.unknown()).refine(
    (h) => h.length === 0,
    "plug-in helpers are not supported in this release",
  ),
  remoteCode: z.boolean(),
  // Every source the plug-in fetches and runs code from: each one needs its own trustRemote
  // record. An updater whose code loads more code from a second repository names both.
  remoteSources: z.array(TrustSource).min(
    1,
    "remoteSources needs at least one source",
  ).max(MAX_REMOTE_SOURCES, `at most ${MAX_REMOTE_SOURCES} remoteSources`)
    .refine(
      (s) => new Set(s).size === s.length,
      "remoteSources names a source twice",
    ).optional(),
}).strict().superRefine((p, ctx) => {
  if (p.remoteCode && p.remoteSources === undefined) {
    ctx.addIssue({
      code: "custom",
      path: ["remoteSources"],
      message: "remoteSources is required when remoteCode is true",
    });
  }
  if (!p.remoteCode && p.remoteSources !== undefined) {
    ctx.addIssue({
      code: "custom",
      path: ["remoteSources"],
      message: "remoteSources is only for remoteCode: true",
    });
  }
});

/** A validated plug-in command as the provisioner receives and grants it. */
const PluginCommandRecord = z.object({
  id: z.string().regex(PLUGIN_ID, "must be plugin-<n>-<slug>"),
  capability: z.literal("plugin"),
  family: z.literal("plugin"),
  bin: z.string(),
  args: z.array(z.string()),
  env: z.record(z.string(), z.string()).optional(),
}).strict();

/** The slug of a model name for an id: lowercase letters, digits and dashes, at most 40. */
export function modelSlug(model: string): string {
  const s = model.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(
    /^-+|-+$/g,
    "",
  ).slice(0, 40).replace(/-+$/, "");
  return s || "model";
}

/** Where a zod issue sits: `commands[0].argv[0]`, or `declaration` for the whole object. */
function where(path: PropertyKey[]): string {
  if (path.length === 0) return "declaration";
  return path.map((p, i) => {
    if (typeof p === "number") return `[${p}]`;
    return i === 0 ? String(p) : `.${String(p)}`;
  }).join("");
}

function toPrivCommand(
  id: string,
  argv: string[],
  env: Record<string, string> | undefined,
): PrivCommand {
  const [bin, ...args] = argv;
  const cmd: PrivCommand = {
    id,
    capability: "plugin",
    family: "plugin",
    bin,
    args,
  };
  if (env && Object.keys(env).length > 0) cmd.env = { ...env };
  return cmd;
}

/** The result of parsing one model's declaration: its commands, or why it is refused. */
export type PluginParse =
  | {
    ok: true;
    commands: PrivCommand[];
    /** True when the plug-in runs code fetched at run time. */
    remoteCode: boolean;
    /** The sources it runs code from, when remoteCode is true; empty otherwise. */
    remoteSources: string[];
  }
  | { ok: false; errors: string[] };

/**
 * Validate one model's `privileges` result. `first` numbers the ids: the command at index i
 * gets `plugin-<first+i>-<slug of the model>`, so a caller that passes a running count keeps
 * the ids of several models apart. Returns the commands, or every error with its place.
 */
export function parsePluginPrivileges(
  model: string,
  raw: unknown,
  first = 1,
): PluginParse {
  const parsed = PluginPrivileges.safeParse(raw);
  if (!parsed.success) {
    return {
      ok: false,
      errors: parsed.error.issues.map((i) =>
        `privileges of "${model}": ${where(i.path)}: ${i.message}`
      ),
    };
  }
  const slug = modelSlug(model);
  const commands = parsed.data.commands.map((c, i) =>
    toPrivCommand(`plugin-${first + i}-${slug}`, c.argv, c.env)
  );
  return {
    ok: true,
    commands,
    remoteCode: parsed.data.remoteCode,
    remoteSources: parsed.data.remoteCode
      ? [...parsed.data.remoteSources!]
      : [],
  };
}

/**
 * Validate one argv that the fleet itself runs as root (a privileged health check), with the
 * rules of a plug-in command and no env. `id` must be a plug-in id: the command is granted
 * and audited like a plug-in's. Returns the command, or why it is refused.
 */
export function parseRootArgv(
  id: string,
  argv: unknown,
): { ok: true; command: PrivCommand } | { ok: false; error: string } {
  if (!PLUGIN_ID.test(id)) throw new Error(`not a plug-in command id: ${id}`);
  const parsed = PluginCommand.safeParse({ argv });
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    return {
      ok: false,
      error: `${where(issue?.path ?? [])}: ${issue?.message ?? "invalid"}`,
    };
  }
  return { ok: true, command: toPrivCommand(id, parsed.data.argv, undefined) };
}

/**
 * Check the plug-in commands again where the provisioner receives them: the same rules as the
 * parser, and the id, capability and family the parser gives. Throws on the first problem, so
 * the provisioner never grants a command that the parser would refuse.
 */
export function validatePluginCommands(list: unknown): PrivCommand[] {
  if (!Array.isArray(list)) throw new Error("plug-in commands must be a list");
  if (list.length > MAX_MACHINE_PLUGIN_COMMANDS) {
    throw new Error(
      `at most ${MAX_MACHINE_PLUGIN_COMMANDS} plug-in commands per machine`,
    );
  }
  const ids = new Set<string>();
  return list.map((raw, i) => {
    const rec = PluginCommandRecord.safeParse(raw);
    if (!rec.success) {
      const issue = rec.error.issues[0];
      throw new Error(
        `plug-in command ${i}: ${where(issue?.path ?? [])}: ${
          issue?.message ?? "invalid"
        }`,
      );
    }
    const g = rec.data;
    const checked = PluginCommand.safeParse({
      argv: [g.bin, ...g.args],
      ...(g.env ? { env: g.env } : {}),
    });
    if (!checked.success) {
      const issue = checked.error.issues[0];
      throw new Error(
        `plug-in command ${g.id}: ${where(issue.path)}: ${issue.message}`,
      );
    }
    if (ids.has(g.id)) {
      throw new Error(`plug-in command ${g.id} is listed twice`);
    }
    ids.add(g.id);
    return toPrivCommand(g.id, checked.data.argv, checked.data.env);
  });
}
