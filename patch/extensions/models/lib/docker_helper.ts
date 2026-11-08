/**
 * The root-owned docker helper of the swamp-patch access login.
 *
 * Once the login is out of the docker group it cannot run docker, so the runtime (safeUpdate,
 * pruneImages) reaches docker only through this helper: a bash script that runs as root
 * through `sudo -n`, with a fixed set of subcommands. The sudoers grant names the helper's
 * path and no arguments, so the helper is the gate: it validates every argument against a
 * strict pattern, and it refuses the whole call when its project list is not intact.
 *
 * This module is pure. It has no imports, so the provisioning and the audit can both use it
 * without a cycle. It generates the helper text, the project list, and the TS validators the
 * runtime uses before it builds a command line.
 *
 * @module
 */

/** Where the helper is installed on the host, and the directory and file of the project list. */
export const DOCKER_HELPER_PATH =
  "/usr/local/libexec/swamp-patch/swamp-patch-docker";
export const DOCKER_PROJECTS_DIR = "/etc/swamp-patch";
export const DOCKER_PROJECTS_PATH = "/etc/swamp-patch/docker-projects";

/** One compose project the helper may run: a name, its compose directory, and its service. */
export interface DockerProject {
  name: string;
  composeDir: string;
  /** The compose service the commands target, or "-" for every service of the project. */
  service: string;
}

/** The subcommands and how many arguments each takes after the subcommand name. */
const ARG_COUNT = {
  ps: 1,
  inspect: 1,
  update: 1,
  restore: 3,
  prune: 1,
} as const;
export type HelperSub = keyof typeof ARG_COUNT;

const PROJECT_NAME = /^[a-z0-9][a-z0-9_-]{0,62}$/;
const SERVICE = /^(-|[A-Za-z0-9][A-Za-z0-9_.-]{0,62})$/;
const COMPOSE_DIR = /^\/[A-Za-z0-9._/-]+$/;
const IMAGE_REF = /^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$/;
const IMAGE_ID = /^sha256:[0-9a-f]{64}$/;

/** A compose directory: an absolute plain path with no `..` and no empty segment. */
function plainDir(p: string): boolean {
  return COMPOSE_DIR.test(p) && !p.includes("..") && !p.includes("//");
}

/**
 * The project name of a machine's compose directory: its basename, lowercased, with every
 * character outside [a-z0-9_-] turned into `-`. Throws when the result is not a valid name, so
 * a machine is never given a name the helper would refuse.
 */
export function dockerProjectName(composePath: string): string {
  if (typeof composePath !== "string" || !plainDir(composePath)) {
    throw new Error(
      `the docker composePath must be an absolute path of letters, digits, . _ / or - (got ${
        JSON.stringify(composePath ?? null)
      })`,
    );
  }
  const base = composePath.replace(/\/+$/, "").split("/").pop() ?? "";
  const name = base.toLowerCase().replace(/[^a-z0-9_-]/g, "-");
  if (!PROJECT_NAME.test(name)) {
    throw new Error(
      `the docker composePath ${composePath} gives the project name "${name}", which is not valid: name the directory with a letter or digit first, then letters, digits, _ or -, up to 63 characters`,
    );
  }
  return name;
}

/** One project, checked: every field against its pattern. Returns a copy. Throws on the first problem. */
export function validateDockerProject(p: DockerProject): DockerProject {
  if (typeof p !== "object" || p === null) {
    throw new Error("a docker project must be an object");
  }
  if (typeof p.name !== "string" || !PROJECT_NAME.test(p.name)) {
    throw new Error(
      `the docker project name must be 1-63 characters of a-z, 0-9, _ or -, starting with a-z or 0-9 (got ${
        JSON.stringify(p.name ?? null)
      })`,
    );
  }
  if (typeof p.composeDir !== "string" || !plainDir(p.composeDir)) {
    throw new Error(
      `the docker composeDir must be an absolute path of letters, digits, . _ / or -, with no .. or //: ${
        JSON.stringify(p.composeDir ?? null)
      }`,
    );
  }
  if (typeof p.service !== "string" || !SERVICE.test(p.service)) {
    throw new Error(
      `the docker service must be "-" (every service) or a compose service name: ${
        JSON.stringify(p.service ?? null)
      }`,
    );
  }
  return { name: p.name, composeDir: p.composeDir, service: p.service };
}

/** The project list of one host: each project checked, and no name listed twice. */
export function validateDockerProjects(list: DockerProject[]): DockerProject[] {
  if (!Array.isArray(list)) {
    throw new Error("dockerProjects must be a list");
  }
  const out = list.map(validateDockerProject);
  const names = new Set<string>();
  for (const p of out) {
    if (names.has(p.name)) {
      throw new Error(`the docker project name ${p.name} is listed twice`);
    }
    names.add(p.name);
  }
  return out;
}

/**
 * The text of the project list: the managed header as a `#` comment line (the helper skips
 * comment lines), then one `name<TAB>composeDir<TAB>service` line per project.
 */
export function dockerProjectsFile(
  projects: DockerProject[],
  managedHeader: string,
): string {
  const lines = validateDockerProjects(projects).map((p) =>
    `${p.name}\t${p.composeDir}\t${p.service}\n`
  );
  return `${managedHeader}\n${lines.join("")}`;
}

/**
 * The argv of one helper call: the helper's fixed path, the subcommand, and its arguments.
 * Throws for an unknown subcommand, a wrong argument count, or an argument that does not
 * match its pattern. The runtime shell-quotes each word; nothing else is added.
 */
export function helperArgv(sub: HelperSub, ...args: string[]): string[] {
  if (!Object.hasOwn(ARG_COUNT, sub)) {
    throw new Error(`no swamp-patch-docker subcommand named ${String(sub)}`);
  }
  if (args.length !== ARG_COUNT[sub]) {
    throw new Error(
      `swamp-patch-docker ${sub} takes ${
        ARG_COUNT[sub]
      } argument(s), got ${args.length}`,
    );
  }
  if (args.some((a) => typeof a !== "string")) {
    throw new Error("swamp-patch-docker arguments must be strings");
  }
  if (sub === "prune") {
    if (!IMAGE_ID.test(args[0])) {
      throw new Error(
        `the image id must be sha256: and 64 lowercase hex digits`,
      );
    }
  } else {
    if (!PROJECT_NAME.test(args[0])) {
      throw new Error(`the docker project name is not valid: ${args[0]}`);
    }
    if (sub === "restore") {
      if (!IMAGE_REF.test(args[1])) {
        throw new Error(`the image ref is not valid: ${args[1]}`);
      }
      if (!IMAGE_ID.test(args[2])) {
        throw new Error(
          `the image id must be sha256: and 64 lowercase hex digits`,
        );
      }
    }
  }
  return [DOCKER_HELPER_PATH, sub, ...args];
}

/** The helper's body. It has no host data in it: the project list is read at run time. */
const BODY = String
  .raw`# Runs as root through sudo, for the restricted swamp-patch login. It is the one gate between that
# login and docker. Fixed subcommands only; the project list is re-read and re-checked on every call,
# and one bad line refuses the whole call. Each argument is checked against a strict pattern before
# it is used. Nothing from the caller is run as code: arguments are only quoted words after checks.
#
#   swamp-patch-docker ps <project>
#   swamp-patch-docker inspect <project>
#   swamp-patch-docker update <project>
#   swamp-patch-docker restore <project> <image-ref> <image-id>
#   swamp-patch-docker prune <image-id>
#
# Exit 2: refused (usage, a bad argument, a bad project list). Anything else is docker's own status.
set -euo pipefail
umask 022
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY COMPOSE_FILE COMPOSE_PROJECT_NAME COMPOSE_PROFILES BASH_ENV ENV

die() {
  echo "swamp-patch-docker: $*" >&2
  exit 2
}

usage() {
  echo "usage: swamp-patch-docker ps|inspect|update <project>" >&2
  echo "       swamp-patch-docker restore <project> <image-ref> <image-id>" >&2
  echo "       swamp-patch-docker prune <image-id>" >&2
  exit 2
}

# True when the octal mode $1 has no group- or world-write bit. A mode that is not octal is refused.
no_gw() {
  [[ $1 =~ ^[0-7]+$ ]] || return 1
  (( (8#$1 & 8#022) == 0 ))
}

# True when $1 is a root-owned directory, not a symlink, that no other account may write.
trusted_dir() {
  local m
  [ -d "$1" ] && [ ! -L "$1" ] && [ -O "$1" ] || return 1
  m="$(stat -c %a "$1" 2>/dev/null)" || return 1
  no_gw "$m"
}

# True when $1 is a root-owned regular file, not a symlink, that no other account may write.
trusted_file() {
  local m
  [ -f "$1" ] && [ ! -L "$1" ] && [ -O "$1" ] || return 1
  m="$(stat -c %a "$1" 2>/dev/null)" || return 1
  no_gw "$m"
}

valid_project() { [[ $1 =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]]; }
valid_service() { [ "$1" = "-" ] || [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]]; }
valid_ref() { [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$ ]]; }
valid_image_id() { [[ $1 =~ ^sha256:[0-9a-f]{64}$ ]]; }

# A compose directory: an absolute plain path with no .. and no empty segment, that exists.
valid_dir() {
  [[ $1 =~ ^/[A-Za-z0-9._/-]+$ ]] || return 1
  case "$1" in
    *..* | *//*) return 1 ;;
  esac
  [ -d "$1" ]
}

# The project list and its directory must be root's: a root-owned directory and file, not symlinks,
# with no group or world write, and a root-owned /etc above them. Checked on every call.
check_list() {
  trusted_dir /etc || die "/etc is not a root-owned directory without group or world write"
  trusted_dir "$PROJECTS_DIR" || die "$PROJECTS_DIR is not a root-owned directory without group or world write"
  trusted_file "$PROJECTS_FILE" || die "$PROJECTS_FILE is not a root-owned regular file without group or world write"
}

# Reads the whole project list, checks every line, and sets P_NAME, P_DIR and P_SVC for project $1.
# Every call runs this, prune included: a bad line refuses the call. A comment line (starting with #)
# is skipped; any other line must have exactly three tab-separated fields, each valid. With $2 = yes,
# $1 must be a valid project name, listed exactly once; with $2 = no (prune), there is no project.
scan_list() {
  local want="$1" need="$2" tab line n=0 hits=0 name dir svc
  if [ "$need" = yes ]; then
    valid_project "$want" || die "the project name is not valid"
  fi
  tab=$'\t'
  P_NAME=""
  P_DIR=""
  P_SVC=""
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    case "$line" in
      '#'*) continue ;;
    esac
    case "$line" in
      *"$tab"*"$tab"*"$tab"*) die "the project list has too many fields on line $n" ;;
      *"$tab"*"$tab"*) ;;
      *) die "the project list has too few fields on line $n" ;;
    esac
    IFS="$tab" read -r name dir svc <<<"$line"
    valid_project "$name" || die "the project list has a bad name on line $n"
    valid_dir "$dir" || die "the project list has a bad composeDir on line $n"
    valid_service "$svc" || die "the project list has a bad service on line $n"
    if [ "$need" = yes ] && [ "$name" = "$want" ]; then
      hits=$((hits + 1))
      P_NAME="$name"
      P_DIR="$dir"
      P_SVC="$svc"
    fi
  done <"$PROJECTS_FILE"
  if [ "$need" = yes ]; then
    [ "$hits" -eq 1 ] || die "project $want is not listed exactly once in the project list"
  fi
}

# docker compose in the project's directory, with the fixed arguments and the project's service.
compose() {
  if [ "$P_SVC" = "-" ]; then
    (cd "$P_DIR" && docker compose "$@")
  else
    (cd "$P_DIR" && docker compose "$@" "$P_SVC")
  fi
}

# One line per container of the project: id|configImage|imageId|state|health.
inspect_project() {
  local ids id
  ids="$(compose ps -q)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    [[ $id =~ ^[0-9a-f]{12,64}$ ]] || die "docker printed a container id that is not hex"
    docker inspect "$id" --format '{{.Id}}|{{.Config.Image}}|{{.Image}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}'
  done <<<"$ids"
}

# Rolls one image back: the ref must be the image of a current container of the project, and the
# image id must be present on this host. Then the ref is tagged to the old image, and the project
# is recreated with it.
restore_image() {
  local ref="$1" image="$2" rows line _id cref _rest got found=0
  valid_ref "$ref" || die "the image ref is not valid"
  valid_image_id "$image" || die "the image id must be sha256: and 64 lowercase hex digits"
  rows="$(inspect_project)"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    IFS='|' read -r _id cref _rest <<<"$line"
    if [ "$cref" = "$ref" ]; then found=1; fi
  done <<<"$rows"
  [ "$found" -eq 1 ] || die "the image ref is not the image of a container of this project"
  got="$(docker image inspect --format '{{.Id}}' "$image" 2>/dev/null)" || die "the image id is not present on this host"
  [ "$got" = "$image" ] || die "the image id is not present on this host"
  docker tag "$image" "$ref"
  compose up -d --force-recreate
}

main() {
  [ "$(id -u)" -eq 0 ] || die "must run as root"
  [ "$#" -ge 1 ] || usage
  local sub="$1"
  shift
  case "$sub" in
    ps | inspect | update) [ "$#" -eq 1 ] || usage ;;
    restore) [ "$#" -eq 3 ] || usage ;;
    prune) [ "$#" -eq 1 ] || usage ;;
    *) usage ;;
  esac
  check_list
  if [ "$sub" = prune ]; then
    valid_image_id "$1" || die "the image id must be sha256: and 64 lowercase hex digits"
    scan_list "" no
    docker rmi "$1"
    return 0
  fi
  scan_list "$1" yes
  case "$sub" in
    ps) compose ps -q ;;
    inspect) inspect_project ;;
    update)
      compose pull
      compose up -d
      ;;
    restore) restore_image "$2" "$3" ;;
  esac
}

main "$@" </dev/null
`;

/**
 * The helper script. Its text is constant for a given header, so the audit knows its sha256
 * without a host. The header is the managed-file header (a `#` comment line).
 */
export function dockerHelperScript(managedHeader: string): string {
  if (!managedHeader.startsWith("#") || managedHeader.includes("\n")) {
    throw new Error("the managed header must be one comment line");
  }
  return `#!/bin/bash
${managedHeader}
PROJECTS_DIR='${DOCKER_PROJECTS_DIR}'
PROJECTS_FILE='${DOCKER_PROJECTS_PATH}'
${BODY}`;
}
