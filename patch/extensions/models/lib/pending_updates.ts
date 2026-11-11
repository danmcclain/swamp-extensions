/**
 * The pending OS updates of one host: the packages the scan counts, by name.
 *
 * The collector already reads the package manager's list to count it (apt's simulated
 * dist-upgrade, dnf check-update, apk version, checkupdates or pacman -Qu). It ships that
 * text base64 on one line, as it does the docker inventory file, and never builds JSON
 * from it. This parser reads the same lines the collector counts, checks every field
 * against a narrow pattern, and only its result is stored: the text itself never is.
 *
 * A line the count includes but this parser cannot read makes the whole list unknown
 * (null), never a shorter list: a list that silently drops packages would hide updates.
 *
 * @module
 */
import { z } from "npm:zod@4";

/** The most entries stored for one host. A longer list is cut, and says so. */
export const PENDING_LIMIT = 1000;

/** The most base64 characters read for one list (the collector also caps its lines). */
const MAX_BASE64_CHARS = 2_000_000;

/**
 * One pending update. The strings reach stored data and Markdown reports, so each takes
 * only the characters its package manager uses: no control characters or markup.
 */
export const PendingUpdate = z.object({
  name: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._+@-]{0,199}$/),
  arch: z.string().regex(/^[A-Za-z0-9_]{1,32}$/).nullable(),
  /** The installed version, when the package manager reports it (dnf does not). */
  from: z.string().regex(/^[A-Za-z0-9._+:~^-]{1,200}$/).nullable(),
  to: z.string().regex(/^[A-Za-z0-9._+:~^-]{1,200}$/),
  /** The repository or origin, when the package manager reports it. */
  source: z.string().regex(/^[A-Za-z0-9 ._,:\/@+~-]{1,300}$/).nullable(),
  /** true or false where the host has a security channel; null where it has none. */
  security: z.boolean().nullable(),
}).strict();

export type PendingUpdateT = z.infer<typeof PendingUpdate>;

export type ParsedPending =
  | { ok: true; items: PendingUpdateT[]; truncated: boolean }
  | { ok: false; error: string };

/** Base64 to UTF-8 text; null when it is not both. An empty string is empty text. */
function decode(b64: string): string | null {
  if (b64.length > MAX_BASE64_CHARS) return null;
  try {
    const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function lines(text: string): string[] {
  return text.split("\n").map((l) => l.replace(/\r$/, ""));
}

type Row = Omit<PendingUpdateT, "security"> & { security?: boolean | null };

// apt: `Inst <name> [<installed>] (<new> <origins> [<arch>])`, maybe followed by ` []`.
// A new package (a dependency the upgrade pulls in) has no installed version.
const APT_INST =
  /^Inst (\S+) (?:\[(\S+)\] )?\((\S+) (.+?)(?: \[([A-Za-z0-9_]+)\])?\)(?: \[[^\]]*\])?$/;
// The collector's own security test, per line (grep -iE '(-security|Security:)').
const APT_SECURITY = /(-security|Security:)/i;

function parseApt(text: string): Row[] | string {
  const rows: Row[] = [];
  for (const l of lines(text)) {
    if (!l.startsWith("Inst")) continue;
    const m = APT_INST.exec(l);
    if (!m) return `an apt line does not parse: ${l.slice(0, 80)}`;
    rows.push({
      name: m[1],
      arch: m[5] ?? null,
      from: m[2] ?? null,
      to: m[3],
      source: m[4],
      security: APT_SECURITY.test(l),
    });
  }
  return rows;
}

// dnf check-update: `<name>.<arch> <version> <repo>`. The "Obsoleting Packages" section
// that may follow repeats packages (with the installed one indented): it is not read.
const DNF_CANDIDATE = /^[A-Za-z0-9._+-]+\.[A-Za-z0-9_]+\s/;
const DNF_ROW = /^(\S+)\.([A-Za-z0-9_]+)\s+(\S+)\s+(\S+)\s*$/;

function dnfRows(text: string): Row[] | string {
  const rows: Row[] = [];
  for (const l of lines(text)) {
    if (/^Obsoleting Packages/i.test(l)) break;
    if (!DNF_CANDIDATE.test(l)) continue;
    const m = DNF_ROW.exec(l);
    if (!m) return `a dnf line does not parse: ${l.slice(0, 80)}`;
    rows.push({ name: m[1], arch: m[2], from: null, to: m[3], source: m[4] });
  }
  return rows;
}

// apk version -l '<': `<name>-<installed> < <new>`; apk versions end in -r<N>.
const APK_ROW = /^(\S+)-([^-\s]+-r\d+)\s+<\s+(\S+)\s*$/;

function parseApk(text: string): Row[] | string {
  const rows: Row[] = [];
  for (const l of lines(text)) {
    if (!l.includes("<")) continue;
    const m = APK_ROW.exec(l);
    if (!m) return `an apk line does not parse: ${l.slice(0, 80)}`;
    rows.push({
      name: m[1],
      arch: null,
      from: m[2],
      to: m[3],
      source: null,
      security: null,
    });
  }
  return rows;
}

// checkupdates and pacman -Qu: `<name> <installed> -> <new>`, maybe ` [ignored]`.
const PACMAN_ROW = /^(\S+) (\S+) -> (\S+)( \[ignored\])?$/;

function pacmanRows(text: string): Row[] | string {
  const rows: Row[] = [];
  for (const l of lines(text)) {
    if (l.trim() === "") continue;
    const m = PACMAN_ROW.exec(l);
    if (!m) return `a pacman line does not parse: ${l.slice(0, 80)}`;
    if (m[4]) continue; // pacman will not upgrade an ignored package; the count skips it too.
    rows.push({ name: m[1], arch: null, from: m[2], to: m[3], source: null });
  }
  return rows;
}

/** The names in a list of one name per line (arch-audit -u -q). */
function nameSet(text: string): Set<string> | string {
  const s = new Set<string>();
  for (const l of lines(text)) {
    const t = l.trim();
    if (t === "") continue;
    if (!/^[A-Za-z0-9][A-Za-z0-9._+@-]{0,199}$/.test(t)) {
      return `a security line does not parse: ${t.slice(0, 80)}`;
    }
    s.add(t);
  }
  return s;
}

/** dnf rows keyed by name.arch, so the security list can mark them. */
function dnfKeys(rows: Row[]): Set<string> {
  return new Set(rows.map((r) => `${r.name}.${r.arch}`));
}

/**
 * The pending updates from the collector's base64 lists. `secB64` is the security list
 * (dnf check-update --security, arch-audit -u -q), or null when the host has no security
 * channel or its check failed: then `security` is null for every entry (apt and apk
 * carry their own answer). An unknown package manager has no list.
 */
export function parsePending(
  packageManager: string,
  b64: string,
  secB64: string | null,
): ParsedPending {
  const text = decode(b64);
  if (text === null) {
    return { ok: false, error: "the pending list is not base64 UTF-8" };
  }
  let rows: Row[] | string;
  if (packageManager === "apt") rows = parseApt(text);
  else if (packageManager === "apk") rows = parseApk(text);
  else if (packageManager === "dnf" || packageManager === "pacman") {
    rows = packageManager === "dnf" ? dnfRows(text) : pacmanRows(text);
    if (typeof rows !== "string") {
      let secure: Set<string> | null = null;
      if (secB64 !== null) {
        const secText = decode(secB64);
        if (secText === null) {
          return { ok: false, error: "the security list is not base64 UTF-8" };
        }
        if (packageManager === "dnf") {
          const secRows = dnfRows(secText);
          if (typeof secRows === "string") return { ok: false, error: secRows };
          secure = dnfKeys(secRows);
        } else {
          const names = nameSet(secText);
          if (typeof names === "string") return { ok: false, error: names };
          secure = names;
        }
      }
      const isDnf = packageManager === "dnf";
      rows = rows.map((r) => ({
        ...r,
        security: secure === null
          ? null
          : secure.has(isDnf ? `${r.name}.${r.arch}` : r.name),
      }));
    }
  } else {
    return {
      ok: false,
      error: `no pending list for package manager ${packageManager}`,
    };
  }
  if (typeof rows === "string") return { ok: false, error: rows };
  const checked = z.array(PendingUpdate).safeParse(rows);
  if (!checked.success) {
    const issues = checked.error.issues.slice(0, 3).map((i) =>
      `${i.path.join(".")}: ${i.message}`
    ).join("; ");
    return { ok: false, error: `the pending list does not match: ${issues}` };
  }
  const items = checked.data;
  return {
    ok: true,
    items: items.slice(0, PENDING_LIMIT),
    truncated: items.length > PENDING_LIMIT,
  };
}
