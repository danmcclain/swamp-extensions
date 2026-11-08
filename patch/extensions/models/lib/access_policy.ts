/**
 * Access policy for @dmc/patch/fleet.
 *
 * Acceptance records are an explicit, reasoned, time-limited acceptance of a
 * security risk: an unsafe path enabled for one machine, trust in code fetched at
 * run time, or one audit finding. The access profile is the unprivileged
 * `swamp-patch` login used from swamp serve, with the one public key allowed to
 * use it. Nothing reads these fields yet; they are declared here first.
 *
 * @module
 */
import { z } from "npm:zod@4";

/** YYYY-MM-DD that is a real calendar date (2026-02-30 is invalid). */
export const Day = z.string().regex(/^\d{4}-\d{2}-\d{2}$/).refine(
  isValidDay,
  "not a real calendar date (YYYY-MM-DD)",
);

const AcceptanceFields = z.object({
  reason: z.string().trim().min(10).describe(
    "Why this risk is accepted (min 10 chars)",
  ),
  acceptedBy: z.string().trim().min(1).describe("Who accepted it"),
  acceptedAt: Day.describe("When it was accepted (YYYY-MM-DD)"),
  reviewBy: Day.describe(
    "Review date; after it the record is overdue (YYYY-MM-DD)",
  ),
}).strict();

/** A record expires within a year: reviewBy is at most 365 days after acceptedAt. */
const MAX_REVIEW_DAYS = 365;

function reviewWindowOk(
  r: { acceptedAt: string; reviewBy: string },
): boolean {
  if (r.reviewBy < r.acceptedAt) return false;
  const [y, m, d] = r.acceptedAt.split("-").map(Number);
  const last = Date.UTC(y, m - 1, d + MAX_REVIEW_DAYS);
  const [ry, rm, rd] = r.reviewBy.split("-").map(Number);
  return Date.UTC(ry, rm - 1, rd) <= last;
}

const REVIEW_RULE = {
  message:
    "reviewBy must be on or after acceptedAt and at most 365 days after it",
  path: ["reviewBy"],
};

export const AcceptanceRecord = AcceptanceFields.refine(
  reviewWindowOk,
  REVIEW_RULE,
);

export const UNSAFE_KEYS = [
  "pctExec",
  "rootSsh",
  "privilegedUpdater",
  "privilegedHealth",
] as const;
export type UnsafeKey = typeof UNSAFE_KEYS[number];

export const Unsafe = z.object({
  pctExec: AcceptanceRecord.optional(),
  rootSsh: AcceptanceRecord.optional(),
  privilegedUpdater: AcceptanceRecord.optional(),
  privilegedHealth: AcceptanceRecord.optional(),
}).strict().describe(
  "Each key that is present is an accepted risk that enables an unsafe path for this machine.",
);

/** A remote code source: `owner/repo@ref`, as a plug-in declares it and a trustRemote record names it. */
export const TrustSource = z.string().regex(
  /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+@[A-Za-z0-9._\/-]+$/,
  "must name a source as owner/repo@ref",
);

export const TrustRemote = AcceptanceFields.extend({
  source: TrustSource,
}).strict().refine(reviewWindowOk, REVIEW_RULE);

export const AcceptedRisk = AcceptanceFields.extend({
  finding: z.string().max(200).regex(
    /^[a-z0-9-]+(:[A-Za-z0-9._@\/-]*)*$/,
  ),
}).strict().refine(reviewWindowOk, REVIEW_RULE);

function isIPv4(s: string): boolean {
  const parts = s.split(".");
  return parts.length === 4 &&
    parts.every((p) => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
}

function isIPv6(s: string): boolean {
  if (!/^[0-9a-fA-F:]+$/.test(s) || s.split(":").length < 3) return false;
  const parts = s.split("::");
  if (parts.length > 2) return false;
  const groups = parts.flatMap((part) => (part === "" ? [] : part.split(":")));
  if (!groups.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g))) return false;
  return parts.length === 2 ? groups.length <= 7 : groups.length === 8;
}

/** An IPv4 or IPv6 address, optionally with a CIDR prefix (/1-/32, /1-/128). A /0 prefix is "any address" and is refused. */
export function isSourceAddr(s: string): boolean {
  const slash = s.indexOf("/");
  const addr = slash === -1 ? s : s.slice(0, slash);
  const prefix = slash === -1 ? null : s.slice(slash + 1);
  if (prefix !== null && !/^(0|[1-9]\d*)$/.test(prefix)) return false;
  if (prefix === "0") return false;
  if (isIPv4(addr)) return prefix === null || Number(prefix) <= 32;
  if (isIPv6(addr)) return prefix === null || Number(prefix) <= 128;
  return false;
}

export const SourceAddr = z.string().refine(
  isSourceAddr,
  "must be an IP address or CIDR",
);

export const AccessProfile = z.object({
  user: z.string().regex(/^[a-z_][a-z0-9_-]{0,31}$/).refine(
    (u) => u !== "root" && u !== "toor",
    "the access user must not be root",
  ).default("swamp-patch"),
  publicKey: z.string().regex(
    /^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+\/]{43}( [A-Za-z0-9@._:+-]{1,64})?$/,
  ).describe("The ONE public key allowed to log in as `user` (ed25519 only)"),
  from: z.array(SourceAddr).min(1).describe(
    "Default source addresses for the authorized_keys from= option",
  ),
  provisionSshModel: z.string().min(1).describe(
    "Root-capable @swamp/ssh model used ONLY by the access methods (provision/audit/revoke); never by scan/update",
  ),
}).strict();

export type AcceptanceRecordT = z.infer<typeof AcceptanceRecord>;
export type UnsafeT = z.infer<typeof Unsafe>;
export type TrustRemoteT = z.infer<typeof TrustRemote>;
export type AcceptedRiskT = z.infer<typeof AcceptedRisk>;
export type AccessProfileT = z.infer<typeof AccessProfile>;

/** True only for a YYYY-MM-DD string that names a real calendar day (UTC). */
export function isValidDay(s: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s + "T00:00:00Z");
  return d.getUTCFullYear() === Number(s.slice(0, 4)) &&
    d.getUTCMonth() + 1 === Number(s.slice(5, 7)) &&
    d.getUTCDate() === Number(s.slice(8, 10));
}

/**
 * True when `now` is on or after the UTC day after `reviewBy`: the review day itself
 * is not overdue. A reviewBy that is not a real day is overdue (fails closed).
 */
export function isOverdue(rec: { reviewBy: string }, now: Date): boolean {
  if (!isValidDay(rec.reviewBy)) return true;
  const [y, m, d] = rec.reviewBy.split("-").map(Number);
  return now.getTime() >= Date.UTC(y, m - 1, d + 1);
}

/** The acceptance record for one unsafe key of a machine, or null when absent. */
export function unsafeRecord(
  m: { unsafe?: UnsafeT },
  key: UnsafeKey,
): AcceptanceRecordT | null {
  return m.unsafe?.[key] ?? null;
}
