import { z } from "npm:zod@^4.4.3";

// ---------------------------------------------------------------------------
// @dmc/fastmail — a Fastmail email-organization pipeline over JMAP:
//
//   email_senders   — fan-out scan of ALL senders in one or more scopes,
//                     recording bulk-ness (List-Id / List-Unsubscribe) as a
//                     per-sender attribute rather than a filter.
//   sieve_generate  — config-driven fan-out that categorizes senders into
//                     (nested) folders and writes ready-to-paste Sieve scripts.
//
// Bulk detection uses the RFC 2369 / 8058 List-* headers, fetched via JMAP's
// `header:{name}` property syntax (RFC 8621 §4.1.1). Newsletters become one
// fallback category, not the whole universe.
// ---------------------------------------------------------------------------

const JMAP_MAIL_URN = "urn:ietf:params:jmap:mail";
const DEFAULT_SESSION_URL = "https://api.fastmail.com/.well-known/jmap";

// Standalone @dmc/fastmail model: Fastmail-specific email organization over JMAP.
// Self-contained JMAP transport below (no external model dependency).
const GlobalArgsSchema = z.object({
  apiToken: z.string()
    .meta({ sensitive: true })
    .optional()
    .describe(
      "Read-only Fastmail JMAP API token (Bearer). Preferred for all read methods. Optional if writeToken is set — a write token also has read scope. At least one of apiToken/writeToken is required.",
    ),
  writeToken: z.string()
    .meta({ sensitive: true })
    .optional()
    .describe(
      "Write-scoped Fastmail token. Required by email_move (execute:true), and used as the read token when apiToken is unset. Leave unset (with apiToken set) to keep the model read-only.",
    ),
  sessionUrl: z.string().url()
    .default(DEFAULT_SESSION_URL)
    .describe("JMAP session discovery URL (defaults to Fastmail)"),
});

/**
 * Resolve the token used for READ operations: prefer the read-only `apiToken`,
 * fall back to `writeToken` (which also carries read scope). So a read-only
 * `apiToken` alone runs every read method, a `writeToken` alone runs everything,
 * and setting both keeps reads on the least-privilege token. `email_move` does
 * NOT use this — it requires `writeToken` explicitly.
 */
function resolveReadToken(
  g: { apiToken?: string; writeToken?: string },
): string {
  const token = g.apiToken ?? g.writeToken;
  if (!token) {
    throw new Error(
      "No Fastmail token: set apiToken (read) or writeToken (read+write) in globalArguments.",
    );
  }
  return token;
}

interface JmapSession {
  apiUrl: string;
  primaryAccounts: Record<string, string>;
}

interface JmapResponse {
  methodResponses: [string, Record<string, unknown>, string][];
}

async function fetchSession(
  apiToken: string,
  sessionUrl: string,
): Promise<JmapSession> {
  const resp = await fetch(sessionUrl, {
    headers: { Authorization: `Bearer ${apiToken}` },
    signal: AbortSignal.timeout(10_000),
  });
  if (!resp.ok) {
    throw new Error(
      `JMAP session fetch failed: HTTP ${resp.status} ${resp.statusText}`,
    );
  }
  return resp.json() as Promise<JmapSession>;
}

async function jmapRequest(
  apiUrl: string,
  apiToken: string,
  methodCalls: unknown[],
): Promise<JmapResponse> {
  const resp = await fetch(apiUrl, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      using: ["urn:ietf:params:jmap:core", JMAP_MAIL_URN],
      methodCalls,
    }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!resp.ok) {
    throw new Error(
      `JMAP request failed: HTTP ${resp.status} ${resp.statusText}`,
    );
  }
  return resp.json() as Promise<JmapResponse>;
}

function unwrapMethodResponse(
  resp: JmapResponse,
  expectedMethod: string,
): Record<string, unknown> {
  if (resp.methodResponses.length === 0) {
    throw new Error(
      `JMAP returned empty methodResponses for ${expectedMethod}`,
    );
  }
  const [name, result] = resp.methodResponses[0];
  if (name === "error") {
    throw new Error(
      `JMAP method error for ${expectedMethod}: ${JSON.stringify(result)}`,
    );
  }
  return result as Record<string, unknown>;
}

interface Mailbox {
  id: string;
  role: string | null;
  name: string;
  parentId: string | null;
}

/** Fetch mailboxes so scopes can target by role and categories by folder path. */
async function fetchMailboxes(
  apiUrl: string,
  apiToken: string,
  accountId: string,
): Promise<Mailbox[]> {
  const resp = await jmapRequest(apiUrl, apiToken, [
    ["Mailbox/get", { accountId, ids: null }, "0"],
  ]);
  const r = unwrapMethodResponse(resp, "Mailbox/get") as { list: Mailbox[] };
  return r.list ?? [];
}

/** Map a full folder path (lowercased, "/"-joined) to its JMAP mailbox id. */
function buildPathIndex(mailboxes: Mailbox[]): Map<string, string> {
  const byId = new Map(mailboxes.map((m) => [m.id, m]));
  const pathOf = (m: Mailbox): string => {
    const parts: string[] = [];
    let cur: Mailbox | undefined = m;
    const seen = new Set<string>();
    while (cur && !seen.has(cur.id)) {
      seen.add(cur.id);
      parts.unshift(cur.name);
      cur = cur.parentId ? byId.get(cur.parentId) : undefined;
    }
    return parts.join("/").toLowerCase();
  };
  const idx = new Map<string, string>();
  for (const m of mailboxes) idx.set(pathOf(m), m.id);
  return idx;
}

/**
 * Resolve a category path ("Finance/Statements") to a mailbox id, creating any
 * missing segments (nested) via Mailbox/set — mirrors the sieve's `:create`.
 * Mutates `mailboxes` so later lookups in the same run see newly-created ids.
 * Returns { id, created } where `created` lists the paths it had to make.
 */
async function ensureMailbox(
  apiUrl: string,
  apiToken: string,
  accountId: string,
  category: string,
  mailboxes: Mailbox[],
): Promise<{ id: string; created: string[] }> {
  const idx = buildPathIndex(mailboxes);
  const created: string[] = [];
  let parentId: string | null = null;
  let path = "";
  let leafId = "";
  for (const seg of category.split("/")) {
    path = path ? `${path}/${seg}` : seg;
    const existing = idx.get(path.toLowerCase());
    if (existing) {
      parentId = existing;
      leafId = existing;
      continue;
    }
    const resp = await jmapRequest(apiUrl, apiToken, [
      [
        "Mailbox/set",
        { accountId, create: { new: { name: seg, parentId } } },
        "0",
      ],
    ]);
    const r = unwrapMethodResponse(resp, "Mailbox/set") as {
      created?: Record<string, { id: string }>;
      notCreated?: Record<string, unknown>;
    };
    const newId = r.created?.new?.id;
    if (!newId) {
      throw new Error(
        `Failed to create mailbox "${path}": ${
          JSON.stringify(r.notCreated ?? r)
        }`,
      );
    }
    mailboxes.push({ id: newId, role: null, name: seg, parentId });
    idx.set(path.toLowerCase(), newId);
    created.push(path);
    parentId = newId;
    leafId = newId;
  }
  return { id: leafId, created };
}

/** Fetch pages of an Email/query result, stopping once `cap` ids are collected. */
async function queryIds(
  apiUrl: string,
  apiToken: string,
  accountId: string,
  filter: Record<string, unknown>,
  cap: number,
  pageSize = 50,
): Promise<string[]> {
  const ids: string[] = [];
  let position = 0;
  let total = Infinity;
  while (ids.length < total && ids.length < cap) {
    const resp = await jmapRequest(apiUrl, apiToken, [
      ["Email/query", {
        accountId,
        filter,
        sort: [{ property: "receivedAt", isAscending: false }],
        position,
        limit: Math.min(pageSize, cap - ids.length),
      }, "0"],
    ]);
    const page = unwrapMethodResponse(resp, "Email/query") as {
      ids: string[];
      total?: number;
    };
    if (typeof page.total === "number") total = page.total;
    if (page.ids.length === 0) break;
    ids.push(...page.ids);
    position += page.ids.length;
  }
  return cap === Infinity ? ids : ids.slice(0, cap);
}

async function getEmailBatch(
  apiUrl: string,
  apiToken: string,
  accountId: string,
  ids: string[],
  properties: string[],
  batchSize = 50,
): Promise<Record<string, unknown>[]> {
  const emails: Record<string, unknown>[] = [];
  for (let i = 0; i < ids.length; i += batchSize) {
    const batch = ids.slice(i, i + batchSize);
    const resp = await jmapRequest(apiUrl, apiToken, [
      ["Email/get", { accountId, ids: batch, properties }, "0"],
    ]);
    const r = unwrapMethodResponse(resp, "Email/get") as {
      list: Record<string, unknown>[];
    };
    emails.push(...(r.list ?? []));
  }
  return emails;
}

/** Normalize a List-Id header value to its bare id, e.g. "<news.example.com>". */
function cleanListId(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const m = trimmed.match(/<([^>]+)>/);
  return (m ? m[1] : trimmed).trim().toLowerCase();
}

function registrableDomain(email: string): string | null {
  const at = email.toLowerCase().split("@")[1];
  if (!at) return null;
  return at.split(".").slice(-2).join(".");
}

// Shared domain where the sender identity lives in the LOCAL part (freemail
// individuals, or list platforms like golang-nuts@googlegroups.com) — a domain
// match would sweep in unrelated senders, so match the FULL ADDRESS.
const FULL_ADDRESS = new Set([
  // freemail
  "gmail.com",
  "googlemail.com",
  "outlook.com",
  "hotmail.com",
  "live.com",
  "yahoo.com",
  "ymail.com",
  "icloud.com",
  "me.com",
  "mac.com",
  "aol.com",
  "proton.me",
  "protonmail.com",
  "pm.me",
  "gmx.com",
  "hey.com",
  // list/newsletter platforms keyed by local part
  "googlegroups.com",
  "substack.com",
  "ghost.io",
  "beehiiv.com",
]);

// Shared platforms where the brand lives in the SUBDOMAIN
// (e.g. info@newenglandforce.ccsend.com) — match the full domain.
const SHARED_HOST = new Set([
  "ccsend.com",
  "sendgrid.net",
  "onmicrosoft.com",
  "sparkpostmail.com",
]);

/** Pick the most precise sender token that still generalizes across a brand. */
function senderToken(
  email: string,
  reg: string,
  overrides: Record<string, string>,
): string {
  if (overrides[reg]) return overrides[reg];
  const at = email.toLowerCase().split("@")[1] ?? reg;
  if (FULL_ADDRESS.has(reg)) return email.toLowerCase(); // full address
  if (SHARED_HOST.has(reg)) return at; // full domain incl. subdomain
  return reg; // brand registrable domain (matches all its subdomains)
}

// ---------------------------------------------------------------------------
// Resource schemas
// ---------------------------------------------------------------------------

const SenderSchema = z.object({
  email: z.string(),
  name: z.string().nullable(),
  count: z.number(),
  bulkCount: z.number(),
  unreadCount: z.number(),
  oneClickUnsubscribe: z.boolean(),
  listIds: z.array(z.string()),
  mostRecent: z.string().nullable(),
  sampleSubjects: z.array(z.string()),
});
type Sender = z.infer<typeof SenderSchema>;

const SieveResourceSchema = z.object({
  generatedAt: z.string(),
  source: z.string(),
  folderPrefix: z.string(),
  mode: z.string(),
  categories: z.array(z.string()),
  matchCount: z.number(),
  sendersMatched: z.number(),
  bulkFallbackCount: z.number(),
  leftInInbox: z.number(),
  // Senders that no rule matched (fell to bulkFallback) — the to-do list for
  // new rules, ranked by volume. Surfaced by the @dmc/fastmail-coverage report.
  uncategorized: z.array(z.object({
    email: z.string(),
    name: z.string().nullable(),
    count: z.number(),
  })).default([]),
  script: z.string(),
});

const PlanMoveSchema = z.object({
  messageId: z.string(),
  from: z.string(),
  subject: z.string(),
  receivedAt: z.string().nullable(),
  category: z.string(),
  sievePath: z.string(),
  mailboxId: z.string().nullable(),
  matchedBy: z.string(),
  keepInbox: z.boolean().default(false), // true = add label, leave in Inbox
});
const PlanResourceSchema = z.object({
  generatedAt: z.string(),
  sourceMailbox: z.string(),
  scannedMessages: z.number(),
  moveCount: z.number(),
  leftInInbox: z.number(),
  byDestination: z.record(z.string(), z.number()),
  moves: z.array(PlanMoveSchema),
});

// A sender the current rules leave in the inbox, with why it stayed.
const AnalysisSenderSchema = z.object({
  token: z.string(), // the rule-pattern unit (registrable domain / full addr / subdomain)
  count: z.number(),
  bulk: z.number(),
  unread: z.number(),
  reason: z.enum(["protected", "excluded", "flagged", "unmatched"]),
  sampleFroms: z.array(z.string()),
  sampleSubjects: z.array(z.string()),
});

const AnalysisResourceSchema = z.object({
  generatedAt: z.string(),
  sourceMailbox: z.string(),
  scannedMessages: z.number(),
  covered: z.number(), // matched by current rules (would leave the inbox)
  coveredByCategory: z.record(z.string(), z.number()),
  remaining: z.object({
    total: z.number(),
    bulk: z.number(),
    personal: z.number(),
    unread: z.number(),
    distinctSenders: z.number(),
    // Message counts by why-kept: unmatched = real rule candidate; the rest are
    // kept by design (exclude list / finance-protect stop / flag-only rule).
    byReason: z.record(z.string(), z.number()),
    candidates: z.array(AnalysisSenderSchema), // reason === "unmatched"
    keptByDesign: z.array(AnalysisSenderSchema), // excluded / protected / flagged
  }),
});

// ---------------------------------------------------------------------------
// Sieve categorization + rendering
// ---------------------------------------------------------------------------

type CompiledRule = { category: string; re: RegExp };

interface SetupConfig {
  folderPrefix: string;
  mode: "move" | "label";
  rules: Array<{ category: string; pattern: string }>;
  exclude: string[];
  overrides: Record<string, string>;
  bulkFallback: string | null;
  bulkThreshold: number;
  // Fastmail-idiom options:
  dialect: "simple" | "fastmail";
  action: "file" | "allowlist";
  rootPrefix: string;
  separator: string;
  skipInbox: boolean;
  markRead: boolean;
}

const depth = (category: string) => category.split("/").filter(Boolean).length;

/** Compile + auto-sort rules so more specific paths (A/B) win over parents (A). */
function compileRules(rules: SetupConfig["rules"]): CompiledRule[] {
  return rules
    .map((r) => ({ category: r.category, re: new RegExp(r.pattern, "i") }))
    .sort((a, b) => depth(b.category) - depth(a.category));
}

interface CategorizeResult {
  byCategory: Map<string, Set<string>>;
  sendersMatched: number;
  bulkFallbackCount: number;
  leftInInbox: number;
  fallbackSenders: Array<{ email: string; name: string | null; count: number }>;
}

function categorize(senders: Sender[], cfg: SetupConfig): CategorizeResult {
  const rules = compileRules(cfg.rules);
  const exclude = new Set(cfg.exclude.map((d) => d.toLowerCase()));
  const byCategory = new Map<string, Set<string>>();
  const fallbackSenders: CategorizeResult["fallbackSenders"] = [];
  let sendersMatched = 0;
  let bulkFallbackCount = 0;
  let leftInInbox = 0;

  for (const s of senders) {
    const email = (s.email ?? "").toLowerCase();
    const reg = registrableDomain(email);
    if (!reg || exclude.has(reg)) {
      leftInInbox++;
      continue;
    }
    const hay = `${email} ${(s.name ?? "").toLowerCase()}`;
    let category: string | null = null;
    const rule = rules.find((r) => r.re.test(hay));
    if (rule) {
      category = rule.category;
    } else if (cfg.bulkFallback && s.count > 0) {
      const ratio = s.bulkCount / s.count;
      if (ratio >= cfg.bulkThreshold) category = cfg.bulkFallback;
    }
    if (!category) {
      leftInInbox++;
      continue;
    }
    if (category === cfg.bulkFallback) {
      bulkFallbackCount++;
      fallbackSenders.push({ email: s.email, name: s.name, count: s.count });
    } else sendersMatched++;
    const token = senderToken(email, reg, cfg.overrides);
    if (!byCategory.has(category)) byCategory.set(category, new Set());
    byCategory.get(category)!.add(token);
  }
  fallbackSenders.sort((a, b) => b.count - a.count);
  return {
    byCategory,
    sendersMatched,
    bulkFallbackCount,
    leftInInbox,
    fallbackSenders,
  };
}

/** Emit the require tokens + rule blocks (no `require` header line) for a setup. */
function emitBody(
  byCategory: Map<string, Set<string>>,
  cfg: SetupConfig,
): {
  requires: string[];
  body: string;
  categories: string[];
  matchCount: number;
} {
  const categories = [...byCategory.keys()].sort(
    (a, b) => depth(b) - depth(a) || a.localeCompare(b),
  );
  let matchCount = 0;
  const blocks = categories.map((cat) => {
    const tokens = [...byCategory.get(cat)!].sort();
    matchCount += tokens.length;
    const tests = tokens
      .map((t) => `  address :all :contains "From" "${t}"`)
      .join(",\n");
    const action = cfg.mode === "move"
      ? `  fileinto :create "${cfg.folderPrefix}/${cat}";\n  stop;`
      : `  addflag "${cfg.folderPrefix}/${cat}";`;
    return `### ${cat}\nif anyof(\n${tests}\n) {\n${action}\n}\n`;
  });
  const requires = cfg.mode === "move"
    ? ["fileinto", "mailbox"]
    : ["imap4flags"];
  return { requires, body: blocks.join("\n"), categories, matchCount };
}

function renderScript(
  requires: string[],
  header: string,
  body: string,
): string {
  const req = `require [${
    [...new Set(requires)].map((r) => `"${r}"`).join(", ")
  }];`;
  return `${req}\n\n${header}\n\n${body}`;
}

// --- jmapquery helpers (used by the spam allowlist) ------------------------

function jmapqueryBlock(tokens: string[]): string {
  const conds = tokens.map((t) => `      { "from": ${JSON.stringify(t)} }`);
  const body = tokens.length === 1
    ? `{ "from": ${JSON.stringify(tokens[0])} }`
    : `{\n   "conditions": [\n${
      conds.join(",\n")
    }\n   ],\n   "operator": "OR"\n}`;
  return `  jmapquery text:\n${body}\n.\n`;
}

/**
 * Emit a spam-allowlist block: force ${spam} to "N" for trusted senders so
 * Fastmail's "Execute spam filing" never routes them to Junk. Injected BEFORE
 * that section (after the spam-scoring block), so it overrides a high score.
 */
function emitAllowlist(
  byCategory: Map<string, Set<string>>,
  label: string,
): { requires: string[]; allow: string; count: number } {
  const tokens = new Set<string>();
  for (const set of byCategory.values()) for (const t of set) tokens.add(t);
  const toks = [...tokens].sort();
  const requires = ["variables", "vnd.cyrus.jmapquery"];
  if (toks.length === 0) return { requires, allow: "", count: 0 };
  const block =
    `# Spam allowlist: ${label} (${toks.length} senders) — force not-spam\n` +
    `if ${jmapqueryBlock(toks).trimStart()}{\n  set "spam" "N";\n}\n`;
  return { requires, allow: block, count: toks.length };
}

// ---------------------------------------------------------------------------
// Self-contained rule emission (custom-sieve-only; no reliance on Fastmail's
// variable pipeline / finalize). Each rule acts and stops in place.
// ---------------------------------------------------------------------------

type MatchField = "from" | "to" | "list" | "with" | "subject" | "header";

interface RuleSpec {
  label: string;
  match?: MatchField;
  pattern?: string; // "|"-separated OR values
  header?: string; // header name, when match === "header"
  all?: Array<{ match: MatchField; pattern: string; header?: string }>;
  category?: string;
  sievePath?: string;
  mailboxId?: string | null;
  markRead?: boolean;
  markSpam?: boolean;
  flag?: string;
  redirectTo?: string;
  skipInbox?: boolean; // filing: move (true/undef) vs label (false)
  stop?: boolean;
}

/** One jmapquery condition object for a match field + value. */
function condFor(field: MatchField, value: string, header?: string): unknown {
  switch (field) {
    case "from":
      return { from: value };
    case "list":
      return { listId: value };
    case "to":
      return {
        conditions: [{ to: value }, { cc: value }, { bcc: value }, {
          deliveredTo: value,
        }],
        operator: "OR",
      };
    case "with":
      return {
        conditions: [{ from: value }, { to: value }, { cc: value }, {
          bcc: value,
        }, { deliveredTo: value }],
        operator: "OR",
      };
    case "subject":
      return { subject: value };
    case "header":
      return { header: [header ?? "", value] };
  }
}

/** OR several "|"-separated patterns for one match field. */
function orFor(field: MatchField, pattern: string, header?: string): unknown {
  const conds = pattern.split("|").filter(Boolean).map((p) =>
    condFor(field, p, header)
  );
  return conds.length === 1 ? conds[0] : { conditions: conds, operator: "OR" };
}

function jmapQueryObj(spec: RuleSpec): unknown {
  if (spec.all && spec.all.length) {
    return {
      conditions: spec.all.map((c) => orFor(c.match, c.pattern, c.header)),
      operator: "AND",
    };
  }
  return orFor(spec.match ?? "from", spec.pattern ?? "", spec.header);
}

/** A self-contained rule block: `if allof(not stop, jmapquery) { effects }`. */
function emitRule(spec: RuleSpec): string {
  const effects: string[] = [];
  // Flags first so they apply to the filed/kept copy.
  if (spec.markRead) effects.push(`  addflag "\\\\Seen";`);
  if (spec.flag) {
    // `$notify` is Fastmail-reserved: its push-notification engine fires off the
    // `notify` VARIABLE (set "notify" "Y"), which Fastmail's own "Execute rule
    // actions" stage converts into the `$notify` keyword + a push (and suppresses
    // it on spam). Stamping the keyword directly with `addflag "$notify"` labels
    // the message but doesn't trigger the push — so route through the variable.
    if (spec.flag === "$notify") effects.push(`  set "notify" "Y";`);
    else effects.push(`  addflag "${spec.flag}";`);
  }
  if (spec.redirectTo) effects.push(`  redirect :copy "${spec.redirectTo}";`);
  if (spec.markSpam) {
    // This block runs AFTER Fastmail's spam-filing stage, so `set spam Y` would
    // be too late — file to Junk directly instead.
    effects.push(`  fileinto :specialuse "\\\\Junk" "INBOX.Spam";`);
  } else if (spec.category && spec.sievePath) {
    const copy = spec.skipInbox === false ? " :copy" : "";
    const target = spec.mailboxId
      ? ` :mailboxid "${spec.mailboxId}"`
      : " :create";
    effects.push(`  fileinto${copy}${target} "${spec.sievePath}";`);
  }
  // Any category rule stops — including label-and-keep (skipInbox:false), so a
  // labeled message doesn't also fall through to the Newsletters bulk fallback.
  // With :copy the implicit Inbox keep survives the stop, so it stays in the Inbox.
  const doStop = spec.stop ??
    (spec.markSpam === true || spec.category !== undefined);
  if (doStop) effects.push(`  stop;`);
  const query = `  jmapquery text:\n${
    JSON.stringify(jmapQueryObj(spec), null, 3)
  }\n.\n`;
  return `# ${spec.label}\nif allof(\n  not string :is "\${stop}" "Y",\n${query}) {\n${
    effects.join("\n")
  }\n}\n`;
}

/** Wrap emitted rule blocks in a labeled @dmc/fastmail marker section. */
function markedBlock(title: string, pasteHint: string, body: string): string {
  return [
    `### BEGIN @dmc/fastmail ${title} {{{`,
    `#   >>> ${pasteHint} <<<`,
    "",
    body,
    `### END @dmc/fastmail ${title}`,
    "### }}}",
    "",
  ].join("\n");
}

function setupHeader(cfg: SetupConfig): string {
  return [
    "# Auto-generated by @dmc/fastmail email extension (sieve_generate).",
    "# Source: an email_senders scan. Paste into Fastmail:",
    "#   Settings -> Filters & Rules -> Edit custom Sieve code.",
    "#",
    cfg.mode === "move"
      ? `# Files matched senders into ${cfg.folderPrefix}/<Category> (nested via :create) and stops.`
      : `# Flags matched senders with a ${cfg.folderPrefix}/<Category> keyword, keeping them in the Inbox.`,
    cfg.bulkFallback
      ? `# Leftover bulk mail (List-Unsubscribe, ratio >= ${cfg.bulkThreshold}) -> ${cfg.folderPrefix}/${cfg.bulkFallback}.`
      : "# No bulk fallback: only explicitly-matched senders are filed.",
    "# Unmatched non-bulk (personal/transactional) senders are left in the Inbox.",
  ].join("\n");
}

// ---------------------------------------------------------------------------
// Per-message classification (apply-sieve) — same rules as the sieve, so the plan
// matches what future mail will do.
// ---------------------------------------------------------------------------

interface PlanMsg {
  from: string;
  fromName: string | null;
  recipients: string[]; // to/cc/bcc/deliveredTo
  listId: string | null;
  isBulk: boolean;
  subject?: string | null;
  headers?: Record<string, string>; // lowercased header name → value
}

/** A setup as consumed by the classifier (a superset of SetupSchema fields). */
interface SetupLike {
  dialect: string;
  action: string;
  rootPrefix: string;
  separator: string;
  bulkFallback: string | null;
  exclude: string[];
  skipInbox?: boolean; // file-setup default: false = label + keep in inbox
  rules: Array<{
    category?: string;
    pattern?: string;
    match?: MatchField;
    header?: string; // header name when match === "header"
    all?: Array<{ match: MatchField; pattern: string; header?: string }>;
    markSpam?: boolean;
    stop?: boolean;
    skipInbox?: boolean; // false = label + keep in inbox (:copy)
    flag?: string;
    markRead?: boolean;
    redirectTo?: string;
  }>;
}

function fieldMatches(
  msg: PlanMsg,
  field: MatchField,
  pattern: string,
  header?: string,
): boolean {
  let re: RegExp;
  try {
    re = new RegExp(pattern, "i");
  } catch {
    return false;
  }
  const fromStr = `${msg.from} ${msg.fromName ?? ""}`;
  switch (field) {
    case "from":
      return re.test(fromStr);
    case "list":
      return msg.listId ? re.test(msg.listId) : false;
    case "to":
      return msg.recipients.some((r) => re.test(r));
    case "with":
      return re.test(fromStr) || msg.recipients.some((r) => re.test(r));
    case "subject":
      return msg.subject ? re.test(msg.subject) : false;
    case "header": {
      const v = msg.headers?.[(header ?? "").toLowerCase()];
      return v ? re.test(v) : false;
    }
  }
}

function ruleMatches(msg: PlanMsg, rule: SetupLike["rules"][number]): boolean {
  if (rule.all && rule.all.length) {
    return rule.all.every((c) =>
      fieldMatches(msg, c.match, c.pattern, c.header)
    );
  }
  return fieldMatches(
    msg,
    rule.match ?? "from",
    rule.pattern ?? "",
    rule.header,
  );
}

/** Distinct header names referenced by any `match: header` rule across setups. */
function neededHeaders(setups: SetupLike[]): string[] {
  const names = new Set<string>();
  for (const s of setups) {
    for (const r of s.rules ?? []) {
      if (r.match === "header" && r.header) names.add(r.header);
      for (const c of r.all ?? []) {
        if (c.match === "header" && c.header) names.add(c.header);
      }
    }
  }
  return [...names];
}

interface Destination {
  category: string;
  sievePath: string;
  mailboxId: string | null;
  matchedBy: string;
  keepInbox: boolean; // true = add the label but leave the message in the Inbox
}

// Why a message stays in the inbox (dest === null). "unmatched" = no rule
// touched it = a genuine rule candidate; the others are kept by design.
type KeptReason = "protected" | "excluded" | "flagged" | "unmatched";
interface Classification {
  dest: Destination | null;
  keptReason: KeptReason | null; // set iff dest === null
}

/** Classify one message: a destination folder, or null (with a reason) to leave in Inbox. */
function classifyMessage(
  msg: PlanMsg,
  setups: SetupLike[],
  pathIndex: Map<string, string>,
): Classification {
  const resolve = (
    cat: string,
    s: SetupLike,
    keepInbox: boolean,
  ): Destination => ({
    category: cat,
    sievePath: [s.rootPrefix, ...cat.split("/")].filter(Boolean).join(
      s.separator,
    ),
    mailboxId: pathIndex.get(cat.toLowerCase()) ?? null,
    matchedBy: "",
    keepInbox,
  });
  let sawFlag = false; // matched a flag/markRead/redirect rule but no file/stop
  let sawExclude = false; // sender is in a file setup's exclude list
  for (const s of setups) {
    if (s.dialect !== "fastmail") continue;
    if (s.action === "rules") {
      for (const r of s.rules) {
        if (!ruleMatches(msg, r)) continue;
        if (r.category) {
          const d = resolve(r.category, s, r.skipInbox === false);
          d.matchedBy = `rule ${r.match ?? "from"}:${
            (r.pattern ?? "").slice(0, 30)
          }`;
          return { dest: d, keptReason: null };
        }
        // Spam rules move to Junk; other stopping/flag rules don't move.
        if (r.markSpam) {
          return {
            dest: {
              category: "Spam",
              sievePath: "INBOX.Spam",
              mailboxId: null,
              matchedBy: "spam rule",
              keepInbox: false,
            },
            keptReason: null,
          };
        }
        if (r.stop) return { dest: null, keptReason: "protected" };
        if (r.flag || r.markRead || r.redirectTo) sawFlag = true;
      }
    } else if (s.action === "file") {
      const exclude = new Set(s.exclude.map((d) => d.toLowerCase()));
      const reg = registrableDomain(msg.from);
      if (!reg) continue;
      if (exclude.has(reg)) {
        sawExclude = true;
        continue;
      }
      const compiled = compileRules(
        s.rules.filter((r) => r.category && r.pattern).map((r) => ({
          category: r.category!,
          pattern: r.pattern!,
        })),
      );
      const hay = `${msg.from.toLowerCase()} ${
        (msg.fromName ?? "").toLowerCase()
      }`;
      const hit = compiled.find((r) => r.re.test(hay));
      let category = hit?.category ?? null;
      if (!category && s.bulkFallback && msg.isBulk) category = s.bulkFallback;
      if (category) {
        const d = resolve(category, s, s.skipInbox === false);
        d.matchedBy = hit ? `file:${hit.category}` : "bulkFallback";
        return { dest: d, keptReason: null };
      }
    }
  }
  const keptReason: KeptReason = sawFlag
    ? "flagged"
    : sawExclude
    ? "excluded"
    : "unmatched";
  return { dest: null, keptReason };
}

// ---------------------------------------------------------------------------
// Method argument schemas
// ---------------------------------------------------------------------------

const ScopeSchema = z.object({
  name: z.string().describe(
    "Resource instance name, e.g. 'inbox' or 'recent'.",
  ),
  mode: z.enum(["mailbox", "recent"]).default("recent").describe(
    "'mailbox' scans an entire mailbox; 'recent' scans the newest maxMessages.",
  ),
  mailboxRole: z.string().optional().describe(
    "Mailbox role to target (e.g. 'inbox', 'archive'); resolved to an id.",
  ),
  inMailbox: z.string().optional().describe(
    "Explicit mailbox id (overrides role).",
  ),
  maxMessages: z.number().int().positive().optional().describe(
    "Cap of newest messages to scan. Defaults: recent=2000, mailbox=unlimited.",
  ),
  minCount: z.number().int().positive().default(1),
  after: z.string().optional().describe("ISO date; JMAP filter.after."),
  before: z.string().optional().describe("ISO date; JMAP filter.before."),
  headers: z.array(z.string()).default([]).describe(
    "Header names to tally a value→count frequency for (e.g. ['X-Business-Group', " +
      "'Auto-Submitted']) — surfaces header-based rule opportunities in the audit report.",
  ),
});

const SendersArgsSchema = z.object({
  scopes: z.array(ScopeSchema).min(1).describe(
    "One or more scopes to scan; each writes a 'senders' resource.",
  ),
});

const MatchSchema = z.enum(["from", "to", "list", "with", "subject", "header"]);

const RuleSchema = z.object({
  // Scan-driven categorization: {category, pattern} with no `match`.
  // Direct rule: set `match` (+ effects); `pattern` is the literal jmapquery value.
  category: z.string().optional().describe("Folder path, e.g. 'Sports/Chess'."),
  pattern: z.string().optional().describe(
    "Scan-driven: regex vs 'email name'. Direct: literal jmapquery value (| = OR).",
  ),
  match: MatchSchema.optional().describe(
    "Direct rule: match field. from | to (→to/cc/bcc/deliveredTo) | list (listId) | with (from+recipients) | subject | header (needs `header`).",
  ),
  header: z.string().optional().describe(
    "Header name to match when match: header (e.g. 'X-Business-Group'). `pattern` is the value.",
  ),
  all: z.array(z.object({
    match: MatchSchema,
    pattern: z.string(),
    header: z.string().optional(),
  })).optional()
    .describe("Compound AND of conditions (e.g. from X AND header Y)."),
  markRead: z.boolean().optional().describe(
    "Direct: mark read (addflag \\Seen).",
  ),
  markSpam: z.boolean().optional().describe(
    "Direct: mark spam (set spam Y → Junk).",
  ),
  flag: z.string().optional().describe(
    "Direct: addflag this keyword (e.g. $notify).",
  ),
  redirectTo: z.string().optional().describe(
    "Direct: redirect :copy to this address.",
  ),
  skipInbox: z.boolean().optional().describe(
    "Direct: move out of Inbox (default true if category).",
  ),
  stop: z.boolean().optional().describe(
    "Direct: halt further rules after match.",
  ),
});

const SetupSchema = z.object({
  name: z.string().describe("Resource instance for the generated sieve."),
  source: z.string().default("").describe(
    "Name of the senders scope to read (not needed for action: rules).",
  ),
  folderPrefix: z.string().default("Newsletters"),
  mode: z.enum(["move", "label"]).default("move"),
  rules: z.array(RuleSchema).default([]),
  exclude: z.array(z.string()).default([]).describe(
    "Registrable domains this setup skips. file → left in the Inbox; allowlist → not force-marked not-spam.",
  ),
  overrides: z.record(z.string(), z.string()).default({}),
  bulkFallback: z.string().nullable().default(null).describe(
    "Category for leftover bulk senders (e.g. 'Newsletters'); null to skip.",
  ),
  bulkThreshold: z.number().min(0).max(1).default(0.5),
  dialect: z.enum(["simple", "fastmail"]).default("simple").describe(
    "'simple' = address :contains + fileinto; 'fastmail' = jmapquery + :mailboxid + skipinbox/read vars.",
  ),
  action: z.enum(["file", "allowlist", "rules"]).default("file").describe(
    "fastmail: 'file' = scan-driven categorization; 'allowlist' = force not-spam; 'rules' = direct match→effect rules (scan-independent).",
  ),
  rootPrefix: z.string().default("INBOX").describe(
    "Sieve mailbox root prefix for the fastmail dialect (Fastmail uses 'INBOX').",
  ),
  separator: z.string().default(".").describe(
    "Folder hierarchy separator for the fastmail dialect (Fastmail uses '.').",
  ),
  skipInbox: z.boolean().default(true).describe(
    "fastmail dialect: matched mail skips the Inbox (move); false = label + keep.",
  ),
  markRead: z.boolean().default(false).describe(
    "fastmail dialect: mark matched mail as read.",
  ),
});

const SieveArgsSchema = z.object({
  setups: z.array(SetupSchema).min(1),
  output: z.object({
    name: z.string().default("custom").describe(
      "Resource name for the assembled custom sieve.",
    ),
  }).default({ name: "custom" }).describe(
    "Assembles all fastmail setups into one custom-sieve resource (two paste-slots).",
  ),
});

const PlanArgsSchema = z.object({
  setups: z.array(SetupSchema).min(1).describe(
    "Same setups as sieve_generate — the plan applies the identical rules.",
  ),
  mailboxRole: z.string().default("inbox").describe(
    "Mailbox to apply the sieve to (default 'inbox'; 'archive' to fix old " +
      "classifications; 'all' to scan ALL mail, e.g. with `after` — pair with " +
      "email_move labelOnly since all-mail has no single source to move from).",
  ),
  inMailbox: z.string().optional().describe(
    "Explicit mailbox id (overrides role).",
  ),
  after: z.string().optional().describe(
    "ISO date; only plan mail received after this.",
  ),
  before: z.string().optional().describe(
    "ISO date; only plan mail received before this.",
  ),
  maxMessages: z.number().int().positive().optional().describe(
    "Cap of newest messages to plan (default: all).",
  ),
  name: z.string().default("apply-plan").describe(
    "Plan resource instance name.",
  ),
});

const AnalyzeArgsSchema = z.object({
  setups: z.array(SetupSchema).min(1).describe(
    "Same setups as sieve_generate — analysis applies the identical rules to see what's covered vs left behind.",
  ),
  mailboxRole: z.string().default("inbox").describe(
    "Mailbox to analyze (default 'inbox').",
  ),
  inMailbox: z.string().optional().describe(
    "Explicit mailbox id (overrides role).",
  ),
  maxMessages: z.number().int().positive().optional().describe(
    "Cap of newest messages to analyze (default: all).",
  ),
  name: z.string().default("analysis").describe(
    "Analysis resource instance name.",
  ),
  // Ignored passthrough: lets `--input-file config/email-config.yaml` (which also
  // carries `scopes` for the scan stage) drive analyze without a trimmed copy.
  scopes: z.any().optional().describe(
    "Ignored; present so the shared config file is accepted by strict input validation.",
  ),
});

const MoveArgsSchema = z.object({
  source: z.string().default("apply-plan").describe(
    "Plan resource name to execute (from email_plan).",
  ),
  execute: z.boolean().default(false).describe(
    "false = dry-run (moves nothing, just reports). true = perform the moves — REQUIRES a write-scoped token.",
  ),
  forceMove: z.boolean().default(false).describe(
    "Remove the source mailbox even for keep (skipInbox:false) rules. Use when " +
      "cleaning a NON-inbox folder (e.g. Newsletters) where 'keep in inbox' doesn't " +
      "apply — everything with a home leaves the source folder.",
  ),
  labelOnly: z.boolean().default(false).describe(
    "Only ADD the target label; never remove any mailbox. Use for an all-mail " +
      "backfill (mailboxRole=all) where messages live in many folders — tag them " +
      "with their category label in place, moving nothing.",
  ),
  batchSize: z.number().int().positive().default(50),
});

// ---------------------------------------------------------------------------
// Context type
// ---------------------------------------------------------------------------

type Ctx = {
  globalArgs: { apiToken: string; writeToken?: string; sessionUrl?: string };
  logger?: { info: (msg: string, props?: Record<string, unknown>) => void };
  writeResource: (
    spec: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
  readResource?: (
    name: string,
    version?: number,
  ) => Promise<Record<string, unknown> | null>;
};

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

/**
 * `@dmc/fastmail` — a Fastmail email-organization model over JMAP.
 *
 * Methods: `email_senders` (fan-out sender scan with bulk detection),
 * `sieve_generate` (config-driven Sieve script generation into nested folders),
 * `email_plan` (dry-run message-id → destination plan), `email_analyze`
 * (post-hoc analysis of a scan against the rules), `email_headers` (dump raw
 * headers of sample messages for rule discovery), and `email_move` (apply the
 * plan; requires a write-scoped token and `execute: true`).
 */
export const model = {
  type: "@dmc/fastmail",
  version: "2026.09.15.1",
  globalArguments: GlobalArgsSchema,
  checks: {
    "valid-api-token": {
      description:
        "Verify Fastmail JMAP credentials by fetching the session endpoint",
      labels: ["connectivity"],
      execute: async (
        context: {
          globalArgs: Record<string, unknown>;
          logger?: { warn: (m: string, p?: Record<string, unknown>) => void };
        },
      ) => {
        const args = GlobalArgsSchema.parse(context.globalArgs);
        const token = resolveReadToken(args);
        try {
          const session = await fetchSession(token, args.sessionUrl);
          const errors: string[] = [];
          if (!session.apiUrl) errors.push("JMAP session missing apiUrl");
          if (!session.primaryAccounts?.[JMAP_MAIL_URN]) {
            errors.push(`no primary account for ${JMAP_MAIL_URN}`);
          }
          return errors.length ? { pass: false, errors } : { pass: true };
        } catch (e) {
          const msg = String(e);
          return {
            pass: false,
            errors: [msg.includes(token) ? "[token redacted]" : msg],
          };
        }
      },
    },
  },
  resources: {
    senders: {
      description:
        "All senders in a scanned scope with per-sender bulk attributes (from email_senders)",
      schema: z.object({
        scannedAt: z.string(),
        scope: z.object({
          name: z.string(),
          mode: z.string(),
          inMailbox: z.string().nullable(),
          maxMessages: z.number().nullable(),
        }),
        scannedMessages: z.number(),
        unreadMessages: z.number(),
        senderCount: z.number(),
        bulkSenders: z.number(),
        senders: z.array(SenderSchema),
        // value→count frequency for each requested header name (top values).
        headerStats: z.record(
          z.string(),
          z.array(z.object({ value: z.string(), count: z.number() })),
        ).default({}),
      }),
      lifetime: "30d" as const,
      garbageCollection: 10,
    },
    sieve: {
      description:
        "Generated Fastmail Sieve script (and metadata) organizing senders into folders",
      schema: SieveResourceSchema,
      lifetime: "30d" as const,
      garbageCollection: 10,
    },
    plan: {
      description:
        "Apply-sieve plan: message id → destination folder for existing mail, per the same rules",
      schema: PlanResourceSchema,
      lifetime: "7d" as const,
      garbageCollection: 5,
    },
    analysis: {
      description:
        "Standalone inbox analysis: what current rules cover vs the senders left behind (the rule-candidate to-do list)",
      schema: AnalysisResourceSchema,
      lifetime: "7d" as const,
      garbageCollection: 5,
    },
    headers: {
      description:
        "Diagnostic: full header lists of sample messages, for designing header-based rules",
      schema: z.object({
        query: z.string(),
        messages: z.array(z.object({
          subject: z.string().nullable(),
          from: z.string().nullable(),
          headers: z.array(z.object({ name: z.string(), value: z.string() })),
        })),
      }),
      lifetime: "1d" as const,
      garbageCollection: 3,
    },
  },
  methods: {
    email_senders: {
      description:
        "Scan ALL senders across one or more scopes (whole mailbox or recent N), grouping by sender and recording bulk-ness (List-Id / List-Unsubscribe) as a per-sender attribute. Fan-out: writes one 'senders' resource per scope.",
      arguments: SendersArgsSchema,
      execute: async (
        args: z.infer<typeof SendersArgsSchema>,
        context: Ctx,
      ) => {
        const apiToken = resolveReadToken(context.globalArgs);
        const sessionUrl = context.globalArgs.sessionUrl ?? DEFAULT_SESSION_URL;
        const session = await fetchSession(apiToken, sessionUrl);
        const accountId = session.primaryAccounts[JMAP_MAIL_URN];

        const needsRoles = args.scopes.some((s) =>
          s.mailboxRole && !s.inMailbox
        );
        const roleToId: Record<string, string> = {};
        if (needsRoles) {
          const mailboxes = await fetchMailboxes(
            session.apiUrl,
            apiToken,
            accountId,
          );
          for (const mb of mailboxes) {
            if (mb.role) roleToId[mb.role.toLowerCase()] = mb.id;
          }
        }

        const handles: { name: string }[] = [];
        const summary: Array<Record<string, unknown>> = [];

        for (const scope of args.scopes) {
          const inMailbox = scope.inMailbox ??
            (scope.mailboxRole
              ? roleToId[scope.mailboxRole.toLowerCase()]
              : undefined);
          if (scope.mailboxRole && !scope.inMailbox && !inMailbox) {
            throw new Error(
              `Scope "${scope.name}": no mailbox found with role "${scope.mailboxRole}".`,
            );
          }
          const cap = scope.maxMessages ??
            (scope.mode === "mailbox" ? Infinity : 2000);

          const filter: Record<string, unknown> = {};
          if (inMailbox) filter.inMailbox = inMailbox;
          if (scope.after) filter.after = scope.after;
          if (scope.before) filter.before = scope.before;

          context.logger?.info("Scanning scope {name}", {
            name: scope.name,
            mode: scope.mode,
            inMailbox: inMailbox ?? "(all mail)",
            cap: cap === Infinity ? "unlimited" : cap,
          });

          const ids = await queryIds(
            session.apiUrl,
            apiToken,
            accountId,
            filter,
            cap,
          );
          const emails = await getEmailBatch(
            session.apiUrl,
            apiToken,
            accountId,
            ids,
            [
              "id",
              "from",
              "subject",
              "receivedAt",
              "keywords",
              "header:List-Id:asText",
              "header:List-Unsubscribe",
              "header:List-Unsubscribe-Post",
              ...scope.headers.map((n) => `header:${n}:asText`),
            ],
          );

          const byEmail = new Map<string, Sender>();
          // value→count frequency for each requested header name.
          const headerTally: Record<string, Map<string, number>> = {};
          for (const n of scope.headers) headerTally[n] = new Map();
          for (const e of emails) {
            const from = (e.from as Array<{ name?: string; email?: string }>) ??
              [];
            const addr = from[0]?.email?.toLowerCase();
            if (!addr) continue;
            const listId = cleanListId(e["header:List-Id:asText"]);
            const listUnsub =
              typeof e["header:List-Unsubscribe"] === "string" &&
              (e["header:List-Unsubscribe"] as string).trim() !== "";
            const isBulkMsg = !!listId || listUnsub;
            const keywords = (e.keywords as Record<string, boolean>) ?? {};
            const isUnread = !keywords["$seen"];
            const oneClick =
              typeof e["header:List-Unsubscribe-Post"] === "string" &&
              (e["header:List-Unsubscribe-Post"] as string).trim() !== "";
            const subject = typeof e.subject === "string" ? e.subject : "";
            const receivedAt = typeof e.receivedAt === "string"
              ? e.receivedAt
              : null;

            let s = byEmail.get(addr);
            if (!s) {
              s = {
                email: addr,
                name: from[0]?.name ?? null,
                count: 0,
                bulkCount: 0,
                unreadCount: 0,
                oneClickUnsubscribe: false,
                listIds: [],
                mostRecent: null,
                sampleSubjects: [],
              };
              byEmail.set(addr, s);
            }
            s.count++;
            if (isBulkMsg) s.bulkCount++;
            if (isUnread) s.unreadCount++;
            if (!s.name && from[0]?.name) s.name = from[0].name!;
            if (listId && !s.listIds.includes(listId)) s.listIds.push(listId);
            if (oneClick) s.oneClickUnsubscribe = true;
            if (receivedAt && (!s.mostRecent || receivedAt > s.mostRecent)) {
              s.mostRecent = receivedAt;
            }
            if (subject && s.sampleSubjects.length < 3) {
              s.sampleSubjects.push(subject);
            }
            for (const n of scope.headers) {
              const v = e[`header:${n}:asText`];
              if (typeof v === "string" && v.trim()) {
                const key = v.trim();
                headerTally[n].set(key, (headerTally[n].get(key) ?? 0) + 1);
              }
            }
          }

          const senders = [...byEmail.values()]
            .filter((s) => s.count >= scope.minCount)
            .sort((a, b) => b.count - a.count);
          const bulkSenders = senders.filter((s) => s.bulkCount > 0).length;
          const unreadMessages = senders.reduce((a, s) => a + s.unreadCount, 0);
          const headerStats: Record<
            string,
            Array<{ value: string; count: number }>
          > = {};
          for (const n of scope.headers) {
            headerStats[n] = [...headerTally[n].entries()]
              .map(([value, count]) => ({ value, count }))
              .sort((a, b) => b.count - a.count)
              .slice(0, 20);
          }

          context.logger?.info("Scope {name} complete", {
            name: scope.name,
            scannedMessages: ids.length,
            senderCount: senders.length,
            bulkSenders,
          });

          const handle = await context.writeResource("senders", scope.name, {
            scannedAt: new Date().toISOString(),
            scope: {
              name: scope.name,
              mode: scope.mode,
              inMailbox: inMailbox ?? null,
              maxMessages: cap === Infinity ? null : cap,
            },
            scannedMessages: ids.length,
            unreadMessages,
            senderCount: senders.length,
            bulkSenders,
            senders,
            headerStats,
          });
          handles.push(handle);
          summary.push({
            scope: scope.name,
            scannedMessages: ids.length,
            unreadMessages,
            senderCount: senders.length,
            bulkSenders,
          });
        }

        return { dataHandles: handles, scopes: summary };
      },
    },
    sieve_generate: {
      description:
        "Generate Fastmail Sieve scripts from email_senders scans. Config-driven fan-out: each setup categorizes senders into (nested) folders, sweeps leftover bulk into a fallback category, and leaves unmatched personal mail in the Inbox. Optionally merges setups into one combined script.",
      arguments: SieveArgsSchema,
      execute: async (args: z.infer<typeof SieveArgsSchema>, context: Ctx) => {
        const handles: { name: string }[] = [];
        const summary: Array<Record<string, unknown>> = [];

        // Resolve the folder tree once if any setup uses the fastmail dialect.
        let pathIndex = new Map<string, string>();
        if (args.setups.some((s) => s.dialect === "fastmail")) {
          const apiToken = resolveReadToken(context.globalArgs);
          const sessionUrl = context.globalArgs.sessionUrl ??
            DEFAULT_SESSION_URL;
          const session = await fetchSession(apiToken, sessionUrl);
          const accountId = session.primaryAccounts[JMAP_MAIL_URN];
          const mailboxes = await fetchMailboxes(
            session.apiUrl,
            apiToken,
            accountId,
          );
          pathIndex = buildPathIndex(mailboxes);
        }

        const resolvePath = (cat: string, cfg: SetupConfig) => {
          const sievePath = [cfg.rootPrefix, ...cat.split("/")]
            .filter(Boolean).join(cfg.separator);
          return {
            sievePath,
            mailboxId: pathIndex.get(cat.toLowerCase()) ?? null,
          };
        };
        // Custom-sieve slots: allowlist runs before STATIC, rules after.
        const allowBlocks: string[] = [];
        const ruleBlocks: string[] = [];

        // Blank stats used by non-file setups (allowlist/rules/simple/output).
        const zero = {
          sendersMatched: 0,
          bulkFallbackCount: 0,
          leftInInbox: 0,
          uncategorized: [] as unknown[],
        };

        for (const setup of args.setups) {
          const cfg: SetupConfig = {
            folderPrefix: setup.folderPrefix,
            mode: setup.mode,
            rules: setup.rules,
            exclude: setup.exclude,
            overrides: setup.overrides,
            bulkFallback: setup.bulkFallback,
            bulkThreshold: setup.bulkThreshold,
            dialect: setup.dialect,
            action: setup.action,
            rootPrefix: setup.rootPrefix,
            separator: setup.separator,
            skipInbox: setup.skipInbox,
            markRead: setup.markRead,
          };

          // Direct rules (scan-independent) — the migrated Fastmail UI rules.
          if (setup.dialect === "fastmail" && setup.action === "rules") {
            const blocks = setup.rules.map((r) => {
              let sievePath: string | undefined;
              let mailboxId: string | null | undefined;
              if (r.category) {
                ({ sievePath, mailboxId } = resolvePath(r.category, cfg));
              }
              const label = r.category
                ? `${r.category} -> ${sievePath}${
                  mailboxId ? ` (${mailboxId})` : " (NEW)"
                }`
                : `${r.match ?? "from"}: ${(r.pattern ?? "").slice(0, 50)}`;
              return emitRule({
                label,
                match: r.match,
                pattern: r.pattern,
                header: r.header,
                all: r.all,
                category: r.category,
                sievePath,
                mailboxId,
                markRead: r.markRead,
                markSpam: r.markSpam,
                flag: r.flag,
                redirectTo: r.redirectTo,
                skipInbox: r.skipInbox,
                stop: r.stop,
              });
            });
            ruleBlocks.push(...blocks);
            const handle = await context.writeResource("sieve", setup.name, {
              generatedAt: new Date().toISOString(),
              source: "(direct rules)",
              folderPrefix: setup.rootPrefix,
              mode: "rules",
              categories: [],
              matchCount: blocks.length,
              ...zero,
              script: blocks.join("\n"),
            });
            handles.push(handle);
            summary.push({
              setup: setup.name,
              action: "rules",
              rules: blocks.length,
            });
            continue;
          }

          // The rest need a senders scan.
          const data = await context.readResource?.(setup.source);
          if (!data) {
            throw new Error(
              `No senders data named "${setup.source}" — run email_senders first (scope name=${setup.source}).`,
            );
          }
          const senders = (data.senders as Sender[] | undefined) ?? [];
          const cat = categorize(senders, cfg);

          if (setup.dialect === "simple") {
            const e = emitBody(cat.byCategory, cfg);
            const handle = await context.writeResource("sieve", setup.name, {
              generatedAt: new Date().toISOString(),
              source: setup.source,
              folderPrefix: setup.folderPrefix,
              mode: setup.mode,
              categories: e.categories,
              matchCount: e.matchCount,
              sendersMatched: cat.sendersMatched,
              bulkFallbackCount: cat.bulkFallbackCount,
              leftInInbox: cat.leftInInbox,
              uncategorized: cat.fallbackSenders.slice(0, 50),
              script: renderScript(e.requires, setupHeader(cfg), e.body),
            });
            handles.push(handle);
            summary.push({
              setup: setup.name,
              dialect: "simple",
              categories: e.categories.length,
            });
            continue;
          }

          if (setup.action === "allowlist") {
            const e = emitAllowlist(cat.byCategory, setup.name);
            if (e.allow.trim()) allowBlocks.push(e.allow);
            const handle = await context.writeResource("sieve", setup.name, {
              generatedAt: new Date().toISOString(),
              source: setup.source,
              folderPrefix: setup.rootPrefix,
              mode: "allowlist",
              categories: [],
              matchCount: e.count,
              ...zero,
              script: e.allow,
            });
            handles.push(handle);
            summary.push({
              setup: setup.name,
              action: "allowlist",
              senders: e.count,
            });
            continue;
          }

          // action file: scan-driven categorization → self-contained rule blocks.
          // Specific categories first (per-sender from-list); the bulk fallback
          // LAST, matched by the List-Unsubscribe/List-Id header rather than a huge
          // domain list (which Cyrus rejects) — so it also catches future bulk.
          const cats = [...cat.byCategory.keys()]
            .filter((c) => c !== cfg.bulkFallback)
            .sort((a, b) => depth(b) - depth(a) || a.localeCompare(b));
          let newFolders = 0;
          let resolvedFolders = 0;
          const blocks: string[] = cats.map((c) => {
            const tokens = [...cat.byCategory.get(c)!].sort();
            const { sievePath, mailboxId } = resolvePath(c, cfg);
            mailboxId ? resolvedFolders++ : newFolders++;
            return emitRule({
              label: `${c} -> ${sievePath}${
                mailboxId ? ` (${mailboxId})` : " (NEW)"
              }`,
              match: "from",
              pattern: tokens.join("|"),
              category: c,
              sievePath,
              mailboxId,
              skipInbox: cfg.skipInbox,
              markRead: cfg.markRead,
            });
          });
          if (cfg.bulkFallback && cat.byCategory.has(cfg.bulkFallback)) {
            const { sievePath, mailboxId } = resolvePath(cfg.bulkFallback, cfg);
            mailboxId ? resolvedFolders++ : newFolders++;
            // Keep excluded senders in the Inbox before the bulk sweep.
            if (cfg.exclude.length) {
              const excl = cfg.exclude.map((d) => d.toLowerCase()).sort().join(
                "|",
              );
              blocks.push(
                `# keep-in-inbox (excluded) before bulk fallback\n` +
                  `if allof(\n  not string :is "\${stop}" "Y",\n  jmapquery text:\n${
                    JSON.stringify(orFor("from", excl), null, 3)
                  }\n.\n) {\n  stop;\n}\n`,
              );
            }
            const fileLine = mailboxId
              ? ` :mailboxid "${mailboxId}"`
              : " :create";
            blocks.push(
              `# ${cfg.bulkFallback} (bulk fallback, List-Unsubscribe/List-Id) -> ${sievePath}${
                mailboxId ? ` (${mailboxId})` : " (NEW)"
              }\n` +
                `if allof(\n  not string :is "\${stop}" "Y",\n  anyof(exists "list-unsubscribe", exists "list-id")\n) {\n  fileinto${fileLine} "${sievePath}";\n  stop;\n}\n`,
            );
          }
          ruleBlocks.push(...blocks);
          context.logger?.info("Generated file setup {name}", {
            name: setup.name,
            categories: cats.length,
            sendersMatched: cat.sendersMatched,
            bulkFallback: cat.bulkFallbackCount,
            leftInInbox: cat.leftInInbox,
            newFolders,
          });
          const handle = await context.writeResource("sieve", setup.name, {
            generatedAt: new Date().toISOString(),
            source: setup.source,
            folderPrefix: setup.rootPrefix,
            mode: setup.skipInbox ? "move" : "label",
            categories: cats,
            matchCount: blocks.length,
            sendersMatched: cat.sendersMatched,
            bulkFallbackCount: cat.bulkFallbackCount,
            leftInInbox: cat.leftInInbox,
            uncategorized: cat.fallbackSenders.slice(0, 50),
            script: blocks.join("\n"),
          });
          handles.push(handle);
          summary.push({
            setup: setup.name,
            action: "file",
            categories: cats.length,
            sendersMatched: cat.sendersMatched,
            bulkFallbackCount: cat.bulkFallbackCount,
            leftInInbox: cat.leftInInbox,
            resolvedFolders,
            newFolders,
          });
        }

        // Assemble the two-slot custom sieve (no require; Fastmail's covers it).
        const parts: string[] = [
          "# @dmc/fastmail custom sieve — paste each marked block into its slot",
          "# in your Fastmail custom sieve (around your # START/END STATIC CODE).",
          "# No `require` line here — Fastmail's own require already covers these.",
          "",
        ];
        if (allowBlocks.length) {
          parts.push(markedBlock(
            "spam allowlist",
            "PASTE BEFORE your `# START STATIC CODE`",
            allowBlocks.join("\n"),
          ));
        }
        if (ruleBlocks.length) {
          parts.push(markedBlock(
            "rules",
            "PASTE AFTER your `# END STATIC CODE` (where RULE GENERATED was)",
            ruleBlocks.join("\n"),
          ));
        }
        const customScript = parts.join("\n");
        const outHandle = await context.writeResource(
          "sieve",
          args.output.name,
          {
            generatedAt: new Date().toISOString(),
            source: args.setups.map((s) => s.name).join("+"),
            folderPrefix: "(custom)",
            mode: "custom",
            categories: [],
            matchCount: (customScript.match(/jmapquery text:/g) ?? []).length,
            ...zero,
            script: customScript,
          },
        );
        handles.push(outHandle);
        summary.push({
          output: args.output.name,
          allowlistBlocks: allowBlocks.length,
          ruleBlocks: ruleBlocks.length,
        });

        return { dataHandles: handles, setups: summary };
      },
    },

    email_plan: {
      description:
        "Plan applying the sieve to existing mail: classify a mailbox's messages to destination folders using the SAME rules as sieve_generate, producing a message-id → destination mapping for manual review (executed later by email_move). Read-only — moves nothing.",
      arguments: PlanArgsSchema,
      execute: async (args: z.infer<typeof PlanArgsSchema>, context: Ctx) => {
        const apiToken = resolveReadToken(context.globalArgs);
        const sessionUrl = context.globalArgs.sessionUrl ?? DEFAULT_SESSION_URL;
        const session = await fetchSession(apiToken, sessionUrl);
        const accountId = session.primaryAccounts[JMAP_MAIL_URN];
        const mailboxes = await fetchMailboxes(
          session.apiUrl,
          apiToken,
          accountId,
        );
        const pathIndex = buildPathIndex(mailboxes);
        const roleToId: Record<string, string> = {};
        for (const mb of mailboxes) {
          if (mb.role) roleToId[mb.role.toLowerCase()] = mb.id;
        }
        const explicit = args.inMailbox && args.inMailbox.trim()
          ? args.inMailbox.trim()
          : null;
        // mailboxRole "all" (no explicit inMailbox) scans ALL mail — no mailbox
        // restriction, just the optional date window.
        const allMail = !explicit && args.mailboxRole.toLowerCase() === "all";
        const inMailbox = allMail
          ? undefined
          : (explicit ?? roleToId[args.mailboxRole.toLowerCase()]);
        if (!allMail && !inMailbox) {
          throw new Error(`No mailbox found for role "${args.mailboxRole}".`);
        }

        const cap = args.maxMessages ?? Infinity;
        const filter: Record<string, unknown> = {};
        if (inMailbox) filter.inMailbox = inMailbox;
        if (args.after) filter.after = args.after;
        if (args.before) filter.before = args.before;
        const ids = await queryIds(
          session.apiUrl,
          apiToken,
          accountId,
          filter,
          cap,
        );
        const setups = args.setups as unknown as SetupLike[];
        const hdrNames = neededHeaders(setups);
        const emails = await getEmailBatch(
          session.apiUrl,
          apiToken,
          accountId,
          ids,
          [
            "id",
            "from",
            "to",
            "cc",
            "bcc",
            "subject",
            "receivedAt",
            "header:List-Id:asText",
            "header:List-Unsubscribe",
            ...hdrNames.map((n) => `header:${n}:asText`),
          ],
        );

        const moves: Array<Record<string, unknown>> = [];
        const byDestination: Record<string, number> = {};
        let leftInInbox = 0;

        for (const e of emails) {
          const from0 = (e.from as Array<{ name?: string; email?: string }>)
            ?.[0];
          const addr = from0?.email?.toLowerCase();
          if (!addr) {
            leftInInbox++;
            continue;
          }
          const recipients: string[] = [];
          for (const k of ["to", "cc", "bcc"]) {
            for (const x of (e[k] as Array<{ email?: string }>) ?? []) {
              if (x.email) recipients.push(x.email.toLowerCase());
            }
          }
          const listId = cleanListId(e["header:List-Id:asText"]);
          const listUnsub = typeof e["header:List-Unsubscribe"] === "string" &&
            (e["header:List-Unsubscribe"] as string).trim() !== "";
          const headers: Record<string, string> = {};
          for (const n of hdrNames) {
            const v = e[`header:${n}:asText`];
            if (typeof v === "string") headers[n.toLowerCase()] = v;
          }
          const { dest } = classifyMessage(
            {
              from: addr,
              fromName: from0?.name ?? null,
              recipients,
              listId,
              isBulk: !!listId || listUnsub,
              subject: typeof e.subject === "string" ? e.subject : null,
              headers,
            },
            setups,
            pathIndex,
          );
          if (!dest) {
            leftInInbox++;
            continue;
          }
          byDestination[dest.category] = (byDestination[dest.category] ?? 0) +
            1;
          moves.push({
            messageId: e.id as string,
            from: addr,
            subject: typeof e.subject === "string" ? e.subject : "",
            receivedAt: typeof e.receivedAt === "string" ? e.receivedAt : null,
            category: dest.category,
            sievePath: dest.sievePath,
            mailboxId: dest.mailboxId,
            matchedBy: dest.matchedBy,
            keepInbox: dest.keepInbox,
          });
        }

        context.logger?.info("Apply-sieve plan built", {
          scanned: ids.length,
          moves: moves.length,
          leftInInbox,
        });
        const handle = await context.writeResource("plan", args.name, {
          generatedAt: new Date().toISOString(),
          sourceMailbox: inMailbox ?? "", // "" = all-mail (no single source)
          scannedMessages: ids.length,
          moveCount: moves.length,
          leftInInbox,
          byDestination,
          moves,
        });
        return {
          dataHandles: [handle],
          scannedMessages: ids.length,
          moveCount: moves.length,
          byDestination,
        };
      },
    },

    email_analyze: {
      description:
        "Analyze a mailbox against the CURRENT rules (read-only): report overall composition and the senders that would still be LEFT in the inbox — the rule-candidate list that drives the pre-build tuning loop. Writes an 'analysis' resource. Moves nothing.",
      arguments: AnalyzeArgsSchema,
      execute: async (
        args: z.infer<typeof AnalyzeArgsSchema>,
        context: Ctx,
      ) => {
        const apiToken = resolveReadToken(context.globalArgs);
        const sessionUrl = context.globalArgs.sessionUrl ?? DEFAULT_SESSION_URL;
        const session = await fetchSession(apiToken, sessionUrl);
        const accountId = session.primaryAccounts[JMAP_MAIL_URN];
        const mailboxes = await fetchMailboxes(
          session.apiUrl,
          apiToken,
          accountId,
        );
        const pathIndex = buildPathIndex(mailboxes);
        const roleToId: Record<string, string> = {};
        for (const mb of mailboxes) {
          if (mb.role) roleToId[mb.role.toLowerCase()] = mb.id;
        }
        const explicit = args.inMailbox && args.inMailbox.trim()
          ? args.inMailbox.trim()
          : null;
        const inMailbox = explicit ?? roleToId[args.mailboxRole.toLowerCase()];
        if (!inMailbox) {
          throw new Error(`No mailbox found for role "${args.mailboxRole}".`);
        }

        const cap = args.maxMessages ?? Infinity;
        const ids = await queryIds(
          session.apiUrl,
          apiToken,
          accountId,
          { inMailbox },
          cap,
        );
        const setups = args.setups as unknown as SetupLike[];
        const hdrNames = neededHeaders(setups);
        const emails = await getEmailBatch(
          session.apiUrl,
          apiToken,
          accountId,
          ids,
          [
            "id",
            "from",
            "to",
            "cc",
            "bcc",
            "subject",
            "receivedAt",
            "keywords",
            "header:List-Id:asText",
            "header:List-Unsubscribe",
            ...hdrNames.map((n) => `header:${n}:asText`),
          ],
        );

        const coveredByCategory: Record<string, number> = {};
        let covered = 0;
        // Senders left in the inbox — aggregated by rule-pattern token, with the
        // reason they stayed so candidates (unmatched) split from kept-by-design.
        const remBy = new Map<string, {
          token: string;
          count: number;
          bulk: number;
          unread: number;
          reasons: Record<KeptReason, number>;
          sampleFroms: string[];
          sampleSubjects: string[];
        }>();
        let remBulk = 0;
        let remUnread = 0;
        const byReason: Record<KeptReason, number> = {
          unmatched: 0,
          excluded: 0,
          protected: 0,
          flagged: 0,
        };

        for (const e of emails) {
          const kw = (e.keywords ?? {}) as Record<string, boolean>;
          const isUnread = !kw["$seen"];
          const from0 = (e.from as Array<{ name?: string; email?: string }>)
            ?.[0];
          const addr = from0?.email?.toLowerCase() ?? "(no from address)";
          const listId = cleanListId(e["header:List-Id:asText"]);
          const listUnsub = typeof e["header:List-Unsubscribe"] === "string" &&
            (e["header:List-Unsubscribe"] as string).trim() !== "";
          const isBulk = !!listId || listUnsub;
          const recipients: string[] = [];
          for (const k of ["to", "cc", "bcc"]) {
            for (const x of (e[k] as Array<{ email?: string }>) ?? []) {
              if (x.email) recipients.push(x.email.toLowerCase());
            }
          }
          const headers: Record<string, string> = {};
          for (const n of hdrNames) {
            const v = e[`header:${n}:asText`];
            if (typeof v === "string") headers[n.toLowerCase()] = v;
          }
          const cls: Classification = from0?.email
            ? classifyMessage(
              {
                from: addr,
                fromName: from0?.name ?? null,
                recipients,
                listId,
                isBulk,
                subject: typeof e.subject === "string" ? e.subject : null,
                headers,
              },
              setups,
              pathIndex,
            )
            : { dest: null, keptReason: "unmatched" };
          if (cls.dest) {
            covered++;
            coveredByCategory[cls.dest.category] =
              (coveredByCategory[cls.dest.category] ?? 0) + 1;
            continue;
          }
          // Left in the inbox — group by sender token (the unit a rule targets).
          const reason = cls.keptReason ?? "unmatched";
          byReason[reason]++;
          const reg = registrableDomain(addr);
          const token = reg ? senderToken(addr, reg, {}) : addr;
          if (isBulk) remBulk++;
          if (isUnread) remUnread++;
          const row = remBy.get(token) ?? {
            token,
            count: 0,
            bulk: 0,
            unread: 0,
            reasons: { unmatched: 0, excluded: 0, protected: 0, flagged: 0 },
            sampleFroms: [],
            sampleSubjects: [],
          };
          row.count++;
          if (isBulk) row.bulk++;
          if (isUnread) row.unread++;
          row.reasons[reason]++;
          if (!row.sampleFroms.includes(addr) && row.sampleFroms.length < 3) {
            row.sampleFroms.push(addr);
          }
          const subj = typeof e.subject === "string" ? e.subject : "";
          if (subj && row.sampleSubjects.length < 3) {
            row.sampleSubjects.push(subj);
          }
          remBy.set(token, row);
        }

        const rows = [...remBy.values()]
          .map((r) => {
            const dominant =
              (Object.entries(r.reasons) as Array<[KeptReason, number]>)
                .sort((a, b) => b[1] - a[1])[0][0];
            return {
              token: r.token,
              count: r.count,
              bulk: r.bulk,
              unread: r.unread,
              reason: dominant,
              sampleFroms: r.sampleFroms,
              sampleSubjects: r.sampleSubjects,
            };
          })
          .sort((a, b) => b.count - a.count || a.token.localeCompare(b.token));
        const remainingTotal = rows.reduce((n, r) => n + r.count, 0);
        const candidates = rows.filter((r) => r.reason === "unmatched").slice(
          0,
          40,
        );
        const keptByDesign = rows.filter((r) => r.reason !== "unmatched").slice(
          0,
          25,
        );
        const remaining = {
          total: remainingTotal,
          bulk: remBulk,
          personal: remainingTotal - remBulk,
          unread: remUnread,
          distinctSenders: rows.length,
          byReason,
          candidates,
          keptByDesign,
        };

        context.logger?.info("Inbox analysis built", {
          scanned: ids.length,
          covered,
          remaining: remainingTotal,
          candidates: candidates.length,
        });
        const handle = await context.writeResource("analysis", args.name, {
          generatedAt: new Date().toISOString(),
          sourceMailbox: inMailbox,
          scannedMessages: ids.length,
          covered,
          coveredByCategory,
          remaining,
        });
        return {
          dataHandles: [handle],
          scannedMessages: ids.length,
          covered,
          remaining,
        };
      },
    },

    email_headers: {
      description:
        "Diagnostic (read-only): dump the full header list of sample messages matching a `from` filter to a 'headers' resource — for discovering a robust header to build a rule on.",
      arguments: z.object({
        from: z.string().describe(
          "Sender substring to sample (JMAP from filter).",
        ),
        inMailbox: z.string().optional().describe("Restrict to a mailbox id."),
        limit: z.number().int().positive().default(3),
        name: z.string().default("headers").describe("Resource instance name."),
      }),
      execute: async (
        args: { from: string; inMailbox?: string; limit: number; name: string },
        context: Ctx,
      ) => {
        const apiToken = resolveReadToken(context.globalArgs);
        const sessionUrl = context.globalArgs.sessionUrl ?? DEFAULT_SESSION_URL;
        const session = await fetchSession(apiToken, sessionUrl);
        const accountId = session.primaryAccounts[JMAP_MAIL_URN];
        const filter: Record<string, unknown> = { from: args.from };
        if (args.inMailbox) filter.inMailbox = args.inMailbox;
        const ids = await queryIds(
          session.apiUrl,
          apiToken,
          accountId,
          filter,
          args.limit,
        );
        const emails = await getEmailBatch(
          session.apiUrl,
          apiToken,
          accountId,
          ids,
          ["subject", "from", "headers"],
        );
        const messages = emails.map((e) => ({
          subject: typeof e.subject === "string" ? e.subject : null,
          from: (e.from as Array<{ email?: string }>)?.[0]?.email ?? null,
          headers: (e.headers as Array<{ name: string; value: string }>) ?? [],
        }));
        const handle = await context.writeResource("headers", args.name, {
          query: args.from,
          messages,
        });
        return { dataHandles: [handle], count: messages.length };
      },
    },

    email_move: {
      description:
        "Apply the sieve plan by moving messages to their destination folders (JMAP Email/set mailboxIds). DEFAULT DRY-RUN — moves nothing and just reports. `execute: true` performs the moves and REQUIRES a write-scoped token. Always gate behind a manual-approval step.",
      arguments: MoveArgsSchema,
      execute: async (args: z.infer<typeof MoveArgsSchema>, context: Ctx) => {
        const plan = await context.readResource?.(args.source);
        if (!plan) {
          throw new Error(
            `No plan named "${args.source}" — run email_plan first.`,
          );
        }
        const allMoves = (plan.moves as Array<
          {
            messageId: string;
            mailboxId: string | null;
            category: string;
            keepInbox?: boolean;
          }
        >) ?? [];
        const sourceMailbox = plan.sourceMailbox as string | undefined;
        // A message already in its target mailbox is a no-op — and a naive move
        // patch would add AND remove the same id and strip it into limbo (e.g.
        // re-filing the Newsletters bulk-fallback against the Newsletters folder
        // itself). Drop those.
        const alreadyThere =
          allMoves.filter((m) => !!m.mailboxId && m.mailboxId === sourceMailbox)
            .length;
        const moves = allMoves.filter((m) => m.mailboxId !== sourceMailbox);
        // Every remaining move is fileable — the target label is created if missing.
        // keepInbox = add the label but leave it in the source; otherwise it moves
        // out. forceMove removes the source even for keep rules (folder cleanup).
        const wouldLabel = args.labelOnly
          ? moves.length
          : (args.forceMove ? 0 : moves.filter((m) => m.keepInbox).length);
        const wouldMove = moves.length - wouldLabel;
        const foldersToCreate = [
          ...new Set(moves.filter((m) => !m.mailboxId).map((m) => m.category)),
        ];

        if (!args.execute) {
          context.logger?.info("email_move DRY-RUN (nothing moved)", {
            wouldMove,
            wouldLabel,
            alreadyThere,
            foldersToCreate: foldersToCreate.length,
          });
          return {
            dryRun: true,
            wouldMove,
            wouldLabel,
            alreadyThere,
            foldersToCreate,
            byDestination: plan.byDestination,
          };
        }

        // Real execution — least-privilege: use the write-scoped token only.
        // Refuse to fall back to the read-only apiToken so a missing write token
        // fails loudly here instead of as an opaque JMAP 403 mid-batch.
        const writeToken = context.globalArgs.writeToken;
        if (!writeToken) {
          throw new Error(
            "email_move execute:true needs a write-scoped token. Vault it " +
              "(swamp vault put local-secrets fastmail-write-token) and set " +
              "globalArguments.writeToken on my-fastmail. The read-only apiToken " +
              "is never used for moves.",
          );
        }
        const sessionUrl = context.globalArgs.sessionUrl ?? DEFAULT_SESSION_URL;
        const session = await fetchSession(writeToken, sessionUrl);
        const accountId = session.primaryAccounts[JMAP_MAIL_URN];

        // Resolve every category to a target mailbox id, creating missing (nested)
        // labels first — the plan leaves mailboxId null for labels that don't exist.
        const mailboxes = await fetchMailboxes(
          session.apiUrl,
          writeToken,
          accountId,
        );
        const idByCat = new Map<string, string>();
        for (const m of moves) {
          if (m.mailboxId) idByCat.set(m.category, m.mailboxId);
        }
        const createdFolders: string[] = [];
        for (const cat of new Set(moves.map((m) => m.category))) {
          if (idByCat.has(cat)) continue;
          const { id, created } = await ensureMailbox(
            session.apiUrl,
            writeToken,
            accountId,
            cat,
            mailboxes,
          );
          idByCat.set(cat, id);
          createdFolders.push(...created);
        }

        let updated = 0;
        const notUpdated: Record<string, unknown> = {};
        for (let i = 0; i < moves.length; i += args.batchSize) {
          const batch = moves.slice(i, i + args.batchSize);
          // JMAP PatchObject: add the target label; for a real move also drop the
          // source (Inbox) mailbox. keepInbox leaves the Inbox in place, and this
          // never touches other labels the message already carries.
          const update = Object.fromEntries(
            batch.map((m) => {
              const patch: Record<string, boolean | null> = {
                [`mailboxIds/${idByCat.get(m.category)!}`]: true,
              };
              if (
                !args.labelOnly && (!m.keepInbox || args.forceMove) &&
                sourceMailbox
              ) {
                patch[`mailboxIds/${sourceMailbox}`] = null;
              }
              return [m.messageId, patch];
            }),
          );
          const resp = await jmapRequest(session.apiUrl, writeToken, [
            ["Email/set", { accountId, update }, "0"],
          ]);
          const r = unwrapMethodResponse(resp, "Email/set") as {
            updated?: Record<string, unknown>;
            notUpdated?: Record<string, unknown>;
          };
          updated += Object.keys(r.updated ?? {}).length;
          Object.assign(notUpdated, r.notUpdated ?? {});
        }
        const notUpdatedCount = Object.keys(notUpdated).length;
        context.logger?.info("email_move executed", {
          updated,
          labeled: wouldLabel,
          moved: wouldMove,
          alreadyThere,
          createdFolders: createdFolders.length,
          notUpdated: notUpdatedCount,
        });
        return {
          executed: true,
          updated,
          labeled: wouldLabel,
          moved: wouldMove,
          alreadyThere,
          createdFolders,
          notUpdatedCount,
          notUpdated,
        };
      },
    },
  },
};
