/**
 * @dmc/patch-access — the access audit of the swamp-patch login across the fleet.
 *
 * Model-scoped on @dmc/patch/fleet: reads the latest `accessAudit` of each host (from
 * auditAccess), the latest `accessRun` per action (provisionAccess / revokeAccess) and
 * the latest `inventory` (the accepted risks and findings of the last scan). The top
 * lines flag what needs attention; one section per host follows. Text that came from a
 * host or from a definition is escaped by `mdCell` before it reaches Markdown. The json
 * output keeps the raw values. Fetch with:
 *   swamp report get @dmc/patch-access --model fleet --markdown
 *
 * @module
 */

import { isOverdue } from "../models/lib/access_policy.ts";

interface Finding {
  id: string;
  severity: string;
  message: string;
}

interface AcceptedRisk extends Finding {
  record: {
    reason: string;
    acceptedBy: string;
    acceptedAt: string;
    reviewBy: string;
  };
}

/** One accessAudit record: named `access-audit-<host>`. */
interface Audit {
  host: string;
  auditedAt: string;
  ok: boolean;
  findings: Finding[];
  acceptedRisks: AcceptedRisk[];
  userProbeError?: string | null;
  rootProbeError?: string | null;
}

/** One accessRun record: named `access-<action>-<host>-<ts>`. */
interface Run {
  host: string;
  action: "provision" | "revoke";
  dryRun: boolean;
  outcome: string;
  ranAt: string;
}

/** The inventory record of a host, from its last scan. */
interface Scan {
  hostname: string;
  acceptedRisksUsed?: string[] | null;
  securityFindings?: string[] | null;
}

interface DataMeta {
  name: string;
  version: number;
  tags?: Record<string, string>;
}

// ModelType is an opaque token object (not a string) that the data methods require.
type ModelTypeRef = unknown;

interface ModelCtx {
  modelType: ModelTypeRef;
  modelId: string;
  /** Model global arguments; `machines` is the current fleet. */
  globalArgs?: { machines?: Array<{ host: string }> };
  dataRepository: {
    findAllForModel(type: ModelTypeRef, modelId: string): Promise<DataMeta[]>;
    getContent(
      type: ModelTypeRef,
      modelId: string,
      dataName: string,
      version?: number,
    ): Promise<Uint8Array | null>;
  };
}

/** Markdown and HTML syntax that is escaped in a host-supplied or definition-supplied value. */
const MD_ESCAPES: Record<string, string> = {
  "\\": "\\\\",
  "|": "\\|",
  "`": "\\`",
  "<": "&lt;",
  ">": "&gt;",
  "*": "\\*",
  "_": "\\_",
  "[": "\\[",
  "]": "\\]",
  "#": "\\#",
};

/** The most characters one value shows; a longer value is cut and marked with an ellipsis. */
const MAX_TEXT = 300;

/**
 * Make a value safe for one Markdown table cell or one plain line. Line breaks and tabs
 * become one space per run. Other control characters are dropped. The text is cut to
 * MAX_TEXT characters and marked with an ellipsis. Syntax is escaped in one pass, so no
 * backslash is escaped twice.
 */
export function mdCell(s: string): string {
  const flat = s.replace(/[\r\n\t]+/g, " ");
  const printable = [...flat].filter((c) => {
    const code = c.codePointAt(0) ?? 0;
    return code >= 0x20 && (code < 0x7f || code > 0x9f);
  }).join("");
  const chars = [...printable];
  const cut = chars.length > MAX_TEXT
    ? chars.slice(0, MAX_TEXT).join("") + "…"
    : printable;
  return cut.replace(/[\\|`<>*_[\]#]/g, (c) => MD_ESCAPES[c]);
}

const DAY_MS = 24 * 60 * 60 * 1000;
/** An audit older than this is reported as stale. */
const STALE_AFTER_MS = 7 * DAY_MS;
const SEVERITIES = ["critical", "high", "warning", "info"];

/** Sort rank of a severity. A host with no findings (null) sorts after every severity. */
const rank = (sev: string | null): number => {
  const i = SEVERITIES.indexOf(sev ?? "");
  return i === -1 ? SEVERITIES.length : i;
};

const AUDIT_PREFIX = "access-audit-";
const RUN_NAME = /^access-(provision|revoke)-/;

const stamp = (ts: string): string => {
  const t = Date.parse(ts);
  return Number.isNaN(t)
    ? "—"
    : new Date(t).toISOString().slice(0, 16).replace("T", " ") + " UTC";
};

const list = (xs: string[] | null | undefined): string =>
  xs && xs.length > 0 ? xs.map(mdCell).join(", ") : "none";

export const report = {
  name: "@dmc/patch-access",
  description:
    "Access audit of the swamp-patch login across fleet nodes: findings, accepted risks, missing or stale audits, last provision and revoke runs",
  scope: "model" as const,
  labels: ["patch", "patching", "access", "security", "fleet"],
  execute: async (context: ModelCtx) => {
    const dec = new TextDecoder();
    const now = new Date();
    const all = await context.dataRepository.findAllForModel(
      context.modelType,
      context.modelId,
    );
    // Keep the latest version of each record. The spec tag is part of the key: an
    // accessPlan record and an inventory record can share a host name.
    const latest = new Map<string, DataMeta>();
    for (const d of all) {
      const key = JSON.stringify([d.tags?.specName ?? "", d.name]);
      const prev = latest.get(key);
      if (!prev || d.version > prev.version) latest.set(key, d);
    }

    const audits = new Map<string, Audit>();
    const runs: Run[] = [];
    const scans = new Map<string, Scan>();
    for (const d of latest.values()) {
      const raw = await context.dataRepository.getContent(
        context.modelType,
        context.modelId,
        d.name,
        d.version,
      );
      if (!raw) continue;
      let body: Record<string, unknown>;
      try {
        body = JSON.parse(dec.decode(raw));
      } catch {
        continue;
      }
      if (!body || typeof body !== "object") continue;
      if (
        d.name.startsWith(AUDIT_PREFIX) && typeof body.host === "string" &&
        Array.isArray(body.findings) && Array.isArray(body.acceptedRisks)
      ) {
        audits.set(body.host, body as unknown as Audit);
      } else if (RUN_NAME.test(d.name) && typeof body.host === "string") {
        runs.push(body as unknown as Run);
      } else if (typeof body.hostname === "string") {
        // Only inventory has a hostname; an accessPlan of the same host does not.
        scans.set(body.hostname, body as unknown as Scan);
      }
    }

    // The current fleet. Without machines in the context, the hosts with an inventory
    // record are the fleet.
    const machines = [
      ...new Set((context.globalArgs?.machines ?? []).map((m) => m.host)),
    ];
    const fleet = machines.length > 0 ? machines : [...scans.keys()];
    const notAudited = fleet.filter((h) => !audits.has(h)).sort((a, b) =>
      a.localeCompare(b)
    );
    // An audit time that does not parse is stale too (fails closed).
    const staleAudit = [...audits.values()]
      .filter((a) =>
        !(now.getTime() - Date.parse(a.auditedAt) <= STALE_AFTER_MS)
      )
      .map((a) => a.host)
      .sort((a, b) => a.localeCompare(b));

    const latestRun = (host: string, action: Run["action"]): Run | null => {
      let best: Run | null = null;
      for (const r of runs) {
        if (r.host !== host || r.action !== action) continue;
        if (!best || Date.parse(r.ranAt) > Date.parse(best.ranAt)) best = r;
      }
      return best;
    };

    const hosts = [...audits.values()].map((audit) => {
      const findings = [...audit.findings].sort((a, b) =>
        (rank(a.severity) - rank(b.severity)) || a.id.localeCompare(b.id)
      );
      return {
        host: audit.host,
        audit,
        findings,
        worst: findings.length > 0 ? findings[0].severity : null,
        lastProvision: latestRun(audit.host, "provision"),
        lastRevoke: latestRun(audit.host, "revoke"),
        scan: scans.get(audit.host) ?? null,
      };
    }).sort((a, b) =>
      (rank(a.worst) - rank(b.worst)) || a.host.localeCompare(b.host)
    );

    const findingsOf = (sev: string) =>
      hosts.flatMap((h) => h.findings.filter((f) => f.severity === sev));
    const hostsWith = (sev: string) =>
      hosts.filter((h) => h.findings.some((f) => f.severity === sev)).length;
    const critical = findingsOf("critical").length;
    const criticalHosts = hostsWith("critical");
    const high = findingsOf("high").length;
    const highHosts = hostsWith("high");
    const accepted = hosts.flatMap((h) => h.audit.acceptedRisks);
    const acceptedHosts = hosts.filter((h) => h.audit.acceptedRisks.length > 0)
      .length;
    const overdue = accepted.filter((r) => isOverdue(r.record, now)).length;

    const flags: string[] = [];
    if (critical > 0) {
      flags.push(`CRITICAL: ${critical} on ${criticalHosts} hosts`);
    }
    if (high > 0) flags.push(`HIGH: ${high} on ${highHosts} hosts`);
    const warning = findingsOf("warning").length;
    if (warning > 0) {
      flags.push(`WARNING: ${warning} on ${hostsWith("warning")} hosts`);
    }
    if (accepted.length > 0) {
      flags.push(
        `ACCEPTED RISKS: ${accepted.length} on ${acceptedHosts} hosts` +
          (overdue > 0 ? `, ${overdue} overdue` : ""),
      );
    }
    if (notAudited.length > 0) {
      flags.push(`NOT AUDITED: ${notAudited.map(mdCell).join(", ")}`);
    }
    if (staleAudit.length > 0) {
      flags.push(`STALE AUDIT: ${staleAudit.map(mdCell).join(", ")}`);
    }

    const lines: string[] = [];
    if (hosts.length === 0 && flags.length === 0) {
      // Nothing audited and no fleet to compare with: an all-clear would be vacuous.
      lines.push("No access audits yet: run auditAccess.", "");
    } else if (flags.length === 0) {
      lines.push("All audited hosts pass with no accepted risks.", "");
    } else {
      // Two trailing spaces keep each flag on its own line, as patch-status does.
      lines.push(
        ...flags.map((f, i) => (i < flags.length - 1 ? `${f}  ` : f)),
        "",
      );
    }

    const runCell = (r: Run | null): string =>
      r
        ? `${mdCell(r.outcome)}${r.dryRun ? " (dry run)" : ""} at ${
          stamp(r.ranAt)
        }`
        : "none";

    for (const h of hosts) {
      const { audit: a } = h;
      lines.push(
        `## ${mdCell(h.host)}`,
        "",
        `Audited ${stamp(a.auditedAt)} · ok: ${a.ok ? "yes" : "**no**"}`,
        "",
      );

      if (h.findings.length === 0) {
        lines.push("No findings.", "");
      } else {
        lines.push(
          "| Severity | Id | Message |",
          "| -------- | -- | ------- |",
          ...h.findings.map((f) =>
            `| ${mdCell(f.severity)} | ${mdCell(f.id)} | ${mdCell(f.message)} |`
          ),
          "",
        );
      }

      if (a.acceptedRisks.length > 0) {
        lines.push(
          "### Accepted risks",
          "",
          "| Id | Severity | Reason | Accepted by | Accepted at | Review by |",
          "| -- | -------- | ------ | ----------- | ----------- | --------- |",
          ...a.acceptedRisks.map((r) => {
            const over = isOverdue(r.record, now) ? " **OVERDUE**" : "";
            return `| ${mdCell(r.id)} | ${mdCell(r.severity)} | ${
              mdCell(r.record.reason)
            } | ${mdCell(r.record.acceptedBy)} | ${
              mdCell(r.record.acceptedAt)
            } | ${mdCell(r.record.reviewBy)}${over} |`;
          }),
          "",
        );
      }

      const probeErrors = [
        a.userProbeError ? `- User probe: ${mdCell(a.userProbeError)}` : null,
        a.rootProbeError ? `- Root probe: ${mdCell(a.rootProbeError)}` : null,
      ].filter((l): l is string => l !== null);
      if (probeErrors.length > 0) {
        lines.push("### Probe errors", "", ...probeErrors, "");
      }

      lines.push(
        "### Access runs",
        "",
        `- Last provision: ${runCell(h.lastProvision)}`,
        `- Last revoke: ${runCell(h.lastRevoke)}`,
        "",
      );

      lines.push("### Last scan", "");
      if (h.scan) {
        lines.push(
          `- Accepted risks used: ${list(h.scan.acceptedRisksUsed)}`,
          `- Security findings: ${list(h.scan.securityFindings)}`,
        );
      } else {
        lines.push("No inventory record.");
      }
      lines.push("");
    }

    return {
      markdown: lines.join("\n"),
      json: {
        generatedAt: now.toISOString(),
        flags: {
          critical,
          high,
          acceptedRisks: accepted.length,
          overdue,
          notAudited,
          staleAudit,
        },
        hosts: hosts.map((h) => ({
          host: h.host,
          auditedAt: h.audit.auditedAt,
          ok: h.audit.ok,
          worst: h.worst,
          findings: h.findings,
          acceptedRisks: h.audit.acceptedRisks,
          lastProvision: h.lastProvision &&
            {
              outcome: h.lastProvision.outcome,
              dryRun: h.lastProvision.dryRun,
              ranAt: h.lastProvision.ranAt,
            },
          lastRevoke: h.lastRevoke &&
            {
              outcome: h.lastRevoke.outcome,
              dryRun: h.lastRevoke.dryRun,
              ranAt: h.lastRevoke.ranAt,
            },
          lastScan: h.scan && {
            acceptedRisksUsed: h.scan.acceptedRisksUsed ?? [],
            securityFindings: h.scan.securityFindings ?? [],
          },
        })),
      },
    };
  },
};
