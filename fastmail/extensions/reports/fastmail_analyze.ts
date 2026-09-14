// Standalone inbox-analysis report for @dmc/fastmail email_analyze.
//
// Scope: method. Renders inbox composition, the senders the CURRENT rules would
// leave behind split into real rule CANDIDATES (nothing matched) vs KEPT BY
// DESIGN (exclude list / finance-protect stop / flag-only rule), and what's
// already covered. No-ops on runs with no `analysis` data.

type KeptReason = "protected" | "excluded" | "flagged" | "unmatched";

interface AnalysisSender {
  token: string;
  count: number;
  bulk: number;
  unread: number;
  reason: KeptReason;
  sampleFroms: string[];
  sampleSubjects: string[];
}
interface AnalysisData {
  sourceMailbox: string;
  scannedMessages: number;
  covered: number;
  coveredByCategory: Record<string, number>;
  remaining: {
    total: number;
    bulk: number;
    personal: number;
    unread: number;
    distinctSenders: number;
    byReason: Record<string, number>;
    candidates: AnalysisSender[];
    keptByDesign: AnalysisSender[];
  };
}

const REASON_LABEL: Record<KeptReason, string> = {
  protected: "finance-protect (stop)",
  excluded: "exclude list",
  flagged: "flag rule",
  unmatched: "no rule",
};

/**
 * `@dmc/fastmail-analyze` — method-scoped report that reads the `analysis`
 * artifact from an `email_analyze` run and renders inbox composition: what the
 * current rules already cover, and the senders still left in the inbox split
 * into real rule CANDIDATES (nothing matched) vs. KEPT BY DESIGN (exclude list,
 * finance-protect stop, or flag-only rule). No-ops on runs with no `analysis`
 * data.
 */
export const report = {
  name: "@dmc/fastmail-analyze",
  description:
    "Analyze a mailbox against the current rules: composition, the senders that would still be left in the inbox split into rule candidates vs kept-by-design, and what's already covered.",
  scope: "method" as const,
  labels: ["email", "fastmail", "analyze", "rules"],
  execute: async (context: {
    dataHandles: Array<{ specName: string; name: string; version: number }>;
    modelType: string;
    modelId: string;
    dataRepository: {
      getContent: (
        modelType: string,
        modelId: string,
        name: string,
        version: number,
      ) => Promise<Uint8Array | null>;
    };
  }) => {
    const handle = (context.dataHandles ?? []).find((h) =>
      h.specName === "analysis"
    );
    if (!handle) {
      return {
        markdown: "_No inbox analysis in this run (not an email_analyze run)._",
        json: { applicable: false },
      };
    }
    const raw = await context.dataRepository.getContent(
      context.modelType,
      context.modelId,
      handle.name,
      handle.version,
    );
    if (!raw) return { markdown: "_Analysis data not found._", json: {} };
    const d = JSON.parse(new TextDecoder().decode(raw)) as AnalysisData;
    const r = d.remaining;

    const pct = (n: number, total: number) =>
      total > 0 ? `${Math.round((n / total) * 100)}%` : "0%";
    const clip = (s: string) => (s ?? "").slice(0, 48).replace(/\|/g, "\\|");

    // Real rule candidates — nothing matched these.
    const candRows = (r.candidates ?? [])
      .map((s) =>
        `| ${s.count} | ${s.token} | ${
          s.bulk ? "bulk" : "personal"
        } | ${s.unread} | ${clip(s.sampleSubjects[0] ?? "")} |`
      )
      .join("\n");

    // Kept by design — already handled; not candidates.
    const keptRows = (r.keptByDesign ?? [])
      .map((s) =>
        `| ${s.count} | ${s.token} | ${REASON_LABEL[s.reason]} | ${
          clip(s.sampleSubjects[0] ?? "")
        } |`
      )
      .join("\n");

    const covRows = Object.entries(d.coveredByCategory ?? {})
      .sort((a, b) => b[1] - a[1])
      .map(([cat, n]) => `| ${n} | ${cat} |`)
      .join("\n");

    const br = r.byReason ?? {};
    const markdown = [
      "# Inbox Analysis — what the rules cover vs. what's left",
      "",
      `- **Scanned:** ${d.scannedMessages} messages in \`${d.sourceMailbox}\``,
      `- **Covered by current rules:** ${d.covered} (${
        pct(d.covered, d.scannedMessages)
      })`,
      `- **Left in the inbox:** ${r.total} (${
        pct(r.total, d.scannedMessages)
      }) — ` +
      `${r.bulk} bulk / ${r.personal} personal, ${r.unread} unread, ` +
      `${r.distinctSenders} distinct senders`,
      `- **Why left:** ${br.unmatched ?? 0} need a rule · ${
        br.excluded ?? 0
      } excluded · ` +
      `${br.protected ?? 0} finance-protected · ${br.flagged ?? 0} flag-kept`,
      "",
      "## Rule candidates — nothing matched these",
      "",
      "The to-do list. `bulk` = has List-Id/List-Unsubscribe (fold into a bulk",
      "folder); a personal, low-count row is more likely genuine inbox mail.",
      "",
      "| Msgs | Sender token | Kind | Unread | Sample subject |",
      "| ---: | :-- | :-- | ---: | :-- |",
      candRows ||
      "| — | (none — every leftover is kept by design) | — | — | — |",
      "",
      "## Kept by design — already handled, not candidates",
      "",
      "| Msgs | Sender token | Why kept | Sample subject |",
      "| ---: | :-- | :-- | :-- |",
      keptRows || "| — | (none) | — | — |",
      "",
      "## Covered by current rules",
      "",
      "| Msgs | Folder |",
      "| ---: | :-- |",
      covRows || "| — | (none) |",
      "",
      "> Read-only analysis. Add rules in `config/email-config.yaml` for the",
      "> candidates worth filing, then re-run to watch the candidate list shrink.",
    ].join("\n");

    return {
      markdown,
      json: {
        applicable: true,
        scannedMessages: d.scannedMessages,
        covered: d.covered,
        remaining: r,
      },
    };
  },
};
