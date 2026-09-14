// Inbox-audit report — renders a human summary of an email_senders scan.
//
// Scope: method. It reads every "senders" data artifact produced by a run and
// summarizes sender volume, bulk-ness, and unsubscribe availability. It is
// independent of sieve_generate: run `email_senders` (e.g. via the build-sieves
// workflow's scan step, or standalone) and this report is produced from the
// scan alone. On method runs that produce no "senders" data it no-ops.

interface Sender {
  email: string;
  name: string | null;
  count: number;
  bulkCount: number;
  unreadCount: number;
  oneClickUnsubscribe: boolean;
  listIds: string[];
  mostRecent: string | null;
  sampleSubjects: string[];
}

interface SendersData {
  scannedAt: string;
  scope: {
    name: string;
    mode: string;
    inMailbox: string | null;
    maxMessages: number | null;
  };
  scannedMessages: number;
  unreadMessages: number;
  senderCount: number;
  bulkSenders: number;
  senders: Sender[];
  headerStats?: Record<string, Array<{ value: string; count: number }>>;
}

function pct(n: number, d: number): string {
  return d === 0 ? "0%" : `${Math.round((n / d) * 100)}%`;
}

/** Smallest number of senders accounting for >= `frac` of total messages. */
function concentration(
  senders: Sender[],
  totalMsgs: number,
  frac: number,
): number {
  const sorted = [...senders].sort((a, b) => b.count - a.count);
  let acc = 0;
  for (let i = 0; i < sorted.length; i++) {
    acc += sorted[i].count;
    if (acc >= totalMsgs * frac) return i + 1;
  }
  return sorted.length;
}

function scopeSection(
  d: SendersData,
): { md: string; json: Record<string, unknown> } {
  const senders = d.senders ?? [];
  const bulk = senders.filter((s) => s.bulkCount > 0);
  const nonBulk = senders.filter((s) => s.bulkCount === 0);
  const bulkMsgs = bulk.reduce((a, s) => a + s.bulkCount, 0);
  const oneClick = senders.filter((s) => s.oneClickUnsubscribe).length;
  const unreadMsgs = d.unreadMessages ??
    senders.reduce((a, s) => a + (s.unreadCount ?? 0), 0);
  const top = [...senders].sort((a, b) => b.count - a.count).slice(0, 20);

  const rows = top
    .map((s) => {
      const ratio = s.count ? Math.round((s.bulkCount / s.count) * 100) : 0;
      const tag = s.oneClickUnsubscribe ? "1-click" : ratio > 0 ? "bulk" : "—";
      const name = (s.name ?? "").replace(/\|/g, "/");
      return `| ${s.count} | ${s.unreadCount} | ${ratio}% | ${tag} | ${s.email} | ${name} |`;
    })
    .join("\n");

  // Most-unread senders — the highest-value unsubscribe/archive targets.
  const topUnread = [...senders]
    .filter((s) => s.unreadCount > 0)
    .sort((a, b) => b.unreadCount - a.unreadCount)
    .slice(0, 15);
  const unreadRows = topUnread
    .map((s) => {
      const name = (s.name ?? "").replace(/\|/g, "/");
      const unsub = s.oneClickUnsubscribe ? "1-click" : "—";
      return `| ${s.unreadCount} | ${s.count} | ${unsub} | ${s.email} | ${name} |`;
    })
    .join("\n");

  const c50 = concentration(senders, d.scannedMessages, 0.5);
  const c80 = concentration(senders, d.scannedMessages, 0.8);

  // Header value frequency (a rule-discovery aid): value → count per header.
  const headerStats = d.headerStats ?? {};
  const headerSections = Object.entries(headerStats)
    .filter(([, vals]) => vals.length)
    .map(([name, vals]) => {
      const rows = vals
        .map((v) =>
          `| ${v.count} | ${v.value.replace(/\|/g, "\\|").slice(0, 60)} |`
        )
        .join("\n");
      return [
        `### Header \`${name}\` — value distribution`,
        "",
        "| Msgs | Value |",
        "| ---: | :-- |",
        rows,
        "",
      ].join("\n");
    })
    .join("\n");

  const md = [
    `## Scope: \`${d.scope.name}\` (${d.scope.mode})`,
    "",
    `- **Messages scanned:** ${d.scannedMessages}`,
    `- **Unread:** ${unreadMsgs} (${
      pct(unreadMsgs, d.scannedMessages)
    } of scanned)`,
    `- **Distinct senders:** ${d.senderCount}`,
    `- **Bulk senders:** ${bulk.length} (${
      pct(bulk.length, d.senderCount)
    } of senders, ${pct(bulkMsgs, d.scannedMessages)} of mail)`,
    `- **Non-bulk (likely personal/transactional):** ${nonBulk.length} senders`,
    `- **Offer one-click unsubscribe:** ${oneClick} senders`,
    `- **Concentration:** ${c50} senders = 50% of mail, ${c80} senders = 80%`,
    "",
    "### Top 20 senders by volume",
    "",
    "| Msgs | Unread | Bulk% | Tag | Sender | Name |",
    "| ---: | ---: | ---: | :-- | :-- | :-- |",
    rows || "| — | — | — | — | (none) | |",
    "",
    "### Top 15 senders by unread (cleanup targets)",
    "",
    "| Unread | Total | Unsub | Sender | Name |",
    "| ---: | ---: | :-- | :-- | :-- |",
    unreadRows || "| — | — | — | (none) | |",
    "",
    headerSections,
  ].join("\n");

  return {
    md,
    json: {
      scope: d.scope.name,
      mode: d.scope.mode,
      scannedMessages: d.scannedMessages,
      unreadMessages: unreadMsgs,
      senderCount: d.senderCount,
      bulkSenders: bulk.length,
      bulkMessages: bulkMsgs,
      nonBulkSenders: nonBulk.length,
      oneClickUnsubscribe: oneClick,
      concentration50: c50,
      concentration80: c80,
      topSenders: top.map((s) => ({
        email: s.email,
        name: s.name,
        count: s.count,
        unreadCount: s.unreadCount,
        bulkCount: s.bulkCount,
        oneClickUnsubscribe: s.oneClickUnsubscribe,
      })),
      topUnread: topUnread.map((s) => ({
        email: s.email,
        name: s.name,
        unreadCount: s.unreadCount,
        count: s.count,
        oneClickUnsubscribe: s.oneClickUnsubscribe,
      })),
      headerStats,
    },
  };
}

/**
 * `@dmc/fastmail-audit` — method-scoped report that reads the `senders`
 * artifacts from a run and audits the sender inventory (bulk vs. personal,
 * message concentration, and coverage gaps). No-ops on runs that produce no
 * `senders` data.
 */
export const report = {
  name: "@dmc/fastmail-audit",
  description:
    "Summarize an email_senders scan: sender volume, bulk-ness, unsubscribe availability, and volume concentration.",
  scope: "method" as const,
  labels: ["email", "inbox", "audit"],
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
    const handles = (context.dataHandles ?? []).filter(
      (h) => h.specName === "senders",
    );
    if (handles.length === 0) {
      return {
        markdown:
          "_Inbox audit: no `senders` data in this run (not an email_senders scan)._",
        json: { applicable: false },
      };
    }

    const sections: string[] = [];
    const jsonScopes: Record<string, unknown>[] = [];
    for (const h of handles) {
      const raw = await context.dataRepository.getContent(
        context.modelType,
        context.modelId,
        h.name,
        h.version,
      );
      if (!raw) continue;
      const data = JSON.parse(new TextDecoder().decode(raw)) as SendersData;
      const { md, json } = scopeSection(data);
      sections.push(md);
      jsonScopes.push(json);
    }

    const markdown = [`# Inbox Audit`, "", ...sections].join("\n");
    return { markdown, json: { applicable: true, scopes: jsonScopes } };
  },
};
