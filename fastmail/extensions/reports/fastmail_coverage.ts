// Rule-coverage report for @dmc/fastmail sieve_generate.
//
// Scope: method. Reads every `sieve` data artifact a generate run produced and,
// per file setup, shows how much of the mail your rules cover vs. what fell
// through to the bulk fallback ("uncategorized"). The ranked uncategorized list
// is the actionable to-do for new rules in config/email-config.yaml.
//
// "Uncategorized" = a sender that no rules[] pattern matched, so it landed in the
// setup's bulkFallback category. It no-ops on runs with no `sieve` data.

interface UncategorizedSender {
  email: string;
  name: string | null;
  count: number;
}

interface SieveData {
  source: string;
  mode: string;
  folderPrefix: string;
  sendersMatched: number;
  bulkFallbackCount: number;
  leftInInbox: number;
  uncategorized: UncategorizedSender[];
}

function pct(n: number, d: number): string {
  return d === 0 ? "n/a" : `${Math.round((n / d) * 100)}%`;
}

function setupSection(
  name: string,
  d: SieveData,
): { md: string; json: Record<string, unknown> } {
  const uncategorized = d.uncategorized ?? [];
  const categorizable = d.sendersMatched + d.bulkFallbackCount;
  const rows = uncategorized
    .map((s) =>
      `| ${s.count} | ${s.email} | ${(s.name ?? "").replace(/\|/g, "/")} |`
    )
    .join("\n");

  const md = [
    `## Setup: \`${name}\`  (source: \`${d.source}\`)`,
    "",
    `- **Filed to folders:** ${d.sendersMatched} senders`,
    `- **Uncategorized (bulk, no rule matched → fallback):** ${d.bulkFallbackCount} senders`,
    `- **Left in Inbox (personal / denied):** ${d.leftInInbox} senders`,
    `- **Rule coverage:** ${
      pct(d.sendersMatched, categorizable)
    } of categorizable mail matched a specific rule`,
    "",
    "### Top uncategorized senders — candidates for new rules",
    "",
    "| Msgs | Sender | Name |",
    "| ---: | :-- | :-- |",
    rows || "| — | (none) | |",
    "",
  ].join("\n");

  return {
    md,
    json: {
      setup: name,
      source: d.source,
      sendersMatched: d.sendersMatched,
      uncategorizedCount: d.bulkFallbackCount,
      leftInInbox: d.leftInInbox,
      coverage: categorizable === 0 ? null : d.sendersMatched / categorizable,
      uncategorized,
    },
  };
}

export const report = {
  name: "@dmc/fastmail-coverage",
  description:
    "Per-setup rule coverage from sieve_generate: senders filed vs. uncategorized (fell to the bulk fallback), with a ranked list of uncategorized senders to write rules for.",
  scope: "method" as const,
  labels: ["email", "fastmail", "coverage"],
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
      (h) => h.specName === "sieve",
    );
    if (handles.length === 0) {
      return {
        markdown:
          "_Rule coverage: no `sieve` data in this run (not a sieve_generate run)._",
        json: { applicable: false },
      };
    }

    const sections: string[] = [];
    const jsonSetups: Record<string, unknown>[] = [];
    for (const h of handles) {
      const raw = await context.dataRepository.getContent(
        context.modelType,
        context.modelId,
        h.name,
        h.version,
      );
      if (!raw) continue;
      const data = JSON.parse(new TextDecoder().decode(raw)) as SieveData;
      // Only report setups that actually categorize (skip allowlist / merged
      // outputs, which carry no uncategorized/matched breakdown).
      if (
        (data.uncategorized?.length ?? 0) === 0 &&
        data.sendersMatched === 0 &&
        data.bulkFallbackCount === 0
      ) {
        continue;
      }
      const { md, json } = setupSection(h.name, data);
      sections.push(md);
      jsonSetups.push(json);
    }

    if (sections.length === 0) {
      return {
        markdown: "_Rule coverage: no categorizing setups in this run._",
        json: { applicable: false },
      };
    }

    const markdown = ["# Fastmail Rule Coverage", "", ...sections].join("\n");
    return { markdown, json: { applicable: true, setups: jsonSetups } };
  },
};
