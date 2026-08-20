// Apply-sieve plan review report for @dmc/fastmail email_plan.
//
// Scope: method. Renders the message-id → destination plan grouped by folder so
// you can MANUALLY REVIEW exactly what would move before any token/move runs.
// No-ops on runs with no `plan` data.

interface PlanMove {
  messageId: string;
  from: string;
  subject: string;
  category: string;
  sievePath: string;
  mailboxId: string | null;
  matchedBy: string;
}
interface PlanData {
  sourceMailbox: string;
  scannedMessages: number;
  moveCount: number;
  leftInInbox: number;
  byDestination: Record<string, number>;
  moves: PlanMove[];
}

export const report = {
  name: "@dmc/fastmail-plan",
  description:
    "Review an apply-sieve plan: destinations, counts, and sample messages that email_move would relocate. Read this before approving/executing a move.",
  scope: "method" as const,
  labels: ["email", "fastmail", "apply-sieve", "review"],
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
      h.specName === "plan"
    );
    if (!handle) {
      return {
        markdown: "_No apply-sieve plan in this run (not an email_plan run)._",
        json: { applicable: false },
      };
    }
    const raw = await context.dataRepository.getContent(
      context.modelType,
      context.modelId,
      handle.name,
      handle.version,
    );
    if (!raw) return { markdown: "_Plan data not found._", json: {} };
    const d = JSON.parse(new TextDecoder().decode(raw)) as PlanData;

    // Destinations by volume.
    const dests = Object.entries(d.byDestination ?? {}).sort((a, b) =>
      b[1] - a[1]
    );
    const destRows = dests
      .map(([cat, n]) => `| ${n} | ${cat} |`)
      .join("\n");

    // Up to 3 sample subjects per destination.
    const samples = new Map<string, string[]>();
    for (const m of d.moves ?? []) {
      const arr = samples.get(m.category) ?? [];
      if (arr.length < 3) {
        arr.push(`${m.from} — ${(m.subject || "(no subject)").slice(0, 60)}`);
      }
      samples.set(m.category, arr);
    }
    const sampleBlocks = dests
      .map(([cat]) =>
        `**${cat}**\n${
          (samples.get(cat) ?? []).map((s) => `- ${s}`).join("\n")
        }`
      )
      .join("\n\n");

    const markdown = [
      "# Apply-Sieve Plan — review before moving",
      "",
      `- **Scanned:** ${d.scannedMessages} messages in \`${d.sourceMailbox}\``,
      `- **Would move:** ${d.moveCount}`,
      `- **Left in Inbox:** ${d.leftInInbox}`,
      "",
      "## Destinations",
      "",
      "| Msgs | Folder |",
      "| ---: | :-- |",
      destRows || "| — | (none) |",
      "",
      "## Sample messages per destination",
      "",
      sampleBlocks || "_none_",
      "",
      "> Nothing has moved. Approve the workflow step (and provide a write-scoped",
      "> token) before `email_move` relocates anything.",
    ].join("\n");

    return {
      markdown,
      json: {
        applicable: true,
        moveCount: d.moveCount,
        leftInInbox: d.leftInInbox,
        byDestination: d.byDestination,
      },
    };
  },
};
