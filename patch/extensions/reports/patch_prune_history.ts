/**
 * @dmc/patch-prune-history — history of snapshot/image prune runs.
 *
 * Model-scoped on @dmc/patch/fleet: reads the `prune` results (from pruneSnapshots
 * and pruneImages) and renders a chronological table of what was retired and what
 * was kept (and why). Fetch with:
 *   swamp report get @dmc/patch-prune-history --model fleet --markdown
 *
 * @module
 */

interface PruneEntry {
  host: string;
  name: string;
  detail?: string | null;
  reason?: string;
}
interface PruneResult {
  scannedAt: string;
  kind: "snapshots" | "images";
  dryRun: boolean;
  pruned: PruneEntry[];
  kept: PruneEntry[];
}

interface DataMeta {
  name: string;
  version: number;
}
interface ModelCtx {
  modelType: string;
  modelId: string;
  definition: { name: string };
  dataRepository: {
    findAllForModel(type: string, modelId: string): Promise<DataMeta[]>;
    getContent(
      type: string,
      modelId: string,
      dataName: string,
      version?: number,
    ): Promise<Uint8Array | null>;
  };
}

export const report = {
  name: "@dmc/patch-prune-history",
  description:
    "History of snapshot and docker-image prune runs (retired vs kept)",
  scope: "model" as const,
  labels: ["patch", "patching", "prune", "retention", "history"],
  execute: async (context: ModelCtx) => {
    const dec = new TextDecoder();
    const all = await context.dataRepository.findAllForModel(
      context.modelType,
      context.modelId,
    );
    const latest = new Map<string, DataMeta>();
    for (const d of all) {
      const prev = latest.get(d.name);
      if (!prev || d.version > prev.version) latest.set(d.name, d);
    }
    const prunes: PruneResult[] = [];
    for (const d of latest.values()) {
      if (!d.name.startsWith("prune-")) continue;
      const raw = await context.dataRepository.getContent(
        context.modelType,
        context.modelId,
        d.name,
        d.version,
      );
      if (!raw) continue;
      try {
        prunes.push(JSON.parse(dec.decode(raw)) as PruneResult);
      } catch { /* skip */ }
    }

    if (prunes.length === 0) {
      return {
        markdown: "# Prune History\n\n_No prune runs recorded yet._",
        json: { status: "no-data" },
      };
    }

    prunes.sort((a, b) => b.scannedAt.localeCompare(a.scannedAt));
    const totalPruned = prunes.reduce((s, p) => s + p.pruned.length, 0);

    const lines: string[] = [
      "# Prune History",
      "",
      `**${prunes.length} run(s)** · **${totalPruned} item(s) retired** · latest ${
        new Date(prunes[0].scannedAt).toUTCString()
      }`,
      "",
      "| When | Kind | Mode | Retired | Kept |",
      "| ---- | ---- | ---- | ------- | ---- |",
    ];
    for (const p of prunes) {
      const when =
        new Date(p.scannedAt).toISOString().slice(0, 16).replace("T", " ") +
        " UTC";
      const mode = p.dryRun ? "dry-run" : "live";
      const retired = p.pruned.length > 0 ? `**${p.pruned.length}**` : "—";
      lines.push(
        `| ${when} | ${
          p.kind ?? "—"
        } | ${mode} | ${retired} | ${p.kept.length} |`,
      );
    }
    lines.push("");

    // Detail: what each run retired / kept.
    for (const p of prunes) {
      if (p.pruned.length === 0 && p.kept.length === 0) continue;
      const when = new Date(p.scannedAt).toISOString().slice(0, 16).replace(
        "T",
        " ",
      );
      lines.push(
        `<details><summary>${when} — ${p.kind} (${
          p.dryRun ? "dry-run" : "live"
        })</summary>`,
        "",
      );
      if (p.pruned.length) {
        lines.push(
          "**Retired**",
          "",
          "| Host | Item | Detail |",
          "| ---- | ---- | ------ |",
        );
        for (const e of p.pruned) {
          lines.push(`| ${e.host} | ${e.name} | ${e.detail ?? "—"} |`);
        }
        lines.push("");
      }
      if (p.kept.length) {
        lines.push(
          "**Kept**",
          "",
          "| Host | Item | Reason |",
          "| ---- | ---- | ------ |",
        );
        for (const e of p.kept) {
          lines.push(`| ${e.host} | ${e.name} | ${e.reason ?? "—"} |`);
        }
        lines.push("");
      }
      lines.push("</details>", "");
    }

    return {
      markdown: lines.join("\n"),
      json: {
        totalRuns: prunes.length,
        totalRetired: totalPruned,
        runs: prunes.map((p) => ({
          scannedAt: p.scannedAt,
          kind: p.kind,
          dryRun: p.dryRun,
          retired: p.pruned.length,
          kept: p.kept.length,
        })),
      },
    };
  },
};
