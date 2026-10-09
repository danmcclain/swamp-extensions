/**
 * @dmc/patch-history — per-host detail view across the fleet.
 *
 * Model-scoped on @dmc/patch/fleet. For every host it renders current status
 * (OS packages, location, community-script app, docker, reboot) followed by that
 * host's run history (osUpdate / docker / reboot) with the exact packages and
 * container images each run changed. Only machines in `globalArguments.machines`
 * get a detail section. Hosts that left the fleet but still have stored records are
 * listed under "Retired machines" (last status plus run history) until
 * `clearRetired` removes them. Fetch with:
 *   swamp report get @dmc/patch-history --model fleet --markdown
 *
 * @module
 */

interface PkgChange {
  name: string;
  from: string | null;
  to: string | null;
}
interface ImageChange {
  ref: string;
  from: string | null;
  to: string | null;
}

interface RunRecord {
  runId: string;
  action: "osUpdate" | "docker" | "reboot";
  host: string;
  outcome: string;
  beforeUpdates: number | null;
  afterUpdates: number | null;
  packages: PkgChange[] | null;
  packagesChanged: number | null;
  images: ImageChange[] | null;
  imagesChanged: number | null;
  snapshot: string | null;
  rolledBack: boolean;
  needsReboot: boolean | null;
  timestamp: string;
}

interface DockerImage {
  container: string;
  image: string;
  updateAvailable: boolean | null;
}

interface Inventory {
  hostname: string;
  error?: string | null;
  osType: string;
  osVersion: string;
  packageManager: string;
  updatesCount: number | null;
  securityUpdatesCount: number | null;
  heldBackCount: number | null;
  removalsCount: number | null;
  distUpgradeRequired: boolean | null;
  totalPackages: number | null;
  needsReboot: boolean;
  rebootReason: string | null;
  dockerEngine?: string | null;
  dockerImages?: DockerImage[] | null;
  reachMethod?: "ssh" | "pct" | null;
  health?: {
    healthy: boolean;
    checks: Array<{ label: string; ok: boolean; detail: string }>;
  } | null;
  scannedAt: string;
}

interface LxcUpdate {
  name: string;
  node?: string;
  ctid?: number;
  installedVersion: string | null;
  latestVersion: string | null;
  upstreamVersion?: string | null;
  updateAvailable: boolean | null;
  osManaged?: boolean;
}

interface Machine {
  host: string;
  vm?: { proxmoxNode: string; vmid: number };
  proxmox?: { model?: string };
}

type ModelTypeRef = unknown;
interface DataMeta {
  name: string;
  version: number;
}
interface ModelCtx {
  modelType: ModelTypeRef;
  modelId: string;
  definition: { name: string };
  globalArgs?: { machines?: Machine[] };
  dataRepository: {
    findAllForModel(type: ModelTypeRef, modelId: string): Promise<DataMeta[]>;
    findAllGlobal(): Promise<
      Array<{ data: DataMeta; modelType: ModelTypeRef; modelId: string }>
    >;
    getContent(
      type: ModelTypeRef,
      modelId: string,
      dataName: string,
      version?: number,
    ): Promise<Uint8Array | null>;
  };
}

// Inventory records are named by bare host. These records never are inventory.
const NON_INVENTORY =
  /^(seed$|update-|os-update-|reboot-|run-|snap-|image-|prune-|report-)/;
// Non-inventory records that belong to one host (their `host` field names it).
const HOST_OWNED = /^(update-|os-update-|reboot-|run-|snap-|image-)/;
const ICON: Record<string, string> = {
  osUpdate: "📦",
  docker: "🐳",
  reboot: "🔄",
};
const num = (
  v: number | null | undefined,
): number => (typeof v === "number" ? v : 0);
const outcomeMark = (o: string): string =>
  o === "rolled-back"
    ? `⏪ ${o}`
    : o === "failed" || o === "timeout" || o === "unhealthy"
    ? `❌ ${o}`
    : o;
const when = (ts: string): string =>
  new Date(ts).toISOString().slice(0, 16).replace("T", " ") + " UTC";

export const report = {
  name: "@dmc/patch-history",
  description:
    "Per-host detail: current status + run history with package/image changes",
  scope: "model" as const,
  labels: ["patch", "patching", "history", "detail", "audit"],
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
    const read = async <T>(
      pred: (name: string) => boolean,
    ): Promise<Array<T & { _name: string }>> => {
      const out: Array<T & { _name: string }> = [];
      for (const d of latest.values()) {
        if (!pred(d.name)) continue;
        const raw = await context.dataRepository.getContent(
          context.modelType,
          context.modelId,
          d.name,
          d.version,
        );
        if (!raw) continue;
        try {
          out.push({ _name: d.name, ...(JSON.parse(dec.decode(raw)) as T) });
        } catch { /* skip */ }
      }
      return out;
    };

    // Inventory per host (current and retired), keyed by the record name.
    const invByHost = new Map<string, Inventory>();
    const invRecords = await read<Inventory>((n) => !NON_INVENTORY.test(n));
    for (const inv of invRecords) {
      if (inv.hostname && !inv.error) invByHost.set(inv._name, inv);
    }
    // Every host that owns a stored record. The host of an inventory record is its
    // exact name, of the others the `host` field. Never a name prefix.
    const storedHosts = new Set<string>(invRecords.map((i) => i._name));
    for (
      const rec of await read<{ host?: string }>((n) => HOST_OWNED.test(n))
    ) {
      if (typeof rec.host === "string" && rec.host !== "") {
        storedHosts.add(rec.host);
      }
    }

    // Community-script app per host (matched by app name).
    const appByHost = new Map<string, LxcUpdate>();
    const latestUC = new Map<
      string,
      { modelType: ModelTypeRef; modelId: string; data: DataMeta }
    >();
    for (const g of await context.dataRepository.findAllGlobal()) {
      if (g.data.name !== "updateCheck") continue;
      const prev = latestUC.get(g.modelId);
      if (!prev || g.data.version > prev.data.version) {
        latestUC.set(g.modelId, g);
      }
    }
    for (const g of latestUC.values()) {
      const raw = await context.dataRepository.getContent(
        g.modelType,
        g.modelId,
        g.data.name,
        g.data.version,
      );
      if (!raw) continue;
      try {
        const a = JSON.parse(dec.decode(raw)) as LxcUpdate;
        appByHost.set(a.name.toLowerCase(), a);
      } catch { /* skip */ }
    }

    // Run history per host.
    const runsByHost = new Map<string, RunRecord[]>();
    for (const r of await read<RunRecord>((n) => n.startsWith("run-"))) {
      const arr = runsByHost.get(r.host) ?? [];
      arr.push(r);
      runsByHost.set(r.host, arr);
    }
    for (const arr of runsByHost.values()) {
      arr.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
    }

    const machineByHost = new Map<string, Machine>();
    for (const m of context.globalArgs?.machines ?? []) {
      machineByHost.set(m.host, m);
    }
    // With no machines in the context, show every host rather than hide everything.
    const filtering = machineByHost.size > 0;

    const allHosts = [
      ...new Set([...invByHost.keys(), ...runsByHost.keys()]),
    ].sort();
    const hosts = filtering
      ? allHosts.filter((h) => machineByHost.has(h))
      : allHosts;
    const retiredHosts = filtering
      ? [...storedHosts].filter((h) => !machineByHost.has(h)).sort()
      : [];
    if (hosts.length === 0 && retiredHosts.length === 0) {
      return {
        markdown:
          "# Fleet Host Detail\n\n_No data yet — run `swamp workflow run patch-scan`._",
        json: { status: "no-data" },
      };
    }

    const totalRuns = hosts.reduce(
      (s, h) => s + (runsByHost.get(h)?.length ?? 0),
      0,
    );
    const lines: string[] = [
      "# Fleet Host Detail",
      "",
      `**${hosts.length} host(s)** · **${totalRuns} recorded run(s)**${
        retiredHosts.length > 0
          ? ` · ${retiredHosts.length} retired machine(s) below`
          : ""
      }`,
      "",
    ];

    const location = (host: string): string => {
      const m = machineByHost.get(host);
      const app = appByHost.get(host.toLowerCase());
      if (m?.vm) return `Proxmox VM · vmid ${m.vm.vmid} on ${m.vm.proxmoxNode}`;
      if (m?.proxmox || app?.ctid) {
        return `Proxmox CT${
          app?.ctid ? ` · ctid ${app.ctid} on ${app.node}` : ""
        }`;
      }
      return "host / VPS";
    };

    // The run table and the package/image detail blocks of one host.
    const runLines = (runs: RunRecord[]): string[] => {
      const out: string[] = [];
      out.push(
        "| When | Action | Outcome | Changed | Reboot | Snapshot |",
        "| ---- | ------ | ------- | ------- | ------ | -------- |",
      );
      for (const r of runs) {
        const action = `${ICON[r.action] ?? ""} ${r.action}`.trim();
        let changed = "—";
        if (r.action === "osUpdate") {
          changed =
            `${r.beforeUpdates ?? "?"}→${r.afterUpdates ?? "?"} updates` +
            (r.packagesChanged ? ` · ${r.packagesChanged} pkgs` : "");
        } else if (r.action === "docker") {
          changed = r.imagesChanged
            ? `${r.imagesChanged} image(s)`
            : "no change";
        }
        const reboot = r.needsReboot === true
          ? "⚠️ needed"
          : r.needsReboot === false
          ? "ok"
          : "—";
        out.push(
          `| ${when(r.timestamp)} | ${action} | ${
            outcomeMark(r.outcome)
          } | ${changed} | ${reboot} | ${r.snapshot ? "yes" : "—"} |`,
        );
      }
      out.push("");

      for (const r of runs) {
        const pkgs = r.packages ?? [];
        const imgs = r.images ?? [];
        if (pkgs.length === 0 && imgs.length === 0) continue;
        out.push(
          `<details><summary>${
            when(r.timestamp)
          } — ${r.action} details</summary>`,
          "",
        );
        if (pkgs.length) {
          out.push("| Package | From | To |", "| ------- | ---- | -- |");
          for (const p of pkgs.slice(0, 200)) {
            out.push(
              `| ${p.name} | ${p.from ?? "—"} | ${p.to ?? "removed"} |`,
            );
          }
          if (pkgs.length > 200) {
            out.push(`| … | ${pkgs.length - 200} more | |`);
          }
          out.push("");
        }
        if (imgs.length) {
          out.push("| Image | From | To |", "| ----- | ---- | -- |");
          for (const im of imgs) {
            out.push(
              `| ${im.ref} | ${(im.from ?? "—").slice(0, 19)} | ${
                (im.to ?? "—").slice(0, 19)
              } |`,
            );
          }
          out.push("");
        }
        out.push("</details>", "");
      }
      return out;
    };

    for (const host of hosts) {
      const inv = invByHost.get(host);
      const app = appByHost.get(host.toLowerCase());
      const runs = runsByHost.get(host) ?? [];
      lines.push(`## ${host}`, "");

      if (inv) {
        lines.push(
          `**${inv.osType} ${inv.osVersion}** · ${inv.packageManager} · ${
            location(host)
          } · via ${inv.reachMethod ?? "ssh"} · scanned ${when(inv.scannedAt)}`,
          "",
        );
        const osBits = [
          num(inv.updatesCount) > 0
            ? `**${inv.updatesCount}** updates`
            : "up to date",
          num(inv.securityUpdatesCount) > 0
            ? `🔒 ${inv.securityUpdatesCount} security`
            : null,
          num(inv.heldBackCount) > 0 ? `${inv.heldBackCount} held back` : null,
          inv.distUpgradeRequired ? "needs dist-upgrade" : null,
          typeof inv.totalPackages === "number"
            ? `${inv.totalPackages} installed`
            : null,
        ].filter(Boolean).join(" · ");
        lines.push(`- **OS**: ${osBits}`);
        lines.push(
          `- **Reboot**: ${
            inv.needsReboot
              ? `⚠️ required${inv.rebootReason ? ` (${inv.rebootReason})` : ""}`
              : "not needed"
          }`,
        );
        if (inv.health) {
          const detail = inv.health.checks.map((c) =>
            `${c.ok ? "✓" : "✗"} ${c.label}`
          ).join(", ");
          lines.push(
            `- **Health**: ${
              inv.health.healthy ? "✅ healthy" : "❌ unhealthy"
            }${detail ? ` — ${detail}` : ""}`,
          );
        }
        if (app) {
          const drift =
            app.upstreamVersion && app.upstreamVersion !== app.installedVersion
              ? ` — upstream ${app.upstreamVersion}${
                app.osManaged ? " (OS-managed, not installable here)" : ""
              }`
              : "";
          lines.push(
            `- **App**: ${
              app.updateAvailable === true ? "⬆️ " : ""
            }${app.name} ${app.installedVersion ?? "?"}${
              app.updateAvailable === true
                ? ` → ${app.latestVersion ?? "?"}`
                : " (current)"
            }${drift}`,
          );
        }
        if (inv.dockerEngine) {
          const imgs = Array.isArray(inv.dockerImages) ? inv.dockerImages : [];
          const upd = imgs.filter((d) => d.updateAvailable === true).length;
          lines.push(
            `- **Docker**: 🐳 ${inv.dockerEngine} · ${imgs.length} container(s)${
              upd ? ` · ⬆️ ${upd} with updates` : ""
            }`,
          );
          for (const d of imgs) {
            lines.push(
              `  - ${d.container} \`${d.image}\`${
                d.updateAvailable === true ? " ⬆️" : ""
              }`,
            );
          }
        }
        lines.push("");
      } else {
        lines.push("_Not scanned recently._", "");
      }

      if (runs.length === 0) {
        lines.push("_No runs recorded._", "");
        continue;
      }

      lines.push("### Runs", "", ...runLines(runs));
    }

    // Retired machines: stored records, but not in the fleet any more.
    if (retiredHosts.length > 0) {
      lines.push(
        "## Retired machines",
        "",
        `These hosts have stored records but are not in the fleet. They stay here until \`swamp model method run ${context.definition.name} clearRetired\` removes them (\`--input keepHistory=true\` keeps their run history).`,
        "",
      );
      for (const host of retiredHosts) {
        const inv = invByHost.get(host);
        const runs = runsByHost.get(host) ?? [];
        lines.push(`### ${host}`, "");
        if (inv) {
          const bits = [
            `**${inv.osType} ${inv.osVersion}**`,
            inv.packageManager,
            `last scanned ${when(inv.scannedAt)}`,
            num(inv.updatesCount) > 0
              ? `${inv.updatesCount} updates`
              : "up to date",
            num(inv.securityUpdatesCount) > 0
              ? `🔒 ${inv.securityUpdatesCount} security`
              : null,
            inv.needsReboot ? "⚠️ reboot was required" : null,
          ].filter(Boolean).join(" · ");
          lines.push(bits, "");
        } else {
          lines.push("_No inventory record kept._", "");
        }
        if (runs.length === 0) {
          lines.push("_No runs recorded._", "");
          continue;
        }
        lines.push(
          `<details><summary>Run history (${runs.length} run(s))</summary>`,
          "",
          ...runLines(runs),
          "</details>",
          "",
        );
      }
    }

    return {
      markdown: lines.join("\n"),
      json: {
        hosts: hosts.map((host) => {
          const inv = invByHost.get(host);
          const app = appByHost.get(host.toLowerCase());
          return {
            host,
            os: inv ? `${inv.osType} ${inv.osVersion}` : null,
            updatesCount: inv?.updatesCount ?? null,
            securityUpdatesCount: inv?.securityUpdatesCount ?? null,
            needsReboot: inv?.needsReboot ?? null,
            app: app
              ? {
                name: app.name,
                installed: app.installedVersion,
                latest: app.latestVersion,
                updateAvailable: app.updateAvailable,
              }
              : null,
            dockerEngine: inv?.dockerEngine ?? null,
            runs: (runsByHost.get(host) ?? []).map((r) => ({
              action: r.action,
              outcome: r.outcome,
              packagesChanged: r.packagesChanged,
              imagesChanged: r.imagesChanged,
              rolledBack: r.rolledBack,
              timestamp: r.timestamp,
            })),
          };
        }),
        totalRuns,
        retired: retiredHosts.map((host) => {
          const inv = invByHost.get(host);
          return {
            host,
            os: inv ? `${inv.osType} ${inv.osVersion}` : null,
            lastScanned: inv?.scannedAt ?? null,
            updatesCount: inv?.updatesCount ?? null,
            securityUpdatesCount: inv?.securityUpdatesCount ?? null,
            runs: (runsByHost.get(host) ?? []).map((r) => ({
              action: r.action,
              outcome: r.outcome,
              packagesChanged: r.packagesChanged,
              imagesChanged: r.imagesChanged,
              rolledBack: r.rolledBack,
              timestamp: r.timestamp,
            })),
          };
        }),
      },
    };
  },
};
