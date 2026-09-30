/**
 * @dmc/patch-status — overall fleet status across all nodes.
 *
 * Model-scoped on @dmc/patch/fleet: reads the latest `inventory` per host (from
 * scan / safeOsUpdate) plus current retention (`snapshot` / `image`) and renders
 * one fleet status table. Fetch with:
 *   swamp report get @dmc/patch-status --model fleet --markdown
 *
 * @module
 */

interface Inventory {
  hostname: string;
  error?: string | null;
  osType: string;
  osVersion: string;
  packageManager: string;
  updatesCount: number | null;
  securityUpdatesCount: number | null;
  heldBackCount: number | null;
  distUpgradeRequired: boolean | null;
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

interface DockerImage {
  container: string;
  image: string;
  updateAvailable: boolean | null;
}

/** @dmc/proxmox/community-script `updateCheck` (one per LXC app). */
interface LxcUpdate {
  name: string;
  installedVersion: string | null;
  latestVersion: string | null;
  upstreamVersion?: string | null;
  updateAvailable: boolean | null;
  osManaged?: boolean;
  checkedAt?: string;
}

interface DataMeta {
  name: string;
  version: number;
}

// findAllForModel returns handles with names but no specName, so resources are
// identified by their (controlled) name pattern. Inventory records are named by
// bare host, everything else carries one of these prefixes.
const NON_INVENTORY =
  /^(seed$|update-|os-update-|reboot-|run-|snap-|image-|prune-|report-)/;

// ModelType is an opaque token object (not a string) that the data methods require.
type ModelTypeRef = unknown;

interface ModelCtx {
  modelType: ModelTypeRef;
  modelId: string;
  definition: { name: string };
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

const num = (
  v: number | null | undefined,
): number => (typeof v === "number" ? v : 0);

export const report = {
  name: "@dmc/patch-status",
  description: "Overall patch/update/reboot status across all fleet nodes",
  scope: "model" as const,
  labels: ["patch", "patching", "status", "fleet"],
  execute: async (context: ModelCtx) => {
    const dec = new TextDecoder();
    const all = await context.dataRepository.findAllForModel(
      context.modelType,
      context.modelId,
    );
    // Keep the latest version of each name.
    const latest = new Map<string, DataMeta>();
    for (const d of all) {
      const prev = latest.get(d.name);
      if (!prev || d.version > prev.version) latest.set(d.name, d);
    }
    const readWhere = async <T>(
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

    const inv = (await readWhere<Inventory>((n) => !NON_INVENTORY.test(n)))
      .filter((h) => h.hostname && !h.error);
    const snaps = await readWhere<{ status: string }>((n) =>
      n.startsWith("snap-")
    );
    const imgs = await readWhere<{ status: string }>((n) =>
      n.startsWith("image-")
    );

    // LXC apps: the community-script `updateCheck` lives on separate
    // @dmc/proxmox/community-script models. findAllGlobal returns each with its own
    // (opaque) modelType — reuse that to read the content. `updateCheck` is a name
    // only community-script produces, so filter on it alone.
    const lxc: LxcUpdate[] = [];
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
        lxc.push(JSON.parse(dec.decode(raw)) as LxcUpdate);
      } catch { /* skip */ }
    }
    const lxcUpdatable = lxc.filter((a) => a.updateAvailable === true);
    const lxcSorted = [...lxc].sort((a, b) =>
      (Number(b.updateAvailable === true) -
        Number(a.updateAvailable === true)) || a.name.localeCompare(b.name)
    );
    // Tie each community-script app back to its host (the CT), matched by name.
    const appByHost = new Map<string, LxcUpdate>();
    for (const a of lxc) appByHost.set(a.name.toLowerCase(), a);
    const activeSnaps = snaps.filter((s) => s.status === "active").length;
    const activeImgs = imgs.filter((i) => i.status === "active").length;

    if (inv.length === 0) {
      return {
        markdown:
          "# Fleet Patch Status\n\n_No inventory yet — run `swamp workflow run patch-scan`._",
        json: { status: "no-data" },
      };
    }

    const totalUpdates = inv.reduce((s, h) => s + num(h.updatesCount), 0);
    const needsReboot = inv.filter((h) => h.needsReboot);
    const hasSecurity = inv.filter((h) => num(h.securityUpdatesCount) > 0);
    const needsDist = inv.filter((h) => h.distUpgradeRequired === true);
    const unhealthy = inv.filter((h) => h.health && !h.health.healthy);

    // Container image drift: flatten each host's dockerImages, tagged with host.
    type DockerRow = DockerImage & { host: string };
    const dockerRows: DockerRow[] = [];
    for (const h of inv) {
      if (Array.isArray(h.dockerImages)) {
        for (const d of h.dockerImages) {
          dockerRows.push({ ...d, host: h.hostname });
        }
      }
    }
    const dockerUpdatable = dockerRows.filter((d) =>
      d.updateAvailable === true
    );
    const dockerSorted = [...dockerRows].sort((a, b) =>
      (Number(b.updateAvailable === true) -
        Number(a.updateAvailable === true)) ||
      a.host.localeCompare(b.host) || a.container.localeCompare(b.container)
    );

    const allCurrent = totalUpdates === 0 && needsReboot.length === 0 &&
      dockerUpdatable.length === 0 && lxcUpdatable.length === 0;

    const statusLine = allCurrent && unhealthy.length === 0
      ? "✅ All fleet nodes, containers and LXC apps up to date and healthy"
      : [
        unhealthy.length > 0
          ? `❌ ${unhealthy.length} node(s) UNHEALTHY`
          : null,
        totalUpdates > 0 ? `${totalUpdates} update(s) pending` : null,
        hasSecurity.length > 0
          ? `${hasSecurity.length} node(s) with security updates`
          : null,
        needsDist.length > 0
          ? `${needsDist.length} node(s) need dist-upgrade`
          : null,
        needsReboot.length > 0
          ? `${needsReboot.length} node(s) need reboot`
          : null,
        lxcUpdatable.length > 0
          ? `${lxcUpdatable.length} LXC app(s) with updates`
          : null,
        dockerUpdatable.length > 0
          ? `${dockerUpdatable.length} container image(s) with updates`
          : null,
      ].filter(Boolean).join(" · ");

    const sorted = [...inv].sort((a, b) =>
      (num(b.securityUpdatesCount) - num(a.securityUpdatesCount)) ||
      (num(b.updatesCount) - num(a.updatesCount)) ||
      a.hostname.localeCompare(b.hostname)
    );

    const lines: string[] = [
      "# Fleet Patch Status",
      "",
      `**${statusLine}**  `,
      `**Nodes**: ${inv.length} · **Retained snapshots**: ${activeSnaps} · **Retained images**: ${activeImgs}`,
      "",
      "| Node | OS | Mgr | Via | Health | OS Updates | Security | App (LXC) | Reboot | Docker (engine · containers) | Scanned |",
      "| ---- | -- | --- | --- | ------ | ---------- | -------- | --------- | ------ | ---------------------------- | ------- |",
    ];
    for (const h of sorted) {
      let updates = num(h.updatesCount) > 0 ? `**${h.updatesCount}**` : "—";
      if (num(h.heldBackCount) > 0) updates += ` (+${h.heldBackCount} held)`;
      const security = num(h.securityUpdatesCount) > 0
        ? `🔒 **${h.securityUpdatesCount}**`
        : h.securityUpdatesCount === null
        ? "n/a"
        : "—";
      const reboot = h.needsReboot ? "⚠️ yes" : "—";
      const app = appByHost.get(h.hostname.toLowerCase());
      const drift = app && app.upstreamVersion &&
          app.upstreamVersion !== app.installedVersion
        ? ` _(upstream ${app.upstreamVersion})_`
        : "";
      const appCell = !app
        ? "—"
        : app.updateAvailable === true
        ? `⬆️ ${app.name} ${app.installedVersion ?? "?"}→${
          app.latestVersion ?? "?"
        }`
        : `${app.name} ${app.installedVersion ?? "?"}${drift}`;
      let docker = "—";
      if (h.dockerEngine) {
        const imgs = Array.isArray(h.dockerImages) ? h.dockerImages : [];
        const upd = imgs.filter((d) => d.updateAvailable === true).length;
        docker = `🐳 ${h.dockerEngine}` +
          (imgs.length ? ` · ${imgs.length}c${upd ? ` ⬆️${upd}` : ""}` : "");
      }
      const scanned = h.scannedAt
        ? new Date(h.scannedAt).toISOString().slice(0, 16).replace("T", " ") +
          " UTC"
        : "—";
      const health = !h.health ? "—" : h.health.healthy ? "✅" : "❌";
      lines.push(
        `| ${h.hostname} | ${h.osType} ${h.osVersion} | ${h.packageManager} | ${
          h.reachMethod ?? "ssh"
        } | ${health} | ${updates} | ${security} | ${appCell} | ${reboot} | ${docker} | ${scanned} |`,
      );
    }
    lines.push(
      "_App (LXC) = community-script app version. OS Updates = the CT's OS packages._",
      "",
    );

    if (dockerRows.length > 0) {
      lines.push("## Docker containers", "");
      lines.push(
        "| Host | Container | Image | Update |",
        "| ---- | --------- | ----- | ------ |",
      );
      for (const d of dockerSorted) {
        const upd = d.updateAvailable === true
          ? "⬆️ **yes**"
          : d.updateAvailable === false
          ? "—"
          : "?";
        lines.push(`| ${d.host} | ${d.container} | ${d.image} | ${upd} |`);
      }
      lines.push("");
    }

    if (unhealthy.length > 0) {
      lines.push("## Unhealthy", "");
      for (const h of unhealthy) {
        const failed = (h.health?.checks ?? []).filter((c) => !c.ok)
          .map((c) => `${c.label} (${c.detail})`).join(", ");
        lines.push(`- **${h.hostname}** — ${failed || "health check failed"}`);
      }
      lines.push("");
    }

    if (needsReboot.length > 0) {
      lines.push("## Reboot required", "");
      for (const h of needsReboot) {
        lines.push(
          `- **${h.hostname}**${h.rebootReason ? ` — ${h.rebootReason}` : ""}`,
        );
      }
      lines.push("");
    }

    return {
      markdown: lines.join("\n"),
      json: {
        nodes: inv.length,
        totalPendingUpdates: totalUpdates,
        nodesNeedingReboot: needsReboot.map((h) => h.hostname),
        nodesWithSecurityUpdates: hasSecurity.map((h) => h.hostname),
        nodesRequiringDistUpgrade: needsDist.map((h) => h.hostname),
        unhealthyNodes: unhealthy.map((h) => h.hostname),
        lxcAppsWithUpdates: lxcUpdatable.map((a) => a.name),
        containerImagesWithUpdates: dockerUpdatable.map((d) =>
          `${d.host}/${d.container}`
        ),
        retainedSnapshots: activeSnaps,
        retainedImages: activeImgs,
        allCurrent,
        hosts: sorted,
        lxcApps: lxcSorted,
        containers: dockerSorted,
      },
    };
  },
};
