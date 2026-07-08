/**
 * UniFi firewall summary report — renders zone inventory and a detailed
 * policy table (flow, action, protocol, ports, host scope) from the
 * siteFirewall resources produced by the unifi-networks `scanFirewall` method.
 *
 * @module
 */

interface Zone {
  id: string;
  name: string;
  networkIds: string[];
  metadataOrigin?: string;
}

interface Policy {
  id: string;
  name: string;
  enabled: boolean;
  index: number;
  action: string;
  sourceZone?: string;
  destinationZone?: string;
  ipVersion?: string;
  protocol?: string;
  sourceMatch?: string;
  destinationMatch?: string;
  destinationPorts?: string;
  connectionStates?: string[];
  loggingEnabled?: boolean;
  metadataOrigin?: string;
}

interface SiteFirewall {
  scannedAt: string;
  siteName: string;
  consoleShortname?: string;
  zoneCount: number;
  policyCount: number;
  zones: Zone[];
  policies: Policy[];
}

/** UniFi firewall summary — zones + detailed policy table. */
export const report = {
  name: "@dmc/unifi-firewall-summary",
  description:
    "Zone inventory and a detailed firewall policy table (flow, action, " +
    "protocol, ports, host scope) from unifi-networks scanFirewall",
  scope: "method" as const,
  labels: ["networking", "unifi", "firewall", "security"],
  execute: async (context: {
    modelType: string;
    modelId: string;
    methodName: string;
    executionStatus: "succeeded" | "failed";
    errorMessage?: string;
    dataHandles: Array<{ name: string; specName: string; version: number }>;
    dataRepository: {
      getContent(
        type: string,
        modelId: string,
        dataName: string,
        version?: number,
      ): Promise<Uint8Array | null>;
    };
  }) => {
    if (context.methodName !== "scanFirewall") {
      return { markdown: "", json: {} };
    }
    if (context.executionStatus === "failed") {
      return {
        markdown: `# UniFi Firewall Summary\n\n**Scan failed**: ${
          context.errorMessage ?? "unknown error"
        }\n`,
        json: { status: "failed", error: context.errorMessage },
      };
    }

    const handles = context.dataHandles.filter(
      (h) => h.specName === "siteFirewall",
    );
    if (handles.length === 0) {
      return {
        markdown: "# UniFi Firewall Summary\n\nNo firewall data produced.\n",
        json: { status: "no-data" },
      };
    }

    const lines: string[] = [];
    const jsonSites: unknown[] = [];

    for (const handle of handles) {
      const raw = await context.dataRepository.getContent(
        context.modelType,
        context.modelId,
        handle.name,
        handle.version,
      );
      if (!raw) continue;
      const site = JSON.parse(new TextDecoder().decode(raw)) as SiteFirewall;

      const label = site.consoleShortname
        ? `${site.consoleShortname} · ${site.siteName}`
        : site.siteName;

      const emptyZones = site.zones.filter((z) => z.networkIds.length === 0);
      const userRules = site.policies.filter(
        (p) => p.metadataOrigin === "USER_DEFINED",
      );

      lines.push(
        `# UniFi Firewall Summary — ${label}`,
        "",
        `**Zones**: ${site.zoneCount} (${emptyZones.length} empty)  `,
        `**Policies**: ${site.policyCount} (${userRules.length} user-defined)  `,
        `**Scanned**: ${new Date(site.scannedAt).toUTCString()}`,
        "",
        "## Zones",
        "",
        "| Zone | Networks | Origin |",
        "| ---- | -------- | ------ |",
      );
      for (
        const z of [...site.zones].sort((a, b) =>
          b.networkIds.length - a.networkIds.length
        )
      ) {
        const n = z.networkIds.length;
        lines.push(
          `| ${z.name} | ${n === 0 ? "— (empty)" : n} | ${
            z.metadataOrigin ?? "?"
          } |`,
        );
      }
      lines.push("");

      lines.push(
        "## User-Defined Policies",
        "",
        "| # | Name | Flow | Action | Proto | Dest scope | Ports | Log |",
        "| - | ---- | ---- | ------ | ----- | ---------- | ----- | --- |",
      );
      for (const p of [...userRules].sort((a, b) => a.index - b.index)) {
        const flow = `${p.sourceZone ?? "?"} → ${p.destinationZone ?? "?"}`;
        const scope = p.destinationMatch ?? p.sourceMatch ?? "—";
        const ports = p.destinationPorts ?? "all";
        const act = p.action === "ALLOW" ? "✅ ALLOW" : `⛔ ${p.action}`;
        const log = p.loggingEnabled ? "📝" : "";
        const dis = p.enabled ? "" : " _(disabled)_";
        lines.push(
          `| ${p.index} | ${p.name}${dis} | ${flow} | ${act} | ${
            p.protocol ?? "all"
          } | ${scope} | ${ports} | ${log} |`,
        );
      }
      lines.push("");

      // Heuristic callouts worth a human's attention
      const notes: string[] = [];
      for (const p of userRules) {
        if (/for now|temp|test|todo|fixme|xxx/i.test(p.name)) {
          notes.push(
            `⚠️ **${p.name}** (${p.sourceZone} → ${p.destinationZone}) — name suggests a temporary rule`,
          );
        }
        if (
          p.action === "ALLOW" &&
          p.protocol === "all" &&
          !p.destinationMatch &&
          !p.destinationPorts
        ) {
          const srcEmpty = emptyZones.some((z) => z.name === p.sourceZone);
          notes.push(
            `⚠️ **${p.name}** — unrestricted ALLOW (all protocols/ports)${
              srcEmpty ? `, and source zone '${p.sourceZone}' is empty` : ""
            }`,
          );
        }
      }
      if (notes.length > 0) {
        lines.push("## Attention", "", ...notes.map((n) => `- ${n}`), "");
      }

      jsonSites.push({
        site: label,
        zoneCount: site.zoneCount,
        emptyZones: emptyZones.map((z) => z.name),
        policyCount: site.policyCount,
        userRuleCount: userRules.length,
        flags: notes.length,
      });
    }

    return {
      markdown: lines.join("\n").trimEnd() + "\n",
      json: { status: "ok", sites: jsonSites },
    };
  },
};
