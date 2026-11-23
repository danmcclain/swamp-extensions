/**
 * UniFi DNS records report — renders every local DNS record (UniFi DNS
 * policy) from the siteDnsRecords resources produced by the unifi-networks
 * `scanDns` method, and lists what changed since the previous snapshot
 * (records added, removed, or changed in value, TTL or enabled flag).
 *
 * The history itself is the versioned siteDnsRecords data: each scheduled
 * scanDns run writes a new version, and this report compares the new version
 * with the one before it.
 *
 * @module
 */

interface DnsRecord {
  id: string;
  type: string;
  domain: string;
  value: string;
  ttlSeconds?: number;
  priority?: number;
  weight?: number;
  enabled: boolean;
  origin?: string;
}

interface SiteDnsRecords {
  scannedAt: string;
  siteName: string;
  consoleShortname?: string;
  records: DnsRecord[];
}

export interface DnsChange {
  domain: string;
  type: string;
  kind: "added" | "removed" | "changed";
  /** For "changed": which fields differ, with their old and new values. */
  fields?: Array<{ field: string; from: string; to: string }>;
}

export interface SiteDnsStatus {
  siteName: string;
  label: string;
  scannedAt: string;
  previousScannedAt?: string;
  summary: {
    records: number;
    disabled: number;
    byType: Record<string, number>;
  };
  changes: DnsChange[];
  records: DnsRecord[];
}

/** "A_RECORD" → "A", "FORWARD_DOMAIN" → "Forward". */
export function typeLabel(type: string): string {
  if (type === "FORWARD_DOMAIN") return "Forward";
  return type.replace(/_RECORD$/, "");
}

const show = (v: unknown) => (v === undefined ? "—" : String(v));

const COMPARED: Array<keyof DnsRecord> = [
  "domain",
  "value",
  "ttlSeconds",
  "priority",
  "weight",
  "enabled",
];

/** Compare two snapshots of one site, record by record (matched by id). */
export function diffDnsRecords(
  previous: DnsRecord[],
  current: DnsRecord[],
): DnsChange[] {
  const prevById = new Map(previous.map((r) => [r.id, r]));
  const curIds = new Set(current.map((r) => r.id));
  const changes: DnsChange[] = [];
  for (const r of current) {
    const p = prevById.get(r.id);
    if (!p) {
      changes.push({ domain: r.domain, type: r.type, kind: "added" });
      continue;
    }
    const fields = COMPARED
      .filter((f) => p[f] !== r[f])
      .map((f) => ({ field: f, from: show(p[f]), to: show(r[f]) }));
    if (fields.length) {
      changes.push({ domain: r.domain, type: r.type, kind: "changed", fields });
    }
  }
  for (const p of previous) {
    if (!curIds.has(p.id)) {
      changes.push({ domain: p.domain, type: p.type, kind: "removed" });
    }
  }
  return changes;
}

/** Build one site's status: summary, changes since the previous snapshot. */
export function buildSiteDns(
  current: SiteDnsRecords,
  previous?: SiteDnsRecords,
): SiteDnsStatus {
  const byType: Record<string, number> = {};
  for (const r of current.records) {
    const t = typeLabel(r.type);
    byType[t] = (byType[t] ?? 0) + 1;
  }
  return {
    siteName: current.siteName,
    label: current.consoleShortname
      ? `${current.consoleShortname} · ${current.siteName}`
      : current.siteName,
    scannedAt: current.scannedAt,
    previousScannedAt: previous?.scannedAt,
    summary: {
      records: current.records.length,
      disabled: current.records.filter((r) => !r.enabled).length,
      byType,
    },
    changes: previous ? diffDnsRecords(previous.records, current.records) : [],
    records: current.records,
  };
}

const cell = (s: string | undefined) =>
  (s === undefined || s === "" ? "—" : s).replace(/\|/g, "\\|")
    .replace(/\r?\n/g, " ");

function describeChange(c: DnsChange): string {
  const what = `\`${c.domain}\` (${typeLabel(c.type)})`;
  if (c.kind === "added") return `${what}: added`;
  if (c.kind === "removed") return `${what}: **removed**`;
  const parts = (c.fields ?? []).map((f) => `${f.field} ${f.from} → ${f.to}`);
  return `${what}: ${parts.join(", ")}`;
}

export function renderSite(s: SiteDnsStatus): string[] {
  const m = s.summary;
  const types = Object.keys(m.byType).sort()
    .map((t) => `${t} ${m.byType[t]}`).join(", ");
  const lines = [
    `# UniFi DNS Records — ${s.label}`,
    "",
    `**Records**: ${m.records}${types ? ` (${types})` : ""}  `,
    `**Disabled**: ${m.disabled}  `,
    `**Scanned**: ${new Date(s.scannedAt).toUTCString()}`,
    "",
    "## Changes since the previous scan",
    "",
  ];
  if (!s.previousScannedAt) {
    lines.push("First snapshot; nothing to compare yet.");
  } else if (s.changes.length === 0) {
    lines.push(
      `No changes since ${new Date(s.previousScannedAt).toUTCString()}.`,
    );
  } else {
    lines.push(`Since ${new Date(s.previousScannedAt).toUTCString()}:`, "");
    for (const c of s.changes) lines.push(`- ${describeChange(c)}`);
  }
  lines.push("", "## Records", "");
  if (s.records.length === 0) {
    lines.push("No local DNS records.");
  } else {
    lines.push(
      "| Domain | Type | Value | TTL | Priority | Enabled |",
      "| ------ | ---- | ----- | --- | -------- | ------- |",
    );
    for (const r of s.records) {
      lines.push(
        `| ${
          [
            cell(r.domain),
            typeLabel(r.type),
            cell(r.value),
            show(r.ttlSeconds),
            show(r.priority),
            r.enabled ? "yes" : "**no**",
          ].join(" | ")
        } |`,
      );
    }
  }
  lines.push("");
  return lines;
}

/** UniFi DNS records — every local DNS record plus changes since last scan. */
export const report = {
  name: "@dmc/unifi-dns-records",
  description:
    "Every local DNS record (A, AAAA, CNAME, MX, TXT, SRV, forward domain) " +
    "from unifi-networks scanDns, with the changes since the previous scan",
  scope: "method" as const,
  labels: ["networking", "unifi", "dns", "inventory"],
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
    if (context.methodName !== "scanDns") {
      return { markdown: "", json: {} };
    }
    if (context.executionStatus === "failed") {
      return {
        markdown: `# UniFi DNS Records\n\n**Scan failed**: ${
          context.errorMessage ?? "unknown error"
        }\n`,
        json: { status: "failed", error: context.errorMessage },
      };
    }
    const handles = context.dataHandles.filter(
      (h) => h.specName === "siteDnsRecords",
    );
    if (handles.length === 0) {
      return {
        markdown: "# UniFi DNS Records\n\nNo DNS data produced.\n",
        json: { status: "no-data" },
      };
    }

    const read = async (name: string, version: number) => {
      if (version < 1) return undefined;
      const raw = await context.dataRepository.getContent(
        context.modelType,
        context.modelId,
        name,
        version,
      );
      if (!raw) return undefined;
      const parsed = JSON.parse(new TextDecoder().decode(raw));
      // Only a siteDnsRecords snapshot counts; anything else is no baseline.
      return Array.isArray(parsed?.records)
        ? parsed as SiteDnsRecords
        : undefined;
    };

    const lines: string[] = [];
    const sites: SiteDnsStatus[] = [];
    for (const h of handles) {
      const current = await read(h.name, h.version);
      if (!current) continue;
      // The previous version may have been garbage-collected; then there is
      // nothing to compare against.
      const previous = await read(h.name, h.version - 1).catch(() => undefined);
      const status = buildSiteDns(current, previous);
      sites.push(status);
      lines.push(...renderSite(status));
    }

    return {
      markdown: lines.join("\n"),
      json: { status: "ok", sites },
    };
  },
};
