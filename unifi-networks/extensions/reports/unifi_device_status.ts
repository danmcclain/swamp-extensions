/**
 * UniFi device status report — renders every adopted device's state, current
 * firmware, offered upgrade, last seen and uplink from the siteDevices
 * resources produced by the unifi-networks `scanDevices` method, and lists
 * what changed since the previous snapshot (state, firmware, upgrades,
 * uplink, STP-blocked ports, devices added or removed).
 *
 * The history itself is the versioned siteDevices data: each scheduled
 * scanDevices run writes a new version, and this report compares the new
 * version with the one before it.
 *
 * @module
 */

interface DevicePort {
  portIdx: number;
  stpState?: string;
}

interface Device {
  name: string;
  mac: string;
  model?: string;
  ipAddress?: string;
  state?: string;
  firmwareVersion?: string;
  firmwareUpdatable?: boolean;
  upgradeToFirmware?: string;
  lastSeen?: string;
  uptimeSeconds?: number;
  uplink?: { deviceMac: string; deviceName?: string; port?: number };
  stpBlockedPorts: number[];
  ports: DevicePort[];
}

interface SiteDevices {
  scannedAt: string;
  siteName: string;
  consoleShortname?: string;
  deviceCount: number;
  devices: Device[];
}

export interface DeviceChange {
  device: string;
  mac: string;
  kind:
    | "added"
    | "removed"
    | "state"
    | "firmware"
    | "upgrade"
    | "uplink"
    | "stp";
  from?: string;
  to?: string;
}

export interface DeviceStatusRow {
  name: string;
  mac: string;
  model?: string;
  ipAddress?: string;
  state: string;
  firmwareVersion?: string;
  upgradeAvailable: boolean;
  upgradeToFirmware?: string;
  lastSeen?: string;
  lastSeenAgoSeconds?: number;
  uplink?: string;
  stpBlockedPorts: number[];
}

export interface SiteDeviceStatus {
  siteName: string;
  label: string;
  scannedAt: string;
  previousScannedAt?: string;
  summary: {
    devices: number;
    online: number;
    notOnline: number;
    upgradesAvailable: number;
    stpBlockedPorts: number;
  };
  changes: DeviceChange[];
  devices: DeviceStatusRow[];
}

const hasUpgrade = (d: Device) =>
  d.firmwareUpdatable === true || d.upgradeToFirmware !== undefined;

const uplinkLabel = (d: Device) =>
  d.uplink
    ? `${d.uplink.deviceName ?? d.uplink.deviceMac}${
      d.uplink.port !== undefined ? ` port ${d.uplink.port}` : ""
    }`
    : undefined;

const stpLabel = (d: Device) =>
  d.stpBlockedPorts.length
    ? d.stpBlockedPorts.map((p) => {
      const s = d.ports.find((x) => x.portIdx === p)?.stpState;
      return s ? `${p} (${s})` : String(p);
    }).join(", ")
    : "none";

/** Compare two snapshots of one site, device by device (matched by MAC). */
export function diffDevices(
  previous: Device[],
  current: Device[],
): DeviceChange[] {
  const prevByMac = new Map(previous.map((d) => [d.mac, d]));
  const curMacs = new Set(current.map((d) => d.mac));
  const changes: DeviceChange[] = [];
  for (const d of current) {
    const p = prevByMac.get(d.mac);
    const base = { device: d.name, mac: d.mac };
    if (!p) {
      changes.push({ ...base, kind: "added", to: d.state ?? "unknown" });
      continue;
    }
    if ((p.state ?? "unknown") !== (d.state ?? "unknown")) {
      changes.push({
        ...base,
        kind: "state",
        from: p.state ?? "unknown",
        to: d.state ?? "unknown",
      });
    }
    if (p.firmwareVersion !== d.firmwareVersion) {
      changes.push({
        ...base,
        kind: "firmware",
        from: p.firmwareVersion ?? "unknown",
        to: d.firmwareVersion ?? "unknown",
      });
    }
    if (
      hasUpgrade(d) &&
      (!hasUpgrade(p) || p.upgradeToFirmware !== d.upgradeToFirmware)
    ) {
      changes.push({
        ...base,
        kind: "upgrade",
        from: d.firmwareVersion,
        to: d.upgradeToFirmware ?? "available",
      });
    }
    if (uplinkLabel(p) !== uplinkLabel(d)) {
      changes.push({
        ...base,
        kind: "uplink",
        from: uplinkLabel(p) ?? "none",
        to: uplinkLabel(d) ?? "none",
      });
    }
    if (stpLabel(p) !== stpLabel(d)) {
      changes.push({
        ...base,
        kind: "stp",
        from: stpLabel(p),
        to: stpLabel(d),
      });
    }
  }
  for (const p of previous) {
    if (!curMacs.has(p.mac)) {
      changes.push({
        device: p.name,
        mac: p.mac,
        kind: "removed",
        from: p.state ?? "unknown",
      });
    }
  }
  return changes;
}

/** Build one site's status: summary, changes since the previous snapshot, rows. */
export function buildSiteStatus(
  current: SiteDevices,
  previous?: SiteDevices,
): SiteDeviceStatus {
  const now = Date.parse(current.scannedAt);
  const rows: DeviceStatusRow[] = current.devices.map((d) => {
    const seen = d.lastSeen ? Date.parse(d.lastSeen) : NaN;
    return {
      name: d.name,
      mac: d.mac,
      model: d.model,
      ipAddress: d.ipAddress,
      state: d.state ?? "unknown",
      firmwareVersion: d.firmwareVersion,
      upgradeAvailable: hasUpgrade(d),
      upgradeToFirmware: d.upgradeToFirmware,
      lastSeen: d.lastSeen,
      lastSeenAgoSeconds: Number.isFinite(seen) && Number.isFinite(now)
        ? Math.max(0, Math.round((now - seen) / 1000))
        : undefined,
      uplink: uplinkLabel(d),
      stpBlockedPorts: d.stpBlockedPorts,
    };
  });
  // Not-online devices first, then by name, so problems are at the top.
  rows.sort((a, b) =>
    Number(a.state === "ONLINE") - Number(b.state === "ONLINE") ||
    a.name.localeCompare(b.name)
  );
  return {
    siteName: current.siteName,
    label: current.consoleShortname
      ? `${current.consoleShortname} · ${current.siteName}`
      : current.siteName,
    scannedAt: current.scannedAt,
    previousScannedAt: previous?.scannedAt,
    summary: {
      devices: rows.length,
      online: rows.filter((r) => r.state === "ONLINE").length,
      notOnline: rows.filter((r) => r.state !== "ONLINE").length,
      upgradesAvailable: rows.filter((r) => r.upgradeAvailable).length,
      stpBlockedPorts: rows.reduce((n, r) => n + r.stpBlockedPorts.length, 0),
    },
    changes: previous ? diffDevices(previous.devices, current.devices) : [],
    devices: rows,
  };
}

/** "3m", "5h", "42d" — how long ago, for the table. */
export function formatAgo(seconds: number | undefined): string {
  if (seconds === undefined) return "never";
  if (seconds < 120) return "now";
  if (seconds < 7200) return `${Math.round(seconds / 60)}m`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

const cell = (s: string | undefined) => (s ?? "—").replace(/\|/g, "\\|");

function describeChange(c: DeviceChange): string {
  switch (c.kind) {
    case "added":
      return `**${c.device}** added (${c.to})`;
    case "removed":
      return `**${c.device}** removed (was ${c.from})`;
    case "upgrade":
      return `**${c.device}** upgrade available: ${c.from ?? "?"} → ${c.to}`;
    case "stp":
      return `**${c.device}** STP-blocked ports: ${c.from} → ${c.to}`;
    default:
      return `**${c.device}** ${c.kind}: ${c.from} → ${c.to}`;
  }
}

export type GroupBy = "none" | "model" | "state" | "uplink";

/** The group key of a row for a groupBy setting. */
export function groupKey(r: DeviceStatusRow, by: GroupBy): string {
  if (by === "model") return r.model ?? "Unknown model";
  if (by === "state") return r.state;
  if (by === "uplink") {
    return r.uplink?.replace(/ port \d+$/, "") ?? "No uplink";
  }
  return "";
}

function deviceTable(rows: DeviceStatusRow[], showModel: boolean): string[] {
  const head = showModel
    ? "| Device | Model | State | Firmware | Upgrade | Last seen | Uplink | STP blocked |"
    : "| Device | State | Firmware | Upgrade | Last seen | Uplink | STP blocked |";
  const out = [
    head,
    head.replace(
      /[^|]+/g,
      (c) => " " + "-".repeat(Math.max(3, c.trim().length)) + " ",
    ),
  ];
  for (const r of rows) {
    const upgrade = r.upgradeAvailable ? (r.upgradeToFirmware ?? "yes") : "—";
    const state = r.state === "ONLINE" ? r.state : `**${r.state}**`;
    const seen = r.lastSeen
      ? `${formatAgo(r.lastSeenAgoSeconds)} (${r.lastSeen.slice(0, 16)}Z)`
      : "never";
    const cols = [
      cell(r.name),
      ...(showModel ? [cell(r.model)] : []),
      state,
      cell(r.firmwareVersion),
      cell(upgrade),
      seen,
      cell(r.uplink),
      r.stpBlockedPorts.length ? r.stpBlockedPorts.join(", ") : "—",
    ];
    out.push(`| ${cols.join(" | ")} |`);
  }
  return out;
}

export function renderSite(
  s: SiteDeviceStatus,
  groupBy: GroupBy = "none",
): string[] {
  const m = s.summary;
  const lines = [
    `# UniFi Device Status — ${s.label}`,
    "",
    `**Devices**: ${m.devices} (${m.online} online, ${m.notOnline} not online)  `,
    `**Upgrades available**: ${m.upgradesAvailable}  `,
    `**STP-blocked ports**: ${m.stpBlockedPorts}  `,
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
  lines.push("", "## Devices", "");
  if (groupBy === "none") {
    lines.push(...deviceTable(s.devices, true));
  } else {
    // Rows are already ordered (not-online first, then name); keep that
    // order inside each group and sort the groups by name.
    const groups = new Map<string, DeviceStatusRow[]>();
    for (const r of s.devices) {
      const k = groupKey(r, groupBy);
      groups.set(k, [...(groups.get(k) ?? []), r]);
    }
    for (const k of [...groups.keys()].sort((a, b) => a.localeCompare(b))) {
      const rows = groups.get(k)!;
      const down = rows.filter((r) => r.state !== "ONLINE").length;
      lines.push(
        `### ${k} (${rows.length}${down ? `, ${down} not online` : ""})`,
        "",
        ...deviceTable(rows, groupBy !== "model"),
        "",
      );
    }
  }
  lines.push("");
  return lines;
}

/** UniFi device status — current state per device plus changes since last scan. */
export const report = {
  name: "@dmc/unifi-device-status",
  description:
    "Per-device state, firmware, offered upgrade, last seen, uplink and " +
    "STP-blocked ports from unifi-networks scanDevices, with the changes " +
    "since the previous scan",
  scope: "method" as const,
  labels: ["networking", "unifi", "inventory", "firmware"],
  execute: async (context: {
    modelType: string;
    modelId: string;
    methodName: string;
    methodArgs?: Record<string, unknown>;
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
    if (context.methodName !== "scanDevices") {
      return { markdown: "", json: {} };
    }
    if (context.executionStatus === "failed") {
      return {
        markdown: `# UniFi Device Status\n\n**Scan failed**: ${
          context.errorMessage ?? "unknown error"
        }\n`,
        json: { status: "failed", error: context.errorMessage },
      };
    }
    const handles = context.dataHandles.filter(
      (h) => h.specName === "siteDevices",
    );
    if (handles.length === 0) {
      return {
        markdown: "# UniFi Device Status\n\nNo device data produced.\n",
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
      // Only a siteDevices snapshot counts; anything else is no baseline.
      return Array.isArray(parsed?.devices) ? parsed as SiteDevices : undefined;
    };

    const g = context.methodArgs?.groupBy;
    const groupBy: GroupBy = g === "model" || g === "state" || g === "uplink"
      ? g
      : "none";
    const lines: string[] = [];
    const sites: SiteDeviceStatus[] = [];
    for (const h of handles) {
      const current = await read(h.name, h.version);
      if (!current) continue;
      // The previous version may have been garbage-collected; then there is
      // nothing to compare against.
      const previous = await read(h.name, h.version - 1).catch(() => undefined);
      const status = buildSiteStatus(current, previous);
      sites.push(status);
      lines.push(...renderSite(status, groupBy));
    }

    return {
      markdown: lines.join("\n"),
      json: { status: "ok", groupBy, sites },
    };
  },
};
