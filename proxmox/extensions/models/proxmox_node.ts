/**
 * `@dmc/proxmox/node` — node-level Proxmox operations with API-token auth:
 * node status, guest discovery for `@dmc/patch`, and VM snapshot guarding
 * (snapshot / rollback / list / delete).
 *
 * Replaces `@keeb/proxmox/node` plus the ai-infra `proxmox_node_guests.ts`
 * extension. The method names and argument/output shapes of the guest methods
 * match that extension, so `@dmc/patch` can point its `proxmoxNodes` /
 * `proxmoxNode` at a definition of this type unchanged.
 *
 * @module
 */
import { z } from "npm:zod@4";
import {
  authHeaders,
  createMethodLogger,
  fetchWithCurl,
  hasUnresolvedAuth,
  nodePath,
  ProxmoxConnectionArgs,
  pveCall,
  resolveAuth,
  validateConnection,
  waitForTask,
} from "./lib/proxmox.ts";

type NodeGlobalArgs = z.infer<typeof ProxmoxConnectionArgs>;

/** The part of swamp's method context these methods use. */
interface Ctx {
  globalArgs: NodeGlobalArgs;
  logger?: unknown;
  writeResource: (
    spec: string,
    name: string,
    data: unknown,
  ) => Promise<{ name: string }>;
}

/** Snapshot tasks are short; give up after this long. */
const SNAPSHOT_TASK_TIMEOUT_SECONDS = 600;

/** Proxmox snapshot names: a letter, then letters, digits, `_` or `-`. */
const SNAPSHOT_NAME_RE = /^[A-Za-z][A-Za-z0-9_-]{0,39}$/;

const NodeStatusSchema = z.object({
  memoryTotal: z.number().describe("Total memory in bytes"),
  memoryUsed: z.number().describe("Used memory in bytes"),
  memoryFree: z.number().describe("Free memory in bytes"),
  cpuUsage: z.number().describe("CPU usage (0-1)"),
  cpuCount: z.number().describe("Number of logical CPUs"),
  uptime: z.number().describe("Node uptime in seconds"),
  timestamp: z.string(),
});

const GuestSchema = z.object({
  type: z.enum(["qemu", "lxc"]),
  vmid: z.number(),
  name: z.string(),
  status: z.string(),
  node: z.string(),
  ip: z.string().nullable(),
});

const GuestsSchema = z.object({
  total: z.number(),
  guests: z.array(GuestSchema),
  checkedAt: z.string(),
});

const SnapshotSchema = z.object({
  host: z.string(),
  vmid: z.number(),
  action: z.enum(["snapshot", "rollback", "list", "delete"]),
  snapshot: z.string().nullable(),
  exitStatus: z.string().nullable(),
  snapshots: z.array(
    z.object({ name: z.string(), description: z.string().nullable() }),
  ),
  timestamp: z.string(),
});

const VmidArg = z.number().int().positive().describe("VM id");
const SnapshotNameArg = z.string().regex(
  SNAPSHOT_NAME_RE,
  "snapshot name must start with a letter and use only letters, digits, _ or - (max 40)",
);

/** Map the /nodes/{node}/status payload onto the `status` resource shape. */
export function parseNodeStatus(d: unknown) {
  // deno-lint-ignore no-explicit-any
  const s = d as any;
  if (
    typeof s?.memory?.total !== "number" ||
    typeof s?.memory?.used !== "number" ||
    typeof s?.cpuinfo?.cpus !== "number"
  ) {
    throw new Error(
      "Unexpected /status response from Proxmox: missing memory or cpuinfo",
    );
  }
  return {
    memoryTotal: s.memory.total,
    memoryUsed: s.memory.used,
    memoryFree: s.memory.total - s.memory.used,
    cpuUsage: typeof s.cpu === "number" ? s.cpu : 0,
    cpuCount: s.cpuinfo.cpus,
    uptime: typeof s.uptime === "number" ? s.uptime : 0,
  };
}

/** Normalise the /cluster/resources?type=vm payload into guests (no IPs yet). */
export function parseClusterGuests(
  data: unknown,
): Array<Omit<z.infer<typeof GuestSchema>, "ip">> {
  if (!Array.isArray(data)) {
    throw new Error(
      "Unexpected /cluster/resources response from Proxmox (not an array)",
    );
  }
  return data
    .filter((g) => g && (g.type === "qemu" || g.type === "lxc"))
    .map((g) => ({
      type: g.type as "qemu" | "lxc",
      vmid: Number(g.vmid),
      name: g.name ?? String(g.vmid),
      status: g.status ?? "unknown",
      node: String(g.node),
    }))
    .filter((g) => Number.isInteger(g.vmid))
    .sort((a, b) => a.vmid - b.vmid);
}

/** First non-loopback IPv4 from an LXC /interfaces payload. */
export function pickLxcIpv4(interfaces: unknown): string | null {
  if (!Array.isArray(interfaces)) return null;
  for (const i of interfaces) {
    if (!i || i.name === "lo") continue;
    const ip = String(i.inet ?? "").split("/")[0];
    if (ip && !ip.startsWith("127.")) return ip;
  }
  return null;
}

/** First non-loopback IPv4 from a QEMU guest-agent payload. */
function pickQemuIpv4(result: unknown): string | null {
  if (!Array.isArray(result)) return null;
  for (const i of result) {
    for (const a of i?.["ip-addresses"] ?? []) {
      const ip = a?.["ip-address"];
      if (
        a?.["ip-address-type"] === "ipv4" && typeof ip === "string" &&
        !ip.startsWith("127.")
      ) return ip;
    }
  }
  return null;
}

/** A running guest's IPv4 (guest agent for qemu, interfaces for lxc), or null. */
async function guestIp(
  g: NodeGlobalArgs,
  auth: Awaited<ReturnType<typeof resolveAuth>>,
  guest: { type: string; vmid: number; node: string; status: string },
): Promise<string | null> {
  if (guest.status !== "running") return null;
  const path = guest.type === "qemu"
    ? `/qemu/${guest.vmid}/agent/network-get-interfaces`
    : `/lxc/${guest.vmid}/interfaces`;
  try {
    const res = await fetchWithCurl(
      nodePath({ apiUrl: g.apiUrl, node: guest.node }, path),
      {
        method: "GET",
        headers: authHeaders(auth),
        skipTlsVerify: g.skipTlsVerify ?? true,
      },
    );
    if (!res.ok) return null;
    const data = res.json()?.data;
    return guest.type === "qemu"
      ? pickQemuIpv4(data?.result)
      : pickLxcIpv4(data);
  } catch {
    return null; // no agent / not reachable: no IP
  }
}

/** Run a snapshot task (POST or DELETE) and wait for it; returns the exit status. */
async function runSnapshotTask(
  g: NodeGlobalArgs,
  auth: Awaited<ReturnType<typeof resolveAuth>>,
  method: "POST" | "DELETE",
  path: string,
  what: string,
  form?: Record<string, string>,
): Promise<string> {
  const upid = await pveCall(
    g,
    auth,
    method,
    nodePath(g, path),
    what,
    form ? new URLSearchParams(form).toString() : undefined,
  );
  if (typeof upid !== "string" || !upid) return "OK";
  const result = await waitForTask(
    g.apiUrl,
    g.node,
    upid,
    auth,
    g.skipTlsVerify ?? true,
    SNAPSHOT_TASK_TIMEOUT_SECONDS,
  );
  return result.exitstatus ?? "unknown";
}

/** The `snapshot` resource for one VM action. */
function snapshotRecord(
  vmid: number,
  action: z.infer<typeof SnapshotSchema>["action"],
  snapshot: string | null,
  exitStatus: string | null,
  snapshots: z.infer<typeof SnapshotSchema>["snapshots"] = [],
): z.infer<typeof SnapshotSchema> {
  return {
    host: String(vmid),
    vmid,
    action,
    snapshot,
    exitStatus,
    snapshots,
    timestamp: new Date().toISOString(),
  };
}

/** Swamp model definition for `@dmc/proxmox/node`. */
export const model = {
  type: "@dmc/proxmox/node",
  version: "2026.10.26.1",
  globalArguments: ProxmoxConnectionArgs,
  upgrades: [
    {
      toVersion: "2026.10.26.1",
      description:
        "First release. Definitions moved from @keeb/proxmox/node keep their attributes; set tokenId/tokenSecret for token auth",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  resources: {
    status: {
      description: "Node resource usage (memory, CPU, uptime)",
      schema: NodeStatusSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    guests: {
      description: "VMs + CTs known to the Proxmox cluster",
      schema: GuestsSchema,
      lifetime: "infinite",
      garbageCollection: 5,
    },
    snapshot: {
      description: "Result of a VM snapshot / rollback / list / delete",
      schema: SnapshotSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
  },
  checks: {
    "valid-connection": {
      description:
        "apiUrl is an http(s) URL without credentials and node is set",
      labels: ["policy"],
      execute: (context: { globalArgs: NodeGlobalArgs }) =>
        Promise.resolve(validateConnection(context.globalArgs)),
    },
    "node-reachable": {
      description:
        "The Proxmox API answers for this node with the configured auth (needs Sys.Audit on /nodes/{node})",
      labels: ["live"],
      execute: async (context: { globalArgs: NodeGlobalArgs }) => {
        const g = context.globalArgs;
        if (hasUnresolvedAuth(g)) return { pass: true };
        try {
          const auth = await resolveAuth(g, context, { skipCache: true });
          await pveCall(
            g,
            auth,
            "GET",
            nodePath(g, "/status"),
            `Reading status of node "${g.node}"`,
          );
          return { pass: true };
        } catch (err) {
          return {
            pass: false,
            errors: [
              `${
                (err as Error).message
              }. Fix the cause, or skip with --skip-check-label live.`,
            ],
          };
        }
      },
    },
  },
  methods: {
    status: {
      description:
        "Fetch current node resource usage (memory, CPU, uptime). Needs: Sys.Audit on /nodes/{node}.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Fetching status of node {node}", { node: g.node });
        const auth = await resolveAuth(g, context, { skipCache: true });
        const status = parseNodeStatus(
          await pveCall(
            g,
            auth,
            "GET",
            nodePath(g, "/status"),
            `Fetching status of node ${g.node}`,
          ),
        );
        const handle = await context.writeResource("status", "status", {
          ...status,
          timestamp: new Date().toISOString(),
        });
        log.info("Node {node}: {cpus} CPUs, {used}/{total} bytes memory used", {
          node: g.node,
          cpus: status.cpuCount,
          used: status.memoryUsed,
          total: status.memoryTotal,
        });
        return { dataHandles: [handle] };
      },
    },

    listGuests: {
      description:
        "List all VMs and CTs on the Proxmox cluster (type, vmid, name, status, node, ip). Needs: VM.Audit on each guest (others are not listed); VM.GuestAgent.Audit for VM IPs.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Listing guests on the cluster of node {node}", {
          node: g.node,
        });
        const auth = await resolveAuth(g, context, { skipCache: true });
        const base = parseClusterGuests(
          await pveCall(
            g,
            auth,
            "GET",
            `${g.apiUrl}/api2/json/cluster/resources?type=vm`,
            "Listing cluster guests",
          ),
        );
        const guests = await Promise.all(
          base.map(async (guest) => ({
            ...guest,
            ip: await guestIp(g, auth, guest),
          })),
        );
        const handle = await context.writeResource("guests", "guests", {
          total: guests.length,
          guests,
          checkedAt: new Date().toISOString(),
        });
        log.info("Found {total} guests ({vms} VMs, {cts} CTs)", {
          total: guests.length,
          vms: guests.filter((x) => x.type === "qemu").length,
          cts: guests.filter((x) => x.type === "lxc").length,
        });
        return { dataHandles: [handle] };
      },
    },

    snapshotVm: {
      description:
        "Create a Proxmox snapshot of a VM (waits for the task to finish). Needs: VM.Snapshot on /vms/{vmid}.",
      arguments: z.object({
        vmid: VmidArg,
        name: z.union([z.literal(""), SnapshotNameArg]).default("").describe(
          "Snapshot name; default preupdate-<timestamp>",
        ),
        description: z.string().default("").describe(
          "Optional snapshot description",
        ),
      }),
      execute: async (
        args: { vmid: number; name: string; description: string },
        context: Ctx,
      ) => {
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        const snap = args.name ||
          `preupdate-${new Date().toISOString().replace(/[:.]/g, "-")}`;
        log.info("Snapshotting VM {vmid} as {snap}", {
          vmid: args.vmid,
          snap,
        });
        const auth = await resolveAuth(g, context, { skipCache: true });
        const form: Record<string, string> = { snapname: snap };
        if (args.description) form.description = args.description;
        const exit = await runSnapshotTask(
          g,
          auth,
          "POST",
          `/qemu/${args.vmid}/snapshot`,
          `Snapshotting VM ${args.vmid}`,
          form,
        );
        if (exit !== "OK") throw new Error(`snapshot failed: ${exit}`);
        const handle = await context.writeResource(
          "snapshot",
          `snapshot-${args.vmid}`,
          snapshotRecord(args.vmid, "snapshot", snap, exit),
        );
        log.info("VM {vmid} snapshot {snap}: {exit}", {
          vmid: args.vmid,
          snap,
          exit,
        });
        return { dataHandles: [handle] };
      },
    },

    rollbackVm: {
      description:
        "Roll a VM back to a Proxmox snapshot (waits for the task to finish). Needs: VM.Snapshot.Rollback (or VM.Snapshot) on /vms/{vmid}.",
      arguments: z.object({ vmid: VmidArg, name: SnapshotNameArg }),
      execute: async (args: { vmid: number; name: string }, context: Ctx) => {
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Rolling VM {vmid} back to {snap}", {
          vmid: args.vmid,
          snap: args.name,
        });
        const auth = await resolveAuth(g, context, { skipCache: true });
        const exit = await runSnapshotTask(
          g,
          auth,
          "POST",
          `/qemu/${args.vmid}/snapshot/${args.name}/rollback`,
          `Rolling VM ${args.vmid} back to ${args.name}`,
        );
        if (exit !== "OK") throw new Error(`rollback failed: ${exit}`);
        const handle = await context.writeResource(
          "snapshot",
          `snapshot-${args.vmid}`,
          snapshotRecord(args.vmid, "rollback", args.name, exit),
        );
        log.info("VM {vmid} rolled back to {snap}: {exit}", {
          vmid: args.vmid,
          snap: args.name,
          exit,
        });
        return { dataHandles: [handle] };
      },
    },

    listVmSnapshots: {
      description: "List a VM's snapshots. Needs: VM.Audit on /vms/{vmid}.",
      arguments: z.object({ vmid: VmidArg }),
      execute: async (args: { vmid: number }, context: Ctx) => {
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Listing snapshots of VM {vmid}", { vmid: args.vmid });
        const auth = await resolveAuth(g, context, { skipCache: true });
        const raw = await pveCall(
          g,
          auth,
          "GET",
          nodePath(g, `/qemu/${args.vmid}/snapshot`),
          `Listing snapshots of VM ${args.vmid}`,
        );
        if (!Array.isArray(raw)) {
          throw new Error(
            `Unexpected snapshot list for VM ${args.vmid} (not an array)`,
          );
        }
        const snapshots = raw
          .filter((s) => s && s.name !== "current")
          .map((s) => ({
            name: String(s.name),
            description: s.description ?? null,
          }));
        const handle = await context.writeResource(
          "snapshot",
          `snapshot-${args.vmid}`,
          snapshotRecord(args.vmid, "list", null, null, snapshots),
        );
        log.info("VM {vmid} has {count} snapshots", {
          vmid: args.vmid,
          count: snapshots.length,
        });
        return { dataHandles: [handle] };
      },
    },

    deleteVmSnapshot: {
      description:
        "Delete a VM snapshot (waits for the task to finish). Needs: VM.Snapshot on /vms/{vmid}.",
      arguments: z.object({ vmid: VmidArg, name: SnapshotNameArg }),
      execute: async (args: { vmid: number; name: string }, context: Ctx) => {
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Deleting snapshot {snap} of VM {vmid}", {
          vmid: args.vmid,
          snap: args.name,
        });
        const auth = await resolveAuth(g, context, { skipCache: true });
        const exit = await runSnapshotTask(
          g,
          auth,
          "DELETE",
          `/qemu/${args.vmid}/snapshot/${args.name}`,
          `Deleting snapshot ${args.name} of VM ${args.vmid}`,
        );
        if (exit !== "OK") throw new Error(`delete failed: ${exit}`);
        const handle = await context.writeResource(
          "snapshot",
          `snapshot-${args.vmid}`,
          snapshotRecord(args.vmid, "delete", args.name, exit),
        );
        log.info("VM {vmid} snapshot {snap} deleted: {exit}", {
          vmid: args.vmid,
          snap: args.name,
          exit,
        });
        return { dataHandles: [handle] };
      },
    },
  },
};
