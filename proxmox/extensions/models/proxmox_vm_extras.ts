import { z } from "npm:zod@4";
import { fetchWithCurl, resolveAuth, waitForTask } from "./lib/proxmox.ts";

function authOpts() {
  return { modelType: "@keeb/proxmox/vm" };
}

async function resolveVmId(
  apiUrl,
  node,
  vmName,
  ticket,
  csrfToken,
  skipTlsVerify,
) {
  const response = await fetchWithCurl(
    `${apiUrl}/api2/json/nodes/${node}/qemu`,
    {
      method: "GET",
      headers: {
        "Cookie": `PVEAuthCookie=${ticket}`,
        "CSRFPreventionToken": csrfToken,
      },
      skipTlsVerify,
    },
  );
  if (!response.ok) {
    throw new Error(`Failed to list VMs: ${await response.text()}`);
  }
  const vms = (await response.json()).data;
  const vm = vms.find((v) => v.name === vmName);
  if (!vm) {
    throw new Error(
      `VM "${vmName}" not found. Available: ${
        vms.map((v) => v.name).filter(Boolean).join(", ")
      }`,
    );
  }
  return vm;
}

async function resolveLxcId(
  apiUrl,
  node,
  ctName,
  ticket,
  csrfToken,
  skipTlsVerify,
) {
  const response = await fetchWithCurl(
    `${apiUrl}/api2/json/nodes/${node}/lxc`,
    {
      method: "GET",
      headers: {
        "Cookie": `PVEAuthCookie=${ticket}`,
        "CSRFPreventionToken": csrfToken,
      },
      skipTlsVerify,
    },
  );
  if (!response.ok) {
    throw new Error(`Failed to list LXC containers: ${await response.text()}`);
  }
  const cts = (await response.json()).data;
  const ct = cts.find((c) => c.name === ctName);
  if (!ct) {
    throw new Error(
      `LXC "${ctName}" not found. Available: ${
        cts.map((c) => c.name).filter(Boolean).join(", ")
      }`,
    );
  }
  return ct;
}

// ---- Pre-flight checks ------------------------------------------------------
//
// swamp runs these before the mutating methods they list in `appliesTo`. They
// are cheap, read-only API probes. Labels: `policy` = static rule about the
// inputs (no network); `live` = asks the Proxmox API. A user skips them with
// `--skip-check <name>`, `--skip-check-label <label>` or `--skip-checks`.
//
// Checks cannot see the parsed method args. They read the raw ones from
// `context.unresolvedMethodArgs`. When an arg is absent or is still an
// unresolved ${{ }} expression, the check passes and leaves the decision to
// the method's own validation.

/** The part of swamp's check context these checks read. */
interface VmCheckContext {
  globalArgs: {
    apiUrl: string;
    node: string;
    skipTlsVerify?: boolean;
    ticket?: string;
    csrfToken?: string;
  };
  methodName: string;
  /** Method args merged over global args (raw, before expression resolution). */
  unresolvedMethodArgs?: Record<string, unknown>;
}

/** Result shape swamp expects from a check. */
interface CheckResult {
  pass: boolean;
  errors?: string[];
}

type ApiGet =
  | { ok: true; data: unknown }
  | { ok: false; errors: string[] };

const SKIP_LIVE_HINT = "Fix the cause, or skip with --skip-check-label live.";

/** A string method arg, or undefined when absent or an unresolved expression. */
function stringArg(ctx: VmCheckContext, name: string): string | undefined {
  const v = ctx.unresolvedMethodArgs?.[name];
  return typeof v === "string" && v.length > 0 && !v.includes("${{")
    ? v
    : undefined;
}

/** GET a Proxmox API path for a check. Never throws; failures come back as `ok: false`. */
async function checkApiGet(
  ctx: VmCheckContext,
  path: string,
  what: string,
): Promise<ApiGet> {
  try {
    const { apiUrl, skipTlsVerify } = ctx.globalArgs;
    const auth = await resolveAuth(ctx.globalArgs, ctx, authOpts());
    const response = await fetchWithCurl(`${apiUrl}/api2/json${path}`, {
      method: "GET",
      headers: {
        "Cookie": `PVEAuthCookie=${auth.ticket}`,
        "CSRFPreventionToken": auth.csrfToken,
      },
      skipTlsVerify,
    });
    if (!response.ok) {
      return {
        ok: false,
        errors: [
          `Could not read ${what}: ${response.status} ${await response
            .text()}. ${SKIP_LIVE_HINT}`,
        ],
      };
    }
    return { ok: true, data: (await response.json()).data };
  } catch (err) {
    return {
      ok: false,
      errors: [
        `Could not read ${what}: ${(err as Error).message}. ${SKIP_LIVE_HINT}`,
      ],
    };
  }
}

type GuestKind = "qemu" | "lxc";
type Guest = { vmid: number; name?: string; status?: string };

/** The guest-taking methods: what kind of guest, and which arg holds its name. */
const GUEST_METHODS: Record<string, { kind: GuestKind; nameArg: string }> = {
  configureCloudInit: { kind: "qemu", nameArg: "vmName" },
  snapshot: { kind: "qemu", nameArg: "vmName" },
  deleteSnapshot: { kind: "qemu", nameArg: "vmName" },
  moveDisk: { kind: "qemu", nameArg: "vmName" },
  migrate: { kind: "qemu", nameArg: "vmName" },
  lxcStop: { kind: "lxc", nameArg: "ctName" },
  lxcStart: { kind: "lxc", nameArg: "ctName" },
  lxcMoveVolume: { kind: "lxc", nameArg: "ctName" },
};

type FindGuest =
  | { ok: true; guest: Guest }
  | { ok: false; errors: string[] };

/** Find a VM or LXC by name on a node through the API. */
async function findGuest(
  ctx: VmCheckContext,
  kind: GuestKind,
  name: string,
  node: string,
): Promise<FindGuest> {
  const res = await checkApiGet(
    ctx,
    `/nodes/${node}/${kind}`,
    `the ${kind === "qemu" ? "VM" : "LXC"} list of node "${node}"`,
  );
  if (!res.ok) return res;
  const guests = (Array.isArray(res.data) ? res.data : []) as Guest[];
  const guest = guests.find((g) => g.name === name);
  if (!guest) {
    const names = guests.map((g) => g.name).filter(Boolean).slice(0, 10);
    return {
      ok: false,
      errors: [
        `${
          kind === "qemu" ? "VM" : "LXC"
        } "${name}" not found on node "${node}" (found: ${
          names.join(", ") || "none"
        }). Fix the name or node, or skip with --skip-check guest-exists.`,
      ],
    };
  }
  return { ok: true, guest };
}

type SnapshotNames =
  | { ok: true; names: string[] }
  | { ok: false; errors: string[] };

/** Snapshot names of a VM, found by name on the model's node. */
async function vmSnapshotNames(
  ctx: VmCheckContext,
  vmName: string,
): Promise<SnapshotNames> {
  const node = ctx.globalArgs.node;
  const found = await findGuest(ctx, "qemu", vmName, node);
  if (!found.ok) return found;
  const res = await checkApiGet(
    ctx,
    `/nodes/${node}/qemu/${found.guest.vmid}/snapshot`,
    `the snapshots of VM "${vmName}"`,
  );
  if (!res.ok) return res;
  const rows = (Array.isArray(res.data) ? res.data : []) as Array<
    { name?: string }
  >;
  return {
    ok: true,
    names: rows.map((r) => r.name).filter((n): n is string => !!n),
  };
}

/** Proxmox snapshot names: a letter first, then letters, digits, _ or -; 2-40 chars. */
const SNAPNAME_RE = /^[A-Za-z][A-Za-z0-9_-]{1,39}$/;

const preflightChecks = {
  "guest-exists": {
    description:
      "Verify the VM or LXC named in the method args exists on the node (the source node for migrate) before the method changes it",
    labels: ["live"],
    appliesTo: Object.keys(GUEST_METHODS),
    execute: async (ctx: VmCheckContext): Promise<CheckResult> => {
      const spec = GUEST_METHODS[ctx.methodName];
      const name = spec && stringArg(ctx, spec.nameArg);
      if (!spec || !name) return { pass: true };
      const node =
        (ctx.methodName === "migrate"
          ? stringArg(ctx, "sourceNode")
          : undefined) ?? ctx.globalArgs.node;
      const found = await findGuest(ctx, spec.kind, name, node);
      return found.ok ? { pass: true } : { pass: false, errors: found.errors };
    },
  },
  "vmid-free": {
    description:
      "Verify the explicit vmid is not already used by any VM or container in the cluster. Passes when no vmid is given (Proxmox picks one).",
    labels: ["live"],
    appliesTo: ["createFromImage"],
    execute: async (ctx: VmCheckContext): Promise<CheckResult> => {
      const vmid = ctx.unresolvedMethodArgs?.vmid;
      if (typeof vmid !== "number") return { pass: true };
      const res = await checkApiGet(
        ctx,
        "/cluster/resources?type=vm",
        "the cluster VM list",
      );
      if (!res.ok) return { pass: false, errors: res.errors };
      const rows = (Array.isArray(res.data) ? res.data : []) as Guest[];
      const used = rows.find((r) => r.vmid === vmid);
      if (used) {
        return {
          pass: false,
          errors: [
            `vmid ${vmid} is already used by "${
              used.name ?? "unnamed"
            }". Pick another vmid or leave it unset, or skip with --skip-check vmid-free.`,
          ],
        };
      }
      return { pass: true };
    },
  },
  "target-storage-exists": {
    description:
      "Verify the target storage pool exists and is active on the node before a disk is imported or moved to it",
    labels: ["live"],
    appliesTo: ["createFromImage", "moveDisk", "lxcMoveVolume"],
    execute: async (ctx: VmCheckContext): Promise<CheckResult> => {
      const storage = stringArg(
        ctx,
        ctx.methodName === "createFromImage" ? "diskStorage" : "targetStorage",
      );
      if (!storage) return { pass: true };
      const node = ctx.globalArgs.node;
      const res = await checkApiGet(
        ctx,
        `/nodes/${node}/storage/${encodeURIComponent(storage)}/status`,
        `storage "${storage}" on node "${node}"`,
      );
      if (!res.ok) return { pass: false, errors: res.errors };
      const status = res.data as { active?: number } | null;
      if (status?.active !== 1) {
        return {
          pass: false,
          errors: [
            `Storage "${storage}" on node "${node}" is not active. Activate it, or skip with --skip-check target-storage-exists.`,
          ],
        };
      }
      return { pass: true };
    },
  },
  "snapshot-name-valid": {
    description:
      'Verify the snapshot name follows the Proxmox rule (a letter first, then letters, digits, "_" or "-", 2 to 40 characters) and is not "current"',
    labels: ["policy"],
    appliesTo: ["snapshot"],
    execute: (ctx: VmCheckContext): Promise<CheckResult> => {
      const snapname = stringArg(ctx, "snapname");
      const bad = snapname !== undefined &&
        (!SNAPNAME_RE.test(snapname) || snapname === "current");
      return Promise.resolve(
        bad
          ? {
            pass: false,
            errors: [
              `Snapshot name "${snapname}" is not valid. Use a letter first, then letters, digits, "_" or "-" (2 to 40 characters), and not "current". Or skip with --skip-check snapshot-name-valid.`,
            ],
          }
          : { pass: true },
      );
    },
  },
  "snapshot-name-free": {
    description:
      "Verify the VM has no snapshot with this name yet, so snapshot does not collide",
    labels: ["live"],
    appliesTo: ["snapshot"],
    execute: async (ctx: VmCheckContext): Promise<CheckResult> => {
      const vmName = stringArg(ctx, "vmName");
      const snapname = stringArg(ctx, "snapname");
      if (!vmName || !snapname) return { pass: true };
      const res = await vmSnapshotNames(ctx, vmName);
      if (!res.ok) return { pass: false, errors: res.errors };
      if (res.names.includes(snapname)) {
        return {
          pass: false,
          errors: [
            `VM "${vmName}" already has a snapshot named "${snapname}". Pick another name, or skip with --skip-check snapshot-name-free.`,
          ],
        };
      }
      return { pass: true };
    },
  },
  "snapshot-exists": {
    description:
      "Verify the snapshot to delete exists on the VM, so deleteSnapshot does not fail late",
    labels: ["live"],
    appliesTo: ["deleteSnapshot"],
    execute: async (ctx: VmCheckContext): Promise<CheckResult> => {
      const vmName = stringArg(ctx, "vmName");
      const snapname = stringArg(ctx, "snapname");
      if (!vmName || !snapname) return { pass: true };
      const res = await vmSnapshotNames(ctx, vmName);
      if (!res.ok) return { pass: false, errors: res.errors };
      if (!res.names.includes(snapname)) {
        return {
          pass: false,
          errors: [
            `VM "${vmName}" has no snapshot named "${snapname}" (found: ${
              res.names.filter((n) => n !== "current").join(", ") || "none"
            }). Fix the name, or skip with --skip-check snapshot-exists.`,
          ],
        };
      }
      return { pass: true };
    },
  },
};

/** VM and LXC lifecycle extensions for `@keeb/proxmox/vm` — provisioning, snapshots, disk/node migration, and container control. */
export const extension = {
  type: "@keeb/proxmox/vm",
  checks: [{
    "cluster-has-migration-target": {
      description:
        "Verify the node is part of a multi-node Proxmox cluster — migration has nowhere to go on a standalone node",
      labels: ["live"],
      appliesTo: ["migrate"],
      execute: async (context) => {
        const { apiUrl, node, skipTlsVerify } = context.globalArgs;
        const auth = await resolveAuth(context.globalArgs, context, authOpts());

        const response = await fetchWithCurl(
          `${apiUrl}/api2/json/cluster/status`,
          {
            method: "GET",
            headers: {
              "Cookie": `PVEAuthCookie=${auth.ticket}`,
              "CSRFPreventionToken": auth.csrfToken,
            },
            skipTlsVerify,
          },
        );
        if (!response.ok) {
          return {
            pass: false,
            errors: [
              `Failed to read cluster status: ${response.status} ${await response
                .text()}`,
            ],
          };
        }

        const items = (await response.json()).data;
        const nodes = items.filter((n) => n.type === "node");
        if (nodes.length < 2) {
          return {
            pass: false,
            errors: [
              `Node "${node}" is not part of a multi-node cluster — migration has no valid target`,
            ],
          };
        }

        const self = nodes.find((n) => n.name === node);
        if (self && self.online !== 1) {
          return {
            pass: false,
            errors: [`Node "${node}" is reported offline in cluster status`],
          };
        }

        return { pass: true };
      },
    },
    ...preflightChecks,
  }],
  methods: [{
    createFromImage: {
      description:
        "Create a VM by importing a cloud image disk — handles VM creation, disk import, and cloud-init drive in one step",
      arguments: z.object({
        vmName: z.string().describe("VM name"),
        vmid: z.number().int().optional().describe(
          "Explicit VM ID to assign (default: auto-assigned by Proxmox)",
        ),
        importFrom: z.string().describe(
          "Storage reference of the image to import (e.g., local:import/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2)",
        ),
        diskStorage: z.string().describe(
          "Storage pool for the imported VM disk and cloud-init drive",
        ),
        memory: z.number().default(2048).describe("Memory in MB"),
        cores: z.number().default(2).describe("CPU cores"),
        networkBridge: z.string().default("vmbr0").describe("Network bridge"),
        ciUser: z.string().optional().describe(
          "Cloud-init username (e.g., rocky)",
        ),
        sshKeys: z.string().optional().describe(
          "URL-encoded SSH public key(s) for cloud-init",
        ),
        ipConfig: z.string().default("ip=dhcp").describe(
          "Cloud-init IP config (ip=dhcp or ip=x.x.x.x/24,gw=x.x.x.1)",
        ),
      }),
      execute: async (args, context) => {
        const { apiUrl, node, skipTlsVerify } = context.globalArgs;
        const {
          vmName,
          importFrom,
          diskStorage,
          memory,
          cores,
          networkBridge,
          ciUser,
          sshKeys,
          ipConfig,
        } = args;
        context.logger.info(
          "Creating VM {vmName} on {node} from image {importFrom}",
          { vmName, node, importFrom },
        );
        const logs = [];
        const log = (msg) => logs.push(msg);

        const auth = await resolveAuth(context.globalArgs, context, authOpts());
        const { ticket, csrfToken } = auth;
        const authHeaders = {
          "Cookie": `PVEAuthCookie=${ticket}`,
          "CSRFPreventionToken": csrfToken,
        };

        let vmid: number;
        if (args.vmid != null) {
          vmid = args.vmid;
          log(`Using explicit VM ID: ${vmid}`);
        } else {
          log(`Fetching next available VM ID`);
          const nextIdResp = await fetchWithCurl(
            `${apiUrl}/api2/json/cluster/nextid`,
            {
              method: "GET",
              headers: authHeaders,
              skipTlsVerify,
            },
          );
          if (!nextIdResp.ok) {
            throw new Error(
              `Failed to get next VM ID: ${await nextIdResp.text()}`,
            );
          }
          vmid = parseInt((await nextIdResp.json()).data, 10);
          log(`VM ID: ${vmid}`);
        }

        log(`Creating VM "${vmName}" (${vmid}) with import-from=${importFrom}`);
        const createParams = new URLSearchParams({
          vmid: String(vmid),
          name: vmName,
          memory: String(memory),
          cores: String(cores),
          sockets: "1",
          cpu: "Broadwell",
          ostype: "l26",
          agent: "1",
          virtio0:
            `${diskStorage}:0,import-from=${importFrom},iothread=1,discard=on`,
          net0: `virtio,bridge=${networkBridge}`,
          serial0: "socket",
          boot: "order=virtio0",
        });

        const createResp = await fetchWithCurl(
          `${apiUrl}/api2/json/nodes/${node}/qemu`,
          {
            method: "POST",
            headers: {
              ...authHeaders,
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: createParams.toString(),
            skipTlsVerify,
          },
        );
        if (!createResp.ok) {
          throw new Error(
            `Failed to create VM: ${createResp.status} ${await createResp
              .text()}`,
          );
        }

        const createUpid = (await createResp.json()).data;
        log(`VM creation task started, waiting...`);
        const createResult = await waitForTask(
          apiUrl,
          node,
          createUpid,
          ticket,
          csrfToken,
          skipTlsVerify,
        );
        if (!createResult.success) {
          throw new Error(`VM creation failed: ${createResult.exitstatus}`);
        }
        log(`VM ${vmid} created (${createResult.pollCount} polls)`);

        log(`Attaching cloud-init drive and configuring`);
        const ciParams = new URLSearchParams({
          ide2: `${diskStorage}:cloudinit`,
          ipconfig0: ipConfig,
        });
        if (ciUser) ciParams.set("ciuser", ciUser);
        // Proxmox requires sshkeys to be URL-encoded inside the form field (double-encode).
        if (sshKeys) ciParams.set("sshkeys", encodeURIComponent(sshKeys));

        const ciResp = await fetchWithCurl(
          `${apiUrl}/api2/json/nodes/${node}/qemu/${vmid}/config`,
          {
            method: "PUT",
            headers: {
              ...authHeaders,
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: ciParams.toString(),
            skipTlsVerify,
          },
        );
        if (!ciResp.ok) {
          throw new Error(
            `Failed to configure cloud-init: ${ciResp.status} ${await ciResp
              .text()}`,
          );
        }
        log(
          `Cloud-init configured (user=${
            ciUser ?? "default"
          }, ipConfig=${ipConfig})`,
        );

        const handle = await context.writeResource("vm", vmName, {
          vmid,
          vmName,
          status: "stopped",
          ip: null,
          success: true,
          logs: logs.join("\n"),
          timestamp: new Date().toISOString(),
        });
        context.logger.info("Created VM {vmName} with vmid {vmid} on {node}", {
          vmName,
          vmid,
          node,
        });
        return { dataHandles: [handle] };
      },
    },

    configureCloudInit: {
      description:
        "Update cloud-init configuration on an existing VM (user, SSH keys, IP config)",
      arguments: z.object({
        vmName: z.string().describe("VM name"),
        ciUser: z.string().optional().describe("Cloud-init username"),
        sshKeys: z.string().optional().describe(
          "URL-encoded SSH public key(s)",
        ),
        ipConfig: z.string().optional().describe(
          "IP config (ip=dhcp or ip=x.x.x.x/24,gw=x.x.x.1)",
        ),
      }),
      execute: async (args, context) => {
        const { apiUrl, node, skipTlsVerify } = context.globalArgs;
        const { vmName, ciUser, sshKeys, ipConfig } = args;
        context.logger.info("Updating cloud-init on VM {vmName} on {node}", {
          vmName,
          node,
        });
        const logs = [];
        const log = (msg) => logs.push(msg);

        const auth = await resolveAuth(context.globalArgs, context, authOpts());
        const { ticket, csrfToken } = auth;

        const vm = await resolveVmId(
          apiUrl,
          node,
          vmName,
          ticket,
          csrfToken,
          skipTlsVerify,
        );
        log(`Found VM "${vmName}" → vmid ${vm.vmid}`);

        const ciParams = new URLSearchParams();
        if (ciUser) ciParams.set("ciuser", ciUser);
        if (sshKeys) ciParams.set("sshkeys", encodeURIComponent(sshKeys));
        if (ipConfig) ciParams.set("ipconfig0", ipConfig);
        if ([...ciParams].length === 0) {
          throw new Error("No cloud-init params provided");
        }

        const response = await fetchWithCurl(
          `${apiUrl}/api2/json/nodes/${node}/qemu/${vm.vmid}/config`,
          {
            method: "PUT",
            headers: {
              "Cookie": `PVEAuthCookie=${ticket}`,
              "Content-Type": "application/x-www-form-urlencoded",
              "CSRFPreventionToken": csrfToken,
            },
            body: ciParams.toString(),
            skipTlsVerify,
          },
        );
        if (!response.ok) {
          throw new Error(
            `Failed to configure cloud-init: ${response.status} ${await response
              .text()}`,
          );
        }
        log(`Cloud-init updated on VM ${vm.vmid}`);

        const handle = await context.writeResource("vm", vmName, {
          vmid: vm.vmid,
          vmName,
          config: Object.fromEntries(ciParams),
          success: true,
          logs: logs.join("\n"),
          timestamp: new Date().toISOString(),
        });
        context.logger.info("Updated cloud-init on VM {vmName} (vmid {vmid})", {
          vmName,
          vmid: vm.vmid,
        });
        return { dataHandles: [handle] };
      },
    },

    snapshot: {
      description: "Create a Proxmox VM snapshot",
      arguments: z.object({
        vmName: z.string().describe("VM name"),
        snapname: z.string().describe(
          "Snapshot name (alphanumeric/underscore, no spaces)",
        ),
        description: z.string().optional().describe("Snapshot description"),
      }),
      execute: async (args, context) => {
        const { apiUrl, node, skipTlsVerify } = context.globalArgs;
        const { vmName, snapname, description } = args;
        context.logger.info(
          "Creating snapshot {snapname} of VM {vmName} on {node}",
          { snapname, vmName, node },
        );
        const logs = [];
        const log = (msg) => logs.push(msg);

        const auth = await resolveAuth(context.globalArgs, context, authOpts());
        const { ticket, csrfToken } = auth;
        const authHeaders = {
          "Cookie": `PVEAuthCookie=${ticket}`,
          "CSRFPreventionToken": csrfToken,
        };

        const vm = await resolveVmId(
          apiUrl,
          node,
          vmName,
          ticket,
          csrfToken,
          skipTlsVerify,
        );
        log(`Found VM "${vmName}" → vmid ${vm.vmid}`);

        const body = new URLSearchParams({ snapname });
        if (description) body.set("description", description);

        log(`Creating snapshot "${snapname}"`);
        const response = await fetchWithCurl(
          `${apiUrl}/api2/json/nodes/${node}/qemu/${vm.vmid}/snapshot`,
          {
            method: "POST",
            headers: {
              ...authHeaders,
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: body.toString(),
            skipTlsVerify,
          },
        );
        if (!response.ok) {
          throw new Error(
            `Failed to create snapshot: ${response.status} ${await response
              .text()}`,
          );
        }

        const upid = (await response.json()).data;
        const taskResult = await waitForTask(
          apiUrl,
          node,
          upid,
          ticket,
          csrfToken,
          skipTlsVerify,
        );
        if (!taskResult.success) {
          throw new Error(`Snapshot creation failed: ${taskResult.exitstatus}`);
        }
        log(`Snapshot "${snapname}" created (${taskResult.pollCount} polls)`);
        context.logger.info(
          "Created snapshot {snapname} of VM {vmName} (vmid {vmid})",
          { snapname, vmName, vmid: vm.vmid },
        );

        const handle = await context.writeResource("vm", `${vmName}-ops`, {
          vmid: vm.vmid,
          vmName,
          success: true,
          logs: logs.join("\n"),
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    deleteSnapshot: {
      description: "Delete a Proxmox VM snapshot",
      arguments: z.object({
        vmName: z.string().describe("VM name"),
        snapname: z.string().describe("Snapshot name to delete"),
      }),
      execute: async (args, context) => {
        const { apiUrl, node, skipTlsVerify } = context.globalArgs;
        const { vmName, snapname } = args;
        context.logger.info(
          "Deleting snapshot {snapname} of VM {vmName} on {node}",
          { snapname, vmName, node },
        );
        const logs = [];
        const log = (msg) => logs.push(msg);

        const auth = await resolveAuth(context.globalArgs, context, authOpts());
        const { ticket, csrfToken } = auth;
        const authHeaders = {
          "Cookie": `PVEAuthCookie=${ticket}`,
          "CSRFPreventionToken": csrfToken,
        };

        const vm = await resolveVmId(
          apiUrl,
          node,
          vmName,
          ticket,
          csrfToken,
          skipTlsVerify,
        );
        log(`Found VM "${vmName}" → vmid ${vm.vmid}`);

        log(`Deleting snapshot "${snapname}"`);
        const response = await fetchWithCurl(
          `${apiUrl}/api2/json/nodes/${node}/qemu/${vm.vmid}/snapshot/${
            encodeURIComponent(snapname)
          }`,
          {
            method: "DELETE",
            headers: authHeaders,
            skipTlsVerify,
          },
        );
        if (!response.ok) {
          throw new Error(
            `Failed to delete snapshot: ${response.status} ${await response
              .text()}`,
          );
        }

        const upid = (await response.json()).data;
        const taskResult = await waitForTask(
          apiUrl,
          node,
          upid,
          ticket,
          csrfToken,
          skipTlsVerify,
        );
        if (!taskResult.success) {
          throw new Error(`Snapshot deletion failed: ${taskResult.exitstatus}`);
        }
        log(`Snapshot "${snapname}" deleted (${taskResult.pollCount} polls)`);
        context.logger.info(
          "Deleted snapshot {snapname} of VM {vmName} (vmid {vmid})",
          { snapname, vmName, vmid: vm.vmid },
        );

        const handle = await context.writeResource("vm", `${vmName}-ops`, {
          vmid: vm.vmid,
          vmName,
          success: true,
          logs: logs.join("\n"),
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    moveDisk: {
      description:
        "Move a VM's disk to a different storage backend (VM should be stopped first for safety)",
      arguments: z.object({
        vmName: z.string().describe("VM name"),
        disk: z.string().default("virtio0").describe(
          "Disk identifier to move (e.g. virtio0, scsi0)",
        ),
        targetStorage: z.string().describe("Destination storage pool name"),
        deleteSource: z.boolean().default(true).describe(
          "Delete the source disk after a successful move",
        ),
      }),
      execute: async (args, context) => {
        const { apiUrl, node, skipTlsVerify } = context.globalArgs;
        const { vmName, disk, targetStorage, deleteSource } = args;
        context.logger.info(
          "Moving disk {disk} of VM {vmName} to storage {targetStorage}",
          { disk, vmName, targetStorage },
        );
        const logs = [];
        const log = (msg) => logs.push(msg);

        const auth = await resolveAuth(context.globalArgs, context, authOpts());
        const { ticket, csrfToken } = auth;
        const authHeaders = {
          "Cookie": `PVEAuthCookie=${ticket}`,
          "CSRFPreventionToken": csrfToken,
        };

        const vm = await resolveVmId(
          apiUrl,
          node,
          vmName,
          ticket,
          csrfToken,
          skipTlsVerify,
        );
        log(`Found VM "${vmName}" → vmid ${vm.vmid} [${vm.status}]`);
        if (vm.status === "running") {
          log(
            `Warning: VM is running — moving disk live. Stop it first for a safer migration.`,
          );
        }

        const body = new URLSearchParams({
          disk,
          storage: targetStorage,
          delete: deleteSource ? "1" : "0",
        });

        log(`Moving disk "${disk}" to storage "${targetStorage}"`);
        const response = await fetchWithCurl(
          `${apiUrl}/api2/json/nodes/${node}/qemu/${vm.vmid}/move_disk`,
          {
            method: "POST",
            headers: {
              ...authHeaders,
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: body.toString(),
            skipTlsVerify,
          },
        );
        if (!response.ok) {
          throw new Error(
            `Failed to move disk: ${response.status} ${await response.text()}`,
          );
        }

        const upid = (await response.json()).data;
        const taskResult = await waitForTask(
          apiUrl,
          node,
          upid,
          ticket,
          csrfToken,
          skipTlsVerify,
        );
        if (!taskResult.success) {
          throw new Error(`Disk move failed: ${taskResult.exitstatus}`);
        }
        log(
          `Disk "${disk}" moved to "${targetStorage}" (${taskResult.pollCount} polls)`,
        );
        context.logger.info(
          "Moved disk {disk} of VM {vmName} (vmid {vmid}) to storage {targetStorage}",
          { disk, vmName, vmid: vm.vmid, targetStorage },
        );

        const handle = await context.writeResource("vm", `${vmName}-ops`, {
          vmid: vm.vmid,
          vmName,
          success: true,
          logs: logs.join("\n"),
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    listSnapshots: {
      description: "List snapshots for a Proxmox VM",
      arguments: z.object({
        vmName: z.string().describe("VM name"),
      }),
      execute: async (args, context) => {
        const { apiUrl, node, skipTlsVerify } = context.globalArgs;
        const { vmName } = args;
        context.logger.info("Listing snapshots of VM {vmName} on {node}", {
          vmName,
          node,
        });

        const auth = await resolveAuth(context.globalArgs, context, authOpts());
        const { ticket, csrfToken } = auth;

        const vm = await resolveVmId(
          apiUrl,
          node,
          vmName,
          ticket,
          csrfToken,
          skipTlsVerify,
        );

        const response = await fetchWithCurl(
          `${apiUrl}/api2/json/nodes/${node}/qemu/${vm.vmid}/snapshot`,
          {
            method: "GET",
            headers: {
              "Cookie": `PVEAuthCookie=${ticket}`,
              "CSRFPreventionToken": csrfToken,
            },
            skipTlsVerify,
          },
        );
        if (!response.ok) {
          throw new Error(
            `Failed to list snapshots: ${response.status} ${await response
              .text()}`,
          );
        }
        const snapshots = (await response.json()).data;
        const names = snapshots.map((s) => s.name).filter((n) =>
          n !== "current"
        );

        const handle = await context.writeResource("vm", `${vmName}-ops`, {
          vmid: vm.vmid,
          vmName,
          success: true,
          logs: `Snapshots: ${names.join(", ") || "(none)"}`,
          timestamp: new Date().toISOString(),
        });
        context.logger.info("Listed {count} snapshots of VM {vmName}", {
          count: names.length,
          vmName,
        });
        return { dataHandles: [handle] };
      },
    },

    lxcStop: {
      description: "Stop a Proxmox LXC container",
      arguments: z.object({
        ctName: z.string().describe("LXC container name"),
      }),
      execute: async (args, context) => {
        const { apiUrl, node, skipTlsVerify } = context.globalArgs;
        const { ctName } = args;
        context.logger.info("Stopping LXC {ctName} on {node}", {
          ctName,
          node,
        });
        const logs = [];
        const log = (msg) => logs.push(msg);

        const auth = await resolveAuth(context.globalArgs, context, authOpts());
        const { ticket, csrfToken } = auth;
        const authHeaders = {
          "Cookie": `PVEAuthCookie=${ticket}`,
          "CSRFPreventionToken": csrfToken,
        };

        const ct = await resolveLxcId(
          apiUrl,
          node,
          ctName,
          ticket,
          csrfToken,
          skipTlsVerify,
        );
        log(`Found LXC "${ctName}" → vmid ${ct.vmid} [${ct.status}]`);

        if (ct.status === "stopped") {
          log(`Already stopped`);
        } else {
          const response = await fetchWithCurl(
            `${apiUrl}/api2/json/nodes/${node}/lxc/${ct.vmid}/status/stop`,
            {
              method: "POST",
              headers: authHeaders,
              skipTlsVerify,
            },
          );
          if (!response.ok) {
            throw new Error(
              `Failed to stop LXC: ${response.status} ${await response.text()}`,
            );
          }
          const upid = (await response.json()).data;
          const taskResult = await waitForTask(
            apiUrl,
            node,
            upid,
            ticket,
            csrfToken,
            skipTlsVerify,
          );
          if (!taskResult.success) {
            throw new Error(`LXC stop failed: ${taskResult.exitstatus}`);
          }
          log(`LXC ${ct.vmid} stopped (${taskResult.pollCount} polls)`);
        }
        context.logger.info("LXC {ctName} (vmid {vmid}) is stopped", {
          ctName,
          vmid: ct.vmid,
        });

        const handle = await context.writeResource("vm", `${ctName}-ops`, {
          vmid: ct.vmid,
          vmName: ctName,
          success: true,
          logs: logs.join("\n"),
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    lxcStart: {
      description: "Start a Proxmox LXC container",
      arguments: z.object({
        ctName: z.string().describe("LXC container name"),
      }),
      execute: async (args, context) => {
        const { apiUrl, node, skipTlsVerify } = context.globalArgs;
        const { ctName } = args;
        context.logger.info("Starting LXC {ctName} on {node}", {
          ctName,
          node,
        });
        const logs = [];
        const log = (msg) => logs.push(msg);

        const auth = await resolveAuth(context.globalArgs, context, authOpts());
        const { ticket, csrfToken } = auth;
        const authHeaders = {
          "Cookie": `PVEAuthCookie=${ticket}`,
          "CSRFPreventionToken": csrfToken,
        };

        const ct = await resolveLxcId(
          apiUrl,
          node,
          ctName,
          ticket,
          csrfToken,
          skipTlsVerify,
        );
        log(`Found LXC "${ctName}" → vmid ${ct.vmid} [${ct.status}]`);

        if (ct.status === "running") {
          log(`Already running`);
        } else {
          const response = await fetchWithCurl(
            `${apiUrl}/api2/json/nodes/${node}/lxc/${ct.vmid}/status/start`,
            {
              method: "POST",
              headers: authHeaders,
              skipTlsVerify,
            },
          );
          if (!response.ok) {
            throw new Error(
              `Failed to start LXC: ${response.status} ${await response
                .text()}`,
            );
          }
          const upid = (await response.json()).data;
          const taskResult = await waitForTask(
            apiUrl,
            node,
            upid,
            ticket,
            csrfToken,
            skipTlsVerify,
          );
          if (!taskResult.success) {
            throw new Error(`LXC start failed: ${taskResult.exitstatus}`);
          }
          log(`LXC ${ct.vmid} started (${taskResult.pollCount} polls)`);
        }
        context.logger.info("LXC {ctName} (vmid {vmid}) is running", {
          ctName,
          vmid: ct.vmid,
        });

        const handle = await context.writeResource("vm", `${ctName}-ops`, {
          vmid: ct.vmid,
          vmName: ctName,
          success: true,
          logs: logs.join("\n"),
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    lxcMoveVolume: {
      description:
        "Move an LXC container's volume (rootfs or mount point) to a different storage backend",
      arguments: z.object({
        ctName: z.string().describe("LXC container name"),
        volume: z.string().default("rootfs").describe(
          "Volume identifier (e.g. rootfs, mp0)",
        ),
        targetStorage: z.string().describe("Destination storage pool name"),
        deleteSource: z.boolean().default(true).describe(
          "Delete the source volume after a successful move",
        ),
      }),
      execute: async (args, context) => {
        const { apiUrl, node, skipTlsVerify } = context.globalArgs;
        const { ctName, volume, targetStorage, deleteSource } = args;
        context.logger.info(
          "Moving volume {volume} of LXC {ctName} to storage {targetStorage}",
          { volume, ctName, targetStorage },
        );
        const logs = [];
        const log = (msg) => logs.push(msg);

        const auth = await resolveAuth(context.globalArgs, context, authOpts());
        const { ticket, csrfToken } = auth;
        const authHeaders = {
          "Cookie": `PVEAuthCookie=${ticket}`,
          "CSRFPreventionToken": csrfToken,
        };

        const ct = await resolveLxcId(
          apiUrl,
          node,
          ctName,
          ticket,
          csrfToken,
          skipTlsVerify,
        );
        log(`Found LXC "${ctName}" → vmid ${ct.vmid} [${ct.status}]`);
        if (ct.status === "running") {
          log(
            `Warning: LXC is running — moving volume live. Stop it first for a safer migration.`,
          );
        }

        const body = new URLSearchParams({
          volume,
          storage: targetStorage,
          delete: deleteSource ? "1" : "0",
        });

        log(`Moving volume "${volume}" to storage "${targetStorage}"`);
        const response = await fetchWithCurl(
          `${apiUrl}/api2/json/nodes/${node}/lxc/${ct.vmid}/move_volume`,
          {
            method: "POST",
            headers: {
              ...authHeaders,
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: body.toString(),
            skipTlsVerify,
          },
        );
        if (!response.ok) {
          throw new Error(
            `Failed to move volume: ${response.status} ${await response
              .text()}`,
          );
        }

        const upid = (await response.json()).data;
        const taskResult = await waitForTask(
          apiUrl,
          node,
          upid,
          ticket,
          csrfToken,
          skipTlsVerify,
        );
        if (!taskResult.success) {
          throw new Error(`Volume move failed: ${taskResult.exitstatus}`);
        }
        log(
          `Volume "${volume}" moved to "${targetStorage}" (${taskResult.pollCount} polls)`,
        );
        context.logger.info(
          "Moved volume {volume} of LXC {ctName} (vmid {vmid}) to storage {targetStorage}",
          { volume, ctName, vmid: ct.vmid, targetStorage },
        );

        const handle = await context.writeResource("vm", `${ctName}-ops`, {
          vmid: ct.vmid,
          vmName: ctName,
          success: true,
          logs: logs.join("\n"),
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    getConfig: {
      description: "Read the raw config for a Proxmox VM or LXC container",
      arguments: z.object({
        vmName: z.string().describe("VM or LXC name"),
        kind: z.enum(["qemu", "lxc"]).default("qemu").describe(
          "Whether vmName is a QEMU VM or an LXC container",
        ),
      }),
      execute: async (args, context) => {
        const { apiUrl, node, skipTlsVerify } = context.globalArgs;
        const { vmName, kind } = args;
        context.logger.info("Reading {kind} config of {vmName} on {node}", {
          kind,
          vmName,
          node,
        });

        const auth = await resolveAuth(context.globalArgs, context, authOpts());
        const { ticket, csrfToken } = auth;

        const entity = kind === "lxc"
          ? await resolveLxcId(
            apiUrl,
            node,
            vmName,
            ticket,
            csrfToken,
            skipTlsVerify,
          )
          : await resolveVmId(
            apiUrl,
            node,
            vmName,
            ticket,
            csrfToken,
            skipTlsVerify,
          );

        const response = await fetchWithCurl(
          `${apiUrl}/api2/json/nodes/${node}/${kind}/${entity.vmid}/config`,
          {
            method: "GET",
            headers: {
              "Cookie": `PVEAuthCookie=${ticket}`,
              "CSRFPreventionToken": csrfToken,
            },
            skipTlsVerify,
          },
        );
        if (!response.ok) {
          throw new Error(
            `Failed to get config: ${response.status} ${await response.text()}`,
          );
        }
        const config = (await response.json()).data;

        const handle = await context.writeResource("vm", `${vmName}-ops`, {
          vmid: entity.vmid,
          vmName,
          success: true,
          logs: JSON.stringify(config, null, 2),
          timestamp: new Date().toISOString(),
        });
        context.logger.info(
          "Read {kind} config of {vmName} (vmid {vmid}): {keyCount} keys",
          {
            kind,
            vmName,
            vmid: entity.vmid,
            keyCount: Object.keys(config ?? {}).length,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    migrate: {
      description:
        "Live-migrate a VM to another Proxmox node. Requires shared storage (NFS/Ceph) — disk is not copied, only VM state is transferred.",
      arguments: z.object({
        vmName: z.string().describe("VM name to migrate"),
        target: z.string().describe(
          "Destination node name (e.g. pve2)",
        ),
        sourceNode: z.string().optional().describe(
          "Source node name — overrides the model's globalArguments node. Use when the VM has already been migrated away from the default node.",
        ),
        online: z.boolean().default(true).describe(
          "Live migration — VM keeps running during transfer",
        ),
      }),
      execute: async (args, context) => {
        const { apiUrl, node: defaultNode, skipTlsVerify } = context.globalArgs;
        const { vmName, target, sourceNode, online } = args;
        const node = sourceNode ?? defaultNode;
        const logs: string[] = [];
        const log = (msg: string) => logs.push(msg);
        context.logger.info(
          "Migrating VM {vmName} from {sourceNode} to {target} (online={online})",
          { vmName, sourceNode: node, target, online },
        );

        const auth = await resolveAuth(context.globalArgs, context, authOpts());
        const { ticket, csrfToken } = auth;
        const authHeaders = {
          "Cookie": `PVEAuthCookie=${ticket}`,
          "CSRFPreventionToken": csrfToken,
        };

        const vm = await resolveVmId(
          apiUrl,
          node,
          vmName,
          ticket,
          csrfToken,
          skipTlsVerify,
        );
        log(`Found VM "${vmName}" → vmid ${vm.vmid} [${vm.status}] on ${node}`);

        if (online && vm.status !== "running") {
          log(`Warning: VM is not running — falling back to offline migration`);
        }

        const body = new URLSearchParams({
          target,
          online: online && vm.status === "running" ? "1" : "0",
        });

        log(
          `Migrating vmid ${vm.vmid} from ${node} → ${target} (online=${
            body.get("online")
          })`,
        );
        const response = await fetchWithCurl(
          `${apiUrl}/api2/json/nodes/${node}/qemu/${vm.vmid}/migrate`,
          {
            method: "POST",
            headers: {
              ...authHeaders,
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: body.toString(),
            skipTlsVerify,
          },
        );
        if (!response.ok) {
          throw new Error(
            `Migration failed to start: ${response.status} ${await response
              .text()}`,
          );
        }

        const upid = (await response.json()).data;
        log(`Migration task started: ${upid}`);

        const taskResult = await waitForTask(
          apiUrl,
          node,
          upid,
          ticket,
          csrfToken,
          skipTlsVerify,
        );
        if (!taskResult.success) {
          throw new Error(`Migration failed: ${taskResult.exitstatus}`);
        }
        log(
          `Migration complete (${taskResult.pollCount} polls) — VM is now on ${target}`,
        );

        const handle = await context.writeResource("vm", `${vmName}-ops`, {
          vmid: vm.vmid,
          vmName,
          sourceNode: node,
          targetNode: target,
          success: true,
          logs: logs.join("\n"),
          timestamp: new Date().toISOString(),
        });
        context.logger.info(
          "Migrated VM {vmName} (vmid {vmid}) from {sourceNode} to {target}",
          { vmName, vmid: vm.vmid, sourceNode: node, target },
        );
        return { dataHandles: [handle] };
      },
    },
  }],
};
