/**
 * `@dmc/proxmox/vm` — QEMU VM (and LXC) lifecycle against the Proxmox VE API
 * with API-token auth: lookup, create, start, stop, delete, boot order,
 * config, fleet sync, plus every `proxmox_vm_extras.ts` method
 * (createFromImage, snapshots, disk/node migration, LXC control).
 *
 * Replaces `@keeb/proxmox/vm`. The base methods are adapted from
 * @keeb/proxmox (MIT, Copyright (c) 2026 keeb; full notice in
 * `lib/proxmox.ts`); `spiceConnect` is not carried over.
 *
 * @module
 */
import { z } from "npm:zod@4";
import {
  createMethodLogger,
  getVmIpWithRetry,
  nodePath,
  ProxmoxConnectionArgs,
  pveCall,
  resolveAuth,
  validateConnection,
  waitForTask,
} from "./lib/proxmox.ts";
import { vmExtraChecks, vmExtraMethods } from "./proxmox_vm_extras.ts";

type VmGlobalArgs = z.infer<typeof ProxmoxConnectionArgs>;
type PveAuth = Awaited<ReturnType<typeof resolveAuth>>;

/** The part of swamp's method context these methods use. */
interface Ctx {
  globalArgs: VmGlobalArgs;
  logger?: unknown;
  writeResource: (
    spec: string,
    name: string,
    data: unknown,
  ) => Promise<{ name: string }>;
  readResource?: (name: string) => Promise<Record<string, unknown> | null>;
}

const VmNameArg = z.string().describe("VM name to manage");

const LookupArgs = z.object({ vmName: VmNameArg });

const StartArgs = z.object({
  vmName: VmNameArg,
  waitSeconds: z.number().min(0).default(120).describe(
    "Max seconds to wait for VM IP",
  ),
  pollInterval: z.number().positive().default(5).describe(
    "Seconds between IP poll attempts",
  ),
  requireIp: z.boolean().default(true).describe(
    "Fail if the guest agent does not report an IP. Set false for VMs with no agent (e.g. booting an installer ISO).",
  ),
});

const StopArgs = z.object({ vmName: VmNameArg });

const DeleteArgs = z.object({ vmName: VmNameArg });

const CreateArgs = z.object({
  vmName: VmNameArg,
  memory: z.number().positive().optional().describe(
    "Memory in MB (default 2048)",
  ),
  cores: z.number().positive().optional().describe("CPU cores (default 2)"),
  sockets: z.number().positive().optional().describe(
    "CPU sockets (default 1)",
  ),
  diskSize: z.number().min(0).optional().describe(
    "Disk size in GB (default 32, 0 for PXE-only)",
  ),
  diskStorage: z.string().optional().describe(
    "Storage pool (default 'local-lvm')",
  ),
  networkBridge: z.string().optional().describe(
    "Network bridge (default 'vmbr0')",
  ),
  osType: z.string().optional().describe("OS type (default 'l26')"),
});

const SetBootOrderArgs = z.object({
  vmName: VmNameArg,
  boot: z.string().describe("Boot order string (e.g. 'order=scsi0;net0')"),
});

const SetConfigArgs = z.object({
  vmName: VmNameArg,
  config: z.record(z.string(), z.string()).describe(
    "Arbitrary VM config key/values for setConfig method",
  ),
});

/** Same shape as `@keeb/proxmox/vm`'s `vm` resource, so the extras write it unchanged. */
const VmDataSchema = z.object({
  vmid: z.number(),
  vmName: z.string(),
  status: z.string().optional(),
  ip: z.string().nullable().optional(),
  maxmem: z.number().optional().describe("Allocated memory in bytes"),
  maxcpu: z.number().optional().describe("Allocated CPU count"),
  success: z.boolean().optional(),
  wasStarted: z.boolean().optional(),
  boot: z.string().optional(),
  config: z.record(z.string(), z.string()).optional(),
  logs: z.string().optional(),
  timestamp: z.string(),
});

/** One entry from GET /nodes/{node}/qemu. */
export interface PveVm {
  vmid: number;
  name?: string;
  status?: string;
  maxmem?: number;
  maxcpu?: number;
}

/** Validate and normalise the /qemu list payload. */
export function parseVmList(data: unknown): PveVm[] {
  if (!Array.isArray(data)) {
    throw new Error("Unexpected VM list response from Proxmox (not an array)");
  }
  return data
    .filter((v) => v && v.vmid !== undefined)
    .map((v) => ({ ...v, vmid: Number(v.vmid) }))
    .filter((v) => Number.isInteger(v.vmid));
}

/** Find a VM by name, or throw listing every available name. */
export function findVm(vms: PveVm[], vmName: string): PveVm {
  const vm = vms.find((v) => v.name === vmName);
  if (!vm) {
    const names = vms.map((v) => v.name).filter(Boolean).join(", ");
    throw new Error(`VM "${vmName}" not found. Available: ${names}`);
  }
  return vm;
}

/** Build the POST /qemu form for `create`, applying defaults. */
export function buildCreateParams(
  vmid: number,
  args: z.infer<typeof CreateArgs>,
): URLSearchParams {
  const hasDisk = args.diskSize !== 0;
  const params = new URLSearchParams({
    vmid: String(vmid),
    name: args.vmName,
    memory: String(args.memory ?? 2048),
    cores: String(args.cores ?? 2),
    sockets: String(args.sockets ?? 1),
    ostype: args.osType ?? "l26",
    agent: "1",
    boot: hasDisk ? "order=net0;scsi0" : "order=net0",
    net0: `virtio,bridge=${args.networkBridge ?? "vmbr0"}`,
    scsihw: "virtio-scsi-single",
    smbios1: `base64=1,serial=${
      btoa(String.fromCharCode(...new TextEncoder().encode(args.vmName)))
    }`,
  });
  if (hasDisk) {
    params.set(
      "scsi0",
      `${args.diskStorage ?? "local-lvm"}:${args.diskSize ?? 32},format=raw`,
    );
  }
  return params;
}

function vmAuth(g: VmGlobalArgs, context: Ctx): Promise<PveAuth> {
  return resolveAuth(g, context, { skipCache: true });
}

async function listVms(g: VmGlobalArgs, auth: PveAuth): Promise<PveVm[]> {
  return parseVmList(
    await pveCall(
      g,
      auth,
      "GET",
      nodePath(g, "/qemu"),
      `Listing VMs on node ${g.node}`,
    ),
  );
}

async function resolveVm(
  g: VmGlobalArgs,
  auth: PveAuth,
  vmName: string,
): Promise<PveVm> {
  return findVm(await listVms(g, auth), vmName);
}

function runTask(g: VmGlobalArgs, auth: PveAuth, upid: unknown) {
  return waitForTask(g.apiUrl, g.node, upid, auth, g.skipTlsVerify ?? true);
}

/** Swamp model definition for `@dmc/proxmox/vm`. */
export const model = {
  type: "@dmc/proxmox/vm",
  version: "2026.10.26.1",
  globalArguments: ProxmoxConnectionArgs,
  resources: {
    vm: {
      description: "VM operation result",
      schema: VmDataSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  checks: {
    "valid-connection": {
      description:
        "apiUrl is an http(s) URL without credentials and node is set",
      labels: ["policy"],
      execute: (context: { globalArgs: VmGlobalArgs }) =>
        Promise.resolve(validateConnection(context.globalArgs)),
    },
    ...vmExtraChecks,
  },
  methods: {
    lookup: {
      description:
        "Look up VM by name, return vmid and IP if running. Needs: VM.Audit; VM.GuestAgent.Audit for the IP.",
      arguments: LookupArgs,
      execute: async (args: z.infer<typeof LookupArgs>, context: Ctx) => {
        const { vmName } = args;
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Looking up VM {vmName} on node {node}", {
          vmName,
          node: g.node,
        });

        const auth = await vmAuth(g, context);
        const vm = await resolveVm(g, auth, vmName);
        log.info("Found VM {vmName}: vmid {vmid} [{status}]", {
          vmName,
          vmid: vm.vmid,
          status: vm.status,
        });

        let ip: string | null = null;
        if (vm.status === "running") {
          log.info("VM is running, fetching IP from guest agent", {});
          ip = await getVmIpWithRetry(g, auth, vm.vmid, 15, 3);
          if (ip) log.info("Got IP {ip}", { ip });
          else log.warn("Could not get IP from guest agent", {});
        }

        const handle = await context.writeResource("vm", vmName, {
          vmid: vm.vmid,
          vmName,
          status: vm.status,
          ip,
          logs: log.text(),
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    start: {
      description:
        "Start VM if stopped (idempotent), wait for IP. Needs: VM.PowerMgmt, VM.Audit; VM.GuestAgent.Audit for the IP.",
      arguments: StartArgs,
      execute: async (args: z.infer<typeof StartArgs>, context: Ctx) => {
        const {
          vmName,
          waitSeconds = 120,
          pollInterval = 5,
          requireIp = true,
        } = args;
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Ensuring VM {vmName} is running on node {node}", {
          vmName,
          node: g.node,
        });

        const auth = await vmAuth(g, context);
        const vm = await resolveVm(g, auth, vmName);
        log.info("Found VM {vmName}: vmid {vmid} [{status}]", {
          vmName,
          vmid: vm.vmid,
          status: vm.status,
        });

        let wasStarted = false;
        if (vm.status === "stopped") {
          log.info("VM is stopped, starting", {});
          const upid = await pveCall(
            g,
            auth,
            "POST",
            nodePath(g, `/qemu/${vm.vmid}/status/start`),
            `Starting VM "${vmName}" (vmid ${vm.vmid})`,
          );
          const taskResult = await runTask(g, auth, upid);
          if (!taskResult.success) {
            throw new Error(
              `VM "${vmName}" (vmid ${vm.vmid}) start failed: ${taskResult.exitstatus}`,
            );
          }
          wasStarted = true;
          log.info("VM {vmid} started ({polls} polls)", {
            vmid: vm.vmid,
            polls: taskResult.pollCount,
          });
        } else {
          log.info("VM is already {status}", { status: vm.status });
        }

        log.info("Waiting for guest agent IP (up to {waitSeconds}s)", {
          waitSeconds,
        });
        const ip = await getVmIpWithRetry(
          g,
          auth,
          vm.vmid,
          waitSeconds,
          pollInterval,
        );
        if (ip) {
          log.info("Got IP {ip}", { ip });
        } else if (requireIp) {
          throw new Error(
            `VM "${vmName}" (vmid ${vm.vmid}) is running but guest agent did not return an IP within ${waitSeconds}s. Is qemu-guest-agent installed and agent enabled in VM config?`,
          );
        } else {
          log.warn(
            "No guest agent IP after {waitSeconds}s, continuing (requireIp=false)",
            { waitSeconds },
          );
        }

        const handle = await context.writeResource("vm", vmName, {
          vmid: vm.vmid,
          vmName,
          status: "running",
          ip,
          wasStarted,
          logs: log.text(),
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    stop: {
      description: "Stop a VM by name. Needs: VM.PowerMgmt, VM.Audit.",
      arguments: StopArgs,
      execute: async (args: z.infer<typeof StopArgs>, context: Ctx) => {
        const { vmName } = args;
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Stopping VM {vmName} on node {node}", {
          vmName,
          node: g.node,
        });

        const auth = await vmAuth(g, context);
        const vm = await resolveVm(g, auth, vmName);
        log.info("Found VM {vmName}: vmid {vmid} [{status}]", {
          vmName,
          vmid: vm.vmid,
          status: vm.status,
        });

        if (vm.status !== "stopped") {
          const upid = await pveCall(
            g,
            auth,
            "POST",
            nodePath(g, `/qemu/${vm.vmid}/status/stop`),
            `Stopping VM "${vmName}" (vmid ${vm.vmid})`,
          );
          log.info("Stop task initiated, waiting for completion", {});
          const taskResult = await runTask(g, auth, upid);
          if (!taskResult.success) {
            throw new Error(
              `VM "${vmName}" (vmid ${vm.vmid}) stop failed: ${taskResult.exitstatus}`,
            );
          }
          log.info("VM {vmid} stopped ({polls} polls)", {
            vmid: vm.vmid,
            polls: taskResult.pollCount,
          });
        } else {
          log.info("VM is already stopped", {});
        }

        const handle = await context.writeResource("vm", vmName, {
          vmid: vm.vmid,
          vmName,
          status: "stopped",
          ip: null,
          success: true,
          logs: log.text(),
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    create: {
      description:
        "Create a new VM with PXE boot enabled, auto-allocating vmid (no-op if a VM with that name exists). Needs: VM.Allocate, Datastore.AllocateSpace on the disk storage, SDN.Use on the bridge.",
      arguments: CreateArgs,
      execute: async (args: z.infer<typeof CreateArgs>, context: Ctx) => {
        const { vmName } = args;
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Creating VM {vmName} on node {node}", {
          vmName,
          node: g.node,
        });

        const auth = await vmAuth(g, context);

        // Idempotent: Proxmox allows duplicate names, so never create a
        // second VM with the same name.
        const existing = (await listVms(g, auth)).find((v) =>
          v.name === vmName
        );
        if (existing) {
          log.info("VM {vmName} already exists as vmid {vmid}, skipping", {
            vmName,
            vmid: existing.vmid,
          });
          const handle = await context.writeResource("vm", vmName, {
            vmid: existing.vmid,
            vmName,
            status: existing.status,
            success: true,
            logs: log.text(),
            timestamp: new Date().toISOString(),
          });
          return { dataHandles: [handle] };
        }

        const vmid = parseInt(
          String(
            await pveCall(
              g,
              auth,
              "GET",
              `${g.apiUrl}/api2/json/cluster/nextid`,
              "Fetching next available VM ID",
            ),
          ),
          10,
        );
        if (!Number.isInteger(vmid)) {
          throw new Error("Proxmox returned an invalid next VM ID");
        }
        log.info("Got next VM ID {vmid}", { vmid });

        const params = buildCreateParams(vmid, args);
        log.info("Specs: {memory}MB RAM, {cores} cores, disk {disk}", {
          memory: params.get("memory"),
          cores: params.get("cores"),
          disk: params.get("scsi0") ?? "none (PXE)",
        });

        const upid = await pveCall(
          g,
          auth,
          "POST",
          nodePath(g, "/qemu"),
          `Creating VM "${vmName}"`,
          params.toString(),
        );
        log.info("VM creation task started, waiting for completion", {});
        const taskResult = await runTask(g, auth, upid);
        if (!taskResult.success) {
          throw new Error(
            `VM "${vmName}" (vmid ${vmid}) creation failed: ${taskResult.exitstatus}`,
          );
        }
        log.info("VM {vmid} ({vmName}) created ({polls} polls)", {
          vmid,
          vmName,
          polls: taskResult.pollCount,
        });

        const handle = await context.writeResource("vm", vmName, {
          vmid,
          vmName,
          status: "stopped",
          ip: null,
          success: true,
          logs: log.text(),
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    delete: {
      description:
        "Stop (if running) and delete a VM by name (succeeds if already gone). Needs: VM.Allocate, VM.PowerMgmt, VM.Audit.",
      arguments: DeleteArgs,
      execute: async (args: z.infer<typeof DeleteArgs>, context: Ctx) => {
        const { vmName } = args;
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Deleting VM {vmName} on node {node}", {
          vmName,
          node: g.node,
        });

        const auth = await vmAuth(g, context);
        const vm = (await listVms(g, auth)).find((v) => v.name === vmName);

        if (!vm) {
          // Already gone: succeed, and mark stored data deleted if we have it.
          log.info("VM {vmName} not found, nothing to delete", { vmName });
          const prior = context.readResource
            ? await context.readResource(vmName)
            : null;
          if (prior && typeof prior.vmid === "number") {
            const handle = await context.writeResource("vm", vmName, {
              vmid: prior.vmid,
              vmName,
              status: "deleted",
              ip: null,
              success: true,
              logs: log.text(),
              timestamp: new Date().toISOString(),
            });
            return { dataHandles: [handle] };
          }
          return { dataHandles: [] };
        }
        log.info("Found VM {vmName}: vmid {vmid} [{status}]", {
          vmName,
          vmid: vm.vmid,
          status: vm.status,
        });

        if (vm.status !== "stopped") {
          log.info("VM is {status}, stopping first", { status: vm.status });
          const upid = await pveCall(
            g,
            auth,
            "POST",
            nodePath(g, `/qemu/${vm.vmid}/status/stop`),
            `Stopping VM "${vmName}" (vmid ${vm.vmid}) before delete`,
          );
          const stopResult = await runTask(g, auth, upid);
          log.info("VM {vmid} stop: {exitstatus}", {
            vmid: vm.vmid,
            exitstatus: stopResult.exitstatus,
          });
        }

        log.info("Sending delete command for VM {vmid}", { vmid: vm.vmid });
        const upid = await pveCall(
          g,
          auth,
          "DELETE",
          nodePath(g, `/qemu/${vm.vmid}`),
          `Deleting VM "${vmName}" (vmid ${vm.vmid})`,
        );
        const taskResult = await runTask(g, auth, upid);
        if (!taskResult.success) {
          throw new Error(
            `VM "${vmName}" (vmid ${vm.vmid}) deletion failed: ${taskResult.exitstatus}`,
          );
        }
        log.info("VM {vmid} deleted ({polls} polls)", {
          vmid: vm.vmid,
          polls: taskResult.pollCount,
        });

        const handle = await context.writeResource("vm", vmName, {
          vmid: vm.vmid,
          vmName,
          status: "deleted",
          ip: null,
          success: true,
          logs: log.text(),
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    setBootOrder: {
      description:
        "Set VM boot order via Proxmox API. Needs: VM.Config.Options, VM.Audit.",
      arguments: SetBootOrderArgs,
      execute: async (args: z.infer<typeof SetBootOrderArgs>, context: Ctx) => {
        const { vmName, boot } = args;
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Setting boot order for VM {vmName} to {boot}", {
          vmName,
          boot,
        });

        const auth = await vmAuth(g, context);
        const vm = await resolveVm(g, auth, vmName);

        await pveCall(
          g,
          auth,
          "PUT",
          nodePath(g, `/qemu/${vm.vmid}/config`),
          `Setting boot order for VM "${vmName}" (vmid ${vm.vmid})`,
          new URLSearchParams({ boot }).toString(),
        );
        log.info("Boot order updated for VM {vmid}: {boot}", {
          vmid: vm.vmid,
          boot,
        });

        const handle = await context.writeResource("vm", vmName, {
          vmid: vm.vmid,
          vmName,
          boot,
          success: true,
          logs: log.text(),
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    setConfig: {
      description:
        "Set arbitrary VM config options via Proxmox API (e.g. agent, memory, cores). Needs: the matching VM.Config.* privilege, VM.Audit.",
      arguments: SetConfigArgs,
      execute: async (args: z.infer<typeof SetConfigArgs>, context: Ctx) => {
        const { vmName, config } = args;
        const configParams = new URLSearchParams();
        for (const [key, value] of Object.entries(config ?? {})) {
          configParams.set(key, String(value));
        }
        if ([...configParams].length === 0) {
          throw new Error(
            "No config params provided. Pass config options via workflow step inputs, e.g. inputs: { config: { agent: '1' } }",
          );
        }

        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Setting config on VM {vmName}: {keys}", {
          vmName,
          keys: [...configParams.keys()].join(", "),
        });

        const auth = await vmAuth(g, context);
        const vm = await resolveVm(g, auth, vmName);

        await pveCall(
          g,
          auth,
          "PUT",
          nodePath(g, `/qemu/${vm.vmid}/config`),
          `Setting config for VM "${vmName}" (vmid ${vm.vmid})`,
          configParams.toString(),
        );
        log.info("Config updated for VM {vmid}", { vmid: vm.vmid });

        const handle = await context.writeResource("vm", vmName, {
          vmid: vm.vmid,
          vmName,
          config: Object.fromEntries(configParams),
          success: true,
          logs: log.text(),
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    sync: {
      description:
        "Sync all VMs from Proxmox — writes a named resource per VM. Needs: VM.Audit (only audited VMs are listed); VM.GuestAgent.Audit for IPs.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Syncing all VMs from node {node}", { node: g.node });

        const auth = await vmAuth(g, context);
        const vms = await listVms(g, auth);
        log.info("Found {count} VMs, resolving IPs for running VMs", {
          count: vms.length,
        });

        const handles = [];
        for (const rv of vms) {
          let ip: string | null = null;
          if (rv.status === "running") {
            ip = await getVmIpWithRetry(g, auth, rv.vmid, 5, 2);
          }
          const vmName = rv.name || `vm-${rv.vmid}`;
          log.info("{vmName} (vmid {vmid}) [{status}] ip={ip}", {
            vmName,
            vmid: rv.vmid,
            status: rv.status,
            ip: ip ?? "-",
          });
          const handle = await context.writeResource("vm", vmName, {
            vmid: rv.vmid,
            vmName,
            status: rv.status,
            ip,
            maxmem: rv.maxmem,
            maxcpu: rv.maxcpu,
            logs: log.text(),
            timestamp: new Date().toISOString(),
          });
          handles.push(handle);
        }

        log.info("Complete: {count} VMs synced", { count: handles.length });
        return { dataHandles: handles };
      },
    },

    ...vmExtraMethods,
  },
};
