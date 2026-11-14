/**
 * `@dmc/proxmox/vm` — QEMU VM (and LXC) lifecycle against the Proxmox VE API
 * with API-token auth: lookup, create, clone, convertToTemplate, start, stop,
 * delete, boot order, config, fleet sync, plus every `proxmox_vm_extras.ts` method
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
  dropRemovedAuthArgs,
  getVmIpWithRetry,
  nodePath,
  ProxmoxConnectionArgs,
  pveCall,
  resolveAuth,
  tlsOptions,
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

const ShutdownArgs = z.object({
  vmName: VmNameArg,
  timeoutSeconds: z.number().int().min(10).max(3600).default(300).describe(
    "Seconds Proxmox waits for the guest to power off. When it is still running after that, the method fails; it never forces a stop (stop does that)",
  ),
});

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

/** A Proxmox VM name: a DNS name. */
const VM_DNS_NAME_RE = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,61}[A-Za-z0-9])?$/;

/** Pool name: no `/`, so no nested pools. */
const POOL_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$/;

/** Proxmox storage id. */
const STORAGE_ID_RE = /^[A-Za-z][A-Za-z0-9._-]{0,98}[A-Za-z0-9]$/;

const CloneArgs = z.object({
  source: z.string().describe("Name of the VM or template to clone"),
  vmName: z.string()
    .regex(VM_DNS_NAME_RE, "vmName must be a DNS name (letters, digits, . -)")
    .describe("Name of the new VM"),
  newid: z.number().int().min(100).optional().describe(
    "VM id of the new VM (default: the next free id)",
  ),
  pool: z.string()
    .regex(POOL_NAME_RE, "pool must be one pool name")
    .optional()
    .describe("Pool to put the new VM in"),
  linked: z.boolean().default(true).describe(
    "Linked clone (default): the new disks are copy-on-write on the template's base disks; the source must be a template. False makes a full copy",
  ),
  storage: z.string()
    .regex(STORAGE_ID_RE, "storage must be a Proxmox storage id")
    .optional()
    .describe("Target storage of a full clone (default: the source's)"),
}).refine(
  (a) => !(a.linked && a.storage !== undefined),
  {
    message:
      "storage is only for a full clone: a linked clone stays on the template's storage",
    path: ["storage"],
  },
);

const ConvertToTemplateArgs = z.object({ vmName: VmNameArg });

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
  template: z.boolean().optional().describe("True when the VM is a template"),
  source: z.string().optional().describe(
    "The VM or template it was cloned from",
  ),
  pool: z.string().optional().describe("The pool a clone was put in"),
  linked: z.boolean().optional().describe("True for a linked clone"),
  durationMs: z.number().optional().describe(
    "How long the clone task took, from the request to the task end (1 s polls)",
  ),
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
  /** 1 for a template. */
  template?: number;
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

/**
 * Build the POST /qemu/{vmid}/status/shutdown form for `shutdown`. forceStop
 * is always 0: a guest that does not power off in time stays running, and the
 * task fails.
 */
export function buildShutdownParams(timeoutSeconds: number): URLSearchParams {
  return new URLSearchParams({
    timeout: String(timeoutSeconds),
    forceStop: "0",
  });
}

/** Build the POST /qemu/{vmid}/clone form for `clone`. */
export function buildCloneParams(
  newid: number,
  args: z.infer<typeof CloneArgs>,
): URLSearchParams {
  const params = new URLSearchParams({
    newid: String(newid),
    name: args.vmName,
    full: args.linked ? "0" : "1",
  });
  if (args.pool) params.set("pool", args.pool);
  if (args.storage) params.set("storage", args.storage);
  return params;
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

function vmAuth(g: VmGlobalArgs): Promise<PveAuth> {
  return resolveAuth(g);
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
  return waitForTask(g.apiUrl, g.node, upid, auth, tlsOptions(g));
}

/** Swamp model definition for `@dmc/proxmox/vm`. */
export const model = {
  type: "@dmc/proxmox/vm",
  version: "2026.11.14.1",
  globalArguments: ProxmoxConnectionArgs,
  upgrades: [
    {
      toVersion: "2026.10.26.1",
      description:
        "First release. Definitions moved from @keeb/proxmox/vm keep their attributes; set tokenId/tokenSecret for token auth",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.11.07.1",
      description:
        "Breaking: API tokens are the only auth. The upgrade drops the ticket, csrfToken, username, password and realm global args; a definition that used them needs tokenId and tokenSecret. The @keeb/proxmox/vm extension is removed: move those definitions to @dmc/proxmox/vm. Additive: optional caCert (verify a self-signed API certificate). Set skipTlsVerify false or caCert, so the token is not sent unverified",
      upgradeAttributes: dropRemovedAuthArgs,
    },
    {
      toVersion: "2026.11.13.1",
      description:
        "Additive: new methods clone (linked by default, optionally into a pool, records the clone time) and convertToTemplate. The vm resource gains optional template, source, pool, linked and durationMs fields. No argument changes",
      upgradeAttributes: dropRemovedAuthArgs,
    },
    {
      toVersion: "2026.11.14.1",
      description:
        "Additive: new method shutdown (a clean guest shutdown that waits until the VM is stopped and never forces a stop). No argument or resource changes",
      upgradeAttributes: dropRemovedAuthArgs,
    },
  ],
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

        const auth = await vmAuth(g);
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

        const auth = await vmAuth(g);
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

        const auth = await vmAuth(g);
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

        const auth = await vmAuth(g);

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

    shutdown: {
      description:
        "Shut a VM down cleanly (ACPI, or the guest agent when the VM has it on) and wait until it is stopped; no-op when it is stopped. Fails when the guest is still running after timeoutSeconds: it never forces a stop (stop does that). Needs: VM.PowerMgmt, VM.Audit.",
      arguments: ShutdownArgs,
      execute: async (args: z.infer<typeof ShutdownArgs>, context: Ctx) => {
        const { vmName, timeoutSeconds } = args;
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Shutting down VM {vmName} on node {node}", {
          vmName,
          node: g.node,
        });

        const auth = await vmAuth(g);
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
            nodePath(g, `/qemu/${vm.vmid}/status/shutdown`),
            `Shutting down VM "${vmName}" (vmid ${vm.vmid})`,
            buildShutdownParams(timeoutSeconds).toString(),
          );
          log.info("Shutdown task started; Proxmox waits up to {s}s", {
            s: timeoutSeconds,
          });
          // Proxmox ends the task at its own timeout; the margin covers the polls.
          const taskResult = await waitForTask(
            g.apiUrl,
            g.node,
            upid,
            auth,
            tlsOptions(g),
            timeoutSeconds + 60,
          );
          if (!taskResult.success) {
            throw new Error(
              `VM "${vmName}" (vmid ${vm.vmid}) did not shut down within ${timeoutSeconds}s: ${taskResult.exitstatus}`,
            );
          }
          const after = await resolveVm(g, auth, vmName);
          if (after.status !== "stopped") {
            throw new Error(
              `VM "${vmName}" (vmid ${vm.vmid}) is ${after.status} after the shutdown task`,
            );
          }
          log.info("VM {vmid} is stopped ({polls} polls)", {
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

        const auth = await vmAuth(g);
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

    clone: {
      description:
        "Clone a VM or template by name into a new VM, linked by default (the source must then be a template), optionally into a pool. No-op when a VM with the new name exists. Records how long the clone task took (durationMs). Needs: VM.Clone on the source; VM.Allocate on /vms/{newid} or on /pool/{pool}; Datastore.AllocateSpace on the target storage; SDN.Use on the bridge when Proxmox checks it.",
      arguments: CloneArgs,
      execute: async (args: z.infer<typeof CloneArgs>, context: Ctx) => {
        const { vmName, source } = args;
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Cloning {source} to {vmName} on node {node} ({kind})", {
          source,
          vmName,
          node: g.node,
          kind: args.linked ? "linked" : "full",
        });

        const auth = await vmAuth(g);
        const vms = await listVms(g, auth);
        // Idempotent: Proxmox allows duplicate names, so never make a second
        // VM with the same name.
        const existing = vms.find((v) => v.name === vmName);
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

        const src = findVm(vms, source);
        if (args.linked && src.template !== 1) {
          throw new Error(
            `"${source}" (vmid ${src.vmid}) is not a template; a linked clone needs one (convertToTemplate), or set linked false`,
          );
        }

        let newid = args.newid;
        if (newid === undefined) {
          newid = parseInt(
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
          if (!Number.isInteger(newid)) {
            throw new Error("Proxmox returned an invalid next VM ID");
          }
        }

        const started = Date.now();
        const upid = await pveCall(
          g,
          auth,
          "POST",
          nodePath(g, `/qemu/${src.vmid}/clone`),
          `Cloning "${source}" (vmid ${src.vmid}) to "${vmName}" (vmid ${newid})`,
          buildCloneParams(newid, args).toString(),
        );
        const taskResult = await runTask(g, auth, upid);
        const durationMs = Date.now() - started;
        if (!taskResult.success) {
          throw new Error(
            `Cloning "${source}" to "${vmName}" (vmid ${newid}) failed: ${taskResult.exitstatus}`,
          );
        }
        log.info("Cloned {source} to {vmName} (vmid {vmid}) in {ms} ms", {
          source,
          vmName,
          vmid: newid,
          ms: durationMs,
        });

        const handle = await context.writeResource("vm", vmName, {
          vmid: newid,
          vmName,
          status: "stopped",
          ip: null,
          success: true,
          source,
          ...(args.pool ? { pool: args.pool } : {}),
          linked: args.linked,
          durationMs,
          logs: log.text(),
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    convertToTemplate: {
      description:
        "Turn a stopped VM into a template (no-op when it is one). Refuses a VM that is not stopped; it never stops it. Needs: VM.Allocate, VM.Audit.",
      arguments: ConvertToTemplateArgs,
      execute: async (
        args: z.infer<typeof ConvertToTemplateArgs>,
        context: Ctx,
      ) => {
        const { vmName } = args;
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Making VM {vmName} a template on node {node}", {
          vmName,
          node: g.node,
        });

        const auth = await vmAuth(g);
        const vm = await resolveVm(g, auth, vmName);
        if (vm.template === 1) {
          log.info("VM {vmName} (vmid {vmid}) is already a template", {
            vmName,
            vmid: vm.vmid,
          });
        } else {
          if (vm.status !== "stopped") {
            throw new Error(
              `VM "${vmName}" (vmid ${vm.vmid}) is ${vm.status}; stop it before it becomes a template`,
            );
          }
          const upid = await pveCall(
            g,
            auth,
            "POST",
            nodePath(g, `/qemu/${vm.vmid}/template`),
            `Making VM "${vmName}" (vmid ${vm.vmid}) a template`,
          );
          // Newer Proxmox runs this as a task (UPID); older versions finish it inline.
          if (typeof upid === "string" && upid.startsWith("UPID:")) {
            const taskResult = await runTask(g, auth, upid);
            if (!taskResult.success) {
              throw new Error(
                `Making VM "${vmName}" (vmid ${vm.vmid}) a template failed: ${taskResult.exitstatus}`,
              );
            }
          }
          log.info("VM {vmid} is now a template", { vmid: vm.vmid });
        }

        const handle = await context.writeResource("vm", vmName, {
          vmid: vm.vmid,
          vmName,
          status: "stopped",
          template: true,
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

        const auth = await vmAuth(g);
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

        const auth = await vmAuth(g);
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

        const auth = await vmAuth(g);
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
