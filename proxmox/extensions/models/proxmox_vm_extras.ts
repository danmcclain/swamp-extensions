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
        return { dataHandles: [handle] };
      },
    },
  }],
};
