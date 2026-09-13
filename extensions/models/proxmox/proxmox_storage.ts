import { z } from "npm:zod@4";
import { fetchWithCurl, resolveAuth, waitForTask } from "./lib/proxmox.ts";

const GlobalArgs = z.object({
  apiUrl: z.string().describe(
    "Proxmox API base URL (e.g., https://10.0.0.4:8006)",
  ),
  node: z.string().describe("Proxmox node name"),
  storage: z.string().describe("Storage name to download into (e.g., mrrobot)"),
  skipTlsVerify: z.boolean().default(true).describe(
    "Skip TLS certificate verification",
  ),
  ticket: z.string().optional().describe("Auth ticket from proxmox-node").meta(
    { sensitive: true },
  ),
  csrfToken: z.string().optional().describe("CSRF token from proxmox-node")
    .meta({ sensitive: true }),
  username: z.string().optional().describe("Proxmox username (fallback auth)"),
  password: z.string().optional().describe("Proxmox password (fallback auth)")
    .meta({ sensitive: true }),
  realm: z.string().default("pam").describe("Authentication realm"),
});

const ImageSchema = z.object({
  storage: z.string(),
  filename: z.string(),
  storageRef: z.string().describe(
    "Storage reference for use in import-from (e.g., mrrobot:import/Rocky-9.qcow2)",
  ),
  timestamp: z.string(),
});

/** Proxmox storage model — downloads cloud images server-side via the Proxmox download-url API. */
export const model = {
  type: "@dmc/proxmox/storage",
  version: "2026.07.18.1",
  globalArguments: GlobalArgs,
  upgrades: [
    {
      toVersion: "2026.07.18.1",
      description: "Version bump, no schema changes",
      upgradeAttributes: (old) => old,
    },
  ],
  resources: {
    image: {
      description:
        "Cloud image downloaded into Proxmox storage, ready for import-from",
      schema: ImageSchema,
      lifetime: "infinite",
      garbageCollection: 5,
    },
  },
  checks: {
    "storage-target-exists": {
      description:
        "Verify the target storage exists and is active on the target node before requesting a download",
      labels: ["live"],
      appliesTo: ["downloadImage"],
      execute: async (context) => {
        const { apiUrl, node, storage, skipTlsVerify } = context.globalArgs;
        const auth = await resolveAuth(context.globalArgs, context, {
          modelType: "@dmc/proxmox/storage",
        });

        const response = await fetchWithCurl(
          `${apiUrl}/api2/json/nodes/${node}/storage/${storage}/status`,
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
              `Storage "${storage}" not found on node "${node}": ${response.status} ${await response
                .text()}`,
            ],
          };
        }

        const status = (await response.json()).data;
        if (status?.active !== 1) {
          return {
            pass: false,
            errors: [`Storage "${storage}" on node "${node}" is not active`],
          };
        }

        return { pass: true };
      },
    },
  },
  methods: {
    downloadImage: {
      description:
        "Download a cloud image from a URL into Proxmox storage via the download-url API (Proxmox fetches directly — no local upload). Skips the download if the filename already exists in storage.",
      arguments: z.object({
        url: z.string().describe("Public URL of the image to download"),
        filename: z.string().describe(
          "Filename to save as in storage (e.g., Rocky-9-GenericCloud-Base.latest.x86_64.qcow2)",
        ),
        checksum: z.string().optional().describe(
          "Expected checksum value for integrity verification",
        ),
        checksumAlgorithm: z.string().optional().describe(
          "Checksum algorithm (sha256, md5, sha1)",
        ),
      }),
      execute: async (args, context) => {
        const { apiUrl, node, storage, skipTlsVerify } = context.globalArgs;
        const { url, filename, checksum, checksumAlgorithm } = args;
        const logs = [];
        const log = (msg) => logs.push(msg);

        log(`Authenticating with Proxmox at ${apiUrl}`);
        const auth = await resolveAuth(context.globalArgs, context, {
          modelType: "@dmc/proxmox/storage",
        });
        const authHeaders = {
          "Cookie": `PVEAuthCookie=${auth.ticket}`,
          "CSRFPreventionToken": auth.csrfToken,
        };

        log(`Checking if "${filename}" already exists in storage "${storage}"`);
        const existingResp = await fetchWithCurl(
          `${apiUrl}/api2/json/nodes/${node}/storage/${storage}/content`,
          { method: "GET", headers: authHeaders, skipTlsVerify },
        );
        if (!existingResp.ok) {
          throw new Error(
            `Failed to list storage content: ${await existingResp.text()}`,
          );
        }
        const existing = (await existingResp.json()).data.find((v) =>
          v.volid && v.volid.includes(filename)
        );
        if (existing) {
          log(`Image already exists at ${existing.volid} — skipping download`);
          const handle = await context.writeResource("image", filename, {
            storage,
            filename,
            storageRef: existing.volid,
            timestamp: new Date().toISOString(),
          });
          return { dataHandles: [handle] };
        }

        log(
          `Requesting Proxmox to download ${filename} into storage ${storage}`,
        );
        log(`Source: ${url}`);

        const params = new URLSearchParams({
          content: "import",
          filename,
          url,
        });
        if (checksum) params.set("checksum", checksum);
        if (checksumAlgorithm) {
          params.set("checksum-algorithm", checksumAlgorithm);
        }

        const response = await fetchWithCurl(
          `${apiUrl}/api2/json/nodes/${node}/storage/${storage}/download-url`,
          {
            method: "POST",
            headers: {
              ...authHeaders,
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: params.toString(),
            skipTlsVerify,
          },
        );

        if (!response.ok) {
          throw new Error(
            `Failed to start download: ${response.status} ${await response
              .text()}`,
          );
        }

        const upid = (await response.json()).data;
        log(`Download task started: ${upid}`);
        log(
          `Waiting for Proxmox to finish downloading (this may take a few minutes)...`,
        );

        const taskResult = await waitForTask(
          apiUrl,
          node,
          upid,
          auth.ticket,
          auth.csrfToken,
          skipTlsVerify,
        );
        // A concurrent download of the same file races this check-then-download —
        // Proxmox reports task failure with this message rather than succeeding idempotently.
        const alreadyExists = !taskResult.success &&
          typeof taskResult.exitstatus === "string" &&
          taskResult.exitstatus.includes("refusing to override existing file");
        if (!taskResult.success && !alreadyExists) {
          throw new Error(`Download task failed: ${taskResult.exitstatus}`);
        }
        if (alreadyExists) {
          log(
            `Proxmox reports file already exists — treating as idempotent success`,
          );
        }

        // Query content list to get the canonical volid as Proxmox assigned it.
        // Constructing the volid from storage+filename can produce a format that
        // Proxmox's property-string parser rejects (duplicate "file" key error).
        const contentResp = await fetchWithCurl(
          `${apiUrl}/api2/json/nodes/${node}/storage/${storage}/content`,
          { method: "GET", headers: authHeaders, skipTlsVerify },
        );
        if (!contentResp.ok) {
          throw new Error(
            `Failed to list storage content: ${await contentResp.text()}`,
          );
        }
        const contentList = (await contentResp.json()).data;
        const imageEntry = contentList.find((v) =>
          v.volid && v.volid.includes(filename)
        );
        if (!imageEntry) {
          throw new Error(
            `Downloaded image "${filename}" not found in storage content list after task completed`,
          );
        }
        const storageRef = imageEntry.volid;
        log(`Image ready at ${storageRef} (${taskResult.pollCount} polls)`);

        const handle = await context.writeResource("image", filename, {
          storage,
          filename,
          storageRef,
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
  },
};
