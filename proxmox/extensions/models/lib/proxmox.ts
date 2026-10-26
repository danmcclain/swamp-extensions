// Proxmox API helpers. Parts are adapted from @keeb/proxmox
// (https://github.com/keeb/swamp-proxmox):
//
//   MIT License
//
//   Copyright (c) 2026 keeb <keeb@systeminit.com>
//
//   Permission is hereby granted, free of charge, to any person obtaining a
//   copy of this software and associated documentation files (the
//   "Software"), to deal in the Software without restriction, including
//   without limitation the rights to use, copy, modify, merge, publish,
//   distribute, sublicense, and/or sell copies of the Software, and to permit
//   persons to whom the Software is furnished to do so, subject to the
//   following conditions:
//
//   The above copyright notice and this permission notice shall be included
//   in all copies or substantial portions of the Software.
//
//   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
//   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
//   NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
//   DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
//   OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
//   USE OR OTHER DEALINGS IN THE SOFTWARE.

import { z } from "npm:zod@4";

/** Quote a value for a curl config file (double-quoted string). */
export function quoteCurlConfig(value) {
  return `"${
    String(value)
      .replace(/\\/g, "\\\\")
      .replace(/"/g, '\\"')
      .replace(/\r/g, "\\r")
      .replace(/\n/g, "\\n")
  }"`;
}

/**
 * curl config file text for request headers. Headers carry the auth cookie,
 * CSRF token or API token secret, so they go in a 0600 temp file read with
 * `-K`, never on the command line where `ps` shows them.
 */
export function buildHeaderConfig(headers) {
  return Object.entries(headers)
    .map(([key, value]) => {
      const line = `${key}: ${value}`;
      // A CR/LF would let one header value inject another header.
      if (/[\r\n]/.test(line)) {
        throw new Error(`Header "${key}" contains a line break`);
      }
      return `header = ${quoteCurlConfig(line)}`;
    })
    .join("\n") + "\n";
}

export async function fetchWithCurl(url, options) {
  const { method = "GET", headers = {}, body, skipTlsVerify } = options;

  const args = ["-s", "-S"];
  if (skipTlsVerify) args.push("-k");
  args.push("-X", method);
  const config = Object.keys(headers).length > 0
    ? buildHeaderConfig(headers)
    : null;
  let configPath;
  try {
    if (config !== null) {
      // @ts-ignore - Deno API
      configPath = await Deno.makeTempFile({ prefix: "pve-curl-" });
      // @ts-ignore - Deno API
      await Deno.writeTextFile(configPath, config, { mode: 0o600 });
      args.push("-K", configPath);
    }
    if (body) args.push("-d", body);
    args.push("-i", url);
    return await runCurl(args);
  } finally {
    // @ts-ignore - Deno API
    if (configPath) await Deno.remove(configPath).catch(() => {});
  }
}

async function runCurl(args) {
  // @ts-ignore - Deno API
  const command = new Deno.Command("curl", { args });
  const { code, stdout, stderr } = await command.output();

  if (code !== 0) {
    const errorText = new TextDecoder().decode(stderr);
    throw new Error(`curl failed with code ${code}: ${errorText}`);
  }

  const output = new TextDecoder().decode(stdout);
  const headerEndIndex = output.indexOf("\r\n\r\n");
  const headersText = output.substring(0, headerEndIndex);
  const bodyText = output.substring(headerEndIndex + 4);
  const statusLine = headersText.split("\r\n")[0];
  const statusMatch = statusLine.match(/HTTP\/[\d.]+ (\d+)/);
  const status = statusMatch ? parseInt(statusMatch[1]) : 0;

  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: statusLine,
    text: () => bodyText,
    json: () => JSON.parse(bodyText),
  };
}

/**
 * Poll a Proxmox task (UPID) until it stops. With `timeoutSeconds`, throw if
 * it is still running after that long; without it, wait as long as it takes.
 */
export async function waitForTask(
  apiUrl,
  node,
  upid,
  auth,
  skipTlsVerify,
  timeoutSeconds?: number,
) {
  const encodedUpid = encodeURIComponent(upid);
  const url = `${apiUrl}/api2/json/nodes/${node}/tasks/${encodedUpid}/status`;
  const deadline = timeoutSeconds === undefined
    ? Infinity
    : Date.now() + timeoutSeconds * 1000;
  let pollCount = 0;

  while (true) {
    pollCount++;
    const response = await fetchWithCurl(url, {
      method: "GET",
      headers: authHeaders(auth),
      skipTlsVerify,
    });

    if (!response.ok) {
      throw new Error(`Task status check failed: ${response.status}`);
    }

    const result = await response.json();
    const status = result.data?.status;

    if (status === "stopped") {
      return {
        success: result.data?.exitstatus === "OK",
        exitstatus: result.data?.exitstatus,
        pollCount,
      };
    }

    if (Date.now() >= deadline) {
      throw new Error(
        `Proxmox task ${upid} did not finish within ${timeoutSeconds}s`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

export const AUTH_TTL_MS = 2 * 60 * 60 * 1000;

/** True when `value` is a still-unresolved `${{ ... }}` vault/CEL reference. */
export function isUnresolvedRef(value) {
  return typeof value === "string" && value.includes("${{");
}

/**
 * True when any auth global arg is still an unresolved expression. Checks
 * can see raw global args (e.g. under `validate`); they pass in that case and
 * leave auth to the method run.
 */
export function hasUnresolvedAuth(globalArgs) {
  return [
    "tokenId",
    "tokenSecret",
    "ticket",
    "csrfToken",
    "username",
    "password",
  ]
    .some((k) => isUnresolvedRef(globalArgs?.[k]));
}

/** Proxmox API token id: `user@realm!tokenname`. */
const TOKEN_ID_RE = /^[^@!\s]+@[^@!\s]+![A-Za-z][A-Za-z0-9._-]*$/;

/**
 * Request headers for a resolved auth. Token auth sends only the
 * `Authorization: PVEAPIToken=...` header: Proxmox needs no CSRF token for
 * token requests. Ticket auth sends the cookie and, when known, the CSRF token.
 */
export function authHeaders(auth) {
  if (auth.source === "token") {
    return {
      "Authorization": `PVEAPIToken=${auth.tokenId}=${auth.tokenSecret}`,
    };
  }
  return {
    "Cookie": `PVEAuthCookie=${auth.ticket}`,
    ...(auth.csrfToken && { "CSRFPreventionToken": auth.csrfToken }),
  };
}

/**
 * Resolve Proxmox auth, in order:
 * 1. API token (`tokenId` + `tokenSecret` global args),
 * 2. explicit `ticket` + `csrfToken` global args,
 * 3. a fresh ticket cached in the model's `auth` data,
 * 4. username/password login via POST /access/ticket.
 */
export async function resolveAuth(
  globalArgs,
  context,
  opts: { modelType?: string; skipCache?: boolean } = {},
) {
  const { apiUrl, skipTlsVerify } = globalArgs;

  const { tokenId, tokenSecret } = globalArgs;
  if (tokenId || tokenSecret) {
    if (!tokenId || !tokenSecret) {
      throw new Error(
        "Proxmox token auth needs both tokenId and tokenSecret global args.",
      );
    }
    if (isUnresolvedRef(tokenId) || isUnresolvedRef(tokenSecret)) {
      throw new Error(
        "Proxmox tokenId/tokenSecret is still an unresolved ${{ }} expression; check the vault reference.",
      );
    }
    if (!TOKEN_ID_RE.test(tokenId)) {
      throw new Error(
        `Proxmox tokenId "${tokenId}" is not in the form user@realm!tokenname.`,
      );
    }
    return { tokenId, tokenSecret, source: "token", freshAuth: false };
  }

  const { ticket: explicitTicket, csrfToken: explicitCsrf } = globalArgs;
  if (explicitTicket && explicitCsrf) {
    return {
      ticket: explicitTicket,
      csrfToken: explicitCsrf,
      source: "explicit",
      freshAuth: false,
    };
  }

  if (!opts.skipCache) {
    try {
      const modelType = opts.modelType || "@dmc/proxmox";
      const defId = context.definition.id;
      const authDir =
        `${context.repoDir}/.swamp/data/${modelType}/${defId}/auth`;
      const entries = [];
      // @ts-ignore - Deno API
      for await (const entry of Deno.readDir(authDir)) {
        if (entry.isDirectory) entries.push(entry);
      }
      if (entries.length > 0) {
        const versions = entries.map((e) => parseInt(e.name, 10)).filter((n) =>
          !isNaN(n)
        );
        const latest = Math.max(...versions);
        const rawPath = `${authDir}/${latest}/raw`;
        const metaPath = `${authDir}/${latest}/metadata.yaml`;
        // @ts-ignore - Deno API
        const metaText = await Deno.readTextFile(metaPath);
        const createdAtMatch = metaText.match(/createdAt:\s*'([^']+)'/);
        if (createdAtMatch) {
          const createdAt = new Date(createdAtMatch[1]);
          if (Date.now() - createdAt.getTime() < AUTH_TTL_MS) {
            // @ts-ignore - Deno API
            const rawText = await Deno.readTextFile(rawPath);
            const cached = JSON.parse(rawText);
            return {
              ticket: cached.ticket,
              csrfToken: cached.csrfToken,
              source: "cache",
              freshAuth: false,
            };
          }
        }
      }
    } catch (_e) {
      // No cached auth — fall through
    }
  }

  const { username, password, realm } = globalArgs;
  if (!username || !password) {
    throw new Error(
      "No auth available: provide tokenId/tokenSecret, explicit ticket/csrfToken, or username/password global args.",
    );
  }

  const formData = new URLSearchParams();
  formData.append("username", `${username}@${realm || "pam"}`);
  formData.append("password", password);

  const response = await fetchWithCurl(`${apiUrl}/api2/json/access/ticket`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: formData.toString(),
    skipTlsVerify: skipTlsVerify ?? true,
  });

  if (!response.ok) {
    throw new Error(
      `Authentication failed: ${response.status} - ${await response.text()}`,
    );
  }

  const result = await response.json();
  const { ticket, CSRFPreventionToken } = result.data;
  return {
    ticket,
    csrfToken: CSRFPreventionToken,
    username: `${username}@${realm || "pam"}`,
    source: "password",
    freshAuth: true,
  };
}

/** Base URL for a node-scoped API path. */
export function nodePath(
  conn: { apiUrl: string; node: string },
  suffix: string,
): string {
  return `${conn.apiUrl}/api2/json/nodes/${
    encodeURIComponent(conn.node)
  }${suffix}`;
}

/**
 * Call the Proxmox API and return `data` from the JSON envelope. Throws a
 * descriptive error (operation, HTTP status, response body) on a non-2xx.
 */
export async function pveCall(
  conn: { skipTlsVerify?: boolean },
  auth,
  method: string,
  url: string,
  what: string,
  body?: string,
): Promise<unknown> {
  const headers = authHeaders(auth);
  if (body !== undefined || method !== "GET") {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
  }
  const response = await fetchWithCurl(url, {
    method,
    headers,
    body,
    skipTlsVerify: conn.skipTlsVerify ?? true,
  });
  if (!response.ok) {
    throw new Error(
      `${what} failed: HTTP ${response.status} ${
        response.text().slice(0, 500)
      }`,
    );
  }
  return response.json()?.data;
}

/**
 * Pick the first routable IPv4 address from QEMU guest-agent interfaces,
 * skipping loopback and link-local addresses.
 */
export function pickGuestIpv4(interfaces: unknown): string | null {
  if (!Array.isArray(interfaces)) return null;
  for (const iface of interfaces) {
    if (!iface || iface.name === "lo") continue;
    for (const ip of iface["ip-addresses"] ?? []) {
      const addr = ip?.["ip-address"];
      if (ip?.["ip-address-type"] !== "ipv4" || typeof addr !== "string") {
        continue;
      }
      if (addr.startsWith("127.") || addr.startsWith("169.254.")) continue;
      return addr;
    }
  }
  return null;
}

/**
 * Ask the QEMU guest agent for the VM's IPv4, retrying until `waitSeconds`
 * elapse. Always makes at least one attempt. Returns null if none is found.
 */
export async function getVmIpWithRetry(
  conn: { apiUrl: string; node: string; skipTlsVerify?: boolean },
  auth,
  vmid: number,
  waitSeconds = 120,
  pollInterval = 5,
): Promise<string | null> {
  const deadline = Date.now() + waitSeconds * 1000;
  const pollMs = pollInterval * 1000;
  const url = nodePath(conn, `/qemu/${vmid}/agent/network-get-interfaces`);

  while (true) {
    let response = null;
    try {
      response = await fetchWithCurl(url, {
        method: "GET",
        headers: authHeaders(auth),
        skipTlsVerify: conn.skipTlsVerify ?? true,
      });
    } catch {
      response = null; // transport error: the guest agent is not reachable yet
    }
    if (response?.ok) {
      let interfaces: unknown = null;
      try {
        interfaces = response.json()?.data?.result;
      } catch {
        interfaces = null;
      }
      const ip = pickGuestIpv4(interfaces);
      if (ip) return ip;
    }
    if (Date.now() + pollMs >= deadline) return null;
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

/** Pre-flight validation of the connection global arguments. */
export function validateConnection(
  globalArgs: { apiUrl?: unknown; node?: unknown },
): { pass: boolean; errors?: string[] } {
  const errors: string[] = [];
  const { apiUrl, node } = globalArgs;
  if (isUnresolvedRef(apiUrl) || isUnresolvedRef(node)) return { pass: true };
  if (typeof apiUrl !== "string" || apiUrl.length === 0) {
    errors.push("apiUrl is required");
  } else {
    try {
      const u = new URL(apiUrl);
      if (u.protocol !== "https:" && u.protocol !== "http:") {
        errors.push(`apiUrl must be http(s), got "${u.protocol}"`);
      }
      if (u.username || u.password) {
        errors.push("apiUrl must not embed credentials");
      }
    } catch {
      errors.push(`apiUrl is not a valid URL: ${JSON.stringify(apiUrl)}`);
    }
  }
  if (typeof node !== "string" || node.trim().length === 0) {
    errors.push("node is required");
  }
  return errors.length ? { pass: false, errors } : { pass: true };
}

/** Render `{key}` placeholders for the human-readable `logs` field. */
export function renderTemplate(
  template: string,
  props: Record<string, unknown> = {},
): string {
  return template.replace(
    /\{(\w+)\}/g,
    (m, k) => (k in props ? String(props[k]) : m),
  );
}

/**
 * Method logger: forwards structured messages to `context.logger` and keeps a
 * rendered copy for the resource `logs` field.
 */
export function createMethodLogger(context: { logger? }) {
  const lines: string[] = [];
  return {
    lines,
    info(template: string, props: Record<string, unknown> = {}) {
      lines.push(renderTemplate(template, props));
      context.logger?.info(template, props);
    },
    warn(template: string, props: Record<string, unknown> = {}) {
      lines.push(renderTemplate(template, props));
      const l = context.logger;
      const warnFn = l?.warning ?? l?.warn;
      if (warnFn) warnFn.call(l, template, props);
      else l?.info(template, props);
    },
    text() {
      return lines.join("\n");
    },
  };
}

/** Global arguments shared by every `@dmc/proxmox` model that calls the API. */
export const ProxmoxConnectionArgs = z.object({
  apiUrl: z.string().describe(
    "Proxmox API base URL (e.g., https://192.0.2.10:8006)",
  ),
  node: z.string().describe("Proxmox node name"),
  skipTlsVerify: z.boolean().default(true).describe(
    "Skip TLS certificate verification",
  ),
  tokenId: z.string().optional().describe(
    "Proxmox API token id, user@realm!tokenname (preferred auth; used with tokenSecret)",
  ),
  tokenSecret: z.string().optional().describe("Proxmox API token secret")
    .meta({ sensitive: true }),
  ticket: z.string().optional().describe("Auth ticket (ticket auth)").meta({
    sensitive: true,
  }),
  csrfToken: z.string().optional().describe("CSRF token (ticket auth)").meta({
    sensitive: true,
  }),
  username: z.string().optional().describe(
    "Proxmox username (password auth fallback)",
  ),
  password: z.string().optional().describe(
    "Proxmox password (password auth fallback)",
  ).meta({ sensitive: true }),
  realm: z.string().default("pam").describe("Authentication realm"),
});
