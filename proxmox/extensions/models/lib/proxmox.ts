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
 * curl config file text for request headers. Headers carry the API token secret, so
 * they go in a 0600 temp file read with `-K`, never on the command line where `ps` shows them.
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

/**
 * TLS settings for one API call. With `caCert`, curl checks the server
 * certificate and host name with `--cacert`, and `skipTlsVerify` has no
 * effect. Linux curl then trusts that CA only; Apple's /usr/bin/curl also
 * keeps trusting the macOS system roots. Without `caCert`, `skipTlsVerify`
 * turns off all certificate checks (`-k`), and false verifies against the
 * system roots.
 */
export interface TlsOptions {
  skipTlsVerify?: boolean;
  caCert?: string;
}

const PEM_CERT_RE =
  /^\s*(?:-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*)+$/;

/** The TLS settings in a model's global arguments. */
export function tlsOptions(
  g: { skipTlsVerify?: boolean; caCert?: string },
): TlsOptions {
  return { skipTlsVerify: g.skipTlsVerify ?? true, caCert: g.caCert };
}

/**
 * The CA bundle to pin, or null when no `caCert` is set. A `caCert` that is
 * set but is not a PEM certificate bundle is an error, never a fall back to
 * `-k`: that would send the token to whoever answers.
 */
export function pinnedCaCert(tls: TlsOptions | undefined): string | null {
  const ca: unknown = tls?.caCert;
  if (ca === undefined || ca === null) return null;
  if (isUnresolvedRef(ca)) {
    throw new Error(
      "Proxmox caCert is still an unresolved ${{ }} expression; check the reference.",
    );
  }
  if (typeof ca !== "string" || !PEM_CERT_RE.test(ca)) {
    throw new Error(
      "Proxmox caCert is not a PEM certificate bundle (-----BEGIN CERTIFICATE----- ...).",
    );
  }
  return ca;
}

export async function fetchWithCurl(url, options) {
  const { method = "GET", headers = {}, body, tls } = options;

  const caCert = pinnedCaCert(tls);
  // -q (first) skips ~/.curlrc, which could turn verification off.
  const args = ["-q", "-s", "-S"];
  if (caCert === null && tls?.skipTlsVerify) args.push("-k");
  args.push("-X", method);
  const config = Object.keys(headers).length > 0
    ? buildHeaderConfig(headers)
    : null;
  let configPath;
  let caPath;
  let bodyPath;
  try {
    if (caCert !== null) {
      // @ts-ignore - Deno API
      caPath = await Deno.makeTempFile({ prefix: "pve-ca-", suffix: ".pem" });
      // @ts-ignore - Deno API
      await Deno.writeTextFile(caPath, caCert, { mode: 0o600 });
      args.push("--cacert", caPath);
    }
    if (config !== null) {
      // @ts-ignore - Deno API
      configPath = await Deno.makeTempFile({ prefix: "pve-curl-" });
      // @ts-ignore - Deno API
      await Deno.writeTextFile(configPath, config, { mode: 0o600 });
      args.push("-K", configPath);
    }
    if (body) {
      // The body can hold cloud-init secrets (a password or keys), so it goes in
      // a 0600 file like the headers: an argument shows in `ps`.
      // @ts-ignore - Deno API
      bodyPath = await Deno.makeTempFile({ prefix: "pve-body-" });
      // @ts-ignore - Deno API
      await Deno.writeTextFile(bodyPath, body, { mode: 0o600 });
      args.push("--data-binary", `@${bodyPath}`);
    }
    args.push("-i", url);
    return await runCurl(args);
  } finally {
    // @ts-ignore - Deno API
    if (bodyPath) await Deno.remove(bodyPath).catch(() => {});
    // @ts-ignore - Deno API
    if (configPath) await Deno.remove(configPath).catch(() => {});
    // @ts-ignore - Deno API
    if (caPath) await Deno.remove(caPath).catch(() => {});
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
  tls: TlsOptions,
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
      tls,
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
  return ["tokenId", "tokenSecret"]
    .some((k) => isUnresolvedRef(globalArgs?.[k]));
}

/**
 * Global arguments that 2026.11.07.1 removed with password and ticket login.
 * The upgrade drops them; a definition left with only these has no auth and
 * fails at the first API call.
 */
export const REMOVED_AUTH_ARGS = [
  "ticket",
  "csrfToken",
  "username",
  "password",
  "realm",
] as const;

/** Upgrade step for 2026.11.07.1: drop the removed password and ticket args. */
export function dropRemovedAuthArgs(
  old: Record<string, unknown>,
): Record<string, unknown> {
  const out = { ...old };
  for (const k of REMOVED_AUTH_ARGS) delete out[k];
  return out;
}

/** Proxmox API token id: `user@realm!tokenname`. */
const TOKEN_ID_RE = /^[^@!\s]+@[^@!\s]+![A-Za-z][A-Za-z0-9._-]*$/;

/** A resolved Proxmox API token. */
export interface ProxmoxAuth {
  tokenId: string;
  tokenSecret: string;
}

/**
 * Request headers for a resolved token: only `Authorization: PVEAPIToken=...`.
 * Proxmox needs no CSRF token for token requests.
 */
export function authHeaders(auth: ProxmoxAuth): Record<string, string> {
  return {
    "Authorization": `PVEAPIToken=${auth.tokenId}=${auth.tokenSecret}`,
  };
}

/**
 * Resolve Proxmox auth from the `tokenId` + `tokenSecret` global args. API
 * tokens are the only auth: password and ticket login were removed in
 * 2026.11.07.1. Fails closed when the token is missing, unresolved or
 * malformed.
 */
export function resolveAuth(globalArgs): Promise<ProxmoxAuth> {
  const { tokenId, tokenSecret } = globalArgs ?? {};
  if (!tokenId || !tokenSecret) {
    return Promise.reject(
      new Error(
        "Proxmox auth needs the tokenId and tokenSecret global args (an API token). Password and ticket login were removed in 2026.11.07.1.",
      ),
    );
  }
  if (isUnresolvedRef(tokenId) || isUnresolvedRef(tokenSecret)) {
    return Promise.reject(
      new Error(
        "Proxmox tokenId/tokenSecret is still an unresolved ${{ }} expression; check the vault reference.",
      ),
    );
  }
  if (typeof tokenId !== "string" || !TOKEN_ID_RE.test(tokenId)) {
    return Promise.reject(
      new Error(
        "Proxmox tokenId is not in the form user@realm!tokenname (the value is not shown, in case it is a secret).",
      ),
    );
  }
  if (typeof tokenSecret !== "string") {
    return Promise.reject(new Error("Proxmox tokenSecret must be a string."));
  }
  return Promise.resolve({ tokenId, tokenSecret });
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
  conn: TlsOptions,
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
    tls: tlsOptions(conn),
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
  conn: { apiUrl: string; node: string } & TlsOptions,
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
        tls: tlsOptions(conn),
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
    "Skip TLS certificate verification (curl -k). Ignored when caCert is set.",
  ),
  caCert: z.string().optional().describe(
    "PEM CA certificate(s) that sign a self-signed API certificate (for a cluster, /etc/pve/pve-root-ca.pem). When set, every API call checks the certificate and host name with curl --cacert, and skipTlsVerify has no effect. Linux curl then trusts this CA only; the macOS system curl also keeps trusting the system roots. Not needed when the API has a publicly trusted certificate: set skipTlsVerify false instead.",
  ),
  tokenId: z.string().optional().describe(
    "Proxmox API token id, user@realm!tokenname (used with tokenSecret; the only auth)",
  ),
  tokenSecret: z.string().optional().describe("Proxmox API token secret")
    .meta({ sensitive: true }),
});
