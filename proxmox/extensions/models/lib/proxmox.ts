// Proxmox API helpers — copied from @keeb/proxmox for use in local extensions.

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

export async function waitForTask(
  apiUrl,
  node,
  upid,
  auth,
  skipTlsVerify,
) {
  const encodedUpid = encodeURIComponent(upid);
  const url = `${apiUrl}/api2/json/nodes/${node}/tasks/${encodedUpid}/status`;
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
