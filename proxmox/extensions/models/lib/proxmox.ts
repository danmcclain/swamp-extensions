// Proxmox API helpers — copied from @keeb/proxmox for use in local extensions.

export async function fetchWithCurl(url, options) {
  const { method = "GET", headers = {}, body, skipTlsVerify } = options;

  const args = ["-s", "-S"];
  if (skipTlsVerify) args.push("-k");
  args.push("-X", method);
  for (const [key, value] of Object.entries(headers)) {
    args.push("-H", `${key}: ${value}`);
  }
  if (body) args.push("-d", body);
  args.push("-i", url);

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
  ticket,
  csrfToken,
  skipTlsVerify,
) {
  const encodedUpid = encodeURIComponent(upid);
  const url = `${apiUrl}/api2/json/nodes/${node}/tasks/${encodedUpid}/status`;
  let pollCount = 0;

  while (true) {
    pollCount++;
    const response = await fetchWithCurl(url, {
      method: "GET",
      headers: {
        "Cookie": `PVEAuthCookie=${ticket}`,
        ...(csrfToken && { "CSRFPreventionToken": csrfToken }),
      },
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

export async function resolveAuth(
  globalArgs,
  context,
  opts: { modelType?: string; skipCache?: boolean } = {},
) {
  const { apiUrl, skipTlsVerify } = globalArgs;

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
      "No auth available: provide explicit ticket/csrfToken or username/password global args.",
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
