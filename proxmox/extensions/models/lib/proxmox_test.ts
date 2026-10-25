import {
  assert,
  assertEquals,
  assertFalse,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import {
  createModelTestContext,
  withMockedCommand,
} from "jsr:@systeminit/swamp-testing@0.20260604.20";
import {
  authHeaders,
  buildHeaderConfig,
  fetchWithCurl,
  resolveAuth,
  waitForTask,
} from "./proxmox.ts";
import { model as storageModel } from "../proxmox_storage.ts";

const TOKEN_ID = "swamp@pve!automation";
const TOKEN_SECRET = "11111111-2222-3333-4444-555555555555";

function httpOutput(status: number, body: unknown) {
  return {
    stdout: `HTTP/1.1 ${status} OK\r\n\r\n${JSON.stringify(body)}`,
    code: 0,
  };
}

/** Read the curl config file a call passed with -K (only exists during the call). */
function readHeaderConfig(args: string[]): string {
  const i = args.indexOf("-K");
  return i === -1 ? "" : Deno.readTextFileSync(args[i + 1]);
}

Deno.test("authHeaders sends only the PVEAPIToken header for token auth", () => {
  assertEquals(
    authHeaders({
      source: "token",
      tokenId: TOKEN_ID,
      tokenSecret: TOKEN_SECRET,
    }),
    { "Authorization": `PVEAPIToken=${TOKEN_ID}=${TOKEN_SECRET}` },
  );
});

Deno.test("authHeaders sends the cookie and CSRF token for ticket auth", () => {
  assertEquals(
    authHeaders({ source: "explicit", ticket: "t", csrfToken: "c" }),
    { "Cookie": "PVEAuthCookie=t", "CSRFPreventionToken": "c" },
  );
});

Deno.test("resolveAuth prefers the API token over a ticket and makes no login call", async () => {
  const { result, calls } = await withMockedCommand([], () =>
    resolveAuth(
      {
        apiUrl: "https://pve.test:8006",
        tokenId: TOKEN_ID,
        tokenSecret: TOKEN_SECRET,
        ticket: "stale-ticket",
        csrfToken: "stale-csrf",
      },
      {},
    ));
  assertEquals(calls.length, 0);
  assertEquals(result.source, "token");
  assertEquals(result.tokenId, TOKEN_ID);
});

Deno.test("resolveAuth rejects a token id without a secret", async () => {
  await assertRejects(
    () =>
      resolveAuth({ apiUrl: "https://pve.test:8006", tokenId: TOKEN_ID }, {}),
    Error,
    "both tokenId and tokenSecret",
  );
});

Deno.test("resolveAuth rejects a token id that is not user@realm!name", async () => {
  await assertRejects(
    () =>
      resolveAuth({
        apiUrl: "https://pve.test:8006",
        tokenId: "swamp@pve",
        tokenSecret: TOKEN_SECRET,
      }, {}),
    Error,
    "user@realm!tokenname",
  );
});

Deno.test("fetchWithCurl puts headers in a -K config file, not on the command line", async () => {
  let config = "";
  const { calls } = await withMockedCommand((_cmd, args) => {
    config = readHeaderConfig(args);
    return httpOutput(200, { data: [] });
  }, () =>
    fetchWithCurl("https://pve.test:8006/api2/json/nodes", {
      headers: authHeaders({
        source: "token",
        tokenId: TOKEN_ID,
        tokenSecret: TOKEN_SECRET,
      }),
    }));

  const argv = calls[0].args.join(" ");
  assertFalse(argv.includes(TOKEN_SECRET), "secret must not be in argv");
  assertFalse(argv.includes("-H"));
  assertEquals(
    config,
    `header = "Authorization: PVEAPIToken=${TOKEN_ID}=${TOKEN_SECRET}"\n`,
  );
  const path = calls[0].args[calls[0].args.indexOf("-K") + 1];
  assertFalse(
    await Deno.stat(path).then(() => true, () => false),
    "config file is removed after the call",
  );
});

Deno.test("buildHeaderConfig escapes quotes and backslashes", () => {
  assertEquals(
    buildHeaderConfig({ "X-Test": 'a"b\\c' }),
    'header = "X-Test: a\\"b\\\\c"\n',
  );
});

Deno.test("buildHeaderConfig rejects a header value with a line break", () => {
  for (const bad of ["a\nX-Injected: 1", "a\rb"]) {
    assertThrows(
      () => buildHeaderConfig({ "X-Test": bad }),
      Error,
      "line break",
    );
  }
});

Deno.test("fetchWithCurl with a bad header makes no call and leaves no temp file", async () => {
  const before = new Set(
    [...Deno.readDirSync(Deno.env.get("TMPDIR") ?? "/tmp")]
      .filter((e) => e.name.startsWith("pve-curl-")).map((e) => e.name),
  );
  const { calls } = await withMockedCommand([], () =>
    assertRejects(
      () =>
        fetchWithCurl("https://pve.test:8006/api2/json/nodes", {
          headers: { "Authorization": "PVEAPIToken=a@b!c=x\ny" },
        }),
      Error,
      "line break",
    ));
  assertEquals(calls.length, 0);
  const after = [...Deno.readDirSync(Deno.env.get("TMPDIR") ?? "/tmp")]
    .filter((e) => e.name.startsWith("pve-curl-") && !before.has(e.name));
  assertEquals(after.length, 0);
});

Deno.test("resolveAuth rejects a token that is still an unresolved expression", async () => {
  await assertRejects(
    () =>
      resolveAuth({
        apiUrl: "https://pve.test:8006",
        tokenId: TOKEN_ID,
        tokenSecret: "${{ vault.get(infra, PROXMOX_TOKEN_SECRET) }}",
      }, {}),
    Error,
    "unresolved",
  );
});

Deno.test("storage-target-exists passes without a call when auth args are unresolved", async () => {
  const check = storageModel.checks["storage-target-exists"];
  const { result, calls } = await withMockedCommand([], () =>
    check.execute({
      globalArgs: {
        apiUrl: "https://pve.test:8006",
        node: "pve",
        storage: "local",
        tokenId: TOKEN_ID,
        tokenSecret: "${{ vault.get(infra, PROXMOX_TOKEN_SECRET) }}",
      },
    }));
  assertEquals(result, { pass: true });
  assertEquals(calls.length, 0);
});

Deno.test("waitForTask polls with token auth headers", async () => {
  let config = "";
  const { result } = await withMockedCommand((_cmd, args) => {
    config = readHeaderConfig(args);
    return httpOutput(200, { data: { status: "stopped", exitstatus: "OK" } });
  }, () =>
    waitForTask(
      "https://pve.test:8006",
      "pve",
      "UPID:pve:1:",
      { source: "token", tokenId: TOKEN_ID, tokenSecret: TOKEN_SECRET },
      true,
    ));
  assert(result.success);
  assertStringIncludes(config, "PVEAPIToken=");
  assertFalse(config.includes("CSRFPreventionToken"));
});

Deno.test("storage downloadImage authenticates every call with the API token", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {
      apiUrl: "https://pve.test:8006",
      node: "pve",
      storage: "local",
      skipTlsVerify: true,
      tokenId: TOKEN_ID,
      tokenSecret: TOKEN_SECRET,
      realm: "pam",
    },
  });
  const outputs = [
    httpOutput(200, { data: [] }),
    httpOutput(200, { data: "UPID:pve:00000001:qmdownload:" }),
    httpOutput(200, { data: { status: "stopped", exitstatus: "OK" } }),
    httpOutput(200, { data: [{ volid: "local:import/new.qcow2" }] }),
  ];
  const configs: string[] = [];
  const { calls } = await withMockedCommand((_cmd, args) => {
    configs.push(readHeaderConfig(args));
    return outputs[configs.length - 1];
  }, () =>
    storageModel.methods.downloadImage.execute(
      { url: "https://example.com/new.qcow2", filename: "new.qcow2" },
      context,
    ));

  assertEquals(calls.length, 4);
  for (const c of configs) {
    assertStringIncludes(
      c,
      `Authorization: PVEAPIToken=${TOKEN_ID}=${TOKEN_SECRET}`,
    );
    assertFalse(c.includes("PVEAuthCookie"));
    assertFalse(c.includes("CSRFPreventionToken"));
  }
  assertFalse(calls.some((c) => c.args.join(" ").includes("/access/ticket")));
  assertEquals(
    getWrittenResources()[0].data.storageRef,
    "local:import/new.qcow2",
  );
});

Deno.test("storage-target-exists reports refused credentials, not a missing storage", async () => {
  const check = storageModel.checks["storage-target-exists"];
  const { result } = await withMockedCommand(
    [{ stdout: "HTTP/1.1 401 Unauthorized\r\n\r\n", code: 0 }],
    () =>
      check.execute({
        globalArgs: {
          apiUrl: "https://pve.test:8006",
          node: "pve",
          storage: "local",
          tokenId: TOKEN_ID,
          tokenSecret: "wrong",
        },
      }),
  );
  assertFalse(result.pass);
  assertStringIncludes(result.errors[0], "refused the credentials (401)");
});
