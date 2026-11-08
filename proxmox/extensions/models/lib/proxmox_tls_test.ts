// TLS settings of the runner-side curl calls: caCert verifies a self-signed
// API certificate with --cacert, and replaces -k. The real-curl test uses a
// CA that no system trusts, so it holds for Apple's curl too, which keeps the
// system roots next to --cacert.
import {
  assert,
  assertEquals,
  assertFalse,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import {
  createModelTestContext,
  withMockedCommand,
} from "jsr:@systeminit/swamp-testing@0.20260604.20";
import {
  fetchWithCurl,
  pinnedCaCert,
  ProxmoxConnectionArgs,
  pveCall,
  tlsOptions,
} from "./proxmox.ts";
import { model as storageModel } from "../proxmox_storage.ts";

const TOKEN_ID = "swamp@pve!automation";
const TOKEN_SECRET = "11111111-2222-3333-4444-555555555555";
const TOKEN_AUTH = {
  tokenId: TOKEN_ID,
  tokenSecret: TOKEN_SECRET,
};
const CA_PEM = "-----BEGIN CERTIFICATE-----\n" +
  "MIIBszCCAVmgAwIBAgIUQ2VydGlmaWNhdGVGb3JUZXN0czAKBggqhkjOPQQDAjAS\n" +
  "-----END CERTIFICATE-----\n";

function httpOutput(status: number, body: unknown) {
  return {
    stdout: `HTTP/1.1 ${status} OK\r\n\r\n${JSON.stringify(body)}`,
    code: 0,
  };
}

/** The --cacert path and the file's text, read while the call runs. */
function readCaFile(args: string[]): { path: string; text: string } | null {
  const i = args.indexOf("--cacert");
  if (i === -1) return null;
  return { path: args[i + 1], text: Deno.readTextFileSync(args[i + 1]) };
}

async function exists(path: string): Promise<boolean> {
  try {
    await Deno.stat(path);
    return true;
  } catch {
    return false;
  }
}

// --- pinnedCaCert / tlsOptions ----------------------------------------------

Deno.test("pinnedCaCert: no caCert means no pin", () => {
  assertEquals(pinnedCaCert(undefined), null);
  assertEquals(pinnedCaCert({ skipTlsVerify: true }), null);
});

Deno.test("pinnedCaCert: accepts a PEM bundle of one or more certificates", () => {
  assertEquals(pinnedCaCert({ caCert: CA_PEM }), CA_PEM);
  const two = CA_PEM + "\n" + CA_PEM.replace(/\n/g, "\r\n");
  assertEquals(pinnedCaCert({ caCert: two }), two);
});

Deno.test("pinnedCaCert: a set caCert that is not a PEM bundle is an error, not -k", () => {
  for (
    const bad of [
      "",
      "   ",
      "not a cert",
      "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
      CA_PEM + "trailing text",
      "prefix\n" + CA_PEM,
      CA_PEM.replace("-----END CERTIFICATE-----", ""),
    ]
  ) {
    let threw = false;
    try {
      pinnedCaCert({ caCert: bad });
    } catch (e) {
      threw = true;
      assertStringIncludes((e as Error).message, "not a PEM certificate");
    }
    assert(threw, `accepted ${JSON.stringify(bad)}`);
  }
});

Deno.test("pinnedCaCert: an unresolved expression is an error", () => {
  let msg = "";
  try {
    pinnedCaCert({ caCert: '${{ vault.get(infra, "PVE CA/pem") }}' });
  } catch (e) {
    msg = (e as Error).message;
  }
  assertStringIncludes(msg, "unresolved");
});

Deno.test("tlsOptions: skipTlsVerify defaults to true, as the schema does", () => {
  assertEquals(tlsOptions({}), { skipTlsVerify: true, caCert: undefined });
  assertEquals(tlsOptions({ skipTlsVerify: false, caCert: CA_PEM }), {
    skipTlsVerify: false,
    caCert: CA_PEM,
  });
});

Deno.test("ProxmoxConnectionArgs accepts an optional caCert", () => {
  const base = { apiUrl: "https://pve.test:8006", node: "pve" };
  assertEquals(ProxmoxConnectionArgs.parse(base).caCert, undefined);
  assertEquals(
    ProxmoxConnectionArgs.parse({ ...base, caCert: CA_PEM }).caCert,
    CA_PEM,
  );
});

// --- fetchWithCurl arguments (mocked curl) -----------------------------------

Deno.test("fetchWithCurl: the body goes in a 0600 file, never on the command line", async () => {
  const body = "ciuser=rocky&cipassword=s3cret-pass";
  let path = "";
  let text = "";
  let mode = -1;
  const { calls } = await withMockedCommand(
    (_cmd, args) => {
      const i = args.indexOf("--data-binary");
      path = args[i + 1].replace(/^@/, "");
      text = Deno.readTextFileSync(path);
      mode = Deno.statSync(path).mode! & 0o777;
      return httpOutput(200, { data: 1 });
    },
    () =>
      fetchWithCurl(
        "https://pve.test:8006/api2/json/nodes/node1/qemu/100/config",
        {
          method: "POST",
          body,
          tls: { skipTlsVerify: false },
        },
      ),
  );
  const args = calls[0].args;
  assertFalse(args.includes("-d"));
  assertFalse(
    args.some((a) => a.includes("s3cret")),
    "the secret is in a curl argument",
  );
  assertEquals(text, body);
  assertEquals(mode, 0o600);
  assertFalse(await exists(path), "the body file stays after the call");
});

Deno.test("fetchWithCurl: the body file is removed when curl fails", async () => {
  let path = "";
  await assertRejects(
    () =>
      withMockedCommand((_cmd, args) => {
        path = args[args.indexOf("--data-binary") + 1].replace(/^@/, "");
        return { stdout: "", stderr: "Connection refused", code: 7 };
      }, () =>
        fetchWithCurl(
          "https://pve.test:8006/api2/json/nodes/node1/qemu/100/config",
          {
            method: "POST",
            body: "cipassword=s3cret-pass",
          },
        )),
    Error,
    "curl failed with code 7",
  );
  assert(path.length > 0);
  assertFalse(await exists(path));
});

Deno.test("fetchWithCurl: no body, no --data-binary", async () => {
  const { calls } = await withMockedCommand(
    [httpOutput(200, { data: 1 })],
    () => fetchWithCurl("https://pve.test:8006/api2/json/version", {}),
  );
  assertFalse(calls[0].args.includes("--data-binary"));
});

Deno.test("fetchWithCurl: caCert gives --cacert and no -k, even with skipTlsVerify", async () => {
  const seen: ({ path: string; text: string } | null)[] = [];
  const { calls } = await withMockedCommand((_cmd, args) => {
    seen.push(readCaFile(args));
    return httpOutput(200, { data: 1 });
  }, () =>
    fetchWithCurl("https://pve.test:8006/api2/json/version", {
      tls: { skipTlsVerify: true, caCert: CA_PEM },
    }));
  assertEquals(calls.length, 1);
  const args = calls[0].args;
  assertEquals(args[0], "-q");
  assertFalse(args.includes("-k"));
  const ca = seen[0];
  assert(ca !== null);
  assertEquals(ca.text, CA_PEM);
  assertFalse(await exists(ca.path), "the CA temp file stays after the call");
});

Deno.test("fetchWithCurl: the CA temp file is removed when curl fails", async () => {
  let path = "";
  await assertRejects(
    () =>
      withMockedCommand((_cmd, args) => {
        path = readCaFile(args)!.path;
        return { stdout: "", stderr: "SSL certificate problem", code: 60 };
      }, () =>
        fetchWithCurl("https://pve.test:8006/api2/json/version", {
          tls: { caCert: CA_PEM },
        })),
    Error,
    "curl failed with code 60",
  );
  assert(path.length > 0);
  assertFalse(await exists(path));
});

Deno.test("fetchWithCurl: skipTlsVerify without caCert gives -k", async () => {
  const { calls } = await withMockedCommand(
    [httpOutput(200, { data: 1 })],
    () =>
      fetchWithCurl("https://pve.test:8006/api2/json/version", {
        tls: { skipTlsVerify: true },
      }),
  );
  assert(calls[0].args.includes("-k"));
  assertFalse(calls[0].args.includes("--cacert"));
});

Deno.test("fetchWithCurl: no TLS settings verifies with the system CAs", async () => {
  const { calls } = await withMockedCommand(
    [httpOutput(200, { data: 1 }), httpOutput(200, { data: 1 })],
    async () => {
      await fetchWithCurl("https://pve.test:8006/api2/json/version", {});
      await fetchWithCurl("https://pve.test:8006/api2/json/version", {
        tls: { skipTlsVerify: false },
      });
    },
  );
  for (const c of calls) {
    assertFalse(c.args.includes("-k"));
    assertFalse(c.args.includes("--cacert"));
  }
});

Deno.test("fetchWithCurl: a bad caCert stops the call before curl runs", async () => {
  const { calls } = await withMockedCommand([], async () => {
    await assertRejects(
      () =>
        fetchWithCurl("https://pve.test:8006/api2/json/version", {
          headers: { Authorization: `PVEAPIToken=${TOKEN_ID}=${TOKEN_SECRET}` },
          tls: { skipTlsVerify: true, caCert: "oops" },
        }),
      Error,
      "not a PEM certificate",
    );
  });
  assertEquals(calls.length, 0);
});

Deno.test("pveCall: reads caCert from the connection (the global args)", async () => {
  const { calls } = await withMockedCommand(
    [httpOutput(200, { data: { version: "8" } })],
    () =>
      pveCall(
        {
          apiUrl: "https://pve.test:8006",
          node: "pve",
          skipTlsVerify: true,
          caCert: CA_PEM,
        } as { skipTlsVerify?: boolean; caCert?: string },
        TOKEN_AUTH,
        "GET",
        "https://pve.test:8006/api2/json/version",
        "read version",
      ),
  );
  assert(calls[0].args.includes("--cacert"));
  assertFalse(calls[0].args.includes("-k"));
});

Deno.test("storage downloadImage pins every call, task polls included", async () => {
  const { context } = createModelTestContext({
    globalArgs: {
      apiUrl: "https://pve.test:8006",
      node: "pve",
      storage: "local",
      skipTlsVerify: true,
      caCert: CA_PEM,
      tokenId: TOKEN_ID,
      tokenSecret: TOKEN_SECRET,
    },
  });
  const outputs = [
    httpOutput(200, { data: [] }),
    httpOutput(200, { data: "UPID:pve:00000001:qmdownload:" }),
    httpOutput(200, { data: { status: "stopped", exitstatus: "OK" } }),
    httpOutput(200, { data: [{ volid: "local:import/new.qcow2" }] }),
  ];
  const cas: string[] = [];
  const { calls } = await withMockedCommand((_cmd, args) => {
    cas.push(readCaFile(args)?.text ?? "");
    return outputs[cas.length - 1];
  }, () =>
    storageModel.methods.downloadImage.execute(
      { url: "https://example.com/new.qcow2", filename: "new.qcow2" },
      context,
    ));
  assertEquals(calls.length, 4);
  for (const c of calls) assertFalse(c.args.includes("-k"));
  assertEquals(cas, [CA_PEM, CA_PEM, CA_PEM, CA_PEM]);
});

// --- real curl against a local HTTPS server ----------------------------------

async function run(cmd: string, args: string[], cwd: string) {
  const out = await new Deno.Command(cmd, { args, cwd, stderr: "piped" })
    .output();
  if (!out.success) {
    throw new Error(
      `${cmd} ${args.join(" ")}: ${new TextDecoder().decode(out.stderr)}`,
    );
  }
}

async function haveOpenssl(): Promise<boolean> {
  try {
    return (await new Deno.Command("openssl", { args: ["version"] }).output())
      .success;
  } catch {
    return false;
  }
}

/** A CA, a server certificate for DNS:localhost signed by it, and a second CA. */
async function makePki(dir: string) {
  await Deno.writeTextFile(
    `${dir}/srv.ext`,
    "subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n",
  );
  for (const ca of ["ca", "other"]) {
    await run("openssl", [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      `${ca}.key`,
      "-out",
      `${ca}.pem`,
      "-days",
      "1",
      "-subj",
      `/CN=${ca} test CA`,
    ], dir);
  }
  await run("openssl", [
    "req",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    "srv.key",
    "-out",
    "srv.csr",
    "-subj",
    "/CN=localhost",
  ], dir);
  await run("openssl", [
    "x509",
    "-req",
    "-in",
    "srv.csr",
    "-CA",
    "ca.pem",
    "-CAkey",
    "ca.key",
    "-CAcreateserial",
    "-out",
    "srv.pem",
    "-days",
    "1",
    "-extfile",
    "srv.ext",
  ], dir);
  const read = (f: string) => Deno.readTextFile(`${dir}/${f}`);
  return {
    ca: await read("ca.pem"),
    other: await read("other.pem"),
    cert: await read("srv.pem"),
    key: await read("srv.key"),
  };
}

Deno.test({
  name: "real curl: caCert accepts the right server and refuses the others",
  ignore: !(await haveOpenssl()),
  fn: async () => {
    const dir = await Deno.makeTempDir({ prefix: "pve-tls-test-" });
    try {
      const pki = await makePki(dir);
      const server = Deno.serve({
        hostname: "127.0.0.1",
        port: 0,
        cert: pki.cert,
        key: pki.key,
        onListen: () => {},
      }, () => Response.json({ data: "pinned" }));
      const port = (server.addr as Deno.NetAddr).port;
      try {
        // The right CA and a name in the certificate: verified.
        const ok = await fetchWithCurl(
          `https://localhost:${port}/api2/json/version`,
          { tls: { skipTlsVerify: true, caCert: pki.ca } },
        );
        assertEquals(ok.status, 200);
        assertEquals(ok.json(), { data: "pinned" });

        // Another CA: refused, though skipTlsVerify is true.
        await assertRejects(
          () =>
            fetchWithCurl(`https://localhost:${port}/api2/json/version`, {
              tls: { skipTlsVerify: true, caCert: pki.other },
            }),
          Error,
          "curl failed",
        );

        // The right CA, but a host name that is not in the certificate.
        await assertRejects(
          () =>
            fetchWithCurl(`https://127.0.0.1:${port}/api2/json/version`, {
              tls: { caCert: pki.ca },
            }),
          Error,
          "curl failed",
        );

        // Not pinned and not skipped: the system CAs do not know this CA.
        await assertRejects(
          () =>
            fetchWithCurl(`https://localhost:${port}/api2/json/version`, {
              tls: { skipTlsVerify: false },
            }),
          Error,
          "curl failed",
        );
      } finally {
        await server.shutdown();
      }
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
});
