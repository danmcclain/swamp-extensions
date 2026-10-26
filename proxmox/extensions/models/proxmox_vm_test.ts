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
import { model } from "./proxmox_vm.ts";
import { extension } from "./proxmox_vm_extras.ts";

const TOKEN_ID = "swamp@pve!automation";
const TOKEN_SECRET = "11111111-2222-3333-4444-555555555555";

const globalArgs = {
  apiUrl: "https://pve.test:8006",
  node: "pve",
  skipTlsVerify: true,
  tokenId: TOKEN_ID,
  tokenSecret: TOKEN_SECRET,
  realm: "pam",
};

function httpOutput(status: number, body: unknown) {
  return {
    stdout: `HTTP/1.1 ${status} OK\r\n\r\n${JSON.stringify(body)}`,
    code: 0,
  };
}

interface Seen {
  method: string;
  url: string;
  headers: string;
}

/** Route curl calls by "METHOD path-suffix"; a route may hold a list (one body per call). */
function router(routes: Record<string, unknown>) {
  const seen: Seen[] = [];
  const queues = new Map<string, unknown[]>();
  const handler = (_cmd: string, args: string[]) => {
    const method = args[args.indexOf("-X") + 1];
    const url = args[args.length - 1];
    const k = args.indexOf("-K");
    seen.push({
      method,
      url,
      headers: k === -1 ? "" : Deno.readTextFileSync(args[k + 1]),
    });
    for (const [key, body] of Object.entries(routes)) {
      const [m, suffix] = key.split(" ");
      if (m !== method || !url.endsWith(suffix)) continue;
      if (!Array.isArray(body)) return httpOutput(200, body);
      if (!queues.has(key)) queues.set(key, [...body]);
      const q = queues.get(key)!;
      return httpOutput(200, q.length > 1 ? q.shift() : q[0]);
    }
    return httpOutput(404, {
      errors: { path: `no route for ${method} ${url}` },
    });
  };
  return { seen, handler };
}

function assertTokenOnly(seen: Seen[]) {
  assert(seen.length > 0);
  for (const s of seen) {
    assertStringIncludes(
      s.headers,
      `Authorization: PVEAPIToken=${TOKEN_ID}=${TOKEN_SECRET}`,
    );
    assertFalse(s.headers.includes("PVEAuthCookie"));
    assertFalse(s.headers.includes("CSRFPreventionToken"));
  }
}

const UPID = "UPID:pve:9:qmstart:";
const taskDone = {
  [`GET /tasks/${encodeURIComponent(UPID)}/status`]: {
    data: { status: "stopped", exitstatus: "OK" },
  },
};

Deno.test("@dmc/proxmox/vm has the keeb base methods and every extra, but no spiceConnect", () => {
  for (
    const m of [
      "lookup",
      "start",
      "stop",
      "create",
      "delete",
      "setBootOrder",
      "setConfig",
      "sync",
    ]
  ) assert(m in model.methods, m);
  for (const m of Object.keys(extension.methods[0])) {
    assert(m in model.methods, `extra ${m}`);
    assertEquals(model.methods[m], extension.methods[0][m]);
  }
  assertFalse("spiceConnect" in model.methods);
  for (const c of Object.keys(extension.checks[0])) {
    assert(c in model.checks, c);
  }
});

Deno.test("start starts a stopped VM with the token and waits for its IP", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const { seen, handler } = router({
    "GET /nodes/pve/qemu": {
      data: [{ vmid: 300, name: "swamp-serve", status: "stopped" }],
    },
    "POST /nodes/pve/qemu/300/status/start": { data: UPID },
    ...taskDone,
    "GET /nodes/pve/qemu/300/agent/network-get-interfaces": {
      data: {
        result: [{
          name: "eth0",
          "ip-addresses": [{
            "ip-address-type": "ipv4",
            "ip-address": "192.0.2.31",
          }],
        }],
      },
    },
  });
  await withMockedCommand(handler, () =>
    model.methods.start.execute(
      {
        vmName: "swamp-serve",
        waitSeconds: 1,
        pollInterval: 1,
        requireIp: true,
      },
      context,
    ));
  assertTokenOnly(seen);
  const data = getWrittenResources()[0].data;
  assertEquals(data.ip, "192.0.2.31");
  assertEquals(data.wasStarted, true);
});

Deno.test("start leaves a running VM alone", async () => {
  const { context } = createModelTestContext({ globalArgs });
  const { seen, handler } = router({
    "GET /nodes/pve/qemu": {
      data: [{ vmid: 300, name: "swamp-serve", status: "running" }],
    },
    "GET /nodes/pve/qemu/300/agent/network-get-interfaces": {
      data: {
        result: [{
          name: "eth0",
          "ip-addresses": [{
            "ip-address-type": "ipv4",
            "ip-address": "192.0.2.31",
          }],
        }],
      },
    },
  });
  await withMockedCommand(handler, () =>
    model.methods.start.execute(
      {
        vmName: "swamp-serve",
        waitSeconds: 1,
        pollInterval: 1,
        requireIp: true,
      },
      context,
    ));
  assertFalse(seen.some((s) => s.method === "POST"));
});

Deno.test("start fails when no IP arrives and requireIp is set", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const { handler } = router({
    "GET /nodes/pve/qemu": {
      data: [{ vmid: 300, name: "swamp-serve", status: "running" }],
    },
    "GET /nodes/pve/qemu/300/agent/network-get-interfaces": {
      data: { result: [] },
    },
  });
  await assertRejects(
    () =>
      withMockedCommand(handler, () =>
        model.methods.start.execute(
          {
            vmName: "swamp-serve",
            waitSeconds: 0,
            pollInterval: 1,
            requireIp: true,
          },
          context,
        )),
    Error,
    "did not return an IP",
  );
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("create is a no-op when a VM with that name exists", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const { seen, handler } = router({
    "GET /nodes/pve/qemu": {
      data: [{ vmid: 300, name: "pxe", status: "stopped" }],
    },
  });
  await withMockedCommand(
    handler,
    () => model.methods.create.execute({ vmName: "pxe" }, context),
  );
  assertEquals(seen.length, 1);
  assertEquals(getWrittenResources()[0].data.vmid, 300);
});

Deno.test("delete stops a running VM, then deletes it", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const { seen, handler } = router({
    "GET /nodes/pve/qemu": {
      data: [{ vmid: 300, name: "old", status: "running" }],
    },
    "POST /nodes/pve/qemu/300/status/stop": { data: UPID },
    "DELETE /nodes/pve/qemu/300": { data: UPID },
    ...taskDone,
  });
  await withMockedCommand(
    handler,
    () => model.methods.delete.execute({ vmName: "old" }, context),
  );
  assertTokenOnly(seen);
  assertEquals(
    seen.filter((s) => s.method !== "GET").map((s) => s.method),
    ["POST", "DELETE"],
  );
  assertEquals(getWrittenResources()[0].data.status, "deleted");
});

Deno.test("delete succeeds when the VM is already gone", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const { handler } = router({ "GET /nodes/pve/qemu": { data: [] } });
  const { result } = await withMockedCommand(
    handler,
    () => model.methods.delete.execute({ vmName: "gone" }, context),
  );
  assertEquals(result.dataHandles.length, 0);
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("an extra method (getConfig) runs on @dmc/proxmox/vm with the token", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const { seen, handler } = router({
    "GET /nodes/pve/qemu": {
      data: [{ vmid: 300, name: "swamp-serve", status: "running" }],
    },
    "GET /nodes/pve/qemu/300/config": {
      data: { cores: 2, name: "swamp-serve" },
    },
  });
  await withMockedCommand(handler, () =>
    model.methods.getConfig.execute(
      { vmName: "swamp-serve", kind: "qemu" },
      context,
    ));
  assertTokenOnly(seen);
  assertEquals(getWrittenResources()[0].data.vmid, 300);
});

Deno.test("live extra checks pass without a call when auth is unresolved", async () => {
  const ctx = {
    globalArgs: {
      ...globalArgs,
      tokenSecret: "${{ vault.get(infra, PROXMOX_TOKEN_SECRET) }}",
    },
    methodName: "snapshot",
    unresolvedMethodArgs: { vmName: "swamp-serve", name: "pre-a" },
  };
  const { calls } = await withMockedCommand([], async () => {
    for (
      const [name, check] of Object.entries(
        model.checks as Record<
          string,
          {
            labels?: string[];
            execute: (c: unknown) => Promise<{ pass: boolean }>;
          }
        >,
      )
    ) {
      if (!check.labels?.includes("live")) continue;
      assertEquals((await check.execute(ctx)).pass, true, name);
    }
  });
  assertEquals(calls.length, 0);
});

Deno.test("valid-connection rejects credentials in apiUrl and skips unresolved values", async () => {
  const check = model.checks["valid-connection"];
  const bad = await check.execute({
    globalArgs: { ...globalArgs, apiUrl: "https://root:pw@pve.test:8006" },
  });
  assertFalse(bad.pass);
  const unresolved = await check.execute({
    globalArgs: {
      ...globalArgs,
      apiUrl: "${{ vault.get(local-secrets, PROXMOX_URL) }}",
    },
  });
  assert(unresolved.pass);
});
