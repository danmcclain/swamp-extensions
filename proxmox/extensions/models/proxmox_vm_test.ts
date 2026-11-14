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
import * as extras from "./proxmox_vm_extras.ts";

const { vmExtraChecks, vmExtraMethods } = extras;

const TOKEN_ID = "swamp@pve!automation";
const TOKEN_SECRET = "11111111-2222-3333-4444-555555555555";

const globalArgs = {
  apiUrl: "https://pve.test:8006",
  node: "pve",
  skipTlsVerify: true,
  tokenId: TOKEN_ID,
  tokenSecret: TOKEN_SECRET,
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

Deno.test("@dmc/proxmox/vm has the base methods and every extra, but no spiceConnect", () => {
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
  for (const m of Object.keys(vmExtraMethods)) {
    assert(m in model.methods, `extra ${m}`);
    assertEquals(model.methods[m], vmExtraMethods[m]);
  }
  assertFalse("spiceConnect" in model.methods);
  for (const c of Object.keys(vmExtraChecks)) {
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

// ---- clone and convertToTemplate ---------------------------------------------

interface SeenWithBody extends Seen {
  body: string | null;
}

/** Like `router`, but also records each request's form body. */
function bodyRouter(routes: Record<string, unknown>) {
  const inner = router(routes);
  const seen: SeenWithBody[] = [];
  const handler = (cmd: string, args: string[]) => {
    const i = args.indexOf("--data-binary");
    const body = i === -1
      ? null
      : Deno.readTextFileSync(args[i + 1].replace(/^@/, ""));
    const out = inner.handler(cmd, args);
    seen.push({ ...inner.seen[inner.seen.length - 1], body });
    return out;
  };
  return { seen, handler };
}

const CLONE_UPID = "UPID:pve:9:qmclone:";
const cloneDone = {
  [`GET /tasks/${encodeURIComponent(CLONE_UPID)}/status`]: {
    data: { status: "stopped", exitstatus: "OK" },
  },
};
const TEMPLATE_LIST = {
  data: [
    { vmid: 9000, name: "ci-runner-template", status: "stopped", template: 1 },
    { vmid: 300, name: "swamp-serve", status: "running" },
  ],
};

/** Run one vm method; errors are returned, not thrown. */
async function runVm(
  method: "clone" | "convertToTemplate" | "shutdown",
  routes: Record<string, unknown>,
  input: Record<string, unknown>,
) {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const r = bodyRouter(routes);
  const args = model.methods[method].arguments.parse(input);
  let error: Error | null = null;
  try {
    await withMockedCommand(
      r.handler,
      // deno-lint-ignore no-explicit-any
      () => (model.methods[method].execute as any)(args, context),
    );
  } catch (e) {
    error = e as Error;
  }
  return { seen: r.seen, written: getWrittenResources(), error };
}

Deno.test("@dmc/proxmox/vm has clone and convertToTemplate", () => {
  assert("clone" in model.methods);
  assert("convertToTemplate" in model.methods);
});

Deno.test("clone makes a linked clone of a template into a pool, with the next id, and records the time", async () => {
  const r = await runVm("clone", {
    "GET /nodes/pve/qemu": TEMPLATE_LIST,
    "GET /cluster/nextid": { data: "9101" },
    "POST /nodes/pve/qemu/9000/clone": { data: CLONE_UPID },
    ...cloneDone,
  }, { source: "ci-runner-template", vmName: "ci-runner-1", pool: "ci" });
  assertEquals(r.error, null);
  assertTokenOnly(r.seen);
  const post = r.seen.filter((s) => s.method === "POST");
  assertEquals(post.length, 1);
  assertEquals(Object.fromEntries(new URLSearchParams(post[0].body ?? "")), {
    newid: "9101",
    name: "ci-runner-1",
    full: "0",
    pool: "ci",
  });
  const data = r.written[0].data as Record<string, unknown>;
  assertEquals(data.vmid, 9101);
  assertEquals(data.vmName, "ci-runner-1");
  assertEquals(data.source, "ci-runner-template");
  assertEquals(data.pool, "ci");
  assertEquals(data.linked, true);
  assertEquals(typeof data.durationMs, "number");
});

Deno.test("clone with linked false makes a full copy on the given storage and id", async () => {
  const r = await runVm("clone", {
    "GET /nodes/pve/qemu": TEMPLATE_LIST,
    "POST /nodes/pve/qemu/300/clone": { data: CLONE_UPID },
    ...cloneDone,
  }, {
    source: "swamp-serve",
    vmName: "serve-copy",
    newid: 9200,
    linked: false,
    storage: "vm-nfs",
  });
  assertEquals(r.error, null);
  assertFalse(r.seen.some((s) => s.url.endsWith("/cluster/nextid")));
  const post = r.seen.find((s) => s.method === "POST")!;
  assertEquals(Object.fromEntries(new URLSearchParams(post.body ?? "")), {
    newid: "9200",
    name: "serve-copy",
    full: "1",
    storage: "vm-nfs",
  });
});

Deno.test("clone refuses a linked clone of a VM that is not a template, with no write", async () => {
  const r = await runVm("clone", {
    "GET /nodes/pve/qemu": TEMPLATE_LIST,
    "GET /cluster/nextid": { data: "9101" },
  }, { source: "swamp-serve", vmName: "ci-runner-1" });
  assert(r.error);
  assertStringIncludes(r.error.message, "is not a template");
  assertFalse(r.seen.some((s) => s.method !== "GET"));
  assertEquals(r.written, []);
});

Deno.test("clone is a no-op when a VM with the new name exists", async () => {
  const r = await runVm("clone", {
    "GET /nodes/pve/qemu": {
      data: [...TEMPLATE_LIST.data, {
        vmid: 9101,
        name: "ci-runner-1",
        status: "running",
      }],
    },
  }, { source: "ci-runner-template", vmName: "ci-runner-1" });
  assertEquals(r.error, null);
  assertFalse(r.seen.some((s) => s.method !== "GET"));
  assertEquals((r.written[0].data as { vmid: number }).vmid, 9101);
});

Deno.test("clone fails when the source is unknown or the task fails", async () => {
  const missing = await runVm("clone", {
    "GET /nodes/pve/qemu": TEMPLATE_LIST,
  }, { source: "nope", vmName: "ci-runner-1" });
  assert(missing.error);
  assertStringIncludes(missing.error.message, 'VM "nope" not found');

  const failed = await runVm("clone", {
    "GET /nodes/pve/qemu": TEMPLATE_LIST,
    "GET /cluster/nextid": { data: "9101" },
    "POST /nodes/pve/qemu/9000/clone": { data: CLONE_UPID },
    [`GET /tasks/${encodeURIComponent(CLONE_UPID)}/status`]: {
      data: { status: "stopped", exitstatus: "permission denied" },
    },
  }, { source: "ci-runner-template", vmName: "ci-runner-1" });
  assert(failed.error);
  assertStringIncludes(failed.error.message, "permission denied");
  assertEquals(failed.written, []);
});

Deno.test("clone arguments refuse a storage on a linked clone and unsafe names", () => {
  const parse = (input: Record<string, unknown>) =>
    model.methods.clone.arguments.safeParse({
      source: "t",
      vmName: "ci-runner-1",
      ...input,
    }).success;
  assert(parse({}));
  assertFalse(parse({ storage: "vm-nfs" }));
  assert(parse({ storage: "vm-nfs", linked: false }));
  assertFalse(parse({ vmName: "bad name" }));
  assertFalse(parse({ vmName: "-bad" }));
  assertFalse(parse({ pool: "ci/x" }));
  assertFalse(parse({ newid: 99 }));
  assertEquals(
    model.methods.clone.arguments.parse({ source: "t", vmName: "x" }).linked,
    true,
  );
});

Deno.test("convertToTemplate posts /template for a stopped VM and waits for the task", async () => {
  const r = await runVm("convertToTemplate", {
    "GET /nodes/pve/qemu": {
      data: [{ vmid: 9000, name: "ci-runner-template", status: "stopped" }],
    },
    "POST /nodes/pve/qemu/9000/template": { data: UPID },
    ...taskDone,
  }, { vmName: "ci-runner-template" });
  assertEquals(r.error, null);
  assertTokenOnly(r.seen);
  assertEquals(
    r.seen.filter((s) => s.method === "POST").map((s) =>
      new URL(s.url).pathname
    ),
    ["/api2/json/nodes/pve/qemu/9000/template"],
  );
  assert(r.seen.some((s) => s.url.includes("/tasks/")));
  assertEquals((r.written[0].data as { template: boolean }).template, true);
});

Deno.test("convertToTemplate is a no-op for a template and refuses a running VM", async () => {
  const done = await runVm("convertToTemplate", {
    "GET /nodes/pve/qemu": TEMPLATE_LIST,
  }, { vmName: "ci-runner-template" });
  assertEquals(done.error, null);
  assertFalse(done.seen.some((s) => s.method !== "GET"));

  const running = await runVm("convertToTemplate", {
    "GET /nodes/pve/qemu": TEMPLATE_LIST,
  }, { vmName: "swamp-serve" });
  assert(running.error);
  assertStringIncludes(running.error.message, "is running");
  assertFalse(running.seen.some((s) => s.method !== "GET"));
  assertEquals(running.written, []);
});

const SHUTDOWN_UPID = "UPID:pve:9:qmshutdown:";
const shutdownTask = (exitstatus: string) => ({
  [`GET /tasks/${encodeURIComponent(SHUTDOWN_UPID)}/status`]: {
    data: { status: "stopped", exitstatus },
  },
});
const buildVm = (status: string) => ({
  data: [{ vmid: 9100, name: "runner-template", status }],
});

Deno.test("@dmc/proxmox/vm has shutdown", () => {
  assert("shutdown" in model.methods);
});

Deno.test("shutdown asks for a clean shutdown with no force stop, waits, and checks the VM is stopped", async () => {
  const r = await runVm("shutdown", {
    "GET /nodes/pve/qemu": [buildVm("running"), buildVm("stopped")],
    "POST /nodes/pve/qemu/9100/status/shutdown": { data: SHUTDOWN_UPID },
    ...shutdownTask("OK"),
  }, { vmName: "runner-template", timeoutSeconds: 120 });
  assertEquals(r.error, null);
  assertTokenOnly(r.seen);
  const post = r.seen.filter((s) => s.method === "POST");
  assertEquals(post.length, 1);
  assertEquals(Object.fromEntries(new URLSearchParams(post[0].body ?? "")), {
    timeout: "120",
    forceStop: "0",
  });
  assert(r.seen.some((s) => s.url.includes("/tasks/")));
  const data = r.written[0].data as Record<string, unknown>;
  assertEquals(data.vmid, 9100);
  assertEquals(data.status, "stopped");
  assertEquals(data.success, true);
});

Deno.test("shutdown is a no-op for a stopped VM", async () => {
  const r = await runVm("shutdown", {
    "GET /nodes/pve/qemu": buildVm("stopped"),
  }, { vmName: "runner-template" });
  assertEquals(r.error, null);
  assertFalse(r.seen.some((s) => s.method !== "GET"));
  assertEquals((r.written[0].data as { status: string }).status, "stopped");
});

Deno.test("shutdown fails, with no data, when the guest does not power off in time", async () => {
  const r = await runVm("shutdown", {
    "GET /nodes/pve/qemu": buildVm("running"),
    "POST /nodes/pve/qemu/9100/status/shutdown": { data: SHUTDOWN_UPID },
    ...shutdownTask("VM quit/powerdown failed"),
  }, { vmName: "runner-template" });
  assert(r.error);
  assertStringIncludes(r.error.message, "did not shut down within 300s");
  assertEquals(r.written, []);
});

Deno.test("shutdown fails when the VM still runs after a task that reports OK", async () => {
  const r = await runVm("shutdown", {
    "GET /nodes/pve/qemu": buildVm("running"),
    "POST /nodes/pve/qemu/9100/status/shutdown": { data: SHUTDOWN_UPID },
    ...shutdownTask("OK"),
  }, { vmName: "runner-template" });
  assert(r.error);
  assertStringIncludes(r.error.message, "is running after the shutdown task");
  assertEquals(r.written, []);
});

Deno.test("shutdown arguments: timeoutSeconds defaults to 300 and stays in 10..3600", () => {
  const args = model.methods.shutdown.arguments;
  assertEquals(args.parse({ vmName: "x" }).timeoutSeconds, 300);
  assertFalse(args.safeParse({ vmName: "x", timeoutSeconds: 5 }).success);
  assertFalse(args.safeParse({ vmName: "x", timeoutSeconds: 4000 }).success);
  assertFalse(args.safeParse({ vmName: "x", timeoutSeconds: 30.5 }).success);
});
