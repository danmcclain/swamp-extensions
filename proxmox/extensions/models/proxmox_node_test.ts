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
import { model, parseClusterGuests, pickLxcIpv4 } from "./proxmox_node.ts";

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
  body: string | null;
  headers: string;
}

/** Route curl calls by "METHOD path-suffix"; records each call's method, URL, body and header file. */
function router(routes: Record<string, unknown>) {
  const seen: Seen[] = [];
  const handler = (_cmd: string, args: string[]) => {
    const method = args[args.indexOf("-X") + 1];
    const url = args[args.length - 1];
    const k = args.indexOf("-K");
    const d = args.indexOf("-d");
    seen.push({
      method,
      url,
      body: d === -1 ? null : args[d + 1],
      headers: k === -1 ? "" : Deno.readTextFileSync(args[k + 1]),
    });
    for (const [key, body] of Object.entries(routes)) {
      const [m, suffix] = key.split(" ");
      if (m === method && url.endsWith(suffix)) return httpOutput(200, body);
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
  assertFalse(seen.some((s) => s.url.includes("/access/ticket")));
}

Deno.test("node status reads /status with the API token", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const { seen, handler } = router({
    "GET /nodes/pve/status": {
      data: {
        memory: { total: 100, used: 40 },
        cpuinfo: { cpus: 8 },
        cpu: 0.25,
        uptime: 99,
      },
    },
  });
  await withMockedCommand(
    handler,
    () => model.methods.status.execute({}, context),
  );
  assertTokenOnly(seen);
  const data = getWrittenResources()[0].data;
  assertEquals(data.memoryFree, 60);
  assertEquals(data.cpuCount, 8);
});

Deno.test("listGuests lists qemu + lxc with IPs from each guest's node", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const { seen, handler } = router({
    "GET /cluster/resources?type=vm": {
      data: [
        {
          type: "lxc",
          vmid: 200,
          name: "forgejo",
          status: "running",
          node: "pve2",
        },
        {
          type: "qemu",
          vmid: 101,
          name: "tsidp",
          status: "running",
          node: "pve",
        },
        {
          type: "qemu",
          vmid: 102,
          name: "off",
          status: "stopped",
          node: "pve",
        },
        { type: "storage", id: "local" },
      ],
    },
    "GET /nodes/pve/qemu/101/agent/network-get-interfaces": {
      data: {
        result: [
          {
            name: "lo",
            "ip-addresses": [{
              "ip-address-type": "ipv4",
              "ip-address": "127.0.0.1",
            }],
          },
          {
            name: "eth0",
            "ip-addresses": [{
              "ip-address-type": "ipv4",
              "ip-address": "192.0.2.11",
            }],
          },
        ],
      },
    },
    "GET /nodes/pve2/lxc/200/interfaces": {
      data: [{ name: "lo", inet: "127.0.0.1/8" }, {
        name: "eth0",
        inet: "192.0.2.20/24",
      }],
    },
  });
  await withMockedCommand(
    handler,
    () => model.methods.listGuests.execute({}, context),
  );
  assertTokenOnly(seen);
  const data = getWrittenResources()[0].data;
  assertEquals(data.total, 3);
  assertEquals(
    data.guests.map((g: { vmid: number; ip: string | null }) => [g.vmid, g.ip]),
    [[101, "192.0.2.11"], [102, null], [200, "192.0.2.20"]],
  );
  assertFalse(
    seen.some((s) => s.url.includes("/qemu/102/")),
    "no IP lookup for a stopped guest",
  );
});

Deno.test("snapshotVm posts the snapshot, waits for the task, records it", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const { seen, handler } = router({
    "POST /nodes/pve/qemu/101/snapshot": { data: "UPID:pve:1:qmsnapshot:" },
    [`GET /tasks/${encodeURIComponent("UPID:pve:1:qmsnapshot:")}/status`]: {
      data: { status: "stopped", exitstatus: "OK" },
    },
  });
  await withMockedCommand(handler, () =>
    model.methods.snapshotVm.execute(
      { vmid: 101, name: "preupdate-a", description: "before update" },
      context,
    ));
  assertTokenOnly(seen);
  const form = new URLSearchParams(seen[0].body ?? "");
  assertEquals(form.get("snapname"), "preupdate-a");
  assertEquals(form.get("description"), "before update");
  const rec = getWrittenResources()[0];
  assertEquals(rec.name, "snapshot-101");
  assertEquals(rec.data.action, "snapshot");
  assertEquals(rec.data.exitStatus, "OK");
});

Deno.test("snapshotVm throws before writing when the task fails", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const { handler } = router({
    "POST /nodes/pve/qemu/101/snapshot": { data: "UPID:pve:2:qmsnapshot:" },
    [`GET /tasks/${encodeURIComponent("UPID:pve:2:qmsnapshot:")}/status`]: {
      data: {
        status: "stopped",
        exitstatus: "snapshot feature is not available",
      },
    },
  });
  await assertRejects(
    () =>
      withMockedCommand(handler, () =>
        model.methods.snapshotVm.execute(
          { vmid: 101, name: "", description: "" },
          context,
        )),
    Error,
    "snapshot failed",
  );
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("rollbackVm and deleteVmSnapshot hit the snapshot paths", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const upid = "UPID:pve:3:x:";
  const { seen, handler } = router({
    "POST /nodes/pve/qemu/101/snapshot/pre-a/rollback": { data: upid },
    "DELETE /nodes/pve/qemu/101/snapshot/pre-a": { data: upid },
    [`GET /tasks/${encodeURIComponent(upid)}/status`]: {
      data: { status: "stopped", exitstatus: "OK" },
    },
  });
  await withMockedCommand(handler, async () => {
    await model.methods.rollbackVm.execute(
      { vmid: 101, name: "pre-a" },
      context,
    );
    await model.methods.deleteVmSnapshot.execute(
      { vmid: 101, name: "pre-a" },
      context,
    );
  });
  assertTokenOnly(seen);
  assertEquals(
    getWrittenResources().map((r: { data: { action: string } }) =>
      r.data.action
    ),
    ["rollback", "delete"],
  );
});

Deno.test("listVmSnapshots drops the 'current' pseudo-snapshot", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const { handler } = router({
    "GET /nodes/pve/qemu/101/snapshot": {
      data: [
        { name: "pre-a", description: "x" },
        { name: "current", description: "You are here!" },
        { name: "pre-b" },
      ],
    },
  });
  await withMockedCommand(
    handler,
    () => model.methods.listVmSnapshots.execute({ vmid: 101 }, context),
  );
  assertEquals(getWrittenResources()[0].data.snapshots, [
    { name: "pre-a", description: "x" },
    { name: "pre-b", description: null },
  ]);
});

Deno.test("snapshot name arguments reject path characters", () => {
  const args = model.methods.rollbackVm.arguments;
  assert(args.safeParse({ vmid: 101, name: "pre-a_1" }).success);
  for (const bad of ["../x", "a/b", "1abc", "", "a b"]) {
    assertFalse(args.safeParse({ vmid: 101, name: bad }).success, bad);
  }
  assert(
    model.methods.snapshotVm.arguments.safeParse({ vmid: 101 }).success,
    "empty name means the default preupdate-<timestamp>",
  );
});

Deno.test("node-reachable passes without a call when auth is unresolved", async () => {
  const { result, calls } = await withMockedCommand(
    [],
    () =>
      model.checks["node-reachable"].execute({
        globalArgs: {
          ...globalArgs,
          tokenSecret: "${{ vault.get(infra, PROXMOX_TOKEN_SECRET) }}",
        },
      }),
  );
  assertEquals(result, { pass: true });
  assertEquals(calls.length, 0);
});

Deno.test("node-reachable reports the API error", async () => {
  const { result } = await withMockedCommand(
    [{ stdout: "HTTP/1.1 401 Unauthorized\r\n\r\n", code: 0 }],
    () => model.checks["node-reachable"].execute({ globalArgs }),
  );
  assertFalse(result.pass);
  assertStringIncludes(result.errors[0], "HTTP 401");
});

Deno.test("parseClusterGuests and pickLxcIpv4 handle odd payloads", () => {
  assertEquals(parseClusterGuests([{ type: "qemu", vmid: "7", node: "n" }]), [
    { type: "qemu", vmid: 7, name: "7", status: "unknown", node: "n" },
  ]);
  assertEquals(pickLxcIpv4(null), null);
  assertEquals(pickLxcIpv4([{ name: "eth0", inet: "" }]), null);
});
