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
  bridgeAclPath,
  guestNode,
  model,
  parseClusterGuests,
  parseClusterStatus,
  parsePermissions,
  pickLxcIpv4,
} from "./proxmox_node.ts";

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
  body: string | null;
  headers: string;
}

/** The request body curl sends from its 0600 --data-binary file, or null. */
function curlBody(args: string[]): string | null {
  const i = args.indexOf("--data-binary");
  return i === -1 ? null : Deno.readTextFileSync(args[i + 1].replace(/^@/, ""));
}

/** Route curl calls by "METHOD path-suffix"; records each call's method, URL, body and header file. */
function router(routes: Record<string, unknown>) {
  const seen: Seen[] = [];
  const handler = (_cmd: string, args: string[]) => {
    const method = args[args.indexOf("-X") + 1];
    const url = args[args.length - 1];
    const k = args.indexOf("-K");
    seen.push({
      method,
      url,
      body: curlBody(args),
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

/** /cluster/resources with VM 101 on node pve: the snapshot methods look the guest up first. */
const VM_101_ON_PVE = {
  "GET /cluster/resources?type=vm": {
    data: [{
      type: "qemu",
      vmid: 101,
      node: "pve",
      name: "web",
      status: "running",
    }],
  },
};

Deno.test("snapshotVm posts the snapshot, waits for the task, records it", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const { seen, handler } = router({
    ...VM_101_ON_PVE,
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
  assertEquals(seen[0].method, "GET", "the guest is looked up first");
  const form = new URLSearchParams(
    seen.find((x) => x.method === "POST")?.body ?? "",
  );
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
    ...VM_101_ON_PVE,
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
    ...VM_101_ON_PVE,
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
    ...VM_101_ON_PVE,
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

/** /cluster/resources with CT 201 on node pve2, not on the configured node pve. */
const CT_201_ON_PVE2 = {
  "GET /cluster/resources?type=vm": {
    data: [{
      type: "lxc",
      vmid: 201,
      node: "pve2",
      name: "forgejo",
      status: "running",
    }],
  },
};

type TestContext = ReturnType<typeof createModelTestContext>["context"];

Deno.test("guestNode returns the node a guest runs on", () => {
  assertEquals(
    guestNode([{ type: "lxc", vmid: 201, node: "pve2" }], "lxc", 201),
    "pve2",
  );
});

Deno.test("guestNode throws for a guest that is not listed, listed twice, or the other kind", () => {
  assertThrows(
    () => guestNode([], "lxc", 201),
    Error,
    "CT 201 is not in /cluster/resources",
  );
  assertThrows(
    () =>
      guestNode(
        [
          { type: "qemu", vmid: 101, node: "pve" },
          { type: "qemu", vmid: 101, node: "pve2" },
        ],
        "qemu",
        101,
      ),
    Error,
    "guest 101 is listed more than once in /cluster/resources",
  );
  assertThrows(
    () => guestNode([{ type: "qemu", vmid: 101, node: "pve" }], "lxc", 101),
    Error,
    "guest 101 is a VM, not a CT",
  );
  assertThrows(
    () => guestNode([{ type: "lxc", vmid: 201, node: "pve2" }], "qemu", 201),
    Error,
    "guest 201 is a CT, not a VM",
  );
});

Deno.test("guestNode refuses a node name that is not safe in a path", () => {
  for (const node of ["../pve", "pve/2", "-pve", "pve 2", "", "a".repeat(64)]) {
    assertThrows(
      () => guestNode([{ type: "lxc", vmid: 201, node }], "lxc", 201),
      Error,
      "unexpected node name",
      JSON.stringify(node),
    );
  }
  assertEquals(
    guestNode([{ type: "lxc", vmid: 201, node: "a".repeat(63) }], "lxc", 201),
    "a".repeat(63),
  );
});

Deno.test("snapshotCt posts to the node a CT runs on, not the configured node", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const upid = "UPID:pve2:1:vzsnapshot:";
  const { seen, handler } = router({
    ...CT_201_ON_PVE2,
    "POST /nodes/pve2/lxc/201/snapshot": { data: upid },
    [`GET /nodes/pve2/tasks/${encodeURIComponent(upid)}/status`]: {
      data: { status: "stopped", exitstatus: "OK" },
    },
  });
  await withMockedCommand(handler, () =>
    model.methods.snapshotCt.execute(
      { vmid: 201, name: "pre-a", description: "" },
      context,
    ));
  assertTokenOnly(seen);
  assertEquals(seen[0].method, "GET", "the guest is looked up first");
  const post = seen.find((x) => x.method === "POST");
  assertEquals(
    new URL(post?.url ?? "").pathname,
    "/api2/json/nodes/pve2/lxc/201/snapshot",
  );
  assertEquals(new URLSearchParams(post?.body ?? "").get("snapname"), "pre-a");
  assert(
    seen.some((x) => x.url.includes("/nodes/pve2/tasks/")),
    "the task is waited for on pve2",
  );
  assertFalse(
    seen.some((x) => x.url.includes("/nodes/pve/")),
    "no call goes to the configured node",
  );
  const rec = getWrittenResources()[0];
  assertEquals(rec.name, "snapshot-201");
  assertEquals(rec.data.type, "lxc");
  assertEquals(rec.data.node, "pve2");
  assertEquals(rec.data.action, "snapshot");
  assertEquals(rec.data.exitStatus, "OK");
});

Deno.test("rollbackCt sends start=1 by default and no body with start false", async () => {
  const { context } = createModelTestContext({ globalArgs });
  const upid = "UPID:pve2:4:vzrollback:";
  const { seen, handler } = router({
    ...CT_201_ON_PVE2,
    "POST /nodes/pve2/lxc/201/snapshot/pre-a/rollback": { data: upid },
    [`GET /nodes/pve2/tasks/${encodeURIComponent(upid)}/status`]: {
      data: { status: "stopped", exitstatus: "OK" },
    },
  });
  const byDefault = model.methods.rollbackCt.arguments.parse({
    vmid: 201,
    name: "pre-a",
  });
  const noStart = model.methods.rollbackCt.arguments.parse({
    vmid: 201,
    name: "pre-a",
    start: false,
  });
  assertEquals(byDefault.start, true);
  await withMockedCommand(handler, async () => {
    await model.methods.rollbackCt.execute(byDefault, context);
    await model.methods.rollbackCt.execute(noStart, context);
    // A direct call without start starts the CT too.
    await model.methods.rollbackCt.execute(
      { vmid: 201, name: "pre-a" },
      context,
    );
  });
  assertTokenOnly(seen);
  const posts = seen.filter((x) => x.method === "POST");
  assertEquals(posts.map((x) => new URL(x.url).pathname), [
    "/api2/json/nodes/pve2/lxc/201/snapshot/pre-a/rollback",
    "/api2/json/nodes/pve2/lxc/201/snapshot/pre-a/rollback",
    "/api2/json/nodes/pve2/lxc/201/snapshot/pre-a/rollback",
  ]);
  assertEquals(posts.map((x) => x.body), ["start=1", null, "start=1"]);
});

Deno.test("listCtSnapshots drops 'current' and deleteCtSnapshot uses the CT's node", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const upid = "UPID:pve2:5:vzdelsnapshot:";
  const { seen, handler } = router({
    ...CT_201_ON_PVE2,
    "GET /nodes/pve2/lxc/201/snapshot": {
      data: [
        { name: "pre-a", description: "x" },
        { name: "current", description: "You are here!" },
        { name: "pre-b" },
      ],
    },
    "DELETE /nodes/pve2/lxc/201/snapshot/pre-a": { data: upid },
    [`GET /nodes/pve2/tasks/${encodeURIComponent(upid)}/status`]: {
      data: { status: "stopped", exitstatus: "OK" },
    },
  });
  await withMockedCommand(handler, async () => {
    await model.methods.listCtSnapshots.execute({ vmid: 201 }, context);
    await model.methods.deleteCtSnapshot.execute(
      { vmid: 201, name: "pre-a" },
      context,
    );
  });
  assertTokenOnly(seen);
  assertEquals(
    seen.filter((x) => x.method === "GET" && x.url.includes("/lxc/201/")).map(
      (x) => new URL(x.url).pathname,
    ),
    ["/api2/json/nodes/pve2/lxc/201/snapshot"],
  );
  assertEquals(
    seen.filter((x) => x.method === "DELETE").map((x) =>
      new URL(x.url).pathname
    ),
    ["/api2/json/nodes/pve2/lxc/201/snapshot/pre-a"],
  );
  assertFalse(seen.some((x) => x.url.includes("/nodes/pve/")));
  const [list, del] = getWrittenResources();
  assertEquals(list.data.snapshots, [
    { name: "pre-a", description: "x" },
    { name: "pre-b", description: null },
  ]);
  assertEquals(del.data.action, "delete");
});

Deno.test("CT and VM snapshot methods fail closed on the wrong kind or an unknown id", async () => {
  const cases: Array<
    [Record<string, unknown>, (c: TestContext) => Promise<unknown>, string]
  > = [
    [
      VM_101_ON_PVE,
      (c) =>
        model.methods.snapshotCt.execute(
          { vmid: 101, name: "pre-a", description: "" },
          c,
        ),
      "guest 101 is a VM, not a CT",
    ],
    [
      VM_101_ON_PVE,
      (c) => model.methods.rollbackCt.execute({ vmid: 101, name: "pre-a" }, c),
      "guest 101 is a VM, not a CT",
    ],
    [
      VM_101_ON_PVE,
      (c) => model.methods.listCtSnapshots.execute({ vmid: 101 }, c),
      "guest 101 is a VM, not a CT",
    ],
    [
      VM_101_ON_PVE,
      (c) =>
        model.methods.deleteCtSnapshot.execute(
          { vmid: 101, name: "pre-a" },
          c,
        ),
      "guest 101 is a VM, not a CT",
    ],
    [
      CT_201_ON_PVE2,
      (c) =>
        model.methods.snapshotVm.execute(
          { vmid: 201, name: "pre-a", description: "" },
          c,
        ),
      "guest 201 is a CT, not a VM",
    ],
    [
      CT_201_ON_PVE2,
      (c) => model.methods.rollbackVm.execute({ vmid: 201, name: "pre-a" }, c),
      "guest 201 is a CT, not a VM",
    ],
    [
      CT_201_ON_PVE2,
      (c) =>
        model.methods.deleteVmSnapshot.execute(
          { vmid: 201, name: "pre-a" },
          c,
        ),
      "guest 201 is a CT, not a VM",
    ],
    [
      CT_201_ON_PVE2,
      (c) =>
        model.methods.snapshotCt.execute(
          { vmid: 999, name: "pre-a", description: "" },
          c,
        ),
      "CT 999 is not in /cluster/resources",
    ],
  ];
  for (const [routes, run, message] of cases) {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs,
    });
    const { seen, handler } = router(routes);
    await assertRejects(
      () => withMockedCommand(handler, () => run(context)),
      Error,
      message,
    );
    assertEquals(seen.length, 1, `${message}: only the lookup is called`);
    assertEquals(seen[0].method, "GET");
    assertEquals(
      new URL(seen[0].url).pathname,
      "/api2/json/cluster/resources",
    );
    assertEquals(getWrittenResources().length, 0, message);
  }
});

Deno.test("snapshotVm posts to the node a VM runs on after it migrated", async () => {
  const { context } = createModelTestContext({ globalArgs });
  const upid = "UPID:pve2:6:qmsnapshot:";
  const { seen, handler } = router({
    "GET /cluster/resources?type=vm": {
      data: [{
        type: "qemu",
        vmid: 101,
        node: "pve2",
        name: "web",
        status: "running",
      }],
    },
    "POST /nodes/pve2/qemu/101/snapshot": { data: upid },
    [`GET /nodes/pve2/tasks/${encodeURIComponent(upid)}/status`]: {
      data: { status: "stopped", exitstatus: "OK" },
    },
  });
  await withMockedCommand(handler, () =>
    model.methods.snapshotVm.execute(
      { vmid: 101, name: "pre-a", description: "" },
      context,
    ));
  assertTokenOnly(seen);
  const post = seen.find((x) => x.method === "POST");
  assertEquals(
    new URL(post?.url ?? "").pathname,
    "/api2/json/nodes/pve2/qemu/101/snapshot",
  );
  assertFalse(seen.some((x) => x.url.includes("/nodes/pve/")));
});

Deno.test("CT method arguments reject a bad snapshot name and a non-positive vmid", () => {
  const args = model.methods.rollbackCt.arguments;
  assert(args.safeParse({ vmid: 201, name: "pre-a_1" }).success);
  for (const bad of ["../x", "a/b", "1abc", "", "a b"]) {
    assertFalse(args.safeParse({ vmid: 201, name: bad }).success, bad);
  }
  for (const vmid of [0, -1]) {
    assertFalse(
      args.safeParse({ vmid, name: "pre-a" }).success,
      String(vmid),
    );
  }
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

Deno.test("node-reachable reads /version, so a token without node access passes", async () => {
  const { seen, handler } = router({
    "GET /version": { data: { version: "8.2.4" } },
  });
  const { result } = await withMockedCommand(
    handler,
    () => model.checks["node-reachable"].execute({ globalArgs }),
  );
  assertEquals(result, { pass: true });
  assertEquals(seen.length, 1);
  assertTokenOnly(seen);
  assert(seen[0].url.endsWith("/api2/json/version"), seen[0].url);
  assertFalse(seen[0].url.includes("/nodes/"));
});

Deno.test("parseClusterGuests and pickLxcIpv4 handle odd payloads", () => {
  assertEquals(parseClusterGuests([{ type: "qemu", vmid: "7", node: "n" }]), [
    { type: "qemu", vmid: 7, name: "7", status: "unknown", node: "n" },
  ]);
  assertEquals(pickLxcIpv4(null), null);
  assertEquals(pickLxcIpv4([{ name: "eth0", inet: "" }]), null);
});

Deno.test("permissions writes the caller's privileges, sorted by path and name", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const { seen, handler } = router({
    "GET /access/permissions": {
      data: {
        "/vms/101": { "VM.Audit": 1, "VM.PowerMgmt": 0 },
        "/": { "VM.Audit": 0, "Sys.Audit": 1, "Datastore.Audit": 1 },
      },
    },
  });
  await withMockedCommand(
    handler,
    () => model.methods.permissions.execute({}, context),
  );
  assertTokenOnly(seen);
  assertEquals(
    seen[0].url,
    `${globalArgs.apiUrl}/api2/json/access/permissions`,
  );
  const rec = getWrittenResources()[0];
  assertEquals(rec.name, "permissions");
  assertEquals(rec.data.subject, TOKEN_ID);
  assertEquals(rec.data.path, null);
  assertEquals(rec.data.paths, [
    {
      path: "/",
      privileges: [
        { name: "Datastore.Audit", propagate: true },
        { name: "Sys.Audit", propagate: true },
        { name: "VM.Audit", propagate: false },
      ],
    },
    {
      path: "/vms/101",
      privileges: [
        { name: "VM.Audit", propagate: true },
        { name: "VM.PowerMgmt", propagate: false },
      ],
    },
  ]);
  assert(typeof rec.data.checkedAt === "string");
});

Deno.test("permissions sends path and userid as query params only when set", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const { seen, handler } = router({
    "GET /access/permissions?path=%2Fpool%2Fpatch&userid=patch%40pve%21ci": {
      data: { "/pool/patch": { "VM.Audit": 1 } },
    },
    "GET /access/permissions": { data: {} },
  });
  await withMockedCommand(handler, async () => {
    await model.methods.permissions.execute(
      { path: "/pool/patch", userid: "patch@pve!ci" },
      context,
    );
    await model.methods.permissions.execute({}, context);
  });
  assertTokenOnly(seen);
  assertEquals(
    seen[0].url,
    `${globalArgs.apiUrl}/api2/json/access/permissions?path=%2Fpool%2Fpatch&userid=patch%40pve%21ci`,
  );
  assertEquals(
    seen[1].url,
    `${globalArgs.apiUrl}/api2/json/access/permissions`,
  );
  const [withParams, bare] = getWrittenResources();
  assertEquals(withParams.data.path, "/pool/patch");
  assertEquals(withParams.data.subject, "patch@pve!ci");
  assertEquals(bare.data.path, null);
  assertEquals(bare.data.subject, TOKEN_ID);
  assertEquals(bare.data.paths, []);
});

Deno.test("permissions rejects malformed path and userid arguments", () => {
  const args = model.methods.permissions.arguments;
  for (const ok of ["/", "/access", "/pool/patch", "/vms/101"]) {
    assert(args.safeParse({ path: ok }).success, ok);
  }
  for (const ok of ["root@pam", "swamp@pve!automation"]) {
    assert(args.safeParse({ userid: ok }).success, ok);
  }
  for (const bad of ["/../x", "pool/patch", "/a b", "/a;b", "/a//b"]) {
    assertFalse(args.safeParse({ path: bad }).success, bad);
  }
  for (const bad of ["root", "a@b!1x", "a@b c"]) {
    assertFalse(args.safeParse({ userid: bad }).success, bad);
  }
});

Deno.test("parsePermissions rejects payloads of the wrong shape", () => {
  const msg = "Unexpected /access/permissions response from Proxmox";
  assertThrows(() => parsePermissions(null), Error, msg);
  assertThrows(() => parsePermissions([]), Error, msg);
  assertThrows(() => parsePermissions("x"), Error, msg);
  assertThrows(() => parsePermissions({ "/": 1 }), Error, msg);
  assertThrows(() => parsePermissions({ "/": ["VM.Audit"] }), Error, msg);
});

Deno.test("parsePermissions skips junk values, bad names and non-path keys", () => {
  assertEquals(
    parsePermissions({
      "/": {
        "VM.Audit": 1,
        "Sys.Audit": 0,
        "Datastore.Audit": "1",
        "Pool.Allocate": null,
        "Sys.Modify": 2,
        "bad name": 1,
        "1x": 1,
      },
      "relative": 5,
    }),
    [
      {
        path: "/",
        privileges: [
          { name: "Sys.Audit", propagate: false },
          { name: "VM.Audit", propagate: true },
        ],
      },
    ],
  );
  assertEquals(parsePermissions({}), []);
});

Deno.test("permissions reports an HTTP error with the status", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  await assertRejects(
    () =>
      withMockedCommand(
        [httpOutput(403, { errors: { userid: "denied" } })],
        () =>
          model.methods.permissions.execute(
            { userid: "other@pve" },
            context,
          ),
      ),
    Error,
    "HTTP 403",
  );
  assertEquals(getWrittenResources().length, 0);
});

// ensureSnapshotAccess ------------------------------------------------------

const ACCESS_TOKEN_ID = "swamp-patch@pve!patch";
const ACCESS_SECRET = "22222222-3333-4444-5555-666666666666";
const ACCESS_COMMENT = "managed by @dmc/proxmox ensureSnapshotAccess";
const SNAPSHOT_PRIVS = [
  "VM.Audit",
  "VM.PowerMgmt",
  "VM.Snapshot",
  "VM.Snapshot.Rollback",
];
const CALLER_PRIVS = [
  "Sys.Audit",
  "Sys.Modify",
  "User.Modify",
  "Pool.Allocate",
  "Pool.Audit",
  "Permissions.Modify",
  "Realm.AllocateUser",
  "VM.Allocate",
];

interface FakeToken {
  tokenid: string;
  privsep: number;
  expire: number;
  comment: string;
}
interface FakeUser {
  userid: string;
  enable: number;
  groups?: string;
  tokens?: FakeToken[];
}
interface FakeRole {
  roleid: string;
  privs: string;
  special: number;
}
interface FakeAcl {
  path: string;
  type: string;
  ugid: string;
  roleid: string;
  propagate: number;
}
interface FakeGuest {
  vmid: number;
  type: string;
  node: string;
  pool?: string;
}
interface FakePve {
  roles: FakeRole[];
  users: FakeUser[];
  acl: FakeAcl[];
  pools: Array<{ poolid: string }>;
  guests: FakeGuest[];
  /** Privileges the caller holds on every path not listed in `callerPaths`. */
  callerAll: string[];
  callerPaths: Record<string, string[]>;
  /** Extra privileges the token appears to hold on each guest it reaches. */
  tokenExtra: string[];
  /** Extra privileges the token appears to hold on / when it has a grant there. */
  rootExtra?: string[];
  /** Extra privileges the token appears to hold on another granted path (storage, bridge). */
  pathExtra?: Record<string, string[]>;
  fullTokenId?: string;
  omitPrivsep?: boolean;
  /** The privsep value the token-create answer echoes, when not the number from the form. */
  createdPrivsep?: unknown;
  failWhen?: (method: string, path: string, body: string | null) => boolean;
}

/** An empty cluster with two unpooled guests; the caller holds every checked privilege. */
function pveState(over: Partial<FakePve> = {}): FakePve {
  return {
    roles: [],
    users: [],
    acl: [],
    pools: [],
    guests: [
      { vmid: 101, type: "lxc", node: "pve" },
      { vmid: 102, type: "qemu", node: "pve" },
    ],
    callerAll: [...CALLER_PRIVS],
    callerPaths: {},
    tokenExtra: [],
    ...over,
  };
}

/** A finished run: role, user, token, pool, both ACLs and both guests in place. */
function presentState(over: Partial<FakePve> = {}): FakePve {
  return pveState({
    roles: [{
      roleid: "SwampPatch",
      privs: "VM.Snapshot.Rollback,VM.Audit,VM.PowerMgmt,VM.Snapshot",
      special: 0,
    }],
    users: [{
      userid: "swamp-patch@pve",
      enable: 1,
      tokens: [{ tokenid: "patch", privsep: 1, expire: 0, comment: "" }],
    }],
    acl: [
      {
        path: "/pool/patch",
        type: "user",
        ugid: "swamp-patch@pve",
        roleid: "SwampPatch",
        propagate: 0,
      },
      {
        path: "/pool/patch",
        type: "token",
        ugid: ACCESS_TOKEN_ID,
        roleid: "SwampPatch",
        propagate: 0,
      },
    ],
    pools: [{ poolid: "patch" }],
    guests: [
      { vmid: 101, type: "lxc", node: "pve", pool: "patch" },
      { vmid: 102, type: "qemu", node: "pve", pool: "patch" },
    ],
    ...over,
  });
}

/** Form fields of a request body as a plain object. */
function formOf(body: string | null): Record<string, string> {
  return Object.fromEntries(new URLSearchParams(body ?? ""));
}

/** A token's privileges on a pool path or a guest: the role of its ACL on that pool, plus any extras. */
function tokenPrivileges(st: FakePve, path: string, tokenId: string): string[] {
  if (!/^\/(vms|pool)\//.test(path)) {
    const grant = st.acl.find((a) =>
      a.type === "token" && a.ugid === tokenId && a.path === path
    );
    const role = st.roles.find((r) => r.roleid === grant?.roleid);
    const extra = path === "/"
      ? (st.rootExtra ?? [])
      : (st.pathExtra?.[path] ?? []);
    return grant && role ? [...role.privs.split(","), ...extra] : [];
  }
  const vmid = Number(/^\/vms\/(\d+)$/.exec(path)?.[1]);
  const pool = /^\/pool\/(.+)$/.exec(path)?.[1] ??
    st.guests.find((g) => g.vmid === vmid)?.pool;
  if (!pool) return [];
  const grant = st.acl.find((a) =>
    a.type === "token" && a.ugid === tokenId && a.path === `/pool/${pool}`
  );
  const role = st.roles.find((r) => r.roleid === grant?.roleid);
  if (!grant || !role) return [];
  return [...role.privs.split(","), ...st.tokenExtra];
}

/** The `/access/permissions` payload for the caller, or for a token when `userid` is set. */
function permissionsFor(st: FakePve, path: string, userid: string | null) {
  const names = userid
    ? tokenPrivileges(st, path, userid)
    : (st.callerPaths[path] ?? st.callerAll);
  return names.length > 0
    ? { [path]: Object.fromEntries(names.map((n) => [n, 1])) }
    : {};
}

/** Answer one API call from `st`, applying writes to it. Undefined for an unknown route. */
function apiRoute(
  st: FakePve,
  method: string,
  path: string,
  u: URL,
  body: string,
): unknown {
  const form = new URLSearchParams(body);
  if (method === "GET") {
    switch (path) {
      case "/access/roles":
        return st.roles;
      case "/access/users":
        return st.users;
      case "/access/acl":
        return st.acl;
      case "/pools":
        return st.pools;
      case "/cluster/resources":
        return st.guests;
      case "/access/permissions":
        return permissionsFor(
          st,
          u.searchParams.get("path") ?? "",
          u.searchParams.get("userid"),
        );
      default:
        return undefined;
    }
  }
  if (method === "POST" && path === "/access/roles") {
    st.roles.push({
      roleid: form.get("roleid") ?? "",
      privs: form.get("privs") ?? "",
      special: 0,
    });
    return null;
  }
  if (method === "POST" && path === "/access/users") {
    st.users.push({
      userid: form.get("userid") ?? "",
      enable: Number(form.get("enable")),
      tokens: [],
    });
    return null;
  }
  if (method === "POST" && path === "/pools") {
    st.pools.push({ poolid: form.get("poolid") ?? "" });
    return null;
  }
  if (method === "PUT" && path === "/pools") {
    for (const vmid of (form.get("vms") ?? "").split(",").filter(Boolean)) {
      const guest = st.guests.find((g) => g.vmid === Number(vmid));
      if (guest) guest.pool = form.get("poolid") ?? "";
    }
    return null;
  }
  if (method === "PUT" && path === "/access/acl") {
    const isToken = form.has("tokens");
    st.acl.push({
      path: form.get("path") ?? "",
      type: isToken ? "token" : "user",
      ugid: (isToken ? form.get("tokens") : form.get("users")) ?? "",
      roleid: form.get("roles") ?? "",
      propagate: Number(form.get("propagate")),
    });
    return null;
  }
  const tokenRoute = /^\/access\/users\/([^/]+)\/token\/([^/]+)$/.exec(path);
  if (method === "POST" && tokenRoute) {
    const [, userid, tokenid] = tokenRoute;
    const user = st.users.find((x) => x.userid === userid);
    if (!user) return undefined;
    const privsep = Number(form.get("privsep"));
    const comment = form.get("comment") ?? "";
    user.tokens = [
      ...(user.tokens ?? []),
      { tokenid, privsep, expire: 0, comment },
    ];
    return {
      "full-tokenid": st.fullTokenId ?? `${userid}!${tokenid}`,
      value: ACCESS_SECRET,
      info: st.omitPrivsep ? { expire: 0, comment } : {
        privsep: "createdPrivsep" in st ? st.createdPrivsep : privsep,
        expire: 0,
        comment,
      },
    };
  }
  return undefined;
}

/** Stateful stand-in for the Proxmox API: records every call and applies writes to `st`. */
function fakePve(st: FakePve) {
  const seen: Seen[] = [];
  const handler = (_cmd: string, args: string[]) => {
    const method = args[args.indexOf("-X") + 1];
    const url = args[args.length - 1];
    const k = args.indexOf("-K");
    const body = curlBody(args);
    seen.push({
      method,
      url,
      body,
      headers: k === -1 ? "" : Deno.readTextFileSync(args[k + 1]),
    });
    const u = new URL(url);
    const path = decodeURIComponent(u.pathname.replace("/api2/json", ""));
    if (st.failWhen?.(method, path, body)) {
      return httpOutput(500, { errors: { reason: "injected failure" } });
    }
    const data = apiRoute(st, method, path, u, body ?? "");
    return data === undefined
      ? httpOutput(404, { errors: { path: `no route for ${method} ${path}` } })
      : httpOutput(200, { data });
  };
  return { seen, handler };
}

/** Run ensureSnapshotAccess (or `method`) against `st`. Errors are returned, not thrown. */
async function ensure(
  st: FakePve,
  args: Record<string, unknown>,
  method: "ensureSnapshotAccess" | "ensureRunnerPoolAccess" =
    "ensureSnapshotAccess",
) {
  const { context, getWrittenResources, getLogs } = createModelTestContext({
    globalArgs,
  });
  const fake = fakePve(st);
  let error: Error | null = null;
  try {
    await withMockedCommand(
      fake.handler,
      () =>
        method === "ensureSnapshotAccess"
          ? model.methods.ensureSnapshotAccess.execute(
            args as Parameters<
              typeof model.methods.ensureSnapshotAccess.execute
            >[0],
            context,
          )
          : model.methods.ensureRunnerPoolAccess.execute(
            args as Parameters<
              typeof model.methods.ensureRunnerPoolAccess.execute
            >[0],
            context,
          ),
    );
  } catch (e) {
    error = e as Error;
  }
  return {
    seen: fake.seen,
    written: getWrittenResources(),
    logs: JSON.stringify(getLogs()),
    error,
  };
}

/** Arguments as the method sees them, with schema defaults applied. */
function accessArgs(input: Record<string, unknown>): Record<string, unknown> {
  return model.methods.ensureSnapshotAccess.arguments.parse(input);
}

// deno-lint-ignore no-explicit-any
type Data = any;

/** Data of the first written resource with this spec name. */
function writtenData(
  written: Array<{ specName: string; data: unknown }>,
  specName: string,
): Data {
  return written.find((w) => w.specName === specName)?.data;
}

const writesOf = (seen: Seen[]) => seen.filter((s) => s.method !== "GET");

Deno.test("ensureSnapshotAccess dry run on an empty cluster plans every action and only reads", async () => {
  const r = await ensure(
    pveState(),
    accessArgs({ dryRun: true, members: [101, 102] }),
  );
  assertEquals(r.error, null);
  assertTokenOnly(r.seen);
  assertEquals(writesOf(r.seen), []);
  const rec = writtenData(r.written, "snapshotAccess");
  assertEquals(rec.status, "planned");
  assertEquals(rec.actions, [
    { action: "createRole", target: "SwampPatch", state: "planned" },
    { action: "createUser", target: "swamp-patch@pve", state: "planned" },
    { action: "createPool", target: "patch", state: "planned" },
    { action: "addMembers", target: "101,102", state: "planned" },
    { action: "aclUser", target: "/pool/patch", state: "planned" },
    { action: "createToken", target: ACCESS_TOKEN_ID, state: "planned" },
    { action: "aclToken", target: "/pool/patch", state: "planned" },
  ]);
  assertEquals(rec.blockers, []);
  assertEquals(rec.callerMissing, []);
  assertEquals(rec.extraMembers, []);
  assertEquals(rec.verified, []);
  assertFalse(r.written.some((w) => w.specName === "snapshotToken"));
});

Deno.test("ensureSnapshotAccess live on an empty cluster writes the exact sequence and bodies", async () => {
  const r = await ensure(
    pveState(),
    accessArgs({ dryRun: false, members: [101, 102] }),
  );
  assertEquals(r.error, null);
  assertTokenOnly(r.seen);
  const writes = writesOf(r.seen);
  assertEquals(writes.map((w) => `${w.method} ${new URL(w.url).pathname}`), [
    "POST /api2/json/access/roles",
    "POST /api2/json/access/users",
    "POST /api2/json/pools",
    "PUT /api2/json/pools",
    "PUT /api2/json/access/acl",
    "POST /api2/json/access/users/swamp-patch%40pve/token/patch",
    "PUT /api2/json/access/acl",
  ]);
  const bodies = writes.map((w) => formOf(w.body));
  assertEquals(bodies[0], {
    roleid: "SwampPatch",
    privs: SNAPSHOT_PRIVS.join(","),
  });
  assertEquals(bodies[1], {
    userid: "swamp-patch@pve",
    enable: "1",
    comment: ACCESS_COMMENT,
  });
  assertFalse(new URLSearchParams(writes[1].body ?? "").has("password"));
  assertEquals(bodies[2], { poolid: "patch", comment: ACCESS_COMMENT });
  assertEquals(bodies[3], { poolid: "patch", vms: "101,102" });
  assertEquals(bodies[4], {
    path: "/pool/patch",
    roles: "SwampPatch",
    users: "swamp-patch@pve",
    propagate: "0",
  });
  assertEquals(bodies[5], { privsep: "1", comment: ACCESS_COMMENT });
  assertEquals(bodies[6], {
    path: "/pool/patch",
    roles: "SwampPatch",
    tokens: ACCESS_TOKEN_ID,
    propagate: "0",
  });

  // Verification reads the token's privileges on each guest after the writes.
  assertEquals(
    r.seen.slice(-2).map((s) => {
      const q = new URL(s.url).searchParams;
      return [q.get("path"), q.get("userid")];
    }),
    [["/vms/101", ACCESS_TOKEN_ID], ["/vms/102", ACCESS_TOKEN_ID]],
  );

  const rec = writtenData(r.written, "snapshotAccess");
  assertEquals(rec.status, "applied");
  assertEquals(rec.tokenSecretIssued, true);
  assertEquals(
    rec.actions.map((a: { state: string }) => a.state),
    Array(7).fill("applied"),
  );
  assertEquals(rec.verified, [
    { path: "/pool/patch", privileges: SNAPSHOT_PRIVS, ok: true },
    { path: "/vms/101", privileges: SNAPSHOT_PRIVS, ok: true },
    { path: "/vms/102", privileges: SNAPSHOT_PRIVS, ok: true },
  ]);

  const token = writtenData(r.written, "snapshotToken");
  assertEquals(token.tokenId, ACCESS_TOKEN_ID);
  assertEquals(token.tokenSecret, ACCESS_SECRET);
  assertFalse(JSON.stringify(rec).includes(ACCESS_SECRET));
  assertFalse(r.logs.includes(ACCESS_SECRET));
});

Deno.test("snapshotToken tokenSecret is marked sensitive", () => {
  assertEquals(
    model.resources.snapshotToken.schema.shape.tokenSecret.meta()?.sensitive,
    true,
  );
});

Deno.test("ensureSnapshotAccess with everything in place makes no writes and no token", async () => {
  const st = presentState({
    callerAll: CALLER_PRIVS.filter((p) => p !== "Realm.AllocateUser"),
  });
  const r = await ensure(
    st,
    accessArgs({ dryRun: false, members: [101, 102] }),
  );
  assertEquals(r.error, null);
  assertEquals(writesOf(r.seen), []);
  const rec = writtenData(r.written, "snapshotAccess");
  assertEquals(rec.status, "unchanged");
  assertEquals(
    rec.actions.map((a: { state: string }) => a.state),
    Array(7).fill("present"),
  );
  assertEquals(rec.actions[3].target, "");
  assertEquals(
    rec.verified.map((v: { ok: boolean }) => v.ok),
    [true, true, true],
  );
  assertFalse(r.written.some((w) => w.specName === "snapshotToken"));
});

Deno.test("ensureSnapshotAccess blocks a role with an extra privilege, with no writes", async () => {
  for (const dryRun of [true, false]) {
    const st = presentState();
    st.roles = [{
      roleid: "SwampPatch",
      privs:
        "VM.Audit,VM.PowerMgmt,VM.Snapshot,VM.Snapshot.Rollback,Sys.Modify",
      special: 0,
    }];
    const r = await ensure(st, accessArgs({ dryRun, members: [101, 102] }));
    assertStringIncludes(
      r.error?.message ?? "",
      "ensureSnapshotAccess blocked",
    );
    assertEquals(writesOf(r.seen), []);
    const rec = writtenData(r.written, "snapshotAccess");
    assertEquals(rec.status, "blocked");
    assert(
      rec.blockers.some((b: string) =>
        b.includes("extra privileges: Sys.Modify")
      ),
      rec.blockers.join(" | "),
    );
  }
});

const blockerCases: Array<[string, (s: FakePve) => void, string, number[]?]> = [
  [
    "the user is in a group",
    (s) => {
      s.users[0] = { ...s.users[0], groups: "admins" };
    },
    "in group(s) admins",
  ],
  [
    "the user is disabled",
    (s) => {
      s.users[0] = { ...s.users[0], enable: 0 };
    },
    "user swamp-patch@pve is disabled",
  ],
  [
    "the token has no privilege separation",
    (s) => {
      s.users[0] = {
        ...s.users[0],
        tokens: [{ tokenid: "patch", privsep: 0, expire: 0, comment: "" }],
      };
    },
    "does not use privilege separation",
  ],
  [
    "the token has an ACL on /",
    (s) => {
      s.acl.push({
        path: "/",
        type: "token",
        ugid: ACCESS_TOKEN_ID,
        roleid: "SwampPatch",
        propagate: 0,
      });
    },
    "on / with propagate 0",
  ],
  [
    "the user ACL propagates",
    (s) => {
      s.acl[0] = { ...s.acl[0], propagate: 1 };
    },
    "with propagate 1",
  ],
  [
    "another user holds the role",
    (s) => {
      s.acl.push({
        path: "/pool/patch",
        type: "user",
        ugid: "other@pve",
        roleid: "SwampPatch",
        propagate: 0,
      });
    },
    "granted to user other@pve",
  ],
  [
    "the role is built in",
    (s) => {
      s.roles[0] = { ...s.roles[0], special: 1 };
    },
    "is a built-in role",
  ],
  [
    "the role lacks a privilege",
    (s) => {
      s.roles = [{
        roleid: "SwampPatch",
        privs: "VM.Audit,VM.PowerMgmt,VM.Snapshot",
        special: 0,
      }];
    },
    "missing privileges: VM.Snapshot.Rollback",
  ],
  [
    "a requested guest does not exist",
    () => {},
    "guest 999 does not exist",
    [101, 999],
  ],
  [
    "a requested guest is in another pool",
    (s) => {
      s.guests[0] = { ...s.guests[0], pool: "other" };
    },
    "guest 101 is in pool other",
  ],
  [
    "the caller lacks Sys.Modify on /access",
    (s) => {
      s.callerAll = CALLER_PRIVS.filter((p) => p !== "Sys.Modify");
    },
    "caller lacks Sys.Modify on /access",
  ],
  [
    "the caller lacks Permissions.Modify on /pool/patch",
    (s) => {
      s.callerPaths["/pool/patch"] = ["Pool.Allocate", "Pool.Audit"];
    },
    "caller lacks Permissions.Modify on /pool/patch",
  ],
];

for (const [name, mutate, fragment, members] of blockerCases) {
  Deno.test(`ensureSnapshotAccess blocks when ${name}, dry run or live, with no writes`, async () => {
    for (const dryRun of [true, false]) {
      const st = presentState();
      mutate(st);
      const r = await ensure(
        st,
        accessArgs({ dryRun, members: members ?? [101, 102] }),
      );
      assertStringIncludes(
        r.error?.message ?? "",
        "ensureSnapshotAccess blocked",
      );
      assertStringIncludes(r.error?.message ?? "", fragment);
      assertEquals(writesOf(r.seen), []);
      const rec = writtenData(r.written, "snapshotAccess");
      assertEquals(rec.status, "blocked");
      assert(
        rec.blockers.some((b: string) => b.includes(fragment)),
        rec.blockers.join(" | "),
      );
    }
  });
}

Deno.test("ensureSnapshotAccess reports missing caller privileges for the user and the guests", async () => {
  for (const dryRun of [true, false]) {
    const st = pveState({
      callerPaths: {
        "/access/realm/pve": ["Sys.Audit"],
        "/vms/101": ["VM.Audit"],
      },
    });
    const r = await ensure(st, accessArgs({ dryRun, members: [101, 102] }));
    const message = r.error?.message ?? "";
    assertStringIncludes(
      message,
      "caller lacks Realm.AllocateUser on /access/realm/pve",
    );
    assertStringIncludes(
      message,
      "caller lacks Permissions.Modify or VM.Allocate on /vms/101",
    );
    assertEquals(writesOf(r.seen), []);
    assertEquals(writtenData(r.written, "snapshotAccess").callerMissing, [
      { path: "/access/realm/pve", privilege: "Realm.AllocateUser" },
      { path: "/vms/101", privilege: "Permissions.Modify|VM.Allocate" },
    ]);
  }
});

Deno.test("ensureSnapshotAccess keeps the token secret when the token ACL write fails", async () => {
  const st = pveState({
    failWhen: (method, path, body) =>
      method === "PUT" &&
      path === "/access/acl" &&
      new URLSearchParams(body ?? "").has("tokens"),
  });
  const r = await ensure(
    st,
    accessArgs({ dryRun: false, members: [101, 102] }),
  );
  assert(r.error, "the method should reject");
  assertStringIncludes(r.error.message, "failed");
  assertFalse(r.error.message.includes(ACCESS_SECRET));
  const rec = writtenData(r.written, "snapshotAccess");
  assertEquals(rec.status, "failed");
  assertEquals(
    rec.actions.find((a: { action: string }) => a.action === "aclToken").state,
    "failed",
  );
  assertEquals(
    rec.actions.find((a: { action: string }) => a.action === "createToken")
      .state,
    "applied",
  );
  assertEquals(
    writtenData(r.written, "snapshotToken").tokenSecret,
    ACCESS_SECRET,
  );
  assertFalse(JSON.stringify(rec).includes(ACCESS_SECRET));
});

Deno.test('ensureSnapshotAccess accepts a token-create answer that echoes privsep as "1"', async () => {
  // Proxmox echoes the form value, so a real answer has the string, not the number.
  const r = await ensure(
    pveState({ createdPrivsep: "1" }),
    accessArgs({ dryRun: false, members: [101, 102] }),
  );
  assertEquals(r.error, null);
  assertEquals(writtenData(r.written, "snapshotAccess").status, "applied");
});

Deno.test("ensureSnapshotAccess rejects when verification finds an extra privilege", async () => {
  const st = pveState({ tokenExtra: ["Sys.Modify"] });
  const r = await ensure(
    st,
    accessArgs({ dryRun: false, members: [101, 102] }),
  );
  assertStringIncludes(r.error?.message ?? "", "verification failed");
  const rec = writtenData(r.written, "snapshotAccess");
  assertEquals(rec.status, "failed");
  assertEquals(
    rec.verified.map((v: { ok: boolean }) => v.ok),
    [false, false, false],
  );
  assert(rec.verified[0].privileges.includes("Sys.Modify"));
  assertFalse(JSON.stringify(rec).includes(ACCESS_SECRET));
});

for (
  const [label, over] of [
    ["full-tokenid does not match", { fullTokenId: "swamp-patch@pve!other" }],
    ["token info has no privsep", { omitPrivsep: true }],
    ["token info has privsep 0", { createdPrivsep: 0 }],
    ['token info has privsep "0"', { createdPrivsep: "0" }],
    ["token info has privsep true", { createdPrivsep: true }],
  ] as Array<[string, Partial<FakePve>]>
) {
  Deno.test(`ensureSnapshotAccess stores the secret, then fails when ${label}`, async () => {
    const r = await ensure(
      pveState(over),
      accessArgs({ dryRun: false, members: [101, 102] }),
    );
    assert(r.error, "the method should reject");
    assertFalse(r.error.message.includes(ACCESS_SECRET));
    assertEquals(
      writtenData(r.written, "snapshotToken").tokenSecret,
      ACCESS_SECRET,
    );
    assertEquals(
      writtenData(r.written, "snapshotAccess").actions.find(
        (a: { action: string }) => a.action === "createToken",
      ).state,
      "failed",
    );
    const writes = writesOf(r.seen);
    assertStringIncludes(writes[writes.length - 1].url, "/token/patch");
  });
}

Deno.test("ensureSnapshotAccess dry run fails when an existing token has an extra privilege", async () => {
  const r = await ensure(
    presentState({ tokenExtra: ["Sys.Modify"] }),
    accessArgs({ dryRun: true, members: [101, 102] }),
  );
  assertStringIncludes(r.error?.message ?? "", "does not have exactly");
  assertEquals(writesOf(r.seen), []);
  assertEquals(writtenData(r.written, "snapshotAccess").status, "blocked");
});

Deno.test("ensureSnapshotAccess adds only the token ACL when the rest is in place", async () => {
  const acl = [{
    path: "/pool/patch",
    type: "user",
    ugid: "swamp-patch@pve",
    roleid: "SwampPatch",
    propagate: 0,
  }];
  const dry = await ensure(
    presentState({ acl }),
    accessArgs({ dryRun: true, members: [101, 102] }),
  );
  assertEquals(dry.error, null);
  assertEquals(writesOf(dry.seen), []);
  const dryRec = writtenData(dry.written, "snapshotAccess");
  assertEquals(dryRec.status, "planned");
  assertEquals(dryRec.verified, []);
  assertEquals(
    dryRec.actions.find((a: { action: string }) => a.action === "aclToken")
      .state,
    "planned",
  );

  const live = await ensure(
    presentState({ acl }),
    accessArgs({ dryRun: false, members: [101, 102] }),
  );
  assertEquals(live.error, null);
  assertEquals(
    writesOf(live.seen).map((w) => `${w.method} ${new URL(w.url).pathname}`),
    ["PUT /api2/json/access/acl"],
  );
  const liveRec = writtenData(live.written, "snapshotAccess");
  assertEquals(liveRec.status, "applied");
  assertEquals(
    liveRec.verified.map((v: { ok: boolean }) => v.ok),
    [true, true, true],
  );
  assertFalse(live.written.some((w) => w.specName === "snapshotToken"));
});

Deno.test("ensureSnapshotAccess reports guests in the pool that were not requested, and never removes them", async () => {
  for (const dryRun of [true, false]) {
    const st = presentState({
      guests: [
        { vmid: 101, type: "lxc", node: "pve", pool: "patch" },
        { vmid: 102, type: "qemu", node: "pve", pool: "patch" },
        { vmid: 103, type: "qemu", node: "pve", pool: "patch" },
      ],
    });
    const r = await ensure(st, accessArgs({ dryRun, members: [101, 102] }));
    assertEquals(r.error, null);
    assertEquals(writesOf(r.seen), []);
    const rec = writtenData(r.written, "snapshotAccess");
    assertEquals(rec.status, "unchanged");
    assertEquals(rec.extraMembers, [103]);
    assertEquals(st.guests[2].pool, "patch");
  }
});

Deno.test("ensureSnapshotAccess arguments default to a dry run of the SwampPatch role", () => {
  assertEquals(accessArgs({}), {
    dryRun: true,
    user: "swamp-patch@pve",
    tokenName: "patch",
    role: "SwampPatch",
    clusterAudit: false,
    auditRole: "SwampPatchAudit",
    pool: "patch",
    members: [],
  });
});

Deno.test("ensureSnapshotAccess arguments refuse unsafe users, roles, pools, tokens and members", () => {
  const args = model.methods.ensureSnapshotAccess.arguments;
  assert(
    args.safeParse({
      user: "ops.bot@pve",
      role: "Snapshot-Role_2",
      pool: "patch-2",
      members: [101, 102],
    }).success,
  );
  for (
    const bad of [
      { user: "root@pam" },
      { user: "x@pam" },
      { user: "X@pve" },
      { role: "PVEAdmin" },
      { role: "pveadmin" },
      { role: "Administrator" },
      { role: "NoAccess" },
      { role: "noaccess" },
      { pool: "a/b" },
      { pool: "../x" },
      { tokenName: "1x" },
      { members: [101, 101] },
      { members: [0] },
    ]
  ) {
    assertFalse(args.safeParse(bad).success, JSON.stringify(bad));
  }
});

Deno.test("ensureSnapshotAccess with no members still verifies the grant on the pool path", async () => {
  const r = await ensure(pveState(), accessArgs({ dryRun: false }));
  assertEquals(r.error, null);
  const rec = writtenData(r.written, "snapshotAccess");
  assertEquals(rec.status, "applied");
  assertEquals(rec.verified, [
    { path: "/pool/patch", privileges: SNAPSHOT_PRIVS, ok: true },
  ]);
});

Deno.test("ensureSnapshotAccess never passes on a JSON error from the token response", async () => {
  const st = pveState();
  const fake = fakePve(st);
  const handler = (cmd: string, args: string[]) => {
    const url = args[args.length - 1];
    if (
      args[args.indexOf("-X") + 1] === "POST" && url.endsWith("/token/patch")
    ) {
      fake.handler(cmd, args); // let the fake record the token
      return {
        stdout: `HTTP/1.1 200 OK\r\n\r\n{"data":{"value":"${ACCESS_SECRET}"`,
        code: 0,
      };
    }
    return fake.handler(cmd, args);
  };
  const { context, getWrittenResources, getLogs } = createModelTestContext({
    globalArgs,
  });
  const err = await assertRejects(() =>
    withMockedCommand(
      handler,
      () =>
        model.methods.ensureSnapshotAccess.execute(
          accessArgs({ dryRun: false, members: [101] }),
          context,
        ),
    )
  );
  const message = (err as Error).message;
  assertStringIncludes(message, "not JSON");
  assertStringIncludes(message, `delete ${ACCESS_TOKEN_ID}`);
  assertFalse(message.includes(ACCESS_SECRET));
  assertFalse(JSON.stringify(getLogs()).includes(ACCESS_SECRET));
  assertFalse(JSON.stringify(getWrittenResources()).includes(ACCESS_SECRET));
});

Deno.test("ensureSnapshotAccess says the secret is lost when it cannot be stored", async () => {
  const { context, getLogs } = createModelTestContext({ globalArgs });
  const writeResource = context.writeResource;
  context.writeResource = (spec: string, name: string, data: unknown) =>
    spec === "snapshotToken"
      ? Promise.reject(new Error(`vault refused ${JSON.stringify(data)}`))
      : writeResource(spec, name, data);
  const fake = fakePve(pveState());
  const err = await assertRejects(() =>
    withMockedCommand(
      fake.handler,
      () =>
        model.methods.ensureSnapshotAccess.execute(
          accessArgs({ dryRun: false, members: [101] }),
          context,
        ),
    )
  );
  const message = (err as Error).message;
  assertStringIncludes(message, "Could not store the token secret");
  assertFalse(message.includes(ACCESS_SECRET));
  assertFalse(JSON.stringify(getLogs()).includes(ACCESS_SECRET));
});

// ensureSnapshotAccess with clusterAudit -------------------------------------

const AUDIT_ROLE = {
  roleid: "SwampPatchAudit",
  privs: "Sys.Audit",
  special: 0,
};

/** A finished clusterAudit run: presentState plus the audit role and both grants on /. */
function auditPresentState(over: Partial<FakePve> = {}): FakePve {
  const st = presentState(over);
  st.roles.push({ ...AUDIT_ROLE });
  st.acl.push(
    {
      path: "/",
      type: "user",
      ugid: "swamp-patch@pve",
      roleid: "SwampPatchAudit",
      propagate: 0,
    },
    {
      path: "/",
      type: "token",
      ugid: ACCESS_TOKEN_ID,
      roleid: "SwampPatchAudit",
      propagate: 0,
    },
  );
  return st;
}

Deno.test("ensureSnapshotAccess clusterAudit dry run plans the audit role and both grants on /", async () => {
  const r = await ensure(
    pveState(),
    accessArgs({ dryRun: true, clusterAudit: true, members: [101, 102] }),
  );
  assertEquals(r.error, null);
  assertEquals(writesOf(r.seen), []);
  const rec = writtenData(r.written, "snapshotAccess");
  assertEquals(rec.status, "planned");
  assertEquals(rec.clusterAudit, true);
  assertEquals(rec.auditRole, "SwampPatchAudit");
  assertEquals(rec.auditPrivileges, ["Sys.Audit"]);
  assertEquals(
    rec.actions.map((a: { action: string; target: string }) =>
      `${a.action} ${a.target}`
    ),
    [
      "createRole SwampPatch",
      "createAuditRole SwampPatchAudit",
      "createUser swamp-patch@pve",
      "createPool patch",
      "addMembers 101,102",
      "aclUser /pool/patch",
      "aclUserAudit /",
      `createToken ${ACCESS_TOKEN_ID}`,
      "aclToken /pool/patch",
      "aclTokenAudit /",
    ],
  );
});

Deno.test("ensureSnapshotAccess without clusterAudit plans no audit action and records none", async () => {
  const r = await ensure(pveState(), accessArgs({ dryRun: true }));
  const rec = writtenData(r.written, "snapshotAccess");
  assertEquals(rec.clusterAudit, false);
  assertEquals(rec.auditRole, null);
  assertEquals(rec.auditPrivileges, []);
  assertFalse(
    rec.actions.some((a: { action: string }) => a.action.includes("Audit")),
  );
});

Deno.test("ensureSnapshotAccess clusterAudit live writes the audit role and grants on / with propagate 0, then verifies /", async () => {
  const r = await ensure(
    pveState(),
    accessArgs({ dryRun: false, clusterAudit: true, members: [101] }),
  );
  assertEquals(r.error, null);
  const writes = writesOf(r.seen);
  assertEquals(writes.map((w) => `${w.method} ${new URL(w.url).pathname}`), [
    "POST /api2/json/access/roles",
    "POST /api2/json/access/roles",
    "POST /api2/json/access/users",
    "POST /api2/json/pools",
    "PUT /api2/json/pools",
    "PUT /api2/json/access/acl",
    "PUT /api2/json/access/acl",
    "POST /api2/json/access/users/swamp-patch%40pve/token/patch",
    "PUT /api2/json/access/acl",
    "PUT /api2/json/access/acl",
  ]);
  const bodies = writes.map((w) => formOf(w.body));
  assertEquals(bodies[1], { roleid: "SwampPatchAudit", privs: "Sys.Audit" });
  assertEquals(bodies[6], {
    path: "/",
    roles: "SwampPatchAudit",
    users: "swamp-patch@pve",
    propagate: "0",
  });
  assertEquals(bodies[9], {
    path: "/",
    roles: "SwampPatchAudit",
    tokens: ACCESS_TOKEN_ID,
    propagate: "0",
  });
  const rec = writtenData(r.written, "snapshotAccess");
  assertEquals(rec.status, "applied");
  assertEquals(rec.verified, [
    { path: "/pool/patch", privileges: SNAPSHOT_PRIVS, ok: true },
    { path: "/vms/101", privileges: SNAPSHOT_PRIVS, ok: true },
    { path: "/", privileges: ["Sys.Audit"], ok: true },
  ]);
});

Deno.test("ensureSnapshotAccess clusterAudit needs Permissions.Modify on /", async () => {
  const r = await ensure(
    pveState({ callerPaths: { "/": ["Sys.Audit"] } }),
    accessArgs({ dryRun: true, clusterAudit: true }),
  );
  assertStringIncludes(
    r.error?.message ?? "",
    "caller lacks Permissions.Modify on /",
  );
  assertEquals(writesOf(r.seen), []);
});

Deno.test("ensureSnapshotAccess clusterAudit with everything in place writes nothing and verifies / in a dry run", async () => {
  for (const dryRun of [true, false]) {
    const r = await ensure(
      auditPresentState(),
      accessArgs({ dryRun, clusterAudit: true, members: [101, 102] }),
    );
    assertEquals(r.error, null);
    assertEquals(writesOf(r.seen), []);
    const rec = writtenData(r.written, "snapshotAccess");
    assertEquals(rec.status, "unchanged");
    assertEquals(rec.verified.at(-1), {
      path: "/",
      privileges: ["Sys.Audit"],
      ok: true,
    });
  }
});

Deno.test("ensureSnapshotAccess clusterAudit fails when the token holds more than Sys.Audit on /", async () => {
  const dry = await ensure(
    auditPresentState({ rootExtra: ["Sys.Modify"] }),
    accessArgs({ dryRun: true, clusterAudit: true }),
  );
  assertStringIncludes(
    dry.error?.message ?? "",
    "does not have exactly Sys.Audit on /",
  );
  assertEquals(writtenData(dry.written, "snapshotAccess").status, "blocked");
  const live = await ensure(
    pveState({ rootExtra: ["Sys.Modify"] }),
    accessArgs({ dryRun: false, clusterAudit: true }),
  );
  assertStringIncludes(live.error?.message ?? "", "verification failed");
  assertStringIncludes(
    live.error?.message ?? "",
    "does not have exactly Sys.Audit on /",
  );
  assertEquals(writtenData(live.written, "snapshotAccess").status, "failed");
});

const auditBlockerCases: Array<
  [string, (st: FakePve) => void, string, boolean]
> = [
  [
    "the audit role has an extra privilege",
    (st) => {
      st.roles.find((r) => r.roleid === "SwampPatchAudit")!.privs =
        "Sys.Audit,Sys.Modify";
    },
    "role SwampPatchAudit has extra privileges: Sys.Modify",
    true,
  ],
  [
    "the audit role lacks Sys.Audit",
    (st) => {
      st.roles.find((r) => r.roleid === "SwampPatchAudit")!.privs = "VM.Audit";
    },
    "role SwampPatchAudit is missing privileges: Sys.Audit",
    true,
  ],
  [
    "the audit grant on / propagates",
    (st) => {
      st.acl.find((a) => a.path === "/" && a.type === "token")!.propagate = 1;
    },
    `token ${ACCESS_TOKEN_ID} has role SwampPatchAudit on / with propagate 1`,
    true,
  ],
  [
    "the audit role is granted to someone else",
    (st) => {
      st.acl.push({
        path: "/",
        type: "user",
        ugid: "ops@pve",
        roleid: "SwampPatchAudit",
        propagate: 0,
      });
    },
    "role SwampPatchAudit is granted to user ops@pve on /",
    true,
  ],
  [
    "the snapshot role is granted on /",
    (st) => {
      st.acl.find((a) => a.path === "/" && a.type === "token")!.roleid =
        "SwampPatch";
    },
    `token ${ACCESS_TOKEN_ID} has role SwampPatch on /`,
    true,
  ],
  [
    "an audit grant exists but clusterAudit is off",
    () => {},
    `token ${ACCESS_TOKEN_ID} has role SwampPatchAudit on / with propagate 0; the only allowed grant is role SwampPatch on /pool/patch`,
    false,
  ],
];

for (const [name, mutate, fragment, clusterAudit] of auditBlockerCases) {
  Deno.test(`ensureSnapshotAccess blocks when ${name}, dry run or live, with no writes`, async () => {
    for (const dryRun of [true, false]) {
      const st = auditPresentState();
      mutate(st);
      const r = await ensure(
        st,
        accessArgs({ dryRun, clusterAudit, members: [101, 102] }),
      );
      assertStringIncludes(
        r.error?.message ?? "",
        "ensureSnapshotAccess blocked",
      );
      assertStringIncludes(r.error?.message ?? "", fragment);
      assertEquals(writesOf(r.seen), []);
      assertEquals(writtenData(r.written, "snapshotAccess").status, "blocked");
    }
  });
}

Deno.test("ensureSnapshotAccess arguments refuse an audit role that is the snapshot role or built in", () => {
  const args = model.methods.ensureSnapshotAccess.arguments;
  assertFalse(
    args.safeParse({ clusterAudit: true, auditRole: "SwampPatch" }).success,
  );
  assertFalse(
    args.safeParse({ role: "Snap", auditRole: "Snap" }).success,
  );
  for (const bad of ["PVEAuditor", "Administrator", "noaccess", "a b"]) {
    assertFalse(args.safeParse({ auditRole: bad }).success, bad);
  }
  assert(args.safeParse({ auditRole: "PatchAudit" }).success);
});

// clusterHealth ---------------------------------------------------------------

const CLUSTER_OK = [
  {
    type: "cluster",
    id: "cluster",
    name: "bridges",
    nodes: 2,
    quorate: 1,
    version: 4,
  },
  {
    type: "node",
    id: "node/node1",
    name: "node1",
    nodeid: 1,
    online: 1,
    local: 1,
    ip: "192.0.2.2",
    level: "",
  },
  {
    type: "node",
    id: "node/pve",
    name: "pve",
    nodeid: 2,
    online: 1,
    local: 0,
    ip: "192.0.2.3",
    level: "",
  },
];

/** CLUSTER_OK with `patch` applied to the entry named `name`. */
function clusterWith(name: string, patch: Record<string, unknown>) {
  return CLUSTER_OK.map((e) => e.name === name ? { ...e, ...patch } : e);
}

Deno.test("parseClusterStatus: a listed, online node in a quorate cluster is healthy", () => {
  const h = parseClusterStatus(CLUSTER_OK, "pve");
  assertEquals(h, {
    node: "pve",
    answeredBy: "node1",
    clustered: true,
    cluster: "bridges",
    quorate: true,
    nodeListed: true,
    nodeOnline: true,
    nodesOnline: 2,
    nodesTotal: 2,
    healthy: true,
    problems: [],
  });
});

Deno.test("parseClusterStatus: offline, unlisted, no quorum or a node count mismatch is unhealthy", () => {
  const offline = parseClusterStatus(clusterWith("pve", { online: 0 }), "pve");
  assertEquals(offline.healthy, false);
  assertEquals(offline.problems, ["node pve is offline"]);
  assertEquals(offline.nodesOnline, 1);

  const missing = parseClusterStatus(CLUSTER_OK, "pve2");
  assertEquals(missing.nodeListed, false);
  assertEquals(missing.problems, ["node pve2 is not in /cluster/status"]);

  const noQuorum = parseClusterStatus(
    clusterWith("bridges", { quorate: 0 }),
    "node1",
  );
  assertEquals(noQuorum.quorate, false);
  assertEquals(noQuorum.problems, ["cluster bridges is not quorate"]);

  const count = parseClusterStatus(
    clusterWith("bridges", { nodes: 3 }),
    "node1",
  );
  assertEquals(count.healthy, false);
  assertEquals(count.problems, [
    "cluster bridges says it has 3 nodes but lists 2",
  ]);
});

Deno.test("parseClusterStatus: a standalone node has no quorum to judge", () => {
  const h = parseClusterStatus(
    [{ type: "node", name: "solo", online: 1, local: 1, nodeid: 0 }],
    "solo",
  );
  assertEquals(h.clustered, false);
  assertEquals(h.quorate, null);
  assertEquals(h.healthy, true);
  assertEquals(h.nodesTotal, 1);
});

Deno.test("parseClusterStatus: a malformed answer throws", () => {
  const bad: Array<[unknown, string]> = [
    [{}, "not an array"],
    [[], "no node entries"],
    [CLUSTER_OK.filter((e) => e.type === "cluster"), "no node entries"],
    [clusterWith("pve", { online: "1" }), "online is not 0 or 1"],
    [clusterWith("pve", { online: true }), "online is not 0 or 1"],
    [clusterWith("pve", { online: undefined }), "online is not 0 or 1"],
    [clusterWith("pve", { local: 2 }), "local is not 0 or 1"],
    [clusterWith("bridges", { quorate: "yes" }), "quorate is not 0 or 1"],
    [clusterWith("bridges", { nodes: "2" }), "nodes missing"],
    [clusterWith("bridges", { name: "" }), "name missing"],
    [clusterWith("pve", { name: "../x" }), "unsafe node name"],
    [[...CLUSTER_OK, CLUSTER_OK[0]], "two cluster entries"],
    [[...CLUSTER_OK, CLUSTER_OK[2]], "listed twice"],
    [clusterWith("pve", { local: 1 }), "more than one local node"],
    [[...CLUSTER_OK, "junk"], "Unexpected /cluster/status response"],
  ];
  for (const [data, fragment] of bad) {
    assertThrows(
      () => parseClusterStatus(data, "pve"),
      Error,
      fragment,
      JSON.stringify(data).slice(0, 80),
    );
  }
});

Deno.test("parseClusterStatus: entries of other types are ignored", () => {
  const h = parseClusterStatus(
    [...CLUSTER_OK, { type: "qdevice", name: "q", online: "?" }],
    "node1",
  );
  assertEquals(h.healthy, true);
});

Deno.test("clusterHealth reads /cluster/status with the token and records the verdict for the node", async () => {
  for (
    const [args, node, healthy] of [
      [{}, "pve", true],
      [{ node: "node1" }, "node1", true],
      [{ node: "pve2" }, "pve2", false],
    ] as Array<[Record<string, string>, string, boolean]>
  ) {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs,
    });
    const { seen, handler } = router({
      "GET /cluster/status": { data: CLUSTER_OK },
    });
    await withMockedCommand(
      handler,
      () => model.methods.clusterHealth.execute(args, context),
    );
    assertTokenOnly(seen);
    assertEquals(seen.length, 1);
    const written = getWrittenResources();
    assertEquals(written.length, 1);
    assertEquals(written[0].specName, "clusterHealth");
    assertEquals(written[0].name, `cluster-health-${node}`);
    assertEquals(written[0].data.node, node);
    assertEquals(written[0].data.healthy, healthy);
    assertEquals(written[0].data.answeredBy, "node1");
  }
});

Deno.test("clusterHealth fails on an HTTP error or a malformed answer, and writes nothing", async () => {
  for (
    const handler of [
      () => httpOutput(403, { errors: { reason: "Permission check failed" } }),
      () => httpOutput(200, { data: { not: "a list" } }),
    ]
  ) {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs,
    });
    await assertRejects(() =>
      withMockedCommand(
        handler,
        () => model.methods.clusterHealth.execute({}, context),
      )
    );
    assertEquals(getWrittenResources().length, 0);
  }
});

Deno.test("clusterHealth refuses an unsafe node argument or configured node", async () => {
  const args = model.methods.clusterHealth.arguments;
  assertFalse(args.safeParse({ node: "../access" }).success);
  assertFalse(args.safeParse({ node: "pve/x" }).success);
  const { context } = createModelTestContext({
    globalArgs: { ...globalArgs, node: "pve/../x" },
  });
  await assertRejects(
    () => model.methods.clusterHealth.execute({}, context),
    Error,
    "not a Proxmox node name",
  );
});

// ---- ensureRunnerPoolAccess --------------------------------------------------

const RUNNER_TOKEN_ID = "swamp-ci@pve!runner-pool";
const RUNNER_COMMENT = "managed by @dmc/proxmox ensureRunnerPoolAccess";
const RUNNER_PRIVS = ["VM.Allocate", "VM.Audit", "VM.Clone", "VM.PowerMgmt"];
const STORAGE_PATH = "/storage/mrrobot-nfs";
const BRIDGE_PATH = "/sdn/zones/localnetwork/vmbr1v10";

/** Arguments as ensureRunnerPoolAccess sees them, with schema defaults applied. */
function runnerArgs(input: Record<string, unknown>): Record<string, unknown> {
  return model.methods.ensureRunnerPoolAccess.arguments.parse(input);
}

/** Storage and bridge set, template 9000 requested. */
function fullRunnerArgs(over: Record<string, unknown> = {}) {
  return runnerArgs({
    storage: "mrrobot-nfs",
    bridge: "vmbr1v10",
    members: [9000],
    ...over,
  });
}

/** An empty cluster with an unpooled template 9000 and serve (300) in no pool. */
function runnerState(over: Partial<FakePve> = {}): FakePve {
  return pveState({
    guests: [
      { vmid: 9000, type: "qemu", node: "pve" },
      { vmid: 300, type: "qemu", node: "pve" },
    ],
    ...over,
  });
}

/** A finished runner-pool run: three roles, user, token, pool, six ACLs, template pooled. */
function runnerPresentState(over: Partial<FakePve> = {}): FakePve {
  const grants: Array<[string, string]> = [
    ["/pool/ci", "SwampCiPool"],
    [STORAGE_PATH, "SwampCiStorage"],
    [BRIDGE_PATH, "SwampCiNet"],
  ];
  return runnerState({
    roles: [
      { roleid: "SwampCiPool", privs: RUNNER_PRIVS.join(","), special: 0 },
      {
        roleid: "SwampCiStorage",
        privs: "Datastore.AllocateSpace",
        special: 0,
      },
      { roleid: "SwampCiNet", privs: "SDN.Use", special: 0 },
    ],
    users: [{
      userid: "swamp-ci@pve",
      enable: 1,
      tokens: [{ tokenid: "runner-pool", privsep: 1, expire: 0, comment: "" }],
    }],
    acl: grants.flatMap(([path, roleid]) => [
      { path, type: "user", ugid: "swamp-ci@pve", roleid, propagate: 0 },
      { path, type: "token", ugid: RUNNER_TOKEN_ID, roleid, propagate: 0 },
    ]),
    pools: [{ poolid: "ci" }],
    guests: [
      { vmid: 9000, type: "qemu", node: "pve", pool: "ci" },
      { vmid: 300, type: "qemu", node: "pve" },
    ],
    ...over,
  });
}

Deno.test("ensureRunnerPoolAccess arguments default to a dry run of the ci pool with no storage or bridge", () => {
  const a = runnerArgs({});
  assertEquals(a.dryRun, true);
  assertEquals(a.user, "swamp-ci@pve");
  assertEquals(a.tokenName, "runner-pool");
  assertEquals(a.pool, "ci");
  assertEquals(a.role, "SwampCiPool");
  assertEquals(a.storage, undefined);
  assertEquals(a.bridge, undefined);
  assertEquals(a.sdnZone, "localnetwork");
  assertEquals(a.members, []);
});

Deno.test("ensureRunnerPoolAccess arguments refuse unsafe or clashing values", () => {
  const bad: Array<Record<string, unknown>> = [
    { user: "root@pam" },
    { pool: "ci/sub" },
    { role: "PVEVMAdmin" },
    { role: "Administrator" },
    { storage: "../etc" },
    { storage: "a" },
    { bridge: "vmbr0;rm" },
    { bridge: "averyveryverylongbridge" },
    { sdnZone: "local/network" },
    { vlan: 10 },
    { bridge: "vmbr0", vlan: 0 },
    { bridge: "vmbr0", vlan: 4095 },
    { storage: "nfs", storageRole: "SwampCiPool" },
    { bridge: "vmbr0", netRole: "SwampCiPool" },
    { storage: "nfs", bridge: "vmbr0", netRole: "SwampCiStorage" },
    { members: [9000, 9000] },
    { members: [0] },
  ];
  for (const input of bad) {
    assertThrows(
      () => runnerArgs(input),
      Error,
      undefined,
      JSON.stringify(input),
    );
  }
  // A role name only clashes when its grant is used.
  runnerArgs({ storageRole: "SwampCiPool", netRole: "SwampCiPool" });
});

Deno.test("bridgeAclPath adds the VLAN tag only when one is given", () => {
  assertEquals(bridgeAclPath("localnetwork", "vmbr1v10"), BRIDGE_PATH);
  assertEquals(
    bridgeAclPath("localnetwork", "vmbr0", 10),
    "/sdn/zones/localnetwork/vmbr0/10",
  );
});

Deno.test("ensureRunnerPoolAccess dry run on an empty cluster plans a role and two ACLs per grant and only reads", async () => {
  const r = await ensure(
    runnerState(),
    fullRunnerArgs({ dryRun: true }),
    "ensureRunnerPoolAccess",
  );
  assertEquals(r.error, null);
  assertTokenOnly(r.seen);
  assertEquals(writesOf(r.seen), []);
  const rec = writtenData(r.written, "runnerPoolAccess");
  assertEquals(rec.status, "planned");
  assertEquals(rec.actions, [
    { action: "createRole", target: "SwampCiPool", state: "planned" },
    { action: "createRole", target: "SwampCiStorage", state: "planned" },
    { action: "createRole", target: "SwampCiNet", state: "planned" },
    { action: "createUser", target: "swamp-ci@pve", state: "planned" },
    { action: "createPool", target: "ci", state: "planned" },
    { action: "addMembers", target: "9000", state: "planned" },
    { action: "aclUser", target: "/pool/ci", state: "planned" },
    { action: "aclUser", target: STORAGE_PATH, state: "planned" },
    { action: "aclUser", target: BRIDGE_PATH, state: "planned" },
    { action: "createToken", target: RUNNER_TOKEN_ID, state: "planned" },
    { action: "aclToken", target: "/pool/ci", state: "planned" },
    { action: "aclToken", target: STORAGE_PATH, state: "planned" },
    { action: "aclToken", target: BRIDGE_PATH, state: "planned" },
  ]);
  assertEquals(rec.grants, [
    { path: "/pool/ci", role: "SwampCiPool", privileges: RUNNER_PRIVS },
    {
      path: STORAGE_PATH,
      role: "SwampCiStorage",
      privileges: ["Datastore.AllocateSpace"],
    },
    { path: BRIDGE_PATH, role: "SwampCiNet", privileges: ["SDN.Use"] },
  ]);
  assertEquals(rec.blockers, []);
  assertEquals(rec.callerMissing, []);
  assertEquals(rec.verified, []);
  assertFalse(r.written.some((w) => w.specName === "runnerPoolToken"));
  assertFalse(r.written.some((w) => w.specName === "snapshotAccess"));
});

Deno.test("ensureRunnerPoolAccess live writes each role, ACL (propagate 0) and the token, then verifies every path", async () => {
  const r = await ensure(
    runnerState(),
    fullRunnerArgs({ dryRun: false }),
    "ensureRunnerPoolAccess",
  );
  assertEquals(r.error, null);
  assertTokenOnly(r.seen);
  const writes = writesOf(r.seen);
  assertEquals(writes.map((w) => `${w.method} ${new URL(w.url).pathname}`), [
    "POST /api2/json/access/roles",
    "POST /api2/json/access/roles",
    "POST /api2/json/access/roles",
    "POST /api2/json/access/users",
    "POST /api2/json/pools",
    "PUT /api2/json/pools",
    "PUT /api2/json/access/acl",
    "PUT /api2/json/access/acl",
    "PUT /api2/json/access/acl",
    "POST /api2/json/access/users/swamp-ci%40pve/token/runner-pool",
    "PUT /api2/json/access/acl",
    "PUT /api2/json/access/acl",
    "PUT /api2/json/access/acl",
  ]);
  const bodies = writes.map((w) => formOf(w.body));
  assertEquals(bodies.slice(0, 3), [
    { roleid: "SwampCiPool", privs: RUNNER_PRIVS.join(",") },
    { roleid: "SwampCiStorage", privs: "Datastore.AllocateSpace" },
    { roleid: "SwampCiNet", privs: "SDN.Use" },
  ]);
  assertEquals(bodies[3], {
    userid: "swamp-ci@pve",
    enable: "1",
    comment: RUNNER_COMMENT,
  });
  assertEquals(bodies[4], { poolid: "ci", comment: RUNNER_COMMENT });
  assertEquals(bodies[5], { poolid: "ci", vms: "9000" });
  const acls = [6, 7, 8, 10, 11, 12].map((i) => bodies[i]);
  assertEquals(acls.map((b) => [b.path, b.roles, b.users ?? b.tokens]), [
    ["/pool/ci", "SwampCiPool", "swamp-ci@pve"],
    [STORAGE_PATH, "SwampCiStorage", "swamp-ci@pve"],
    [BRIDGE_PATH, "SwampCiNet", "swamp-ci@pve"],
    ["/pool/ci", "SwampCiPool", RUNNER_TOKEN_ID],
    [STORAGE_PATH, "SwampCiStorage", RUNNER_TOKEN_ID],
    [BRIDGE_PATH, "SwampCiNet", RUNNER_TOKEN_ID],
  ]);
  assert(acls.every((b) => b.propagate === "0"));
  assertEquals(bodies[9], { privsep: "1", comment: RUNNER_COMMENT });

  const rec = writtenData(r.written, "runnerPoolAccess");
  assertEquals(rec.status, "applied");
  assertEquals(rec.tokenSecretIssued, true);
  assertEquals(rec.verified, [
    { path: "/pool/ci", privileges: RUNNER_PRIVS, ok: true },
    { path: "/vms/9000", privileges: RUNNER_PRIVS, ok: true },
    {
      path: STORAGE_PATH,
      privileges: ["Datastore.AllocateSpace"],
      ok: true,
    },
    { path: BRIDGE_PATH, privileges: ["SDN.Use"], ok: true },
  ]);
  const token = writtenData(r.written, "runnerPoolToken");
  assertEquals(token.tokenId, RUNNER_TOKEN_ID);
  assertEquals(token.tokenSecret, ACCESS_SECRET);
  assertFalse(JSON.stringify(rec).includes(ACCESS_SECRET));
  assertFalse(r.logs.includes(ACCESS_SECRET));
  assertFalse(r.written.some((w) => w.specName === "snapshotToken"));
});

Deno.test("runnerPoolToken tokenSecret is marked sensitive", () => {
  assertEquals(
    model.resources.runnerPoolToken.schema.shape.tokenSecret.meta()?.sensitive,
    true,
  );
});

Deno.test("ensureRunnerPoolAccess with no storage or bridge grants the pool role only", async () => {
  const r = await ensure(
    runnerState(),
    runnerArgs({ dryRun: false, members: [9000] }),
    "ensureRunnerPoolAccess",
  );
  assertEquals(r.error, null);
  const rec = writtenData(r.written, "runnerPoolAccess");
  assertEquals(rec.grants.map((x: { path: string }) => x.path), ["/pool/ci"]);
  assertEquals(
    writesOf(r.seen).filter((w) => w.url.endsWith("/access/acl")).map((w) =>
      formOf(w.body).path
    ),
    ["/pool/ci", "/pool/ci"],
  );
  assertEquals(rec.verified.map((v: { path: string }) => v.path), [
    "/pool/ci",
    "/vms/9000",
  ]);
});

Deno.test("ensureRunnerPoolAccess adds only the missing grants on a re-run with a bridge", async () => {
  // A first run made the pool and storage grants; this run adds the bridge.
  const st = runnerPresentState();
  st.roles = st.roles.filter((x) => x.roleid !== "SwampCiNet");
  st.acl = st.acl.filter((a) => a.path !== BRIDGE_PATH);
  const r = await ensure(
    st,
    fullRunnerArgs({ dryRun: false }),
    "ensureRunnerPoolAccess",
  );
  assertEquals(r.error, null);
  const writes = writesOf(r.seen).map((w) => formOf(w.body));
  assertEquals(writes, [
    { roleid: "SwampCiNet", privs: "SDN.Use" },
    {
      path: BRIDGE_PATH,
      roles: "SwampCiNet",
      users: "swamp-ci@pve",
      propagate: "0",
    },
    {
      path: BRIDGE_PATH,
      roles: "SwampCiNet",
      tokens: RUNNER_TOKEN_ID,
      propagate: "0",
    },
  ]);
  assertFalse(r.written.some((w) => w.specName === "runnerPoolToken"));
  assertEquals(writtenData(r.written, "runnerPoolAccess").status, "applied");
});

Deno.test("ensureRunnerPoolAccess with everything in place writes nothing and reports clones as extra members", async () => {
  const st = runnerPresentState({
    callerAll: CALLER_PRIVS.filter((p) => p !== "Realm.AllocateUser"),
  });
  st.guests.push(
    { vmid: 9101, type: "qemu", node: "pve", pool: "ci" },
    { vmid: 9102, type: "qemu", node: "pve", pool: "ci" },
  );
  for (const dryRun of [true, false]) {
    const r = await ensure(
      st,
      fullRunnerArgs({ dryRun }),
      "ensureRunnerPoolAccess",
    );
    assertEquals(r.error, null);
    assertEquals(writesOf(r.seen), []);
    const rec = writtenData(r.written, "runnerPoolAccess");
    assertEquals(rec.status, "unchanged");
    assertEquals(rec.extraMembers, [9101, 9102]);
    assertEquals(
      rec.verified.map((v: { path: string; ok: boolean }) => [v.path, v.ok]),
      [
        ["/pool/ci", true],
        ["/vms/9000", true],
        [STORAGE_PATH, true],
        [BRIDGE_PATH, true],
      ],
    );
  }
});

Deno.test("ensureRunnerPoolAccess needs Permissions.Modify on the storage and bridge paths", async () => {
  const r = await ensure(
    runnerState({
      callerPaths: {
        [STORAGE_PATH]: ["Datastore.Audit"],
        [BRIDGE_PATH]: [],
      },
    }),
    fullRunnerArgs({ dryRun: false }),
    "ensureRunnerPoolAccess",
  );
  assert(r.error);
  assertStringIncludes(r.error.message, "ensureRunnerPoolAccess blocked");
  assertEquals(writesOf(r.seen), []);
  const rec = writtenData(r.written, "runnerPoolAccess");
  assertEquals(rec.status, "blocked");
  assertEquals(rec.callerMissing, [
    { path: STORAGE_PATH, privilege: "Permissions.Modify" },
    { path: BRIDGE_PATH, privilege: "Permissions.Modify" },
  ]);
});

const runnerBlockerCases: Array<[string, (s: FakePve) => void, string]> = [
  [
    "the storage grant propagates",
    (s) => {
      s.acl.find((a) => a.path === STORAGE_PATH && a.type === "token")!
        .propagate = 1;
    },
    `token ${RUNNER_TOKEN_ID} has role SwampCiStorage on ${STORAGE_PATH} with propagate 1`,
  ],
  [
    "the token holds the storage role on another storage",
    (s) => {
      s.acl.push({
        path: "/storage/local",
        type: "token",
        ugid: RUNNER_TOKEN_ID,
        roleid: "SwampCiStorage",
        propagate: 0,
      });
    },
    "has role SwampCiStorage on /storage/local",
  ],
  [
    "the net role holds an extra privilege",
    (s) => {
      s.roles.find((x) => x.roleid === "SwampCiNet")!.privs =
        "SDN.Use,SDN.Allocate";
    },
    "role SwampCiNet has extra privileges: SDN.Allocate",
  ],
  [
    "the pool role is granted to someone else",
    (s) => {
      s.acl.push({
        path: "/pool/ci",
        type: "user",
        ugid: "other@pve",
        roleid: "SwampCiPool",
        propagate: 0,
      });
    },
    "role SwampCiPool is granted to user other@pve on /pool/ci",
  ],
  [
    "the template is in another pool",
    (s) => {
      s.guests.find((x) => x.vmid === 9000)!.pool = "patch";
    },
    "guest 9000 is in pool patch; guests are never moved between pools",
  ],
];

for (const [name, mutate, expected] of runnerBlockerCases) {
  Deno.test(`ensureRunnerPoolAccess blocks when ${name}, dry run or live, with no writes`, async () => {
    for (const dryRun of [true, false]) {
      const st = runnerPresentState();
      mutate(st);
      const r = await ensure(
        st,
        fullRunnerArgs({ dryRun }),
        "ensureRunnerPoolAccess",
      );
      assert(r.error, `${name} (dryRun ${dryRun}) must fail`);
      assertStringIncludes(r.error.message, expected);
      assertEquals(writesOf(r.seen), []);
      assertEquals(
        writtenData(r.written, "runnerPoolAccess").status,
        "blocked",
      );
    }
  });
}

Deno.test("ensureRunnerPoolAccess fails when the token holds more than Datastore.AllocateSpace on the storage", async () => {
  for (const dryRun of [true, false]) {
    const r = await ensure(
      runnerPresentState({
        pathExtra: { [STORAGE_PATH]: ["Datastore.Allocate"] },
      }),
      fullRunnerArgs({ dryRun }),
      "ensureRunnerPoolAccess",
    );
    assert(r.error);
    assertStringIncludes(
      r.error.message,
      `${RUNNER_TOKEN_ID} does not have exactly Datastore.AllocateSpace on ${STORAGE_PATH}`,
    );
    assertEquals(writesOf(r.seen), []);
    const rec = writtenData(r.written, "runnerPoolAccess");
    assertEquals(rec.status, dryRun ? "blocked" : "failed");
  }
});

Deno.test("ensureRunnerPoolAccess with a VLAN grants SDN.Use on the tag path only", async () => {
  const r = await ensure(
    runnerState(),
    runnerArgs({ dryRun: false, bridge: "vmbr0", vlan: 10 }),
    "ensureRunnerPoolAccess",
  );
  assertEquals(r.error, null);
  const rec = writtenData(r.written, "runnerPoolAccess");
  assertEquals(rec.grants[1], {
    path: "/sdn/zones/localnetwork/vmbr0/10",
    role: "SwampCiNet",
    privileges: ["SDN.Use"],
  });
});
