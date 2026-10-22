import {
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import {
  createModelTestContext,
  withMockedCommand,
} from "jsr:@systeminit/swamp-testing@0.20260604.20";
import { extension } from "./proxmox_vm_extras.ts";

const globalArgs = {
  apiUrl: "https://proxmox.test:8006",
  node: "pve",
  skipTlsVerify: true,
  ticket: "test-ticket",
  csrfToken: "test-csrf",
};

function httpOutput(status: number, body: unknown) {
  return {
    stdout: `HTTP/1.1 ${status} OK\r\n\r\n${JSON.stringify(body)}`,
    code: 0,
  };
}

const clusterCheck = extension.checks[0]["cluster-has-migration-target"];
const migrate = extension.methods[0].migrate;

Deno.test("cluster-has-migration-target passes for a healthy multi-node cluster", async () => {
  const { context } = createModelTestContext({ globalArgs });

  const { result } = await withMockedCommand(
    [
      httpOutput(200, {
        data: [
          { type: "node", name: "pve", online: 1 },
          { type: "node", name: "pve2", online: 1 },
        ],
      }),
    ],
    () => clusterCheck.execute({ ...context, methodName: "migrate" }),
  );

  assertEquals(result, { pass: true });
});

Deno.test("cluster-has-migration-target fails on a standalone node", async () => {
  const { context } = createModelTestContext({ globalArgs });

  const { result } = await withMockedCommand(
    [httpOutput(200, { data: [{ type: "node", name: "pve", online: 1 }] })],
    () => clusterCheck.execute({ ...context, methodName: "migrate" }),
  );

  assertEquals(result.pass, false);
});

Deno.test("cluster-has-migration-target fails when the node is reported offline", async () => {
  const { context } = createModelTestContext({ globalArgs });

  const { result } = await withMockedCommand(
    [
      httpOutput(200, {
        data: [
          { type: "node", name: "pve", online: 0 },
          { type: "node", name: "pve2", online: 1 },
        ],
      }),
    ],
    () => clusterCheck.execute({ ...context, methodName: "migrate" }),
  );

  assertEquals(result.pass, false);
});

Deno.test("cluster-has-migration-target fails when the cluster status call errors", async () => {
  const { context } = createModelTestContext({ globalArgs });

  const { result } = await withMockedCommand(
    [httpOutput(500, {})],
    () => clusterCheck.execute({ ...context, methodName: "migrate" }),
  );

  assertEquals(result.pass, false);
});

Deno.test("migrate moves a running VM to the target node", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });

  await withMockedCommand(
    [
      httpOutput(200, {
        data: [{ vmid: 100, name: "test-vm", status: "running" }],
      }), // resolveVmId
      httpOutput(200, { data: "UPID:pve:00000004:qmigrate:" }), // migrate POST
      httpOutput(200, { data: { status: "stopped", exitstatus: "OK" } }), // waitForTask
    ],
    () =>
      migrate.execute(
        { vmName: "test-vm", target: "pve2", online: true },
        context,
      ),
  );

  const written = getWrittenResources()[0].data;
  assertEquals(written.success, true);
  assertEquals(written.sourceNode, "pve");
  assertEquals(written.targetNode, "pve2");
});

Deno.test("migrate throws when the VM is not found", async () => {
  const { context } = createModelTestContext({ globalArgs });

  await assertRejects(
    () =>
      withMockedCommand(
        [httpOutput(200, { data: [] })],
        () =>
          migrate.execute(
            { vmName: "does-not-exist", target: "pve2", online: true },
            context,
          ),
      ),
    Error,
    "not found",
  );
});

// ---- createFromImage --------------------------------------------------------

const createFromImage = extension.methods[0].createFromImage;
const baseCreateArgs = {
  vmName: "new-vm",
  vmid: 300,
  importFrom: "nfs:import/rocky10.qcow2",
  diskStorage: "nfs",
};

/** The `-d` form body of one recorded curl call, parsed. */
function formBody(call: { args: string[] }): URLSearchParams {
  return new URLSearchParams(call.args[call.args.indexOf("-d") + 1]);
}

async function runCreate(
  args: Record<string, unknown>,
  responses: Array<{ stdout: string; code: number }>,
) {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const parsed = createFromImage.arguments.parse({
    ...baseCreateArgs,
    ...args,
  });
  const { calls } = await withMockedCommand(
    responses,
    () => createFromImage.execute(parsed, context),
  );
  return { calls, written: getWrittenResources()[0]?.data };
}

const createOk = [
  httpOutput(200, { data: "UPID:pve:00000001:qmcreate:" }), // create POST
  httpOutput(200, { data: { status: "stopped", exitstatus: "OK" } }), // waitForTask
];
const cloudInitOk = httpOutput(200, { data: null }); // cloud-init PUT

Deno.test("createFromImage sends the defaults when no hardware inputs are given", async () => {
  const { calls, written } = await runCreate({}, [...createOk, cloudInitOk]);

  const create = formBody(calls[0]);
  assertEquals(create.get("cpu"), "Broadwell-noTSX");
  assertEquals(create.get("sockets"), "1");
  assertEquals(create.get("ostype"), "l26");
  assertEquals(create.get("agent"), "1");
  assertEquals(create.get("serial0"), "socket");
  assertEquals(
    create.get("virtio0"),
    "nfs:0,import-from=nfs:import/rocky10.qcow2,iothread=1,discard=on",
  );
  // No diskSize: create, wait, cloud-init — and no resize call.
  assertEquals(calls.length, 3);
  assertEquals(
    calls.some((c: { args: string[] }) => c.args.join(" ").includes("/resize")),
    false,
  );
  assertEquals(written.success, true);
});

Deno.test("createFromImage passes explicit hardware inputs through", async () => {
  const { calls } = await runCreate(
    {
      cpu: "Broadwell",
      sockets: 2,
      ostype: "other",
      agent: false,
      serialConsole: false,
      diskOptions: "cache=writeback",
    },
    [...createOk, cloudInitOk],
  );

  const create = formBody(calls[0]);
  assertEquals(create.get("cpu"), "Broadwell");
  assertEquals(create.get("sockets"), "2");
  assertEquals(create.get("ostype"), "other");
  assertEquals(create.get("agent"), "0");
  assertEquals(create.has("serial0"), false);
  assertEquals(
    create.get("virtio0"),
    "nfs:0,import-from=nfs:import/rocky10.qcow2,cache=writeback",
  );
});

Deno.test("createFromImage with an empty diskOptions adds no trailing comma", async () => {
  const { calls } = await runCreate({ diskOptions: "" }, [
    ...createOk,
    cloudInitOk,
  ]);
  assertEquals(
    formBody(calls[0]).get("virtio0"),
    "nfs:0,import-from=nfs:import/rocky10.qcow2",
  );
});

Deno.test("createFromImage grows virtio0 to diskSize before cloud-init (resize task)", async () => {
  const { calls, written } = await runCreate({ diskSize: 32 }, [
    ...createOk,
    httpOutput(200, { data: "UPID:pve:00000002:resize:" }), // resize PUT
    httpOutput(200, { data: { status: "stopped", exitstatus: "OK" } }), // waitForTask
    cloudInitOk,
  ]);

  const resize = calls[2];
  assertStringIncludes(resize.args.join(" "), "/nodes/pve/qemu/300/resize");
  assertEquals(formBody(resize).get("disk"), "virtio0");
  assertEquals(formBody(resize).get("size"), "32G");
  assertStringIncludes(calls[4].args.join(" "), "/qemu/300/config");
  assertStringIncludes(String(written.logs), "virtio0 is now 32G");
});

Deno.test("createFromImage accepts an inline resize (older Proxmox returns null)", async () => {
  const { calls } = await runCreate({ diskSize: 32 }, [
    ...createOk,
    httpOutput(200, { data: null }), // resize PUT, no task
    cloudInitOk,
  ]);
  assertEquals(calls.length, 4);
  assertStringIncludes(calls[3].args.join(" "), "/qemu/300/config");
});

/** Run createFromImage expecting it to throw; return the error and the calls. */
async function runCreateFailing(
  args: Record<string, unknown>,
  responses: Array<{ stdout: string; code: number }>,
) {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });
  const parsed = createFromImage.arguments.parse({
    ...baseCreateArgs,
    ...args,
  });
  const { result, calls } = await withMockedCommand(
    responses,
    async () => {
      try {
        await createFromImage.execute(parsed, context);
      } catch (err) {
        return err as Error;
      }
      throw new Error("createFromImage did not throw");
    },
  );
  return { error: result, calls, written: getWrittenResources() };
}

const http500 = (body: string) => ({
  stdout: `HTTP/1.1 500 Internal Server Error\r\n\r\n${body}`,
  code: 0,
});
const deleteOk = [
  httpOutput(200, { data: "UPID:pve:00000003:qmdestroy:" }), // DELETE
  httpOutput(200, { data: { status: "stopped", exitstatus: "OK" } }), // waitForTask
];

Deno.test("createFromImage removes the new VM when the resize is rejected", async () => {
  const { error, calls, written } = await runCreateFailing({ diskSize: 4 }, [
    ...createOk,
    http500("shrinking disks is not supported"),
    ...deleteOk,
  ]);

  assertStringIncludes(error.message, "Failed to grow virtio0 to 4G");
  assertStringIncludes(error.message, "VM 300 was removed again");
  const del = calls[3].args.join(" ");
  assertStringIncludes(del, "-X DELETE");
  assertStringIncludes(
    del,
    "/nodes/pve/qemu/300?purge=1&destroy-unreferenced-disks=1",
  );
  assertEquals(written.length, 0);
});

Deno.test("createFromImage removes the new VM when the resize task fails", async () => {
  const { error } = await runCreateFailing({ diskSize: 32 }, [
    ...createOk,
    httpOutput(200, { data: "UPID:pve:00000002:resize:" }),
    httpOutput(200, { data: { status: "stopped", exitstatus: "ERROR" } }),
    ...deleteOk,
  ]);
  assertStringIncludes(error.message, "Growing virtio0 to 32G failed");
  assertStringIncludes(error.message, "safe to re-run");
});

Deno.test("createFromImage removes the new VM when cloud-init fails", async () => {
  const { error, calls } = await runCreateFailing({}, [
    ...createOk,
    http500("bad sshkeys"),
    ...deleteOk,
  ]);
  assertStringIncludes(error.message, "Failed to configure cloud-init");
  assertStringIncludes(error.message, "VM 300 was removed again");
  assertStringIncludes(calls[3].args.join(" "), "-X DELETE");
});

Deno.test("createFromImage says so when the half-built VM cannot be removed", async () => {
  const { error } = await runCreateFailing({}, [
    ...createOk,
    http500("bad sshkeys"),
    http500("VM is locked"), // DELETE refused
  ]);
  assertStringIncludes(error.message, "Failed to configure cloud-init");
  assertStringIncludes(error.message, "could not be removed");
  assertStringIncludes(error.message, "VM is locked");
  assertStringIncludes(error.message, "delete it before re-running");
});

Deno.test("createFromImage does not remove anything when the create itself fails", async () => {
  const { error, calls } = await runCreateFailing({}, [
    httpOutput(200, { data: "UPID:pve:00000001:qmcreate:" }),
    httpOutput(200, { data: { status: "stopped", exitstatus: "ERROR" } }),
  ]);
  assertStringIncludes(error.message, "VM creation failed");
  assertEquals(calls.length, 2);
});

Deno.test("createFromImage rejects a non-positive diskSize", () => {
  assertEquals(
    createFromImage.arguments.safeParse({ ...baseCreateArgs, diskSize: 0 })
      .success,
    false,
  );
});

// ---- pre-flight checks ------------------------------------------------------

const preflight = extension.checks[0];
type PreflightName = Exclude<
  keyof typeof preflight,
  "cluster-has-migration-target"
>;
type PreflightCtx = Parameters<typeof preflight["guest-exists"]["execute"]>[0];

const MUTATING_METHODS = [
  "createFromImage",
  "configureCloudInit",
  "snapshot",
  "deleteSnapshot",
  "moveDisk",
  "lxcStop",
  "lxcStart",
  "lxcMoveVolume",
  "migrate",
];
const READ_ONLY_METHODS = ["listSnapshots", "getConfig"];

/** Run one check for a method with raw method args and a queue of API responses. */
async function runCheck(
  name: PreflightName,
  methodName: string,
  methodArgs: Record<string, unknown>,
  responses: Array<{ stdout: string; code: number }> = [],
) {
  const { context } = createModelTestContext({ globalArgs });
  const ctx = {
    ...context,
    methodName,
    unresolvedMethodArgs: methodArgs,
  } as unknown as PreflightCtx;
  const { result, calls } = await withMockedCommand(
    responses,
    () => preflight[name].execute(ctx),
  );
  return { result, calls };
}

const qemuList = httpOutput(200, {
  data: [{ vmid: 100, name: "test-vm", status: "running" }],
});
const lxcList = httpOutput(200, {
  data: [{ vmid: 200, name: "test-ct", status: "running" }],
});

Deno.test("every mutating method is covered by at least one check", () => {
  for (const method of MUTATING_METHODS) {
    const covering = Object.values(preflight).filter((c) =>
      c.appliesTo.includes(method)
    );
    assertEquals(covering.length > 0, true, `${method} has no check`);
  }
});

Deno.test("read-only methods are not covered by any check", () => {
  for (const method of READ_ONLY_METHODS) {
    const covering = Object.values(preflight).filter((c) =>
      c.appliesTo.includes(method)
    );
    assertEquals(covering.length, 0, `${method} must have no check`);
  }
});

Deno.test("every method is classified as mutating or read-only", () => {
  assertEquals(
    Object.keys(extension.methods[0]).sort(),
    [...MUTATING_METHODS, ...READ_ONLY_METHODS].sort(),
  );
});

Deno.test("every check has a label and a description", () => {
  for (const check of Object.values(preflight)) {
    assertEquals(check.labels.length > 0, true);
    assertEquals(check.description.length > 0, true);
  }
});

Deno.test("guest-exists passes for an existing VM", async () => {
  const { result, calls } = await runCheck(
    "guest-exists",
    "snapshot",
    { vmName: "test-vm" },
    [qemuList],
  );
  assertEquals(result, { pass: true });
  assertEquals(calls.length, 1);
});

Deno.test("guest-exists fails for a missing VM and tells how to skip", async () => {
  const { result } = await runCheck(
    "guest-exists",
    "moveDisk",
    { vmName: "ghost" },
    [qemuList],
  );
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors?.[0] ?? "", '"ghost"');
  assertStringIncludes(result.errors?.[0] ?? "", "test-vm");
  assertStringIncludes(result.errors?.[0] ?? "", "--skip-check guest-exists");
});

Deno.test("guest-exists uses the LXC list and ctName for container methods", async () => {
  const ok = await runCheck("guest-exists", "lxcStop", { ctName: "test-ct" }, [
    lxcList,
  ]);
  assertEquals(ok.result, { pass: true });
  assertStringIncludes(ok.calls[0].args.join(" "), "/nodes/pve/lxc");

  const bad = await runCheck("guest-exists", "lxcStart", { ctName: "ghost" }, [
    lxcList,
  ]);
  assertEquals(bad.result.pass, false);
  assertStringIncludes(bad.result.errors?.[0] ?? "", "LXC");
});

Deno.test("guest-exists for migrate looks on sourceNode when given", async () => {
  const { result, calls } = await runCheck(
    "guest-exists",
    "migrate",
    { vmName: "test-vm", target: "pve2", sourceNode: "pve3" },
    [qemuList],
  );
  assertEquals(result, { pass: true });
  assertStringIncludes(calls[0].args.join(" "), "/nodes/pve3/qemu");
});

Deno.test("guest-exists fails when the API call errors", async () => {
  const { result } = await runCheck(
    "guest-exists",
    "snapshot",
    { vmName: "test-vm" },
    [httpOutput(500, {})],
  );
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors?.[0] ?? "", "--skip-check-label live");
});

Deno.test("guest-exists passes without a call when the name arg is missing", async () => {
  const { result, calls } = await runCheck("guest-exists", "snapshot", {});
  assertEquals(result, { pass: true });
  assertEquals(calls.length, 0);
});

Deno.test("vmid-free passes when the vmid is unused", async () => {
  const { result } = await runCheck(
    "vmid-free",
    "createFromImage",
    { vmName: "new", vmid: 300 },
    [httpOutput(200, { data: [{ vmid: 100, name: "a" }] })],
  );
  assertEquals(result, { pass: true });
});

Deno.test("vmid-free fails when the vmid is taken anywhere in the cluster", async () => {
  const { result } = await runCheck(
    "vmid-free",
    "createFromImage",
    { vmName: "new", vmid: 100 },
    [httpOutput(200, { data: [{ vmid: 100, name: "taken-vm" }] })],
  );
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors?.[0] ?? "", "taken-vm");
  assertStringIncludes(result.errors?.[0] ?? "", "--skip-check vmid-free");
});

Deno.test("vmid-free passes without a call when no vmid is given", async () => {
  const { result, calls } = await runCheck("vmid-free", "createFromImage", {
    vmName: "new",
  });
  assertEquals(result, { pass: true });
  assertEquals(calls.length, 0);
});

Deno.test("vmid-free fails when the API call errors", async () => {
  const { result } = await runCheck(
    "vmid-free",
    "createFromImage",
    { vmid: 5 },
    [httpOutput(500, {})],
  );
  assertEquals(result.pass, false);
});

Deno.test("vmid-free passes without a call under a plain `swamp model validate` (empty methodName), even for a taken vmid", async () => {
  // An existing VM's own vmid (merged in from its global args) is always taken.
  const { result, calls } = await runCheck("vmid-free", "", { vmid: 100 }, [
    httpOutput(200, { data: [{ vmid: 100, name: "this-vm" }] }),
  ]);
  assertEquals(result, { pass: true });
  assertEquals(calls.length, 0);
});

Deno.test("cluster-has-migration-target passes without a call under a plain `swamp model validate` (empty methodName)", async () => {
  const { context } = createModelTestContext({ globalArgs });
  const { result, calls } = await withMockedCommand(
    [httpOutput(200, { data: [{ type: "node", name: "pve", online: 1 }] })],
    () => clusterCheck.execute({ ...context, methodName: "" }),
  );
  assertEquals(result, { pass: true });
  assertEquals(calls.length, 0);
});

const imageArgs = {
  vmName: "v",
  importFrom: "mrrobot:import/rocky10.qcow2",
  diskStorage: "mrrobot",
};
const tenGiBImage = httpOutput(200, {
  data: { format: "qcow2", size: 10 * 1024 ** 3, used: 520355840 },
});

Deno.test("disk-size-fits-image passes when diskSize is at least the image's virtual size", async () => {
  const { result, calls } = await runCheck(
    "disk-size-fits-image",
    "createFromImage",
    { ...imageArgs, diskSize: 32 },
    [tenGiBImage],
  );
  assertEquals(result, { pass: true });
  assertStringIncludes(
    calls[0].args.join(" "),
    "/nodes/pve/storage/mrrobot/content/mrrobot%3Aimport%2Frocky10.qcow2",
  );

  const exact = await runCheck(
    "disk-size-fits-image",
    "createFromImage",
    { ...imageArgs, diskSize: 10 },
    [tenGiBImage],
  );
  assertEquals(exact.result, { pass: true });
});

Deno.test("disk-size-fits-image fails when diskSize is smaller than the image", async () => {
  const { result } = await runCheck(
    "disk-size-fits-image",
    "createFromImage",
    { ...imageArgs, diskSize: 4 },
    [tenGiBImage],
  );
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors?.[0] ?? "", "smaller than the image");
  assertStringIncludes(result.errors?.[0] ?? "", "at least 10");
});

Deno.test("disk-size-fits-image passes without a call when diskSize is unset or importFrom unresolved", async () => {
  const unset = await runCheck(
    "disk-size-fits-image",
    "createFromImage",
    imageArgs,
  );
  assertEquals(unset.result, { pass: true });
  assertEquals(unset.calls.length, 0);

  const unresolved = await runCheck(
    "disk-size-fits-image",
    "createFromImage",
    {
      ...imageArgs,
      importFrom: '${{ data.latest("s", "img").attributes.storageRef }}',
      diskSize: 32,
    },
  );
  assertEquals(unresolved.result, { pass: true });
  assertEquals(unresolved.calls.length, 0);
});

Deno.test("disk-size-fits-image fails when the image cannot be read", async () => {
  const { result } = await runCheck(
    "disk-size-fits-image",
    "createFromImage",
    { ...imageArgs, diskSize: 32 },
    [httpOutput(500, {})],
  );
  assertEquals(result.pass, false);
});

Deno.test("disk-size-fits-image passes without a call under a plain `swamp model validate` (empty methodName)", async () => {
  const { result, calls } = await runCheck(
    "disk-size-fits-image",
    "",
    { ...imageArgs, diskSize: 4 },
  );
  assertEquals(result, { pass: true });
  assertEquals(calls.length, 0);
});

Deno.test("target-storage-exists passes for an active storage (createFromImage and moveDisk)", async () => {
  const a = await runCheck(
    "target-storage-exists",
    "createFromImage",
    { diskStorage: "local-lvm" },
    [httpOutput(200, { data: { active: 1 } })],
  );
  assertEquals(a.result, { pass: true });
  assertStringIncludes(a.calls[0].args.join(" "), "/storage/local-lvm/status");

  const b = await runCheck(
    "target-storage-exists",
    "moveDisk",
    { vmName: "v", targetStorage: "nfs1" },
    [httpOutput(200, { data: { active: 1 } })],
  );
  assertEquals(b.result, { pass: true });
  assertStringIncludes(b.calls[0].args.join(" "), "/storage/nfs1/status");
});

Deno.test("target-storage-exists fails when the storage is missing", async () => {
  const { result } = await runCheck(
    "target-storage-exists",
    "lxcMoveVolume",
    { ctName: "c", targetStorage: "nope" },
    [httpOutput(500, { data: null })],
  );
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors?.[0] ?? "", '"nope"');
});

Deno.test("target-storage-exists fails when the storage is inactive", async () => {
  const { result } = await runCheck(
    "target-storage-exists",
    "moveDisk",
    { vmName: "v", targetStorage: "nfs1" },
    [httpOutput(200, { data: { active: 0 } })],
  );
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors?.[0] ?? "", "not active");
});

Deno.test("snapshot-name-valid accepts good names and is a policy check (no network)", async () => {
  for (const snapname of ["pre_update-1", "ab", "A1"]) {
    const { result, calls } = await runCheck(
      "snapshot-name-valid",
      "snapshot",
      { snapname },
    );
    assertEquals(result, { pass: true }, snapname);
    assertEquals(calls.length, 0);
  }
  assertEquals(preflight["snapshot-name-valid"].labels, ["policy"]);
});

Deno.test("snapshot-name-valid rejects bad names", async () => {
  for (
    const snapname of ["1start", "has space", "x", "current", "a".repeat(41)]
  ) {
    const { result } = await runCheck("snapshot-name-valid", "snapshot", {
      snapname,
    });
    assertEquals(result.pass, false, snapname);
    assertStringIncludes(result.errors?.[0] ?? "", "--skip-check");
  }
});

Deno.test("snapshot-name-free passes when the name is unused", async () => {
  const { result } = await runCheck(
    "snapshot-name-free",
    "snapshot",
    { vmName: "test-vm", snapname: "fresh" },
    [qemuList, httpOutput(200, { data: [{ name: "current" }] })],
  );
  assertEquals(result, { pass: true });
});

Deno.test("snapshot-name-free fails when the name already exists", async () => {
  const { result } = await runCheck(
    "snapshot-name-free",
    "snapshot",
    { vmName: "test-vm", snapname: "old" },
    [
      qemuList,
      httpOutput(200, { data: [{ name: "old" }, { name: "current" }] }),
    ],
  );
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors?.[0] ?? "", '"old"');
});

Deno.test("snapshot-name-free fails when the VM is not found", async () => {
  const { result } = await runCheck(
    "snapshot-name-free",
    "snapshot",
    { vmName: "ghost", snapname: "x1" },
    [qemuList],
  );
  assertEquals(result.pass, false);
});

Deno.test("snapshot-exists passes when the snapshot exists", async () => {
  const { result } = await runCheck(
    "snapshot-exists",
    "deleteSnapshot",
    { vmName: "test-vm", snapname: "old" },
    [
      qemuList,
      httpOutput(200, { data: [{ name: "old" }, { name: "current" }] }),
    ],
  );
  assertEquals(result, { pass: true });
});

Deno.test("snapshot-exists fails when the snapshot is missing", async () => {
  const { result } = await runCheck(
    "snapshot-exists",
    "deleteSnapshot",
    { vmName: "test-vm", snapname: "gone" },
    [
      qemuList,
      httpOutput(200, { data: [{ name: "old" }, { name: "current" }] }),
    ],
  );
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors?.[0] ?? "", '"gone"');
  assertStringIncludes(result.errors?.[0] ?? "", "old");
  assertStringIncludes(
    result.errors?.[0] ?? "",
    "--skip-check snapshot-exists",
  );
});

Deno.test("snapshot-exists fails when the snapshot list call errors", async () => {
  const { result } = await runCheck(
    "snapshot-exists",
    "deleteSnapshot",
    { vmName: "test-vm", snapname: "old" },
    [qemuList, httpOutput(500, {})],
  );
  assertEquals(result.pass, false);
});

Deno.test("the existing cluster-has-migration-target check still covers migrate", () => {
  assertEquals(clusterCheck.appliesTo, ["migrate"]);
  assertEquals(clusterCheck.labels, ["live"]);
});
