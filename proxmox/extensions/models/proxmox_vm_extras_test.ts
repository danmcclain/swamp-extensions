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
    () => clusterCheck.execute(context),
  );

  assertEquals(result, { pass: true });
});

Deno.test("cluster-has-migration-target fails on a standalone node", async () => {
  const { context } = createModelTestContext({ globalArgs });

  const { result } = await withMockedCommand(
    [httpOutput(200, { data: [{ type: "node", name: "pve", online: 1 }] })],
    () => clusterCheck.execute(context),
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
    () => clusterCheck.execute(context),
  );

  assertEquals(result.pass, false);
});

Deno.test("cluster-has-migration-target fails when the cluster status call errors", async () => {
  const { context } = createModelTestContext({ globalArgs });

  const { result } = await withMockedCommand(
    [httpOutput(500, {})],
    () => clusterCheck.execute(context),
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
