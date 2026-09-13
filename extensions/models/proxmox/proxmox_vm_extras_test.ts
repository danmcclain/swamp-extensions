import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  createModelTestContext,
  withMockedCommand,
} from "jsr:@systeminit/swamp-testing";
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
