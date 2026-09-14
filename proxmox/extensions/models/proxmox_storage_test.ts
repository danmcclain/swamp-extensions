import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  createModelTestContext,
  withMockedCommand,
} from "jsr:@systeminit/swamp-testing";
import { model } from "./proxmox_storage.ts";

const globalArgs = {
  apiUrl: "https://proxmox.test:8006",
  node: "pve",
  storage: "mrrobot",
  skipTlsVerify: true,
  ticket: "test-ticket",
  csrfToken: "test-csrf",
  realm: "pam",
};

function httpOutput(status: number, body: unknown) {
  return {
    stdout: `HTTP/1.1 ${status} OK\r\n\r\n${JSON.stringify(body)}`,
    code: 0,
  };
}

Deno.test("downloadImage skips the download when the file already exists", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });

  const { calls } = await withMockedCommand(
    [httpOutput(200, { data: [{ volid: "mrrobot:import/rocky10.qcow2" }] })],
    () =>
      model.methods.downloadImage.execute(
        {
          url: "https://example.com/rocky10.qcow2",
          filename: "rocky10.qcow2",
        },
        context,
      ),
  );

  assertEquals(calls.length, 1, "should only check content, never download");
  assertEquals(
    getWrittenResources()[0].data.storageRef,
    "mrrobot:import/rocky10.qcow2",
  );
});

Deno.test("downloadImage downloads and records the volid when the file is new", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });

  await withMockedCommand(
    [
      httpOutput(200, { data: [] }), // initial existence check: not found
      httpOutput(200, { data: "UPID:pve:00000001:qmdownload:" }), // start download
      httpOutput(200, { data: { status: "stopped", exitstatus: "OK" } }), // task poll
      httpOutput(200, { data: [{ volid: "mrrobot:import/new.qcow2" }] }), // final content list
    ],
    () =>
      model.methods.downloadImage.execute(
        { url: "https://example.com/new.qcow2", filename: "new.qcow2" },
        context,
      ),
  );

  assertEquals(
    getWrittenResources()[0].data.storageRef,
    "mrrobot:import/new.qcow2",
  );
});

Deno.test("downloadImage treats Proxmox's 'refusing to override existing file' as idempotent success", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs,
  });

  await withMockedCommand(
    [
      httpOutput(200, { data: [] }), // initial check misses (race)
      httpOutput(200, { data: "UPID:pve:00000002:qmdownload:" }),
      httpOutput(200, {
        data: {
          status: "stopped",
          exitstatus: "refusing to override existing file",
        },
      }),
      httpOutput(200, { data: [{ volid: "mrrobot:import/race.qcow2" }] }),
    ],
    () =>
      model.methods.downloadImage.execute(
        { url: "https://example.com/race.qcow2", filename: "race.qcow2" },
        context,
      ),
  );

  assertEquals(
    getWrittenResources()[0].data.storageRef,
    "mrrobot:import/race.qcow2",
  );
});

Deno.test("downloadImage throws on a genuine download task failure", async () => {
  const { context } = createModelTestContext({ globalArgs });

  await assertRejects(
    () =>
      withMockedCommand(
        [
          httpOutput(200, { data: [] }),
          httpOutput(200, { data: "UPID:pve:00000003:qmdownload:" }),
          httpOutput(200, {
            data: { status: "stopped", exitstatus: "TASK ERROR: disk full" },
          }),
        ],
        () =>
          model.methods.downloadImage.execute(
            { url: "https://example.com/bad.qcow2", filename: "bad.qcow2" },
            context,
          ),
      ),
    Error,
    "Download task failed",
  );
});

Deno.test("storage-target-exists check passes for an active storage", async () => {
  const { context } = createModelTestContext({ globalArgs });

  const { result } = await withMockedCommand(
    [httpOutput(200, { data: { active: 1 } })],
    () => model.checks["storage-target-exists"].execute(context),
  );

  assertEquals(result, { pass: true });
});

Deno.test("storage-target-exists check fails when the storage is not found on the node", async () => {
  const { context } = createModelTestContext({ globalArgs });

  const { result } = await withMockedCommand(
    [httpOutput(500, { data: null })],
    () => model.checks["storage-target-exists"].execute(context),
  );

  assertEquals(result.pass, false);
});

Deno.test("storage-target-exists check fails when the storage is inactive", async () => {
  const { context } = createModelTestContext({ globalArgs });

  const { result } = await withMockedCommand(
    [httpOutput(200, { data: { active: 0 } })],
    () => model.checks["storage-target-exists"].execute(context),
  );

  assertEquals(result.pass, false);
});
