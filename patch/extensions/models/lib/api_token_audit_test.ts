/**
 * Unit tests for the snapshot API token audit: auditApiToken turns one node model's
 * `permissions` answer into findings, and requiredPrivileges says what a guest's
 * snapshots need. Pure: nothing runs and nothing is contacted.
 */
import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import {
  type ApiTokenInput,
  auditApiToken,
  requiredPrivileges,
} from "./api_token_audit.ts";

/** The four privileges a snapshot token holds on its pool and its guest. */
const SNAPSHOT = [
  "VM.Audit",
  "VM.PowerMgmt",
  "VM.Snapshot",
  "VM.Snapshot.Rollback",
];

/** One `permissions` path entry, every privilege propagated. */
function perm(path: string, names: string[]) {
  return { path, privileges: names.map((name) => ({ name, propagate: true })) };
}

/** The paths of a clean CT token: its pool and its guest, the four privileges on each. */
const CLEAN_CT = [perm("/pool/patch", SNAPSHOT), perm("/vms/101", SNAPSHOT)];

/** A token for a CT 101 on node model patch-pve, readable, with the given overrides. */
function tokenOf(over: Partial<ApiTokenInput> = {}): ApiTokenInput {
  return {
    model: "patch-pve",
    guest: { type: "ct", vmid: 101 },
    paths: CLEAN_CT,
    error: null,
    ...over,
  };
}

/** Run auditApiToken and collect what it adds. */
function findingsOf(t: ApiTokenInput) {
  const out: Array<{ id: string; severity: string; message: string }> = [];
  auditApiToken(t, (id, severity, message) => {
    out.push({ id, severity, message });
  });
  return out;
}

/** The findings of a token as "id severity", in order. */
const ids = (t: ApiTokenInput) =>
  findingsOf(t).map((f) => `${f.id} ${f.severity}`);

Deno.test("auditApiToken: a CT token with the four privileges on its pool and guest has no findings", () => {
  assertEquals(findingsOf(tokenOf()), []);
});

Deno.test("auditApiToken: a VM needs no VM.PowerMgmt, a CT does", () => {
  const vmPrivs = ["VM.Audit", "VM.Snapshot", "VM.Snapshot.Rollback"];
  const vm = tokenOf({
    guest: { type: "vm", vmid: 100 },
    paths: [perm("/pool/patch", SNAPSHOT), perm("/vms/100", vmPrivs)],
  });
  assertEquals(findingsOf(vm), []);
  const ct = tokenOf({
    paths: [perm("/pool/patch", SNAPSHOT), perm("/vms/101", vmPrivs)],
  });
  assertEquals(ids(ct), ["api-token-missing:patch-pve high"]);
  assertStringIncludes(findingsOf(ct)[0].message, "VM.PowerMgmt");
});

Deno.test("auditApiToken: any privilege on /, /nodes/<node> or /storage/<id> is a critical extra", () => {
  for (const path of ["/", "/nodes/node1", "/storage/local"]) {
    const t = tokenOf({ paths: [...CLEAN_CT, perm(path, ["Sys.Audit"])] });
    assertEquals(ids(t), [`api-token-extra:${path} critical`], path);
  }
  const root = findingsOf(
    tokenOf({ paths: [...CLEAN_CT, perm("/", ["Sys.Audit"])] }),
  );
  assertStringIncludes(root[0].message, "Sys.Audit");
  assertStringIncludes(
    root[0].message,
    "no machine has a proxmox-cluster health check",
  );
  const node = findingsOf(
    tokenOf({ paths: [...CLEAN_CT, perm("/nodes/node1", ["Sys.Audit"])] }),
  );
  assertStringIncludes(node[0].message, "not a pool or a guest");
});

Deno.test("auditApiToken: an extra privilege on the guest is critical, and its message names only the extra", () => {
  const t = tokenOf({
    paths: [
      perm("/pool/patch", SNAPSHOT),
      perm("/vms/101", [...SNAPSHOT, "VM.Config.Disk"]),
    ],
  });
  const found = findingsOf(t);
  assertEquals(
    found.map((f) => `${f.id} ${f.severity}`),
    ["api-token-extra:/vms/101 critical"],
  );
  assertStringIncludes(found[0].message, "VM.Config.Disk");
  assertEquals(found[0].message.includes("VM.Audit"), false);
});

Deno.test("auditApiToken: with no /vms/<id> path, api-token-missing names every privilege the CT needs", () => {
  const t = tokenOf({ paths: [perm("/pool/patch", SNAPSHOT)] });
  const found = findingsOf(t);
  assertEquals(
    found.map((f) => `${f.id} ${f.severity}`),
    ["api-token-missing:patch-pve high"],
  );
  assertStringIncludes(
    found[0].message,
    "lacks VM.Audit, VM.Snapshot, VM.Snapshot.Rollback, VM.PowerMgmt on /vms/101",
  );
});

Deno.test("auditApiToken: a path with an empty privilege list adds nothing", () => {
  assertEquals(
    findingsOf(tokenOf({ paths: [...CLEAN_CT, perm("/", [])] })),
    [],
  );
});

Deno.test("auditApiToken: an error or an unreadable paths value is api-token-unread, high", () => {
  const withError = findingsOf(
    tokenOf({ paths: null, error: "connection refused" }),
  );
  assertEquals(
    withError.map((f) => `${f.id} ${f.severity}`),
    ["api-token-unread:patch-pve high"],
  );
  assertStringIncludes(withError[0].message, "connection refused");
  for (const paths of [null, "not a list", { path: "/" }, [{ path: "/" }]]) {
    assertEquals(
      ids(tokenOf({ paths })),
      ["api-token-unread:patch-pve high"],
      JSON.stringify(paths),
    );
  }
});

Deno.test("auditApiToken: /pool/../x and /vms/abc are not pool or guest paths, so each is a critical extra", () => {
  const t = tokenOf({
    paths: [
      ...CLEAN_CT,
      perm("/pool/../x", ["VM.Audit"]),
      perm("/vms/abc", ["VM.Audit"]),
    ],
  });
  assertEquals(ids(t), [
    "api-token-extra:/pool/../x critical",
    "api-token-extra:/vms/abc critical",
  ]);
});

Deno.test("requiredPrivileges: a VM needs list, snapshot and rollback; a CT also needs VM.PowerMgmt to start again", () => {
  assertEquals(requiredPrivileges("vm"), [
    "VM.Audit",
    "VM.Snapshot",
    "VM.Snapshot.Rollback",
  ]);
  assertEquals(requiredPrivileges("ct"), [
    "VM.Audit",
    "VM.Snapshot",
    "VM.Snapshot.Rollback",
    "VM.PowerMgmt",
  ]);
});

/** One `permissions` path entry, no privilege propagated (an ACL with propagate 0). */
function permOnly(path: string, names: string[]) {
  return {
    path,
    privileges: names.map((name) => ({ name, propagate: false })),
  };
}

const ROOT_AUDIT = permOnly("/", ["Sys.Audit"]);

Deno.test("auditApiToken: Sys.Audit on / without propagation is fine when this or another machine's cluster check uses the token", () => {
  for (const clusterAudit of ["required", "allowed"] as const) {
    assertEquals(
      findingsOf(tokenOf({ clusterAudit, paths: [...CLEAN_CT, ROOT_AUDIT] })),
      [],
      clusterAudit,
    );
  }
  // A node machine: no guest, only the cluster check.
  assertEquals(
    findingsOf(
      tokenOf({ guest: null, clusterAudit: "required", paths: [ROOT_AUDIT] }),
    ),
    [],
  );
});

Deno.test("auditApiToken: on /, a propagated Sys.Audit or any other privilege is a critical extra even when allowed", () => {
  for (const clusterAudit of ["required", "allowed"] as const) {
    const propagated = findingsOf(
      tokenOf({ clusterAudit, paths: [...CLEAN_CT, perm("/", ["Sys.Audit"])] }),
    );
    assertEquals(
      propagated.map((f) => `${f.id} ${f.severity}`),
      ["api-token-extra:/ critical"],
    );
    assertStringIncludes(propagated[0].message, "Sys.Audit (propagated)");
    const more = findingsOf(
      tokenOf({
        clusterAudit,
        paths: [...CLEAN_CT, permOnly("/", ["Sys.Audit", "Sys.Modify"])],
      }),
    );
    assertEquals(
      more.map((f) => `${f.id} ${f.severity}`),
      ["api-token-extra:/ critical"],
    );
    assertStringIncludes(more[0].message, "Sys.Modify");
    assertEquals(more[0].message.includes("Sys.Audit,"), false);
  }
});

Deno.test("auditApiToken: allowing / does not allow /nodes or /storage", () => {
  for (const path of ["/nodes/node1", "/storage/local", "/access"]) {
    assertEquals(
      ids(
        tokenOf({
          clusterAudit: "required",
          paths: [...CLEAN_CT, ROOT_AUDIT, permOnly(path, ["Sys.Audit"])],
        }),
      ),
      [`api-token-extra:${path} critical`],
      path,
    );
  }
});

Deno.test("auditApiToken: a required cluster check without Sys.Audit on / is api-token-missing, high", () => {
  const node = findingsOf(
    tokenOf({ guest: null, clusterAudit: "required", paths: [] }),
  );
  assertEquals(
    node.map((f) => `${f.id} ${f.severity}`),
    ["api-token-missing:patch-pve high"],
  );
  assertStringIncludes(node[0].message, "lacks Sys.Audit on /");
  // With a guest gap too, both gaps share the one finding.
  const both = findingsOf(
    tokenOf({
      clusterAudit: "required",
      paths: [perm("/pool/patch", SNAPSHOT)],
    }),
  );
  assertEquals(both.length, 1);
  assertStringIncludes(both[0].message, "on /vms/101");
  assertStringIncludes(both[0].message, "lacks Sys.Audit on /");
  // Allowed (another machine's check) does not require it.
  assertEquals(findingsOf(tokenOf({ clusterAudit: "allowed" })), []);
});
