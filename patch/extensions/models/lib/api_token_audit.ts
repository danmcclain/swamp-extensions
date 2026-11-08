// The Proxmox API token behind a machine's snapshots and cluster health check, audited from
// what it can do now.
//
// A VM (`vm.proxmoxNode`) or a CT with `ct.nodeModel` is snapshotted through a
// @dmc/proxmox/node model, and a `proxmox-cluster` health check reads /cluster/status
// through one. auditAccess asks each such model's read-only `permissions` method for the
// effective privileges of its own token (`/access/permissions`, which every token may read
// for itself) and compares them with what the machine needs:
//   • api-token-extra:<path> (critical) — a privilege beyond the four snapshot privileges
//     on a pool or a guest (/pool/<name>, /vms/<id>); any privilege on another path; or, on
//     `/`, anything but Sys.Audit without propagation, and Sys.Audit itself when no machine
//     in the fleet has a proxmox-cluster check through this model.
//   • api-token-missing:<model> (high) — a privilege the guest's snapshots need, or the
//     Sys.Audit on `/` that the machine's proxmox-cluster check needs, is absent.
//   • api-token-unread:<model> (high) — the answer is missing or not readable, so the
//     token's reach is unknown.
// Privilege separation (privsep) is not read: a token may not read its own token entry
// (that needs User.Modify), and the effective privileges are what the token can use.
// ensureSnapshotAccess creates the token with privsep=1 and checks it.

import { z } from "npm:zod@4";

/** The four privileges a snapshot token may hold (role SwampPatch). */
export const SNAPSHOT_PRIVILEGES = [
  "VM.Audit",
  "VM.PowerMgmt",
  "VM.Snapshot",
  "VM.Snapshot.Rollback",
] as const;

/** The one privilege a token may hold on `/` (role SwampPatchAudit), without propagation:
 *  enough to read /cluster/status. */
export const CLUSTER_AUDIT_PRIVILEGE = "Sys.Audit";

/** What a guest's snapshots need: list (VM.Audit, also to find its node), snapshot, roll
 *  back and delete (VM.Snapshot, VM.Snapshot.Rollback), and for a CT start it again after
 *  the rollback (VM.PowerMgmt). */
export function requiredPrivileges(type: "vm" | "ct"): string[] {
  const base = ["VM.Audit", "VM.Snapshot", "VM.Snapshot.Rollback"];
  return type === "ct" ? [...base, "VM.PowerMgmt"] : base;
}

/** The `paths` of a @dmc/proxmox/node `permissions` record. */
export const PermissionsPaths = z.array(
  z.object({
    path: z.string(),
    privileges: z.array(
      z.object({ name: z.string(), propagate: z.boolean() }),
    ),
  }),
);
export type PermissionsPathsT = z.infer<typeof PermissionsPaths>;

/** How Sys.Audit on `/` is judged for one machine's token:
 *  • required — this machine's proxmox-cluster check reads /cluster/status through it;
 *  • allowed — another machine's check does, so it is not extra;
 *  • extra — no machine in the fleet does, so any privilege on `/` is extra. */
export type ClusterAuditUse = "required" | "allowed" | "extra";

export interface ApiTokenInput {
  /** The node model whose token is audited. */
  model: string;
  /** The guest this machine's snapshots act on through the model; null when the machine
   *  uses the model only for its proxmox-cluster check. */
  guest: { type: "vm" | "ct"; vmid: number } | null;
  /** How Sys.Audit on `/` is judged; "extra" when absent. */
  clusterAudit?: ClusterAuditUse;
  /** The `paths` of the model's `permissions` record; null when it could not be read. */
  paths: unknown;
  /** Why the permissions could not be read, or null. */
  error: string | null;
}

type Add = (
  id: string,
  severity: "critical" | "high" | "warning" | "info",
  message: string,
) => void;

const GUEST_OR_POOL = /^\/(pool\/[A-Za-z0-9][A-Za-z0-9_.-]*|vms\/[0-9]+)$/;
const ALLOWED = new Set<string>(SNAPSHOT_PRIVILEGES);

/** Adds the findings for one machine's use of one node model's token. */
export function auditApiToken(t: ApiTokenInput, add: Add): void {
  const use = t.clusterAudit ?? "extra";
  const parsed = t.error === null ? PermissionsPaths.safeParse(t.paths) : null;
  if (!parsed?.success) {
    add(
      `api-token-unread:${t.model}`,
      "high",
      `the privileges of node model ${t.model}'s token could not be read${
        t.error
          ? `: ${t.error.slice(0, 200)}`
          : " (no readable permissions record)"
      }`,
    );
    return;
  }
  for (const p of parsed.data) {
    if (p.privileges.length === 0) continue;
    const names = p.privileges.map((x) => x.name);
    if (p.path === "/" && use !== "extra") {
      // Only Sys.Audit, and only on / itself: a propagated grant reaches every path.
      const extra = p.privileges
        .filter((x) => x.name !== CLUSTER_AUDIT_PRIVILEGE || x.propagate)
        .map((x) =>
          x.name === CLUSTER_AUDIT_PRIVILEGE ? `${x.name} (propagated)` : x.name
        );
      if (extra.length > 0) {
        add(
          `api-token-extra:${p.path}`,
          "critical",
          `node model ${t.model}'s token holds ${
            extra.join(", ")
          } on /, beyond ${CLUSTER_AUDIT_PRIVILEGE} without propagation`,
        );
      }
      continue;
    }
    if (!GUEST_OR_POOL.test(p.path)) {
      add(
        `api-token-extra:${p.path}`,
        "critical",
        `node model ${t.model}'s token holds ${
          names.join(", ")
        } on ${p.path}, ${
          p.path === "/"
            ? "and no machine has a proxmox-cluster health check through it"
            : "which is not a pool or a guest"
        }`,
      );
      continue;
    }
    const extra = names.filter((n) => !ALLOWED.has(n));
    if (extra.length > 0) {
      add(
        `api-token-extra:${p.path}`,
        "critical",
        `node model ${t.model}'s token holds ${
          extra.join(", ")
        } on ${p.path}, beyond the snapshot privileges`,
      );
    }
  }
  const held = (path: string) =>
    new Set(
      parsed.data.find((p) => p.path === path)?.privileges.map((x) => x.name) ??
        [],
    );
  const gaps: string[] = [];
  if (t.guest) {
    const guestPath = `/vms/${t.guest.vmid}`;
    const have = held(guestPath);
    const missing = requiredPrivileges(t.guest.type).filter((n) =>
      !have.has(n)
    );
    if (missing.length > 0) {
      gaps.push(
        `lacks ${missing.join(", ")} on ${guestPath}, so the snapshots of ${
          t.guest.type === "ct" ? "CT" : "VM"
        } ${t.guest.vmid} fail`,
      );
    }
  }
  if (use === "required" && !held("/").has(CLUSTER_AUDIT_PRIVILEGE)) {
    gaps.push(
      `lacks ${CLUSTER_AUDIT_PRIVILEGE} on /, so the proxmox-cluster health check fails`,
    );
  }
  if (gaps.length > 0) {
    add(
      `api-token-missing:${t.model}`,
      "high",
      `node model ${t.model}'s token ${gaps.join("; ")}`,
    );
  }
}
