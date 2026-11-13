/**
 * `@dmc/proxmox/node` — node-level Proxmox operations with API-token auth:
 * node status, cluster health (clusterHealth), guest discovery for `@dmc/patch`, VM and CT snapshot guarding
 * (snapshot / rollback / list / delete, on the node each guest runs on now),
 * effective-privilege checks
 * (permissions), the least-privilege snapshot token (ensureSnapshotAccess), and
 * the least-privilege CI runner-pool token (ensureRunnerPoolAccess).
 *
 * Replaces `@keeb/proxmox/node` plus the ai-infra `proxmox_node_guests.ts`
 * extension. The method names and argument/output shapes of the guest methods
 * match that extension, so `@dmc/patch` can point its `proxmoxNodes` /
 * `proxmoxNode` at a definition of this type unchanged.
 *
 * @module
 */
import { z } from "npm:zod@4";
import {
  authHeaders,
  createMethodLogger,
  dropRemovedAuthArgs,
  fetchWithCurl,
  hasUnresolvedAuth,
  nodePath,
  ProxmoxConnectionArgs,
  pveCall,
  resolveAuth,
  tlsOptions,
  validateConnection,
  waitForTask,
} from "./lib/proxmox.ts";

type NodeGlobalArgs = z.infer<typeof ProxmoxConnectionArgs>;

/** The part of swamp's method context these methods use. */
interface Ctx {
  globalArgs: NodeGlobalArgs;
  logger?: unknown;
  writeResource: (
    spec: string,
    name: string,
    data: unknown,
  ) => Promise<{ name: string }>;
}

/** Snapshot tasks are short; give up after this long. */
const SNAPSHOT_TASK_TIMEOUT_SECONDS = 600;

/** Proxmox snapshot names: a letter, then letters, digits, `_` or `-`. */
const SNAPSHOT_NAME_RE = /^[A-Za-z][A-Za-z0-9_-]{0,39}$/;

/** Proxmox privilege names, e.g. `VM.Audit` or `Sys.Audit`. */
const PRIVILEGE_NAME_RE = /^[A-Za-z][A-Za-z0-9.]*$/;

/** An ACL path such as `/`, `/access`, `/pool/patch` or `/vms/101`. */
const ACL_PATH_RE = /^\/[A-Za-z0-9._\/-]*$/;

/** `user@realm` or a token id `user@realm!tokenname`. */
const USERID_RE =
  /^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+(![A-Za-z][A-Za-z0-9._-]*)?$/;

/** Privileges of the snapshot role: a fixed set, sorted, not an argument. */
const SNAPSHOT_ROLE_PRIVILEGES = [
  "VM.Audit",
  "VM.PowerMgmt",
  "VM.Snapshot",
  "VM.Snapshot.Rollback",
];

/** Privileges of the cluster-audit role (`clusterAudit`): exactly Sys.Audit. */
const AUDIT_ROLE_PRIVILEGES = ["Sys.Audit"];

/** Where the cluster-audit role is granted, with propagate 0: `/` itself, so the token may
 *  read /cluster/status and nothing below `/` (no node, guest, pool or storage path). */
const AUDIT_ACL_PATH = "/";

/** Comment stamped on each object `ensureSnapshotAccess` creates. */
const SNAPSHOT_ACCESS_COMMENT = "managed by @dmc/proxmox ensureSnapshotAccess";

/** `name@pve`: the pve realm only, so `root@pam` and every other @pam user is refused. */
const PVE_USER_RE = /^[a-z][a-z0-9._-]{0,63}@pve$/;

/** API token name (the part after `!`). */
const TOKEN_NAME_RE = /^[A-Za-z][A-Za-z0-9._-]{1,63}$/;

/** Role name: letters, digits, `_` or `-`. */
const ROLE_NAME_RE = /^[A-Za-z][A-Za-z0-9_-]{0,39}$/;

/** Pool name: no `/`, so no nested pools. */
const POOL_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$/;

/** Built-in role names that `ensureSnapshotAccess` never uses as its role. */
const RESERVED_ROLE_NAMES = ["administrator", "noaccess"];

/** Actions `ensureSnapshotAccess` plans, in the order it runs them. */
const ACCESS_ACTIONS = [
  "createRole",
  "createAuditRole",
  "createUser",
  "createPool",
  "addMembers",
  "aclUser",
  "aclUserAudit",
  "createToken",
  "aclToken",
  "aclTokenAudit",
] as const;

/** Privileges of the runner-pool role on `/pool/{pool}`: make (clone into the pool), clone,
 *  read, power and delete the pool's guests. No VM.Config.*, no snapshot, no console. */
const RUNNER_POOL_PRIVILEGES = [
  "VM.Allocate",
  "VM.Audit",
  "VM.Clone",
  "VM.PowerMgmt",
];

/** Privileges of the runner template role on each `/vms/{template}`: read and clone it, but
 *  not delete, change or power it. The templates stay out of the pool for this reason. */
const RUNNER_TEMPLATE_PRIVILEGES = ["VM.Audit", "VM.Clone"];

/** Privileges of the runner storage role on `/storage/{storage}`: room for clone disks. */
const RUNNER_STORAGE_PRIVILEGES = ["Datastore.AllocateSpace"];

/** Privileges of the runner network role on the bridge's `/sdn/zones/...` path. */
const RUNNER_NET_PRIVILEGES = ["SDN.Use"];

/** Comment stamped on each object `ensureRunnerPoolAccess` creates. */
const RUNNER_POOL_ACCESS_COMMENT =
  "managed by @dmc/proxmox ensureRunnerPoolAccess";

/** Proxmox storage id. */
const STORAGE_ID_RE = /^[A-Za-z][A-Za-z0-9._-]{0,98}[A-Za-z0-9]$/;

/** Linux bridge or SDN VNet name (an interface name, max 15 chars). */
const BRIDGE_NAME_RE = /^[A-Za-z][A-Za-z0-9_.-]{0,14}$/;

/** SDN zone id; `localnetwork` holds the plain Linux bridges. */
const SDN_ZONE_RE = /^[A-Za-z][A-Za-z0-9]{0,31}$/;

/** Actions `ensureRunnerPoolAccess` records. Each grant adds a createRole, aclUser and aclToken. */
const RUNNER_ACCESS_ACTIONS = [
  "createRole",
  "createUser",
  "createPool",
  "addMembers",
  "aclUser",
  "createToken",
  "aclToken",
] as const;

const NodeStatusSchema = z.object({
  memoryTotal: z.number().describe("Total memory in bytes"),
  memoryUsed: z.number().describe("Used memory in bytes"),
  memoryFree: z.number().describe("Free memory in bytes"),
  cpuUsage: z.number().describe("CPU usage (0-1)"),
  cpuCount: z.number().describe("Number of logical CPUs"),
  uptime: z.number().describe("Node uptime in seconds"),
  timestamp: z.string(),
});

const GuestSchema = z.object({
  type: z.enum(["qemu", "lxc"]),
  vmid: z.number(),
  name: z.string(),
  status: z.string(),
  node: z.string(),
  ip: z.string().nullable(),
});

const GuestsSchema = z.object({
  total: z.number(),
  guests: z.array(GuestSchema),
  checkedAt: z.string(),
});

const SnapshotSchema = z.object({
  host: z.string(),
  vmid: z.number(),
  type: z.enum(["qemu", "lxc"]).optional().describe("The guest's kind"),
  node: z.string().optional().describe(
    "The node the guest ran on, from /cluster/resources",
  ),
  action: z.enum(["snapshot", "rollback", "list", "delete"]),
  snapshot: z.string().nullable(),
  exitStatus: z.string().nullable(),
  snapshots: z.array(
    z.object({ name: z.string(), description: z.string().nullable() }),
  ),
  timestamp: z.string(),
});

const PermissionsSchema = z.object({
  subject: z.string().describe("Token or user the privileges belong to"),
  path: z.string().nullable().describe("ACL path checked; null for all paths"),
  paths: z.array(z.object({
    path: z.string(),
    privileges: z.array(
      z.object({ name: z.string(), propagate: z.boolean() }),
    ),
  })),
  checkedAt: z.string(),
});

const VmidArg = z.number().int().positive().describe("VM id");
const SnapshotNameArg = z.string().regex(
  SNAPSHOT_NAME_RE,
  "snapshot name must start with a letter and use only letters, digits, _ or - (max 40)",
);
const PermissionPathArg = z.string()
  .regex(
    ACL_PATH_RE,
    "path must be an ACL path such as / or /vms/101 (letters, digits, . _ - and /)",
  )
  .refine(
    (p) => !p.includes("..") && !p.includes("//"),
    "path must not contain .. or //",
  )
  .describe("ACL path to check, e.g. / or /vms/101");
const UseridArg = z.string().regex(
  USERID_RE,
  "userid must be user@realm or user@realm!tokenname",
).describe("User or token to read (default: the caller)");

/** A custom role name: never a built-in (PVE*, Administrator, NoAccess). */
function roleArg(defaultName: string, description: string) {
  return z.string()
    .regex(
      ROLE_NAME_RE,
      "role must start with a letter and use only letters, digits, _ or - (max 40)",
    )
    .refine(
      (r) => !/^pve/i.test(r) && !RESERVED_ROLE_NAMES.includes(r.toLowerCase()),
      "role must not start with PVE and must not be Administrator or NoAccess",
    )
    .default(defaultName)
    .describe(description);
}

const EnsureSnapshotAccessArgs = z.object({
  dryRun: z.boolean().default(true).describe(
    "Plan and check only; write nothing (default true)",
  ),
  user: z.string()
    .regex(PVE_USER_RE, "user must be name@pve (only the pve realm)")
    .default("swamp-patch@pve")
    .describe("Proxmox user that owns the snapshot token"),
  tokenName: z.string()
    .regex(
      TOKEN_NAME_RE,
      "tokenName must start with a letter and use only letters, digits, . _ or - (2 to 64 chars)",
    )
    .default("patch")
    .describe("API token name under that user"),
  role: roleArg(
    "SwampPatch",
    "Custom role that holds the snapshot privileges",
  ),
  clusterAudit: z.boolean().default(false).describe(
    "Also let the token read cluster health (/cluster/status: quorum and node membership, for the clusterHealth method): role auditRole, exactly Sys.Audit, on / with propagate 0, for the user and the token. Sys.Audit on / also reads cluster-level status and configuration (HA status, cluster options, firewall rules, backup and replication jobs). It gives no right on a node, guest, pool or storage path, and no write. Default false: the token holds the snapshot role only",
  ),
  auditRole: roleArg(
    "SwampPatchAudit",
    "Custom role that holds Sys.Audit for clusterAudit; never the snapshot role",
  ),
  pool: z.string()
    .regex(
      POOL_NAME_RE,
      "pool must be one name (letters, digits, _ or -, max 40; no /)",
    )
    .default("patch")
    .describe("Pool whose guests the token may snapshot, roll back and power"),
  members: z.array(VmidArg)
    .refine(
      (ids) => new Set(ids).size === ids.length,
      "members must not repeat a vmid",
    )
    .default([])
    .describe("Guests to put in the pool; never moved from another pool"),
}).refine(
  (a) => a.auditRole !== a.role,
  { message: "auditRole must not be the snapshot role", path: ["auditRole"] },
);

type EnsureArgs = z.infer<typeof EnsureSnapshotAccessArgs>;

const EnsureRunnerPoolAccessArgs = z.object({
  dryRun: z.boolean().default(true).describe(
    "Plan and check only; write nothing (default true)",
  ),
  user: z.string()
    .regex(PVE_USER_RE, "user must be name@pve (only the pve realm)")
    .default("swamp-ci@pve")
    .describe("Proxmox user that owns the runner-pool token"),
  tokenName: z.string()
    .regex(
      TOKEN_NAME_RE,
      "tokenName must start with a letter and use only letters, digits, . _ or - (2 to 64 chars)",
    )
    .default("runner-pool")
    .describe("API token name under that user"),
  pool: z.string()
    .regex(
      POOL_NAME_RE,
      "pool must be one name (letters, digits, _ or -, max 40; no /)",
    )
    .default("ci")
    .describe(
      "Pool whose guests the token may clone, power and delete, and the only pool it may clone into",
    ),
  role: roleArg(
    "SwampCiPool",
    `Custom role on /pool/{pool}: exactly ${RUNNER_POOL_PRIVILEGES.join(", ")}`,
  ),
  storage: z.string()
    .regex(STORAGE_ID_RE, "storage must be a Proxmox storage id")
    .optional()
    .describe(
      "Storage that holds the clone disks: the token gets Datastore.AllocateSpace on /storage/{storage}. Omit to grant no storage right",
    ),
  storageRole: roleArg(
    "SwampCiStorage",
    "Custom role on /storage/{storage}: exactly Datastore.AllocateSpace",
  ),
  bridge: z.string()
    .regex(BRIDGE_NAME_RE, "bridge must be an interface name (max 15 chars)")
    .optional()
    .describe(
      "Bridge (or SDN VNet) the clones use: the token gets SDN.Use on /sdn/zones/{sdnZone}/{bridge}[/{vlan}]. Omit to grant no network right",
    ),
  sdnZone: z.string()
    .regex(SDN_ZONE_RE, "sdnZone must be an SDN zone id")
    .default("localnetwork")
    .describe("SDN zone of the bridge; localnetwork for a plain Linux bridge"),
  vlan: z.number().int().min(1).max(4094).optional().describe(
    "VLAN tag the clones use on a VLAN-aware bridge; the grant is then on that tag only",
  ),
  netRole: roleArg(
    "SwampCiNet",
    "Custom role on the bridge path: exactly SDN.Use",
  ),
  templates: z.array(VmidArg)
    .refine(
      (ids) => new Set(ids).size === ids.length,
      "templates must not repeat a vmid",
    )
    .default([])
    .describe(
      "Templates the token may clone: each gets templateRole on /vms/{vmid}. They must be templates outside the pool, so the token cannot delete or change them",
    ),
  templateRole: roleArg(
    "SwampCiTemplate",
    `Custom role on each /vms/{template}: exactly ${
      RUNNER_TEMPLATE_PRIVILEGES.join(", ")
    }`,
  ),
})
  .refine(
    (a) => a.vlan === undefined || a.bridge !== undefined,
    { message: "vlan needs a bridge", path: ["vlan"] },
  )
  .refine(
    (a) => {
      const roles = [
        a.role,
        ...(a.storage ? [a.storageRole] : []),
        ...(a.bridge ? [a.netRole] : []),
        ...(a.templates.length > 0 ? [a.templateRole] : []),
      ];
      return new Set(roles).size === roles.length;
    },
    {
      message:
        "role, storageRole, netRole and templateRole must be different roles",
      path: ["role"],
    },
  );

type RunnerPoolArgs = z.infer<typeof EnsureRunnerPoolAccessArgs>;

const SnapshotAccessSchema = z.object({
  dryRun: z.boolean().describe("True when the run only planned and checked"),
  status: z.enum(["planned", "unchanged", "applied", "blocked", "failed"]),
  user: z.string(),
  tokenId: z.string(),
  role: z.string(),
  privileges: z.array(z.string()),
  clusterAudit: z.boolean().describe(
    "True when the run also grants the cluster-audit role on /",
  ),
  auditRole: z.string().nullable().describe(
    "The cluster-audit role; null without clusterAudit",
  ),
  auditPrivileges: z.array(z.string()).describe(
    "Privileges of the cluster-audit role; empty without clusterAudit",
  ),
  pool: z.string(),
  aclPath: z.string(),
  members: z.array(z.number()),
  extraMembers: z.array(z.number()).describe(
    "Guests in the pool that were not requested; reported, never removed",
  ),
  callerMissing: z.array(
    z.object({ path: z.string(), privilege: z.string() }),
  ).describe("Privileges the caller lacks (`A|B` means either one)"),
  actions: z.array(z.object({
    action: z.enum(ACCESS_ACTIONS),
    target: z.string(),
    state: z.enum(["present", "planned", "applied", "failed"]),
  })),
  blockers: z.array(z.string()),
  verified: z.array(z.object({
    path: z.string().describe(
      "/pool/{pool}, /vms/{vmid}, or / for the cluster-audit role",
    ),
    privileges: z.array(z.string()),
    ok: z.boolean(),
  })),
  tokenSecretIssued: z.boolean(),
  checkedAt: z.string(),
});

const SnapshotTokenSchema = z.object({
  tokenId: z.string(),
  tokenSecret: z.string().describe("Token secret, shown once by Proxmox")
    .meta({ sensitive: true }),
  createdAt: z.string(),
});

const RunnerPoolAccessSchema = z.object({
  dryRun: z.boolean().describe("True when the run only planned and checked"),
  status: z.enum(["planned", "unchanged", "applied", "blocked", "failed"]),
  user: z.string(),
  tokenId: z.string(),
  pool: z.string(),
  aclPath: z.string(),
  grants: z.array(z.object({
    path: z.string(),
    role: z.string(),
    privileges: z.array(z.string()),
  })).describe(
    "Each grant (propagate 0): the pool first, then the storage, the bridge and each template when given",
  ),
  templates: z.array(z.number()).describe(
    "Templates the token may clone; outside the pool",
  ),
  extraMembers: z.array(z.number()).describe(
    "Guests in the pool (the clones); reported, never removed",
  ),
  callerMissing: z.array(
    z.object({ path: z.string(), privilege: z.string() }),
  ).describe("Privileges the caller lacks (`A|B` means either one)"),
  actions: z.array(z.object({
    action: z.enum(RUNNER_ACCESS_ACTIONS),
    target: z.string(),
    state: z.enum(["present", "planned", "applied", "failed"]),
  })),
  blockers: z.array(z.string()),
  verified: z.array(z.object({
    path: z.string().describe(
      "/pool/{pool}, /storage/{storage}, the bridge path or /vms/{template}",
    ),
    privileges: z.array(z.string()),
    ok: z.boolean(),
  })),
  tokenSecretIssued: z.boolean(),
  checkedAt: z.string(),
});

const RunnerPoolTokenSchema = z.object({
  tokenId: z.string(),
  tokenSecret: z.string().describe("Token secret, shown once by Proxmox")
    .meta({ sensitive: true }),
  createdAt: z.string(),
});

/** The snapshot role on the pool and, with clusterAudit, the audit role on `/`. */
function snapshotAccessSpec(args: EnsureArgs): AccessSpec {
  const grants: AccessGrant[] = [{
    path: `/pool/${args.pool}`,
    role: args.role,
    privileges: SNAPSHOT_ROLE_PRIVILEGES,
    names: { role: "createRole", userAcl: "aclUser", tokenAcl: "aclToken" },
  }];
  if (args.clusterAudit) {
    grants.push({
      path: AUDIT_ACL_PATH,
      role: args.auditRole,
      privileges: AUDIT_ROLE_PRIVILEGES,
      names: {
        role: "createAuditRole",
        userAcl: "aclUserAudit",
        tokenAcl: "aclTokenAudit",
      },
    });
  }
  return {
    method: "ensureSnapshotAccess",
    comment: SNAPSHOT_ACCESS_COMMENT,
    user: args.user,
    tokenName: args.tokenName,
    pool: args.pool,
    members: [...args.members].sort((a, b) => a - b),
    grants,
    templates: [],
  };
}

/** The ACL path of SDN.Use for a bridge, with the VLAN tag when one is given. */
export function bridgeAclPath(
  zone: string,
  bridge: string,
  vlan?: number,
): string {
  return `/sdn/zones/${zone}/${bridge}${vlan === undefined ? "" : `/${vlan}`}`;
}

/** The runner role on the pool, then the storage role and the bridge role when given. */
function runnerPoolAccessSpec(args: RunnerPoolArgs): AccessSpec {
  const names = {
    role: "createRole",
    userAcl: "aclUser",
    tokenAcl: "aclToken",
  };
  const grants: AccessGrant[] = [{
    path: `/pool/${args.pool}`,
    role: args.role,
    privileges: RUNNER_POOL_PRIVILEGES,
    names,
  }];
  if (args.storage) {
    grants.push({
      path: `/storage/${args.storage}`,
      role: args.storageRole,
      privileges: RUNNER_STORAGE_PRIVILEGES,
      names,
    });
  }
  if (args.bridge) {
    grants.push({
      path: bridgeAclPath(args.sdnZone, args.bridge, args.vlan),
      role: args.netRole,
      privileges: RUNNER_NET_PRIVILEGES,
      names,
    });
  }
  const templates = [...args.templates].sort((a, b) => a - b);
  for (const vmid of templates) {
    grants.push({
      path: `/vms/${vmid}`,
      role: args.templateRole,
      privileges: RUNNER_TEMPLATE_PRIVILEGES,
      names,
    });
  }
  return {
    method: "ensureRunnerPoolAccess",
    comment: RUNNER_POOL_ACCESS_COMMENT,
    user: args.user,
    tokenName: args.tokenName,
    pool: args.pool,
    // Nothing is added to the pool: the templates stay out, and clones join it themselves.
    members: [],
    grants,
    templates,
  };
}

type AccessRecord = z.infer<typeof SnapshotAccessSchema>;
type AccessStatus = AccessRecord["status"];
type VerifiedPath = AccessRecord["verified"][number];

/** One action of an ensure-access run; each method's record narrows `action` to its own names. */
interface AccessAction {
  action: string;
  target: string;
  state: "present" | "planned" | "applied" | "failed";
}

/** Map the /nodes/{node}/status payload onto the `status` resource shape. */
export function parseNodeStatus(d: unknown) {
  // deno-lint-ignore no-explicit-any
  const s = d as any;
  if (
    typeof s?.memory?.total !== "number" ||
    typeof s?.memory?.used !== "number" ||
    typeof s?.cpuinfo?.cpus !== "number"
  ) {
    throw new Error(
      "Unexpected /status response from Proxmox: missing memory or cpuinfo",
    );
  }
  return {
    memoryTotal: s.memory.total,
    memoryUsed: s.memory.used,
    memoryFree: s.memory.total - s.memory.used,
    cpuUsage: typeof s.cpu === "number" ? s.cpu : 0,
    cpuCount: s.cpuinfo.cpus,
    uptime: typeof s.uptime === "number" ? s.uptime : 0,
  };
}

/** Normalise the /cluster/resources?type=vm payload into guests (no IPs yet). */
export function parseClusterGuests(
  data: unknown,
): Array<Omit<z.infer<typeof GuestSchema>, "ip">> {
  if (!Array.isArray(data)) {
    throw new Error(
      "Unexpected /cluster/resources response from Proxmox (not an array)",
    );
  }
  return data
    .filter((g) => g && (g.type === "qemu" || g.type === "lxc"))
    .map((g) => ({
      type: g.type as "qemu" | "lxc",
      vmid: Number(g.vmid),
      name: g.name ?? String(g.vmid),
      status: g.status ?? "unknown",
      node: String(g.node),
    }))
    .filter((g) => Number.isInteger(g.vmid))
    .sort((a, b) => a.vmid - b.vmid);
}

/** First non-loopback IPv4 from an LXC /interfaces payload. */
export function pickLxcIpv4(interfaces: unknown): string | null {
  if (!Array.isArray(interfaces)) return null;
  for (const i of interfaces) {
    if (!i || i.name === "lo") continue;
    const ip = String(i.inet ?? "").split("/")[0];
    if (ip && !ip.startsWith("127.")) return ip;
  }
  return null;
}

type PermissionsPaths = z.infer<typeof PermissionsSchema>["paths"];

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * True when a token's privsep field says privilege separation is on. The token list gives the
 * number 1; the token-create answer echoes the form value, so it gives the string "1". Any other
 * value, or none, is off.
 */
function privsepOn(v: unknown): boolean {
  return v === 1 || v === "1";
}

function codeOrder(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Normalise the /access/permissions payload
 * (`{ "<path>": { "<Privilege>": 1 | 0 } }`) into paths and privileges sorted
 * by name. Junk values, odd privilege names and keys that are not ACL paths
 * are skipped; a payload of the wrong shape throws.
 */
export function parsePermissions(data: unknown): PermissionsPaths {
  const unexpected = "Unexpected /access/permissions response from Proxmox";
  if (!isPlainObject(data)) throw new Error(unexpected);
  const paths: PermissionsPaths = [];
  for (const [path, privs] of Object.entries(data)) {
    if (!path.startsWith("/")) continue;
    if (!isPlainObject(privs)) throw new Error(unexpected);
    const privileges = Object.entries(privs)
      .filter(([name, value]) =>
        PRIVILEGE_NAME_RE.test(name) && (value === 0 || value === 1)
      )
      .map(([name, value]) => ({ name, propagate: value === 1 }))
      .sort((a, b) => codeOrder(a.name, b.name));
    paths.push({ path, privileges });
  }
  return paths.sort((a, b) => codeOrder(a.path, b.path));
}

type ProxmoxAuth = Awaited<ReturnType<typeof resolveAuth>>;

/** A `/access/roles` entry. */
interface RoleInfo {
  roleid: string;
  privs: string[];
  special: boolean;
}

/** A `/access/users?full=1` entry; token ids are normalised to `user@realm!name`. */
interface UserInfo {
  userid: string;
  disabled: boolean;
  groups: string[];
  tokens: Array<{ id: string; privsep: unknown }>;
}

/** A `/access/acl` entry. */
interface AclInfo {
  path: string;
  type: string;
  ugid: string;
  roleid: string;
  propagate: unknown;
}

/** What `ensureSnapshotAccess` reads before it plans anything. */
interface AccessState {
  roles: RoleInfo[];
  users: UserInfo[];
  acl: AclInfo[];
  pools: string[];
  /** vmid -> pool name; "" when the guest is in no pool. */
  guestPools: Map<number, string>;
  /** vmids of the guests that are templates. */
  templates: Set<number>;
}

/** A privilege a check needs; `A|B` is met by either one. */
interface PrivilegeNeed {
  path: string;
  privilege: string;
}

/** A Proxmox object payload; throws unless `value` is a plain object. */
function asRecord(value: unknown, what: string): Record<string, unknown> {
  if (!isPlainObject(value)) {
    throw new Error(`Unexpected ${what} response from Proxmox`);
  }
  return value;
}

/** A Proxmox list payload; throws unless `data` is an array. */
function asList(data: unknown, what: string): unknown[] {
  if (!Array.isArray(data)) {
    throw new Error(`Unexpected ${what} response from Proxmox (not an array)`);
  }
  return data;
}

/** A required non-empty string field. The error names the field, never its value. */
function stringField(
  o: Record<string, unknown>,
  key: string,
  what: string,
): string {
  const value = o[key];
  if (typeof value !== "string" || value === "") {
    throw new Error(
      `Unexpected ${what} response from Proxmox (${key} missing)`,
    );
  }
  return value;
}

/** A list given as a comma string or an array (or not at all), as trimmed non-empty strings. */
function listField(value: unknown): string[] {
  const items: unknown[] = typeof value === "string"
    ? value.split(",")
    : Array.isArray(value)
    ? value
    : [];
  return items.map((v) => String(v).trim()).filter((v) => v !== "");
}

/** Parse `/access/roles`. `privs` is a comma string that may be empty. */
function parseRoles(data: unknown): RoleInfo[] {
  const what = "/access/roles";
  return asList(data, what).map((item) => {
    const role = asRecord(item, what);
    return {
      roleid: stringField(role, "roleid", what),
      privs: listField(role.privs),
      special: role.special === 1,
    };
  });
}

/** Parse `/access/users?full=1`. A token id may be bare (`patch`) or full (`user@realm!patch`). */
function parseUsers(data: unknown): UserInfo[] {
  const what = "/access/users";
  return asList(data, what).map((item) => {
    const user = asRecord(item, what);
    const userid = stringField(user, "userid", what);
    const tokens = Array.isArray(user.tokens) ? user.tokens : [];
    return {
      userid,
      disabled: user.enable === 0,
      groups: listField(user.groups),
      tokens: tokens.map((t) => {
        const token = asRecord(t, what);
        const tokenid = stringField(token, "tokenid", what);
        return {
          id: tokenid.includes("!") ? tokenid : `${userid}!${tokenid}`,
          privsep: token.privsep,
        };
      }),
    };
  });
}

/** Parse `/access/acl`. */
function parseAcl(data: unknown): AclInfo[] {
  const what = "/access/acl";
  return asList(data, what).map((item) => {
    const entry = asRecord(item, what);
    return {
      path: stringField(entry, "path", what),
      type: stringField(entry, "type", what),
      ugid: stringField(entry, "ugid", what),
      roleid: stringField(entry, "roleid", what),
      propagate: entry.propagate,
    };
  });
}

/** Parse `/pools` into pool names. */
function parsePoolIds(data: unknown): string[] {
  const what = "/pools";
  return asList(data, what).map((item) =>
    stringField(asRecord(item, what), "poolid", what)
  );
}

/** Parse `/cluster/resources?type=vm` into vmid -> pool name ("" when in no pool). */
function parseGuestPools(data: unknown): Map<number, string> {
  const what = "/cluster/resources";
  const pools = new Map<number, string>();
  for (const item of asList(data, what)) {
    const guest = asRecord(item, what);
    const vmid = Number(guest.vmid);
    if (Number.isInteger(vmid)) {
      pools.set(vmid, typeof guest.pool === "string" ? guest.pool : "");
    }
  }
  return pools;
}

/** Parse `/cluster/resources?type=vm` into the vmids of the templates. */
function parseTemplateIds(data: unknown): Set<number> {
  const what = "/cluster/resources";
  const ids = new Set<number>();
  for (const item of asList(data, what)) {
    const guest = asRecord(item, what);
    const vmid = Number(guest.vmid);
    if (Number.isInteger(vmid) && guest.template === 1) ids.add(vmid);
  }
  return ids;
}

/** Read everything the plan needs. GET only. */
async function readAccessState(
  g: NodeGlobalArgs,
  auth: ProxmoxAuth,
): Promise<AccessState> {
  const read = (path: string, what: string) =>
    pveCall(g, auth, "GET", `${g.apiUrl}/api2/json${path}`, what);
  const roles = parseRoles(await read("/access/roles", "Listing roles"));
  const users = parseUsers(await read("/access/users?full=1", "Listing users"));
  const acl = parseAcl(await read("/access/acl", "Listing ACLs"));
  const pools = parsePoolIds(await read("/pools", "Listing pools"));
  const guests = await read(
    "/cluster/resources?type=vm",
    "Listing cluster guests",
  );
  return {
    roles,
    users,
    acl,
    pools,
    guestPools: parseGuestPools(guests),
    templates: parseTemplateIds(guests),
  };
}

/**
 * Privilege names a subject holds on one ACL path, sorted. Any name the API
 * lists counts, whatever its value; a path it does not list has none.
 */
async function readPrivileges(
  g: NodeGlobalArgs,
  auth: ProxmoxAuth,
  path: string,
  userid?: string,
): Promise<string[]> {
  const params = new URLSearchParams({ path });
  if (userid) params.set("userid", userid);
  const paths = parsePermissions(
    await pveCall(
      g,
      auth,
      "GET",
      `${g.apiUrl}/api2/json/access/permissions?${params.toString()}`,
      `Reading privileges on ${path}`,
    ),
  );
  return paths
    .filter((p) => p.path === path)
    .flatMap((p) => p.privileges.map((x) => x.name))
    .sort(codeOrder);
}

/** One custom role granted on one ACL path, to the user and to the token, with propagate 0. */
interface AccessGrant {
  /** The ACL path, e.g. `/pool/patch`, `/` or `/storage/nfs`. */
  path: string;
  /** The custom role; it must hold exactly `privileges`. */
  role: string;
  privileges: string[];
  /** The action names this grant records for its role, user ACL and token ACL. */
  names: { role: string; userAcl: string; tokenAcl: string };
}

/** What one ensure-access run makes: a user, its token, one pool and the grants. */
interface AccessSpec {
  /** The method name, for messages. */
  method: string;
  /** Comment stamped on each object the run creates. */
  comment: string;
  user: string;
  tokenName: string;
  pool: string;
  /** Requested pool members, sorted. */
  members: number[];
  /** grants[0] is the pool grant on `/pool/{pool}`; its privileges hold on each pool guest. */
  grants: AccessGrant[];
  /** Guests that must exist, be templates and stay out of `pool` (each has its own grant). */
  templates: number[];
}

/** One planned or present action, with what it needs to run. */
interface AccessStep {
  record: AccessAction;
  kind:
    | "role"
    | "user"
    | "pool"
    | "members"
    | "userAcl"
    | "token"
    | "tokenAcl";
  grant?: AccessGrant;
}

/** What `planAccess` decided. */
interface AccessPlan {
  blockers: string[];
  steps: AccessStep[];
  toAdd: number[];
  extraMembers: number[];
}

/** The grant on the pool path. */
function poolGrant(spec: AccessSpec): AccessGrant {
  return spec.grants[0];
}

/** Requested guests that exist and are in no pool yet: the ones `addMembers` adds. */
function guestsToAdd(
  members: number[],
  guestPools: Map<number, string>,
): number[] {
  return members.filter((vmid) => guestPools.get(vmid) === "");
}

/** The privileges the caller must hold before any write. */
function callerNeeds(spec: AccessSpec, state: AccessState): PrivilegeNeed[] {
  const aclPath = poolGrant(spec).path;
  const needs: PrivilegeNeed[] = [
    { path: "/access", privilege: "Sys.Audit" },
    { path: "/access", privilege: "Sys.Modify" },
    { path: "/access/groups", privilege: "User.Modify" },
    { path: aclPath, privilege: "Pool.Allocate" },
    { path: aclPath, privilege: "Pool.Audit" },
    { path: aclPath, privilege: "Permissions.Modify" },
  ];
  for (const grant of spec.grants.slice(1)) {
    needs.push({ path: grant.path, privilege: "Permissions.Modify" });
  }
  if (!state.users.some((u) => u.userid === spec.user)) {
    needs.push({ path: "/access/realm/pve", privilege: "Realm.AllocateUser" });
  }
  for (const vmid of guestsToAdd(spec.members, state.guestPools)) {
    needs.push({
      path: `/vms/${vmid}`,
      privilege: "Permissions.Modify|VM.Allocate",
    });
  }
  return needs;
}

/** The needs the caller does not meet. Each path is read once. */
async function missingCallerPrivileges(
  g: NodeGlobalArgs,
  auth: ProxmoxAuth,
  needs: PrivilegeNeed[],
): Promise<PrivilegeNeed[]> {
  const granted = new Map<string, string[]>();
  const missing: PrivilegeNeed[] = [];
  for (const need of needs) {
    let names = granted.get(need.path);
    if (!names) {
      names = await readPrivileges(g, auth, need.path);
      granted.set(need.path, names);
    }
    if (!need.privilege.split("|").some((p) => names.includes(p))) {
      missing.push(need);
    }
  }
  return missing;
}

/**
 * Compare the state with the wanted one. Pure: makes no calls. Returns every
 * blocker, the ordered steps (`present` or `planned`), the guests to add and
 * the guests in the pool that were not requested.
 */
function planAccess(
  spec: AccessSpec,
  state: AccessState,
  callerMissing: PrivilegeNeed[],
): AccessPlan {
  const { user, pool, members, grants } = spec;
  const tokenId = `${user}!${spec.tokenName}`;
  const blockers: string[] = [];

  for (const m of callerMissing) {
    blockers.push(
      `caller lacks ${m.privilege.split("|").join(" or ")} on ${m.path}`,
    );
  }

  // An existing role must hold exactly its set: never more, never less.
  // One role may back several grants (one per template); check and create it once.
  const roleGrants = grants.filter((grant, i) =>
    grants.findIndex((x) => x.role === grant.role) === i
  );
  const roleInfos = roleGrants.map((grant) => {
    const info = state.roles.find((r) => r.roleid === grant.role);
    if (!info) return undefined;
    const name = grant.role;
    if (info.special) blockers.push(`role ${name} is a built-in role`);
    const extra = info.privs.filter((p) => !grant.privileges.includes(p))
      .sort(codeOrder);
    const missing = grant.privileges.filter((p) => !info.privs.includes(p));
    if (extra.length > 0) {
      blockers.push(`role ${name} has extra privileges: ${extra.join(", ")}`);
    }
    if (missing.length > 0) {
      blockers.push(
        `role ${name} is missing privileges: ${missing.join(", ")}`,
      );
    }
    return info;
  });

  const userInfo = state.users.find((u) => u.userid === user);
  if (userInfo?.disabled) blockers.push(`user ${user} is disabled`);
  if (userInfo && userInfo.groups.length > 0) {
    blockers.push(
      `user ${user} is in group(s) ${
        userInfo.groups.join(", ")
      }; group ACLs would add rights`,
    );
  }
  const tokenInfo = userInfo?.tokens.find((t) => t.id === tokenId);
  if (tokenInfo && !privsepOn(tokenInfo.privsep)) {
    blockers.push(
      `token ${tokenId} does not use privilege separation (privsep must be 1)`,
    );
  }

  // The user and the token may hold only the spec's grants, each with propagate 0. Any other
  // grant to them, and any grant of our roles to someone else, blocks the run.
  const allowedText = grants
    .map((x) => `role ${x.role} on ${x.path}`)
    .join(" and ");
  const ourRoles = grants.map((x) => x.role);
  for (const a of state.acl) {
    const isOurs = (a.type === "user" && a.ugid === user) ||
      (a.type === "token" && a.ugid === tokenId);
    if (isOurs) {
      const allowed = a.propagate === 0 &&
        grants.some((x) => x.path === a.path && x.role === a.roleid);
      if (!allowed) {
        blockers.push(
          `${a.type} ${a.ugid} has role ${a.roleid} on ${a.path} with propagate ${a.propagate}; the only allowed ${
            grants.length > 1 ? "grants are" : "grant is"
          } ${allowedText}, with propagate 0`,
        );
      }
    } else if (ourRoles.includes(a.roleid)) {
      blockers.push(
        `role ${a.roleid} is granted to ${a.type} ${a.ugid} on ${a.path}`,
      );
    }
  }

  const toAdd = guestsToAdd(members, state.guestPools);
  for (const vmid of members) {
    const current = state.guestPools.get(vmid);
    if (current === undefined) {
      blockers.push(`guest ${vmid} does not exist on the cluster`);
    } else if (current !== "" && current !== pool) {
      blockers.push(
        `guest ${vmid} is in pool ${current}; guests are never moved between pools`,
      );
    }
  }

  for (const vmid of spec.templates) {
    const current = state.guestPools.get(vmid);
    if (current === undefined) {
      blockers.push(`template ${vmid} does not exist on the cluster`);
    } else if (!state.templates.has(vmid)) {
      blockers.push(`guest ${vmid} is not a template`);
    } else if (current === pool) {
      blockers.push(
        `template ${vmid} is in pool ${pool}, where the token could delete it; move it out of the pool`,
      );
    }
  }

  const granted = (type: string, ugid: string, grant: AccessGrant) =>
    state.acl.some((a) =>
      a.type === type && a.ugid === ugid && a.path === grant.path &&
      a.roleid === grant.role && a.propagate === 0
    );
  const step = (
    kind: AccessStep["kind"],
    action: string,
    target: string,
    present: boolean,
    grant?: AccessGrant,
  ): AccessStep => ({
    record: { action, target, state: present ? "present" : "planned" },
    kind,
    grant,
  });

  const steps: AccessStep[] = [
    ...roleGrants.map((grant, i) =>
      step("role", grant.names.role, grant.role, !!roleInfos[i], grant)
    ),
    step("user", "createUser", user, !!userInfo),
    step("pool", "createPool", pool, state.pools.includes(pool)),
    step("members", "addMembers", toAdd.join(","), toAdd.length === 0),
    ...grants.map((grant) =>
      step(
        "userAcl",
        grant.names.userAcl,
        grant.path,
        granted("user", user, grant),
        grant,
      )
    ),
    step("token", "createToken", tokenId, !!tokenInfo),
    ...grants.map((grant) =>
      step(
        "tokenAcl",
        grant.names.tokenAcl,
        grant.path,
        granted("token", tokenId, grant),
        grant,
      )
    ),
  ];

  const extraMembers = [...state.guestPools.entries()]
    .filter(([vmid, p]) => p === pool && !members.includes(vmid))
    .map(([vmid]) => vmid)
    .sort((a, b) => a - b);

  return { blockers, steps, toAdd, extraMembers };
}

/** True when `privs` is exactly `wanted`. */
function isExactSet(privs: string[], wanted: string[]): boolean {
  return privs.length === wanted.length &&
    wanted.every((p) => privs.includes(p));
}

/** A path to verify and the exact privilege set the token must hold there. */
interface VerifyTarget {
  path: string;
  wanted: string[];
}

/** The pool path (always, so a run with no members still proves the grant) and each guest
 *  in `vmids`, each with exactly the pool grant's set; then each other grant in `others`
 *  with exactly its own set. A propagated grant above shows up as extra privileges. */
function verifyTargets(
  spec: AccessSpec,
  vmids: number[],
  others: AccessGrant[],
): VerifyTarget[] {
  const pool = poolGrant(spec);
  return [
    ...[pool.path, ...vmids.map((vmid) => `/vms/${vmid}`)].map((path) => ({
      path,
      wanted: pool.privileges,
    })),
    ...others.map((grant) => ({ path: grant.path, wanted: grant.privileges })),
  ];
}

/** The token's effective privileges on each target, and whether each set is exact. */
async function verifyAccess(
  g: NodeGlobalArgs,
  auth: ProxmoxAuth,
  tokenId: string,
  targets: VerifyTarget[],
): Promise<Array<VerifiedPath & { wanted: string[] }>> {
  const verified: Array<VerifiedPath & { wanted: string[] }> = [];
  for (const { path, wanted } of targets) {
    const privileges = await readPrivileges(g, auth, path, tokenId);
    verified.push({
      path,
      privileges,
      ok: isExactSet(privileges, wanted),
      wanted,
    });
  }
  return verified;
}

/** The blocker or error text for a verified path that is not exact. */
function notExactText(
  tokenId: string,
  v: VerifiedPath & { wanted: string[] },
): string {
  return `${tokenId} does not have exactly ${
    v.wanted.join(", ")
  } on ${v.path} (has ${v.privileges.join(", ") || "none"})`;
}

/** The fields every ensure-access record has. */
interface AccessRecordBase {
  dryRun: boolean;
  status: AccessStatus;
  user: string;
  tokenId: string;
  pool: string;
  aclPath: string;
  members: number[];
  extraMembers: number[];
  callerMissing: PrivilegeNeed[];
  actions: AccessAction[];
  blockers: string[];
  verified: VerifiedPath[];
  tokenSecretIssued: boolean;
  checkedAt: string;
}

/** Where one ensure-access method writes its record and its token secret. */
interface AccessOutput {
  recordSpec: string;
  recordName: string;
  tokenSpec: string;
  tokenName: string;
  /** Log label, e.g. "Snapshot access". */
  label: string;
  /** The full record from the common fields. */
  record: (base: AccessRecordBase) => Record<string, unknown>;
}

/**
 * Run one ensure-access method: read, plan, block on any problem, then (live) create what is
 * missing in order and verify the token's exact privileges on every path. Dry runs write nothing
 * to Proxmox. Never changes or removes an existing object.
 */
async function ensureAccess(
  spec: AccessSpec,
  dryRun: boolean,
  out: AccessOutput,
  context: Ctx,
): Promise<{ dataHandles: Array<{ name: string }> }> {
  const g = context.globalArgs;
  const log = createMethodLogger(context);
  const api = `${g.apiUrl}/api2/json`;
  const tokenId = `${spec.user}!${spec.tokenName}`;
  const pool = poolGrant(spec);
  const aclPath = pool.path;
  log.info(
    "Checking {label} for {tokenId} on {aclPath} ({mode})",
    {
      label: out.label.toLowerCase(),
      tokenId,
      aclPath,
      mode: dryRun ? "dry run" : "live",
    },
  );
  const auth = await resolveAuth(g);
  const state = await readAccessState(g, auth);
  const callerMissing = await missingCallerPrivileges(
    g,
    auth,
    callerNeeds(spec, state),
  );
  const plan = planAccess(spec, state, callerMissing);
  const { steps, blockers } = plan;
  const actions = steps.map((s) => s.record);
  const handles: Array<{ name: string }> = [];
  let verified: Array<VerifiedPath & { wanted: string[] }> = [];
  let tokenSecretIssued = false;

  const writeRecord = (status: AccessStatus) =>
    context.writeResource(
      out.recordSpec,
      out.recordName,
      out.record({
        dryRun,
        status,
        user: spec.user,
        tokenId,
        pool: spec.pool,
        aclPath,
        members: spec.members,
        extraMembers: plan.extraMembers,
        callerMissing,
        actions,
        blockers,
        verified: verified.map(({ path, privileges, ok }) => ({
          path,
          privileges,
          ok,
        })),
        tokenSecretIssued,
        checkedAt: new Date().toISOString(),
      }),
    );

  const failIfBlocked = async () => {
    if (blockers.length === 0) return;
    await writeRecord("blocked");
    throw new Error(`${spec.method} blocked: ${blockers.join("; ")}`);
  };
  await failIfBlocked();

  const tokenAclPresent = (grant: AccessGrant) =>
    steps.some((s) =>
      s.kind === "tokenAcl" && s.grant === grant &&
      s.record.state === "present"
    );

  if (dryRun) {
    // A token whose ACLs are already in place is checked now. A planned
    // ACL cannot be checked until the live run has made it.
    const tokenPresent = steps.some((s) =>
      s.kind === "token" && s.record.state === "present"
    );
    if (tokenPresent && tokenAclPresent(pool)) {
      verified = await verifyAccess(
        g,
        auth,
        tokenId,
        verifyTargets(
          spec,
          spec.members.filter((vmid) =>
            state.guestPools.get(vmid) === spec.pool
          ),
          spec.grants.slice(1).filter(tokenAclPresent),
        ),
      );
      for (const v of verified) {
        if (!v.ok) blockers.push(notExactText(tokenId, v));
      }
      await failIfBlocked();
    }
    const status: AccessStatus = actions.some((a) => a.state === "planned")
      ? "planned"
      : "unchanged";
    const handle = await writeRecord(status);
    log.info("{label} {status} for {tokenId}", {
      label: out.label,
      status,
      tokenId,
    });
    return { dataHandles: [handle] };
  }

  // Always propagate 0: a grant never reaches below its path.
  const grant = (
    path: string,
    roleid: string,
    who: { users: string } | { tokens: string },
  ) =>
    pveCall(
      g,
      auth,
      "PUT",
      `${api}/access/acl`,
      `Granting ${roleid} on ${path} to ${
        "users" in who ? who.users : who.tokens
      }`,
      formBody({ path, roles: roleid, ...who, propagate: "0" }),
    );

  const createToken = async () => {
    const lost =
      `the token may now exist without a stored secret: delete ${tokenId} in Proxmox and run again`;
    let data: unknown;
    try {
      data = await pveCall(
        g,
        auth,
        "POST",
        `${api}/access/users/${encodeURIComponent(spec.user)}/token/${
          encodeURIComponent(spec.tokenName)
        }`,
        `Creating token ${tokenId}`,
        formBody({ privsep: "1", comment: spec.comment }),
      );
    } catch (err) {
      // A JSON parse error quotes the body, and a 2xx body holds the
      // secret: never pass its message on.
      if (err instanceof SyntaxError) {
        throw new Error(
          `Proxmox answered the token request with a body that is not JSON; ${lost}`,
        );
      }
      throw err;
    }
    // The secret is returned once: store it before any other check or call.
    const created: Record<string, unknown> = isPlainObject(data) ? data : {};
    const secret = created.value;
    if (typeof secret !== "string" || secret === "") {
      throw new Error(`Proxmox returned no secret; ${lost}`);
    }
    try {
      handles.push(
        await context.writeResource(out.tokenSpec, out.tokenName, {
          tokenId,
          tokenSecret: secret,
          createdAt: new Date().toISOString(),
        }),
      );
    } catch {
      // The vault error could echo what it was given; keep only the cause.
      throw new Error(`Could not store the token secret; ${lost}`);
    }
    tokenSecretIssued = true;
    if (created["full-tokenid"] !== tokenId) {
      throw new Error(`Proxmox created a token that is not ${tokenId}`);
    }
    const info: Record<string, unknown> = isPlainObject(created.info)
      ? created.info
      : {};
    if (!privsepOn(info.privsep)) {
      throw new Error(
        `token ${tokenId} was not created with privilege separation`,
      );
    }
  };

  const apply = async (s: AccessStep) => {
    switch (s.kind) {
      case "role":
        await pveCall(
          g,
          auth,
          "POST",
          `${api}/access/roles`,
          `Creating role ${s.grant!.role}`,
          formBody({
            roleid: s.grant!.role,
            privs: s.grant!.privileges.join(","),
          }),
        );
        return;
      case "user":
        await pveCall(
          g,
          auth,
          "POST",
          `${api}/access/users`,
          `Creating user ${spec.user}`,
          formBody({ userid: spec.user, enable: "1", comment: spec.comment }),
        );
        return;
      case "pool":
        await pveCall(
          g,
          auth,
          "POST",
          `${api}/pools`,
          `Creating pool ${spec.pool}`,
          formBody({ poolid: spec.pool, comment: spec.comment }),
        );
        return;
      case "members":
        await pveCall(
          g,
          auth,
          "PUT",
          `${api}/pools`,
          `Adding guests to pool ${spec.pool}`,
          formBody({ poolid: spec.pool, vms: plan.toAdd.join(",") }),
        );
        return;
      case "userAcl":
        await grant(s.grant!.path, s.grant!.role, { users: spec.user });
        return;
      case "token":
        await createToken();
        return;
      case "tokenAcl":
        await grant(s.grant!.path, s.grant!.role, { tokens: tokenId });
        return;
    }
  };

  let current: AccessAction | undefined;
  try {
    for (const s of steps) {
      if (s.record.state !== "planned") continue;
      current = s.record;
      await apply(s);
      s.record.state = "applied";
      log.info("Applied {action} on {target}", {
        action: s.record.action,
        target: s.record.target,
      });
    }
    verified = await verifyAccess(
      g,
      auth,
      tokenId,
      verifyTargets(spec, spec.members, spec.grants.slice(1)),
    );
    const bad = verified.filter((v) => !v.ok);
    if (bad.length > 0) {
      throw new Error(
        `${spec.method} verification failed: ${
          bad.map((v) => notExactText(tokenId, v)).join("; ")
        }`,
      );
    }
  } catch (err) {
    if (current?.state === "planned") current.state = "failed";
    await writeRecord("failed");
    throw err;
  }

  const status: AccessStatus = actions.some((a) => a.state === "applied")
    ? "applied"
    : "unchanged";
  const handle = await writeRecord(status);
  log.info("{label} {status} for {tokenId}", {
    label: out.label,
    status,
    tokenId,
  });
  return { dataHandles: [handle, ...handles] };
}

/** A form-encoded request body. */
function formBody(fields: Record<string, string>): string {
  return new URLSearchParams(fields).toString();
}

/** First non-loopback IPv4 from a QEMU guest-agent payload. */
function pickQemuIpv4(result: unknown): string | null {
  if (!Array.isArray(result)) return null;
  for (const i of result) {
    for (const a of i?.["ip-addresses"] ?? []) {
      const ip = a?.["ip-address"];
      if (
        a?.["ip-address-type"] === "ipv4" && typeof ip === "string" &&
        !ip.startsWith("127.")
      ) return ip;
    }
  }
  return null;
}

/** A running guest's IPv4 (guest agent for qemu, interfaces for lxc), or null. */
async function guestIp(
  g: NodeGlobalArgs,
  auth: Awaited<ReturnType<typeof resolveAuth>>,
  guest: { type: string; vmid: number; node: string; status: string },
): Promise<string | null> {
  if (guest.status !== "running") return null;
  const path = guest.type === "qemu"
    ? `/qemu/${guest.vmid}/agent/network-get-interfaces`
    : `/lxc/${guest.vmid}/interfaces`;
  try {
    const res = await fetchWithCurl(
      nodePath({ apiUrl: g.apiUrl, node: guest.node }, path),
      {
        method: "GET",
        headers: authHeaders(auth),
        tls: tlsOptions(g),
      },
    );
    if (!res.ok) return null;
    const data = res.json()?.data;
    return guest.type === "qemu"
      ? pickQemuIpv4(data?.result)
      : pickLxcIpv4(data);
  } catch {
    return null; // no agent / not reachable: no IP
  }
}

type GuestType = "qemu" | "lxc";

/** What a guest of each kind is called in messages. */
const GUEST_WORD: Record<GuestType, string> = { qemu: "VM", lxc: "CT" };

/** A node name as /cluster/resources gives it: safe in an API path. */
const NODE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$/;

/**
 * The node a guest runs on, from parsed /cluster/resources entries. Throws when the guest is
 * not listed (it does not exist, or the caller has no VM.Audit on it), is listed more than once,
 * is the other kind (a VM id given to a CT method, or the reverse), or has a node name that is
 * not safe in a path. Never falls back to the configured node.
 */
export function guestNode(
  guests: ReadonlyArray<{ type: string; vmid: number; node: string }>,
  type: GuestType,
  vmid: number,
): string {
  const word = GUEST_WORD[type];
  const found = guests.filter((x) => x.vmid === vmid);
  if (found.length === 0) {
    throw new Error(
      `${word} ${vmid} is not in /cluster/resources: it does not exist, or this token has no VM.Audit on it`,
    );
  }
  if (found.length > 1) {
    throw new Error(
      `guest ${vmid} is listed more than once in /cluster/resources`,
    );
  }
  const x = found[0];
  if (x.type !== type) {
    throw new Error(
      `guest ${vmid} is a ${
        GUEST_WORD[x.type as GuestType] ?? x.type
      }, not a ${word}`,
    );
  }
  if (!NODE_NAME_RE.test(x.node)) {
    throw new Error(
      `${word} ${vmid}: unexpected node name in /cluster/resources`,
    );
  }
  return x.node;
}

/** The node a guest runs on now. It follows a migration, so one model reaches every node. */
async function locateGuest(
  g: NodeGlobalArgs,
  auth: Awaited<ReturnType<typeof resolveAuth>>,
  type: GuestType,
  vmid: number,
): Promise<string> {
  const guests = parseClusterGuests(
    await pveCall(
      g,
      auth,
      "GET",
      `${g.apiUrl}/api2/json/cluster/resources?type=vm`,
      `Finding ${GUEST_WORD[type]} ${vmid}`,
    ),
  );
  return guestNode(guests, type, vmid);
}

const ClusterHealthSchema = z.object({
  node: z.string().describe("The node judged"),
  answeredBy: z.string().nullable().describe(
    "The node whose API answered (the entry marked local); null when none is marked",
  ),
  clustered: z.boolean().describe("True when the node is part of a cluster"),
  cluster: z.string().nullable().describe("Cluster name; null when standalone"),
  quorate: z.boolean().nullable().describe(
    "Whether the cluster has quorum; null when standalone",
  ),
  nodeListed: z.boolean().describe("The node is in /cluster/status"),
  nodeOnline: z.boolean().describe("The cluster sees the node online"),
  nodesOnline: z.number().int(),
  nodesTotal: z.number().int(),
  healthy: z.boolean().describe(
    "Listed, online and, in a cluster, quorate: problems is empty",
  ),
  problems: z.array(z.string()),
  checkedAt: z.string(),
});

type ClusterHealth = Omit<z.infer<typeof ClusterHealthSchema>, "checkedAt">;

/** A 0/1 flag of /cluster/status as a boolean; any other value throws. `undefined` is
 *  allowed only when `optional`, and is false. */
function flag01(
  o: Record<string, unknown>,
  key: string,
  optional = false,
): boolean {
  const v = o[key];
  if (v === undefined && optional) return false;
  if (v === 0 || v === 1) return v === 1;
  throw new Error(
    `Unexpected /cluster/status response from Proxmox (${key} is not 0 or 1)`,
  );
}

/**
 * Judge `node` from the /cluster/status payload. Strict: a malformed cluster or node entry,
 * two cluster entries, a node listed twice, an unsafe node name, two entries marked local or
 * no node at all throws. Entries of other types are ignored. The node is healthy only when it
 * is listed, online and, in a cluster, the cluster is quorate and lists as many nodes as it
 * says it has; every failed condition is a problem.
 */
export function parseClusterStatus(data: unknown, node: string): ClusterHealth {
  const what = "/cluster/status";
  let cluster: { name: string; quorate: boolean; nodes: number } | null = null;
  const nodes = new Map<string, { online: boolean; local: boolean }>();
  for (const item of asList(data, what)) {
    const entry = asRecord(item, what);
    if (entry.type === "cluster") {
      if (cluster) {
        throw new Error(
          `Unexpected ${what} response from Proxmox (two cluster entries)`,
        );
      }
      const count = entry.nodes;
      if (typeof count !== "number" || !Number.isInteger(count) || count < 0) {
        throw new Error(
          `Unexpected ${what} response from Proxmox (nodes missing)`,
        );
      }
      cluster = {
        name: stringField(entry, "name", what),
        quorate: flag01(entry, "quorate"),
        nodes: count,
      };
    } else if (entry.type === "node") {
      const name = stringField(entry, "name", what);
      if (!NODE_NAME_RE.test(name)) {
        throw new Error(
          `Unexpected ${what} response from Proxmox (unsafe node name)`,
        );
      }
      if (nodes.has(name)) {
        throw new Error(
          `Unexpected ${what} response from Proxmox (node ${name} listed twice)`,
        );
      }
      nodes.set(name, {
        online: flag01(entry, "online"),
        local: flag01(entry, "local", true),
      });
    }
  }
  if (nodes.size === 0) {
    throw new Error(
      `Unexpected ${what} response from Proxmox (no node entries)`,
    );
  }
  const locals = [...nodes.entries()].filter(([, n]) => n.local);
  if (locals.length > 1) {
    throw new Error(
      `Unexpected ${what} response from Proxmox (more than one local node)`,
    );
  }
  const own = nodes.get(node);
  const nodesOnline = [...nodes.values()].filter((n) => n.online).length;
  const problems: string[] = [];
  if (!own) problems.push(`node ${node} is not in ${what}`);
  else if (!own.online) problems.push(`node ${node} is offline`);
  if (cluster && !cluster.quorate) {
    problems.push(`cluster ${cluster.name} is not quorate`);
  }
  if (cluster && cluster.nodes !== nodes.size) {
    problems.push(
      `cluster ${cluster.name} says it has ${cluster.nodes} nodes but lists ${nodes.size}`,
    );
  }
  return {
    node,
    answeredBy: locals[0]?.[0] ?? null,
    clustered: cluster !== null,
    cluster: cluster?.name ?? null,
    quorate: cluster ? cluster.quorate : null,
    nodeListed: !!own,
    nodeOnline: !!own?.online,
    nodesOnline,
    nodesTotal: cluster?.nodes ?? nodes.size,
    healthy: problems.length === 0,
    problems,
  };
}

/** Run a snapshot task (POST or DELETE) on `node` and wait for it; returns the exit status. */
async function runSnapshotTask(
  g: NodeGlobalArgs,
  auth: Awaited<ReturnType<typeof resolveAuth>>,
  node: string,
  method: "POST" | "DELETE",
  path: string,
  what: string,
  form?: Record<string, string>,
): Promise<string> {
  const upid = await pveCall(
    g,
    auth,
    method,
    nodePath({ apiUrl: g.apiUrl, node }, path),
    what,
    form ? new URLSearchParams(form).toString() : undefined,
  );
  if (typeof upid !== "string" || !upid) return "OK";
  const result = await waitForTask(
    g.apiUrl,
    node,
    upid,
    auth,
    tlsOptions(g),
    SNAPSHOT_TASK_TIMEOUT_SECONDS,
  );
  return result.exitstatus ?? "unknown";
}

/** The `snapshot` resource for one VM or CT action. */
function snapshotRecord(
  type: GuestType,
  vmid: number,
  node: string,
  action: z.infer<typeof SnapshotSchema>["action"],
  snapshot: string | null,
  exitStatus: string | null,
  snapshots: z.infer<typeof SnapshotSchema>["snapshots"] = [],
): z.infer<typeof SnapshotSchema> {
  return {
    host: String(vmid),
    vmid,
    type,
    node,
    action,
    snapshot,
    exitStatus,
    snapshots,
    timestamp: new Date().toISOString(),
  };
}

/**
 * The snapshot, rollback, list and delete methods for one guest kind. Each finds the node the
 * guest runs on now in /cluster/resources (VM.Audit), then acts on that node: a guest on another
 * node, or one that moved, is still reached, and a guest that is not found, or is the other
 * kind, fails before any change.
 */
function snapshotMethods(type: GuestType) {
  const word = GUEST_WORD[type];
  const base = (vmid: number) => `/${type}/${vmid}/snapshot`;
  const start = async (context: Ctx, vmid: number) => {
    const g = context.globalArgs;
    const auth = await resolveAuth(g);
    const node = await locateGuest(g, auth, type, vmid);
    return { g, auth, node };
  };
  const rollbackArgs = type === "lxc"
    ? z.object({
      vmid: VmidArg,
      name: SnapshotNameArg,
      start: z.boolean().default(true).describe(
        "Start the CT after the rollback (Proxmox stops a CT to roll it back). Needs VM.PowerMgmt",
      ),
    })
    : z.object({ vmid: VmidArg, name: SnapshotNameArg });
  return {
    snapshot: {
      description:
        `Create a Proxmox snapshot of a ${word} on the node it runs on now (waits for the task to finish). Needs: VM.Audit and VM.Snapshot on /vms/{vmid}.`,
      arguments: z.object({
        vmid: VmidArg,
        name: z.union([z.literal(""), SnapshotNameArg]).default("").describe(
          "Snapshot name; default preupdate-<timestamp>",
        ),
        description: z.string().default("").describe(
          "Optional snapshot description",
        ),
      }),
      execute: async (
        args: { vmid: number; name: string; description: string },
        context: Ctx,
      ) => {
        const log = createMethodLogger(context);
        const snap = args.name ||
          `preupdate-${new Date().toISOString().replace(/[:.]/g, "-")}`;
        log.info(`Snapshotting ${word} {vmid} as {snap}`, {
          vmid: args.vmid,
          snap,
        });
        const { g, auth, node } = await start(context, args.vmid);
        const form: Record<string, string> = { snapname: snap };
        if (args.description) form.description = args.description;
        const exit = await runSnapshotTask(
          g,
          auth,
          node,
          "POST",
          base(args.vmid),
          `Snapshotting ${word} ${args.vmid}`,
          form,
        );
        if (exit !== "OK") throw new Error(`snapshot failed: ${exit}`);
        const handle = await context.writeResource(
          "snapshot",
          `snapshot-${args.vmid}`,
          snapshotRecord(type, args.vmid, node, "snapshot", snap, exit),
        );
        log.info(`${word} {vmid} snapshot {snap} on {node}: {exit}`, {
          vmid: args.vmid,
          snap,
          node,
          exit,
        });
        return { dataHandles: [handle] };
      },
    },
    rollback: {
      description: type === "lxc"
        ? "Roll a CT back to a Proxmox snapshot on the node it runs on now, and start it again (waits for the task to finish). Needs: VM.Audit, VM.Snapshot.Rollback (or VM.Snapshot) and, for start, VM.PowerMgmt on /vms/{vmid}."
        : "Roll a VM back to a Proxmox snapshot on the node it runs on now (waits for the task to finish). Needs: VM.Audit and VM.Snapshot.Rollback (or VM.Snapshot) on /vms/{vmid}.",
      arguments: rollbackArgs,
      execute: async (
        args: { vmid: number; name: string; start?: boolean },
        context: Ctx,
      ) => {
        const log = createMethodLogger(context);
        log.info(`Rolling ${word} {vmid} back to {snap}`, {
          vmid: args.vmid,
          snap: args.name,
        });
        const { g, auth, node } = await start(context, args.vmid);
        const exit = await runSnapshotTask(
          g,
          auth,
          node,
          "POST",
          `${base(args.vmid)}/${args.name}/rollback`,
          `Rolling ${word} ${args.vmid} back to ${args.name}`,
          type === "lxc" && args.start !== false ? { start: "1" } : undefined,
        );
        if (exit !== "OK") throw new Error(`rollback failed: ${exit}`);
        const handle = await context.writeResource(
          "snapshot",
          `snapshot-${args.vmid}`,
          snapshotRecord(type, args.vmid, node, "rollback", args.name, exit),
        );
        log.info(`${word} {vmid} rolled back to {snap} on {node}: {exit}`, {
          vmid: args.vmid,
          snap: args.name,
          node,
          exit,
        });
        return { dataHandles: [handle] };
      },
    },
    list: {
      description:
        `List a ${word}'s snapshots on the node it runs on now. Needs: VM.Audit on /vms/{vmid}.`,
      arguments: z.object({ vmid: VmidArg }),
      execute: async (args: { vmid: number }, context: Ctx) => {
        const log = createMethodLogger(context);
        log.info(`Listing snapshots of ${word} {vmid}`, { vmid: args.vmid });
        const { g, auth, node } = await start(context, args.vmid);
        const raw = await pveCall(
          g,
          auth,
          "GET",
          nodePath({ apiUrl: g.apiUrl, node }, base(args.vmid)),
          `Listing snapshots of ${word} ${args.vmid}`,
        );
        if (!Array.isArray(raw)) {
          throw new Error(
            `Unexpected snapshot list for ${word} ${args.vmid} (not an array)`,
          );
        }
        const snapshots = raw
          .filter((s) => s && s.name !== "current")
          .map((s) => ({
            name: String(s.name),
            description: s.description ?? null,
          }));
        const handle = await context.writeResource(
          "snapshot",
          `snapshot-${args.vmid}`,
          snapshotRecord(type, args.vmid, node, "list", null, null, snapshots),
        );
        log.info(`${word} {vmid} has {count} snapshots`, {
          vmid: args.vmid,
          count: snapshots.length,
        });
        return { dataHandles: [handle] };
      },
    },
    delete: {
      description:
        `Delete a ${word} snapshot on the node it runs on now (waits for the task to finish). Needs: VM.Audit and VM.Snapshot on /vms/{vmid}.`,
      arguments: z.object({ vmid: VmidArg, name: SnapshotNameArg }),
      execute: async (args: { vmid: number; name: string }, context: Ctx) => {
        const log = createMethodLogger(context);
        log.info(`Deleting snapshot {snap} of ${word} {vmid}`, {
          vmid: args.vmid,
          snap: args.name,
        });
        const { g, auth, node } = await start(context, args.vmid);
        const exit = await runSnapshotTask(
          g,
          auth,
          node,
          "DELETE",
          `${base(args.vmid)}/${args.name}`,
          `Deleting snapshot ${args.name} of ${word} ${args.vmid}`,
        );
        if (exit !== "OK") throw new Error(`delete failed: ${exit}`);
        const handle = await context.writeResource(
          "snapshot",
          `snapshot-${args.vmid}`,
          snapshotRecord(type, args.vmid, node, "delete", args.name, exit),
        );
        log.info(`${word} {vmid} snapshot {snap} deleted on {node}: {exit}`, {
          vmid: args.vmid,
          snap: args.name,
          node,
          exit,
        });
        return { dataHandles: [handle] };
      },
    },
  };
}

const VM_SNAPSHOTS = snapshotMethods("qemu");
const CT_SNAPSHOTS = snapshotMethods("lxc");

/** Swamp model definition for `@dmc/proxmox/node`. */
export const model = {
  type: "@dmc/proxmox/node",
  version: "2026.11.13.1",
  globalArguments: ProxmoxConnectionArgs,
  upgrades: [
    {
      toVersion: "2026.10.26.1",
      description:
        "First release. Definitions moved from @keeb/proxmox/node keep their attributes; set tokenId/tokenSecret for token auth",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.11.07.1",
      description:
        "Breaking: API tokens are the only auth. The upgrade drops the ticket, csrfToken, username, password and realm global args; a definition that used them needs tokenId and tokenSecret. Additive: optional caCert (verify a self-signed API certificate). New methods: CT snapshots, permissions, clusterHealth and ensureSnapshotAccess. Set skipTlsVerify false or caCert, so the token is not sent unverified",
      upgradeAttributes: dropRemovedAuthArgs,
    },
    {
      toVersion: "2026.11.13.1",
      description:
        "Additive: new method ensureRunnerPoolAccess (a least-privilege token that may clone its templates, clone only into one CI pool, and power and delete only that pool's guests) with the runnerPoolAccess and runnerPoolToken resources. No argument changes",
      upgradeAttributes: dropRemovedAuthArgs,
    },
  ],
  resources: {
    status: {
      description: "Node resource usage (memory, CPU, uptime)",
      schema: NodeStatusSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    guests: {
      description: "VMs + CTs known to the Proxmox cluster",
      schema: GuestsSchema,
      lifetime: "infinite",
      garbageCollection: 5,
    },
    snapshot: {
      description: "Result of a VM or CT snapshot / rollback / list / delete",
      schema: SnapshotSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    permissions: {
      description:
        "Effective Proxmox privileges of a token or user, per ACL path",
      schema: PermissionsSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    snapshotAccess: {
      description:
        "Plan, blockers, actions and verification of an ensureSnapshotAccess run",
      schema: SnapshotAccessSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    clusterHealth: {
      description:
        "One node judged from /cluster/status: listed, online, cluster quorate",
      schema: ClusterHealthSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    snapshotToken: {
      description:
        "One-time secret of a snapshot API token created by ensureSnapshotAccess (sensitive)",
      schema: SnapshotTokenSchema,
      lifetime: "infinite",
      garbageCollection: 5,
    },
    runnerPoolAccess: {
      description:
        "Plan, blockers, actions and verification of an ensureRunnerPoolAccess run",
      schema: RunnerPoolAccessSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    runnerPoolToken: {
      description:
        "One-time secret of a runner-pool API token created by ensureRunnerPoolAccess (sensitive)",
      schema: RunnerPoolTokenSchema,
      lifetime: "infinite",
      garbageCollection: 5,
    },
  },
  checks: {
    "valid-connection": {
      description:
        "apiUrl is an http(s) URL without credentials and node is set",
      labels: ["policy"],
      execute: (context: { globalArgs: NodeGlobalArgs }) =>
        Promise.resolve(validateConnection(context.globalArgs)),
    },
    "node-reachable": {
      description:
        "The Proxmox API answers with the configured auth (reads /version, which any valid token may read, so a limited token passes too)",
      labels: ["live"],
      execute: async (context: { globalArgs: NodeGlobalArgs }) => {
        const g = context.globalArgs;
        if (hasUnresolvedAuth(g)) return { pass: true };
        try {
          const auth = await resolveAuth(g);
          await pveCall(
            g,
            auth,
            "GET",
            `${g.apiUrl}/api2/json/version`,
            "Reading the Proxmox API version",
          );
          return { pass: true };
        } catch (err) {
          return {
            pass: false,
            errors: [
              `${
                (err as Error).message
              }. Fix the cause, or skip with --skip-check-label live.`,
            ],
          };
        }
      },
    },
  },
  methods: {
    status: {
      description:
        "Fetch current node resource usage (memory, CPU, uptime). Needs: Sys.Audit on /nodes/{node}.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Fetching status of node {node}", { node: g.node });
        const auth = await resolveAuth(g);
        const status = parseNodeStatus(
          await pveCall(
            g,
            auth,
            "GET",
            nodePath(g, "/status"),
            `Fetching status of node ${g.node}`,
          ),
        );
        const handle = await context.writeResource("status", "status", {
          ...status,
          timestamp: new Date().toISOString(),
        });
        log.info("Node {node}: {cpus} CPUs, {used}/{total} bytes memory used", {
          node: g.node,
          cpus: status.cpuCount,
          used: status.memoryUsed,
          total: status.memoryTotal,
        });
        return { dataHandles: [handle] };
      },
    },

    clusterHealth: {
      description:
        "Judge one node from /cluster/status: healthy when the node is listed and online and, in a cluster, the cluster is quorate. Read-only, and an unhealthy node is a result, not an error; a failed call or a malformed answer is an error. Needs: Sys.Audit on / (ensureSnapshotAccess with clusterAudit grants exactly that).",
      arguments: z.object({
        node: z.string()
          .regex(NODE_NAME_RE, "node must be a Proxmox node name")
          .optional()
          .describe("The node to judge (default: the configured node)"),
      }),
      execute: async (args: { node?: string }, context: Ctx) => {
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        const node = args.node ?? g.node;
        if (!NODE_NAME_RE.test(node)) {
          throw new Error("the configured node is not a Proxmox node name");
        }
        log.info("Reading cluster health for node {node}", { node });
        const auth = await resolveAuth(g);
        const health = parseClusterStatus(
          await pveCall(
            g,
            auth,
            "GET",
            `${g.apiUrl}/api2/json/cluster/status`,
            "Reading the cluster status",
          ),
          node,
        );
        const handle = await context.writeResource(
          "clusterHealth",
          `cluster-health-${node}`,
          { ...health, checkedAt: new Date().toISOString() },
        );
        log.info(
          "Node {node}: {verdict} ({online}/{total} nodes online, quorate {quorate})",
          {
            node,
            verdict: health.healthy
              ? "healthy"
              : `unhealthy: ${health.problems.join("; ")}`,
            online: health.nodesOnline,
            total: health.nodesTotal,
            quorate: health.quorate ?? "n/a",
          },
        );
        return { dataHandles: [handle] };
      },
    },

    listGuests: {
      description:
        "List all VMs and CTs on the Proxmox cluster (type, vmid, name, status, node, ip). Needs: VM.Audit on each guest (others are not listed); VM.GuestAgent.Audit for VM IPs.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Listing guests on the cluster of node {node}", {
          node: g.node,
        });
        const auth = await resolveAuth(g);
        const base = parseClusterGuests(
          await pveCall(
            g,
            auth,
            "GET",
            `${g.apiUrl}/api2/json/cluster/resources?type=vm`,
            "Listing cluster guests",
          ),
        );
        const guests = await Promise.all(
          base.map(async (guest) => ({
            ...guest,
            ip: await guestIp(g, auth, guest),
          })),
        );
        const handle = await context.writeResource("guests", "guests", {
          total: guests.length,
          guests,
          checkedAt: new Date().toISOString(),
        });
        log.info("Found {total} guests ({vms} VMs, {cts} CTs)", {
          total: guests.length,
          vms: guests.filter((x) => x.type === "qemu").length,
          cts: guests.filter((x) => x.type === "lxc").length,
        });
        return { dataHandles: [handle] };
      },
    },

    snapshotVm: VM_SNAPSHOTS.snapshot,
    rollbackVm: VM_SNAPSHOTS.rollback,
    listVmSnapshots: VM_SNAPSHOTS.list,
    deleteVmSnapshot: VM_SNAPSHOTS.delete,
    snapshotCt: CT_SNAPSHOTS.snapshot,
    rollbackCt: CT_SNAPSHOTS.rollback,
    listCtSnapshots: CT_SNAPSHOTS.list,
    deleteCtSnapshot: CT_SNAPSHOTS.delete,

    permissions: {
      description:
        "Read the effective Proxmox privileges of the calling token/user (or of `userid`), optionally for one ACL path. Read-only. Needs: nothing for the caller itself; Sys.Audit on /access to read another user or token.",
      arguments: z.object({
        path: PermissionPathArg.optional(),
        userid: UseridArg.optional(),
      }),
      execute: async (
        args: { path?: string; userid?: string },
        context: Ctx,
      ) => {
        const g = context.globalArgs;
        const log = createMethodLogger(context);
        log.info("Reading effective privileges of {who}", {
          who: args.userid ?? "the caller",
        });
        const auth = await resolveAuth(g);
        const params = new URLSearchParams();
        if (args.path) params.set("path", args.path);
        if (args.userid) params.set("userid", args.userid);
        const query = params.toString();
        const paths = parsePermissions(
          await pveCall(
            g,
            auth,
            "GET",
            `${g.apiUrl}/api2/json/access/permissions${
              query ? `?${query}` : ""
            }`,
            "Reading effective privileges",
          ),
        );
        for (const p of paths) {
          log.info("{path}: {count} privileges", {
            path: p.path,
            count: p.privileges.length,
          });
        }
        const subject = args.userid ?? auth.tokenId;
        const handle = await context.writeResource(
          "permissions",
          "permissions",
          {
            subject,
            path: args.path ?? null,
            paths,
            checkedAt: new Date().toISOString(),
          },
        );
        log.info("{subject}: privileges on {count} paths", {
          subject,
          count: paths.length,
        });
        return { dataHandles: [handle] };
      },
    },

    ensureSnapshotAccess: {
      description:
        "Make a least-privilege Proxmox API token that may only snapshot, roll back and power the guests in one pool, and, with clusterAudit, read cluster health (Sys.Audit on / only, in its own role). " +
        "Dry run by default. Reads everything first and writes nothing if any blocker exists. Creates only what is missing: it never changes or removes an existing role, user, token, ACL, pool or guest membership, and never moves a guest out of another pool. " +
        "The new token secret is a sensitive output, stored in the vault as snapshot-token and never in data. " +
        "Needs: Sys.Audit and Sys.Modify on /access; User.Modify on /access/groups; Realm.AllocateUser on /access/realm/pve (new user only); Pool.Allocate, Pool.Audit and Permissions.Modify on /pool/{pool}; Permissions.Modify or VM.Allocate on each guest added; with clusterAudit, Permissions.Modify on /.",
      arguments: EnsureSnapshotAccessArgs,
      execute: (args: EnsureArgs, context: Ctx) =>
        ensureAccess(
          snapshotAccessSpec(args),
          args.dryRun,
          {
            recordSpec: "snapshotAccess",
            recordName: "snapshot-access",
            tokenSpec: "snapshotToken",
            tokenName: "snapshot-token",
            label: "Snapshot access",
            record: (base) => ({
              ...base,
              role: args.role,
              privileges: [...SNAPSHOT_ROLE_PRIVILEGES],
              clusterAudit: args.clusterAudit,
              auditRole: args.clusterAudit ? args.auditRole : null,
              auditPrivileges: args.clusterAudit
                ? [...AUDIT_ROLE_PRIVILEGES]
                : [],
            }),
          },
          context,
        ),
    },

    ensureRunnerPoolAccess: {
      description:
        "Make a least-privilege Proxmox API token for a CI runner pool: it may clone, start, stop and delete the guests in one pool, and make new guests (linked clones) only in that pool. It may only read and clone the templates it is given (VM.Audit and VM.Clone on each /vms/{template}); the templates must stay outside the pool, so the token cannot delete or change them. It also gets Datastore.AllocateSpace on one storage (the clone disks) and, when a bridge is given, SDN.Use on that bridge. Each kind of grant is its own custom role with propagate 0, so the token holds nothing on any other path. " +
        "Dry run by default. Reads everything first and writes nothing if any blocker exists. Creates only what is missing: it never changes or removes an existing role, user, token, ACL, pool or guest membership, and never moves a guest out of another pool. It never adds a guest to the pool: a clone joins it when it is made. Clones in the pool are reported as extra members, never removed. " +
        "The new token secret is a sensitive output, stored in the vault as runner-pool-token and never in data. " +
        "Needs: Sys.Audit and Sys.Modify on /access; User.Modify on /access/groups; Realm.AllocateUser on /access/realm/pve (new user only); Pool.Allocate, Pool.Audit and Permissions.Modify on /pool/{pool}; Permissions.Modify on /storage/{storage}, with a bridge on its /sdn/zones path, and on each /vms/{template}.",
      arguments: EnsureRunnerPoolAccessArgs,
      execute: (args: RunnerPoolArgs, context: Ctx) => {
        const spec = runnerPoolAccessSpec(args);
        return ensureAccess(
          spec,
          args.dryRun,
          {
            recordSpec: "runnerPoolAccess",
            recordName: "runner-pool-access",
            tokenSpec: "runnerPoolToken",
            tokenName: "runner-pool-token",
            label: "Runner pool access",
            record: ({ members: _members, ...base }) => ({
              ...base,
              templates: spec.templates,
              grants: spec.grants.map(({ path, role, privileges }) => ({
                path,
                role,
                privileges: [...privileges],
              })),
            }),
          },
          context,
        );
      },
    },
  },
};
