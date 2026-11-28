/**
 * `@dmc/forgejo/admin` — site-administrator work on a Forgejo server through
 * its API: make a limited service account (ensureUser), give it a repository
 * with Actions and collaborators (ensureRepo), and make an access token for it
 * (ensureUserToken). Built for accounts that own CI runners, such as a test
 * runner pool that must not hold the main account's token.
 *
 * Every method is a dry run by default and reads first. When a blocker
 * exists, it changes nothing in Forgejo, records the blocker and fails. It
 * never manages a site administrator, never makes a token with an admin scope,
 * and never changes or removes an existing token. Secrets (a new account's
 * password, a new token) are sensitive outputs: swamp stores them in the vault
 * and keeps only a reference in data.
 *
 * API shapes follow the Forgejo v16.0.6 source (tag `v16.0.6`, commit 1aa1394).
 *
 * @module
 */
import { z } from "npm:zod@4";
import {
  type ApiUserT,
  type Fetcher,
  ForgejoClient,
  type ForgejoConnection,
  ForgejoConnectionArgs,
  generatePassword,
  getTokenUser,
  getUser,
  hasUnresolvedConnection,
  seg,
  SLUG_RE,
  TOKEN_RE,
  USERNAME_RE,
  validateConnection,
} from "./lib/forgejo.ts";

/** The part of swamp's method context these methods use. */
interface Ctx {
  globalArgs: ForgejoConnection;
  logger?: unknown;
  writeResource: (
    spec: string,
    name: string,
    data: unknown,
  ) => Promise<{ name: string }>;
}

/** Hidden test hook: a fetch replacement. Not a method argument in the schema. */
interface TestHooks {
  _fetch?: Fetcher;
}

/** Token scopes ensureUserToken may give. No admin scope, no `all`, no public-only. */
export const ALLOWED_TOKEN_SCOPES = [
  "read:activitypub",
  "write:activitypub",
  "read:issue",
  "write:issue",
  "read:misc",
  "write:misc",
  "read:notification",
  "write:notification",
  "read:organization",
  "write:organization",
  "read:package",
  "write:package",
  "read:repository",
  "write:repository",
  "read:user",
  "write:user",
] as const;

const Username = z.string().regex(
  USERNAME_RE,
  "username: lowercase letters and digits in groups joined by single hyphens, 2 to 39 characters",
);
const Slug = z.string().regex(
  SLUG_RE,
  "lowercase letters and digits in groups joined by single hyphens, 1 to 64 characters",
);
const DryRun = z.boolean().default(true).describe(
  "Only plan and check; write nothing (default true)",
);

const Status = z.enum(["planned", "unchanged", "applied", "blocked"]);
const ActionState = z.enum(["present", "planned", "applied"]);

function log(ctx: Ctx, msg: string, props: Record<string, unknown> = {}) {
  const l = ctx.logger as
    | { info?: (m: string, p: Record<string, unknown>) => void }
    | undefined;
  l?.info?.(msg, props);
}

function client(ctx: Ctx, hooks: TestHooks): ForgejoClient {
  return new ForgejoClient(ctx.globalArgs, hooks._fetch);
}

/** The caller must be an active site administrator. */
async function callerBlockers(c: ForgejoClient): Promise<string[]> {
  const me = await getTokenUser(c);
  const b: string[] = [];
  if (!me.is_admin) {
    b.push(`the token's user ${me.login} is not a site administrator`);
  }
  return b;
}

/** Blockers for a user that this extension may manage. */
function managedUserBlockers(u: ApiUserT): string[] {
  const b: string[] = [];
  if (u.is_admin) {
    b.push(
      `${u.login} is a site administrator; this extension never manages one`,
    );
  }
  if (u.prohibit_login) {
    b.push(`${u.login} has prohibit_login set; its tokens would not work`);
  }
  if (!u.active) b.push(`${u.login} is not active`);
  return b;
}

// ---------------------------------------------------------------- ensureUser

const EnsureUserArgs = z.object({
  username: Username,
  email: z.email().describe(
    "Primary email of the account (no mail is sent)",
  ),
  fullName: z.string().max(100).default(""),
  restricted: z.boolean().default(true).describe(
    "Restricted: the account sees only repositories and orgs it is given",
  ),
  visibility: z.enum(["public", "limited", "private"]).default("private"),
  maxRepoCreation: z.number().int().min(-1).default(1).describe(
    "Repositories the account may own (-1: the server default)",
  ),
  allowCreateOrganization: z.boolean().default(false),
  dryRun: DryRun,
});
type EnsureUserArgsT = z.infer<typeof EnsureUserArgs>;

const UserRecord = z.object({
  dryRun: z.boolean(),
  status: Status,
  username: z.string(),
  id: z.number().nullable(),
  created: z.boolean().describe("True when this run made the account"),
  restricted: z.boolean(),
  visibility: z.string(),
  maxRepoCreation: z.number(),
  allowCreateOrganization: z.boolean(),
  actions: z.array(z.object({
    action: z.enum(["createUser", "setLimits"]),
    state: ActionState,
  })),
  blockers: z.array(z.string()),
  passwordIssued: z.boolean().describe(
    "True when this run stored a new password in the vault",
  ),
  checkedAt: z.string(),
});

const UserPassword = z.object({
  username: z.string(),
  password: z.string().describe("Generated password of a new account")
    .meta({ sensitive: true }),
  createdAt: z.string(),
});

async function ensureUser(
  args: EnsureUserArgsT & TestHooks,
  ctx: Ctx,
): Promise<{ dataHandles: { name: string }[] }> {
  log(ctx, "ensureUser {username}: checking ({mode})", {
    username: args.username,
    mode: args.dryRun ? "dry run" : "live",
  });
  const c = client(ctx, args);
  const blockers = await callerBlockers(c);
  const existing = await getUser(c, args.username);
  if (existing) blockers.push(...managedUserBlockers(existing));

  const limits = {
    restricted: args.restricted,
    visibility: args.visibility,
    max_repo_creation: args.maxRepoCreation,
    allow_create_organization: args.allowCreateOrganization,
  };
  const actions: z.infer<typeof UserRecord>["actions"] = [
    { action: "createUser", state: existing ? "present" : "planned" },
    // Forgejo's api.User does not show max_repo_creation or
    // allow_create_organization, so the limits are always set (idempotent).
    { action: "setLimits", state: "planned" },
  ];
  const now = new Date().toISOString();
  const base = {
    dryRun: args.dryRun,
    username: args.username,
    restricted: args.restricted,
    visibility: args.visibility,
    maxRepoCreation: args.maxRepoCreation,
    allowCreateOrganization: args.allowCreateOrganization,
    blockers,
    checkedAt: now,
  };
  const handles: { name: string }[] = [];

  if (blockers.length || args.dryRun) {
    handles.push(
      await ctx.writeResource("user", `${args.username}-user`, {
        ...base,
        status: blockers.length ? "blocked" : "planned",
        id: existing?.id ?? null,
        created: false,
        actions,
        passwordIssued: false,
      }),
    );
    if (blockers.length) {
      throw new Error(
        `ensureUser ${args.username} blocked: ${blockers.join("; ")}`,
      );
    }
    log(ctx, "ensureUser {username}: planned", { username: args.username });
    return { dataHandles: handles };
  }

  let created = false;
  if (!existing) {
    const password = generatePassword();
    // Store the password before the account exists: a failure after the
    // create must not leave an account whose password nobody has. If the
    // create fails, the stored password belongs to no account, and the next
    // run stores a new one.
    handles.push(
      await ctx.writeResource("password", `${args.username}-password`, {
        username: args.username,
        password,
        createdAt: now,
      }),
    );
    await c.expect({
      method: "POST",
      path: "/admin/users",
      body: {
        username: args.username,
        email: args.email,
        full_name: args.fullName,
        password,
        must_change_password: false,
        send_notify: false,
        restricted: args.restricted,
        visibility: args.visibility,
      },
      secrets: [password],
    }, [201]);
    created = true;
    actions[0].state = "applied";
  }

  await c.expect({
    method: "PATCH",
    path: `/admin/users/${seg(args.username)}`,
    // source_id and login_name must be given together (local source 0).
    body: { source_id: 0, login_name: args.username, ...limits },
  }, [200]);
  actions[1].state = "applied";

  const after = await getUser(c, args.username);
  if (!after) throw new Error(`${args.username} is missing after the run`);
  const wrong: string[] = [];
  if (after.is_admin) wrong.push("is_admin is true");
  if (after.restricted !== args.restricted) {
    wrong.push(`restricted is ${after.restricted}`);
  }
  if (after.visibility !== args.visibility) {
    wrong.push(`visibility is ${after.visibility}`);
  }
  if (wrong.length) {
    throw new Error(`${args.username} check failed: ${wrong.join(", ")}`);
  }

  handles.unshift(
    await ctx.writeResource("user", `${args.username}-user`, {
      ...base,
      status: "applied",
      id: after.id,
      created,
      actions,
      passwordIssued: created,
    }),
  );
  log(ctx, "ensureUser {username}: applied (created {created})", {
    username: args.username,
    created,
  });
  return { dataHandles: handles };
}

// ---------------------------------------------------------------- ensureRepo

const EnsureRepoArgs = z.object({
  owner: Username.describe("The user that owns the repository"),
  repo: Slug.describe("Repository name"),
  private: z.boolean().default(true),
  actions: z.boolean().default(true).describe("Actions unit on"),
  collaborators: z.array(z.object({
    username: Username,
    permission: z.enum(["read", "write", "admin"]),
  })).default([]).describe(
    "Collaborators to add, each with its permission (set on each live run)",
  ),
  dryRun: DryRun,
});
type EnsureRepoArgsT = z.infer<typeof EnsureRepoArgs>;

const RepoRecord = z.object({
  dryRun: z.boolean(),
  status: Status,
  owner: z.string(),
  repo: z.string(),
  id: z.number().nullable(),
  private: z.boolean(),
  hasActions: z.boolean(),
  collaborators: z.array(z.object({
    username: z.string(),
    permission: z.string(),
  })),
  actions: z.array(z.object({
    action: z.enum([
      "createRepo",
      "setPrivate",
      "setActions",
      "setCollaborator",
    ]),
    target: z.string(),
    state: ActionState,
  })),
  blockers: z.array(z.string()),
  checkedAt: z.string(),
});

const ApiRepo = z.object({
  id: z.number(),
  private: z.boolean(),
  has_actions: z.boolean().optional().default(false),
  owner: z.object({ login: z.string() }),
});

async function getRepo(c: ForgejoClient, owner: string, repo: string) {
  const a = await c.call({
    method: "GET",
    path: `/repos/${seg(owner)}/${seg(repo)}`,
  });
  if (a.status === 404) return null;
  if (a.status !== 200) {
    throw new Error(`GET /repos/${owner}/${repo}: HTTP ${a.status}`);
  }
  return ApiRepo.parse(a.body);
}

async function ensureRepo(
  args: EnsureRepoArgsT & TestHooks,
  ctx: Ctx,
): Promise<{ dataHandles: { name: string }[] }> {
  log(ctx, "ensureRepo {target}: checking ({mode})", {
    target: `${args.owner}/${args.repo}`,
    mode: args.dryRun ? "dry run" : "live",
  });
  const c = client(ctx, args);
  const blockers = await callerBlockers(c);
  const owner = await getUser(c, args.owner);
  if (!owner) blockers.push(`user ${args.owner} does not exist`);
  else if (owner.is_admin) {
    blockers.push(
      `${args.owner} is a site administrator; this extension never manages one`,
    );
  }
  const names = args.collaborators.map((x) => x.username);
  if (new Set(names).size !== names.length) {
    blockers.push("collaborators lists a user twice");
  }
  for (const col of args.collaborators) {
    if (col.username === args.owner) {
      blockers.push(`collaborator ${col.username} is the owner`);
      continue;
    }
    const u = await getUser(c, col.username);
    if (!u) blockers.push(`collaborator ${col.username} does not exist`);
  }
  const existing = owner ? await getRepo(c, args.owner, args.repo) : null;
  if (existing && existing.owner.login !== args.owner) {
    blockers.push(
      `${args.owner}/${args.repo} redirects to ${existing.owner.login}; give the real owner`,
    );
  }

  const target = `${args.owner}/${args.repo}`;
  type Action = z.infer<typeof RepoRecord>["actions"][number];
  const actions: Action[] = [
    { action: "createRepo", target, state: existing ? "present" : "planned" },
    {
      action: "setPrivate",
      target,
      state: existing && existing.private === args.private
        ? "present"
        : "planned",
    },
    {
      action: "setActions",
      target,
      state: existing && existing.has_actions === args.actions
        ? "present"
        : "planned",
    },
    ...args.collaborators.map((col): Action => ({
      action: "setCollaborator",
      target: `${col.username}:${col.permission}`,
      state: "planned",
    })),
  ];
  const record = (status: z.infer<typeof Status>, id: number | null) => ({
    dryRun: args.dryRun,
    status,
    owner: args.owner,
    repo: args.repo,
    id,
    private: args.private,
    hasActions: args.actions,
    collaborators: args.collaborators,
    actions,
    blockers,
    checkedAt: new Date().toISOString(),
  });
  const dataName = `${args.owner}--${args.repo}-repo`;

  if (blockers.length || args.dryRun) {
    const h = await ctx.writeResource(
      "repo",
      dataName,
      record(blockers.length ? "blocked" : "planned", existing?.id ?? null),
    );
    if (blockers.length) {
      throw new Error(`ensureRepo ${target} blocked: ${blockers.join("; ")}`);
    }
    log(ctx, "ensureRepo {target}: planned", { target });
    return { dataHandles: [h] };
  }

  if (!existing) {
    await c.expect({
      method: "POST",
      path: `/admin/users/${seg(args.owner)}/repos`,
      body: {
        name: args.repo,
        private: args.private,
        auto_init: true,
        default_branch: "main",
      },
    }, [201]);
    actions[0].state = "applied";
  }
  const now = await getRepo(c, args.owner, args.repo);
  if (!now) throw new Error(`${target} is missing after create`);
  if (now.private !== args.private || now.has_actions !== args.actions) {
    await c.expect({
      method: "PATCH",
      path: `/repos/${seg(args.owner)}/${seg(args.repo)}`,
      body: { private: args.private, has_actions: args.actions },
    }, [200]);
  }
  if (actions[1].state === "planned") actions[1].state = "applied";
  if (actions[2].state === "planned") actions[2].state = "applied";
  for (const [i, col] of args.collaborators.entries()) {
    await c.expect({
      method: "PUT",
      path: `/repos/${seg(args.owner)}/${seg(args.repo)}/collaborators/${
        seg(col.username)
      }`,
      body: { permission: col.permission },
    }, [204]);
    actions[3 + i].state = "applied";
  }

  const after = await getRepo(c, args.owner, args.repo);
  if (!after) throw new Error(`${target} is missing after the run`);
  const wrong: string[] = [];
  if (after.private !== args.private) wrong.push(`private is ${after.private}`);
  if (after.has_actions !== args.actions) {
    wrong.push(`has_actions is ${after.has_actions}`);
  }
  for (const col of args.collaborators) {
    const a = await c.call({
      method: "GET",
      path: `/repos/${seg(args.owner)}/${seg(args.repo)}/collaborators/${
        seg(col.username)
      }`,
    });
    if (a.status !== 204) wrong.push(`${col.username} is not a collaborator`);
  }
  if (wrong.length) {
    throw new Error(`${target} check failed: ${wrong.join(", ")}`);
  }

  const h = await ctx.writeResource(
    "repo",
    dataName,
    record("applied", after.id),
  );
  log(ctx, "ensureRepo {target}: applied", { target });
  return { dataHandles: [h] };
}

// ----------------------------------------------------------- ensureUserToken

const EnsureUserTokenArgs = z.object({
  username: Username.describe("The account that gets the token"),
  tokenName: Slug.describe("Token name, unique for the account"),
  scopes: z.array(z.enum(ALLOWED_TOKEN_SCOPES)).min(1).describe(
    "Token scopes; no admin scope is allowed",
  ),
  dryRun: DryRun,
});
type EnsureUserTokenArgsT = z.infer<typeof EnsureUserTokenArgs>;

const TokenRecord = z.object({
  dryRun: z.boolean(),
  status: Status,
  username: z.string(),
  tokenName: z.string(),
  tokenId: z.number().nullable(),
  scopes: z.array(z.string()),
  verifiedLogin: z.string().nullable().describe(
    "Login that GET /user gave with the new token",
  ),
  blockers: z.array(z.string()),
  tokenIssued: z.boolean().describe(
    "True when this run stored a new token in the vault",
  ),
  checkedAt: z.string(),
});

const UserToken = z.object({
  username: z.string(),
  tokenName: z.string(),
  tokenId: z.number(),
  token: z.string().describe("The access token, shown once by Forgejo")
    .meta({ sensitive: true }),
  createdAt: z.string(),
});

const ApiToken = z.object({
  id: z.number(),
  name: z.string(),
  scopes: z.array(z.string()).nullable().optional(),
  sha1: z.string().optional().default(""),
});

async function listTokens(c: ForgejoClient, username: string) {
  const all: z.infer<typeof ApiToken>[] = [];
  const limit = 50;
  for (let page = 1; page <= 100; page++) {
    const a = await c.expect({
      method: "GET",
      path: `/admin/users/${seg(username)}/tokens?page=${page}&limit=${limit}`,
    }, [200]);
    const items = z.array(ApiToken).parse(a.body ?? []);
    all.push(...items);
    if (items.length < limit) return all;
  }
  throw new Error(`more than 5000 tokens for ${username}`);
}

function sameScopes(a: string[], b: string[]): boolean {
  const x = [...new Set(a)].sort();
  const y = [...new Set(b)].sort();
  return x.length === y.length && x.every((v, i) => v === y[i]);
}

async function ensureUserToken(
  args: EnsureUserTokenArgsT & TestHooks,
  ctx: Ctx,
): Promise<{ dataHandles: { name: string }[] }> {
  log(ctx, "ensureUserToken {target}: checking ({mode})", {
    target: `${args.username}/${args.tokenName}`,
    mode: args.dryRun ? "dry run" : "live",
  });
  const c = client(ctx, args);
  const blockers = await callerBlockers(c);
  const scopes = [...new Set(args.scopes)].sort();
  const user = await getUser(c, args.username);
  if (!user) blockers.push(`user ${args.username} does not exist`);
  else blockers.push(...managedUserBlockers(user));
  const tokens = user && !user.is_admin
    ? await listTokens(c, args.username)
    : [];
  const existing = tokens.find((t) => t.name === args.tokenName);
  if (existing && !sameScopes(existing.scopes ?? [], scopes)) {
    blockers.push(
      `token ${args.tokenName} exists with scopes ${
        (existing.scopes ?? []).join(",") || "(none)"
      }, not ${scopes.join(",")}; delete it in Forgejo to make a new one`,
    );
  }

  const dataName = `${args.username}--${args.tokenName}`;
  const record = (
    status: z.infer<typeof Status>,
    extra: Partial<z.infer<typeof TokenRecord>> = {},
  ) => ({
    dryRun: args.dryRun,
    status,
    username: args.username,
    tokenName: args.tokenName,
    tokenId: existing?.id ?? null,
    scopes,
    verifiedLogin: null,
    blockers,
    tokenIssued: false,
    checkedAt: new Date().toISOString(),
    ...extra,
  });

  if (blockers.length || args.dryRun || existing) {
    const status = blockers.length
      ? "blocked"
      : existing
      ? "unchanged"
      : "planned";
    const h = await ctx.writeResource(
      "tokenAccess",
      `${dataName}-token-access`,
      record(status),
    );
    if (blockers.length) {
      throw new Error(
        `ensureUserToken ${dataName} blocked: ${blockers.join("; ")}`,
      );
    }
    log(ctx, "ensureUserToken {target}: {status}", {
      target: dataName,
      status,
    });
    return { dataHandles: [h] };
  }

  const a = await c.expect({
    method: "POST",
    path: `/admin/users/${seg(args.username)}/tokens`,
    body: { name: args.tokenName, scopes },
  }, [201]);
  const parsed = ApiToken.safeParse(a.body);
  if (!parsed.success) {
    throw new Error(
      `Forgejo's answer to the token create has no id; token ${args.tokenName} of ${args.username} may exist: delete it in Forgejo`,
    );
  }
  const made = parsed.data;
  const secret = made.sha1;
  /** Delete the new token; say in words whether that worked. */
  const del = async (): Promise<string> => {
    try {
      const d = await c.call({
        method: "DELETE",
        path: `/admin/users/${seg(args.username)}/tokens/${made.id}`,
      });
      if (d.status === 204) return "it was deleted";
      return `its delete failed (HTTP ${d.status}): delete token ${args.tokenName} of ${args.username} in Forgejo`;
    } catch (err) {
      return `its delete failed (${
        (err as Error).message
      }): delete token ${args.tokenName} of ${args.username} in Forgejo`;
    }
  };
  if (!TOKEN_RE.test(secret)) {
    throw new Error(`Forgejo gave no valid token; ${await del()}`);
  }
  const wrong: string[] = [];
  if (!sameScopes(made.scopes ?? [], scopes)) {
    wrong.push(`scopes are ${(made.scopes ?? []).join(",")}`);
  }
  let login: string | null = null;
  try {
    const me = await getTokenUser(c, secret);
    login = me.login;
    if (me.login !== args.username) wrong.push(`GET /user gave ${me.login}`);
    if (me.is_admin) wrong.push("the token's user is a site administrator");
  } catch (err) {
    wrong.push(
      `GET /user with the new token failed: ${(err as Error).message}`,
    );
  }
  if (wrong.length) {
    throw new Error(
      `the new token failed its check (${wrong.join("; ")}); ${await del()}`,
    );
  }

  const createdAt = new Date().toISOString();
  let tokenHandle: { name: string };
  try {
    tokenHandle = await ctx.writeResource("token", `${dataName}-token`, {
      username: args.username,
      tokenName: args.tokenName,
      tokenId: made.id,
      token: secret,
      createdAt,
    });
  } catch (err) {
    // A token nobody can read is no use, and a re-run would only report it
    // unchanged: remove it so the next run makes a new one.
    throw new Error(
      `could not store the new token (${
        (err as Error).message
      }); ${await del()}`,
    );
  }
  const recHandle = await ctx.writeResource(
    "tokenAccess",
    `${dataName}-token-access`,
    record("applied", {
      tokenId: made.id,
      verifiedLogin: login,
      tokenIssued: true,
    }),
  );
  log(ctx, "ensureUserToken {target}: applied", { target: dataName });
  return { dataHandles: [recHandle, tokenHandle] };
}

// --------------------------------------------------------------------- model

/** The `@dmc/forgejo/admin` model. */
export const model = {
  type: "@dmc/forgejo/admin",
  version: "2026.11.27.1",
  globalArguments: ForgejoConnectionArgs,
  resources: {
    user: {
      description: "Plan, actions and check of an ensureUser run",
      schema: UserRecord,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    password: {
      description:
        "Generated password of an account ensureUser made (sensitive)",
      schema: UserPassword,
      lifetime: "infinite",
      garbageCollection: 5,
    },
    repo: {
      description: "Plan, actions and check of an ensureRepo run",
      schema: RepoRecord,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    tokenAccess: {
      description: "Plan and check of an ensureUserToken run",
      schema: TokenRecord,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    token: {
      description: "Access token that ensureUserToken made (sensitive)",
      schema: UserToken,
      lifetime: "infinite",
      garbageCollection: 5,
    },
  },
  checks: {
    "valid-connection": {
      description: "apiUrl is an https base URL with no path or credentials",
      labels: ["policy"],
      execute: (context: { globalArgs: ForgejoConnection }) =>
        Promise.resolve(validateConnection(context.globalArgs)),
    },
    "token-is-admin": {
      description: "The token is accepted and belongs to a site administrator",
      labels: ["live"],
      execute: async (context: { globalArgs: ForgejoConnection }) => {
        const g = context.globalArgs;
        if (hasUnresolvedConnection(g)) return { pass: true };
        try {
          const b = await callerBlockers(new ForgejoClient(g));
          return b.length ? { pass: false, errors: b } : { pass: true };
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
    ensureUser: {
      description:
        "Make a limited local account, or set the limits of an existing one: restricted, visibility, repository limit and organization creation. A new account gets a generated password (40 characters, never shown), stored as a sensitive output in the vault ({username}-password) and never in data. " +
        "Dry run by default; a blocker fails the run. Refuses a site administrator, a user with prohibit_login and an inactive user. Never changes a password, email or admin flag of an existing account. " +
        "Needs: a site-administrator token with write:admin and read:user.",
      arguments: EnsureUserArgs,
      execute: (args: EnsureUserArgsT & TestHooks, context: Ctx) =>
        ensureUser(args, context),
    },
    ensureRepo: {
      description:
        "Make a repository for a user (as admin, with a README on main), set it private or not and the Actions unit on or off, and add collaborators with a permission. Never deletes a repository and never removes a collaborator. " +
        "Dry run by default; a blocker fails the run. Refuses an owner that is a site administrator. " +
        "Needs: a site-administrator token with write:admin, write:repository and read:user.",
      arguments: EnsureRepoArgs,
      execute: (args: EnsureRepoArgsT & TestHooks, context: Ctx) =>
        ensureRepo(args, context),
    },
    ensureUserToken: {
      description:
        "Make an access token for an account, with exact scopes and no admin scope. The token is checked with GET /user (it must belong to the account, which must not be an admin) and is deleted again if a check fails or the vault cannot store it. It is a sensitive output, stored in the vault ({username}--{tokenName}-token) and never in data. " +
        "Dry run by default; a blocker fails the run. An existing token of the same name with the same scopes is reported unchanged (Forgejo shows a token only once, so no secret is issued); with other scopes it blocks. Never changes or deletes an existing token. " +
        "Needs: a site-administrator token with write:admin and read:user.",
      arguments: EnsureUserTokenArgs,
      execute: (args: EnsureUserTokenArgsT & TestHooks, context: Ctx) =>
        ensureUserToken(args, context),
    },
  },
};
