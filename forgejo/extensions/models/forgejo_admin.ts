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

// ------------------------------------------------------- repository fan-out

/** Which repositories of the owner a fan-out method works on. */
const RepoSelection = z.union([z.literal("all"), z.array(Slug).min(1)])
  .describe(
    'Repository names of the owner, or "all": every repository the owner owns (archived repositories and mirrors are skipped and reported)',
  );
const Exclude = z.array(z.string().min(1)).default([]).describe(
  'Repository names to leave out (with "all")',
);

const Skipped = z.array(z.object({ repo: z.string(), reason: z.string() }));

const ApiOwnedRepo = z.object({
  name: z.string(),
  archived: z.boolean().optional().default(false),
  mirror: z.boolean().optional().default(false),
  owner: z.object({ login: z.string() }),
});

/** Every repository the user owns (an admin sees private ones too). */
async function listOwnedRepos(c: ForgejoClient, owner: string) {
  const all: z.infer<typeof ApiOwnedRepo>[] = [];
  const limit = 50;
  for (let page = 1; page <= 40; page++) {
    const a = await c.expect({
      method: "GET",
      path: `/users/${seg(owner)}/repos?page=${page}&limit=${limit}`,
    }, [200]);
    const items = z.array(ApiOwnedRepo).parse(a.body ?? []);
    all.push(...items.filter((r) => r.owner.login === owner));
    if (items.length < limit) return all;
  }
  throw new Error(`more than 2000 repositories for ${owner}`);
}

/**
 * Resolve the repositories a fan-out run works on. With "all", archived
 * repositories and mirrors are skipped (Forgejo refuses changes to an
 * archived repository; a mirror takes no pushes), and a name this extension
 * cannot use blocks unless it is excluded: no repository is left out
 * silently. A listed repository must exist and not be archived.
 */
async function selectRepos(
  c: ForgejoClient,
  owner: string,
  repos: "all" | string[],
  exclude: string[],
): Promise<
  { names: string[]; skipped: z.infer<typeof Skipped>; blockers: string[] }
> {
  const names: string[] = [];
  const skipped: z.infer<typeof Skipped> = [];
  const blockers: string[] = [];
  const excluded = new Set(exclude);
  if (repos === "all") {
    for (const r of await listOwnedRepos(c, owner)) {
      if (excluded.has(r.name)) {
        skipped.push({ repo: r.name, reason: "excluded" });
      } else if (r.archived) skipped.push({ repo: r.name, reason: "archived" });
      else if (r.mirror) skipped.push({ repo: r.name, reason: "mirror" });
      else if (!SLUG_RE.test(r.name)) {
        blockers.push(
          `repository ${owner}/${r.name} has a name this extension cannot use; add it to exclude`,
        );
      } else names.push(r.name);
    }
    if (names.length === 0 && blockers.length === 0) {
      blockers.push(`no repository of ${owner} is left to work on`);
    }
  } else {
    if (new Set(repos).size !== repos.length) {
      blockers.push("repos lists a repository twice");
    }
    for (const name of new Set(repos)) {
      if (excluded.has(name)) {
        skipped.push({ repo: name, reason: "excluded" });
        continue;
      }
      const a = await c.call({
        method: "GET",
        path: `/repos/${seg(owner)}/${seg(name)}`,
      });
      if (a.status === 404) {
        blockers.push(`repository ${owner}/${name} does not exist`);
        continue;
      }
      if (a.status !== 200) {
        throw new Error(`GET /repos/${owner}/${name}: HTTP ${a.status}`);
      }
      const r = ApiOwnedRepo.parse(a.body);
      if (r.owner.login !== owner) {
        blockers.push(
          `${owner}/${name} redirects to ${r.owner.login}; give the real owner`,
        );
      } else if (r.archived) {
        blockers.push(`repository ${owner}/${name} is archived`);
      } else names.push(name);
    }
  }
  return { names: names.sort(), skipped, blockers };
}

/** The overall status of a fan-out run from its per-repository states. */
function runStatus(
  blocked: boolean,
  dryRun: boolean,
  changed: boolean,
): z.infer<typeof Status> {
  if (blocked) return "blocked";
  if (!changed) return "unchanged";
  return dryRun ? "planned" : "applied";
}

// -------------------------------------------------------- ensureCollaborator

const EnsureCollaboratorArgs = z.object({
  owner: Username.describe(
    "Owner of the repositories (may be a site administrator)",
  ),
  repos: RepoSelection,
  exclude: Exclude,
  collaborator: Username.describe(
    "The user to add; must not be a site administrator",
  ),
  permission: z.enum(["read", "write", "admin"]),
  dryRun: DryRun,
});
type EnsureCollaboratorArgsT = z.infer<typeof EnsureCollaboratorArgs>;

const CollaboratorRecord = z.object({
  dryRun: z.boolean(),
  status: Status,
  owner: z.string(),
  collaborator: z.string(),
  permission: z.string(),
  repos: z.array(z.object({
    repo: z.string(),
    previousPermission: z.string().nullable().describe(
      "Permission before the run; null when not a collaborator",
    ),
    state: z.enum(["present", "planned", "applied"]),
  })),
  skipped: Skipped,
  blockers: z.array(z.string()),
  checkedAt: z.string(),
});

/** A collaborator's permission on a repository; null when not a collaborator. */
async function collaboratorPermission(
  c: ForgejoClient,
  owner: string,
  repo: string,
  user: string,
): Promise<string | null> {
  const base = `/repos/${seg(owner)}/${seg(repo)}/collaborators/${seg(user)}`;
  const is = await c.call({ method: "GET", path: base });
  if (is.status === 404) return null;
  if (is.status !== 204) {
    throw new Error(`GET ${base}: HTTP ${is.status}`);
  }
  const a = await c.expect({ method: "GET", path: `${base}/permission` }, [
    200,
  ]);
  return z.object({ permission: z.string() }).parse(a.body).permission;
}

async function ensureCollaborator(
  args: EnsureCollaboratorArgsT & TestHooks,
  ctx: Ctx,
): Promise<{ dataHandles: { name: string }[] }> {
  const target = `${args.owner}/${
    args.repos === "all" ? "*" : args.repos.join(",")
  }`;
  log(ctx, "ensureCollaborator {target} {collaborator}: checking ({mode})", {
    target,
    collaborator: args.collaborator,
    mode: args.dryRun ? "dry run" : "live",
  });
  const c = client(ctx, args);
  const blockers = await callerBlockers(c);
  const user = await getUser(c, args.collaborator);
  if (!user) blockers.push(`user ${args.collaborator} does not exist`);
  else blockers.push(...managedUserBlockers(user));
  if (args.collaborator === args.owner) {
    blockers.push(`${args.collaborator} is the owner`);
  }
  const sel = await selectRepos(c, args.owner, args.repos, args.exclude);
  blockers.push(...sel.blockers);

  type Row = z.infer<typeof CollaboratorRecord>["repos"][number];
  const rows: Row[] = [];
  for (const repo of sel.names) {
    const before = user
      ? await collaboratorPermission(c, args.owner, repo, args.collaborator)
      : null;
    rows.push({
      repo,
      previousPermission: before,
      state: before === args.permission ? "present" : "planned",
    });
  }
  const changed = rows.some((r) => r.state === "planned");
  const dataName = `${args.owner}--${args.collaborator}-collaborator`;
  const record = (status: z.infer<typeof Status>) => ({
    dryRun: args.dryRun,
    status,
    owner: args.owner,
    collaborator: args.collaborator,
    permission: args.permission,
    repos: rows,
    skipped: sel.skipped,
    blockers,
    checkedAt: new Date().toISOString(),
  });

  if (blockers.length || args.dryRun || !changed) {
    const status = runStatus(blockers.length > 0, true, changed);
    const h = await ctx.writeResource("collaborator", dataName, record(status));
    if (blockers.length) {
      throw new Error(
        `ensureCollaborator ${dataName} blocked: ${blockers.join("; ")}`,
      );
    }
    log(ctx, "ensureCollaborator {target}: {status} ({n} repositories)", {
      target: dataName,
      status,
      n: rows.length,
    });
    return { dataHandles: [h] };
  }

  for (const row of rows) {
    if (row.state !== "planned") continue;
    await c.expect({
      method: "PUT",
      path: `/repos/${seg(args.owner)}/${seg(row.repo)}/collaborators/${
        seg(args.collaborator)
      }`,
      body: { permission: args.permission },
    }, [204]);
    const after = await collaboratorPermission(
      c,
      args.owner,
      row.repo,
      args.collaborator,
    );
    if (after !== args.permission) {
      throw new Error(
        `${args.collaborator} on ${args.owner}/${row.repo} check failed: permission is ${
          after ?? "none"
        }, not ${args.permission}`,
      );
    }
    row.state = "applied";
  }
  const h = await ctx.writeResource(
    "collaborator",
    dataName,
    record("applied"),
  );
  log(ctx, "ensureCollaborator {target}: applied ({n} repositories)", {
    target: dataName,
    n: rows.length,
  });
  return { dataHandles: [h] };
}

// ------------------------------------------------------------- ensureUserKey

/** Public SSH key types ensureUserKey accepts. */
const SSH_KEY_TYPES = [
  "ssh-ed25519",
  "sk-ssh-ed25519@openssh.com",
  "ecdsa-sha2-nistp256",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521",
  "sk-ecdsa-sha2-nistp256@openssh.com",
] as const;

/** One public key line: type, base64 body, optional comment. One line only. */
const PUBLIC_KEY_RE = /^([a-z0-9@.-]+) ([A-Za-z0-9+/]+={0,3})(?: [^\r\n]*)?$/;

const EnsureUserKeyArgs = z.object({
  username: Username.describe(
    "The account that gets the key; must not be a site administrator",
  ),
  title: Slug.describe("Key title in Forgejo"),
  publicKey: z.string().max(2000).describe(
    "One OpenSSH public key line (ssh-ed25519 or ECDSA; no RSA, never a private key)",
  ),
  dryRun: DryRun,
});
type EnsureUserKeyArgsT = z.infer<typeof EnsureUserKeyArgs>;

const KeyRecord = z.object({
  dryRun: z.boolean(),
  status: Status,
  username: z.string(),
  title: z.string(),
  keyType: z.string(),
  keyId: z.number().nullable(),
  fingerprint: z.string().nullable(),
  verified: z.boolean().describe(
    "Forgejo marks SSH-signed commits verified only for a verified key; a key is verified only in the web UI, by its user",
  ),
  blockers: z.array(z.string()),
  checkedAt: z.string(),
});

const ApiKey = z.object({
  id: z.number(),
  key: z.string(),
  title: z.string().optional().default(""),
  fingerprint: z.string().optional().default(""),
  verified: z.boolean().optional().default(false),
});

/** Parse one public key line; throws with the reason (never echoes the text). */
export function parsePublicKey(text: string): { type: string; body: string } {
  const line = text.trim();
  if (/PRIVATE KEY/.test(line)) {
    throw new Error("publicKey holds a private key; give the public key only");
  }
  const m = line.match(PUBLIC_KEY_RE);
  if (!m) {
    throw new Error(
      "publicKey must be one OpenSSH public key line: <type> <base64> [comment]",
    );
  }
  if (!(SSH_KEY_TYPES as readonly string[]).includes(m[1])) {
    throw new Error(
      `publicKey type ${m[1]} is not accepted; use ${SSH_KEY_TYPES.join(", ")}`,
    );
  }
  return { type: m[1], body: m[2] };
}

async function listKeys(c: ForgejoClient, username: string) {
  const all: z.infer<typeof ApiKey>[] = [];
  const limit = 50;
  for (let page = 1; page <= 20; page++) {
    const a = await c.expect({
      method: "GET",
      path: `/users/${seg(username)}/keys?page=${page}&limit=${limit}`,
    }, [200]);
    const items = z.array(ApiKey).parse(a.body ?? []);
    all.push(...items);
    if (items.length < limit) return all;
  }
  throw new Error(`more than 1000 keys for ${username}`);
}

function sameKey(apiKey: string, body: string): boolean {
  const parts = apiKey.trim().split(/\s+/);
  return parts[1] === body;
}

async function ensureUserKey(
  args: EnsureUserKeyArgsT & TestHooks,
  ctx: Ctx,
): Promise<{ dataHandles: { name: string }[] }> {
  log(ctx, "ensureUserKey {target}: checking ({mode})", {
    target: `${args.username}/${args.title}`,
    mode: args.dryRun ? "dry run" : "live",
  });
  const parsed = parsePublicKey(args.publicKey);
  const c = client(ctx, args);
  const blockers = await callerBlockers(c);
  const user = await getUser(c, args.username);
  if (!user) blockers.push(`user ${args.username} does not exist`);
  else blockers.push(...managedUserBlockers(user));
  const keys = user && !user.is_admin ? await listKeys(c, args.username) : [];
  const existing = keys.find((k) => sameKey(k.key, parsed.body));
  const titled = keys.find((k) => k.title === args.title);
  if (!existing && titled) {
    blockers.push(
      `${args.username} has another key titled ${args.title}; remove it or pick another title`,
    );
  }

  const dataName = `${args.username}--${args.title}-key`;
  const record = (
    status: z.infer<typeof Status>,
    k: z.infer<typeof ApiKey> | undefined,
  ) => ({
    dryRun: args.dryRun,
    status,
    username: args.username,
    title: args.title,
    keyType: parsed.type,
    keyId: k?.id ?? null,
    fingerprint: k?.fingerprint || null,
    verified: k?.verified ?? false,
    blockers,
    checkedAt: new Date().toISOString(),
  });

  if (blockers.length || args.dryRun || existing) {
    const status = blockers.length
      ? "blocked"
      : existing
      ? "unchanged"
      : "planned";
    const h = await ctx.writeResource(
      "key",
      dataName,
      record(status, existing),
    );
    if (blockers.length) {
      throw new Error(
        `ensureUserKey ${dataName} blocked: ${blockers.join("; ")}`,
      );
    }
    log(ctx, "ensureUserKey {target}: {status} (verified {verified})", {
      target: dataName,
      status,
      verified: existing?.verified ?? false,
    });
    return { dataHandles: [h] };
  }

  // Forgejo refuses a key that any user already has (a key is unique on the
  // server), so this cannot take over another account's key.
  await c.expect({
    method: "POST",
    path: `/admin/users/${seg(args.username)}/keys`,
    body: {
      title: args.title,
      key: `${parsed.type} ${parsed.body}`,
      read_only: false,
    },
  }, [201]);
  const after = (await listKeys(c, args.username)).find((k) =>
    sameKey(k.key, parsed.body)
  );
  if (!after) throw new Error(`${dataName} is missing after the create`);
  const h = await ctx.writeResource("key", dataName, record("applied", after));
  log(ctx, "ensureUserKey {target}: applied (verified {verified})", {
    target: dataName,
    verified: after.verified,
  });
  return { dataHandles: [h] };
}

// ---------------------------------------------------- ensureBranchProtection

const EnsureBranchProtectionArgs = z.object({
  owner: Username.describe(
    "Owner of the repositories (may be a site administrator)",
  ),
  repos: RepoSelection,
  exclude: Exclude,
  rule: Slug.describe("Branch name the rule protects, e.g. main (no globs)"),
  directPush: z.enum(["denied", "allowlist", "allowed"]).describe(
    "denied: changes only through merged pull requests; allowlist: only pushAllowlist may push; allowed: any writer may push",
  ),
  pushAllowlist: z.array(Username).default([]).describe(
    "Users who may push directly (directPush allowlist only)",
  ),
  mergeAllowlist: z.array(Username).describe(
    "Users who may merge pull requests; an empty list lets any writer merge",
  ),
  dismissStaleApprovals: z.boolean().optional().describe(
    "Dismiss approvals when new commits are pushed; left as is when not given",
  ),
  dryRun: DryRun,
});
type EnsureBranchProtectionArgsT = z.infer<typeof EnsureBranchProtectionArgs>;

const ProtectionRecord = z.object({
  dryRun: z.boolean(),
  status: Status,
  owner: z.string(),
  rule: z.string(),
  directPush: z.string(),
  pushAllowlist: z.array(z.string()),
  mergeAllowlist: z.array(z.string()),
  dismissStaleApprovals: z.boolean().nullable(),
  repos: z.array(z.object({
    repo: z.string(),
    created: z.boolean().describe("True when the rule did not exist before"),
    changes: z.array(z.string()).describe("Settings that differ (or differed)"),
    statusCheckContexts: z.array(z.string()).describe(
      "Status checks of the rule, read and kept as they are",
    ),
    state: z.enum(["present", "planned", "applied"]),
  })),
  skipped: Skipped,
  blockers: z.array(z.string()),
  checkedAt: z.string(),
});

const ApiProtection = z.object({
  rule_name: z.string(),
  enable_push: z.boolean(),
  enable_push_whitelist: z.boolean(),
  push_whitelist_usernames: z.array(z.string()).nullable().optional(),
  enable_merge_whitelist: z.boolean(),
  merge_whitelist_usernames: z.array(z.string()).nullable().optional(),
  dismiss_stale_approvals: z.boolean().optional().default(false),
  status_check_contexts: z.array(z.string()).nullable().optional(),
});
type ApiProtectionT = z.infer<typeof ApiProtection>;

async function getProtection(
  c: ForgejoClient,
  owner: string,
  repo: string,
  rule: string,
): Promise<ApiProtectionT | null> {
  const path = `/repos/${seg(owner)}/${seg(repo)}/branch_protections/${
    seg(rule)
  }`;
  const a = await c.call({ method: "GET", path });
  if (a.status === 404) return null;
  if (a.status !== 200) throw new Error(`GET ${path}: HTTP ${a.status}`);
  return ApiProtection.parse(a.body);
}

function sameSet(a: string[] | null | undefined, b: string[]): boolean {
  return sameScopes(a ?? [], b);
}

/** The settings that differ between Forgejo's rule and the wanted one. */
function protectionChanges(
  have: ApiProtectionT | null,
  want: EnsureBranchProtectionArgsT,
): string[] {
  if (!have) return ["createRule"];
  const out: string[] = [];
  const push = !have.enable_push
    ? "denied"
    : have.enable_push_whitelist
    ? "allowlist"
    : "allowed";
  if (push !== want.directPush) out.push("directPush");
  if (
    want.directPush === "allowlist" &&
    !sameSet(have.push_whitelist_usernames, want.pushAllowlist)
  ) out.push("pushAllowlist");
  const mergeOn = want.mergeAllowlist.length > 0;
  if (have.enable_merge_whitelist !== mergeOn) out.push("mergeAllowlistOn");
  if (
    mergeOn && !sameSet(have.merge_whitelist_usernames, want.mergeAllowlist)
  ) {
    out.push("mergeAllowlist");
  }
  if (
    want.dismissStaleApprovals !== undefined &&
    have.dismiss_stale_approvals !== want.dismissStaleApprovals
  ) out.push("dismissStaleApprovals");
  return out;
}

/** The Forgejo body for the wanted rule. Forgejo's API names the allowlists
 *  "whitelist"; this extension does not. Status checks are not sent, so
 *  Forgejo keeps them. */
function protectionBody(want: EnsureBranchProtectionArgsT) {
  const mergeOn = want.mergeAllowlist.length > 0;
  const body: Record<string, unknown> = {
    enable_push: want.directPush !== "denied",
    enable_push_whitelist: want.directPush === "allowlist",
    push_whitelist_usernames: want.directPush === "allowlist"
      ? want.pushAllowlist
      : [],
    push_whitelist_deploy_keys: false,
    enable_merge_whitelist: mergeOn,
    merge_whitelist_usernames: want.mergeAllowlist,
  };
  if (want.dismissStaleApprovals !== undefined) {
    body.dismiss_stale_approvals = want.dismissStaleApprovals;
  }
  return body;
}

async function ensureBranchProtection(
  args: EnsureBranchProtectionArgsT & TestHooks,
  ctx: Ctx,
): Promise<{ dataHandles: { name: string }[] }> {
  const target = `${args.owner}/${
    args.repos === "all" ? "*" : args.repos.join(",")
  }:${args.rule}`;
  log(ctx, "ensureBranchProtection {target}: checking ({mode})", {
    target,
    mode: args.dryRun ? "dry run" : "live",
  });
  const c = client(ctx, args);
  const blockers = await callerBlockers(c);
  if (args.directPush === "allowlist" && args.pushAllowlist.length === 0) {
    blockers.push(
      "directPush allowlist needs at least one user in pushAllowlist",
    );
  }
  if (args.directPush !== "allowlist" && args.pushAllowlist.length > 0) {
    blockers.push("pushAllowlist is given, but directPush is not allowlist");
  }
  const sel = await selectRepos(c, args.owner, args.repos, args.exclude);
  blockers.push(...sel.blockers);
  // Forgejo silently drops an allowlist user without write access, so each
  // one must exist and be the owner or a writer, on every repository.
  const listed = [...new Set([...args.pushAllowlist, ...args.mergeAllowlist])]
    .filter((u) => u !== args.owner);
  const known = new Set<string>();
  for (const u of listed) {
    if (await getUser(c, u)) known.add(u);
    else blockers.push(`allowlist user ${u} does not exist`);
  }

  type Row = z.infer<typeof ProtectionRecord>["repos"][number];
  const rows: Row[] = [];
  const before = new Map<string, ApiProtectionT | null>();
  for (const repo of sel.names) {
    for (const u of known) {
      const p = await collaboratorPermission(c, args.owner, repo, u);
      if (p !== "write" && p !== "admin" && p !== "owner") {
        blockers.push(
          `allowlist user ${u} has no write access to ${args.owner}/${repo}`,
        );
      }
    }
    const have = await getProtection(c, args.owner, repo, args.rule);
    before.set(repo, have);
    const changes = protectionChanges(have, args);
    rows.push({
      repo,
      created: false,
      changes,
      statusCheckContexts: have?.status_check_contexts ?? [],
      state: changes.length ? "planned" : "present",
    });
  }
  const changed = rows.some((r) => r.state === "planned");
  const dataName = `${args.owner}--${args.rule}-protection`;
  const record = (status: z.infer<typeof Status>) => ({
    dryRun: args.dryRun,
    status,
    owner: args.owner,
    rule: args.rule,
    directPush: args.directPush,
    pushAllowlist: args.pushAllowlist,
    mergeAllowlist: args.mergeAllowlist,
    dismissStaleApprovals: args.dismissStaleApprovals ?? null,
    repos: rows,
    skipped: sel.skipped,
    blockers,
    checkedAt: new Date().toISOString(),
  });

  if (blockers.length || args.dryRun || !changed) {
    const status = runStatus(blockers.length > 0, true, changed);
    const h = await ctx.writeResource("protection", dataName, record(status));
    if (blockers.length) {
      throw new Error(
        `ensureBranchProtection ${target} blocked: ${blockers.join("; ")}`,
      );
    }
    log(ctx, "ensureBranchProtection {target}: {status} ({n} repositories)", {
      target,
      status,
      n: rows.length,
    });
    return { dataHandles: [h] };
  }

  for (const row of rows) {
    if (row.state !== "planned") continue;
    const have = before.get(row.repo) ?? null;
    const base = `/repos/${seg(args.owner)}/${
      seg(row.repo)
    }/branch_protections`;
    if (!have) {
      await c.expect({
        method: "POST",
        path: base,
        body: { rule_name: args.rule, ...protectionBody(args) },
      }, [201]);
    } else {
      await c.expect({
        method: "PATCH",
        path: `${base}/${seg(args.rule)}`,
        body: protectionBody(args),
      }, [200]);
    }
    const after = await getProtection(c, args.owner, row.repo, args.rule);
    const where = `${args.owner}/${row.repo}:${args.rule}`;
    if (!after) throw new Error(`${where} rule is missing after the write`);
    const left = protectionChanges(after, args);
    if (left.length) {
      throw new Error(
        `${where} check failed: ${
          left.join(", ")
        } still differ (Forgejo drops allowlist users without write access)`,
      );
    }
    if (
      have &&
      !sameSet(after.status_check_contexts, have.status_check_contexts ?? [])
    ) {
      throw new Error(`${where} check failed: the status checks changed`);
    }
    row.created = !have;
    row.statusCheckContexts = after.status_check_contexts ?? [];
    row.state = "applied";
  }
  const h = await ctx.writeResource("protection", dataName, record("applied"));
  log(ctx, "ensureBranchProtection {target}: applied ({n} repositories)", {
    target,
    n: rows.length,
  });
  return { dataHandles: [h] };
}

// --------------------------------------------------------- ensureMergeStyles

/** Merge styles of a Forgejo pull request, as default_merge_style names them. */
const MERGE_STYLES = [
  "merge",
  "rebase",
  "rebase-merge",
  "squash",
  "fast-forward-only",
] as const;
type MergeStyle = typeof MERGE_STYLES[number];

/** The repository field that allows each merge style. */
const MERGE_STYLE_FIELD: Record<MergeStyle, string> = {
  "merge": "allow_merge_commits",
  "rebase": "allow_rebase",
  "rebase-merge": "allow_rebase_explicit",
  "squash": "allow_squash_merge",
  "fast-forward-only": "allow_fast_forward_only_merge",
};

const EnsureMergeStylesArgs = z.object({
  owner: Username.describe(
    "Owner of the repositories (may be a site administrator)",
  ),
  repos: RepoSelection,
  exclude: Exclude,
  styles: z.array(z.enum(MERGE_STYLES)).min(1).describe(
    "The merge styles to allow; every other style is turned off",
  ),
  defaultStyle: z.enum(MERGE_STYLES).describe(
    "The style the merge button offers first; must be in styles",
  ),
  allowRebaseUpdate: z.boolean().optional().describe(
    "Allow updating a pull request branch by rebase; left as is when not given",
  ),
  deleteBranchAfterMerge: z.boolean().optional().describe(
    "Delete the head branch after a merge by default; left as is when not given",
  ),
  dryRun: DryRun,
});
type EnsureMergeStylesArgsT = z.infer<typeof EnsureMergeStylesArgs>;

const MergeStylesRecord = z.object({
  dryRun: z.boolean(),
  status: Status,
  owner: z.string(),
  styles: z.array(z.string()),
  defaultStyle: z.string(),
  allowRebaseUpdate: z.boolean().nullable(),
  deleteBranchAfterMerge: z.boolean().nullable(),
  repos: z.array(z.object({
    repo: z.string(),
    changes: z.array(z.string()).describe("Settings that differ (or differed)"),
    state: z.enum(["present", "planned", "applied"]),
  })),
  skipped: Skipped,
  blockers: z.array(z.string()),
  checkedAt: z.string(),
});

const ApiMergeSettings = z.object({
  has_pull_requests: z.boolean(),
  allow_merge_commits: z.boolean().optional().default(false),
  allow_rebase: z.boolean().optional().default(false),
  allow_rebase_explicit: z.boolean().optional().default(false),
  allow_squash_merge: z.boolean().optional().default(false),
  allow_fast_forward_only_merge: z.boolean().optional().default(false),
  allow_rebase_update: z.boolean().optional().default(false),
  default_delete_branch_after_merge: z.boolean().optional().default(false),
  default_merge_style: z.string().optional().default(""),
});
type ApiMergeSettingsT = z.infer<typeof ApiMergeSettings>;

async function getMergeSettings(
  c: ForgejoClient,
  owner: string,
  repo: string,
): Promise<ApiMergeSettingsT> {
  const a = await c.expect({
    method: "GET",
    path: `/repos/${seg(owner)}/${seg(repo)}`,
  }, [200]);
  return ApiMergeSettings.parse(a.body);
}

/** The repository fields that differ from the wanted merge settings. */
function mergeChanges(
  have: ApiMergeSettingsT,
  want: EnsureMergeStylesArgsT,
): string[] {
  const out: string[] = [];
  const h = have as unknown as Record<string, unknown>;
  for (const style of MERGE_STYLES) {
    const field = MERGE_STYLE_FIELD[style];
    if (h[field] !== want.styles.includes(style)) out.push(field);
  }
  if (have.default_merge_style !== want.defaultStyle) {
    out.push("default_merge_style");
  }
  if (
    want.allowRebaseUpdate !== undefined &&
    have.allow_rebase_update !== want.allowRebaseUpdate
  ) out.push("allow_rebase_update");
  if (
    want.deleteBranchAfterMerge !== undefined &&
    have.default_delete_branch_after_merge !== want.deleteBranchAfterMerge
  ) out.push("default_delete_branch_after_merge");
  return out;
}

/** The PATCH body: every merge style field, the default, and the optional ones. */
function mergeBody(want: EnsureMergeStylesArgsT): Record<string, unknown> {
  const body: Record<string, unknown> = {
    default_merge_style: want.defaultStyle,
  };
  for (const style of MERGE_STYLES) {
    body[MERGE_STYLE_FIELD[style]] = want.styles.includes(style);
  }
  if (want.allowRebaseUpdate !== undefined) {
    body.allow_rebase_update = want.allowRebaseUpdate;
  }
  if (want.deleteBranchAfterMerge !== undefined) {
    body.default_delete_branch_after_merge = want.deleteBranchAfterMerge;
  }
  return body;
}

async function ensureMergeStyles(
  args: EnsureMergeStylesArgsT & TestHooks,
  ctx: Ctx,
): Promise<{ dataHandles: { name: string }[] }> {
  const target = `${args.owner}/${
    args.repos === "all" ? "*" : args.repos.join(",")
  }`;
  log(ctx, "ensureMergeStyles {target}: checking ({mode})", {
    target,
    mode: args.dryRun ? "dry run" : "live",
  });
  const c = client(ctx, args);
  const blockers = await callerBlockers(c);
  if (!args.styles.includes(args.defaultStyle)) {
    blockers.push(`defaultStyle ${args.defaultStyle} is not in styles`);
  }
  if (new Set(args.styles).size !== args.styles.length) {
    blockers.push("styles lists a style twice");
  }
  const sel = await selectRepos(c, args.owner, args.repos, args.exclude);
  blockers.push(...sel.blockers);
  const skipped = [...sel.skipped];

  type Row = z.infer<typeof MergeStylesRecord>["repos"][number];
  const rows: Row[] = [];
  for (const repo of sel.names) {
    const have = await getMergeSettings(c, args.owner, repo);
    if (!have.has_pull_requests) {
      // Merge settings live in the pull request unit; a repository without
      // it has none to set, and turning the unit on is not this method's job.
      skipped.push({ repo, reason: "pull requests off" });
      continue;
    }
    const changes = mergeChanges(have, args);
    rows.push({ repo, changes, state: changes.length ? "planned" : "present" });
  }
  const changed = rows.some((r) => r.state === "planned");
  const dataName = `${args.owner}-merge-styles`;
  const record = (status: z.infer<typeof Status>) => ({
    dryRun: args.dryRun,
    status,
    owner: args.owner,
    styles: [...args.styles],
    defaultStyle: args.defaultStyle,
    allowRebaseUpdate: args.allowRebaseUpdate ?? null,
    deleteBranchAfterMerge: args.deleteBranchAfterMerge ?? null,
    repos: rows,
    skipped,
    blockers,
    checkedAt: new Date().toISOString(),
  });

  if (blockers.length || args.dryRun || !changed) {
    const status = runStatus(blockers.length > 0, true, changed);
    const h = await ctx.writeResource("mergeStyles", dataName, record(status));
    if (blockers.length) {
      throw new Error(
        `ensureMergeStyles ${target} blocked: ${blockers.join("; ")}`,
      );
    }
    log(ctx, "ensureMergeStyles {target}: {status} ({n} repositories)", {
      target,
      status,
      n: rows.length,
    });
    return { dataHandles: [h] };
  }

  for (const row of rows) {
    if (row.state !== "planned") continue;
    await c.expect({
      method: "PATCH",
      path: `/repos/${seg(args.owner)}/${seg(row.repo)}`,
      body: mergeBody(args),
    }, [200]);
    const left = mergeChanges(
      await getMergeSettings(c, args.owner, row.repo),
      args,
    );
    if (left.length) {
      throw new Error(
        `${args.owner}/${row.repo} check failed: ${
          left.join(", ")
        } still differ`,
      );
    }
    row.state = "applied";
  }
  const h = await ctx.writeResource("mergeStyles", dataName, record("applied"));
  log(ctx, "ensureMergeStyles {target}: applied ({n} repositories)", {
    target,
    n: rows.length,
  });
  return { dataHandles: [h] };
}

// --------------------------------------------------------------------- model

/** The `@dmc/forgejo/admin` model. */
export const model = {
  type: "@dmc/forgejo/admin",
  version: "2026.11.28.3",
  globalArguments: ForgejoConnectionArgs,
  upgrades: [
    {
      toVersion: "2026.11.28.1",
      description:
        "Additive: new methods ensureCollaborator (add a non-admin user to an existing repository, also one an admin owns) and ensureUserKey (add an SSH public key to a non-admin account), with the collaborator and key resources. No argument changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.11.28.2",
      description:
        'New method ensureBranchProtection (direct push denied, allowlist or allowed; push and merge allowlists; dismiss stale approvals; status checks kept) with the protection resource. Breaking for ensureCollaborator: it fans out over repos (a list or "all", with exclude) in place of one repo, and its collaborator record holds one row per repository. Global arguments do not change',
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.11.28.3",
      description:
        "Additive: new method ensureMergeStyles (allowed merge styles, default style, rebase update and delete-branch-after-merge on many repositories) with the mergeStyles resource. No argument changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
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
    collaborator: {
      description: "Plan and check of an ensureCollaborator run",
      schema: CollaboratorRecord,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    mergeStyles: {
      description: "Plan, changes and check of an ensureMergeStyles run",
      schema: MergeStylesRecord,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    protection: {
      description: "Plan, changes and check of an ensureBranchProtection run",
      schema: ProtectionRecord,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    key: {
      description: "Plan and check of an ensureUserKey run (no key material)",
      schema: KeyRecord,
      lifetime: "infinite",
      garbageCollection: 20,
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
    ensureCollaborator: {
      description:
        "Add a user as a collaborator with a permission to many repositories of one owner (a list, or all with exclude; archived repositories and mirrors are skipped and reported), or change its permission. The repositories may belong to a site administrator; the collaborator must not be one. Reads every repository first and changes none while any blocker exists. An equal permission is reported present. Never removes a collaborator. One record per run. " +
        "Dry run by default; a blocker fails the run. " +
        "Needs: a site-administrator token with write:repository and read:user.",
      arguments: EnsureCollaboratorArgs,
      execute: (args: EnsureCollaboratorArgsT & TestHooks, context: Ctx) =>
        ensureCollaborator(args, context),
    },
    ensureUserKey: {
      description:
        "Add one SSH public key (ed25519 or ECDSA) to a non-admin account, for git over SSH and SSH commit signing. Refuses a private key, RSA and multi-line text. A key the account already has is reported unchanged; another key with the same title blocks. Data keeps the fingerprint and the verified flag, never the key. " +
        "Forgejo shows SSH-signed commits as verified only for a verified key, and only the account's own user can verify a key, in the web UI (Settings, SSH keys, Verify). " +
        "Dry run by default; a blocker fails the run. Never removes a key. " +
        "Needs: a site-administrator token with write:admin and read:user.",
      arguments: EnsureUserKeyArgs,
      execute: (args: EnsureUserKeyArgsT & TestHooks, context: Ctx) =>
        ensureUserKey(args, context),
    },
    ensureBranchProtection: {
      description:
        "Make or change the protection rule of one branch on many repositories of one owner (a list, or all with exclude; archived repositories and mirrors are skipped and reported): direct push denied (pull requests only), limited to a push allowlist, or allowed; a merge allowlist (an empty list lets any writer merge); and, when given, dismiss stale approvals. " +
        "Status checks and all other settings are kept. Each allowlist user must be the owner or have write access, because Forgejo silently drops other users; each rule is read back and must match. Reads every repository first and changes none while any blocker exists. Repository admins still bypass the rule (apply_to_admins is not changed). Never deletes a rule. One record per run. " +
        "Dry run by default; a blocker fails the run. " +
        "Needs: a token with admin access to the repository (a site administrator's token with write:repository and read:user).",
      arguments: EnsureBranchProtectionArgs,
      execute: (args: EnsureBranchProtectionArgsT & TestHooks, context: Ctx) =>
        ensureBranchProtection(args, context),
    },
    ensureMergeStyles: {
      description:
        "Set the merge styles of many repositories of one owner (a list, or all with exclude; archived repositories, mirrors and repositories with pull requests off are skipped and reported): the allowed styles (every other style is turned off), the default style, and, when given, rebase update and delete-branch-after-merge. Fast-forward only keeps the commits of a pull request as they are, so their signatures stay valid. " +
        "Each repository is read back and must match. Reads every repository first and changes none while any blocker exists. One record per run. " +
        "Dry run by default; a blocker fails the run. " +
        "Needs: a token with admin access to the repositories (a site administrator's token with write:repository and read:user).",
      arguments: EnsureMergeStylesArgs,
      execute: (args: EnsureMergeStylesArgsT & TestHooks, context: Ctx) =>
        ensureMergeStyles(args, context),
    },
  },
};
