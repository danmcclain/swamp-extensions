import {
  assert,
  assertEquals,
  assertFalse,
  assertMatch,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing@0.20260604.20";
import { model } from "./forgejo_admin.ts";
import type { Fetcher } from "./lib/forgejo.ts";

const ADMIN_TOKEN = "a".repeat(40);
const globalArgs = {
  apiUrl: "https://forgejo.test",
  token: ADMIN_TOKEN,
};

interface FakeUser {
  id: number;
  login: string;
  is_admin: boolean;
  restricted: boolean;
  visibility: string;
  prohibit_login: boolean;
  active: boolean;
  max_repo_creation?: number;
  allow_create_organization?: boolean;
}

interface FakeToken {
  id: number;
  name: string;
  scopes: string[];
  sha1: string;
  owner: string;
}

interface Call {
  method: string;
  path: string;
  auth: string;
  body: unknown;
}

/** An in-memory Forgejo with the routes the methods use. */
class FakeForgejo {
  users = new Map<string, FakeUser>();
  tokens: FakeToken[] = [];
  repos = new Map<
    string,
    { id: number; private: boolean; has_actions: boolean; owner: string }
  >();
  collaborators = new Map<string, Map<string, string>>();
  calls: Call[] = [];
  nextId = 100;
  /** Fault switches for tests. */
  ignoreRestricted = false;
  tokenAnswersAs?: string;
  hasActionsDefault = false;

  constructor() {
    this.addUser("dmc", { is_admin: true });
    this.tokens.push({
      id: 1,
      name: "admin",
      scopes: ["write:admin"],
      sha1: ADMIN_TOKEN,
      owner: "dmc",
    });
  }

  addUser(login: string, extra: Partial<FakeUser> = {}): FakeUser {
    const u: FakeUser = {
      id: this.nextId++,
      login,
      is_admin: false,
      restricted: false,
      visibility: "public",
      prohibit_login: false,
      active: true,
      ...extra,
    };
    this.users.set(login, u);
    return u;
  }

  writes(): Call[] {
    return this.calls.filter((c) => c.method !== "GET");
  }

  fetcher: Fetcher = async (input, init) => {
    const url = new URL(input);
    const method = init.method ?? "GET";
    const auth = new Headers(init.headers).get("Authorization") ?? "";
    const body = init.body ? JSON.parse(String(init.body)) : undefined;
    const path = url.pathname.replace(/^\/api\/v1/, "");
    this.calls.push({ method, path: path + url.search, auth, body });
    await Promise.resolve();
    const json = (status: number, b?: unknown) =>
      new Response(b === undefined ? null : JSON.stringify(b), { status });
    const token = this.tokens.find((t) => `token ${t.sha1}` === auth);
    if (!token) return json(401, { message: "unauthorized" });
    const caller = this.users.get(this.tokenAnswersAs ?? token.owner)!;
    let m: RegExpMatchArray | null;

    if (method === "GET" && path === "/user") return json(200, caller);
    if (method === "GET" && (m = path.match(/^\/users\/([^/]+)$/))) {
      const u = this.users.get(decodeURIComponent(m[1]));
      return u ? json(200, u) : json(404, { message: "not found" });
    }
    if (path.startsWith("/admin/") && !caller.is_admin) {
      return json(403, { message: "not admin" });
    }
    if (method === "POST" && path === "/admin/users") {
      const b = body as Record<string, unknown>;
      const u = this.addUser(String(b.username), {
        restricted: !this.ignoreRestricted && Boolean(b.restricted),
        visibility: String(b.visibility),
      });
      return json(201, u);
    }
    if (method === "PATCH" && (m = path.match(/^\/admin\/users\/([^/]+)$/))) {
      const u = this.users.get(m[1]);
      if (!u) return json(404);
      const b = body as Record<string, unknown>;
      if (!this.ignoreRestricted) u.restricted = Boolean(b.restricted);
      u.visibility = String(b.visibility);
      u.max_repo_creation = Number(b.max_repo_creation);
      u.allow_create_organization = Boolean(b.allow_create_organization);
      return json(200, u);
    }
    if (
      method === "GET" && (m = path.match(/^\/admin\/users\/([^/]+)\/tokens$/))
    ) {
      const page = Number(url.searchParams.get("page") ?? 1);
      const list = this.tokens.filter((t) => t.owner === m![1]).map((t) => ({
        id: t.id,
        name: t.name,
        scopes: t.scopes,
        sha1: "",
      }));
      return json(200, page === 1 ? list : []);
    }
    if (
      method === "POST" && (m = path.match(/^\/admin\/users\/([^/]+)\/tokens$/))
    ) {
      const b = body as { name: string; scopes: string[] };
      const t: FakeToken = {
        id: this.nextId++,
        name: b.name,
        scopes: b.scopes,
        sha1: crypto.randomUUID().replaceAll("-", "").padEnd(40, "0"),
        owner: m[1],
      };
      this.tokens.push(t);
      return json(201, {
        id: t.id,
        name: t.name,
        scopes: t.scopes,
        sha1: t.sha1,
      });
    }
    if (
      method === "DELETE" &&
      (m = path.match(/^\/admin\/users\/([^/]+)\/tokens\/(\d+)$/))
    ) {
      this.tokens = this.tokens.filter((t) => t.id !== Number(m![2]));
      return json(204);
    }
    if (
      method === "POST" && (m = path.match(/^\/admin\/users\/([^/]+)\/repos$/))
    ) {
      const b = body as { name: string; private: boolean };
      const r = {
        id: this.nextId++,
        private: b.private,
        has_actions: this.hasActionsDefault,
        owner: m[1],
      };
      this.repos.set(`${m[1]}/${b.name}`, r);
      return json(201, { ...r, owner: { login: m[1] } });
    }
    if ((m = path.match(/^\/repos\/([^/]+)\/([^/]+)$/))) {
      const r = this.repos.get(`${m[1]}/${m[2]}`);
      if (!r) return json(404);
      if (method === "PATCH") {
        const b = body as { private: boolean; has_actions: boolean };
        r.private = b.private;
        r.has_actions = b.has_actions;
      }
      return json(200, { ...r, owner: { login: r.owner } });
    }
    if (
      (m = path.match(/^\/repos\/([^/]+)\/([^/]+)\/collaborators\/([^/]+)$/))
    ) {
      const key = `${m[1]}/${m[2]}`;
      if (!this.repos.has(key)) return json(404);
      const cols = this.collaborators.get(key) ?? new Map();
      this.collaborators.set(key, cols);
      if (method === "PUT") {
        cols.set(m[3], (body as { permission: string }).permission);
        return json(204);
      }
      return json(cols.has(m[3]) ? 204 : 404);
    }
    return json(404, { message: `no route ${method} ${path}` });
  };
}

type Ctx = Parameters<typeof model.methods.ensureUser.execute>[1];

function setup() {
  const fj = new FakeForgejo();
  const t = createModelTestContext({ globalArgs });
  return { fj, ...t, context: t.context as unknown as Ctx };
}

// ------------------------------------------------------------------ ensureUser

const userArgs = {
  username: "runner-pool-testing",
  email: "runner-pool-testing@example.test",
  fullName: "",
  restricted: true,
  visibility: "private" as const,
  maxRepoCreation: 1,
  allowCreateOrganization: false,
};

Deno.test("ensureUser dry run plans the account and writes nothing", async () => {
  const { fj, context, getWrittenResources } = setup();
  await model.methods.ensureUser.execute(
    { ...userArgs, dryRun: true, _fetch: fj.fetcher },
    context,
  );
  assertEquals(fj.writes(), []);
  const w = getWrittenResources();
  assertEquals(w.length, 1);
  assertEquals(w[0].name, "runner-pool-testing-user");
  assertEquals(w[0].data.status, "planned");
  assertEquals(w[0].data.passwordIssued, false);
});

Deno.test("ensureUser makes the account with a generated password and limits", async () => {
  const { fj, context, getWrittenResources } = setup();
  await model.methods.ensureUser.execute(
    { ...userArgs, dryRun: false, _fetch: fj.fetcher },
    context,
  );
  const post = fj.writes().find((c) => c.path === "/admin/users")!;
  const b = post.body as Record<string, unknown>;
  const password = String(b.password);
  assertEquals(password.length, 40);
  assertMatch(password, /[a-z]/);
  assertMatch(password, /[A-Z]/);
  assertMatch(password, /[0-9]/);
  assertMatch(password, /[-_]/);
  assertEquals(b.must_change_password, false);
  assertEquals(b.send_notify, false);
  const patch = fj.writes().find((c) => c.method === "PATCH")!;
  assertEquals(patch.body, {
    source_id: 0,
    login_name: "runner-pool-testing",
    restricted: true,
    visibility: "private",
    max_repo_creation: 1,
    allow_create_organization: false,
  });
  const u = fj.users.get("runner-pool-testing")!;
  assertEquals(u.max_repo_creation, 1);

  const w = getWrittenResources();
  const rec = w.find((x) => x.specName === "user")!;
  const pw = w.find((x) => x.specName === "password")!;
  assertEquals(rec.data.status, "applied");
  assertEquals(rec.data.created, true);
  assertEquals(rec.data.passwordIssued, true);
  assertEquals(pw.name, "runner-pool-testing-password");
  assertEquals(pw.data.password, password);
  assertFalse(JSON.stringify(rec.data).includes(password));
});

Deno.test("ensureUser password field is marked sensitive", () => {
  const shape = model.resources.password.schema.shape.password;
  assertEquals(
    (shape.meta() as { sensitive?: boolean } | undefined)?.sensitive,
    true,
  );
  const tok = model.resources.token.schema.shape.token;
  assertEquals(
    (tok.meta() as { sensitive?: boolean } | undefined)?.sensitive,
    true,
  );
});

Deno.test("ensureUser on an existing account sets limits only, no password", async () => {
  const { fj, context, getWrittenResources } = setup();
  fj.addUser("runner-pool-testing");
  await model.methods.ensureUser.execute(
    { ...userArgs, dryRun: false, _fetch: fj.fetcher },
    context,
  );
  assertEquals(fj.writes().map((c) => c.method), ["PATCH"]);
  const w = getWrittenResources();
  assertEquals(w.map((x) => x.specName), ["user"]);
  assertEquals(w[0].data.created, false);
  assertEquals(fj.users.get("runner-pool-testing")!.restricted, true);
});

Deno.test("ensureUser refuses a site administrator and writes nothing", async () => {
  const { fj, context, getWrittenResources } = setup();
  fj.addUser("runner-pool-testing", { is_admin: true });
  await assertRejects(
    () =>
      model.methods.ensureUser.execute(
        { ...userArgs, dryRun: false, _fetch: fj.fetcher },
        context,
      ),
    Error,
    "blocked",
  );
  assertEquals(fj.writes(), []);
  const rec = getWrittenResources()[0].data;
  assertEquals(rec.status, "blocked");
  assertStringIncludes(String(rec.blockers), "site administrator");
});

Deno.test("ensureUser refuses prohibit_login (tokens would not work)", async () => {
  const { fj, context, getWrittenResources } = setup();
  fj.addUser("runner-pool-testing", { prohibit_login: true });
  await assertRejects(
    () =>
      model.methods.ensureUser.execute(
        { ...userArgs, dryRun: false, _fetch: fj.fetcher },
        context,
      ),
    Error,
    "blocked",
  );
  assertEquals(fj.writes(), []);
  assertStringIncludes(
    String(getWrittenResources()[0].data.blockers),
    "prohibit_login",
  );
});

Deno.test("ensureUser blocks when the token is not a site administrator", async () => {
  const { fj, context, getWrittenResources } = setup();
  fj.users.get("dmc")!.is_admin = false;
  await assertRejects(
    () =>
      model.methods.ensureUser.execute(
        { ...userArgs, dryRun: false, _fetch: fj.fetcher },
        context,
      ),
    Error,
    "blocked",
  );
  assertEquals(fj.writes(), []);
  assertStringIncludes(
    String(getWrittenResources()[0].data.blockers),
    "not a site administrator",
  );
});

Deno.test("ensureUser fails when the check after the run differs, password kept", async () => {
  const { fj, context, getWrittenResources } = setup();
  fj.ignoreRestricted = true;
  await assertRejects(
    () =>
      model.methods.ensureUser.execute(
        { ...userArgs, dryRun: false, _fetch: fj.fetcher },
        context,
      ),
    Error,
    "restricted is false",
  );
  // The password of the new account is stored before the check.
  assertEquals(getWrittenResources().map((x) => x.specName), ["password"]);
});

Deno.test("ensureUser schema refuses bad usernames", () => {
  const s = model.methods.ensureUser.arguments;
  for (const username of ["Dmc", "a--b", "-a", "a", "a_b", "a/b"]) {
    assertFalse(
      s.safeParse({ ...userArgs, username }).success,
      `${username} should be refused`,
    );
  }
  assert(s.safeParse(userArgs).data?.dryRun, "dry run is the default");
});

// ------------------------------------------------------------------ ensureRepo

const repoArgs = {
  owner: "runner-pool-testing",
  repo: "pool-check",
  private: true,
  actions: true,
  collaborators: [{ username: "dmc", permission: "write" as const }],
};

Deno.test("ensureRepo makes the repo as admin, turns Actions on, adds a collaborator", async () => {
  const { fj, context, getWrittenResources } = setup();
  fj.addUser("runner-pool-testing");
  await model.methods.ensureRepo.execute(
    { ...repoArgs, dryRun: false, _fetch: fj.fetcher },
    context,
  );
  assertEquals(
    fj.writes().map((c) => `${c.method} ${c.path}`),
    [
      "POST /admin/users/runner-pool-testing/repos",
      "PATCH /repos/runner-pool-testing/pool-check",
      "PUT /repos/runner-pool-testing/pool-check/collaborators/dmc",
    ],
  );
  const r = fj.repos.get("runner-pool-testing/pool-check")!;
  assertEquals(r.private, true);
  assertEquals(r.has_actions, true);
  assertEquals(
    fj.collaborators.get("runner-pool-testing/pool-check")!.get("dmc"),
    "write",
  );
  const w = getWrittenResources()[0];
  assertEquals(w.name, "runner-pool-testing--pool-check-repo");
  assertEquals(w.data.status, "applied");
});

Deno.test("ensureRepo skips the PATCH when private and Actions already match", async () => {
  const { fj, context } = setup();
  fj.addUser("runner-pool-testing");
  fj.hasActionsDefault = true;
  await model.methods.ensureRepo.execute(
    { ...repoArgs, collaborators: [], dryRun: false, _fetch: fj.fetcher },
    context,
  );
  assertEquals(fj.writes().map((c) => c.method), ["POST"]);
});

Deno.test("ensureRepo blocks on a missing owner or collaborator", async () => {
  const { fj, context, getWrittenResources } = setup();
  await assertRejects(
    () =>
      model.methods.ensureRepo.execute(
        {
          ...repoArgs,
          collaborators: [{ username: "nobody", permission: "read" }],
          dryRun: false,
          _fetch: fj.fetcher,
        },
        context,
      ),
    Error,
    "blocked",
  );
  assertEquals(fj.writes(), []);
  const b = String(getWrittenResources()[0].data.blockers);
  assertStringIncludes(b, "user runner-pool-testing does not exist");
  assertStringIncludes(b, "collaborator nobody does not exist");
});

Deno.test("ensureRepo refuses an admin owner", async () => {
  const { fj, context, getWrittenResources } = setup();
  await assertRejects(
    () =>
      model.methods.ensureRepo.execute(
        {
          ...repoArgs,
          owner: "dmc",
          collaborators: [],
          dryRun: false,
          _fetch: fj.fetcher,
        },
        context,
      ),
    Error,
    "blocked",
  );
  assertEquals(fj.writes(), []);
  assertEquals(getWrittenResources()[0].data.status, "blocked");
});

// ------------------------------------------------------------- ensureUserToken

const tokenArgs = {
  username: "runner-pool-testing",
  tokenName: "runner-registration",
  scopes: ["write:user" as const],
};

Deno.test("ensureUserToken makes, checks and stores the token", async () => {
  const { fj, context, getWrittenResources } = setup();
  fj.addUser("runner-pool-testing");
  await model.methods.ensureUserToken.execute(
    { ...tokenArgs, dryRun: false, _fetch: fj.fetcher },
    context,
  );
  const made = fj.tokens.find((t) => t.owner === "runner-pool-testing")!;
  assertEquals(made.scopes, ["write:user"]);
  // The new token was used once, for GET /user.
  const used = fj.calls.filter((c) => c.auth === `token ${made.sha1}`);
  assertEquals(used.map((c) => `${c.method} ${c.path}`), ["GET /user"]);

  const w = getWrittenResources();
  const tok = w.find((x) => x.specName === "token")!;
  const rec = w.find((x) => x.specName === "tokenAccess")!;
  assertEquals(tok.name, "runner-pool-testing--runner-registration-token");
  assertEquals(tok.data.token, made.sha1);
  assertEquals(rec.data.status, "applied");
  assertEquals(rec.data.verifiedLogin, "runner-pool-testing");
  assertEquals(rec.data.tokenId, made.id);
  assertFalse(JSON.stringify(rec.data).includes(made.sha1));
});

Deno.test("ensureUserToken reports an existing token with the same scopes unchanged", async () => {
  const { fj, context, getWrittenResources } = setup();
  fj.addUser("runner-pool-testing");
  fj.tokens.push({
    id: 7,
    name: "runner-registration",
    scopes: ["write:user"],
    sha1: "b".repeat(40),
    owner: "runner-pool-testing",
  });
  await model.methods.ensureUserToken.execute(
    { ...tokenArgs, dryRun: false, _fetch: fj.fetcher },
    context,
  );
  assertEquals(fj.writes(), []);
  const w = getWrittenResources();
  assertEquals(w.length, 1);
  assertEquals(w[0].data.status, "unchanged");
  assertEquals(w[0].data.tokenIssued, false);
});

Deno.test("ensureUserToken blocks on an existing token with other scopes", async () => {
  const { fj, context, getWrittenResources } = setup();
  fj.addUser("runner-pool-testing");
  fj.tokens.push({
    id: 7,
    name: "runner-registration",
    scopes: ["write:repository"],
    sha1: "b".repeat(40),
    owner: "runner-pool-testing",
  });
  await assertRejects(
    () =>
      model.methods.ensureUserToken.execute(
        { ...tokenArgs, dryRun: false, _fetch: fj.fetcher },
        context,
      ),
    Error,
    "blocked",
  );
  assertEquals(fj.writes(), []);
  assertEquals(getWrittenResources()[0].data.status, "blocked");
});

Deno.test("ensureUserToken deletes the new token when its check fails", async () => {
  const { fj, context, getWrittenResources } = setup();
  fj.addUser("runner-pool-testing");
  fj.addUser("someone-else");
  // GET /user answers as another user for every token (a broken server).
  const orig = fj.fetcher;
  fj.fetcher = async (input, init) => {
    const auth = new Headers(init.headers).get("Authorization");
    if (
      new URL(input).pathname === "/api/v1/user" &&
      auth !== `token ${ADMIN_TOKEN}`
    ) {
      fj.tokenAnswersAs = "someone-else";
      try {
        return await orig(input, init);
      } finally {
        fj.tokenAnswersAs = undefined;
      }
    }
    return orig(input, init);
  };
  await assertRejects(
    () =>
      model.methods.ensureUserToken.execute(
        { ...tokenArgs, dryRun: false, _fetch: fj.fetcher },
        context,
      ),
    Error,
    "it was deleted",
  );
  assertEquals(fj.tokens.filter((t) => t.owner === "runner-pool-testing"), []);
  assertEquals(getWrittenResources(), []);
});

Deno.test("ensureUserToken refuses an admin user", async () => {
  const { fj, context, getWrittenResources } = setup();
  await assertRejects(
    () =>
      model.methods.ensureUserToken.execute(
        { ...tokenArgs, username: "dmc", dryRun: false, _fetch: fj.fetcher },
        context,
      ),
    Error,
    "blocked",
  );
  assertEquals(fj.writes(), []);
  assertEquals(getWrittenResources()[0].data.status, "blocked");
});

Deno.test("ensureUserToken schema refuses admin and all scopes", () => {
  const s = model.methods.ensureUserToken.arguments;
  for (const scope of ["write:admin", "read:admin", "all", "public-only"]) {
    assertFalse(
      s.safeParse({ ...tokenArgs, scopes: [scope] }).success,
      `${scope} should be refused`,
    );
  }
  assertFalse(s.safeParse({ ...tokenArgs, scopes: [] }).success);
});

Deno.test("ensureUser stores the password before the create, so a failed create loses nothing", async () => {
  const { fj, context, getWrittenResources } = setup();
  const orig = fj.fetcher;
  fj.fetcher = (input, init) =>
    init.method === "POST"
      ? Promise.resolve(new Response('{"message":"boom"}', { status: 500 }))
      : orig(input, init);
  await assertRejects(
    () =>
      model.methods.ensureUser.execute(
        { ...userArgs, dryRun: false, _fetch: fj.fetcher },
        context,
      ),
    Error,
    "HTTP 500",
  );
  assertEquals(getWrittenResources().map((x) => x.specName), ["password"]);
  assertFalse(fj.users.has("runner-pool-testing"));
});

Deno.test("ensureUserToken deletes the new token when the vault write fails", async () => {
  const { fj, context } = setup();
  fj.addUser("runner-pool-testing");
  const ctx = {
    ...context,
    writeResource: (spec: string, name: string, data: unknown) =>
      spec === "token"
        ? Promise.reject(new Error("vault unavailable"))
        : context.writeResource(spec, name, data),
  };
  await assertRejects(
    () =>
      model.methods.ensureUserToken.execute(
        { ...tokenArgs, dryRun: false, _fetch: fj.fetcher },
        ctx,
      ),
    Error,
    "could not store the new token (vault unavailable); it was deleted",
  );
  assertEquals(fj.tokens.filter((t) => t.owner === "runner-pool-testing"), []);
});

Deno.test("ensureUserToken says so when the delete of a bad token fails", async () => {
  const { fj, context } = setup();
  fj.addUser("runner-pool-testing");
  const orig = fj.fetcher;
  fj.fetcher = async (input, init) => {
    if (init.method === "DELETE") return new Response(null, { status: 500 });
    const r = await orig(input, init);
    if (init.method === "POST" && new URL(input).pathname.endsWith("/tokens")) {
      const b = await r.json();
      return new Response(JSON.stringify({ ...b, sha1: "short" }), {
        status: 201,
      });
    }
    return r;
  };
  await assertRejects(
    () =>
      model.methods.ensureUserToken.execute(
        { ...tokenArgs, dryRun: false, _fetch: fj.fetcher },
        context,
      ),
    Error,
    "its delete failed (HTTP 500)",
  );
});

Deno.test("ensureUserToken dry run plans and writes nothing", async () => {
  const { fj, context, getWrittenResources } = setup();
  fj.addUser("runner-pool-testing");
  await model.methods.ensureUserToken.execute(
    { ...tokenArgs, dryRun: true, _fetch: fj.fetcher },
    context,
  );
  assertEquals(fj.writes(), []);
  assertEquals(getWrittenResources()[0].data.status, "planned");
});
