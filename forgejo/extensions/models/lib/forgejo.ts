/**
 * Shared Forgejo API client for `@dmc/forgejo`: connection arguments, one
 * HTTP call with the token in a header, and the name rules the methods use.
 *
 * The client never follows a redirect (a redirect could send the token to
 * another host), never puts a secret in a URL, and removes the token and any
 * other secret it knows from every error text.
 *
 * API shapes follow the Forgejo v16.0.6 source (tag `v16.0.6`, commit 1aa1394).
 *
 * @module
 */
import { z } from "npm:zod@4";

/** Global arguments of every `@dmc/forgejo` type. */
export const ForgejoConnectionArgs = z.object({
  apiUrl: z.string().describe(
    "Forgejo base URL, e.g. https://forgejo.example.com (https only, no path, no /api/v1, no credentials)",
  ),
  token: z.string().describe(
    "Forgejo access token of a site administrator (needs write:admin, write:repository and read:user). Wire it from a vault.",
  ).meta({ sensitive: true }),
});

/** The connection arguments as the methods see them. */
export type ForgejoConnection = z.infer<typeof ForgejoConnectionArgs>;

/** Forgejo usernames this extension manages: lowercase letters and digits in
 *  groups joined by single hyphens, 2 to 39 characters. No `--`, so a data
 *  name `{owner}--{repo}` splits in one way only. */
export const USERNAME_RE = /^(?=.{2,39}$)[a-z0-9]+(?:-[a-z0-9]+)*$/;

/** Repository and token names: the same rule as usernames, up to 64 characters. */
export const SLUG_RE = /^(?=.{1,64}$)[a-z0-9]+(?:-[a-z0-9]+)*$/;

/** A Forgejo access token as Forgejo shows it once: 40 hex characters. */
export const TOKEN_RE = /^[0-9a-f]{40}$/;

/** Time limit of one API call. */
const CALL_TIMEOUT_MS = 30_000;

/** Longest error body kept in a message. */
const MAX_ERROR_TEXT = 300;

/** Check that apiUrl is an https base URL with no path, query or credentials. */
export function validateConnection(
  g: { apiUrl?: unknown },
): { pass: boolean; errors?: string[] } {
  const errors: string[] = [];
  const raw = typeof g.apiUrl === "string" ? g.apiUrl : "";
  let url: URL | undefined;
  try {
    url = new URL(raw);
  } catch {
    errors.push(
      "apiUrl must be an absolute URL, e.g. https://forgejo.example.com",
    );
  }
  if (url) {
    if (url.protocol !== "https:") errors.push("apiUrl must use https");
    if (url.username || url.password) {
      errors.push("apiUrl must not hold credentials");
    }
    if (url.pathname !== "/" && url.pathname !== "") {
      errors.push("apiUrl must have no path (give the base URL, not /api/v1)");
    }
    if (url.search || url.hash) {
      errors.push("apiUrl must have no query or fragment");
    }
  }
  return errors.length ? { pass: false, errors } : { pass: true };
}

/** True when a global argument still holds an unresolved expression. */
export function hasUnresolvedConnection(g: ForgejoConnection): boolean {
  return [g.apiUrl, g.token].some((v) =>
    typeof v !== "string" || v.includes("${{")
  );
}

/** Remove each secret (8 characters or more) from a text and shorten it. */
export function redact(text: string, secrets: string[]): string {
  let out = text;
  for (const s of secrets) {
    if (s && s.length >= 8) out = out.split(s).join("[REDACTED]");
  }
  if (out.length > MAX_ERROR_TEXT) out = out.slice(0, MAX_ERROR_TEXT) + "…";
  return out;
}

/** One answer of the Forgejo API. */
export interface ApiAnswer {
  status: number;
  body: unknown;
}

/** One call: method, path below /api/v1, optional JSON body. */
export interface ApiCall {
  method: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  path: string;
  body?: unknown;
  /** The token to use; the definition's token when not given. */
  token?: string;
  /** Extra secrets to remove from error texts (a password in the body). */
  secrets?: string[];
}

/** The function that makes the HTTP request; tests replace it. */
export type Fetcher = (
  input: string,
  init: RequestInit,
) => Promise<Response>;

/** A Forgejo API client for one definition. */
export class ForgejoClient {
  readonly #base: string;
  readonly #token: string;
  readonly #fetch: Fetcher;

  /** Make a client; `fetcher` defaults to the global fetch. */
  constructor(g: ForgejoConnection, fetcher?: Fetcher) {
    const check = validateConnection(g);
    if (!check.pass) throw new Error(check.errors!.join("; "));
    if (!g.token) throw new Error("token is empty");
    this.#base = new URL(g.apiUrl).origin;
    this.#token = g.token;
    this.#fetch = fetcher ?? ((i, init) => fetch(i, init));
  }

  /** Make one call. Returns the status and the parsed JSON body (or null). */
  async call(c: ApiCall): Promise<ApiAnswer> {
    const token = c.token ?? this.#token;
    const secrets = [this.#token, token, ...(c.secrets ?? [])];
    const headers: Record<string, string> = {
      "Authorization": `token ${token}`,
      "Accept": "application/json",
    };
    let body: string | undefined;
    if (c.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(c.body);
    }
    let res: Response;
    try {
      res = await this.#fetch(`${this.#base}/api/v1${c.path}`, {
        method: c.method,
        headers,
        body,
        redirect: "manual",
        signal: AbortSignal.timeout(CALL_TIMEOUT_MS),
      });
    } catch (err) {
      throw new Error(
        `${c.method} ${c.path}: ${
          redact(String((err as Error)?.message ?? err), secrets)
        }`,
      );
    }
    const text = await res.text();
    if (res.status >= 300 && res.status < 400) {
      throw new Error(
        `${c.method} ${c.path}: HTTP ${res.status} redirect refused (the token is not sent to another place)`,
      );
    }
    let parsed: unknown = null;
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = text;
      }
    }
    return { status: res.status, body: parsed };
  }

  /** Make one call and fail unless the status is one of `ok`. */
  async expect(c: ApiCall, ok: number[]): Promise<ApiAnswer> {
    const a = await this.call(c);
    if (!ok.includes(a.status)) {
      const secrets = [this.#token, c.token ?? "", ...(c.secrets ?? [])];
      throw new Error(
        `${c.method} ${c.path}: HTTP ${a.status} ${
          redact(
            typeof a.body === "string" ? a.body : JSON.stringify(a.body ?? ""),
            secrets,
          )
        }`,
      );
    }
    return a;
  }
}

/** Encode one path segment. */
export function seg(s: string): string {
  return encodeURIComponent(s);
}

/** The fields of a Forgejo user (`api.User`) that the methods read. */
export const ApiUser = z.object({
  id: z.number(),
  login: z.string(),
  is_admin: z.boolean(),
  restricted: z.boolean().optional().default(false),
  prohibit_login: z.boolean().optional().default(false),
  active: z.boolean().optional().default(true),
  visibility: z.string().optional().default("public"),
});

/** A Forgejo user as parsed by {@link ApiUser}. */
export type ApiUserT = z.infer<typeof ApiUser>;

/** Read a user; null when it does not exist. */
export async function getUser(
  client: ForgejoClient,
  username: string,
  token?: string,
): Promise<ApiUserT | null> {
  const a = await client.call({
    method: "GET",
    path: `/users/${seg(username)}`,
    token,
  });
  if (a.status === 404) return null;
  if (a.status !== 200) {
    throw new Error(`GET /users/${username}: HTTP ${a.status}`);
  }
  return ApiUser.parse(a.body);
}

/** Read the user that owns a token (GET /user). */
export async function getTokenUser(
  client: ForgejoClient,
  token?: string,
): Promise<ApiUserT> {
  const a = await client.expect({ method: "GET", path: "/user", token }, [200]);
  return ApiUser.parse(a.body);
}

/** Characters of a generated password: letters, digits, `-` and `_`. */
const PASSWORD_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * A random password of `length` characters (6 bits each, from the system's
 * cryptographic random source), with at least one lowercase letter, one
 * uppercase letter, one digit and one of `-_`, so it passes every Forgejo
 * PASSWORD_COMPLEXITY setting.
 */
export function generatePassword(length = 40): string {
  for (;;) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    const p = Array.from(bytes, (b) => PASSWORD_ALPHABET[b & 63]).join("");
    if (
      /[a-z]/.test(p) && /[A-Z]/.test(p) && /[0-9]/.test(p) && /[-_]/.test(p)
    ) return p;
  }
}
