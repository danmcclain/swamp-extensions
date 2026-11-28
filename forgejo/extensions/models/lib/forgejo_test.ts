import {
  assertEquals,
  assertFalse,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import {
  ForgejoClient,
  generatePassword,
  redact,
  validateConnection,
} from "./forgejo.ts";

const TOKEN = "c".repeat(40);

Deno.test("validateConnection accepts an https base URL", () => {
  assertEquals(
    validateConnection({ apiUrl: "https://forgejo.test" }).pass,
    true,
  );
  assertEquals(
    validateConnection({ apiUrl: "https://forgejo.test/" }).pass,
    true,
  );
});

Deno.test("validateConnection refuses http, paths, credentials and queries", () => {
  for (
    const apiUrl of [
      "http://forgejo.test",
      "https://forgejo.test/api/v1",
      "https://u:p@forgejo.test",
      "https://forgejo.test?x=1",
      "forgejo.test",
      "",
    ]
  ) {
    assertFalse(validateConnection({ apiUrl }).pass, apiUrl);
  }
});

Deno.test("ForgejoClient refuses a bad connection", () => {
  assertThrows(() => new ForgejoClient({ apiUrl: "http://x", token: TOKEN }));
  assertThrows(() => new ForgejoClient({ apiUrl: "https://x", token: "" }));
});

Deno.test("ForgejoClient sends the token in a header, never in the URL", async () => {
  let seen = "";
  let auth = "";
  let redirect: RequestRedirect | undefined;
  const c = new ForgejoClient(
    { apiUrl: "https://forgejo.test/", token: TOKEN },
    (input, init) => {
      seen = input;
      auth = new Headers(init.headers).get("Authorization") ?? "";
      redirect = init.redirect;
      return Promise.resolve(new Response("{}", { status: 200 }));
    },
  );
  await c.call({ method: "GET", path: "/user" });
  assertEquals(seen, "https://forgejo.test/api/v1/user");
  assertEquals(auth, `token ${TOKEN}`);
  assertEquals(redirect, "manual");
  assertFalse(seen.includes(TOKEN));
});

Deno.test("ForgejoClient refuses a redirect", async () => {
  const c = new ForgejoClient(
    { apiUrl: "https://forgejo.test", token: TOKEN },
    () =>
      Promise.resolve(
        new Response(null, {
          status: 302,
          headers: { Location: "https://evil.test" },
        }),
      ),
  );
  await assertRejects(
    () => c.call({ method: "GET", path: "/user" }),
    Error,
    "redirect refused",
  );
});

Deno.test("ForgejoClient removes the token and extra secrets from errors", async () => {
  const pw = "p".repeat(20);
  const c = new ForgejoClient(
    { apiUrl: "https://forgejo.test", token: TOKEN },
    () =>
      Promise.resolve(
        new Response(JSON.stringify({ message: `bad ${TOKEN} ${pw}` }), {
          status: 422,
        }),
      ),
  );
  const err = await assertRejects(
    () =>
      c.expect({ method: "POST", path: "/admin/users", secrets: [pw] }, [201]),
    Error,
  );
  assertStringIncludes(err.message, "HTTP 422");
  assertFalse(err.message.includes(TOKEN));
  assertFalse(err.message.includes(pw));
});

Deno.test("redact shortens long texts", () => {
  assertEquals(redact("x".repeat(400), []).length, 301);
});

Deno.test("generatePassword gives each character class and is random", () => {
  const a = generatePassword();
  const b = generatePassword();
  assertEquals(a.length, 40);
  assertFalse(a === b);
  for (const p of [a, b]) {
    for (const re of [/[a-z]/, /[A-Z]/, /[0-9]/, /[-_]/]) {
      assertEquals(re.test(p), true, String(re));
    }
    assertEquals(/^[A-Za-z0-9_-]+$/.test(p), true);
  }
});
