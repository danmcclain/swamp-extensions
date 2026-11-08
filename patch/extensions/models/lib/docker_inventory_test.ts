/**
 * Unit tests for the docker inventory file parser. Pure: no host, no swamp.
 */
import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { parseDockerFile, validateDockerImages } from "./docker_inventory.ts";

const NOW = new Date("2026-10-29T12:00:00Z");

const DIGEST_A = "sha256:" + "a".repeat(64);
const DIGEST_B = "sha256:" + "b".repeat(64);

const IMAGE = {
  container: "web",
  image: "nginx:1.27",
  localDigest: DIGEST_A,
  registryDigest: DIGEST_B,
  updateAvailable: true,
};

const FILE = {
  schemaVersion: 1,
  generatedAt: "2026-10-29T10:00:00Z",
  dockerEngine: "27.3.1",
  dockerImages: [IMAGE],
};

/** The base64 text the collector ships, from a JS value. */
function b64(value: unknown): string {
  return btoa(JSON.stringify(value));
}

Deno.test("parseDockerFile: a valid file gives the engine, the images and its age", () => {
  const r = parseDockerFile(b64(FILE), NOW);
  assert(r.ok);
  assertEquals(r.dockerEngine, "27.3.1");
  assertEquals(r.dockerImages, [IMAGE]);
  assertEquals(r.ageHours, 2);
});

Deno.test("parseDockerFile: a null engine is accepted", () => {
  const r = parseDockerFile(
    b64({ ...FILE, dockerEngine: null, dockerImages: [] }),
    NOW,
  );
  assert(r.ok);
  assertEquals(r.dockerEngine, null);
  assertEquals(r.dockerImages, []);
});

Deno.test("parseDockerFile: ageHours is whole hours (floor)", () => {
  const r = parseDockerFile(b64(FILE), new Date("2026-10-29T13:30:00Z"));
  assert(r.ok);
  assertEquals(r.ageHours, 3);
});

Deno.test("parseDockerFile: a file up to 30 minutes in the future is accepted, age 0", () => {
  const r = parseDockerFile(
    b64({ ...FILE, generatedAt: "2026-10-29T12:30:00Z" }),
    NOW,
  );
  assert(r.ok);
  assertEquals(r.ageHours, 0);
});

Deno.test("parseDockerFile: a generatedAt 2 hours in the future is rejected", () => {
  const r = parseDockerFile(
    b64({ ...FILE, generatedAt: "2026-10-29T14:00:00Z" }),
    NOW,
  );
  assert(!r.ok);
  assertStringIncludes(r.error, "in the future");
});

Deno.test("parseDockerFile: an empty string is rejected", () => {
  const r = parseDockerFile("", NOW);
  assert(!r.ok);
});

Deno.test("parseDockerFile: text that is not base64 is rejected", () => {
  const r = parseDockerFile("!!!not base64!!!", NOW);
  assert(!r.ok);
  assertStringIncludes(r.error, "base64");
});

Deno.test("parseDockerFile: base64 of bytes that are not UTF-8 is rejected", () => {
  // 0xff can never start a UTF-8 sequence.
  const r = parseDockerFile(btoa("\xff"), NOW);
  assert(!r.ok);
});

Deno.test("parseDockerFile: base64 of text that is not JSON is rejected", () => {
  const r = parseDockerFile(btoa("not json"), NOW);
  assert(!r.ok);
  assertStringIncludes(r.error, "not JSON");
});

Deno.test("parseDockerFile: an extra top-level key is rejected (strict)", () => {
  assert(!parseDockerFile(b64({ ...FILE, extra: 1 }), NOW).ok);
});

Deno.test("parseDockerFile: an extra key on an image is rejected (strict)", () => {
  const r = parseDockerFile(
    b64({ ...FILE, dockerImages: [{ ...IMAGE, extra: 1 }] }),
    NOW,
  );
  assert(!r.ok);
});

Deno.test("parseDockerFile: a schemaVersion other than 1 is rejected", () => {
  assert(!parseDockerFile(b64({ ...FILE, schemaVersion: 2 }), NOW).ok);
});

Deno.test("parseDockerFile: a digest that is not sha256 hex is rejected", () => {
  const r = parseDockerFile(
    b64({ ...FILE, dockerImages: [{ ...IMAGE, localDigest: "sha256:XYZ" }] }),
    NOW,
  );
  assert(!r.ok);
});

Deno.test("parseDockerFile: 500 images are accepted, 501 are rejected", () => {
  const image = (i: number) => ({ ...IMAGE, container: `c${i}` });
  const ok = Array.from({ length: 500 }, (_, i) => image(i));
  assert(parseDockerFile(b64({ ...FILE, dockerImages: ok }), NOW).ok);
  const tooMany = Array.from({ length: 501 }, (_, i) => image(i));
  assert(!parseDockerFile(b64({ ...FILE, dockerImages: tooMany }), NOW).ok);
});

Deno.test("parseDockerFile: more than 1,000,000 base64 chars is rejected before decoding", () => {
  const r = parseDockerFile("A".repeat(1_000_001), NOW);
  assert(!r.ok);
  assertStringIncludes(r.error, "too large");
});

/** One image item with `over` replacing some fields of IMAGE. */
const item = (over: Record<string, unknown>) => [{ ...IMAGE, ...over }];

Deno.test("validateDockerImages: container names with markup, space, newline or a leading - are rejected", () => {
  for (
    const container of ["x|<script>", "a b", "a\nb", "-dash", "a#b", "a<b", ""]
  ) {
    const r = validateDockerImages(item({ container }));
    assert(!r.ok, `should reject container ${JSON.stringify(container)}`);
  }
});

Deno.test("validateDockerImages: image refs with a control char, space or # are rejected", () => {
  for (const image of ["nginx\u0007", "nginx 1.27", "nginx#1", "nginx|x", ""]) {
    const r = validateDockerImages(item({ image }));
    assert(!r.ok, `should reject image ${JSON.stringify(image)}`);
  }
});

Deno.test("validateDockerImages: docker's own names and references are accepted", () => {
  const digest = "sha256:" + "c".repeat(64);
  for (
    const image of [
      `ghcr.io/org/app:1.2.3@${digest}`,
      "library/nginx:latest",
    ]
  ) {
    const r = validateDockerImages(item({ image }));
    assert(r.ok, `should accept image ${image}`);
  }
  const r = validateDockerImages(item({ container: "my_app.v2-1" }));
  assert(r.ok);
});

Deno.test("validateDockerImages: a list over 500 items is rejected", () => {
  const many = Array.from(
    { length: 501 },
    (_, i) => ({ ...IMAGE, container: `c${i}` }),
  );
  assert(!validateDockerImages(many).ok);
});
