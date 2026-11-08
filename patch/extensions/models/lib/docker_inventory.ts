/**
 * The docker inventory file, and its parser.
 *
 * This is the privileged producer, unprivileged reader pattern. A root timer on the
 * host runs docker and writes this file under /var/lib/swamp-patch/. The scan only
 * reads the file (the collector ships it base64 on one line), so the scan login
 * needs no docker access and no sudo. Nothing from the file is stored before
 * parseDockerFile has checked it.
 *
 * @module
 */
import { z } from "npm:zod@4";

/**
 * One container's image drift. The strings reach stored data and Markdown reports, so
 * they take only docker's own name and reference characters: no spaces, control
 * characters or markup.
 */
export const DockerImageItem = z.object({
  container: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$/),
  image: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._\/:@-]{0,511}$/),
  localDigest: z.string().regex(/^(sha256:[0-9a-f]{64})?$/),
  registryDigest: z.string().regex(/^(sha256:[0-9a-f]{64})?$/),
  updateAvailable: z.boolean().nullable(),
}).strict();

export const DockerInventoryFile = z.object({
  schemaVersion: z.literal(1),
  generatedAt: z.string().datetime(),
  dockerEngine: z.string().regex(/^\d+\.\d+\.\d+$/).nullable(),
  dockerImages: z.array(DockerImageItem).max(500),
}).strict();

export type DockerImageT = z.infer<typeof DockerImageItem>;

/** Check the item list of a docker inventory, from either source. */
export function validateDockerImages(
  items: unknown,
): { ok: true; items: DockerImageT[] } | { ok: false; error: string } {
  const parsed = z.array(DockerImageItem).max(500).safeParse(items);
  if (parsed.success) return { ok: true, items: parsed.data };
  const issues = parsed.error.issues.slice(0, 3).map((i) =>
    `${i.path.join(".") || "(images)"}: ${i.message}`
  ).join("; ");
  return { ok: false, error: `the docker images do not match: ${issues}` };
}

const MAX_BASE64_CHARS = 1_000_000;
const MAX_FUTURE_MS = 60 * 60 * 1000;

export type ParsedDockerFile =
  | {
    ok: true;
    dockerEngine: string | null;
    dockerImages: DockerImageT[];
    ageHours: number;
  }
  | { ok: false; error: string };

/**
 * Check the base64 text of the docker inventory file. Returns the engine version and
 * the images with the file's age in whole hours, or the reason it was refused.
 */
export function parseDockerFile(b64: string, now: Date): ParsedDockerFile {
  if (b64.length === 0) {
    return { ok: false, error: "the docker inventory is empty" };
  }
  if (b64.length > MAX_BASE64_CHARS) {
    return { ok: false, error: "the docker inventory is too large" };
  }
  let text: string;
  try {
    const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return { ok: false, error: "the docker inventory is not base64 UTF-8" };
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return { ok: false, error: "the docker inventory is not JSON" };
  }
  const parsed = DockerInventoryFile.safeParse(json);
  if (!parsed.success) {
    const issues = parsed.error.issues.slice(0, 3).map((i) =>
      `${i.path.join(".") || "(file)"}: ${i.message}`
    ).join("; ");
    return {
      ok: false,
      error: `the docker inventory does not match: ${issues}`,
    };
  }
  const generated = Date.parse(parsed.data.generatedAt);
  if (generated - now.getTime() > MAX_FUTURE_MS) {
    return {
      ok: false,
      error: "generatedAt is more than 1 hour in the future",
    };
  }
  return {
    ok: true,
    dockerEngine: parsed.data.dockerEngine,
    dockerImages: parsed.data.dockerImages,
    ageHours: Math.max(0, Math.floor((now.getTime() - generated) / 3600000)),
  };
}
