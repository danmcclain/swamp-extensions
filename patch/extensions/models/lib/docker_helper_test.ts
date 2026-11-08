/**
 * Tests for the docker helper (docker_helper.ts): the TS validators the runtime and the
 * provisioning use, and the text of the helper script. The helper itself runs as root against
 * a real project list; its behaviour (the refusals, the argv docker receives) is checked in the
 * container harness, not here. Nothing here runs the helper or touches a host.
 */
import {
  assert,
  assertEquals,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import {
  DOCKER_HELPER_PATH,
  DOCKER_PROJECTS_DIR,
  DOCKER_PROJECTS_PATH,
  dockerHelperScript,
  dockerProjectName,
  dockerProjectsFile,
  helperArgv,
  validateDockerProject,
  validateDockerProjects,
} from "./docker_helper.ts";
import { MANAGED_HEADER, PATHS } from "./access_artifacts.ts";

const IMAGE_ID = `sha256:${"0123456789abcdef".repeat(4)}`;

Deno.test("paths: the helper and the project list sit where the provisioning and the audit expect", () => {
  assertEquals(
    DOCKER_HELPER_PATH,
    "/usr/local/libexec/swamp-patch/swamp-patch-docker",
  );
  assertEquals(DOCKER_PROJECTS_DIR, "/etc/swamp-patch");
  assertEquals(DOCKER_PROJECTS_PATH, "/etc/swamp-patch/docker-projects");
  assertEquals(PATHS.dockerHelper, DOCKER_HELPER_PATH);
  assertEquals(PATHS.dockerProjects, DOCKER_PROJECTS_PATH);
  assertEquals(PATHS.projectsDir, DOCKER_PROJECTS_DIR);
});

Deno.test("dockerProjectName: the basename, lowercased, with other characters turned into -", () => {
  assertEquals(dockerProjectName("/srv/app"), "app");
  assertEquals(dockerProjectName("/srv/app/"), "app");
  assertEquals(dockerProjectName("/srv/My_App"), "my_app");
  assertEquals(dockerProjectName("/srv/app.v2"), "app-v2");
  assertEquals(dockerProjectName("/opt/stack-1"), "stack-1");
});

Deno.test("dockerProjectName: refuses a path or a name the helper would refuse", () => {
  for (
    const p of [
      "/",
      "/srv/-x",
      "/srv/_x",
      "relative/app",
      "/srv/../app",
      "/srv//app",
      "/srv/app name",
      "/srv/app;id",
      `/srv/${"a".repeat(64)}`,
      "",
    ]
  ) {
    assertThrows(() => dockerProjectName(p), Error, "composePath", p);
  }
});

Deno.test("validateDockerProject: accepts a project and its service, refuses each bad field", () => {
  assertEquals(
    validateDockerProject({
      name: "app",
      composeDir: "/srv/app",
      service: "web",
    }),
    { name: "app", composeDir: "/srv/app", service: "web" },
  );
  assertEquals(
    validateDockerProject({ name: "app", composeDir: "/srv/app", service: "-" })
      .service,
    "-",
  );
  for (
    const bad of [
      { name: "../x", composeDir: "/srv/x", service: "-" },
      { name: "a;id", composeDir: "/srv/x", service: "-" },
      { name: "-rf", composeDir: "/srv/x", service: "-" },
      { name: "a b", composeDir: "/srv/x", service: "-" },
      { name: "", composeDir: "/srv/x", service: "-" },
      { name: "a".repeat(64), composeDir: "/srv/x", service: "-" },
      { name: "app", composeDir: "/srv/a b", service: "-" },
      { name: "app", composeDir: "/srv/../x", service: "-" },
      { name: "app", composeDir: "srv/x", service: "-" },
      { name: "app", composeDir: "/srv/x", service: "" },
      { name: "app", composeDir: "/srv/x", service: "-rf" },
      { name: "app", composeDir: "/srv/x", service: "web;id" },
    ]
  ) {
    assertThrows(() => validateDockerProject(bad));
  }
});

Deno.test("validateDockerProjects: a name listed twice is refused", () => {
  assertThrows(
    () =>
      validateDockerProjects([
        { name: "app", composeDir: "/srv/app", service: "-" },
        { name: "app", composeDir: "/srv/other", service: "-" },
      ]),
    Error,
    "listed twice",
  );
  assertEquals(validateDockerProjects([]), []);
});

Deno.test("dockerProjectsFile: the managed header, then one tab-separated line per project", () => {
  assertEquals(
    dockerProjectsFile(
      [{ name: "app", composeDir: "/srv/app", service: "web" }],
      MANAGED_HEADER,
    ),
    `${MANAGED_HEADER}\napp\t/srv/app\tweb\n`,
  );
  assertEquals(dockerProjectsFile([], MANAGED_HEADER), `${MANAGED_HEADER}\n`);
});

Deno.test("helperArgv: each subcommand takes its own argument count, and the argv starts at the helper", () => {
  assertEquals(helperArgv("ps", "app"), [DOCKER_HELPER_PATH, "ps", "app"]);
  assertEquals(helperArgv("inspect", "app"), [
    DOCKER_HELPER_PATH,
    "inspect",
    "app",
  ]);
  assertEquals(helperArgv("update", "app"), [
    DOCKER_HELPER_PATH,
    "update",
    "app",
  ]);
  assertEquals(
    helperArgv("restore", "app", "nginx:1", IMAGE_ID),
    [DOCKER_HELPER_PATH, "restore", "app", "nginx:1", IMAGE_ID],
  );
  assertEquals(helperArgv("prune", IMAGE_ID), [
    DOCKER_HELPER_PATH,
    "prune",
    IMAGE_ID,
  ]);
});

Deno.test("helperArgv: an unknown subcommand or a wrong argument count is refused", () => {
  assertThrows(
    () => helperArgv("rm" as never, "app"),
    Error,
    "no swamp-patch-docker subcommand",
  );
  assertThrows(() => helperArgv("ps"), Error, "takes 1 argument");
  assertThrows(
    () => helperArgv("ps", "app", "extra"),
    Error,
    "takes 1 argument",
  );
  assertThrows(
    () => helperArgv("restore", "app", "nginx:1"),
    Error,
    "takes 3 argument",
  );
  assertThrows(() => helperArgv("prune"), Error, "takes 1 argument");
});

Deno.test("helperArgv: every project name, image ref and image id is checked before it is used", () => {
  for (
    const project of ["../x", "a;id", "-rf", "a b", "", "a".repeat(64), "$(id)"]
  ) {
    assertThrows(() => helperArgv("ps", project), Error, "project name");
  }
  for (
    const ref of ["nginx;id", "nginx 1", "-nginx", "", "a".repeat(256), "$(id)"]
  ) {
    assertThrows(
      () => helperArgv("restore", "app", ref, IMAGE_ID),
      Error,
      "image ref",
    );
  }
  for (
    const id of [
      "sha256:abc",
      IMAGE_ID.toUpperCase().replace("SHA256", "sha256"),
      IMAGE_ID.slice(7),
      `sha256:${"g".repeat(64)}`,
      `${IMAGE_ID};id`,
      "",
    ]
  ) {
    assertThrows(() => helperArgv("prune", id), Error, "sha256:");
    assertThrows(
      () => helperArgv("restore", "app", "nginx:1", id),
      Error,
      "sha256:",
    );
  }
});

Deno.test("dockerHelperScript: a shebang, the managed header, and nothing host-specific", () => {
  const s = dockerHelperScript(MANAGED_HEADER);
  assert(s.startsWith("#!/bin/bash\n"));
  assertStringIncludes(s, `\n${MANAGED_HEADER}\n`);
  assertStringIncludes(s, `PROJECTS_FILE='${DOCKER_PROJECTS_PATH}'`);
  assert(s.endsWith('main "$@" </dev/null\n'));
  // Constant for a header: the audit's expected digest is computed from it.
  assertEquals(s, dockerHelperScript(MANAGED_HEADER));
  // No brace expansion anywhere: every expansion is a plain $name, so nothing reaches a shell by surprise.
  assert(!s.includes("${"), "the helper must not use ${...} expansions");
});

Deno.test("dockerHelperScript: the managed header must be one comment line", () => {
  assertThrows(() => dockerHelperScript("not a comment"));
  assertThrows(() => dockerHelperScript("# two\n# lines"));
});

Deno.test("dockerHelperScript: root, a fixed PATH and a cleared docker environment come first", () => {
  const s = dockerHelperScript(MANAGED_HEADER);
  assertStringIncludes(s, "set -euo pipefail\n");
  assertStringIncludes(s, '[ "$(id -u)" -eq 0 ] || die');
  assertStringIncludes(
    s,
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  );
  assertStringIncludes(s, "unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG");
  assertStringIncludes(
    s,
    "COMPOSE_FILE COMPOSE_PROJECT_NAME COMPOSE_PROFILES BASH_ENV ENV",
  );
  assert(
    s.indexOf('"$(id -u)" -eq 0') > s.indexOf("main() {"),
    "the root check is in main, after main() starts",
  );
});

Deno.test("dockerHelperScript: every subcommand validates its arguments before docker sees them", () => {
  const s = dockerHelperScript(MANAGED_HEADER);
  // The list is checked before any subcommand runs, and the project before any compose call.
  const dispatch = s.indexOf('case "$sub" in');
  const checked = s.indexOf("check_list\n", dispatch);
  const loaded = s.indexOf('scan_list "$1"', dispatch);
  assert(dispatch > 0 && checked > dispatch && loaded > checked);
  // Restore validates the ref and the image id, then checks the ref belongs to the project.
  const restore = s.indexOf("restore_image() {");
  const validRef = s.indexOf('valid_ref "$ref"', restore);
  const validId = s.indexOf('valid_image_id "$image"', restore);
  const tag = s.indexOf('docker tag "$image" "$ref"', restore);
  const found = s.indexOf('[ "$found" -eq 1 ]', restore);
  assert(restore > 0 && validRef > restore && validId > validRef);
  assert(found > validId && tag > found, "restore tags only after the checks");
  // Prune validates the image id before docker rmi.
  const prune = s.indexOf('if [ "$sub" = prune ]; then');
  assert(
    s.indexOf('valid_image_id "$1"', prune) <
      s.indexOf('docker rmi "$1"', prune),
  );
});

Deno.test("dockerHelperScript: the project list is read as a whole, and a bad line refuses the call", () => {
  const s = dockerHelperScript(MANAGED_HEADER);
  assertStringIncludes(s, "# Reads the whole project list, checks every line");
  assertStringIncludes(s, "case \"$line\" in\n      '#'*) continue ;;");
  assertStringIncludes(s, 'IFS="$tab" read -r name dir svc <<<"$line"');
  assertStringIncludes(s, 'valid_project "$name" || die');
  assertStringIncludes(s, 'valid_dir "$dir" || die');
  assertStringIncludes(s, 'valid_service "$svc" || die');
  assertStringIncludes(s, '[ "$hits" -eq 1 ] || die');
  // The list is trusted only when root owns it, and it is neither a symlink nor group- or world-writable.
  assertStringIncludes(s, 'trusted_file "$PROJECTS_FILE" || die');
  assertStringIncludes(s, 'trusted_dir "$PROJECTS_DIR" || die');
});

Deno.test("dockerHelperScript: docker is run with fixed argument shapes only", () => {
  const s = dockerHelperScript(MANAGED_HEADER);
  // The compose calls take the project's service as the last word, and nothing else from the caller.
  assertStringIncludes(s, 'docker compose "$@" "$P_SVC"');
  assertStringIncludes(s, "compose ps -q ;;");
  assertStringIncludes(s, "compose pull\n");
  assertStringIncludes(s, "compose up -d\n");
  assertStringIncludes(s, "compose up -d --force-recreate\n");
  assertStringIncludes(s, "docker image inspect --format '{{.Id}}' \"$image\"");
  // No eval, no command substitution of a caller word.
  assert(!/\beval\b/.test(s), "the helper must not eval anything");
});

Deno.test("helperArgv: an image ref of up to 255 characters is accepted, one more is refused", () => {
  const max = "a".repeat(255);
  assertEquals(helperArgv("restore", "app", max, IMAGE_ID)[3], max);
  assertThrows(
    () => helperArgv("restore", "app", `${max}a`, IMAGE_ID),
    Error,
    "image ref",
  );
});
