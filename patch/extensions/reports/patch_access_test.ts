import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { createReportTestContext } from "jsr:@systeminit/swamp-testing@0.20260604.20";
import { mdCell, report } from "./patch_access.ts";

const MODEL_TYPE = "@dmc/patch/fleet";
const MODEL_ID = "fleet-id";
const DAY_MS = 24 * 60 * 60 * 1000;

interface Seed {
  name: string;
  version?: number;
  tags?: Record<string, string>;
  body: unknown;
  raw?: string;
}

/** Build the fake data repository contents the report reads. */
function artifacts(seeds: Seed[]) {
  return seeds.map((s, i) => ({
    modelType: MODEL_TYPE,
    modelId: MODEL_ID,
    data: {
      name: s.name,
      kind: "resource" as const,
      dataId: `d${i}`,
      version: s.version ?? 1,
      size: 0,
      contentType: "application/json",
      ...(s.tags ? { tags: s.tags } : {}),
    },
    content: new TextEncoder().encode(s.raw ?? JSON.stringify(s.body)),
  }));
}

async function run(
  seeds: Seed[],
  globalArgs?: Record<string, unknown>,
) {
  const { context } = createReportTestContext({
    scope: "model",
    modelType: MODEL_TYPE,
    modelId: MODEL_ID,
    definition: { name: "fleet" },
    ...(globalArgs ? { globalArgs } : {}),
    dataArtifacts: artifacts(seeds),
  });
  return await report.execute(context as never);
}

const machines = (...hosts: string[]) => ({
  machines: hosts.map((host) => ({ host })),
});

/** An ISO time the given number of days in the past. Tests stay valid as the clock moves. */
const ago = (days: number) =>
  new Date(Date.now() - days * DAY_MS).toISOString();

/** An audit of one host, fresh and clean unless `over` says otherwise. */
function audit(host: string, over: Record<string, unknown> = {}): Seed {
  return {
    name: `access-audit-${host}`,
    body: {
      host,
      auditedAt: ago(0),
      ok: true,
      findings: [],
      acceptedRisks: [],
      summary: {
        critical: 0,
        high: 0,
        warning: 0,
        info: 0,
        accepted: 0,
        overdue: 0,
      },
      userProbe: null,
      rootProbe: null,
      userProbeError: null,
      rootProbeError: null,
      ...over,
    },
  };
}

/** An accepted risk that matched one audit finding. */
function accepted(id: string, reviewBy: string, severity = "warning") {
  return {
    id,
    severity,
    message: `accepted ${id}`,
    record: {
      reason: "Needed by the backup agent",
      acceptedBy: "dan",
      acceptedAt: "2026-01-01",
      reviewBy,
    },
  };
}

const OVERDUE = "2020-01-01";
const NOT_OVERDUE = "2999-12-31";

/** The trimmed top line that starts with `prefix`, or undefined. */
function flagLine(markdown: string, prefix: string): string | undefined {
  return markdown.split("\n").map((l) => l.trim()).find((l) =>
    l.startsWith(prefix)
  );
}

Deno.test("access report: metadata names the model-scoped report", () => {
  assertEquals(report.name, "@dmc/patch-access");
  assertEquals(report.scope, "model");
});

Deno.test("access report: a clean fleet says so and shows no findings", async () => {
  const res = await run(
    [audit("web1"), audit("web2")],
    machines("web1", "web2"),
  );
  assertStringIncludes(
    res.markdown,
    "All audited hosts pass with no accepted risks.",
  );
  assertEquals(res.markdown.includes("| Severity |"), false);
  assertEquals(res.json.flags, {
    critical: 0,
    high: 0,
    acceptedRisks: 0,
    overdue: 0,
    notAudited: [],
    staleAudit: [],
  });
});

Deno.test("access report: a critical finding and an overdue accepted risk are flagged", async () => {
  const res = await run(
    [
      audit("web1", {
        ok: false,
        findings: [{
          id: "login-is-root",
          severity: "critical",
          message: "the user probe ran as uid 0",
        }],
        acceptedRisks: [accepted("unsafe:rootSsh", OVERDUE)],
      }),
    ],
    machines("web1"),
  );
  assertEquals(
    flagLine(res.markdown, "CRITICAL:"),
    "CRITICAL: 1 on 1 hosts",
  );
  assertEquals(
    flagLine(res.markdown, "ACCEPTED RISKS:"),
    "ACCEPTED RISKS: 1 on 1 hosts, 1 overdue",
  );
  assertEquals(
    res.markdown.includes("All audited hosts pass"),
    false,
  );
  assertStringIncludes(
    res.markdown,
    "| unsafe:rootSsh | warning | Needed by the backup agent | dan | 2026-01-01 | 2020-01-01 **OVERDUE** |",
  );
  assertEquals(res.json.flags, {
    critical: 1,
    high: 0,
    acceptedRisks: 1,
    overdue: 1,
    notAudited: [],
    staleAudit: [],
  });
});

Deno.test("access report: an accepted risk that is not overdue still gets its flag line", async () => {
  const res = await run(
    [audit("web1", {
      acceptedRisks: [accepted("unsafe:rootSsh", NOT_OVERDUE)],
    })],
    machines("web1"),
  );
  assertEquals(
    flagLine(res.markdown, "ACCEPTED RISKS:"),
    "ACCEPTED RISKS: 1 on 1 hosts",
  );
  assertEquals(res.markdown.includes("OVERDUE"), false);
  assertEquals(res.json.flags.overdue, 0);
  assertEquals(res.json.flags.acceptedRisks, 1);
});

Deno.test("access report: a fleet machine without an audit is NOT AUDITED, an 8-day-old audit is STALE", async () => {
  const res = await run(
    [audit("web1"), audit("old1", { auditedAt: ago(8) })],
    machines("web1", "web2", "old1"),
  );
  assertEquals(flagLine(res.markdown, "NOT AUDITED:"), "NOT AUDITED: web2");
  assertEquals(flagLine(res.markdown, "STALE AUDIT:"), "STALE AUDIT: old1");
  assertEquals(res.json.flags.notAudited, ["web2"]);
  assertEquals(res.json.flags.staleAudit, ["old1"]);
});

Deno.test("access report: without machines in the context, inventory hosts are the fleet", async () => {
  const res = await run([
    audit("web1"),
    { name: "web2", body: { hostname: "web2", scannedAt: ago(0) } },
  ]);
  assertEquals(flagLine(res.markdown, "NOT AUDITED:"), "NOT AUDITED: web2");
  assertEquals(res.json.flags.notAudited, ["web2"]);
});

Deno.test("access report: hosts sort by worst severity, then by name", async () => {
  const res = await run(
    [
      audit("calm"),
      audit("warn", {
        findings: [{ id: "cache-stale", severity: "warning", message: "old" }],
      }),
      audit("crit", {
        ok: false,
        findings: [{
          id: "login-is-root",
          severity: "critical",
          message: "root",
        }],
      }),
      audit("alpha", {
        findings: [{ id: "cache-stale", severity: "warning", message: "old" }],
      }),
    ],
    machines("calm", "warn", "crit", "alpha"),
  );
  assertEquals(
    res.json.hosts.map((h) => h.host),
    ["crit", "alpha", "warn", "calm"],
  );
  const md = res.markdown;
  assertEquals(md.indexOf("## crit") < md.indexOf("## warn"), true);
});

Deno.test("access report: findings table sorts critical, high, warning, info", async () => {
  const res = await run([
    audit("web1", {
      ok: false,
      findings: [
        { id: "z-info", severity: "info", message: "i" },
        { id: "y-warning", severity: "warning", message: "w" },
        { id: "x-critical", severity: "critical", message: "c" },
        { id: "w-high", severity: "high", message: "h" },
      ],
    }),
  ], machines("web1"));
  const md = res.markdown;
  const at = (sev: string) => md.indexOf(`| ${sev} |`);
  assertEquals(at("critical") < at("high"), true);
  assertEquals(at("high") < at("warning"), true);
  assertEquals(at("warning") < at("info"), true);
});

Deno.test("access report: last scan shows the accepted risks used and the scan findings", async () => {
  const res = await run([
    audit("web1"),
    audit("new1"),
    {
      name: "web1",
      body: {
        hostname: "web1",
        acceptedRisksUsed: ["unsafe.pctExec"],
        securityFindings: ["root-login-unaccepted"],
      },
    },
  ], machines("web1", "new1"));
  assertStringIncludes(res.markdown, "### Last scan");
  assertStringIncludes(
    res.markdown,
    "- Accepted risks used: unsafe.pctExec",
  );
  assertStringIncludes(
    res.markdown,
    "- Security findings: root-login-unaccepted",
  );
  assertStringIncludes(res.markdown, "No inventory record.");
  const web1 = res.json.hosts.find((h) => h.host === "web1");
  assertEquals(web1?.lastScan, {
    acceptedRisksUsed: ["unsafe.pctExec"],
    securityFindings: ["root-login-unaccepted"],
  });
  const new1 = res.json.hosts.find((h) => h.host === "new1");
  assertEquals(new1?.lastScan, null);
});

Deno.test("access report: an accessPlan with the same host name does not hide the inventory", async () => {
  const res = await run([
    audit("web1"),
    {
      name: "web1",
      tags: { specName: "inventory" },
      body: {
        hostname: "web1",
        acceptedRisksUsed: [],
        securityFindings: ["root-login-unaccepted"],
      },
    },
    {
      name: "web1",
      version: 2,
      tags: { specName: "accessPlan" },
      body: { host: "web1", keyLine: "ssh-ed25519 AAAA" },
    },
  ], machines("web1"));
  assertEquals(res.json.hosts[0].lastScan, {
    acceptedRisksUsed: [],
    securityFindings: ["root-login-unaccepted"],
  });
});

Deno.test("access report: the latest provision and revoke runs are shown with their time", async () => {
  const provisioned = ago(1);
  const res = await run([
    audit("web1"),
    {
      name: "access-provision-web1-old",
      body: {
        host: "web1",
        action: "provision",
        dryRun: false,
        outcome: "refused-takeover",
        ranAt: ago(5),
      },
    },
    {
      name: "access-provision-web1-new",
      body: {
        host: "web1",
        action: "provision",
        dryRun: false,
        outcome: "applied",
        ranAt: provisioned,
      },
    },
    {
      name: "access-revoke-web1-1",
      body: {
        host: "web1",
        action: "revoke",
        dryRun: true,
        outcome: "dry-run",
        ranAt: ago(2),
      },
    },
  ], machines("web1"));
  assertStringIncludes(res.markdown, "- Last provision: applied at ");
  assertStringIncludes(res.markdown, "- Last revoke: dry-run (dry run) at ");
  assertEquals(res.json.hosts[0].lastProvision, {
    outcome: "applied",
    dryRun: false,
    ranAt: provisioned,
  });
});

Deno.test("access report: probe errors are shown under the host", async () => {
  const res = await run([
    audit("web1", {
      ok: false,
      rootProbeError: "ssh: connect timed out",
      findings: [{
        id: "probe-failed:root",
        severity: "high",
        message: "the root probe did not run",
      }],
    }),
  ], machines("web1"));
  assertStringIncludes(res.markdown, "### Probe errors");
  assertStringIncludes(
    res.markdown,
    "- Root probe: ssh: connect timed out",
  );
  assertEquals(res.markdown.includes("- User probe:"), false);
});

Deno.test("access report: host-supplied text is escaped before it reaches Markdown", async () => {
  const hostile = "x|y\n# heading <script>";
  const sudoers = "swamp-patch ALL=(ALL) `NOPASSWD: ALL` *x* [y]";
  const res = await run([
    audit("web1", {
      ok: false,
      rootProbeError: "root probe `failed` <i>",
      findings: [
        { id: "sudo-grants", severity: "high", message: hostile },
        { id: "sudo-grants-line", severity: "warning", message: sudoers },
      ],
    }),
  ], machines("web1"));
  const md = res.markdown;
  assertEquals(md.includes("<script>"), false);
  assertEquals(md.includes("\n# heading"), false);
  assertStringIncludes(
    md,
    "| high | sudo-grants | x\\|y \\# heading &lt;script&gt; |",
  );
  assertStringIncludes(
    md,
    "| warning | sudo-grants-line | swamp-patch ALL=(ALL) \\`NOPASSWD: ALL\\` \\*x\\* \\[y\\] |",
  );
  assertStringIncludes(
    md,
    "- Root probe: root probe \\`failed\\` &lt;i&gt;",
  );
  // The row of the hostile finding is one row with three cells: its `|` is escaped.
  const row = md.split("\n").find((l) =>
    l.startsWith("| high | sudo-grants |")
  );
  assertEquals(row?.split(/(?<!\\)\|/).length, 5);
});

Deno.test("access report: a host name is escaped in its heading", async () => {
  const res = await run(
    [audit("web_1")],
    machines("web_1"),
  );
  assertStringIncludes(res.markdown, "## web\\_1");
  assertEquals(res.json.hosts[0].host, "web_1");
});

Deno.test("access report: the json output keeps the raw values", async () => {
  const hostile = "x|y\n# heading <script>";
  const res = await run([
    audit("web1", {
      ok: false,
      findings: [
        { id: "sudo-grants", severity: "high", message: hostile },
      ],
      acceptedRisks: [accepted("unsafe:rootSsh", OVERDUE)],
    }),
  ], machines("web1"));
  const host = res.json.hosts[0];
  assertEquals(host.findings[0].message, hostile);
  assertEquals(
    host.acceptedRisks[0].record.reason,
    "Needed by the backup agent",
  );
  assertEquals(host.acceptedRisks[0].record.reviewBy, OVERDUE);
});

// --- mdCell ----------------------------------------------------------------

Deno.test("mdCell: each Markdown and HTML character is escaped", () => {
  assertEquals(mdCell("\\"), "\\\\");
  assertEquals(mdCell("|"), "\\|");
  assertEquals(mdCell("`"), "\\`");
  assertEquals(mdCell("<"), "&lt;");
  assertEquals(mdCell(">"), "&gt;");
  assertEquals(mdCell("*"), "\\*");
  assertEquals(mdCell("_"), "\\_");
  assertEquals(mdCell("["), "\\[");
  assertEquals(mdCell("]"), "\\]");
  assertEquals(mdCell("#"), "\\#");
});

Deno.test("mdCell: escaping is one pass, so a backslash is not escaped twice", () => {
  assertEquals(mdCell("\\|"), "\\\\\\|");
});

Deno.test("mdCell: plain text is unchanged", () => {
  assertEquals(
    mdCell("Valkey 9.0.4 (ok), 10% of a-b.c: done!"),
    "Valkey 9.0.4 (ok), 10% of a-b.c: done!",
  );
});

Deno.test("mdCell: line breaks and tabs become one space per run", () => {
  assertEquals(mdCell("a\r\nb\tc\nd"), "a b c d");
  assertEquals(mdCell("a\n\n\nb"), "a b");
});

Deno.test("mdCell: other control characters are dropped", () => {
  assertEquals(
    mdCell("a\u0000b\u0007c\u001bd\u007fe\u0085f"),
    "abcdef",
  );
});

Deno.test("mdCell: text is cut to 300 characters and marked with an ellipsis", () => {
  assertEquals(mdCell("a".repeat(300)), "a".repeat(300));
  assertEquals(mdCell("a".repeat(301)), "a".repeat(300) + "…");
  // The cut happens before escaping, so no escape sequence is split.
  assertEquals(mdCell("|".repeat(301)), "\\|".repeat(300) + "…");
});

Deno.test("access report: no audits and no fleet says so instead of an all-clear", async () => {
  const res = await run([]);
  assertStringIncludes(res.markdown, "No access audits yet: run auditAccess.");
  assertEquals(res.markdown.includes("All audited hosts pass"), false);
});

Deno.test("access report: warning-only hosts get a WARNING line, not the all-clear", async () => {
  const res = await run(
    [audit("web1", {
      findings: [{ id: "cache-stale", severity: "warning", message: "old" }],
    })],
    machines("web1"),
  );
  assertEquals(flagLine(res.markdown, "WARNING:"), "WARNING: 1 on 1 hosts");
  assertEquals(res.markdown.includes("All audited hosts pass"), false);
});
