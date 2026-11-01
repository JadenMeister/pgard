// Synthetic scan result for the preview screenshots: a made-up demo project, made-up paths and
// redacted evidence. Nothing here comes from a real scan or a real repository.
import { buildRuleTextCatalog, computeStandardsCoverage } from "@pgard/findings";
import { WEB_RULE_LIST } from "@pgard/http-local";
import { listSupportedRules } from "@pgard/scan-core";

const supported = listSupportedRules();
const rules = [
  ...supported,
  ...WEB_RULE_LIST.map((rule) => ({ id: rule.id, scope: "web", metadata: rule.metadata })),
];
export const ruleTexts = buildRuleTextCatalog([...supported, ...WEB_RULE_LIST]);

const file = (path, line) => ({ kind: "file", path, line, url: null, commit: null });
const refs = (cwe, owasp = []) => ({ cwe, owasp, cve: [] });
let counter = 0;
function make(ruleId, severity, status, confidence, location, evidence, references, extra = {}) {
  counter += 1;
  const text = ruleTexts.get(ruleId);
  return {
    id: `demo-${counter}`,
    ruleId,
    title: text?.title.en ?? ruleId,
    category: supported.find((rule) => rule.id === ruleId)?.category ?? "misconfiguration",
    severity,
    status,
    confidence,
    location,
    evidence,
    impact: text?.impact.en ?? "",
    recommendation: text?.recommendation.en ?? "",
    references,
    sources: ["code"],
    ...extra,
  };
}

export function demoResult() {
  counter = 0;
  const findings = [
    make(
      "PG-SQL-001",
      "critical",
      "confirmed",
      "high",
      file("src/routes/orders.ts", 48),
      'db.query("SELECT * FROM orders WHERE id = " + <request value>) (value redacted)',
      refs(["CWE-89"], ["A05:2025"]),
    ),
    make(
      "PG-SECRET-002",
      "critical",
      "confirmed",
      "high",
      file("config/payments.ts", 12),
      'API_KEY = "<redacted, 40 characters>" in a tracked file',
      refs(["CWE-798"], ["A07:2025"]),
    ),
    make(
      "PG-CRYPTO-002",
      "high",
      "suspected",
      "medium",
      file("src/auth/session.ts", 21),
      'jwt.sign(payload, "<redacted, 32 characters>") (value redacted)',
      refs(["CWE-321"], ["A04:2025"]),
    ),
    make(
      "PG-DEP-001",
      "high",
      "confirmed",
      "high",
      file("package-lock.json", null),
      "demo-markdown 1.4.2 is in the affected range of DEMO-ADVISORY-0001",
      refs(["CWE-79"], ["A03:2025"]),
      {
        dependency: {
          ecosystem: "npm",
          name: "demo-markdown",
          version: "1.4.2",
          direct: true,
          advisoryId: "DEMO-ADVISORY-0001",
          aliases: [],
          affectedRange: ">=1.0.0 <1.5.0",
          fixedVersions: ["1.5.0"],
          severitySource: "database",
        },
      },
    ),
    make(
      "PG-SECRET-001",
      "high",
      "confirmed",
      "high",
      {
        kind: "commit",
        path: ".env.production",
        line: null,
        url: null,
        commit: "0a1b2c3d4e5f6071",
      },
      ".env.production was committed (values redacted)",
      refs(["CWE-540"], ["A02:2025"]),
      { sources: ["history"] },
    ),
    make(
      "PG-COOKIE-001",
      "medium",
      "suspected",
      "medium",
      file("src/middleware/session.ts", 17),
      'res.cookie("sid", <value>) without HttpOnly, Secure and SameSite',
      refs(["CWE-614", "CWE-1004"], ["A02:2025"]),
    ),
    make(
      "PG-XSS-002",
      "medium",
      "suspected",
      "medium",
      file("web/components/ProductNote.tsx", 33),
      "dangerouslySetInnerHTML={{ __html: <dynamic value> }}",
      refs(["CWE-79"], ["A05:2025"]),
    ),
    make(
      "PG-CSRF-001",
      "medium",
      "suspected",
      "low",
      file("src/routes/cart.ts", 9),
      "POST /cart/checkout uses a session cookie and no visible CSRF check",
      refs(["CWE-352"], ["A01:2025"]),
    ),
    make(
      "PG-CRYPTO-001",
      "medium",
      "suspected",
      "medium",
      file("src/auth/password.ts", 14),
      'createHash("md5") applied to a password value',
      refs(["CWE-328"], ["A04:2025"]),
    ),
    make(
      "PG-SQL-001",
      "low",
      "suspected",
      "low",
      file("test/fixtures/seed.ts", 5),
      'db.query("DELETE FROM carts WHERE id = " + <value>) (value redacted)',
      refs(["CWE-89"], ["A05:2025"]),
      { context: "test" },
    ),
  ];
  const ranRules = (area, scope) =>
    supported
      .filter((rule) => rule.scope === scope)
      .map((rule, index) => ({
        ruleId: rule.id,
        area,
        scope,
        status: "completed",
        targets: [
          {
            unit: scope === "history" ? "commits" : "files",
            examined: 140 + index * 6,
            reason: null,
          },
        ],
        findings: findings.filter((f) => f.ruleId === rule.id).length,
      }));
  const coverage = [
    { area: "source:typescript", scope: "code", status: "completed", ruleIds: [], note: null },
    { area: "source:javascript", scope: "code", status: "completed", ruleIds: [], note: null },
    {
      area: "history:tracked-files",
      scope: "history",
      status: "completed",
      ruleIds: [],
      note: null,
    },
    { area: "history:commits", scope: "history", status: "completed", ruleIds: [], note: null },
    { area: "web", scope: "web", status: "not_selected", ruleIds: [], note: null },
  ];
  const ruleStats = [
    ...ranRules("source:typescript", "code"),
    ...ranRules("history:commits", "history"),
  ];
  return {
    schemaVersion: "1.7",
    scanBasis: { mode: "authorized", authorization: "verified", reason: null },
    scanId: "demo-scan-0000",
    startedAt: "2026-11-01T09:00:00.000Z",
    finishedAt: "2026-11-01T09:00:07.000Z",
    tool: { name: "pgard", version: "0.2.0" },
    requestedScopes: ["code", "history"],
    overallStatus: "completed",
    target: { repo: "acme/shop-demo", revision: "4b1e9c0a7d21", webOrigin: null },
    authorization: {
      decision: "allowed",
      checks: [
        ["repository", "acme/shop-demo is a GitHub repository (origin remote)."],
        ["github_identity", "Signed in to GitHub as demo-user."],
        ["owner_approval", "The PGARD GitHub App is installed for acme/shop-demo."],
        ["current_access", "demo-user has write access to acme/shop-demo."],
        ["contribution", "demo-user authored a merged pull request (#1)."],
      ].map(([id, reason]) => ({ id, status: "passed", reason })),
    },
    coverage,
    ruleStats,
    standardsCoverage: computeStandardsCoverage({ rules, coverage, ruleStats }),
    advisoryDb: { version: null, updatedAt: null },
    findings,
  };
}
