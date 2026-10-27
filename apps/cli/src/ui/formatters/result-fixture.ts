import {
  computeStandardsCoverage,
  type Coverage,
  type Finding,
  type RuleStat,
  type ScanResult,
} from "@pgard/findings";
import { listSupportedRules } from "@pgard/scan-core";
import { testFinding, testResult } from "../../test-support.js";

interface Spec {
  ruleId: string;
  title: string;
  severity: Finding["severity"];
  status?: Finding["status"];
  files: string[];
  context?: "test" | "vendored";
  owasp?: string[];
  sources?: Finding["sources"];
}

const SPECS: Spec[] = [
  {
    ruleId: "PG-CMD-001",
    title: "Request input reaches an OS command",
    severity: "critical",
    status: "confirmed",
    files: ["src/jobs/export.ts", "src/jobs/convert.ts", "scripts/deploy.js"],
    owasp: ["A05:2025"],
  },
  {
    ruleId: "PG-SQL-001",
    title: "User input concatenated into SQL",
    severity: "critical",
    status: "confirmed",
    files: ["src/api/users.ts", "src/api/orders.ts"],
    owasp: ["A05:2025"],
  },
  {
    ruleId: "PG-SECRET-003",
    title: "Secret committed in Git history",
    severity: "high",
    status: "confirmed",
    files: ["config/.env", "deploy/keys.json"],
    sources: ["history"],
    owasp: ["A04:2025"],
  },
  {
    ruleId: "PG-XSS-001",
    title: "User input rendered as HTML",
    severity: "high",
    files: ["src/ui/Comment.tsx", "src/ui/Profile.tsx", "src/ui/Search.tsx", "src/ui/Banner.tsx"],
    owasp: ["A05:2025"],
  },
  {
    ruleId: "PG-PATH-001",
    title: "Request input used as a file path",
    severity: "high",
    files: ["src/files/download.ts", "src/files/upload.ts", "src/files/zip.ts"],
    owasp: ["A01:2025"],
  },
  {
    ruleId: "PG-AUTH-002",
    title: "JWT verified without an algorithm allow-list",
    severity: "high",
    files: ["src/auth/token.ts"],
    owasp: ["A07:2025"],
  },
  {
    ruleId: "PG-CORS-001",
    title: "CORS allows any origin with credentials",
    severity: "medium",
    files: ["src/server.ts"],
    owasp: ["A02:2025"],
  },
  {
    ruleId: "PG-COOKIE-001",
    title: "Session cookie without the Secure and HttpOnly flags",
    severity: "medium",
    files: ["src/auth/session.ts", "src/auth/remember.ts"],
    owasp: ["A07:2025"],
  },
  {
    ruleId: "PG-REDIR-001",
    title: "Redirect target taken from the request",
    severity: "medium",
    files: ["src/routes/login.ts", "src/routes/logout.ts", "src/routes/oauth.ts"],
    owasp: ["A01:2025"],
  },
  {
    ruleId: "PG-CRYPTO-002",
    title: "Weak hash used for passwords",
    severity: "medium",
    files: ["src/auth/hash.ts", "src/auth/legacy.ts"],
    owasp: ["A04:2025"],
  },
  {
    ruleId: "PG-LOG-001",
    title: "Credentials written to the log",
    severity: "medium",
    files: ["src/log/request.ts", "src/log/audit.ts", "src/log/debug.ts"],
    owasp: ["A09:2025"],
  },
  {
    ruleId: "PG-HDR-001",
    title: "Security headers missing from the response",
    severity: "medium",
    files: ["src/server.ts"],
    owasp: [],
  },
  {
    ruleId: "PG-RATE-001",
    title: "No rate limit on the login route",
    severity: "low",
    files: ["src/routes/login.ts", "src/routes/reset.ts"],
    owasp: ["A07:2025"],
  },
  {
    ruleId: "PG-DEBUG-001",
    title: "Debug mode enabled outside development",
    severity: "low",
    status: "informational",
    files: ["config/production.js"],
    owasp: ["A02:2025"],
  },
  {
    ruleId: "PG-SSRF-001",
    title: "Outbound request to an address taken from the request",
    severity: "medium",
    files: Array.from({ length: 8 }, (_, i) => `src/clients/fetcher${i}.ts`),
    owasp: ["A01:2025"],
  },
  {
    ruleId: "PG-ERR-001",
    title: "Stack trace returned to the client",
    severity: "low",
    files: Array.from({ length: 6 }, (_, i) => `src/routes/handler${i}.ts`),
    owasp: ["A10:2025"],
  },
  // Test and fixture code.
  {
    ruleId: "PG-SQL-001",
    title: "User input concatenated into SQL",
    severity: "low",
    files: Array.from({ length: 8 }, (_, i) => `test/db/case${i}.test.ts`),
    context: "test",
    owasp: ["A05:2025"],
  },
  {
    ruleId: "PG-SECRET-001",
    title: "Hardcoded credential",
    severity: "high",
    files: ["test/fixtures/aws.json", "test/fixtures/stripe.json"],
    context: "test",
    owasp: ["A04:2025"],
  },
  {
    ruleId: "PG-XSS-001",
    title: "User input rendered as HTML",
    severity: "medium",
    files: Array.from({ length: 4 }, (_, i) => `test/ui/render${i}.test.tsx`),
    context: "test",
    owasp: ["A05:2025"],
  },
  // Vendored code.
  {
    ruleId: "PG-CMD-001",
    title: "Request input reaches an OS command",
    severity: "low",
    files: Array.from({ length: 6 }, (_, i) => `vendor/tool/lib${i}.js`),
    context: "vendored",
    owasp: ["A05:2025"],
  },
  {
    ruleId: "PG-PATH-001",
    title: "Request input used as a file path",
    severity: "info",
    status: "informational",
    files: Array.from({ length: 5 }, (_, i) => `third_party/zip/entry${i}.js`),
    context: "vendored",
    owasp: ["A01:2025"],
  },
];

/** A web finding with a URL too long for any terminal, to pin the "URLs stay whole" rule. */
const LONG_URL =
  "https://shop.example.com/api/v2/customers/export/download/a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071829?format=csv&include=all";

function fromSpecs(): Finding[] {
  let n = 0;
  return SPECS.flatMap((spec) =>
    spec.files.map((path) => {
      n += 1;
      return testFinding({
        id: `f${n}`,
        ruleId: spec.ruleId,
        title: spec.title,
        severity: spec.severity,
        status: spec.status ?? "suspected",
        confidence: spec.context === undefined ? "medium" : "low",
        location:
          spec.sources?.[0] === "history"
            ? { kind: "commit", path, line: null, url: null, commit: "0123456789abcdef0123" }
            : { kind: "file", path, line: 10 + n, url: null, commit: null },
        evidence: `value flows from the request to a sink in ${path}`,
        recommendation: "Validate the value first or pass it as a parameter instead",
        references: { cwe: [], owasp: spec.owasp ?? [], cve: [] },
        sources: spec.sources ?? ["code"],
        ...(spec.context === undefined ? {} : { context: spec.context }),
      });
    }),
  );
}

const COVERAGE: Coverage[] = [
  {
    area: "source:typescript",
    scope: "code",
    status: "completed",
    ruleIds: ["PG-CMD-001", "PG-SQL-001", "PG-XSS-001", "PG-PATH-001"],
    note: null,
  },
  {
    area: "source:javascript",
    scope: "code",
    status: "completed",
    ruleIds: ["PG-CMD-001", "PG-XSS-001"],
    note: null,
  },
  {
    area: "history:secrets",
    scope: "history",
    status: "partial",
    ruleIds: ["PG-SECRET-003"],
    note: "Only the last 500 commits were read because the repository history is very long; older secrets are not checked.",
  },
  {
    area: "web:anonymous",
    scope: "web",
    status: "not_tested",
    ruleIds: [],
    note: "No local web target was confirmed, so no running service was checked (pass --port to include it).",
  },
  { area: "dependencies:lockfile", scope: "code", status: "not_selected", ruleIds: [], note: null },
];

const RULE_STATS: RuleStat[] = [
  {
    ruleId: "PG-CMD-001",
    area: "source:typescript",
    scope: "code",
    status: "completed",
    targets: [{ unit: "files", examined: 412, reason: null }],
    findings: 12,
  },
  {
    ruleId: "PG-SECRET-003",
    area: "history:secrets",
    scope: "history",
    status: "partial",
    targets: [{ unit: "commits", examined: 500, reason: null }],
    findings: 2,
  },
];

/**
 * The shape of a real scan (an owner's repository with 69 findings): mixed severities, findings
 * in test fixtures and vendored code, a partial history area, an untested web area, a long web
 * URL and Korean text in one title.
 */
export function realRepoResult(): ScanResult {
  const findings = fromSpecs();
  findings.push(
    testFinding({
      id: "web1",
      ruleId: "PG-WEB-004",
      title: "Customer export reachable without sign-in (고객 목록 내보내기)",
      severity: "high",
      location: { kind: "url", path: null, line: null, url: LONG_URL, commit: null },
      sources: ["web"],
      references: { cwe: [], owasp: ["A01:2025"], cve: [] },
    }),
  );
  return testResult({
    requestedScopes: ["code", "history", "web"],
    overallStatus: "partial",
    target: {
      repo: "acme-corp/storefront-platform-monorepo",
      revision: "9f3c2a1b7d4e5f60",
      webOrigin: null,
    },
    coverage: COVERAGE,
    ruleStats: RULE_STATS,
    standardsCoverage: computeStandardsCoverage({
      rules: listSupportedRules(),
      coverage: COVERAGE,
      ruleStats: RULE_STATS,
    }),
    findings,
  });
}
