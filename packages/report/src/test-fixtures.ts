import type { Finding, RuleTextCatalog, ScanResult } from "@pgard/findings";

export const XSS = `<script>alert("x")</script><img src=x onerror=alert(1)>`;

export function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "f1",
    ruleId: "PG-SQL-001",
    title: "User input concatenated into SQL",
    category: "injection",
    severity: "high",
    status: "suspected",
    confidence: "medium",
    location: { kind: "file", path: "src/api/users.ts", line: 42, url: null, commit: null },
    evidence: "req.query -> string concat -> query() (value redacted)",
    impact: "Query structure may change",
    recommendation: "Use parameters",
    references: { cwe: ["CWE-89"], owasp: ["A05:2025"], cve: [] },
    sources: ["code"],
    ...overrides,
  };
}

export function scanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    schemaVersion: "1.1",
    scanId: "3f2b9c1e-aaaa-bbbb-cccc-000000000000",
    startedAt: "2026-10-24T01:02:03.000Z",
    finishedAt: "2026-10-24T01:02:09.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code", "history", "web"],
    overallStatus: "partial",
    target: { repo: "owner/name", revision: "abc123", webOrigin: null },
    authorization: {
      decision: "allowed",
      checks: [{ id: "owner_approval", status: "passed", reason: "Owner approved" }],
    },
    coverage: [
      {
        area: "source:typescript",
        scope: "code",
        status: "completed",
        ruleIds: ["PG-SQL-001"],
        note: null,
      },
      {
        area: "web:anonymous",
        scope: "web",
        status: "not_tested",
        ruleIds: [],
        note: "no confirmed web target",
      },
      {
        area: "web:authenticated",
        scope: "web",
        status: "not_selected",
        ruleIds: [],
        note: "authenticated browsing is not available in this MVP",
      },
    ],
    findings: [
      finding({}),
      finding({
        id: "f2",
        ruleId: "PG-WEB-001",
        title: XSS,
        severity: "low",
        status: "informational",
        location: {
          kind: "url",
          path: null,
          line: null,
          url: "http://127.0.0.1:3000/",
          commit: null,
        },
        evidence: XSS,
        sources: ["web"],
      }),
      finding({ id: "f3", severity: "critical", status: "confirmed", ruleId: "PG-SECRET-001" }),
    ],
    advisoryDb: { version: null, updatedAt: null },
    ...overrides,
  };
}

/** Rule texts for the fixture finding's rule, so report tests can render another language. */
export const FIXTURE_RULE_TEXTS: RuleTextCatalog = new Map([
  [
    "PG-SQL-001",
    {
      title: { en: "User input concatenated into SQL", ko: "SQL에 이어 붙인 사용자 입력" },
      impact: { en: "Query structure may change", ko: "쿼리 구조가 바뀔 수 있습니다" },
      recommendation: { en: "Use parameters", ko: "매개변수를 사용하세요" },
    },
  ],
]);
