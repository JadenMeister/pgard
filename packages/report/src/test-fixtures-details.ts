import {
  buildRuleTextCatalog,
  computeStandardsCoverage,
  type RuleMetadata,
  type RuleStat,
  type RuleTextCatalog,
  type ScanResult,
} from "@pgard/findings";
import { finding, scanResult } from "./test-fixtures.js";

/** Hostile example code: must be shown as text, never as markup. */
export const EXAMPLE_VULNERABLE = `pool.query(\`SELECT * FROM t WHERE a = '\${a}'\`); // <img src=x onerror=alert(1)>`;
export const EXAMPLE_SAFE = `pool.query('SELECT * FROM t WHERE a = $1', [a]); // "quoted" & <b>`;

const DETAIL_METADATA: RuleMetadata = {
  standards: {
    owasp: ["A05:2025"],
    cwe: ["CWE-89"],
    cert: [{ kind: "via-cwe", id: "IDS00-J", cwe: "CWE-89" }],
  },
  rationale: { en: "Query structure may change", ko: "쿼리 구조가 바뀔 수 있습니다" },
  remediation: { en: "Use parameters", ko: "매개변수를 사용하세요" },
  examples: [
    {
      language: "javascript",
      vulnerable: EXAMPLE_VULNERABLE,
      safe: EXAMPLE_SAFE,
      note: { en: "A quote in a changes the query.", ko: "a의 따옴표가 쿼리를 바꿉니다." },
    },
  ],
};

/** Catalog with full rule details (standards links and examples) for PG-SQL-001. */
export const DETAIL_RULE_TEXTS: RuleTextCatalog = buildRuleTextCatalog([
  {
    id: "PG-SQL-001",
    title: "User input concatenated into SQL",
    metadata: DETAIL_METADATA,
  },
]);

const SQL_RULE = {
  id: "PG-SQL-001",
  scope: "code",
  metadata: { standards: { owasp: ["A05:2025"], cwe: ["CWE-89"] } },
} as const;
const XSS_RULE = {
  id: "PG-XSS-001",
  scope: "code",
  metadata: { standards: { owasp: ["A05:2025"], cwe: ["CWE-79"] } },
} as const;

/** A 1.1 result with rule statistics and a standards coverage map. */
export function scanResultV11(overrides: Partial<ScanResult> = {}): ScanResult {
  const base = scanResult({ requestedScopes: ["code"] });
  const ruleStats: RuleStat[] = [
    {
      ruleId: "PG-SQL-001",
      area: "source:typescript",
      scope: "code",
      status: "completed",
      targets: [{ unit: "files", examined: 12, reason: null }],
      findings: 1,
    },
    {
      ruleId: "PG-XSS-001",
      area: "source:typescript",
      scope: "code",
      status: "completed",
      targets: [{ unit: "files", examined: null, reason: "history was truncated" }],
      findings: 0,
    },
  ];
  return {
    ...base,
    findings: [finding({})],
    ruleStats,
    standardsCoverage: computeStandardsCoverage({
      rules: [SQL_RULE, XSS_RULE],
      coverage: base.coverage,
      ruleStats,
    }),
    ...overrides,
  };
}
