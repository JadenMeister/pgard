import { describe, expect, it } from "vitest";
import { SCHEMA_VERSION, type Finding, type ScanResult } from "./contract.js";
import { findingIdentity } from "./compare-scans.js";
import {
  SARIF_FINGERPRINT_KEY,
  SARIF_LEVEL_BY_SEVERITY,
  SARIF_SCHEMA_URL,
  SARIF_SECURITY_SEVERITY,
  buildSarif,
} from "./sarif.js";
import { buildRuleTextCatalog } from "./rule-text.js";

const GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";

const CATALOG = buildRuleTextCatalog([
  {
    id: "PG-SQL-001",
    title: "SQL built from a dynamic string",
    metadata: {
      standards: { owasp: ["A05:2025"], cwe: ["CWE-89"], cert: [] },
      rationale: { en: "Input can change the query.", ko: "입력이 쿼리를 바꿀 수 있습니다." },
      remediation: { en: "Use parameters.", ko: "매개변수를 사용하세요." },
    },
  },
  {
    id: "PG-WEB-001",
    title: "Content-Security-Policy header missing",
    metadata: {
      standards: { owasp: ["A02:2025"], cwe: ["CWE-693"], cert: [] },
      rationale: { en: "No CSP.", ko: "CSP 없음." },
      remediation: { en: "Send a CSP header.", ko: "CSP 헤더를 보내세요." },
    },
  },
]);

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    ruleId: "PG-SQL-001",
    title: "SQL built from a dynamic string",
    category: "injection",
    severity: "high",
    status: "suspected",
    confidence: "medium",
    location: { kind: "file", path: "src/api/users.ts", line: 42, url: null, commit: null },
    evidence: "req.query -> concat -> query()",
    impact: "Query structure may change",
    recommendation: "Use parameters",
    references: { cwe: ["CWE-89"], owasp: [], cve: [] },
    sources: ["code"],
    ...overrides,
  };
}

function result(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    schemaVersion: SCHEMA_VERSION,
    scanId: "scan-1",
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:05.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "completed",
    target: { repo: "owner/name", revision: "abc123", webOrigin: null },
    authorization: { decision: "allowed", checks: [] },
    coverage: [
      {
        area: "source:typescript",
        scope: "code",
        status: "completed",
        ruleIds: ["PG-SQL-001"],
        note: null,
      },
    ],
    findings: [finding()],
    advisoryDb: { version: null, updatedAt: null },
    ...overrides,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Obj = Record<string, any>;

/**
 * Structural check of the parts of the SARIF 2.1.0 schema that PGARD emits: required members,
 * types, enums and the cross references (`ruleIndex`). The official schema was also run against
 * real output when this was written; it is not vendored (its repository has no licence file).
 */
function expectValidSarif(log: Obj): void {
  expect(log.$schema).toMatch(/sarif-schema-2\.1\.0\.json$/);
  expect(log.version).toBe("2.1.0");
  expect(log.runs).toHaveLength(1);
  const run = log.runs[0] as Obj;
  const driver = run.tool.driver as Obj;
  expect(driver.name).toBe("pgard");
  expect(typeof driver.version).toBe("string");
  expect(driver.informationUri).toBe("https://github.com/JadenMeister/pgard");
  const ids = new Set<string>();
  for (const rule of driver.rules as Obj[]) {
    expect(typeof rule.id).toBe("string");
    expect(ids.has(rule.id)).toBe(false);
    ids.add(rule.id);
    expect(rule.shortDescription.text.length).toBeGreaterThan(0);
    expect(rule.fullDescription.text.length).toBeGreaterThan(0);
    expect(rule.help.text.length).toBeGreaterThan(0);
    expect(rule.properties.tags).toContain("security");
    if (rule.helpUri !== undefined) expect(rule.helpUri).toMatch(/^https:\/\//);
    if (rule.properties["security-severity"] !== undefined) {
      expect(rule.properties["security-severity"]).toMatch(/^\d+\.\d$/);
    }
  }
  for (const r of run.results as Obj[]) {
    expect(["error", "warning", "note"]).toContain(r.level);
    expect(typeof r.message.text).toBe("string");
    expect(driver.rules[r.ruleIndex].id).toBe(r.ruleId);
    for (const location of r.locations as Obj[]) {
      const physical = location.physicalLocation as Obj | undefined;
      if (physical !== undefined) {
        expect(physical.artifactLocation.uri).not.toMatch(/^[a-z]+:|^\/|\\/);
        expect(physical.artifactLocation.uriBaseId).toBe("%SRCROOT%");
        if (physical.region !== undefined) {
          expect(physical.region.startLine).toBeGreaterThanOrEqual(1);
          expect(physical.region.endLine).toBeGreaterThanOrEqual(physical.region.startLine);
        }
      }
    }
    for (const s of (r.suppressions ?? []) as Obj[]) {
      expect(["inSource", "external"]).toContain(s.kind);
    }
    if (r.baselineState !== undefined) {
      expect(["new", "unchanged", "updated", "absent"]).toContain(r.baselineState);
    }
  }
  const invocation = run.invocations[0] as Obj;
  expect(typeof invocation.executionSuccessful).toBe("boolean");
  for (const n of invocation.toolExecutionNotifications as Obj[]) {
    expect(["none", "note", "warning", "error"]).toContain(n.level);
    expect(typeof n.message.text).toBe("string");
  }
}

describe("buildSarif", () => {
  it("emits a valid SARIF 2.1.0 log with rules, results and the line-insensitive fingerprint", () => {
    const f = finding();
    const log = buildSarif(result({ findings: [f] }), CATALOG) as Obj;
    expectValidSarif(log);
    expect(log.$schema).toBe(SARIF_SCHEMA_URL);
    const run = log.runs[0];
    expect(run.tool.driver.rules).toHaveLength(1);
    expect(run.tool.driver.rules[0]).toMatchObject({
      id: "PG-SQL-001",
      shortDescription: { text: "SQL built from a dynamic string" },
      fullDescription: { text: "Input can change the query." },
      help: { text: "Use parameters." },
      properties: { "security-severity": "8.0" },
    });
    expect(run.tool.driver.rules[0].helpUri).toMatch(/^https:\/\/.*89/);
    expect(run.tool.driver.rules[0].properties.tags).toEqual(
      expect.arrayContaining(["security", "CWE-89", "OWASP-A05:2025"]),
    );
    expect(run.results[0]).toMatchObject({
      ruleId: "PG-SQL-001",
      level: "error",
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: "src/api/users.ts", uriBaseId: "%SRCROOT%" },
            region: { startLine: 42, endLine: 42 },
          },
        },
      ],
    });
    expect(run.results[0].partialFingerprints[SARIF_FINGERPRINT_KEY]).toBe(findingIdentity(f));
    const moved = buildSarif(
      result({ findings: [finding({ location: { ...f.location, line: 99 } })] }),
      CATALOG,
    ) as Obj;
    expect(moved.runs[0].results[0].partialFingerprints[SARIF_FINGERPRINT_KEY]).toBe(
      findingIdentity(f),
    );
    expect(run.invocations[0]).toMatchObject({
      executionSuccessful: true,
      toolExecutionNotifications: [],
    });
  });

  it("maps every severity to a level and a numeric security-severity", () => {
    expect(SARIF_LEVEL_BY_SEVERITY).toEqual({
      critical: "error",
      high: "error",
      medium: "warning",
      low: "note",
      info: "note",
    });
    const scores = Object.values(SARIF_SECURITY_SEVERITY).map(Number);
    expect(scores).toEqual([...scores].sort((a, b) => b - a));
    const findings = (["critical", "high", "medium", "low", "info"] as const).map((severity, i) =>
      finding({ id: `f${i}`, severity, location: { ...finding().location, line: i + 1 } }),
    );
    const log = buildSarif(result({ findings }), CATALOG) as Obj;
    expectValidSarif(log);
    expect(log.runs[0].results.map((r: Obj) => r.level)).toEqual([
      "error",
      "error",
      "warning",
      "note",
      "note",
    ]);
  });

  it("puts the commit of a history finding in properties and gives a web finding a logical location", () => {
    const history = finding({
      id: "h",
      location: { kind: "commit", path: "config/.env", line: null, url: null, commit: "deadbeef" },
    });
    const web = finding({
      id: "w",
      ruleId: "PG-WEB-001",
      severity: "info",
      sources: ["web"],
      location: {
        kind: "url",
        path: null,
        line: null,
        url: "http://127.0.0.1:3000/",
        commit: null,
      },
    });
    const log = buildSarif(result({ findings: [history, web] }), CATALOG) as Obj;
    expectValidSarif(log);
    const [h, w] = log.runs[0].results;
    expect(h.properties.pgard.commit).toBe("deadbeef");
    expect(h.locations[0].physicalLocation.region).toBeUndefined();
    expect(w.locations[0].physicalLocation).toBeUndefined();
    expect(w.locations[0].logicalLocations).toEqual([
      { name: "http://127.0.0.1:3000/", kind: "resource" },
    ]);
    expect(w.properties.pgard.url).toBe("http://127.0.0.1:3000/");
  });

  it("encodes unusual path characters in the uri", () => {
    const log = buildSarif(
      result({
        findings: [finding({ location: { ...finding().location, path: "src/a b/#x?.ts" } })],
      }),
      CATALOG,
    ) as Obj;
    expect(log.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe(
      "src/a%20b/%23x%3F.ts",
    );
  });

  it("keeps suppressed findings with an external suppression and sets baselineState only with a baseline", () => {
    const suppressed = finding({
      id: "s",
      suppression: { reason: "legacy admin tool", source: "pgard.config.json" },
    });
    const inBase = finding({ id: "b", inBaseline: true });
    const fresh = finding({ id: "n", location: { ...finding().location, line: 7 } });
    const without = buildSarif(result({ findings: [suppressed, inBase, fresh] }), CATALOG) as Obj;
    expectValidSarif(without);
    expect(without.runs[0].results[0].suppressions).toEqual([
      { kind: "external", justification: "legacy admin tool" },
    ]);
    for (const r of without.runs[0].results) expect(r.baselineState).toBeUndefined();

    const baseline = {
      setAt: "2026-10-01T00:00:00.000Z",
      scanId: "old",
      revision: null,
      total: 1,
      matched: 1,
      new: 1,
      newInUncertainAreas: 0,
      toolVersionChanged: false,
    };
    const withBaseline = buildSarif(
      result({ findings: [suppressed, inBase, fresh], baseline }),
      CATALOG,
    ) as Obj;
    expectValidSarif(withBaseline);
    const [s, b, n] = withBaseline.runs[0].results;
    expect(s.suppressions).toHaveLength(1);
    expect(s.baselineState).toBeUndefined();
    expect(b.baselineState).toBe("unchanged");
    expect(b.suppressions).toBeUndefined();
    expect(n.baselineState).toBe("new");
  });

  it("reports partial and untested areas as warnings so an empty result is not a clean scan", () => {
    const log = buildSarif(
      result({
        findings: [],
        overallStatus: "partial",
        requestedScopes: ["code", "history", "web"],
        coverage: [
          {
            area: "source:typescript",
            scope: "code",
            status: "completed",
            ruleIds: [],
            note: null,
          },
          {
            area: "history:commits",
            scope: "history",
            status: "partial",
            ruleIds: [],
            note: "Stopped at the time budget.",
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
            note: null,
          },
        ],
      }),
      CATALOG,
    ) as Obj;
    expectValidSarif(log);
    const invocation = log.runs[0].invocations[0];
    expect(log.runs[0].results).toEqual([]);
    expect(invocation.executionSuccessful).toBe(true);
    const notes = invocation.toolExecutionNotifications as Obj[];
    expect(notes.map((n) => n.level)).toEqual(["warning", "warning"]);
    expect(notes[0]?.message.text).toContain("history:commits");
    expect(notes[0]?.message.text).toContain("Stopped at the time budget.");
    expect(notes[1]?.message.text).toContain("web:anonymous");
    expect(JSON.stringify(notes)).not.toContain("web:authenticated");
  });

  it("marks a blocked or failed scan as unsuccessful with an error notification", () => {
    for (const overallStatus of ["blocked", "failed"] as const) {
      const log = buildSarif(result({ findings: [], coverage: [], overallStatus }), CATALOG) as Obj;
      expectValidSarif(log);
      const invocation = log.runs[0].invocations[0];
      expect(invocation.executionSuccessful).toBe(false);
      expect(invocation.toolExecutionNotifications[0].level).toBe("error");
    }
  });

  it("never contains a planted secret value, in any text field", () => {
    const planted = finding({
      id: "secret",
      ruleId: "PG-SECRET-002",
      title: `Token ${GITHUB_TOKEN} in a file`,
      category: "secret_exposure",
      evidence: `const token = "${GITHUB_TOKEN}"`,
      impact: GITHUB_TOKEN,
      recommendation: GITHUB_TOKEN,
      suppression: { reason: `rotated ${GITHUB_TOKEN}`, source: "pgard.config.json" },
    });
    const log = buildSarif(
      result({
        findings: [planted],
        overallStatus: "partial",
        coverage: [
          {
            area: "history:secrets",
            scope: "history",
            status: "partial",
            ruleIds: [],
            note: `stopped near ${GITHUB_TOKEN}`,
          },
        ],
      }),
      CATALOG,
    );
    const text = JSON.stringify(log);
    expect(text).not.toContain(GITHUB_TOKEN);
    expect(text).not.toContain(GITHUB_TOKEN.slice(4, 20));
    expect(text).toContain("REDACTED");
    expectValidSarif(log as Obj);
  });

  it("describes a rule that is missing from the catalog from its findings", () => {
    const log = buildSarif(
      result({ findings: [finding({ ruleId: "PG-X-1" })], coverage: [] }),
      new Map(),
    ) as Obj;
    expectValidSarif(log);
    expect(log.runs[0].tool.driver.rules[0]).toMatchObject({ id: "PG-X-1" });
    expect(log.runs[0].tool.driver.rules[0].helpUri).toBeUndefined();
  });

  it("lists rules that ran without findings, and does not mutate the input", () => {
    const input = result({
      findings: [],
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
          ruleIds: ["PG-WEB-001"],
          note: "x",
        },
      ],
    });
    const before = JSON.stringify(input);
    const log = buildSarif(input, CATALOG) as Obj;
    expect(log.runs[0].tool.driver.rules.map((r: Obj) => r.id)).toEqual(["PG-SQL-001"]);
    expect(JSON.stringify(input)).toBe(before);
  });
});
