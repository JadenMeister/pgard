import { readFileSync } from "node:fs";
import { Ajv } from "ajv";
import { describe, expect, it } from "vitest";
import type { Finding, ScanResult } from "./contract.js";
import { buildLineReplacementDiff } from "./fix-diff.js";
import { buildRuleTextCatalog } from "./rule-text.js";
import { buildSarif } from "./sarif.js";

/** The official SARIF 2.1.0 schema (vendored, see the fixture folder). It is draft-04: `id` -> `$id`. */
const schema = JSON.parse(
  readFileSync(new URL("../test-fixtures/sarif/sarif-schema-2.1.0.json", import.meta.url), "utf8"),
) as Record<string, unknown>;
delete schema.$schema;
schema.$id = schema.id;
delete schema.id;
const validate = new Ajv({ strict: false, allErrors: true, validateFormats: false }).compile(
  schema,
);

const DIFF = buildLineReplacementDiff({
  path: "src/login.js",
  line: 4,
  oldLine: '  res.cookie("sid", token);',
  newLine: '  res.cookie("sid", token, { httpOnly: true, secure: true, sameSite: "lax" });',
}) as string;

const finding = (id: string, fix?: Finding["fix"]): Finding => ({
  id,
  ruleId: "PG-COOKIE-001",
  title: "Cookie flags",
  category: "misconfiguration",
  severity: "medium",
  status: "suspected",
  confidence: "medium",
  location: { kind: "file", path: "src/login.js", line: 4, url: null, commit: null },
  evidence: "res.cookie(session-like name) without httpOnly, secure, sameSite",
  impact: "i",
  recommendation: "r",
  references: { cwe: [], owasp: [], cve: [] },
  sources: ["code"],
  ...(fix === undefined ? {} : { fix }),
});

const scan = (findings: Finding[]): ScanResult => ({
  schemaVersion: "1.7",
  scanId: "s",
  startedAt: "2026-01-01T00:00:00.000Z",
  finishedAt: "2026-01-01T00:00:01.000Z",
  tool: { name: "pgard", version: "0.1.0" },
  requestedScopes: ["code"],
  overallStatus: "completed",
  target: { repo: null, revision: null, webOrigin: null },
  authorization: { decision: "allowed", checks: [] },
  coverage: [
    {
      area: "source:javascript",
      scope: "code",
      status: "completed",
      ruleIds: ["PG-COOKIE-001"],
      note: null,
    },
  ],
  findings,
  advisoryDb: { version: null, updatedAt: null },
});

describe("SARIF output against the official 2.1.0 schema", () => {
  it("is valid with a fix, with guidance and without a fix", () => {
    const log = buildSarif(
      scan([
        finding("a", { kind: "diff", diff: DIFF, confidence: "medium" }),
        finding("b", { kind: "guidance", confidence: "low", reason: "context_not_supported" }),
        finding("c"),
      ]),
      buildRuleTextCatalog([]),
    );
    const valid = validate(log);
    expect(valid ? [] : validate.errors).toEqual([]);
    const results = (log.runs[0] as { results: Array<{ fixes?: unknown[] }> }).results;
    expect(results.filter((result) => result.fixes !== undefined)).toHaveLength(1);
  });
});
