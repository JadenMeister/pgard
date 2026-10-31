import { describe, expect, it } from "vitest";
import { MAX_FIX_DIFF_LENGTH, SCHEMA_VERSION, type Finding, type ScanResult } from "./contract.js";
import { buildLineReplacementDiff } from "./fix-diff.js";
import { readScanResult } from "./read-result.js";
import { buildRuleTextCatalog } from "./rule-text.js";
import { buildSarif } from "./sarif.js";

const CHECKS = (
  ["repository", "github_identity", "owner_approval", "current_access", "contribution"] as const
).map((id) => ({ id, status: "passed" as const, reason: "ok" }));

const DIFF = buildLineReplacementDiff({
  path: "src/login.js",
  line: 4,
  oldLine: '  res.cookie("sid", token);',
  newLine: '  res.cookie("sid", token, { httpOnly: true, secure: true, sameSite: "lax" });',
}) as string;

const finding = (extra: Record<string, unknown> = {}) => ({
  id: "f1",
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
  ...extra,
});

function result(version: string, findings: unknown[]): unknown {
  return {
    schemaVersion: version,
    scanId: "s",
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:05.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "completed",
    target: { repo: "o/n", revision: "abc", webOrigin: null },
    authorization: { decision: "allowed", checks: CHECKS },
    coverage: [],
    findings,
    advisoryDb: { version: null, updatedAt: null },
  };
}

describe("schema 1.6 finding.fix", () => {
  it("is part of version 1.6 and later", () => {
    expect(SCHEMA_VERSION).toBe("1.8");
  });

  it("is kept when valid, as a diff or as guidance", () => {
    const diff = { kind: "diff", diff: DIFF, confidence: "medium" };
    const guidance = { kind: "guidance", confidence: "low", reason: "context_not_supported" };
    for (const fix of [diff, guidance]) {
      const read = readScanResult(result("1.6", [finding({ fix })]));
      expect(read.ok && read.result.findings[0]?.fix).toEqual(fix);
    }
  });

  it("is absent in older results and a reader treats that as not recorded", () => {
    const read = readScanResult(result("1.5", [finding()]));
    expect(read.ok && read.result.findings[0]?.fix).toBeUndefined();
  });

  it("is refused when malformed", () => {
    const bad: unknown[] = [
      "x",
      { kind: "patch", diff: DIFF, confidence: "medium" },
      { kind: "diff", confidence: "medium" },
      { kind: "diff", diff: "", confidence: "medium" },
      { kind: "diff", diff: 4, confidence: "medium" },
      { kind: "diff", diff: "x".repeat(MAX_FIX_DIFF_LENGTH + 1), confidence: "medium" },
      { kind: "guidance", diff: DIFF, confidence: "medium" },
      { kind: "diff", diff: DIFF, confidence: "certain" },
      { kind: "diff", diff: DIFF },
      { kind: "guidance", confidence: "low", reason: 1 },
    ];
    for (const fix of bad) {
      expect(readScanResult(result("1.6", [finding({ fix })])).ok).toBe(false);
    }
  });
});

describe("SARIF fixes", () => {
  const scan = (fix: Finding["fix"]): ScanResult =>
    result("1.6", [finding(fix === undefined ? {} : { fix })]) as ScanResult;

  it("adds one valid fix replacing the flagged line, described as a suggestion", () => {
    const log = buildSarif(
      scan({ kind: "diff", diff: DIFF, confidence: "medium" }),
      buildRuleTextCatalog([]),
    );
    const run = log.runs[0] as { results: Array<Record<string, unknown>> };
    expect(run.results[0]?.fixes).toEqual([
      {
        description: { text: expect.stringContaining("Suggestion to review") },
        artifactChanges: [
          {
            artifactLocation: { uri: "src/login.js", uriBaseId: "%SRCROOT%" },
            replacements: [
              {
                deletedRegion: { startLine: 4, startColumn: 1, endLine: 4, endColumn: 28 },
                insertedContent: {
                  text: '  res.cookie("sid", token, { httpOnly: true, secure: true, sameSite: "lax" });',
                },
              },
            ],
          },
        ],
      },
    ]);
  });

  it("adds no fixes for guidance, for no fix or for a diff that does not read back", () => {
    for (const fix of [
      undefined,
      { kind: "guidance", confidence: "low", reason: "context_not_supported" } as const,
      { kind: "diff", confidence: "low", diff: "--- a/x\n+++ b/x\n+password = hunter2\n" } as const,
    ]) {
      const log = buildSarif(scan(fix), buildRuleTextCatalog([]));
      const run = log.runs[0] as { results: Array<Record<string, unknown>> };
      expect(run.results[0]).not.toHaveProperty("fixes");
    }
  });
});
