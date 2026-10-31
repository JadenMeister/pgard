import { describe, expect, it } from "vitest";
import { isCodeOnlyResult, SCHEMA_VERSION, type ScanResult } from "./contract.js";
import { readScanResult } from "./read-result.js";
import { FINDING_TEXT_VARIANTS, localizeFinding, type RuleTextCatalog } from "./rule-text.js";
import { buildSarif, CODE_ONLY_SARIF_NOTICE } from "./sarif.js";

/** JSON 1.7 `scanBasis` (#414): code-only results say so in JSON and SARIF. */

function result(overrides: Record<string, unknown> = {}): ScanResult {
  return {
    schemaVersion: SCHEMA_VERSION,
    scanId: "s1",
    startedAt: "2026-10-29T00:00:00.000Z",
    finishedAt: "2026-10-29T00:00:01.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "completed",
    target: { repo: null, revision: null, webOrigin: null },
    authorization: { decision: "blocked", checks: [] },
    coverage: [],
    findings: [],
    advisoryDb: { version: null, updatedAt: null },
    ...overrides,
  } as ScanResult;
}

const FINDING = {
  id: "f1",
  ruleId: "PG-SECRET-002",
  title: "t",
  category: "secret_exposure",
  severity: "high",
  status: "suspected",
  confidence: "medium",
  location: { kind: "file", path: "a.js", line: 1, url: null, commit: null },
  evidence: "e",
  impact: "i",
  recommendation: "r",
  references: { cwe: [], owasp: [], cve: [] },
  sources: ["code"],
};
const CODE_ONLY = { mode: "code_only", authorization: "not_verified", reason: "no_github_remote" };
const VERIFIED = { mode: "authorized", authorization: "verified", reason: null };
const ALL_PASSED = {
  decision: "allowed",
  checks: ["repository", "github_identity", "owner_approval", "current_access", "contribution"].map(
    (id) => ({ id, status: "passed", reason: "ok" }),
  ),
};

describe("scanBasis (JSON 1.7)", () => {
  it("is version 1.8", () => {
    expect(SCHEMA_VERSION).toBe("1.8");
  });

  it("reads a code-only and an authorized basis, and treats absent as authorized", () => {
    const codeOnly = readScanResult(result({ scanBasis: CODE_ONLY }));
    expect(codeOnly.ok && codeOnly.result.scanBasis).toEqual(CODE_ONLY);
    expect(codeOnly.ok && isCodeOnlyResult(codeOnly.result)).toBe(true);
    const verified = readScanResult(result({ authorization: ALL_PASSED, scanBasis: VERIFIED }));
    expect(verified.ok).toBe(true);
    const old = readScanResult({ ...result(), schemaVersion: "1.6" });
    expect(old.ok && old.result.scanBasis).toBeUndefined();
    expect(old.ok && isCodeOnlyResult(old.result)).toBe(false);
  });

  it("accepts an unknown reason code but refuses impossible combinations", () => {
    expect(
      readScanResult(result({ scanBasis: { ...CODE_ONLY, reason: "some_future_reason" } })).ok,
    ).toBe(true);
    for (const scanBasis of [
      { mode: "code_only", authorization: "verified", reason: null },
      { mode: "authorized", authorization: "verified", reason: "no_approval" },
      { mode: "authorized", authorization: "not_verified", reason: null },
      { ...CODE_ONLY, reason: "Not A Code" },
      { ...CODE_ONLY, mode: "sometimes" },
      "code_only",
    ]) {
      expect(readScanResult(result({ scanBasis })).ok).toBe(false);
    }
  });

  it("refuses a scanBasis that disagrees with the rest of the result", () => {
    const blockedCheck = {
      ...ALL_PASSED,
      checks: ALL_PASSED.checks.map((check) =>
        check.id === "owner_approval" ? { ...check, status: "failed" } : check,
      ),
    };
    for (const overrides of [
      // "verified" needs an allowed decision with all five checks passed.
      { scanBasis: VERIFIED },
      { scanBasis: VERIFIED, authorization: { ...ALL_PASSED, decision: "blocked" } },
      { scanBasis: VERIFIED, authorization: blockedCheck },
      { scanBasis: VERIFIED, authorization: { ...ALL_PASSED, checks: ALL_PASSED.checks.slice(1) } },
      // "code_only" needs a blocked decision and only the code scope.
      { scanBasis: CODE_ONLY, authorization: ALL_PASSED },
      { scanBasis: CODE_ONLY, requestedScopes: ["code", "history"] },
      { scanBasis: CODE_ONLY, requestedScopes: [] },
    ]) {
      expect(readScanResult(result(overrides)).ok).toBe(false);
    }
    const unverified = {
      mode: "authorized",
      authorization: "not_verified",
      reason: "check_failed",
    };
    expect(readScanResult(result({ overallStatus: "failed", scanBasis: unverified })).ok).toBe(
      true,
    );
    expect(readScanResult(result({ overallStatus: "blocked", scanBasis: unverified })).ok).toBe(
      true,
    );
  });

  it("refuses a code-only result whose label was edited to an unverified authorized scan", () => {
    const edited = { mode: "authorized", authorization: "not_verified", reason: "no_approval" };
    // Analysis ran (completed / partial) or there are findings: the gate never stopped this scan.
    for (const overrides of [
      { overallStatus: "completed" },
      { overallStatus: "partial" },
      { overallStatus: "blocked", findings: [FINDING] },
      { overallStatus: "failed", findings: [FINDING] },
    ]) {
      expect(readScanResult(result({ ...overrides, scanBasis: edited })).ok).toBe(false);
    }
  });

  it("requires scanBasis from 1.7 on, so deleting it cannot drop the label", () => {
    const { scanBasis: _dropped, ...withoutBasis } = result({ scanBasis: CODE_ONLY });
    const missing = readScanResult(withoutBasis);
    expect(missing.ok).toBe(false);
    expect(!missing.ok && missing.error.message).toContain("scanBasis is required");
    expect(readScanResult({ ...withoutBasis, schemaVersion: "1.8" }).ok).toBe(false);
    expect(readScanResult({ ...withoutBasis, schemaVersion: "1.6" }).ok).toBe(true);
  });

  it("refuses a pre-1.7 result that is blocked yet has findings: it is a code-only result with its label removed (#427)", () => {
    const { scanBasis: _dropped, ...downgraded } = result({
      scanBasis: CODE_ONLY,
      findings: [FINDING],
    });
    const old = readScanResult({ ...downgraded, schemaVersion: "1.6" });
    expect(old.ok).toBe(false);
    expect(!old.ok && old.error.message).toContain("must carry scanBasis");
    // A blocked result without findings, and an authorized one with findings, still read.
    expect(readScanResult({ ...downgraded, findings: [], schemaVersion: "1.6" }).ok).toBe(true);
    expect(
      readScanResult({
        ...downgraded,
        authorization: ALL_PASSED,
        schemaVersion: "1.6",
      }).ok,
    ).toBe(true);
    // From 1.7 on the basis is required anyway.
    expect(readScanResult({ ...downgraded, schemaVersion: "1.7" }).ok).toBe(false);
  });

  it("labels a code-only SARIF run and keeps it apart from authorized runs", () => {
    const sarif = buildSarif(result({ scanBasis: CODE_ONLY }), new Map());
    const run = sarif.runs[0] as {
      automationDetails: { id: string };
      invocations: Array<{ toolExecutionNotifications: Array<{ message: { text: string } }> }>;
      properties: { pgard: { scanBasis: unknown } };
    };
    expect(run.automationDetails.id).toBe("pgard/code-only/");
    expect(run.properties.pgard.scanBasis).toEqual(CODE_ONLY);
    expect(run.invocations[0]?.toolExecutionNotifications[0]?.message.text).toBe(
      CODE_ONLY_SARIF_NOTICE,
    );
    const authorized = buildSarif(
      result({
        authorization: { decision: "allowed", checks: [] },
        scanBasis: { mode: "authorized", authorization: "verified", reason: null },
      }),
      new Map(),
    ).runs[0] as typeof run;
    expect(authorized.automationDetails.id).toBe("pgard/code/");
    expect(JSON.stringify(authorized)).not.toContain(CODE_ONLY_SARIF_NOTICE);
  });
});

describe("working-tree secret texts", () => {
  it("never say tracked or committed, and translate like the rule's own texts", () => {
    for (const variants of Object.values(FINDING_TEXT_VARIANTS)) {
      const text = variants.working_tree;
      for (const value of [text.title.en, text.impact.en]) {
        expect(value).not.toMatch(/tracked|committed to Git/i);
      }
    }
    const variant = FINDING_TEXT_VARIANTS["PG-SECRET-002"]!.working_tree;
    const catalog: RuleTextCatalog = new Map([
      [
        "PG-SECRET-002",
        {
          title: { en: "Secret in a tracked file", ko: "추적되는 파일 안의 비밀정보" },
          impact: { en: "r", ko: "알" },
          recommendation: { en: "m", ko: "엠" },
          variants: [variant],
        },
      ],
    ]);
    const localized = localizeFinding(
      {
        ruleId: "PG-SECRET-002",
        title: variant.title.en,
        impact: variant.impact.en,
        recommendation: variant.recommendation.en,
      } as never,
      catalog,
      "ko",
    ) as { title: string; impact: string };
    expect(localized.title).toBe(variant.title.ko);
    expect(localized.impact).toBe(variant.impact.ko);
  });
});
