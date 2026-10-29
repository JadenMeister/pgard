import { buildLineReplacementDiff } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import { UsageError, parseCommandLine } from "../../options.js";
import { testFinding, testResult } from "../../test-support.js";
import { formatScanResult } from "./result-view.js";
import { createStyle } from "./style.js";

const plain = createStyle(false);
const DIFF = buildLineReplacementDiff({
  path: "src/login.js",
  line: 4,
  oldLine: '  res.cookie("sid", token);',
  newLine: '  res.cookie("sid", token, { httpOnly: true, secure: true, sameSite: "lax" });',
}) as string;

const withFix = (fix: ReturnType<typeof testFinding>["fix"]) =>
  testResult({
    findings: [
      testFinding({
        ruleId: "PG-COOKIE-001",
        location: { kind: "file", path: "src/login.js", line: 4, url: null, commit: null },
        ...(fix === undefined ? {} : { fix }),
      }),
    ],
  });

describe("pgard scan --fixes", () => {
  it("is a scan flag that implies --all-findings and is refused elsewhere", () => {
    expect(parseCommandLine(["scan", "--fixes"])).toMatchObject({ fixes: true, allFindings: true });
    expect(parseCommandLine(["scan", "code"])).not.toHaveProperty("fixes");
    expect(() => parseCommandLine(["doctor", "--fixes"])).toThrow(UsageError);
    expect(() => parseCommandLine(["scan", "--fixes", "--fixes"])).toThrow("more than once");
  });

  it("prints the diff under the finding, labelled as a suggestion to review", () => {
    const text = formatScanResult(
      withFix({ kind: "diff", diff: DIFF, confidence: "medium" }),
      plain,
      {
        allFindings: true,
        fixes: true,
      },
    );
    expect(text).toContain("Suggested fix: Suggestion to review. PGARD did not apply it");
    expect(text).toContain("has not checked that it compiles or keeps behaviour");
    expect(text).toContain("--- a/src/login.js");
    expect(text).toContain(
      '+  res.cookie("sid", token, { httpOnly: true, secure: true, sameSite: "lax" });',
    );
  });

  it("labels the suggestion in Korean", () => {
    const text = formatScanResult(
      withFix({ kind: "diff", diff: DIFF, confidence: "medium" }),
      plain,
      {
        allFindings: true,
        fixes: true,
        locale: "ko",
      },
    );
    expect(text).toContain("제안된 수정: 검토용 제안입니다.");
  });

  it("prints no diff without the flag, for guidance, or for a diff that does not read back", () => {
    const diff = { kind: "diff", diff: DIFF, confidence: "medium" } as const;
    expect(formatScanResult(withFix(diff), plain, { allFindings: true })).not.toContain("--- a/");
    expect(
      formatScanResult(withFix({ kind: "guidance", confidence: "low", reason: "x" }), plain, {
        allFindings: true,
        fixes: true,
      }),
    ).not.toContain("Suggested fix");
    expect(
      formatScanResult(
        withFix({
          kind: "diff",
          diff: "--- a/x\n+++ b/x\n+password = hunter2\n",
          confidence: "low",
        }),
        plain,
        { allFindings: true, fixes: true },
      ),
    ).not.toContain("hunter2");
  });
});
