import { describe, expect, it } from "vitest";
import type { Finding } from "./contract.js";
import {
  applyLineReplacementDiff,
  buildLineReplacementDiff,
  parseLineReplacementDiff,
  redactFix,
} from "./fix-diff.js";
import { redactFinding } from "./redact.js";

const replacement = {
  path: "src/login.js",
  line: 4,
  oldLine: '  res.cookie("sid", token);',
  newLine: '  res.cookie("sid", token, { httpOnly: true });',
};

describe("line replacement diffs", () => {
  it("writes one hunk without context lines", () => {
    expect(buildLineReplacementDiff(replacement)).toBe(
      [
        "--- a/src/login.js",
        "+++ b/src/login.js",
        "@@ -4,1 +4,1 @@",
        '-  res.cookie("sid", token);',
        '+  res.cookie("sid", token, { httpOnly: true });',
        "",
      ].join("\n"),
    );
  });

  it("is deterministic", () => {
    expect(buildLineReplacementDiff(replacement)).toBe(
      buildLineReplacementDiff({ ...replacement }),
    );
  });

  it("round-trips through parse and apply", () => {
    const diff = buildLineReplacementDiff(replacement) as string;
    expect(parseLineReplacementDiff(diff)).toEqual(replacement);
    const text = ["a", "b", "c", replacement.oldLine, "e"].join("\n");
    expect(applyLineReplacementDiff(text, diff)).toBe(
      ["a", "b", "c", replacement.newLine, "e"].join("\n"),
    );
  });

  it("does not apply to a different line", () => {
    const diff = buildLineReplacementDiff(replacement) as string;
    expect(applyLineReplacementDiff("a\nb\nc\nd\ne", diff)).toBeNull();
  });

  it("refuses a line that redaction would change (a secret is never echoed)", () => {
    const secrets = [
      'const password = "hunter2";',
      "const key = 'AKIAABCDEFGHIJKLMNOP';",
      "token=ghp_abcdefghijklmnopqrstuvwxyz0123456789",
      "Authorization: Bearer abcdef0123456789abcdef",
      "url = https://user:pa55word@example.com/x",
      "see /Users/alice/project/file.js",
    ];
    for (const secret of secrets) {
      expect(buildLineReplacementDiff({ ...replacement, oldLine: secret })).toBeNull();
      expect(buildLineReplacementDiff({ ...replacement, newLine: secret })).toBeNull();
    }
  });

  it("refuses unsafe paths, control characters, no-ops and oversized lines", () => {
    for (const path of ["/etc/x", "../x", "a b.js", "a/../b.js", "", "x\n.js"]) {
      expect(buildLineReplacementDiff({ ...replacement, path })).toBeNull();
    }
    expect(buildLineReplacementDiff({ ...replacement, newLine: "a\u001b[31mred" })).toBeNull();
    expect(buildLineReplacementDiff({ ...replacement, newLine: "a‮b" })).toBeNull();
    expect(buildLineReplacementDiff({ ...replacement, newLine: "a\nb" })).toBeNull();
    expect(buildLineReplacementDiff({ ...replacement, newLine: replacement.oldLine })).toBeNull();
    expect(buildLineReplacementDiff({ ...replacement, newLine: "x".repeat(401) })).toBeNull();
    expect(buildLineReplacementDiff({ ...replacement, line: 0 })).toBeNull();
  });

  it("parses nothing but its own format", () => {
    for (const diff of [
      "",
      "--- a/x\n+++ b/x\n@@ -1,1 +1,1 @@\n-a\n+b",
      "--- a/x\n+++ b/y\n@@ -1,1 +1,1 @@\n-a\n+b\n",
      "--- a/x\n+++ b/x\n@@ -1,1 +2,1 @@\n-a\n+b\n",
      "--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n-a\n+b\n",
      "--- a/x\n+++ b/x\n@@ -1,1 +1,1 @@\n context\n-a\n+b\n",
      `--- a/x\n+++ b/x\n@@ -1,1 +1,1 @@\n-a\n+${"b".repeat(3000)}\n`,
    ]) {
      expect(parseLineReplacementDiff(diff)).toBeNull();
    }
  });

  it("turns a diff that does not read back into guidance", () => {
    const bad = {
      kind: "diff",
      diff: "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n",
      confidence: "low",
    } as const;
    expect(redactFix(bad)).toEqual({
      kind: "guidance",
      confidence: "low",
      reason: "sensitive_text",
    });
    expect(redactFix({ kind: "guidance", confidence: "low", diff: "x" })).toEqual({
      kind: "guidance",
      confidence: "low",
    });
  });

  it("is applied by redactFinding", () => {
    const finding = {
      id: "1",
      ruleId: "PG-COOKIE-001",
      title: "t",
      category: "misconfiguration",
      severity: "medium",
      status: "suspected",
      confidence: "medium",
      location: { kind: "file", path: "src/login.js", line: 4, url: null, commit: null },
      evidence: "e",
      impact: "i",
      recommendation: "r",
      references: { cwe: [], owasp: [], cve: [] },
      sources: ["code"],
      fix: { kind: "diff", confidence: "medium", diff: "--- a/x\n+++ b/x\n+password = hunter2\n" },
    } satisfies Finding;
    expect(redactFinding(finding).fix).toEqual({
      kind: "guidance",
      confidence: "medium",
      reason: "sensitive_text",
    });
  });
});
