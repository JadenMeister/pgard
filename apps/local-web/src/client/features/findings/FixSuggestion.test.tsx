import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "@pgard/findings";
import { I18nProvider } from "../../i18n/I18nProvider";
import { FixSuggestion } from "./FixSuggestion";

const DIFF = [
  "--- a/src/login.js",
  "+++ b/src/login.js",
  "@@ -4,1 +4,1 @@",
  '-  res.cookie("sid", token);',
  '+  res.cookie("sid", token, { httpOnly: true, secure: true, sameSite: "lax" });',
  "",
].join("\n");

const finding = (fix: Finding["fix"]): Finding => ({
  id: "f1",
  ruleId: "PG-COOKIE-001",
  title: "Cookie",
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
  ...(fix === undefined ? {} : { fix }),
});

function render(language: "en" | "ko", value: Finding): string {
  vi.stubGlobal("navigator", { languages: [language === "ko" ? "ko-KR" : "en-US"] });
  return renderToStaticMarkup(
    <I18nProvider>
      <FixSuggestion finding={value} />
    </I18nProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("FixSuggestion", () => {
  it("shows nothing for a finding without a fix", () => {
    expect(render("en", finding(undefined))).toBe("");
  });

  it("shows the diff read-only, labelled as a suggestion, with a copy button", () => {
    const html = render("en", finding({ kind: "diff", diff: DIFF, confidence: "medium" }));
    expect(html).toContain("Suggested fix (to review)");
    expect(html).toContain("Suggestion to review. PGARD did not apply it");
    expect(html).toContain("not checked that it compiles or keeps behaviour");
    expect(html).toContain("httpOnly: true");
    expect(html).toContain("Copy diff");
    expect(html).not.toContain("<textarea");
  });

  it("labels the diff in Korean", () => {
    const html = render("ko", finding({ kind: "diff", diff: DIFF, confidence: "medium" }));
    expect(html).toContain("제안된 수정 (검토용)");
    expect(html).toContain("확인하지 않았습니다");
    expect(html).toContain("diff 복사");
  });

  it("escapes the diff as text", () => {
    const evil = DIFF.replace("sameSite", "<img src=x onerror=alert(1)>");
    // Not one of PGARD's diffs once edited to hold markup in a way it would not write: it is
    // still escaped if it does read back, and ignored otherwise.
    const html = render("en", finding({ kind: "diff", diff: evil, confidence: "medium" }));
    expect(html).not.toContain("<img");
  });

  it("ignores a diff that does not read back as one of PGARD's (guidance instead)", () => {
    const html = render(
      "en",
      finding({ kind: "diff", diff: "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n", confidence: "low" }),
    );
    expect(html).not.toContain("<pre");
    expect(html).not.toContain("Copy diff");
    expect(html).toContain("No code change is suggested");
  });

  it("shows guidance without a diff or copy button", () => {
    const html = render(
      "en",
      finding({ kind: "guidance", confidence: "low", reason: "context_not_supported" }),
    );
    expect(html).toContain("No code change is suggested");
    expect(html).not.toContain("Copy diff");
  });
});
