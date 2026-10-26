import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding, ScanResult } from "@pgard/findings";
import type { RuleTextsResponse } from "../../../shared/api-types";
import { I18nProvider } from "../../i18n/I18nProvider";
import { FindingsDashboard } from "./FindingsDashboard";
import { localizeFindingText } from "./rule-texts";

const TEXTS: RuleTextsResponse = {
  "PG-SQL-001": {
    title: { en: "SQL from dynamic strings", ko: "동적 문자열로 만든 SQL" },
    impact: { en: "Query may change", ko: "쿼리가 바뀔 수 있습니다" },
    recommendation: { en: "Use parameters", ko: "매개변수를 사용하세요" },
  },
};

const FINDING: Finding = {
  id: "f1",
  ruleId: "PG-SQL-001",
  title: "SQL from dynamic strings",
  category: "injection",
  severity: "high",
  status: "suspected",
  confidence: "medium",
  location: { kind: "file", path: "src/a.ts", line: 3, url: null, commit: null },
  evidence: "concat (value redacted)",
  impact: "Query may change",
  recommendation: "Use parameters",
  references: { cwe: [], owasp: [], cve: [] },
  sources: ["code"],
};

function resultWith(finding: Finding): ScanResult {
  return {
    schemaVersion: "1.2",
    scanId: "s1",
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:05.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "completed",
    target: { repo: "o/n", revision: "abc", webOrigin: null },
    authorization: { decision: "allowed", checks: [] },
    coverage: [],
    advisoryDb: { version: null, updatedAt: null },
    findings: [finding],
  } as ScanResult;
}

function render(finding: Finding, ruleTexts: RuleTextsResponse | null): string {
  return renderToStaticMarkup(
    <I18nProvider>
      <FindingsDashboard result={resultWith(finding)} ruleTexts={ruleTexts} />
    </I18nProvider>,
  );
}

describe("dashboard rule texts", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows the rule title, impact and fix in Korean when the UI is Korean", () => {
    vi.stubGlobal("navigator", { languages: ["ko-KR"] });
    const html = render(FINDING, TEXTS);
    expect(html).toContain("동적 문자열로 만든 SQL");
    expect(html).toContain("쿼리가 바뀔 수 있습니다");
    expect(html).toContain("매개변수를 사용하세요");
    expect(html).not.toContain("Use parameters");
  });

  it("shows the English texts when the UI is English", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    const html = render(FINDING, TEXTS);
    expect(html).toContain("Use parameters");
    expect(html).not.toContain("매개변수를 사용하세요");
  });

  it("keeps the stored text before the rule texts have loaded", () => {
    vi.stubGlobal("navigator", { languages: ["ko-KR"] });
    expect(render(FINDING, null)).toContain("Use parameters");
  });

  it("keeps a finding's own recommendation that differs from the rule default", () => {
    vi.stubGlobal("navigator", { languages: ["ko-KR"] });
    const own = "Remove node_modules from the repository";
    const html = render({ ...FINDING, recommendation: own }, TEXTS);
    expect(html).toContain(own);
    expect(html).not.toContain("매개변수를 사용하세요");
    expect(html).toContain("쿼리가 바뀔 수 있습니다");
  });
});

describe("localizeFindingText", () => {
  it("keeps a finding's own title and impact, and ignores inherited property names", () => {
    const own = { ...FINDING, title: "Own title", impact: "Own impact" };
    const output = localizeFindingText(own, TEXTS, "ko");
    expect(output.title).toBe("Own title");
    expect(output.impact).toBe("Own impact");
    const proto = { ...FINDING, ruleId: "constructor" };
    expect(localizeFindingText(proto, TEXTS, "ko")).toBe(proto);
  });

  it("ignores unknown rules and English", () => {
    const unknown = { ...FINDING, ruleId: "PG-X" };
    expect(localizeFindingText(unknown, TEXTS, "ko")).toEqual(unknown);
    expect(localizeFindingText(FINDING, TEXTS, "en")).toBe(FINDING);
  });
});

describe("dashboard test-group note for config classification", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const testFinding: Finding = { ...FINDING, id: "t1", context: "test", confidence: "low" };
  const withConfig = (count: number): ScanResult => ({
    ...resultWith(testFinding),
    coverage: [
      {
        area: "source:config",
        scope: "code",
        status: "completed",
        ruleIds: [],
        note: `read (${count} finding${count === 1 ? "" : "s"} classified as test code by it)`,
      },
    ],
  });
  const html = (result: ScanResult) =>
    renderToStaticMarkup(
      <I18nProvider>
        <FindingsDashboard result={result} ruleTexts={null} />
      </I18nProvider>,
    );

  it("says how many findings the config classified, in English and Korean", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    expect(html(withConfig(2))).toContain(
      "2 of them were classified by the testDirectories setting of pgard.config.json",
    );
    vi.stubGlobal("navigator", { languages: ["ko-KR"] });
    expect(html(withConfig(2))).toContain("그중 2건은 기본 규칙이 아니라");
  });

  it("adds nothing when the config classified none", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    expect(html(withConfig(0))).not.toContain("testDirectories setting");
    expect(html(resultWith(testFinding))).not.toContain("testDirectories setting");
  });
});
