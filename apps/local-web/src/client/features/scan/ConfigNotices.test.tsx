import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Coverage } from "@pgard/findings";
import { I18nProvider } from "../../i18n/I18nProvider";
import { ConfigNotices } from "./ConfigNotices";

const coverage: Coverage[] = [
  {
    area: "source:config-excluded",
    scope: "code",
    status: "completed",
    ruleIds: [],
    note: '3 files excluded by pgard.config.json (of 9 source files). Patterns: "<b>x</b>".',
  },
  {
    area: "source:config",
    scope: "code",
    status: "completed",
    ruleIds: [],
    note: "read (2 findings classified as test code by it)",
  },
];

function render(language: "en" | "ko", entries: Coverage[] = coverage): string {
  vi.stubGlobal("navigator", { languages: [language === "ko" ? "ko-KR" : "en-US"] });
  return renderToStaticMarkup(
    <I18nProvider>
      <ConfigNotices coverage={entries} />
    </I18nProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("ConfigNotices", () => {
  it("shows the excluded count and the reclassification in English, escaped", () => {
    const html = render("en");
    expect(html).toContain("3 files excluded by pgard.config.json");
    expect(html).toContain(
      "2 findings were classified as test code by the testDirectories setting",
    );
    expect(html).not.toContain("<b>x</b>");
    expect(html).toContain("&lt;b&gt;x&lt;/b&gt;");
  });

  it("localizes the framing in Korean and keeps the detail", () => {
    const html = render("ko");
    expect(html).toContain("pgard.config.json으로 제외된 파일이 있습니다");
    expect(html).toContain("3 files excluded by pgard.config.json");
    expect(html).toContain("테스트 코드로 분류했습니다");
    expect(html).not.toContain("were classified as test code");
  });

  it("renders nothing without a config", () => {
    expect(render("en", [])).toBe("");
  });
});
