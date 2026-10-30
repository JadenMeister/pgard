import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { en } from "../i18n/en";
import { ko } from "../i18n/ko";
import { ConnectionNotice, connectionText, type NoticeOutcome } from "./ConnectionNotice";

const OUTCOMES: NoticeOutcome[] = ["used", "expired", "ended", "no_link", "invalid", "unreachable"];

describe("ConnectionNotice (#419)", () => {
  it("says a used link was already used and what to do, in English and Korean", () => {
    const english = connectionText(en, "used");
    expect(english.title).toBe("This link was already used");
    expect(english.lines.join(" ")).toContain("Use the tab where PGARD is already open");
    expect(english.lines.join(" ")).toContain("run pgard web again");
    expect(english.lines.join(" ")).toContain("Ctrl+C");
    const korean = connectionText(ko, "used");
    expect(korean.title).toBe("이미 사용한 링크입니다");
    expect(korean.lines.join(" ")).toContain("이미 열려 있는 PGARD 탭");
    expect(korean.lines.join(" ")).toContain("pgard web");
    expect(korean.lines.join(" ")).toContain("서버를 멈추고(Ctrl+C)");
  });

  it("has a heading and plain text for every outcome, never an error code", () => {
    for (const messages of [en, ko]) {
      for (const outcome of OUTCOMES) {
        const text = connectionText(messages, outcome);
        expect(text.title.length).toBeGreaterThan(0);
        expect(text.lines.length).toBeGreaterThan(0);
        expect(text.lines.join(" ")).not.toMatch(/token_used|409|401|session_expired/);
      }
    }
  });

  it("renders as a page with the language toggle", () => {
    const html = renderToStaticMarkup(<ConnectionNotice outcome="used" />);
    expect(html).toContain("<h1");
    expect(html).toContain("This link was already used");
    expect(html).toContain("lang-toggle");
    expect(html).not.toContain("token=");
  });
});
