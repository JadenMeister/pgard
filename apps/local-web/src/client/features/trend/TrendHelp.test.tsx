import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HelpTip, nextHelpTipOpen } from "../../components/ui/HelpTip";
import { I18nProvider } from "../../i18n/I18nProvider";
import { EMPTY_FILTERS } from "../findings/filter-findings";
import { TrendView } from "./TrendView";
import type { TrendState } from "./use-trend";

afterEach(() => {
  vi.unstubAllGlobals();
});

function render(state: TrendState, languages: string[]): string {
  vi.stubGlobal("navigator", { languages });
  return renderToStaticMarkup(
    <I18nProvider>
      <TrendView
        state={state}
        onReload={() => undefined}
        filters={EMPTY_FILTERS}
        onFilter={() => undefined}
        hasCurrentScan={false}
        onOpenFindings={() => undefined}
      />
    </I18nProvider>,
  );
}

const ready = (count: number): TrendState => ({
  status: "loaded",
  data: {
    kind: "ready",
    points: Array.from({ length: count }, (_, index) => ({
      savedAt: Date.UTC(2026, 9, 1 + index),
      coverage: "completed" as const,
      incompleteAreas: 0,
      severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      total: 1,
      ignored: 0,
      baselined: 0,
      change: null,
    })),
    skipped: 0,
    newerSkipped: 0,
    futureSkipped: 0,
    unread: 0,
  },
});

const STATES: Record<string, TrendState> = {
  disabled: { status: "loaded", data: { kind: "disabled" } },
  notVerified: { status: "loaded", data: { kind: "unavailable", why: "not-verified" } },
  noStoreDir: { status: "loaded", data: { kind: "unavailable", why: "no-store-dir" } },
  unreadable: { status: "loaded", data: { kind: "unavailable", why: "unreadable" } },
  none: ready(0),
  one: ready(1),
};
const WITH_LIST = ["disabled", "none", "one"];

const TEXT = {
  en: {
    languages: ["en-US"],
    intro: "Common reasons for an empty trend:",
    one: "A scan run in this dashboard, or a code-only scan: not stored. Run pgard scan in a terminal.",
    off: "Storing is off: PGARD_NO_STORE=1, or pgard web --no-store.",
    label: "About trend",
    history: "each approved pgard scan that finishes is stored on this computer",
  },
  ko: {
    languages: ["ko-KR"],
    intro: "추이가 비는 흔한 이유:",
    one: "이 대시보드에서 실행한 검사나 코드 전용 검사: 저장되지 않습니다. 터미널에서 pgard scan을 실행하세요.",
    off: "저장이 꺼져 있음: PGARD_NO_STORE=1 또는 pgard web --no-store.",
    label: "추이 설명",
    history: "승인되어 끝까지 실행된 pgard scan은 저장을 끄지 않는 한 이 컴퓨터에 저장됩니다",
  },
} as const;

describe("help tip behaviour", () => {
  it("toggles, and closes on Esc or an outside press", () => {
    expect(nextHelpTipOpen(false, "toggle")).toBe(true);
    expect(nextHelpTipOpen(true, "toggle")).toBe(false);
    expect(nextHelpTipOpen(true, "escape")).toBe(false);
    expect(nextHelpTipOpen(true, "outside")).toBe(false);
    expect(nextHelpTipOpen(false, "outside")).toBe(false);
  });

  it("renders a closed disclosure with an accessible name and no inline script or style", () => {
    const html = renderToStaticMarkup(
      <I18nProvider>
        <HelpTip label="About trend">
          <p>text</p>
        </HelpTip>
      </I18nProvider>,
    );
    expect(html).toContain('<summary aria-label="About trend"');
    expect(html).toContain('aria-expanded="false"');
    expect(html).not.toMatch(/<details[^>]*\sopen/);
    expect(html).not.toContain("style=");
    expect(html).not.toMatch(/\son[a-z]+=/);
  });
});

describe("trend help and empty-state list", () => {
  for (const [language, text] of Object.entries(TEXT)) {
    it(`${language}: the "?" is labelled and explains how history builds up`, () => {
      const html = render(STATES.none as TrendState, [...text.languages]);
      expect(html).toContain(`aria-label="${text.label}"`);
      expect(html).toContain(text.history);
      expect(html).not.toContain("`");
    });

    for (const [name, state] of Object.entries(STATES)) {
      it(`${language}: ${name} ${WITH_LIST.includes(name) ? "lists" : "does not list"} the common reasons`, () => {
        const html = render(state, [...text.languages]);
        expect(html.includes(text.intro)).toBe(WITH_LIST.includes(name));
        if (WITH_LIST.includes(name)) {
          expect(html).toContain(text.one);
          // The disabled notice already is case 3, so it is not repeated there.
          expect(html.includes(text.off)).toBe(name !== "disabled");
        }
      });
    }
  }
});
