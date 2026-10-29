import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { TrendPointDto, TrendResponse } from "../../../shared/api-types";
import { I18nProvider } from "../../i18n/I18nProvider";
import { EMPTY_FILTERS } from "../findings/filter-findings";
import { TrendView } from "./TrendView";
import { countIncomplete, isChangeUncertain, maxChange, maxTotal, segmentsOf } from "./trend-model";
import type { TrendState } from "./use-trend";

const DAY = 86_400_000;
const START = Date.UTC(2026, 9, 1, 12);

function point(index: number, overrides: Partial<TrendPointDto> = {}): TrendPointDto {
  const high = 3 + (index % 4);
  return {
    savedAt: START + index * DAY,
    coverage: "completed",
    incompleteAreas: 0,
    severity: { critical: index % 2, high, medium: 2, low: 1, info: 0 },
    total: (index % 2) + high + 3,
    ignored: 1,
    baselined: 2,
    change:
      index === 0
        ? null
        : { new: index % 3, noLongerReported: index % 2, unchanged: 5, notComparable: 0 },
    ...overrides,
  };
}

function ready(
  points: TrendPointDto[],
  extra: Partial<Extract<TrendResponse, { kind: "ready" }>> = {},
) {
  return {
    status: "loaded",
    data: {
      kind: "ready",
      points,
      skipped: 0,
      newerSkipped: 0,
      futureSkipped: 0,
      unread: 0,
      ...extra,
    },
  } satisfies TrendState;
}

function render(
  state: TrendState,
  options: { severity?: "high" | null; hasCurrentScan?: boolean } = {},
): string {
  return renderToStaticMarkup(
    <I18nProvider>
      <TrendView
        state={state}
        onReload={() => undefined}
        filters={{ ...EMPTY_FILTERS, severity: options.severity ?? null }}
        onFilter={() => undefined}
        hasCurrentScan={options.hasCurrentScan ?? true}
        onOpenFindings={() => undefined}
      />
    </I18nProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Trend view states", () => {
  it("says where the data comes from: saved CLI scans, not dashboard scans", () => {
    const html = render({ status: "loading" });
    expect(html).toContain("saved with the pgard command");
    expect(html).toContain("not stored");
    expect(html).toContain("Reading the saved scans");
  });

  it("says the store is off instead of drawing an empty chart", () => {
    const html = render({ status: "loaded", data: { kind: "disabled" } });
    expect(html).toContain("Saving scans is switched off");
    expect(html).not.toContain("<svg");
  });

  it("asks to verify the project, and explains missing and unreadable stores", () => {
    expect(
      render({ status: "loaded", data: { kind: "unavailable", why: "not-verified" } }),
    ).toContain("Verify the project first");
    expect(
      render({ status: "loaded", data: { kind: "unavailable", why: "no-store-dir" } }),
    ).toContain("No folder for saved scans");
    const unreadable = render({
      status: "loaded",
      data: { kind: "unavailable", why: "unreadable" },
    });
    expect(unreadable).toContain("could not be read");
    expect(unreadable).toContain('role="alert"');
    expect(render({ status: "failed" })).toContain("could not be loaded");
  });

  it("says so with no saved scan and with one, and draws no chart for either", () => {
    const none = render(ready([]));
    expect(none).toContain("No saved scans for this repository yet");
    expect(none).not.toContain("<svg");
    const one = render(ready([point(0)]));
    expect(one).toContain("Only one saved scan");
    expect(one).not.toContain("<svg");
    // The one scan is still listed, as text.
    expect(one).toContain("<table");
  });

  it("names skipped files, newer-schema scans, future-dated scans and unread files", () => {
    const html = render(
      ready([point(0), point(1)], { skipped: 2, newerSkipped: 1, futureSkipped: 3, unread: 4 }),
    );
    expect(html).toContain("2 saved files could not be read");
    expect(html).toContain("1 saved scan was written by a newer PGARD");
    expect(html).toContain("3 saved scans are dated in the future");
    expect(html).toContain("4 older saved files were not read");
  });
});

describe("Trend view with scans", () => {
  const many = Array.from({ length: 20 }, (_, index) => point(index));

  it("draws labelled charts and a data table with one row per scan", () => {
    const html = render(ready(many));
    expect(html).toContain("Every scan below completed all the areas");
    expect(html).toContain("Stacked bars of active findings by severity for 20 saved scans");
    expect(html).toContain("<caption");
    expect((html.match(/<tr/g) ?? []).length).toBe(21);
    // Each bar is a labelled keyboard stop; exactly one is in the tab order.
    expect((html.match(/data-column/g) ?? []).length).toBe(20);
    expect((html.match(/tabindex="0"/g) ?? []).length).toBe(1);
    expect(html).toContain('role="img"');
    expect(html).toContain("Change between consecutive scans");
  });

  it("never presents partial coverage as an improvement", () => {
    const points = many.slice(0, 5).map((entry, index) =>
      index === 3
        ? {
            ...entry,
            coverage: "partial" as const,
            incompleteAreas: 2,
            total: 1,
            severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
          }
        : entry,
    );
    const html = render(ready(points));
    expect(html).toContain("1 of 5 scans did not cover everything (hatched)");
    expect(html).toContain("not that findings were fixed");
    expect(html).toContain("Partial (2 areas incomplete)");
    expect(html).toContain("trend-flag");
    expect(html).toContain("trend-hatch");
    expect(html).toContain("Coverage: Partial (2 areas incomplete)");
    // The comparisons into and out of the partial scan are marked.
    expect(html).toContain("* One of these two scans did not cover everything");
    expect(isChangeUncertain(points, 3)).toBe(true);
    expect(isChangeUncertain(points, 4)).toBe(true);
    expect(isChangeUncertain(points, 2)).toBe(false);
    expect(countIncomplete(points)).toBe(1);
  });

  it("labels 'no longer reported' as not proof of a fix", () => {
    const html = render(ready(many.slice(0, 3)));
    expect(html).toContain("No longer reported");
    expect(html).toContain("It is not proof that it was fixed");
    expect(html).not.toMatch(/\bfixed\b[^.]*<\/th>/);
  });

  it("links the severity legend to the shared filter, and says the rest does not apply", () => {
    const plain = render(ready(many.slice(0, 3)));
    expect(plain).toContain('aria-pressed="false"');
    expect(plain).toContain("category and the other filters do not apply");
    expect(plain).not.toContain("Show these findings in the current scan");
    const filtered = render(ready(many.slice(0, 3)), { severity: "high" });
    expect(filtered).toContain('aria-pressed="true"');
    expect(filtered).toContain("Show these findings in the current scan");
    expect(filtered).toContain("is-dimmed");
    expect(render(ready(many.slice(0, 3)), { severity: "high", hasCurrentScan: false })).toContain(
      "Run a scan in this dashboard to list the matching findings.",
    );
  });

  it("is fully translated in Korean", () => {
    vi.stubGlobal("navigator", { languages: ["ko-KR"] });
    const html = render(
      ready(
        many
          .slice(0, 4)
          .map((entry, index) =>
            index === 2 ? { ...entry, coverage: "partial" as const } : entry,
          ),
      ),
    );
    expect(html).toContain("추이");
    expect(html).toContain("빗금");
    expect(html).toContain("고쳐졌다는 뜻이 아닙니다");
    expect(html).toContain("데이터 표");
    expect(html).not.toContain("Every scan");
    const off = render({ status: "loaded", data: { kind: "disabled" } });
    expect(off).toContain("저장이 꺼져 있어");
  });
});

describe("trend geometry", () => {
  it("stacks quiet severities first and scales to the largest total", () => {
    const sample = point(2);
    const segments = segmentsOf(sample, maxTotal([sample]));
    expect(segments.map((segment) => segment.severity)).toEqual(
      ["low", "medium", "high", "critical"].filter((name) => sample.severity[name as "low"] > 0),
    );
    const total = segments.reduce((sum, segment) => sum + segment.height, 0);
    expect(total).toBeCloseTo(100);
    expect(segments.at(-1)?.y).toBeCloseTo(0);
  });

  it("keeps a sensible scale for an all-zero history", () => {
    const zero = point(1, {
      total: 0,
      severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      change: { new: 0, noLongerReported: 0, unchanged: 0, notComparable: 0 },
    });
    expect(maxTotal([zero])).toBe(1);
    expect(maxChange([zero])).toBe(1);
    expect(segmentsOf(zero, 1)).toEqual([]);
  });
});
