import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AdvisoryStatusDto } from "../../../shared/api-types";
import { I18nProvider } from "../../i18n/I18nProvider";
import { AdvisoryStatusView } from "./AdvisoryStatusLine";

const ecosystem = {
  ecosystem: "npm",
  state: "fresh" as const,
  fetchedAt: "2026-10-27T08:00:00.000Z",
  ageDays: 2,
  modifiedMax: "2026-10-26T00:00:00Z",
  dataAgeDays: 3,
  dataVersion: "1:abcdef012345",
};

function render(language: "en" | "ko", status: AdvisoryStatusDto): string {
  vi.stubGlobal("navigator", { languages: [language === "ko" ? "ko-KR" : "en-US"] });
  return renderToStaticMarkup(
    <I18nProvider>
      <AdvisoryStatusView status={status} />
    </I18nProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("AdvisoryStatusView", () => {
  it("shows present data with age, version and store path in English", () => {
    const html = render("en", {
      overall: "fresh",
      staleAfterDays: 7,
      storePath: "/scratch/advisories/osv",
      ecosystems: [ecosystem],
    });
    expect(html).toContain("Advisory data (OSV):");
    expect(html).toContain("present, up to date.");
    expect(html).toContain(
      "npm: downloaded 2026-10-27 (2 days old), newest record 2026-10-26, data version 1:abcdef012345;",
    );
    expect(html).toContain("Stored in /scratch/advisories/osv.");
    expect(html).toContain("notice-info");
  });

  it("warns that stale data is stale and how to refresh it, in Korean", () => {
    const html = render("ko", {
      overall: "stale",
      staleAfterDays: 7,
      storePath: "/scratch/advisories/osv",
      ecosystems: [{ ...ecosystem, state: "stale", ageDays: 9 }],
    });
    expect(html).toContain("취약점 데이터 (OSV):");
    expect(html).toContain("있음, 오래됨.");
    expect(html).toContain("7일 이상 지나면 오래된 데이터로 봅니다");
    expect(html).toContain("저장 위치: /scratch/advisories/osv.");
    expect(html).toContain("notice-warning");
  });

  it("says missing data means dependency checks were not tested", () => {
    const html = render("en", {
      overall: "none",
      staleAfterDays: 7,
      storePath: "/scratch/advisories/osv",
      ecosystems: [
        {
          ...ecosystem,
          state: "none",
          fetchedAt: null,
          ageDays: null,
          modifiedMax: null,
          dataAgeDays: null,
          dataVersion: null,
        },
      ],
    });
    expect(html).toContain("missing. Dependency checks are reported as not tested");
    expect(html).toContain("uploads nothing");
  });

  it("says unreadable data could not be read, and partial data is partial", () => {
    const unreadable = render("en", {
      overall: "unreadable",
      staleAfterDays: 7,
      storePath: null,
      ecosystems: [],
    });
    expect(unreadable).toContain("could not be read.");
    expect(unreadable).not.toContain("missing");
    const partial = render("en", {
      overall: "none",
      staleAfterDays: 7,
      storePath: null,
      ecosystems: [
        ecosystem,
        {
          ...ecosystem,
          ecosystem: "Go",
          state: "none",
          fetchedAt: null,
          ageDays: null,
          modifiedMax: null,
          dataAgeDays: null,
          dataVersion: null,
        },
      ],
    });
    expect(partial).toContain("partial: at least one ecosystem has no data.");
    expect(partial).toContain("Go: none;");
  });

  it("states the stale rule as download or newest record", () => {
    const html = render("en", {
      overall: "stale",
      staleAfterDays: 7,
      storePath: null,
      ecosystems: [{ ...ecosystem, state: "stale" }],
    });
    expect(html).toContain("the download or its newest record is 7 or more days old");
  });

  it("points to the README when the store path was hidden", () => {
    const html = render("en", {
      overall: "fresh",
      staleAfterDays: 7,
      storePath: "<absolute-path>",
      ecosystems: [ecosystem],
    });
    expect(html).toContain("the README lists where each system keeps it");
  });
});
