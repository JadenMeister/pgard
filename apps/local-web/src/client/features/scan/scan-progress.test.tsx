import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ScanProgressDto } from "../../../shared/api-types";
import { I18nProvider } from "../../i18n/I18nProvider";
import { describeScanProgress, formatElapsed } from "./scan-progress";
import { ScanProgress } from "./ScanProgress";

const event = (stage: string, status: string, message = ""): ScanProgressDto => ({
  stage,
  status,
  message,
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("describeScanProgress", () => {
  it("lists the gate first, then the selected scopes in run order, all waiting", () => {
    expect(describeScanProgress(["web", "code"], [])).toEqual([
      { area: "authorization", state: "waiting", pagesVisited: null },
      { area: "code", state: "waiting", pagesVisited: null },
      { area: "web", state: "waiting", pagesVisited: null },
    ]);
  });

  it("follows each area's latest event", () => {
    const rows = describeScanProgress(
      ["code", "history"],
      [
        event("authorization", "started"),
        event("authorization", "completed"),
        event("code", "started"),
        event("code", "failed"),
        event("history", "started"),
      ],
    );
    expect(rows.map((row) => row.state)).toEqual(["done", "failed", "running"]);
  });

  it("treats an area as done once a later one started, even if its events were dropped", () => {
    const rows = describeScanProgress(["code", "history"], [event("history", "started")]);
    expect(rows.map((row) => row.state)).toEqual(["done", "done", "running"]);
  });

  it("reads the web page count and a skipped web check", () => {
    const pages = describeScanProgress(
      ["web"],
      [
        event("web", "started", "Running web analysis."),
        event("web", "started", "12 page(s) checked"),
      ],
    );
    expect(pages[1]).toEqual({ area: "web", state: "running", pagesVisited: 12 });
    const skipped = describeScanProgress(
      ["code", "web"],
      [event("code", "completed"), event("web", "skipped", "No confirmed local web target.")],
    );
    expect(skipped.map((row) => row.state)).toEqual(["done", "done", "skipped"]);
  });
});

describe("formatElapsed", () => {
  it("formats seconds as m:ss or h:mm:ss", () => {
    expect(formatElapsed(0)).toBe("0:00");
    expect(formatElapsed(7.9)).toBe("0:07");
    expect(formatElapsed(760)).toBe("12:40");
    expect(formatElapsed(3723)).toBe("1:02:03");
    expect(formatElapsed(-5)).toBe("0:00");
  });
});

describe("scan progress panel", () => {
  const events = [
    event("authorization", "completed", "Authorization verified."),
    event("code", "started", "Running code analysis."),
  ];
  const render = () =>
    renderToStaticMarkup(
      <I18nProvider>
        <ScanProgress scopes={["code", "history"]} events={events} elapsedSeconds={65} />
      </I18nProvider>,
    );

  it("shows each area's state and the elapsed time, and announces changes politely", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    const html = render();
    expect(html).toContain("Elapsed 1:05");
    expect(html).toContain('aria-busy="true"');
    expect(html).toContain('aria-label="Scan progress by area"');
    expect(html).toMatch(/state-done[^]*Authorization[^]*Done/);
    expect(html).toMatch(/state-running[^]*Code[^]*Running/);
    expect(html).toMatch(/state-waiting[^]*Git history[^]*Waiting/);
    // The live region carries the current area only; the clock is outside it.
    expect(html).toMatch(/role="status" aria-live="polite">Code: Running</);
    expect(html).toContain("Activity log");
  });

  it("is translated", () => {
    vi.stubGlobal("navigator", { languages: ["ko-KR"] });
    const html = render();
    expect(html).toContain("경과 시간 1:05");
    expect(html).toContain("권한 확인");
    expect(html).toContain("코드: 진행 중");
    expect(html).toContain("대기 중");
  });
});
