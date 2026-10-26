import { describe, expect, it } from "vitest";
import { CLI_TEXT, cliText } from "./cli-text.js";

type Tree = { [key: string]: unknown };

/** Every leaf path of a catalog, with function arity, so a missing or reshaped key shows up. */
function shape(value: unknown, prefix = ""): string[] {
  if (typeof value === "function") return [`${prefix}()${value.length}`];
  if (typeof value !== "object" || value === null) return [prefix];
  return Object.entries(value as Tree).flatMap(([key, child]) =>
    shape(child, prefix === "" ? key : `${prefix}.${key}`),
  );
}

/** Maps whose keys come from the scan (stages, statuses, messages, check ids). */
const OPEN_MAPS = [
  "progress.stage",
  "progress.status",
  "progress.message",
  "checkName",
  "contextName",
];
const own = (path: string): boolean => !OPEN_MAPS.some((map) => path.startsWith(`${map}.`));

describe("CLI text catalogs", () => {
  it("has every English key in Korean, with the same shape", () => {
    const en = shape(CLI_TEXT.en)
      .filter((path) => !path.startsWith("report."))
      .filter(own);
    const ko = new Set(shape(CLI_TEXT.ko).filter(own));
    const missing = en.filter((path) => !ko.has(path));
    expect(missing).toEqual([]);
  });

  it("translates the scan's stages, statuses, known messages and check names", () => {
    const ko = CLI_TEXT.ko;
    for (const stage of ["authorization", "code", "history", "web"]) {
      expect(ko.progress.stage[stage], stage).toBeTruthy();
    }
    for (const status of ["started", "completed", "failed", "skipped"]) {
      expect(ko.progress.status[status], status).toBeTruthy();
    }
    for (const message of ["No confirmed local web target.", "Web scanner unavailable."]) {
      expect(ko.progress.message[message], message).toBeTruthy();
    }
    for (const id of Object.keys(CLI_TEXT.en.checkName)) {
      expect(ko.checkName[id], id).toBeTruthy();
    }
    for (const name of Object.keys(CLI_TEXT.en.contextName)) {
      expect(ko.contextName[name], name).toBeTruthy();
    }
  });

  it("does not leave a Korean string empty or identical to English where it is a sentence", () => {
    const en = CLI_TEXT.en;
    const ko = CLI_TEXT.ko;
    for (const key of [
      "scanResult",
      "summaryTitle",
      "coverageTitle",
      "standardsNote",
      "showAllHint",
    ] as const) {
      expect(ko[key], key).not.toBe("");
      expect(ko[key], key).not.toBe(en[key]);
    }
    expect(ko.notices.firstRun("/d", false)).toContain("--no-store");
  });

  it("uses the four standards states and never claims safety or coverage in a state word", () => {
    for (const locale of ["en", "ko"] as const) {
      const marks = Object.values(CLI_TEXT[locale].standardMark).join(" ");
      expect(marks).not.toMatch(/covered|checked|safe|안전|검사 완료/i);
      expect(Object.keys(CLI_TEXT[locale].standardMark).sort()).toEqual([
        "no_rules",
        "not_run",
        "rules_partial",
        "rules_ran",
      ]);
    }
  });

  it("falls back to English", () => {
    expect(cliText(undefined)).toBe(CLI_TEXT.en);
    expect(cliText("ko")).toBe(CLI_TEXT.ko);
  });

  it("formats elapsed time with the right unit in each language", () => {
    expect(CLI_TEXT.en.elapsedValue(65_000)).toBe("1 m 5 s");
    expect(CLI_TEXT.ko.elapsedValue(65_000)).toBe("1분 5초");
    expect(CLI_TEXT.en.elapsedValue(2_400)).toBe("2.4 s");
    expect(CLI_TEXT.ko.elapsedValue(2_400)).toBe("2.4초");
    // Rounded once before splitting: never "1 m 60 s" or "60 s".
    expect(CLI_TEXT.en.elapsedValue(119_600)).toBe("2 m 0 s");
    expect(CLI_TEXT.en.elapsedValue(59_960)).toBe("1 m 0 s");
    expect(CLI_TEXT.ko.elapsedValue(119_600)).toBe("2분 0초");
    expect(CLI_TEXT.en.elapsedValue(30_400)).toBe("30 s");
  });
});
