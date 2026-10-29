import { describe, expect, it } from "vitest";
import { PRECOMMIT_TEXT_CATALOG } from "./text.js";

const HANGUL = /[가-힣]/;

/** Calls every message function with sample arguments and collects `path -> text`. */
function flatten(value: unknown, prefix = ""): Map<string, string> {
  const entries = new Map<string, string>();
  if (typeof value === "string") {
    entries.set(prefix, value);
  } else if (typeof value === "function") {
    entries.set(prefix, (value as (...args: unknown[]) => string)("A", "B", "C", "D"));
  } else if (typeof value === "object" && value !== null) {
    for (const [key, child] of Object.entries(value)) {
      for (const [path, text] of flatten(child, prefix === "" ? key : `${prefix}.${key}`)) {
        entries.set(path, text);
      }
    }
  }
  return entries;
}

describe("precommit text catalog", () => {
  const en = flatten(PRECOMMIT_TEXT_CATALOG.en);
  const ko = flatten(PRECOMMIT_TEXT_CATALOG.ko);

  it("has the same entries in English and Korean", () => {
    expect([...ko.keys()].sort()).toEqual([...en.keys()].sort());
    expect(en.size).toBeGreaterThan(40);
  });

  it("writes every Korean sentence in Korean", () => {
    for (const [key, text] of ko) {
      // A product name with a file name needs no translation.
      if (key === "snippet.husky") continue;
      // A line made only of the sample arguments may stay as it is.
      if (text === en.get(key) && !/[a-z]{4,}\s[a-z]{3,}/.test(text)) continue;
      expect(text, key).toMatch(HANGUL);
    }
  });

  it("keeps the variables and names the exact commands a person would type", () => {
    for (const catalog of [en, ko]) {
      expect(catalog.get("install.installed")).toContain("A");
      expect(catalog.get("uninstall.removed")).toContain("A");
      expect(catalog.get("authorizationHint")).toContain("pgard project verify");
      expect(catalog.get("authorizationHint")).toContain("pgard login");
      expect(catalog.get("install.globalHooksPathNote")).toContain(
        "git config --get core.hooksPath",
      );
      expect(catalog.get("decisionBlockedFindings")).toContain("--no-verify");
    }
  });
});
