import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { en } from "./en";
import { I18nProvider, LanguageToggle } from "./I18nProvider";
import {
  detectLanguage,
  LANGUAGE_STORAGE_KEY,
  readStoredLanguage,
  resolveInitialLanguage,
  storeLanguage,
  type LanguageStorage,
} from "./language";
import { ko } from "./ko";
import { formatVendoredSuggestions } from "../features/findings/filter-findings";

/** Every path to a leaf (string, function or array item) in a catalog, with its kind. */
function leaves(value: unknown, prefix = ""): string[] {
  if (typeof value === "string") return [`${prefix}:string`];
  if (typeof value === "function") return [`${prefix}:function`];
  if (Array.isArray(value)) return [`${prefix}:array(${value.length})`];
  return Object.entries(value as Record<string, unknown>).flatMap(([key, child]) =>
    leaves(child, prefix === "" ? key : `${prefix}.${key}`),
  );
}

function fakeStorage(initial: Record<string, string> = {}): LanguageStorage & {
  data: Record<string, string>;
} {
  const data = { ...initial };
  return {
    data,
    getItem: (key) => data[key] ?? null,
    setItem: (key, value) => {
      data[key] = value;
    },
  };
}

describe("message catalogs", () => {
  it("have identical keys, value kinds and array lengths", () => {
    expect(leaves(ko).sort()).toEqual(leaves(en).sort());
  });

  it("have no empty strings", () => {
    const empty = (value: unknown): boolean =>
      typeof value === "string"
        ? value.trim() === ""
        : typeof value === "object" && value !== null && Object.values(value).some(empty);
    expect(empty(en)).toBe(false);
    expect(empty(ko)).toBe(false);
  });

  it("translate the legal notice (same number of points, different text)", () => {
    expect(ko.legal.points).toHaveLength(en.legal.points.length);
    expect(ko.legal.points[0]).not.toBe(en.legal.points[0]);
  });
});

describe("catalog wording", () => {
  it("keeps English words out of Korean inline text", () => {
    const vendored = [{ severity: "critical" as const }, { severity: "high" as const }];
    expect(formatVendoredSuggestions(vendored, ko)).toBe(
      "vendored 코드의 제안 2건 (1 치명적, 1 높음)",
    );
    expect(formatVendoredSuggestions(vendored, en)).toBe(
      "2 suggestions in vendored code (1 critical, 1 high)",
    );
  });

  it("labels the coverage table in Korean and capitalises English status options", () => {
    expect(ko.coverage.caption).toBe("검사 범위");
    expect(en.findings.statusOptions).toEqual({
      confirmed: "Confirmed",
      suspected: "Suspected",
      informational: "Informational",
    });
  });
});

describe("detectLanguage", () => {
  it("picks Korean for any Korean tag", () => {
    expect(detectLanguage(["ko"])).toBe("ko");
    expect(detectLanguage(["ko-KR", "en-US"])).toBe("ko");
    expect(detectLanguage(["KO-kr"])).toBe("ko");
  });

  it("picks English otherwise", () => {
    expect(detectLanguage(["en-US"])).toBe("en");
    expect(detectLanguage(["ja-JP", "de"])).toBe("en");
    expect(detectLanguage([])).toBe("en");
    expect(detectLanguage(undefined)).toBe("en");
  });

  it("respects the order of the preference list", () => {
    expect(detectLanguage(["en-US", "ko-KR"])).toBe("en");
    expect(detectLanguage(["fr-FR", "ko-KR"])).toBe("ko");
  });
});

describe("remembered language", () => {
  it("stores the choice and prefers it over the browser language", () => {
    const storage = fakeStorage();
    expect(resolveInitialLanguage(storage, ["ko-KR"])).toBe("ko");
    storeLanguage(storage, "en");
    expect(storage.data[LANGUAGE_STORAGE_KEY]).toBe("en");
    expect(resolveInitialLanguage(storage, ["ko-KR"])).toBe("en");
    storeLanguage(storage, "ko");
    expect(resolveInitialLanguage(storage, ["en-US"])).toBe("ko");
  });

  it("ignores unknown stored values", () => {
    const storage = fakeStorage({ [LANGUAGE_STORAGE_KEY]: "fr" });
    expect(readStoredLanguage(storage)).toBeNull();
    expect(resolveInitialLanguage(storage, ["ko"])).toBe("ko");
  });

  it("survives storage that throws or is missing", () => {
    const broken: LanguageStorage = {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
    };
    expect(() => storeLanguage(broken, "ko")).not.toThrow();
    expect(readStoredLanguage(broken)).toBeNull();
    expect(resolveInitialLanguage(broken, ["ko-KR"])).toBe("ko");
    expect(resolveInitialLanguage(null, ["en"])).toBe("en");
  });
});

describe("language toggle", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders both languages and marks the active one", () => {
    vi.stubGlobal("navigator", { languages: ["ko-KR"] });
    const html = renderToStaticMarkup(
      <I18nProvider>
        <LanguageToggle />
      </I18nProvider>,
    );
    expect(html).toContain("한국어");
    expect(html).toContain("English");
    expect(html).toContain('aria-label="언어"');
    expect(html).toMatch(/aria-pressed="true"[^>]*lang="ko"|lang="ko"[^>]*aria-pressed="true"/);
  });

  it("defaults to English for a non-Korean browser", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    const html = renderToStaticMarkup(
      <I18nProvider>
        <LanguageToggle />
      </I18nProvider>,
    );
    expect(html).toContain('aria-label="Language"');
  });
});
