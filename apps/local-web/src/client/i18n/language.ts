import { en } from "./en";
import { ko } from "./ko";
import type { Language, Messages } from "./types";

export const LANGUAGES: readonly Language[] = ["ko", "en"];
export const LANGUAGE_STORAGE_KEY = "pgard.dashboard.language";

export const CATALOGS: Record<Language, Messages> = { ko, en };

export function isLanguage(value: unknown): value is Language {
  return value === "ko" || value === "en";
}

/** The first browser-preferred language that is Korean or English; English when neither is. */
export function detectLanguage(languages: readonly string[] | undefined): Language {
  for (const entry of languages ?? []) {
    const tag = entry.toLowerCase();
    if (tag === "ko" || tag.startsWith("ko-")) return "ko";
    if (tag === "en" || tag.startsWith("en-")) return "en";
  }
  return "en";
}

/** Minimal storage surface so tests can pass a fake. */
export interface LanguageStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

/** The remembered choice, or null when none is stored or storage is unavailable. */
export function readStoredLanguage(storage: LanguageStorage | null): Language | null {
  try {
    const value = storage?.getItem(LANGUAGE_STORAGE_KEY) ?? null;
    return isLanguage(value) ? value : null;
  } catch {
    return null;
  }
}

export function storeLanguage(storage: LanguageStorage | null, language: Language): void {
  try {
    storage?.setItem(LANGUAGE_STORAGE_KEY, language);
  } catch {
    // Storage can be blocked (private window, cleared site data); the choice then lasts for this page only.
  }
}

/** Stored choice first, then the browser's language list. */
export function resolveInitialLanguage(
  storage: LanguageStorage | null,
  languages: readonly string[] | undefined,
): Language {
  return readStoredLanguage(storage) ?? detectLanguage(languages);
}

/** `window.localStorage`, or null when even touching it throws. */
export function getBrowserStorage(): LanguageStorage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}
