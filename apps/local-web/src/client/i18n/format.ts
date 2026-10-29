import type { Language } from "./types";

/** BCP 47 locale for each UI language; formatting never falls back to the system locale. */
export const LOCALES: Record<Language, string> = { en: "en-US", ko: "ko-KR" };

/** A clock time ("10:35:58 AM" / "오전 10:35:58") in the dashboard language. */
export function formatTime(epochMs: number, language: Language): string {
  return new Date(epochMs).toLocaleTimeString(LOCALES[language]);
}
