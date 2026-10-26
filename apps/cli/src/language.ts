import type { RuleLocale } from "@pgard/findings";
import { parseLanguageValue } from "./options.js";

export type Environment = Readonly<Record<string, string | undefined>>;

/** `ko`, `ko_KR.UTF-8`, `ko-KR` -> true. */
function isKoreanLocale(value: string | undefined): boolean {
  return value !== undefined && /^ko(?:[._@-]|$)/i.test(value.trim());
}

/**
 * The first non-empty locale variable decides (POSIX precedence: LC_ALL, LC_MESSAGES, LANG), so
 * `LC_ALL=C` is not overridden by a Korean `LANG`.
 */
function localeFromEnvironment(env: Environment): string | undefined {
  for (const name of ["LC_ALL", "LC_MESSAGES", "LANG"]) {
    const value = env[name];
    if (value !== undefined && value.trim() !== "") return value;
  }
  return undefined;
}

/** Windows sets no locale variables; ask the runtime. Other systems use the variables only. */
function systemLocale(): string | undefined {
  if (process.platform !== "win32") return undefined;
  try {
    return Intl.DateTimeFormat().resolvedOptions().locale;
  } catch {
    return undefined;
  }
}

export interface LanguageInput {
  /** `--lang` value, already validated, or null when the option was not given. */
  flag: RuleLocale | null;
  env: Environment;
  /** Operating-system locale, for platforms (Windows) that set none of the variables. */
  platformLocale?: () => string | undefined;
}

/**
 * Language of rule texts: `--lang`, then `PGARD_LANG`, then the system locale, then English. An
 * invalid `PGARD_LANG` is a usage error rather than a silent fallback.
 */
export function resolveLanguage({
  flag,
  env,
  platformLocale = systemLocale,
}: LanguageInput): RuleLocale {
  if (flag !== null) return flag;
  const fromEnv = env.PGARD_LANG;
  if (fromEnv !== undefined && fromEnv !== "") return parseLanguageValue("PGARD_LANG", fromEnv);
  const locale = localeFromEnvironment(env) ?? platformLocale();
  return isKoreanLocale(locale) ? "ko" : "en";
}
