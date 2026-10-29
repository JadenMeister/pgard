import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { Button } from "../components/ui/Button";
import { en } from "./en";
import {
  CATALOGS,
  getBrowserStorage,
  LANGUAGES,
  resolveInitialLanguage,
  storeLanguage,
} from "./language";
import type { Language, Messages } from "./types";

interface I18nValue {
  language: Language;
  setLanguage: (language: Language) => void;
  m: Messages;
}

const I18nContext = createContext<I18nValue>({
  language: "en",
  setLanguage: () => undefined,
  m: en,
});

export function I18nProvider({ children }: { children: ReactNode }) {
  const [language, setLanguageState] = useState<Language>(() =>
    resolveInitialLanguage(getBrowserStorage(), navigator.languages),
  );

  useEffect(() => {
    document.documentElement.lang = language;
  }, [language]);

  const value = useMemo<I18nValue>(
    () => ({
      language,
      setLanguage: (next) => {
        setLanguageState(next);
        storeLanguage(getBrowserStorage(), next);
      },
      m: CATALOGS[language],
    }),
    [language],
  );
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nValue {
  return useContext(I18nContext);
}

/** Header toggle: one button per language, the active one is pressed. */
export function LanguageToggle() {
  const { language, setLanguage, m } = useI18n();
  return (
    <div className="lang-toggle" role="group" aria-label={m.language.label}>
      {LANGUAGES.map((entry) => (
        <Button
          key={entry}
          variant="ghost"
          size="sm"
          aria-pressed={entry === language}
          lang={entry}
          onClick={() => setLanguage(entry)}
        >
          {m.language[entry]}
        </Button>
      ))}
    </div>
  );
}
