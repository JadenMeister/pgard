import type { ReactNode } from "react";
import { useI18n } from "../../i18n/I18nProvider";

/**
 * Explanatory text behind a small "?" disclosure. A native `<details>`, so it works with the
 * keyboard and without script, and the text stays in the page for find-in-page once opened.
 */
export function HelpTip({ children, label }: { children: ReactNode; label?: string }) {
  const { m } = useI18n();
  return (
    <details className="help-tip">
      <summary aria-label={label ?? m.help.label} title={label ?? m.help.label}>
        ?
      </summary>
      <div className="help-tip-body">{children}</div>
    </details>
  );
}
