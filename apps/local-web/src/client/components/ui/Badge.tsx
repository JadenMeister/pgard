import type { ReactNode } from "react";
import type { Severity } from "@pgard/findings";
import { useI18n } from "../../i18n/I18nProvider";

/**
 * A status as plain text with a small dot (`badge-<kind>` picks the dot's tone). Not a pill:
 * the only outlined label on the page is the NEW marker of a baseline scan.
 */
export function Badge({ kind, children }: { kind?: string; children: ReactNode }) {
  return <span className={kind === undefined ? "badge" : `badge badge-${kind}`}>{children}</span>;
}

/** The severity name after a small square in the severity colour. */
export function SeverityLabel({ severity }: { severity: Severity }) {
  const { m } = useI18n();
  return <span className={`sev-label sev-${severity}`}>{m.severity[severity]}</span>;
}
