import type { ReactNode } from "react";
import type { Severity } from "@pgard/findings";
import { useI18n } from "../../i18n/I18nProvider";

/**
 * A pill with a coloured dot. `kind` selects the tone through a `badge-<kind>` class (a check,
 * coverage or finding status); the label is always written out, colour only supports it.
 */
export function Badge({ kind, children }: { kind?: string; children: ReactNode }) {
  return <span className={kind === undefined ? "badge" : `badge badge-${kind}`}>{children}</span>;
}

/** The severity name with the severity colour on the dot and outline. */
export function SeverityPill({ severity }: { severity: Severity }) {
  const { m } = useI18n();
  return <span className={`badge sev-badge sev-${severity}`}>{m.severity[severity]}</span>;
}
