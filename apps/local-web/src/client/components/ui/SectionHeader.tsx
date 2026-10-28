import type { ReactNode } from "react";

interface SectionHeaderProps {
  title: string;
  /** Id of the heading, for `aria-labelledby` on the enclosing region. */
  id?: string;
  step?: number | undefined;
  description?: ReactNode;
  actions?: ReactNode;
  /** Heading level; cards are level 2 under the page's single h1. */
  level?: 2 | 3;
}

/** A bold heading with an optional step number, a muted description and actions on the right. */
export function SectionHeader({
  title,
  id,
  step,
  description,
  actions,
  level = 2,
}: SectionHeaderProps) {
  const Heading = level === 2 ? "h2" : "h3";
  return (
    <header className="section-header">
      <div className="section-heading">
        {step === undefined ? null : (
          <span className="step-num" aria-hidden="true">
            {step}
          </span>
        )}
        <Heading id={id} className="section-title">
          {title}
        </Heading>
      </div>
      {actions === undefined || actions === null ? null : (
        <div className="section-actions">{actions}</div>
      )}
      {description === undefined || description === null ? null : (
        <p className="section-description">{description}</p>
      )}
    </header>
  );
}
