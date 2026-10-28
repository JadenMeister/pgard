import type { ReactNode } from "react";
import { HelpTip } from "./HelpTip";

interface SectionHeaderProps {
  title: string;
  /** Id of the heading, for `aria-labelledby` on the enclosing region. */
  id?: string;
  /** Short context shown next to the title (a count, a status). */
  meta?: ReactNode;
  /** Explanatory text, behind a small "?" so it does not crowd the page. */
  help?: ReactNode;
  actions?: ReactNode;
  level?: 2 | 3;
}

/** A compact heading row: title, optional meta and help, actions on the right. */
export function SectionHeader({ title, id, meta, help, actions, level = 2 }: SectionHeaderProps) {
  const Heading = level === 2 ? "h2" : "h3";
  return (
    <div className={`section-header level-${level}`}>
      <Heading id={id} className="section-title">
        {title}
      </Heading>
      {meta === undefined || meta === null ? null : <span className="section-meta">{meta}</span>}
      {help === undefined || help === null ? null : <HelpTip>{help}</HelpTip>}
      {actions === undefined || actions === null ? null : (
        <div className="section-actions">{actions}</div>
      )}
    </div>
  );
}
