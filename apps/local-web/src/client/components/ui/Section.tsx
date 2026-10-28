import { useId, type ReactNode } from "react";
import { SectionHeader } from "./SectionHeader";

interface SectionProps {
  title: string;
  meta?: ReactNode;
  help?: ReactNode;
  actions?: ReactNode;
  level?: 2 | 3;
  className?: string;
  children: ReactNode;
}

/**
 * A plain region on the page background: a heading row and its content, labelled by the heading.
 * No box: grouping comes from the heading and spacing, borders only where rows need them.
 */
export function Section({ title, meta, help, actions, level, className, children }: SectionProps) {
  const headingId = useId();
  return (
    <section
      className={className === undefined ? "section" : `section ${className}`}
      aria-labelledby={headingId}
    >
      <SectionHeader
        id={headingId}
        title={title}
        meta={meta}
        help={help}
        actions={actions}
        level={level}
      />
      {children}
    </section>
  );
}
