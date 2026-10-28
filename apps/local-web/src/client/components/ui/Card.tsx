import { useId, type ReactNode } from "react";
import { SectionHeader } from "./SectionHeader";

interface CardProps {
  title: string;
  /** Step number in the dashboard flow, shown before the title. */
  step?: number;
  /** One muted line under the title. */
  description?: ReactNode;
  children: ReactNode;
  actions?: ReactNode;
  className?: string;
}

/** An unfilled, outlined region with a heading; labelled by that heading for assistive tech. */
export function Card({ title, step, description, children, actions, className }: CardProps) {
  const headingId = useId();
  return (
    <section
      className={className === undefined ? "card" : `card ${className}`}
      aria-labelledby={headingId}
    >
      <SectionHeader
        id={headingId}
        title={title}
        step={step}
        description={description}
        actions={actions}
      />
      {children}
    </section>
  );
}
