import type { ReactNode } from "react";

/** What to show where a list has nothing: a short title and, optionally, what to do next. */
export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty-state">
      <p className="empty-state-title">{title}</p>
      {children === undefined ? null : <p>{children}</p>}
    </div>
  );
}
