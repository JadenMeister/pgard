import type { ReactNode } from "react";

interface CardProps {
  title: string;
  step?: number;
  children: ReactNode;
  actions?: ReactNode;
}

export function Card({ title, step, children, actions }: CardProps) {
  return (
    <section className="card" aria-label={title}>
      <header className="card-header">
        <h2>
          {step === undefined ? null : <span className="step">{step}</span>}
          {title}
        </h2>
        {actions}
      </header>
      {children}
    </section>
  );
}

export function Notice({
  tone,
  children,
}: {
  tone: "info" | "warning" | "error";
  children: ReactNode;
}) {
  return (
    <p className={`notice notice-${tone}`} role={tone === "error" ? "alert" : "status"}>
      {children}
    </p>
  );
}
