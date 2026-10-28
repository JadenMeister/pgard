import type { ReactNode } from "react";

/** A short message in a bordered box; errors are announced right away, the rest politely. */
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
