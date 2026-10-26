// corpus: expect=none
import type { HTMLAttributes } from "react";

export function Card({ title, ...rest }: HTMLAttributes<HTMLDivElement> & { title: string }) {
  const base = { className: "card", role: "group" };
  return (
    <div {...base} {...rest}>
      <h2>{title}</h2>
    </div>
  );
}
