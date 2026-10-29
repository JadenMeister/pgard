import type { AnchorHTMLAttributes, ButtonHTMLAttributes, ReactNode } from "react";

export type ButtonVariant = "primary" | "secondary" | "ghost";

interface StyleProps {
  variant?: ButtonVariant;
  size?: "md" | "sm";
}

export function buttonClass({ variant = "secondary", size = "md" }: StyleProps = {}): string {
  return ["btn", variant === "secondary" ? null : `btn-${variant}`, size === "sm" ? "btn-sm" : null]
    .filter((part) => part !== null)
    .join(" ");
}

type ButtonProps = StyleProps &
  Omit<ButtonHTMLAttributes<HTMLButtonElement>, "className"> & { children: ReactNode };

/** A `<button>`; `type="button"` unless a form submit is asked for. */
export function Button({ variant, size, type = "button", children, ...rest }: ButtonProps) {
  return (
    <button {...rest} type={type} className={buttonClass({ variant, size })}>
      {children}
    </button>
  );
}

type ButtonLinkProps = StyleProps &
  Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "className"> & {
    href: string;
    children: ReactNode;
  };

/** A link styled as a button (GitHub pages open in a new tab without an opener). */
export function ButtonLink({ variant, size, children, ...rest }: ButtonLinkProps) {
  return (
    <a {...rest} className={buttonClass({ variant, size })}>
      {children}
    </a>
  );
}
