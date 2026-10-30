import { useEffect, useRef, useState, type ReactNode } from "react";
import { useI18n } from "../../i18n/I18nProvider";

/** Click, Enter and Space (the native summary) toggle; Esc and a press outside close. */
export type HelpTipEvent = "toggle" | "escape" | "outside";

export function nextHelpTipOpen(open: boolean, event: HelpTipEvent): boolean {
  return event === "toggle" ? !open : false;
}

/**
 * Explanatory text behind a small "?" disclosure. A native `<details>`, so it works with the
 * keyboard and without inline script. While open, Esc closes it (focus returns to the "?") and so
 * does a press outside it; a press inside the text leaves it open.
 */
export function HelpTip({ children, label }: { children: ReactNode; label?: string }) {
  const { m } = useI18n();
  const [open, setOpen] = useState(false);
  const details = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent): void => {
      if (event.target instanceof Node && details.current?.contains(event.target)) return;
      setOpen((value) => nextHelpTipOpen(value, "outside"));
    };
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key !== "Escape") return;
      setOpen((value) => nextHelpTipOpen(value, "escape"));
      // Give focus back to the "?" only when it was inside the tip (or nowhere).
      const active = document.activeElement;
      if (active === document.body || (active && details.current?.contains(active))) {
        details.current?.querySelector("summary")?.focus();
      }
    };
    const onFocusOut = (event: FocusEvent): void => {
      const next = event.relatedTarget;
      if (next instanceof Node && !details.current?.contains(next)) {
        setOpen((value) => nextHelpTipOpen(value, "outside"));
      }
    };
    const element = details.current;
    element?.addEventListener("focusout", onFocusOut);
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
      element?.removeEventListener("focusout", onFocusOut);
    };
  }, [open]);
  return (
    <details
      ref={details}
      className="help-tip"
      open={open}
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary aria-label={label ?? m.help.label} title={label ?? m.help.label}>
        ?
      </summary>
      <div className="help-tip-body">{children}</div>
    </details>
  );
}
