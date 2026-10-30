import {
  useId,
  useRef,
  useState,
  type FocusEvent,
  type KeyboardEvent,
  type ReactNode,
} from "react";

/** What a user action does to the popover: the whole behaviour, without the DOM. */
export type PopoverAction = "toggle" | "escape" | "focus-left";

/** Click, Enter and Space toggle; Esc and focus leaving the popover close it. */
export function nextPopoverOpen(open: boolean, action: PopoverAction): boolean {
  if (action === "toggle") return !open;
  return false;
}

/**
 * A circled "?" button that toggles a small popover. A real button, so Enter and Space work; Esc
 * closes it and returns focus to the button; moving focus away closes it. No inline script or
 * style (the CSP forbids both): the look is in the stylesheet.
 */
export function HelpPopover({ label, children }: { label: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const bodyId = useId();
  const button = useRef<HTMLButtonElement>(null);
  const onKeyDown = (event: KeyboardEvent<HTMLElement>): void => {
    if (event.key !== "Escape" || !open) return;
    event.stopPropagation();
    setOpen(nextPopoverOpen(open, "escape"));
    button.current?.focus();
  };
  const onBlur = (event: FocusEvent<HTMLElement>): void => {
    if (open && !event.currentTarget.contains(event.relatedTarget)) {
      setOpen(nextPopoverOpen(open, "focus-left"));
    }
  };
  return (
    <span className="help-popover" onKeyDown={onKeyDown} onBlur={onBlur}>
      <button
        ref={button}
        type="button"
        className="help-popover-button"
        aria-label={label}
        aria-expanded={open}
        aria-controls={bodyId}
        onClick={() => setOpen((value) => nextPopoverOpen(value, "toggle"))}
      >
        ?
      </button>
      <span
        id={bodyId}
        className="help-popover-body"
        role="group"
        aria-label={label}
        hidden={!open}
      >
        {children}
      </span>
    </span>
  );
}
