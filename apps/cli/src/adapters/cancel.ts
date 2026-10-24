/** Window in which a second Ctrl+C confirms cancellation of a running scan. */
export const CANCEL_CONFIRM_WINDOW_MS = 5000;

export interface InterruptSource {
  on: (event: "SIGINT", listener: () => void) => unknown;
  off: (event: "SIGINT", listener: () => void) => unknown;
}

export interface CancelController {
  signal: AbortSignal;
  dispose: () => void;
}

/**
 * While no prompt is active (raw mode off), Ctrl+C arrives as SIGINT. The first press asks for
 * confirmation; a second press within the window aborts the scan (exit 130).
 */
export function createCancelController(
  source: InterruptSource,
  warn: (message: string) => void,
  now: () => number = Date.now,
): CancelController {
  const controller = new AbortController();
  let firstPressAt: number | null = null;
  const onInterrupt = (): void => {
    const pressedAt = now();
    if (firstPressAt !== null && pressedAt - firstPressAt <= CANCEL_CONFIRM_WINDOW_MS) {
      warn("Cancelling...");
      controller.abort();
      return;
    }
    firstPressAt = pressedAt;
    warn("Press Ctrl+C again within 5 seconds to cancel.");
  };
  source.on("SIGINT", onInterrupt);
  return {
    signal: controller.signal,
    dispose: () => {
      source.off("SIGINT", onInterrupt);
    },
  };
}
