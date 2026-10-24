import { useEffect, useRef } from "react";

/** Calls `poll` every `intervalMs` while `isActive`; stops on unmount. */
export function usePolling(poll: () => Promise<void>, intervalMs: number, isActive: boolean): void {
  const pollRef = useRef(poll);
  pollRef.current = poll;
  useEffect(() => {
    if (!isActive) return undefined;
    let isCancelled = false;
    const tick = async (): Promise<void> => {
      if (isCancelled) return;
      await pollRef.current().catch(() => undefined);
      if (!isCancelled) timer = window.setTimeout(() => void tick(), intervalMs);
    };
    let timer = window.setTimeout(() => void tick(), intervalMs);
    return () => {
      isCancelled = true;
      window.clearTimeout(timer);
    };
  }, [intervalMs, isActive]);
}
