/**
 * Runs `load` up to `tries` times (waiting 1 s, then 2 s, between tries). Calls `onSuccess` with
 * the first result, or `onGiveUp` after the last failure. The returned function cancels: nothing is
 * called afterwards and no further try starts.
 */
export function loadWithRetry<T>(
  load: () => Promise<T>,
  onSuccess: (value: T) => void,
  onGiveUp: () => void,
  tries = 3,
): () => void {
  let cancelled = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const attempt = (n: number): void => {
    load().then(
      (value) => {
        if (!cancelled) onSuccess(value);
      },
      () => {
        if (cancelled) return;
        if (n >= tries) onGiveUp();
        else timer = setTimeout(() => attempt(n + 1), n * 1000);
      },
    );
  };
  attempt(1);
  return () => {
    cancelled = true;
    if (timer !== undefined) clearTimeout(timer);
  };
}
