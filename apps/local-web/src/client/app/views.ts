import { useCallback, useEffect, useState } from "react";

/** The dashboard's views, in nav order. Each has its own URL hash (`#findings`) for linking. */
export const VIEWS = [
  "overview",
  "findings",
  "coverage",
  "standards",
  "rules",
  "trend",
  "export",
] as const;
export type View = (typeof VIEWS)[number];

/**
 * The view named by a location hash; `overview` for anything else. The session token also
 * arrives in the hash (`#token=...`) but is removed before the app renders.
 */
export function viewFromHash(hash: string): View {
  // `#findings?severity=high`: the part after `?` is the filter state (see filter-url.ts).
  const name = hash.replace(/^#/, "").split("?")[0] ?? "";
  return (VIEWS as readonly string[]).includes(name) ? (name as View) : "overview";
}

/**
 * The fragment (without `#`) to assign to open `next`, or `null` when the address already shows
 * it. The filters after `?` travel with the view.
 */
export function hashForView(hash: string, next: View): string | null {
  const query = hash.includes("?") ? hash.slice(hash.indexOf("?")) : "";
  if (viewFromHash(hash) === next && hash.startsWith(`#${next}`)) return null;
  return `${next}${query}`;
}

/** The current view from `location.hash`, following back and forward navigation. */
export function useHashView(): [View, (view: View) => void] {
  const [view, setViewState] = useState<View>(() => viewFromHash(window.location.hash));
  useEffect(() => {
    const onChange = (): void => setViewState(viewFromHash(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  const setView = useCallback((next: View) => {
    const target = hashForView(window.location.hash, next);
    if (target !== null) window.location.hash = target;
    setViewState(next);
  }, []);
  return [view, setView];
}
