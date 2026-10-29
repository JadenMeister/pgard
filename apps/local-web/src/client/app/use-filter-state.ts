import { useCallback, useEffect, useState } from "react";
import { EMPTY_FILTERS, type FindingFilters } from "../features/findings/filter-findings";
import { buildHash, parseHash } from "../features/findings/filter-url";
import { viewFromHash } from "./views";

export type SetFilters = (patch: Partial<FindingFilters>, options?: { replace?: boolean }) => void;

/**
 * The dashboard filters, kept in the address fragment (`#overview?severity=high&category=xss`) so
 * a copied link, back and forward restore them. The fragment never reaches the server. Only the
 * allow-listed keys are read and written (see `parseHash`), so the session token is never copied
 * into the address or into history.
 *
 * A change pushes a history entry, except while typing in the search box (`replace`), so back
 * steps through filter choices and not through every keystroke.
 */
export function useFilterState(): [FindingFilters, SetFilters, () => void] {
  const [filters, setFiltersState] = useState<FindingFilters>(
    () => parseHash(window.location.hash).filters,
  );
  useEffect(() => {
    const onChange = (): void => setFiltersState(parseHash(window.location.hash).filters);
    window.addEventListener("hashchange", onChange);
    window.addEventListener("popstate", onChange);
    return () => {
      window.removeEventListener("hashchange", onChange);
      window.removeEventListener("popstate", onChange);
    };
  }, []);
  const write = useCallback((next: FindingFilters, replace: boolean): void => {
    const view = viewFromHash(window.location.hash);
    const base = `${window.location.pathname}${window.location.search}`;
    const url = `${base}${buildHash(view, next)}`;
    if (url !== `${base}${window.location.hash}`) {
      if (replace) window.history.replaceState(null, "", url);
      else window.history.pushState(null, "", url);
    }
    setFiltersState(next);
  }, []);
  const setFilters = useCallback<SetFilters>(
    (patch, options = {}) => {
      // Read the address, not the state: two changes in one event must both apply.
      const current = parseHash(window.location.hash).filters;
      write({ ...current, ...patch }, options.replace === true);
    },
    [write],
  );
  const clearFilters = useCallback((): void => write(EMPTY_FILTERS, false), [write]);
  return [filters, setFilters, clearFilters];
}
