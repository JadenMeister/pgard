import { useSyncExternalStore } from "react";
import { EMPTY_FILTERS, type FindingFilters } from "../features/findings/filter-findings";
import { buildHash, parseHash } from "../features/findings/filter-url";
import { viewFromHash } from "./views";

export type SetFilters = (patch: Partial<FindingFilters>, options?: { replace?: boolean }) => void;

/** The part of `window` the filter state needs (a fake in tests). */
export interface AddressWindow {
  location: { hash: string; pathname: string; search: string };
  history: {
    pushState(state: unknown, title: string, url: string): void;
    replaceState(state: unknown, title: string, url: string): void;
  };
  addEventListener(type: "hashchange" | "popstate", listener: () => void): void;
  removeEventListener(type: "hashchange" | "popstate", listener: () => void): void;
}

export interface FilterStore {
  subscribe: (listener: () => void) => () => void;
  getSnapshot: () => FindingFilters;
  set: SetFilters;
  clear: () => void;
}

/**
 * The dashboard filters, kept in the address fragment (`#overview?severity=high&category=xss`) so
 * a copied link, back and forward restore them. The fragment never reaches the server. Only the
 * allow-listed keys are read and written (see `parseHash`), so the session token is never copied
 * into the address or into history.
 *
 * A change pushes a history entry, except while typing in the search box (`replace`), so back
 * steps through filter choices and not through every keystroke. The address is the one source of
 * truth: the store re-reads it on `hashchange` and `popstate` (back and forward, a view change).
 */
export function createFilterStore(win: AddressWindow): FilterStore {
  const listeners = new Set<() => void>();
  let lastHash = win.location.hash;
  let snapshot = parseHash(lastHash).filters;
  const notify = (): void => listeners.forEach((listener) => listener());
  const onAddressChange = (): void => notify();
  const getSnapshot = (): FindingFilters => {
    // Keep the same object while the address is unchanged (required by useSyncExternalStore).
    if (win.location.hash !== lastHash) {
      lastHash = win.location.hash;
      snapshot = parseHash(lastHash).filters;
    }
    return snapshot;
  };
  const write = (next: FindingFilters, replace: boolean): void => {
    const view = viewFromHash(win.location.hash);
    const base = `${win.location.pathname}${win.location.search}`;
    const url = `${base}${buildHash(view, next)}`;
    if (url !== `${base}${win.location.hash}`) {
      if (replace) win.history.replaceState(null, "", url);
      else win.history.pushState(null, "", url);
    }
    notify();
  };
  return {
    subscribe(listener) {
      if (listeners.size === 0) {
        win.addEventListener("hashchange", onAddressChange);
        win.addEventListener("popstate", onAddressChange);
      }
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
        if (listeners.size === 0) {
          win.removeEventListener("hashchange", onAddressChange);
          win.removeEventListener("popstate", onAddressChange);
        }
      };
    },
    getSnapshot,
    set(patch, options = {}) {
      // Read the address, not the snapshot: two changes in one event must both apply.
      const current = parseHash(win.location.hash).filters;
      // Typing replaces the entry, except the first character, which adds one: back then returns
      // to the filters as they were before the search began.
      const replace = options.replace === true && current.text.trim() !== "";
      write({ ...current, ...patch }, replace);
    },
    clear: () => write(EMPTY_FILTERS, false),
  };
}

let browserStore: FilterStore | null = null;
const getBrowserStore = (): FilterStore => (browserStore ??= createFilterStore(window));

/** The filters from the address, a setter and "clear all". */
export function useFilterState(): [FindingFilters, SetFilters, () => void] {
  const store = getBrowserStore();
  const filters = useSyncExternalStore(store.subscribe, store.getSnapshot);
  return [filters, store.set, store.clear];
}
