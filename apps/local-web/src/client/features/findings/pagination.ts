import { EMPTY_FILTERS, type FindingFilters } from "./filter-findings";

export const PAGE_SIZES = [25, 50, 100] as const;
export const DEFAULT_PAGE_SIZE: number = PAGE_SIZES[0];

export interface Page<T> {
  items: T[];
  /** 1-based, clamped to the pages that exist. */
  page: number;
  pageCount: number;
  /** 1-based position of the first and last item shown; both 0 when there are no items. */
  start: number;
  end: number;
  total: number;
}

/** One page of `items`. Out-of-range pages are clamped, so a shrinking list never shows nothing. */
export function paginate<T>(items: readonly T[], page: number, pageSize: number): Page<T> {
  const size = Math.max(1, Math.floor(pageSize));
  const total = items.length;
  const pageCount = Math.max(1, Math.ceil(total / size));
  const current = Math.min(Math.max(1, Math.floor(page)), pageCount);
  const offset = (current - 1) * size;
  const pageItems = items.slice(offset, offset + size);
  return {
    items: pageItems,
    page: current,
    pageCount,
    start: total === 0 ? 0 : offset + 1,
    end: offset + pageItems.length,
    total,
  };
}

/**
 * Page numbers to offer, with `null` for a gap: always the first and last page and up to one
 * neighbour on each side of the current one, e.g. 1 … 4 5 6 … 12.
 */
export function pageWindow(page: number, pageCount: number): Array<number | null> {
  const wanted = new Set([1, pageCount, page - 1, page, page + 1]);
  const pages = [...wanted]
    .filter((entry) => entry >= 1 && entry <= pageCount)
    .sort((a, b) => a - b);
  const output: Array<number | null> = [];
  for (const entry of pages) {
    const previous = output.at(-1);
    if (typeof previous === "number" && entry - previous === 2) output.push(previous + 1);
    else if (typeof previous === "number" && entry - previous > 2) output.push(null);
    output.push(entry);
  }
  return output;
}

/**
 * The page a pager button should go to, or `null` when the click changes nothing (the current
 * page, or outside 1..pageCount). Only a real page change moves focus to the range line.
 */
export function pageRequest(current: number, next: number, pageCount: number): number | null {
  if (next === current || next < 1 || next > pageCount) return null;
  return next;
}

/** Lists that page on their own: the regular findings and each separate group. */
export type FindingListId = "primary" | "test" | "vendored" | "suppressed" | "baseline";

export interface FindingsListState {
  filters: FindingFilters;
  pageSize: number;
  /** Current page per list; a list that is not here is on page 1. */
  pages: Partial<Record<FindingListId, number>>;
}

export type FindingsListAction =
  | { type: "filter"; patch: Partial<FindingFilters> }
  | { type: "page"; list: FindingListId; page: number }
  | { type: "pageSize"; pageSize: number };

export const INITIAL_LIST_STATE: FindingsListState = {
  filters: EMPTY_FILTERS,
  pageSize: DEFAULT_PAGE_SIZE,
  pages: {},
};

/**
 * Filters, page size and pages of the results panel. Changing a filter or the page size sends
 * every list back to page 1, so the person always sees the start of what now matches.
 */
export function findingsListReducer(
  state: FindingsListState,
  action: FindingsListAction,
): FindingsListState {
  switch (action.type) {
    case "filter":
      return { ...state, filters: { ...state.filters, ...action.patch }, pages: {} };
    case "pageSize":
      return { ...state, pageSize: action.pageSize, pages: {} };
    case "page":
      return { ...state, pages: { ...state.pages, [action.list]: Math.max(1, action.page) } };
  }
}
