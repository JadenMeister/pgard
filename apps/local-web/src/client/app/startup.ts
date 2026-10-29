import { takeTokenFromLocation } from "../api/client";
import { canonicalHash } from "../features/findings/filter-url";

/**
 * Runs before the first render. The fragment may carry a view and filters next to the session
 * token. The token leaves the address first (`takeTokenFromLocation` clears the whole fragment
 * and keeps the token in memory); only the allow-listed view and filter keys are then put back,
 * rebuilt from parsed values, never copied from the original fragment.
 */
export function prepareAddress(win: { location: Location; history: History }): void {
  const restoredHash = canonicalHash(win.location.hash);
  takeTokenFromLocation(win.location, win.history);
  if (restoredHash !== "") {
    win.history.replaceState(
      null,
      "",
      `${win.location.pathname}${win.location.search}${restoredHash}`,
    );
  }
}
