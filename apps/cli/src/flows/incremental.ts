import type { IncrementalState, ScanScope } from "@pgard/findings";
import {
  isAuthorizationAllowed,
  type AuthorizationOutcome,
  type IncrementalBaseLoad,
  type IncrementalDependencies,
} from "@pgard/scan-core";
import type { CommandContext } from "../context.js";
import { NO_STORE_ENV } from "./store-result.js";

/** Stored scans older than this are not built on (the store prunes them on the next save). */
export const INCREMENTAL_MAX_AGE_DAYS = 90;
const MS_PER_DAY = 86_400_000;

export interface IncrementalHandle {
  dependencies: IncrementalDependencies;
  /** The state the scan produced, to store next to its result; null when it produced none. */
  takeState: () => IncrementalState | null;
}

function sameScopes(a: readonly ScanScope[], b: readonly ScanScope[]): boolean {
  return a.length === b.length && a.every((scope, index) => scope === b[index]);
}

/**
 * Incremental-scan dependencies for one scan: the newest stored scan of this repository that has
 * the same scopes and is not expired, read through the same store (and the same opt-outs) as the
 * comparison with the last scan. `--full` skips the read.
 */
export function createIncrementalHandle(
  context: CommandContext,
  options: { noStore: boolean; full: boolean },
): IncrementalHandle {
  let state: IncrementalState | null = null;
  const dependencies: IncrementalDependencies = {
    forceFull: options.full,
    loadBase: async (
      outcome: AuthorizationOutcome,
      scopes: readonly ScanScope[],
    ): Promise<IncrementalBaseLoad> => {
      if (options.noStore || context.io.env[NO_STORE_ENV] === "1") {
        return { kind: "none", reason: "store_unavailable" };
      }
      const store = context.deps.openResultStore(context.io.env);
      const repositoryId = outcome.repositoryId;
      if (store === null) return { kind: "none", reason: "store_unavailable" };
      if (!isAuthorizationAllowed(outcome) || typeof repositoryId !== "number") {
        return { kind: "none", reason: "no_previous_scan" };
      }
      let otherScopes = 0;
      let expired = 0;
      const now = Date.now();
      const found = await store.findNewest(repositoryId, (scan) => {
        if (!sameScopes(scan.result.requestedScopes, scopes)) {
          otherScopes += 1;
          return "other scopes";
        }
        if (now - scan.savedAt.getTime() > INCREMENTAL_MAX_AGE_DAYS * MS_PER_DAY) {
          expired += 1;
          return "expired";
        }
        return null;
      });
      // A stored file that could not be read may have been the newest one: fail closed.
      const unreadable = found.warnings.length - otherScopes - expired;
      if (unreadable > 0) return { kind: "none", reason: "previous_unreadable" };
      if (found.scan === null) {
        if (expired > 0) return { kind: "none", reason: "previous_unreadable" };
        return { kind: "none", reason: otherScopes > 0 ? "scopes_changed" : "no_previous_scan" };
      }
      return {
        kind: "found",
        base: { result: found.scan.result, state: found.scan.incrementalState },
      };
    },
    onState: (produced) => {
      state = produced;
    },
  };
  return { dependencies, takeState: () => state };
}
