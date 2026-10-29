import { isAuthorizationAllowed } from "@pgard/scan-core";
import type { TrendResponse } from "../../shared/api-types.js";
import type { SessionState } from "../session/session-state.js";
import { buildTrend } from "../trend/build-trend.js";
import type { ApiContext, ApiHandler } from "./api.js";
import { ApiError } from "./api-error.js";

/** Environment opt-out shared with the CLI: no scan is stored and none is read. */
export const NO_STORE_ENV = "PGARD_NO_STORE";

/**
 * One read per project, authorization and short time window: concurrent requests share the
 * in-flight read, and a repeat within `TREND_CACHE_MS` is answered from memory, so switching
 * tabs does not re-read up to 100 files of 8 MiB each. The entry is tied to the epoch and to the
 * authorization outcome object, so a project change or a new check never reuses it. A scan saved
 * from a terminal shows up after the window.
 */
export const TREND_CACHE_MS = 5_000;

interface CachedTrend {
  epoch: number;
  outcome: object;
  at: number;
  answer: Promise<TrendResponse>;
}

const cache = new WeakMap<SessionState, CachedTrend>();

/**
 * `GET /api/trend`: read-only. The repository id comes only from this session's allowed
 * authorization check of the selected project (never from the request), and the answer holds
 * counts and dates of that repository's saved CLI scans. Dashboard scans are not stored.
 */
export const getTrend: ApiHandler = async (context: ApiContext) => {
  const { state } = context;
  const project = state.project;
  if (project === null) throw new ApiError(409, "no_project", "Choose a project first.");
  const epoch = state.projectEpoch;
  if (context.deps.isStoreDisabled === true || context.env[NO_STORE_ENV] === "1") {
    return { kind: "disabled" } satisfies TrendResponse;
  }
  const outcome = state.auth.status === "done" ? state.auth.outcome : null;
  const repositoryId = outcome?.repositoryId;
  if (outcome === null || !isAuthorizationAllowed(outcome) || typeof repositoryId !== "number") {
    return { kind: "unavailable", why: "not-verified" } satisfies TrendResponse;
  }
  const store = context.deps.openResultStore?.(context.env) ?? null;
  if (store === null) return { kind: "unavailable", why: "no-store-dir" } satisfies TrendResponse;
  const now = context.deps.now();
  let cached = cache.get(state);
  // A clock that moved back (`now < at`) is not a hit: fail closed.
  const isHit =
    cached !== undefined &&
    cached.epoch === epoch &&
    cached.outcome === outcome &&
    now >= cached.at &&
    now - cached.at < TREND_CACHE_MS;
  if (!isHit) {
    const answerPromise = buildTrend(store, repositoryId, now).catch((): TrendResponse => ({
      kind: "unavailable",
      why: "unreadable",
    }));
    cached = { epoch, outcome, at: now, answer: answerPromise };
    cache.set(state, cached);
  }
  const answer = await (cached as CachedTrend).answer;
  // A project change or a new authorization while the files were read: the answer belongs to
  // the old repository and is discarded.
  if (state.project !== project || state.projectEpoch !== epoch || state.auth.outcome !== outcome) {
    throw new ApiError(
      409,
      "project_changed",
      "The project changed while this was running; the result was discarded.",
    );
  }
  return answer;
};
