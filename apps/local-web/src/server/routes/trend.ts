import { isAuthorizationAllowed } from "@pgard/scan-core";
import type { TrendResponse } from "../../shared/api-types.js";
import { buildTrend } from "../trend/build-trend.js";
import type { ApiContext, ApiHandler } from "./api.js";
import { ApiError } from "./api-error.js";

/** Environment opt-out shared with the CLI: no scan is stored and none is read. */
export const NO_STORE_ENV = "PGARD_NO_STORE";

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
  let answer: TrendResponse;
  try {
    answer = await buildTrend(store, repositoryId, context.deps.now());
  } catch {
    answer = { kind: "unavailable", why: "unreadable" };
  }
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
