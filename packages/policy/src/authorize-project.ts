import type { AuthorizationCheck } from "@pgard/findings";
import {
  AUTHORIZATION_CHECK_ORDER,
  type AuthorizationDependencies,
  type AuthorizationOutcome,
} from "./types.js";

/**
 * The single authorization gate. Every scan and `project verify` calls this; results are never
 * cached between commands. Any check that is not `passed` makes the decision `blocked`.
 *
 * This interface revision blocks unconditionally until the evidence checks land.
 */
export async function authorizeProject(
  _projectRoot: string,
  _deps: AuthorizationDependencies,
): Promise<AuthorizationOutcome> {
  const checks: AuthorizationCheck[] = AUTHORIZATION_CHECK_ORDER.map((id) => ({
    id,
    status: "unverifiable",
    reason: "Authorization checks are not implemented yet; scanning is blocked.",
  }));
  return { summary: { decision: "blocked", checks }, repo: null, revision: null };
}

/**
 * True only when the decision is `allowed` and the summary lists exactly the five checks in
 * `AUTHORIZATION_CHECK_ORDER`, each `passed`. Duplicate, missing or reordered ids fail.
 */
export function isAuthorizationAllowed(outcome: AuthorizationOutcome): boolean {
  const { checks } = outcome.summary;
  return (
    outcome.summary.decision === "allowed" &&
    checks.length === AUTHORIZATION_CHECK_ORDER.length &&
    AUTHORIZATION_CHECK_ORDER.every(
      (id, index) => checks[index]?.id === id && checks[index]?.status === "passed",
    )
  );
}
