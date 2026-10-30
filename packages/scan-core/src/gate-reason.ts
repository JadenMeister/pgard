import type { KnownScanBasisReason, ScanResult } from "@pgard/findings";
import type { AuthorizationOutcome } from "@pgard/policy";

/**
 * Why the authorization gate did not pass, as one plain code (#414). Shared by the CLI's question
 * and the web simple screen so both name the same reason. `not_signed_in` only where a frontend
 * can tell (the web screen); the CLI reports it as `check_failed`.
 */
export type GateFailureReason =
  "no_approval" | "not_signed_in" | "no_github_remote" | "not_a_git_repository" | "check_failed";

type RepositoryBlockCode = NonNullable<AuthorizationOutcome["repositoryCode"]>;

/** Repository check codes that mean "no single github.com remote". */
export const REMOTE_FAILURES: ReadonlySet<RepositoryBlockCode> = new Set<RepositoryBlockCode>([
  "no_remote",
  "remote_not_github",
  "remote_ambiguous",
  "remote_unreadable",
]);

/**
 * The reason of a gate that did not pass, from fixed codes and check statuses only, never the
 * text: a gate that could not finish (`failed`) or a check that could not be verified (a network
 * error, a time-out) is `check_failed`; no usable remote is `no_github_remote`; no Git root or no
 * commit yet is `not_a_git_repository` (there is no revision to authorize, and `scanBasis` has no
 * separate code for it); otherwise a check that did not pass is `no_approval`.
 */
export function gateFailureReason(
  result: ScanResult,
  outcome: AuthorizationOutcome | null,
  isNotSignedIn = false,
): GateFailureReason {
  if (result.overallStatus === "failed") return "check_failed";
  if (isNotSignedIn) return "not_signed_in";
  const code = outcome?.repositoryCode ?? null;
  if (code !== null && REMOTE_FAILURES.has(code)) return "no_github_remote";
  if (code === "not_a_git_root" || code === "no_commit_history") return "not_a_git_repository";
  const first = result.authorization.checks.find((check) => check.status !== "passed");
  return first?.status === "unverifiable" ? "check_failed" : "no_approval";
}

/** `scanBasis.reason` of a code-only scan that follows a gate that said `reason`. */
export function codeOnlyReasonForGate(reason: GateFailureReason): KnownScanBasisReason {
  return reason === "not_signed_in" ? "check_failed" : reason;
}
