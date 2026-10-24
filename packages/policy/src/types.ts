import type { AuthorizationCheckId, AuthorizationSummary } from "@pgard/findings";
import type { GitRunner } from "@pgard/git-history";
import type { GitHubSessionProvider } from "@pgard/github-auth";

/** Order in which checks are evaluated and reported. */
export const AUTHORIZATION_CHECK_ORDER: readonly AuthorizationCheckId[] = [
  "repository",
  "github_identity",
  "owner_approval",
  "current_access",
  "contribution",
];

export interface AuthorizationDependencies {
  /**
   * Supplies the signed-in GitHub session. Called only after the local repository check passes,
   * so no sign-in is attempted for a directory that could never be scanned.
   */
  getGitHubSession: GitHubSessionProvider;
  /** Injectable Git runner for tests; defaults to the hardened `execFile` runner. */
  runGit?: GitRunner;
  /** Upper bound on local commits examined against GitHub (default 30). */
  maxContributionCandidates?: number;
}

export interface AuthorizationOutcome {
  /** Always lists all five checks in `AUTHORIZATION_CHECK_ORDER`. */
  summary: AuthorizationSummary;
  /** `owner/name` from the verified remote, or `null` if the repository check failed. */
  repo: string | null;
  /** Local `HEAD` SHA, or `null` if unknown. */
  revision: string | null;
}
