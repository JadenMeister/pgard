import type {
  AuthorizationCheckId,
  AuthorizationCheckStatus,
  AuthorizationSummary,
} from "@pgard/findings";
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
  /**
   * Slug of the configured GitHub App (`resolveGitHubAppClientId(env).slug`), used only to build
   * the install link in `remedy`. Omitted or `null`: no link. It never affects any check.
   */
  appSlug?: string | null;
}

/**
 * Whether the signed-in user can install the App, as far as GitHub's data shows:
 * - `yes`: personal repository owned by the user, or GitHub returned an active owner (admin)
 *   membership of the organization;
 * - `no`: someone else's personal account, or GitHub returned a membership that is not an
 *   active owner (non-admin role or pending);
 * - `unknown`: the organization membership could not be read (GitHub answers 403/404 before the
 *   App is installed on the organization).
 * Guidance only: it never makes any check pass. The install itself needs a real owner, and the
 * full authorization (including the owner membership check) runs again afterwards.
 */
export type InstallApproval = "yes" | "no" | "unknown";

/**
 * What the user can do when owner approval failed only because the PGARD GitHub App is not
 * installed on the owner account, or its installation does not include this repository.
 * Computed from GitHub API data only. It is guidance, never evidence: installing the App is the
 * owner's approval, and the full authorization runs again afterwards.
 */
export interface OwnerApprovalRemedy {
  kind: "install_app";
  /**
   * - `installation`: no installation on the owner account;
   * - `repository`: an installation without this repository;
   * - `access`: GitHub returned 404 for the repository itself, so the cause is unknown (usually a
   *   private repository outside the installation). The link then preselects only the account.
   */
  missing: "installation" | "repository" | "access";
  /** The account that owns the repository, as GitHub reports it. */
  account: { login: string; type: "User" | "Organization" };
  /**
   * The App install page preselected for the owner account and this repository, built from
   * numeric GitHub ids; always an `https://github.com/apps/...` URL. `null` when no link can be
   * built (see `unavailableReason`).
   */
  url: string | null;
  /** Whether the signed-in user can install it; see `InstallApproval`. */
  canApprove: InstallApproval;
  /** Fixed text explaining why `url` is `null`; otherwise `null`. */
  unavailableReason: string | null;
}

export interface AuthorizationOutcome {
  /** Always lists all five checks in `AUTHORIZATION_CHECK_ORDER`. */
  summary: AuthorizationSummary;
  /** `owner/name` from the verified remote, or `null` if the repository check failed. */
  repo: string | null;
  /** Local `HEAD` SHA, or `null` if unknown. */
  revision: string | null;
  /**
   * Set when owner approval failed because the App is not installed for this repository (see
   * `guidedInstallRemedy` for when frontends offer it). Absent or `null` otherwise.
   */
  remedy?: OwnerApprovalRemedy | null;
  /**
   * The GitHub account (login and numeric id, never a token) this run's `github_identity` check
   * signed in with. Absent or `null` when that check did not pass. Frontends use it to tell
   * whether a later sign-in is the same account the check ran with.
   */
  account?: { login: string; userId: number } | null;
}

/** Result of `recheckOwnerApproval`: the owner_approval check alone, evaluated again. */
export interface OwnerApprovalRecheck {
  status: AuthorizationCheckStatus;
  reason: string;
  remedy: OwnerApprovalRemedy | null;
}

/**
 * Display cap for one check reason in the CLI and in scan reports. Every policy reason fits well
 * below it (the longest, a contribution failure with its guidance, is about 420 characters plus
 * the default branch name twice), so frontends show reasons verbatim, like the dashboard does.
 */
export const AUTHORIZATION_REASON_MAX_LENGTH = 1000;
