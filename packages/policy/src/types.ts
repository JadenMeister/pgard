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

/** A repository a frontend confirmed with the user before running the gate. */
export interface ExpectedRepository {
  owner: string;
  name: string;
  /** GitHub's numeric id once a check of this project returned it; `null` or absent before. */
  repositoryId?: number | null;
}

/** Fixed reason when the repository differs from the one the user confirmed. */
export const REPOSITORY_CHANGED_REASON = "The repository changed since you confirmed it.";

export interface AuthorizationDependencies {
  /**
   * Supplies the signed-in GitHub session. Called only after the local repository check passes,
   * so no sign-in is attempted for a directory that could never be scanned.
   */
  getGitHubSession: GitHubSessionProvider;
  /** Injectable Git runner for tests; defaults to the hardened `execFile` runner. */
  runGit?: GitRunner;
  /**
   * Cancellation: given to every Git run during authorization, so an abort (Ctrl+C) kills a
   * blocked git process at once instead of waiting for its time limit.
   */
  signal?: AbortSignal;
  /**
   * The repository the caller showed the user and the user confirmed (the `pgard web` picker).
   * When set, the run stops with the fixed `REPOSITORY_CHANGED_REASON` unless the repository the
   * local check resolves is exactly this one, and, when `repositoryId` is set, unless GitHub
   * returns that same numeric id. It only ever blocks: it never makes a check pass.
   */
  expectedRepo?: ExpectedRepository | null;
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
   *   private repository outside the installation) and the App is not installed on the owner
   *   account. The link then preselects only the account.
   * - `repository_access`: same 404, but the App is already installed on the owner account; `url`
   *   is that installation's settings page, where the repository can be added.
   */
  missing: "installation" | "repository" | "access" | "repository_access";
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

/** Why a 404 is not a missing grant: the App already covers all repositories of the owner. */
export type AccessNote = "app_covers_all_repositories";

export interface AuthorizationOutcome {
  /** Always lists all five checks in `AUTHORIZATION_CHECK_ORDER`. */
  summary: AuthorizationSummary;
  /** `owner/name` from the verified remote, or `null` if the repository check failed. */
  repo: string | null;
  /** Local `HEAD` SHA, or `null` if unknown. */
  revision: string | null;
  /**
   * GitHub's numeric id of the repository, set only when GitHub returned the repository in this
   * run. A storage key for frontends; never evidence and never carried over between runs.
   */
  repositoryId?: number | null;
  /**
   * Set when owner approval failed because the App is not installed for this repository (see
   * `guidedInstallRemedy` for when frontends offer it). Absent or `null` otherwise.
   */
  remedy?: OwnerApprovalRemedy | null;
  /**
   * Set when GitHub showed no repository although the App is installed on the owner account for
   * all repositories (see `accessNoteFor` for when frontends show it). Not a remedy and never a
   * pass. Absent or `null` otherwise.
   */
  accessNote?: AccessNote | null;
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
