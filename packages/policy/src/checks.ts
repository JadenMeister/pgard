import { realpath } from "node:fs/promises";
import type { AuthorizationCheck } from "@pgard/findings";
import {
  findGitRoot,
  listCommitCandidates,
  readGitHubRemote,
  preflightIsolation,
  readHeadRevision,
  readRepositoryIsolation,
  type CommitCandidate,
  type GitHubRepositoryRef,
  type GitRunner,
} from "@pgard/git-history";
import {
  GUIDED_INSTALL_NEEDS_SLUG_MESSAGE,
  INVALID_CLIENT_ID_OVERRIDE_MESSAGE,
  buildAppInstallUrl,
  isGitHubAuthError,
  isOpenableGitHubUrl,
  type GitHubClient,
  type GitHubRepository,
  type GitHubUser,
} from "@pgard/github-auth";
import type { InstallApproval, OwnerApprovalRemedy } from "./types.js";

export type CheckResult = Omit<AuthorizationCheck, "id">;

const passed = (reason: string): CheckResult => ({ status: "passed", reason });
const failed = (reason: string): CheckResult => ({ status: "failed", reason });
const unverifiable = (reason: string): CheckResult => ({ status: "unverifiable", reason });

export interface RepositoryCheckResult {
  check: CheckResult;
  repo: GitHubRepositoryRef | null;
  revision: string | null;
}

async function resolveRealPath(target: string): Promise<string | null> {
  try {
    return await realpath(target);
  } catch {
    return null;
  }
}

/**
 * Local-only: valid Git history at the project root, only the repository's own objects and
 * history (no alternates, grafts or replace refs), and one unambiguous github.com remote.
 */
export async function verifyRepository(
  projectRoot: string,
  runner: GitRunner,
): Promise<RepositoryCheckResult> {
  // Before any Git process: Git may open an alternates file, which would block on a FIFO.
  const preflight = await preflightIsolation(projectRoot);
  if (preflight !== null && !preflight.isIsolated) {
    return { check: failed(preflight.reason), repo: null, revision: null };
  }
  const gitRoot = await findGitRoot(projectRoot, runner);
  if (gitRoot === null) {
    return {
      check: failed("The project directory is not a Git repository."),
      repo: null,
      revision: null,
    };
  }
  const [realRoot, realGitRoot] = await Promise.all([
    resolveRealPath(projectRoot),
    resolveRealPath(gitRoot),
  ]);
  if (realRoot === null || realGitRoot === null || realRoot !== realGitRoot) {
    return {
      check: failed("The project directory must be the root of its Git repository."),
      repo: null,
      revision: null,
    };
  }
  // Isolation first: reading HEAD opens the object store, which alternates could redirect (or a
  // FIFO in their place could block).
  const isolation = await readRepositoryIsolation(projectRoot, runner);
  if (!isolation.isIsolated) {
    return { check: failed(isolation.reason), repo: null, revision: null };
  }
  const revision = await readHeadRevision(projectRoot, runner);
  if (revision === null) {
    return {
      check: failed("The repository has no valid commit history."),
      repo: null,
      revision: null,
    };
  }
  const remote = await readGitHubRemote(projectRoot, runner);
  if (!remote.isResolved) {
    return { check: failed(remote.reason), repo: null, revision };
  }
  return {
    check: passed(
      `Git repository with remote "${remote.remoteName}" -> github.com/${remote.repo.owner}/${remote.repo.name}.`,
    ),
    repo: remote.repo,
    revision,
  };
}

export function describeIdentityError(error: unknown): CheckResult {
  if (isGitHubAuthError(error)) {
    switch (error.code) {
      case "invalid_client_id_override":
        // Fixed text from `@pgard/github-auth` naming the malformed override (client id or slug).
        return unverifiable(error.message || INVALID_CLIENT_ID_OVERRIDE_MESSAGE);
      case "access_denied":
        return failed("GitHub sign-in was denied.");
      case "expired_token":
        return failed("The GitHub sign-in code expired before it was approved.");
      case "device_flow_disabled":
      case "incorrect_client_credentials":
        return unverifiable(`GitHub App sign-in is misconfigured: ${error.message}`);
      case "cancelled":
        return unverifiable("GitHub sign-in was cancelled.");
      case "not_signed_in":
        // Fixed text from `@pgard/github-auth`: the reason and the fix (`pgard login`).
        return unverifiable(error.message);
      default:
        return unverifiable(`GitHub identity could not be verified: ${error.message}`);
    }
  }
  return unverifiable("GitHub identity could not be verified due to an unexpected error.");
}

export function describeApiError(error: unknown, action: string): CheckResult {
  if (isGitHubAuthError(error)) {
    return unverifiable(`Could not ${action}: ${error.message}`);
  }
  return unverifiable(`Could not ${action} due to an unexpected error.`);
}

/** `permissions.pull` (or any higher role) for the signed-in user on the target repository. */
export function verifyCurrentAccess(repository: GitHubRepository): CheckResult {
  const permissions = repository.permissions;
  if (permissions === null) {
    return unverifiable("GitHub did not report the user's permissions for this repository.");
  }
  const hasAccess =
    permissions.pull ||
    permissions.triage ||
    permissions.push ||
    permissions.maintain ||
    permissions.admin;
  return hasAccess
    ? passed(`The signed-in user currently has access to ${repository.fullName}.`)
    : failed(`The signed-in user has no read access to ${repository.fullName}.`);
}

export interface OwnerApprovalContext {
  /** The signed-in user (github_identity passed). */
  user: GitHubUser;
  /** Owner segment of the verified Git remote, exactly as written there. */
  remoteOwner: string;
  /** Configured App slug for the install link in `remedy`; `null`/omitted: no link. */
  appSlug?: string | null;
}

/**
 * Evidence, established while owner approval passed in this run, that the signed-in user is the
 * verified owner of the repository `repositoryId`. Every id comes from the GitHub API, never from
 * the remote.
 * - `personal_owner`: the signed-in user's account id equals the personal owner account id.
 * - `organization_owner`: GitHub returned this user's active owner (`admin`) membership of the
 *   organization that owns the repository.
 */
export type OwnerEvidence =
  | { kind: "personal_owner"; repositoryId: number; userId: number; ownerId: number }
  | {
      kind: "organization_owner";
      repositoryId: number;
      userId: number;
      organizationId: number;
      organization: string;
    };

/** The owner_approval check, plus guidance when the App is not installed for this repository. */
export interface OwnerApprovalResult {
  check: CheckResult;
  remedy: OwnerApprovalRemedy | null;
  /**
   * Set only when `check` passed and the signed-in user is the verified owner (see
   * `OwnerEvidence`); `null` on every other path, including any error or unknown state.
   */
  ownerEvidence: OwnerEvidence | null;
}

/** Shown in `remedy.unavailableReason` when a link could not be built for another reason. */
export const GUIDED_INSTALL_GITHUB_COM_ONLY_MESSAGE =
  "The guided install is only available for repositories on github.com.";

/** Shown when the App's settings link for an existing installation failed its safety check. */
export const REPOSITORY_ACCESS_LINK_UNAVAILABLE_MESSAGE =
  "PGARD could not build a safe link to the App's repository access settings. Open the PGARD GitHub App's installation settings on github.com yourself and add this repository.";

/**
 * Builds the install remedy from API data only: the numeric ids GitHub reported for the owner
 * account and the repository, and the configured slug. Never changes the check result.
 */
function installRemedy(
  repository: GitHubRepository,
  missing: OwnerApprovalRemedy["missing"],
  canApprove: InstallApproval,
  appSlug: string | null | undefined,
): OwnerApprovalRemedy {
  const url =
    typeof appSlug === "string"
      ? buildAppInstallUrl({
          slug: appSlug,
          targetId: repository.owner.id,
          repositoryId: repository.id,
        })
      : null;
  return {
    kind: "install_app",
    missing,
    account: {
      login: repository.owner.login,
      type: repository.owner.type === "Organization" ? "Organization" : "User",
    },
    url,
    canApprove,
    unavailableReason:
      url !== null
        ? null
        : typeof appSlug === "string"
          ? GUIDED_INSTALL_GITHUB_COM_ONLY_MESSAGE
          : GUIDED_INSTALL_NEEDS_SLUG_MESSAGE,
  };
}

/**
 * Owner approval for a personal account = the PGARD GitHub App is installed on the owner's
 * personal account and that installation includes this repository. Only a personal account's
 * owner can install an app on that account.
 *
 * For an organization, GitHub does not reveal who installed the app (repository admins may be
 * allowed to), so the installation alone is not proof. Owner approval passes only when BOTH
 * (a) the App installation on the organization account includes this repository and (b) the
 * signed-in user is an owner of that organization (`state: active`, `role: admin`). Anything
 * unclear is reported as failed or unverifiable, never passed.
 */
export async function verifyOwnerApproval(
  client: GitHubClient,
  repository: GitHubRepository,
  context: OwnerApprovalContext,
): Promise<CheckResult> {
  return (await evaluateOwnerApproval(client, repository, context)).check;
}

/**
 * `verifyOwnerApproval` plus a `remedy` when it failed only because the App is not installed on
 * the owner account or the installation does not include the repository. The check result is
 * exactly the same with or without a remedy.
 */
export async function evaluateOwnerApproval(
  client: GitHubClient,
  repository: GitHubRepository,
  context: OwnerApprovalContext,
): Promise<OwnerApprovalResult> {
  if (repository.owner.type === "Organization") {
    return verifyOrganizationOwnerApproval(client, repository, context);
  }
  if (repository.owner.type !== "User") {
    return noRemedy(unverifiable("The repository owner type could not be determined."));
  }
  let installations;
  try {
    installations = await client.listUserInstallations();
  } catch (error) {
    return noRemedy(describeApiError(error, "list GitHub App installations"));
  }
  const ownerInstallations = installations.filter(
    (installation) =>
      installation.targetType === "User" && installation.account.id === repository.owner.id,
  );
  for (const installation of ownerInstallations) {
    let repositoryIds: number[];
    try {
      repositoryIds = await client.listInstallationRepositoryIds(installation.id);
    } catch (error) {
      return noRemedy(describeApiError(error, "list repositories of the GitHub App installation"));
    }
    if (repositoryIds.includes(repository.id)) {
      // A collaborator also passes owner approval here (the owner installed the App), but only
      // the owner account itself, matched by GitHub account id, is owner evidence.
      const isOwner = context.user.id === repository.owner.id;
      return {
        check: passed(
          `The PGARD GitHub App is installed by the owner account "${repository.owner.login}" and includes ${repository.fullName}.`,
        ),
        remedy: null,
        ownerEvidence: isOwner
          ? {
              kind: "personal_owner",
              repositoryId: repository.id,
              userId: context.user.id,
              ownerId: repository.owner.id,
            }
          : null,
      };
    }
  }
  // Only the owner account itself can install an App on a personal account.
  const canApprove: InstallApproval = context.user.id === repository.owner.id ? "yes" : "no";
  if (ownerInstallations.length > 0) {
    return {
      check: failed(
        `The owner's PGARD GitHub App installation does not include ${repository.fullName}.`,
      ),
      remedy: installRemedy(repository, "repository", canApprove, context.appSlug),
      ownerEvidence: null,
    };
  }
  return {
    check: failed(
      `No PGARD GitHub App installation on the owner account "${repository.owner.login}" was found for ${repository.fullName}.`,
    ),
    remedy: installRemedy(repository, "installation", canApprove, context.appSlug),
    ownerEvidence: null,
  };
}

/**
 * current_access reason when GitHub answers 404 for the repository. PGARD cannot tell whether
 * the App is not installed for a private repository or the account has no access (or the
 * repository does not exist), so it says both.
 */
export function notFoundAccessReason(repoName: string): string {
  return `GitHub returned no access to github.com/${repoName}. For a private repository this usually means the PGARD GitHub App is not installed for it, or your account has no access.`;
}

/**
 * The 404 reason when the signed-in user's installation on the owner account covers all
 * repositories: adding the repository to the App cannot help, so the cause is elsewhere.
 */
export function notFoundAllRepositoriesReason(repoName: string): string {
  return `GitHub returned no access to github.com/${repoName}. The PGARD GitHub App is already installed on the owner account for all repositories, so adding the repository will not help: your account probably has no access, the repository does not exist, or the git remote is wrong.`;
}

/** What `inspectNotFoundAccess` found out about a 404 repository. */
export interface NotFoundAccessInspection {
  remedy: OwnerApprovalRemedy | null;
  /** True only when the user's installation on the owner account is `all` repositories. */
  isCoveredByAllRepositories: boolean;
}

/**
 * The install remedy offered when `getRepository` answered 404 (the repository id is unknown).
 * Looks up the remote owner's account id with the public `GET /users/{owner}`. Returns `null`
 * (no remedy) when that lookup fails, returns another login than the remote names, or reports an
 * account type other than User/Organization. Guidance only: it never changes any check result.
 *
 * - personal account: `yes` only when it is the signed-in user's own account, otherwise `no`;
 * - organization: `unknown` (admin cannot be verified before the App is installed), guided.
 */
export async function evaluateAccessRemedy(
  client: GitHubClient,
  user: GitHubUser,
  remoteOwner: string,
  appSlug: string | null | undefined,
): Promise<OwnerApprovalRemedy | null> {
  return (await inspectNotFoundAccess(client, user, remoteOwner, appSlug)).remedy;
}

/**
 * Like `evaluateAccessRemedy`, and also reports whether the existing installation on the owner
 * account covers all repositories. In that case no remedy is offered (adding the repository does
 * not apply). A missing or unrecognized `repository_selection` also offers no remedy: it is not
 * guessed, and the generic reason stays.
 */
export async function inspectNotFoundAccess(
  client: GitHubClient,
  user: GitHubUser,
  remoteOwner: string,
  appSlug: string | null | undefined,
): Promise<NotFoundAccessInspection> {
  const found = await findAccessRemedy(client, user, remoteOwner, appSlug);
  if (found === "all") return { remedy: null, isCoveredByAllRepositories: true };
  return { remedy: found, isCoveredByAllRepositories: false };
}

async function findAccessRemedy(
  client: GitHubClient,
  user: GitHubUser,
  remoteOwner: string,
  appSlug: string | null | undefined,
): Promise<OwnerApprovalRemedy | "all" | null> {
  let account;
  try {
    account = await client.getAccount(remoteOwner);
  } catch {
    return null;
  }
  if (account.login.toLowerCase() !== remoteOwner.toLowerCase()) return null;
  if (account.type !== "User" && account.type !== "Organization") return null;
  const canApprove: InstallApproval =
    account.type === "Organization" ? "unknown" : account.id === user.id ? "yes" : "no";
  const remedyAccount: { login: string; type: "User" | "Organization" } = {
    login: account.login,
    type: account.type === "Organization" ? "Organization" : "User",
  };

  // Is the App already installed on the owner account? Then the repository only has to be added
  // to that installation. If the listing fails there is no way to tell which page helps, so no
  // remedy is offered (the failed reason still says what is likely wrong): guessing "install"
  // for an installed App, or "configure" for a missing one, would send the user to a wrong page.
  let installations;
  try {
    installations = await client.listUserInstallations();
  } catch {
    return null;
  }
  const existing = installations.find(
    (installation) =>
      installation.account.id === account.id && installation.targetType === account.type,
  );
  if (existing !== undefined) {
    if (existing.repositorySelection === "all") return "all";
    // Only a confirmed `selected` installation can be missing this repository.
    if (existing.repositorySelection !== "selected") return null;
    const configureUrl =
      account.type === "Organization"
        ? `https://github.com/organizations/${encodeURIComponent(account.login)}/settings/installations/${existing.id}`
        : `https://github.com/settings/installations/${existing.id}`;
    const isSafe =
      Number.isSafeInteger(existing.id) &&
      existing.id > 0 &&
      /^[A-Za-z0-9-]{1,100}$/.test(account.login) &&
      isOpenableGitHubUrl(configureUrl);
    return {
      kind: "install_app",
      missing: "repository_access",
      account: remedyAccount,
      url: isSafe ? configureUrl : null,
      canApprove,
      unavailableReason: isSafe ? null : REPOSITORY_ACCESS_LINK_UNAVAILABLE_MESSAGE,
    };
  }

  const url =
    typeof appSlug === "string"
      ? buildAppInstallUrl({ slug: appSlug, targetId: account.id })
      : null;
  return {
    kind: "install_app",
    missing: "access",
    account: remedyAccount,
    url,
    canApprove,
    unavailableReason:
      url !== null
        ? null
        : typeof appSlug === "string"
          ? GUIDED_INSTALL_GITHUB_COM_ONLY_MESSAGE
          : GUIDED_INSTALL_NEEDS_SLUG_MESSAGE,
  };
}

function noRemedy(check: CheckResult): OwnerApprovalResult {
  return { check, remedy: null, ownerEvidence: null };
}

/**
 * Whether the signed-in user can install the App on the organization, used only to decide how
 * to guide the user. `no` only when GitHub actually returned this user's membership of this
 * organization and it is not an active owner (non-admin role, or pending). A membership that
 * cannot be read (403/404 is expected before the App is installed on the organization, or any
 * other error) or that does not match is `unknown`. The owner_approval check itself reads the
 * membership again on every run and requires an active owner.
 */
async function organizationInstallApproval(
  client: GitHubClient,
  repository: GitHubRepository,
  user: GitHubUser,
): Promise<InstallApproval> {
  let membership;
  try {
    membership = await client.getOrganizationMembership(repository.owner.login);
  } catch {
    return "unknown";
  }
  if (
    membership.organization.id !== repository.owner.id ||
    membership.organization.login !== repository.owner.login ||
    membership.user.id !== user.id
  ) {
    return "unknown";
  }
  if (membership.state === "active" && membership.role === "admin") return "yes";
  if (membership.state === "active" || membership.state === "pending") return "no";
  return "unknown";
}

async function verifyOrganizationOwnerApproval(
  client: GitHubClient,
  repository: GitHubRepository,
  { user, remoteOwner, appSlug }: OwnerApprovalContext,
): Promise<OwnerApprovalResult> {
  const org = repository.owner.login;
  // The organization named in the remote must be exactly the account GitHub reports (no
  // redirect from a renamed organization, no case difference), so every lookup below is about
  // the organization the user pointed PGARD at.
  if (remoteOwner !== org) {
    return noRemedy(
      unverifiable(
        `The Git remote names the organization "${remoteOwner}", but GitHub reports the owner as "${org}". Update the remote to github.com/${repository.fullName} so the organization can be verified.`,
      ),
    );
  }

  // (a) The App installation on this organization account includes the repository.
  let installations;
  try {
    installations = await client.listUserInstallations();
  } catch (error) {
    return noRemedy(describeApiError(error, "list GitHub App installations"));
  }
  const orgInstallations = installations.filter(
    (installation) =>
      installation.targetType === "Organization" && installation.account.id === repository.owner.id,
  );
  const mismatched = orgInstallations.find((installation) => installation.account.login !== org);
  if (mismatched) {
    return noRemedy(
      unverifiable(
        `The PGARD GitHub App installation for the organization "${org}" reports the account "${mismatched.account.login}". Owner approval cannot be verified.`,
      ),
    );
  }
  let isIncluded = false;
  for (const installation of orgInstallations) {
    let repositoryIds: number[];
    try {
      repositoryIds = await client.listInstallationRepositoryIds(installation.id);
    } catch (error) {
      return noRemedy(describeApiError(error, "list repositories of the GitHub App installation"));
    }
    if (repositoryIds.includes(repository.id)) {
      isIncluded = true;
      break;
    }
  }
  if (!isIncluded) {
    const canApprove = await organizationInstallApproval(client, repository, user);
    return orgInstallations.length > 0
      ? {
          check: failed(
            `The PGARD GitHub App installation on the organization "${org}" does not include ${repository.fullName}. An owner of ${org} must add the repository to the installation.`,
          ),
          remedy: installRemedy(repository, "repository", canApprove, appSlug),
          ownerEvidence: null,
        }
      : {
          check: failed(
            `No PGARD GitHub App installation on the organization "${org}" was found for ${repository.fullName}. An owner of ${org} must install the App on the organization and include the repository.`,
          ),
          remedy: installRemedy(repository, "installation", canApprove, appSlug),
          ownerEvidence: null,
        };
  }

  // (b) The signed-in user is an owner of the organization.
  let membership;
  try {
    membership = await client.getOrganizationMembership(org);
  } catch (error) {
    return noRemedy(describeMembershipError(error, user, org));
  }
  if (membership.organization.id !== repository.owner.id || membership.organization.login !== org) {
    return noRemedy(
      unverifiable(
        `GitHub returned a membership for the organization "${membership.organization.login}" instead of "${org}". Owner approval cannot be verified.`,
      ),
    );
  }
  if (membership.user.id !== user.id) {
    return noRemedy(
      unverifiable(
        `GitHub returned the ${org} membership of "${membership.user.login}" instead of the signed-in user ${user.login}. Owner approval cannot be verified.`,
      ),
    );
  }
  if (membership.state === "active" && membership.role === "admin") {
    return {
      check: passed(
        `${user.login} is an owner of the organization "${org}", and the organization's PGARD GitHub App installation includes ${repository.fullName}.`,
      ),
      remedy: null,
      ownerEvidence: {
        kind: "organization_owner",
        repositoryId: repository.id,
        userId: user.id,
        organizationId: repository.owner.id,
        organization: org,
      },
    };
  }
  if (membership.state === "pending") {
    return noRemedy(
      failed(
        `${user.login}'s membership in ${org} is pending, not active; an organization owner with an active membership must run the scan.`,
      ),
    );
  }
  if (membership.state === "active") {
    return noRemedy(
      failed(
        `${user.login} is not an owner of ${org} (role: ${membership.role}); an organization owner must run the scan.`,
      ),
    );
  }
  return noRemedy(
    unverifiable(
      `GitHub reported an unexpected membership state for ${user.login} in ${org}; an organization owner with an active membership must run the scan.`,
    ),
  );
}

function describeMembershipError(error: unknown, user: GitHubUser, org: string): CheckResult {
  if (isGitHubAuthError(error)) {
    switch (error.code) {
      case "forbidden":
        return unverifiable(
          `GitHub refused to show ${user.login}'s membership in ${org} (403): the PGARD GitHub App needs the organization permission Members: Read-only, approved by an owner of ${org}.`,
        );
      case "not_found":
        return unverifiable(
          `GitHub did not return ${user.login}'s membership in ${org} (404): ${user.login} may not be a member, or the PGARD GitHub App cannot read the organization's members. An owner of ${org} must run the scan, with the App's Members: Read-only permission approved.`,
        );
      case "rate_limited":
        return unverifiable(
          `Could not read ${user.login}'s membership in ${org}: the GitHub API rate limit was reached. Try again later.`,
        );
      default:
        return unverifiable(
          `Could not read ${user.login}'s membership in ${org}: ${error.message}`,
        );
    }
  }
  return unverifiable(
    `Could not read ${user.login}'s membership in ${org} due to an unexpected error.`,
  );
}

function normalize(value: string): string {
  return value.trim().toLowerCase();
}

/** Orders candidates so commits whose self-asserted identity resembles the user come first. */
export function orderCandidates(
  candidates: CommitCandidate[],
  user: GitHubUser,
): CommitCandidate[] {
  const names = new Set([normalize(user.login), ...(user.name ? [normalize(user.name)] : [])]);
  const emails = new Set([
    `${user.id}+${normalize(user.login)}@users.noreply.github.com`,
    `${normalize(user.login)}@users.noreply.github.com`,
    ...(user.email ? [normalize(user.email)] : []),
  ]);
  const looksLikeUser = (candidate: CommitCandidate) =>
    emails.has(normalize(candidate.authorEmail)) ||
    emails.has(normalize(candidate.committerEmail)) ||
    names.has(normalize(candidate.authorName)) ||
    names.has(normalize(candidate.committerName));
  return [
    ...candidates.filter(looksLikeUser),
    ...candidates.filter((candidate) => !looksLikeUser(candidate)),
  ];
}

export interface ContributionInput {
  client: GitHubClient;
  user: GitHubUser;
  repository: GitHubRepository;
  projectRoot: string;
  runner: GitRunner;
  maxCandidates: number;
  /**
   * Owner evidence from this run's owner_approval check, passed only when that check passed.
   * Omitted or `null`: no exemption, the normal contribution check runs.
   */
  ownerEvidence?: OwnerEvidence | null;
}

/**
 * The owner exemption reason, or `null`. The evidence must have come from a passed owner
 * approval in this run and must still describe this user and this repository's owner account
 * by GitHub id; anything else (missing, mismatched or of the wrong kind) is no exemption.
 */
export function ownerExemptionReason(
  evidence: OwnerEvidence | null | undefined,
  user: GitHubUser,
  repository: GitHubRepository,
): string | null {
  if (!evidence || evidence.repositoryId !== repository.id || evidence.userId !== user.id) {
    return null;
  }
  if (evidence.kind === "personal_owner") {
    return repository.owner.type === "User" &&
      evidence.ownerId === repository.owner.id &&
      user.id === repository.owner.id
      ? `${user.login} owns ${repository.fullName} (verified by GitHub account id); a separate contribution is not required.`
      : null;
  }
  if (evidence.kind === "organization_owner") {
    return repository.owner.type === "Organization" &&
      evidence.organizationId === repository.owner.id &&
      evidence.organization === repository.owner.login
      ? `${user.login} is an owner of the organization "${evidence.organization}"; a separate contribution is not required.`
      : null;
  }
  return null;
}

/** Appended to a contribution that did not pass: how a non-owner qualifies. */
export function contributionGuidance(defaultBranch: string): string {
  return `To qualify, get a pull request merged into "${defaultBranch}", or sign your commits (GitHub shows them as Verified) and push them to "${defaultBranch}".`;
}

/** Splits GitHub's canonical `owner/name`; `null` if it is not in that form. */
export function parseCanonicalRepository(fullName: string): GitHubRepositoryRef | null {
  const parts = fullName.split("/");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return null;
  }
  return { owner: parts[0], name: parts[1] };
}

/**
 * True when GitHub reports `sha` in the default branch history of the canonical repository: the
 * default branch is ahead of it or identical (`compare/<sha>...<default>`). A SHA GitHub does
 * not know (404/422), a commit only on another branch, and an empty repository (409) are not.
 * API errors propagate to the caller, which reports them as unverifiable.
 */
async function isInDefaultBranch(
  client: GitHubClient,
  repo: GitHubRepositoryRef,
  sha: string,
  defaultBranch: string,
): Promise<boolean> {
  const comparison = await client.compareCommits(repo.owner, repo.name, sha, defaultBranch);
  return comparison === "ahead" || comparison === "identical";
}

/**
 * The verified owner's contribution check: no contribution of their own is needed, but the
 * local code must belong to this repository. At least one commit of HEAD's ancestry (newest
 * first, at most `maxCandidates`) must be in the canonical repository's default branch, by the
 * same reachability test the normal check uses. Not linked: failed. API error: unverifiable.
 */
async function verifyOwnerLink(
  input: ContributionInput,
  repo: GitHubRepositoryRef,
  candidates: CommitCandidate[],
  exemption: string,
): Promise<CheckResult> {
  const { client, repository } = input;
  const branch = repository.defaultBranch;
  const unlinked = (count: number) =>
    failed(
      `None of the last ${count} local commits is on ${repository.fullName}'s default branch "${branch}"; the local code can't be tied to this repository. Push or pull so local history shares a commit with the default branch.`,
    );
  if (candidates.length === 0) {
    return unlinked(0);
  }
  const examined = candidates.slice(0, input.maxCandidates);
  try {
    for (const candidate of examined) {
      if (await isInDefaultBranch(client, repo, candidate.sha, branch)) {
        return passed(
          `${exemption} Local HEAD is linked to ${repository.fullName} by commit ${candidate.sha.slice(0, 12)}.`,
        );
      }
    }
  } catch (error) {
    return describeApiError(error, `check that the local code belongs to ${repository.fullName}`);
  }
  return unlinked(examined.length);
}

/**
 * A local commit (from HEAD's ancestry) counts only when (1) GitHub reports it in the default
 * branch history and (2) a pull request authored by the user and merged into this repository's
 * default branch is associated with it, or GitHub verified its signature and attributes the
 * committer to the user. Author name/email, co-author trailers, unmerged PRs, PRs merged into
 * other branches or forks, unsigned direct pushes and local-only commits are never proof.
 * All API calls use GitHub's canonical repository name.
 *
 * Exception: the verified owner (see `ownerExemptionReason`) needs no contribution of their
 * own, but the local code must still be tied to this repository (see `verifyOwnerLink`).
 * Everyone else gets the rule above, with guidance on how to qualify.
 */
export async function verifyContribution(input: ContributionInput): Promise<CheckResult> {
  const { client, user, repository } = input;
  const guidance = contributionGuidance(repository.defaultBranch);
  const repo = parseCanonicalRepository(repository.fullName);
  if (repo === null) {
    return unverifiable("GitHub returned an unexpected repository name.");
  }
  let candidates: CommitCandidate[];
  try {
    candidates = await listCommitCandidates(input.projectRoot, input.runner);
  } catch {
    return unverifiable("Could not read local Git history to find contribution candidates.");
  }
  const exemption = ownerExemptionReason(input.ownerEvidence, user, repository);
  if (exemption !== null) {
    return verifyOwnerLink(input, repo, candidates, exemption);
  }
  if (candidates.length === 0) {
    return failed(`No local commits were found to check for a contribution. ${guidance}`);
  }
  const ordered = orderCandidates(candidates, user);
  const examined = ordered.slice(0, input.maxCandidates);
  try {
    for (const candidate of examined) {
      let evidence: string | null = null;
      const pulls = await client.listPullRequestsForCommit(repo.owner, repo.name, candidate.sha);
      const mergedPull = pulls.find(
        (pull) =>
          pull.userId === user.id &&
          pull.mergedAt !== null &&
          pull.baseRef === repository.defaultBranch &&
          pull.baseRepositoryId === repository.id,
      );
      if (mergedPull) {
        evidence = `pull request #${mergedPull.number} by ${user.login} merged into "${repository.defaultBranch}"`;
      } else {
        const commit = await client.getCommit(repo.owner, repo.name, candidate.sha);
        if (commit !== null && commit.isVerified && commit.committerId === user.id) {
          evidence = `signature-verified commit by ${user.login}`;
        }
      }
      if (evidence === null) {
        continue;
      }
      if (await isInDefaultBranch(client, repo, candidate.sha, repository.defaultBranch)) {
        return passed(
          `Commit ${candidate.sha.slice(0, 12)} is in the default branch "${repository.defaultBranch}" (${evidence}).`,
        );
      }
    }
  } catch (error) {
    return describeApiError(error, "verify contributions with GitHub");
  }
  if (ordered.length > examined.length) {
    return unverifiable(
      `No qualifying contribution among the ${examined.length} commits examined (of ${ordered.length} local commits). A pull request by the signed-in user merged into the default branch, or a signature-verified commit by them in the default branch, is required. ${guidance}`,
    );
  }
  return failed(
    `No qualifying contribution found among ${examined.length} local commits. A pull request by the signed-in user merged into the default branch, or a signature-verified commit by them in the default branch, is required; author name/email, unmerged PRs, PRs into other branches and local-only commits do not count. ${guidance}`,
  );
}
