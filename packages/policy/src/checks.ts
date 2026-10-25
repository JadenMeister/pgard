import { realpath } from "node:fs/promises";
import type { AuthorizationCheck } from "@pgard/findings";
import {
  findGitRoot,
  listCommitCandidates,
  readGitHubRemote,
  readHeadRevision,
  readRepositoryIsolation,
  type CommitCandidate,
  type GitHubRepositoryRef,
  type GitRunner,
} from "@pgard/git-history";
import {
  INVALID_CLIENT_ID_OVERRIDE_MESSAGE,
  isGitHubAuthError,
  type GitHubClient,
  type GitHubRepository,
  type GitHubUser,
} from "@pgard/github-auth";

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
  const revision = await readHeadRevision(projectRoot, runner);
  if (revision === null) {
    return {
      check: failed("The repository has no valid commit history."),
      repo: null,
      revision: null,
    };
  }
  const isolation = await readRepositoryIsolation(projectRoot, runner);
  if (!isolation.isIsolated) {
    return { check: failed(isolation.reason), repo: null, revision };
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
        return unverifiable(INVALID_CLIENT_ID_OVERRIDE_MESSAGE);
      case "access_denied":
        return failed("GitHub sign-in was denied.");
      case "expired_token":
        return failed("The GitHub sign-in code expired before it was approved.");
      case "device_flow_disabled":
      case "incorrect_client_credentials":
        return unverifiable(`GitHub App sign-in is misconfigured: ${error.message}`);
      case "cancelled":
        return unverifiable("GitHub sign-in was cancelled.");
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
  if (repository.owner.type === "Organization") {
    return verifyOrganizationOwnerApproval(client, repository, context);
  }
  if (repository.owner.type !== "User") {
    return unverifiable("The repository owner type could not be determined.");
  }
  let installations;
  try {
    installations = await client.listUserInstallations();
  } catch (error) {
    return describeApiError(error, "list GitHub App installations");
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
      return describeApiError(error, "list repositories of the GitHub App installation");
    }
    if (repositoryIds.includes(repository.id)) {
      return passed(
        `The PGARD GitHub App is installed by the owner account "${repository.owner.login}" and includes ${repository.fullName}.`,
      );
    }
  }
  if (ownerInstallations.length > 0) {
    return failed(
      `The owner's PGARD GitHub App installation does not include ${repository.fullName}.`,
    );
  }
  return failed(
    `No PGARD GitHub App installation on the owner account "${repository.owner.login}" was found for ${repository.fullName}.`,
  );
}

async function verifyOrganizationOwnerApproval(
  client: GitHubClient,
  repository: GitHubRepository,
  { user, remoteOwner }: OwnerApprovalContext,
): Promise<CheckResult> {
  const org = repository.owner.login;
  // The organization named in the remote must be exactly the account GitHub reports (no
  // redirect from a renamed organization, no case difference), so every lookup below is about
  // the organization the user pointed PGARD at.
  if (remoteOwner !== org) {
    return unverifiable(
      `The Git remote names the organization "${remoteOwner}", but GitHub reports the owner as "${org}". Update the remote to github.com/${repository.fullName} so the organization can be verified.`,
    );
  }

  // (a) The App installation on this organization account includes the repository.
  let installations;
  try {
    installations = await client.listUserInstallations();
  } catch (error) {
    return describeApiError(error, "list GitHub App installations");
  }
  const orgInstallations = installations.filter(
    (installation) =>
      installation.targetType === "Organization" && installation.account.id === repository.owner.id,
  );
  const mismatched = orgInstallations.find((installation) => installation.account.login !== org);
  if (mismatched) {
    return unverifiable(
      `The PGARD GitHub App installation for the organization "${org}" reports the account "${mismatched.account.login}". Owner approval cannot be verified.`,
    );
  }
  let isIncluded = false;
  for (const installation of orgInstallations) {
    let repositoryIds: number[];
    try {
      repositoryIds = await client.listInstallationRepositoryIds(installation.id);
    } catch (error) {
      return describeApiError(error, "list repositories of the GitHub App installation");
    }
    if (repositoryIds.includes(repository.id)) {
      isIncluded = true;
      break;
    }
  }
  if (!isIncluded) {
    return orgInstallations.length > 0
      ? failed(
          `The PGARD GitHub App installation on the organization "${org}" does not include ${repository.fullName}. An owner of ${org} must add the repository to the installation.`,
        )
      : failed(
          `No PGARD GitHub App installation on the organization "${org}" was found for ${repository.fullName}. An owner of ${org} must install the App on the organization and include the repository.`,
        );
  }

  // (b) The signed-in user is an owner of the organization.
  let membership;
  try {
    membership = await client.getOrganizationMembership(org);
  } catch (error) {
    return describeMembershipError(error, user, org);
  }
  if (membership.organization.id !== repository.owner.id || membership.organization.login !== org) {
    return unverifiable(
      `GitHub returned a membership for the organization "${membership.organization.login}" instead of "${org}". Owner approval cannot be verified.`,
    );
  }
  if (membership.user.id !== user.id) {
    return unverifiable(
      `GitHub returned the ${org} membership of "${membership.user.login}" instead of the signed-in user ${user.login}. Owner approval cannot be verified.`,
    );
  }
  if (membership.state === "active" && membership.role === "admin") {
    return passed(
      `${user.login} is an owner of the organization "${org}", and the organization's PGARD GitHub App installation includes ${repository.fullName}.`,
    );
  }
  if (membership.state === "pending") {
    return failed(
      `${user.login}'s membership in ${org} is pending, not active; an organization owner with an active membership must run the scan.`,
    );
  }
  if (membership.state === "active") {
    return failed(
      `${user.login} is not an owner of ${org} (role: ${membership.role}); an organization owner must run the scan.`,
    );
  }
  return unverifiable(
    `GitHub reported an unexpected membership state for ${user.login} in ${org}; an organization owner with an active membership must run the scan.`,
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
 * A local commit (from HEAD's ancestry) counts only when (1) GitHub reports it in the default
 * branch history and (2) a pull request authored by the user and merged into this repository's
 * default branch is associated with it, or GitHub verified its signature and attributes the
 * committer to the user. Author name/email, co-author trailers, unmerged PRs, PRs merged into
 * other branches or forks, unsigned direct pushes and local-only commits are never proof.
 * All API calls use GitHub's canonical repository name.
 */
export async function verifyContribution(input: ContributionInput): Promise<CheckResult> {
  const { client, user, repository } = input;
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
  if (candidates.length === 0) {
    return failed("No local commits were found to check for a contribution.");
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
      const comparison = await client.compareCommits(
        repo.owner,
        repo.name,
        candidate.sha,
        repository.defaultBranch,
      );
      if (comparison === "ahead" || comparison === "identical") {
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
      `No qualifying contribution among the ${examined.length} commits examined (of ${ordered.length} local commits). A pull request by the signed-in user merged into the default branch, or a signature-verified commit by them in the default branch, is required.`,
    );
  }
  return failed(
    `No qualifying contribution found among ${examined.length} local commits. A pull request by the signed-in user merged into the default branch, or a signature-verified commit by them in the default branch, is required; author name/email, unmerged PRs, PRs into other branches and local-only commits do not count.`,
  );
}
