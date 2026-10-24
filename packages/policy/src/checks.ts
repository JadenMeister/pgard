import { realpath } from "node:fs/promises";
import type { AuthorizationCheck } from "@pgard/findings";
import {
  findGitRoot,
  listCommitCandidates,
  readGitHubRemote,
  readHeadRevision,
  type CommitCandidate,
  type GitHubRepositoryRef,
  type GitRunner,
} from "@pgard/git-history";
import {
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

/** Local-only: valid Git history at the project root and one unambiguous github.com remote. */
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
      case "missing_client_id":
        return unverifiable(
          "PGARD_GITHUB_APP_CLIENT_ID is not set. No PGARD GitHub App is configured, so GitHub identity cannot be verified.",
        );
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

/**
 * Owner approval = the PGARD GitHub App is installed on the owner's personal account and that
 * installation includes this repository. Only a personal account's owner can install an app on
 * that account. For organizations, GitHub's public APIs do not reveal who installed the app
 * (repository admins may be allowed to), so owner approval cannot be proven and is reported as
 * unverifiable — never passed.
 */
export async function verifyOwnerApproval(
  client: GitHubClient,
  repository: GitHubRepository,
): Promise<CheckResult> {
  if (repository.owner.type === "Organization") {
    return unverifiable(
      "The repository is owned by an organization. GitHub's APIs cannot prove that an organization owner (rather than a repository admin) approved the PGARD GitHub App, so organization repositories are blocked.",
    );
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
  repo: GitHubRepositoryRef;
  projectRoot: string;
  runner: GitRunner;
  maxCandidates: number;
}

/**
 * A local commit counts only when (1) GitHub reports it in the default branch history and
 * (2) a merged pull request authored by the user is associated with it, or GitHub verified its
 * signature and attributes the committer to the user. Author name/email, co-author trailers,
 * unmerged PRs, unsigned direct pushes and local-only commits are never proof.
 */
export async function verifyContribution(input: ContributionInput): Promise<CheckResult> {
  const { client, user, repository, repo } = input;
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
      const mergedPull = pulls.find((pull) => pull.userId === user.id && pull.mergedAt !== null);
      if (mergedPull) {
        evidence = `merged pull request #${mergedPull.number} authored by ${user.login}`;
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
      `No qualifying contribution among the ${examined.length} commits examined (of ${ordered.length} local commits). A merged pull request by the signed-in user, or a signature-verified commit by them, in the default branch is required.`,
    );
  }
  return failed(
    `No qualifying contribution found among ${examined.length} local commits. A merged pull request by the signed-in user, or a signature-verified commit by them, in the default branch is required; author name/email, unmerged PRs and local-only commits do not count.`,
  );
}
