import type { AuthorizationCheck, AuthorizationCheckId } from "@pgard/findings";
import { runGit as defaultRunGit } from "@pgard/git-history";
import {
  isGitHubAuthError,
  type GitHubRepository,
  type GitHubSession,
  type GitHubUser,
} from "@pgard/github-auth";
import {
  describeApiError,
  describeIdentityError,
  verifyContribution,
  verifyCurrentAccess,
  evaluateOwnerApproval,
  verifyRepository,
  type CheckResult,
} from "./checks.js";
import {
  AUTHORIZATION_CHECK_ORDER,
  type AuthorizationDependencies,
  type AuthorizationOutcome,
  type OwnerApprovalRecheck,
  type OwnerApprovalRemedy,
} from "./types.js";

const DEFAULT_MAX_CONTRIBUTION_CANDIDATES = 30;
const MAX_CONTRIBUTION_CANDIDATES_LIMIT = 100;

function notEvaluated(prerequisite: string): CheckResult {
  return {
    status: "unverifiable",
    reason: `Not evaluated because the ${prerequisite} check did not pass.`,
  };
}

/**
 * The single authorization gate. Every scan and `project verify` calls this; results are never
 * cached between commands. The decision is `allowed` only when all five checks pass:
 * repository, github_identity, owner_approval, current_access and contribution.
 */
export async function authorizeProject(
  projectRoot: string,
  deps: AuthorizationDependencies,
): Promise<AuthorizationOutcome> {
  const runner = deps.runGit ?? defaultRunGit;
  const maxCandidates = Math.min(
    Math.max(1, Math.floor(deps.maxContributionCandidates ?? DEFAULT_MAX_CONTRIBUTION_CANDIDATES)),
    MAX_CONTRIBUTION_CANDIDATES_LIMIT,
  );
  const results = new Map<AuthorizationCheckId, CheckResult>();
  let remedy: OwnerApprovalRemedy | null = null;
  const build = (repo: string | null, revision: string | null): AuthorizationOutcome => {
    const checks: AuthorizationCheck[] = AUTHORIZATION_CHECK_ORDER.map((id) => ({
      id,
      ...(results.get(id) ?? notEvaluated("previous")),
    }));
    const isAllowed = checks.every((check) => check.status === "passed");
    return {
      summary: { decision: isAllowed ? "allowed" : "blocked", checks },
      repo,
      revision,
      remedy,
    };
  };

  const repositoryResult = await verifyRepository(projectRoot, runner);
  results.set("repository", repositoryResult.check);
  const { repo, revision } = repositoryResult;
  if (repositoryResult.check.status !== "passed" || repo === null) {
    for (const id of AUTHORIZATION_CHECK_ORDER.slice(1)) {
      results.set(id, notEvaluated("repository"));
    }
    return build(null, revision);
  }
  const repoName = `${repo.owner}/${repo.name}`;

  let session: GitHubSession;
  let user: GitHubUser;
  try {
    session = await deps.getGitHubSession();
    user = await session.client.getAuthenticatedUser();
  } catch (error) {
    results.set("github_identity", describeIdentityError(error));
    for (const id of AUTHORIZATION_CHECK_ORDER.slice(2)) {
      results.set(id, notEvaluated("github_identity"));
    }
    return build(repoName, revision);
  }
  results.set("github_identity", {
    status: "passed",
    reason: `Signed in to GitHub as ${user.login}.`,
  });
  const { client } = session;

  let repository: GitHubRepository;
  try {
    repository = await client.getRepository(repo.owner, repo.name);
  } catch (error) {
    const access =
      isGitHubAuthError(error) && error.code === "not_found"
        ? {
            status: "failed" as const,
            reason: `The signed-in user cannot access github.com/${repoName}.`,
          }
        : describeApiError(error, "read the repository from GitHub");
    results.set("current_access", access);
    results.set("owner_approval", notEvaluated("current_access"));
    results.set("contribution", notEvaluated("current_access"));
    return build(repoName, revision);
  }

  // From here on, report GitHub's canonical name (the remote may use an old or differently
  // cased name that GitHub redirects).
  const canonicalName = repository.fullName;
  const access = verifyCurrentAccess(repository);
  results.set("current_access", access);
  const ownerApproval = await evaluateOwnerApproval(client, repository, {
    user,
    remoteOwner: repo.owner,
    appSlug: deps.appSlug ?? null,
  });
  results.set("owner_approval", ownerApproval.check);
  remedy = ownerApproval.remedy;
  if (access.status !== "passed") {
    results.set("contribution", notEvaluated("current_access"));
    return build(canonicalName, revision);
  }
  results.set(
    "contribution",
    await verifyContribution({
      client,
      user,
      repository,
      projectRoot,
      runner,
      maxCandidates,
      // Owner evidence only from a passed owner approval in this run; otherwise no exemption.
      ownerEvidence: ownerApproval.check.status === "passed" ? ownerApproval.ownerEvidence : null,
    }),
  );
  return build(canonicalName, revision);
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

/**
 * The remedy frontends offer (install link, wait, then the full authorization again), or `null`.
 * It applies only when owner approval failed with an install remedy and every other check
 * passed: installing the App could then be the only missing step. It never changes the outcome.
 */
export function guidedInstallRemedy(outcome: AuthorizationOutcome): OwnerApprovalRemedy | null {
  const remedy = outcome.remedy ?? null;
  if (remedy === null || outcome.summary.decision !== "blocked") return null;
  const { checks } = outcome.summary;
  const isOnlyOwnerApproval =
    checks.length === AUTHORIZATION_CHECK_ORDER.length &&
    AUTHORIZATION_CHECK_ORDER.every((id, index) => {
      const check = checks[index];
      if (check?.id !== id) return false;
      return id === "owner_approval" ? check.status === "failed" : check.status === "passed";
    });
  return isOnlyOwnerApproval ? remedy : null;
}

/**
 * Evaluates only the owner_approval check again, with the same code the gate uses (repository,
 * sign-in and repository lookup first). Used to notice that the App was installed while the
 * user was on GitHub. A `passed` result here is NOT an authorization: callers must run
 * `authorizeProject` again from scratch before any scan.
 */
export async function recheckOwnerApproval(
  projectRoot: string,
  deps: AuthorizationDependencies,
): Promise<OwnerApprovalRecheck> {
  const runner = deps.runGit ?? defaultRunGit;
  const notChecked = (check: CheckResult): OwnerApprovalRecheck => ({ ...check, remedy: null });
  const repositoryResult = await verifyRepository(projectRoot, runner);
  const repo = repositoryResult.repo;
  if (repositoryResult.check.status !== "passed" || repo === null) {
    return notChecked(notEvaluated("repository"));
  }
  let session: GitHubSession;
  let user: GitHubUser;
  try {
    session = await deps.getGitHubSession();
    user = await session.client.getAuthenticatedUser();
  } catch (error) {
    return notChecked(describeIdentityError(error));
  }
  let repository: GitHubRepository;
  try {
    repository = await session.client.getRepository(repo.owner, repo.name);
  } catch (error) {
    return notChecked(describeApiError(error, "read the repository from GitHub"));
  }
  const result = await evaluateOwnerApproval(session.client, repository, {
    user,
    remoteOwner: repo.owner,
    appSlug: deps.appSlug ?? null,
  });
  return { ...result.check, remedy: result.remedy };
}
