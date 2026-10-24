/** Test-only in-memory GitHub client. Never contacts GitHub. */
import {
  GitHubAuthError,
  createGitHubSession,
  type GitHubClient,
  type GitHubCommitSummary,
  type GitHubCompareStatus,
  type GitHubInstallation,
  type GitHubPullRequestSummary,
  type GitHubRepository,
  type GitHubSession,
  type GitHubUser,
} from "@pgard/github-auth";

export interface MockGitHubState {
  user: GitHubUser;
  repository: GitHubRepository | null;
  installations: GitHubInstallation[];
  installationRepositories: Record<number, number[]>;
  pulls: Record<string, GitHubPullRequestSummary[]>;
  commits: Record<string, GitHubCommitSummary>;
  /** Comparison of `sha...defaultBranch`; missing ⇒ `null` (unknown to GitHub). */
  compare: Record<string, GitHubCompareStatus>;
  failWith?: GitHubAuthError;
}

export const ME: GitHubUser = { id: 1001, login: "me", name: "Me Person", email: "me@example.com" };
export const OWNER_ID = 1001;

export function userRepository(overrides: Partial<GitHubRepository> = {}): GitHubRepository {
  return {
    id: 555,
    fullName: "me/app",
    owner: { id: OWNER_ID, login: "me", type: "User" },
    defaultBranch: "main",
    permissions: { admin: true, maintain: true, push: true, triage: true, pull: true },
    ...overrides,
  };
}

export function ownerInstallation(accountId = OWNER_ID): GitHubInstallation {
  return { id: 77, targetType: "User", account: { id: accountId, login: "me" } };
}

export function createMockGitHub(state: MockGitHubState): {
  session: GitHubSession;
  calls: string[];
} {
  const calls: string[] = [];
  const guard = (name: string) => {
    calls.push(name);
    if (state.failWith) {
      throw state.failWith;
    }
  };
  const client: GitHubClient = {
    async getAuthenticatedUser() {
      guard("user");
      return state.user;
    },
    async listUserInstallations() {
      guard("installations");
      return state.installations;
    },
    async listInstallationRepositoryIds(id) {
      guard(`installation-repos:${id}`);
      return state.installationRepositories[id] ?? [];
    },
    async getRepository() {
      guard("repo");
      if (!state.repository) {
        throw new GitHubAuthError("not_found", "not found", 404);
      }
      return state.repository;
    },
    async compareCommits(o, r, base) {
      guard(`compare:${o}/${r}:${base}`);
      return state.compare[base] ?? null;
    },
    async listPullRequestsForCommit(o, r, sha) {
      guard(`pulls:${o}/${r}:${sha}`);
      return state.pulls[sha] ?? [];
    },
    async getCommit(o, r, sha) {
      guard(`commit:${o}/${r}:${sha}`);
      return state.commits[sha] ?? null;
    },
  };
  return { session: createGitHubSession(client), calls };
}
