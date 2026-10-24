import { GitHubAuthError } from "./errors.js";
import {
  asInteger,
  asRecord,
  asString,
  defaultFetch,
  type FetchLike,
  type FetchResponseLike,
} from "./fetch.js";

export const GITHUB_API_BASE_URL = "https://api.github.com";
const API_VERSION = "2022-11-28";
const PAGE_SIZE = 100;
/** Upper bound for paginated listings so a huge account cannot cause unbounded traffic. */
const MAX_PAGES = 10;

export interface GitHubUser {
  id: number;
  login: string;
  name: string | null;
  email: string | null;
}

export interface GitHubAccount {
  id: number;
  login: string;
}

export interface GitHubInstallation {
  id: number;
  /** `User` or `Organization` as reported by GitHub. */
  targetType: string;
  account: GitHubAccount;
}

export interface GitHubRepositoryPermissions {
  admin: boolean;
  maintain: boolean;
  push: boolean;
  triage: boolean;
  pull: boolean;
}

export interface GitHubRepository {
  id: number;
  fullName: string;
  owner: GitHubAccount & { type: string };
  defaultBranch: string;
  /** Permissions of the authenticated user; `null` when GitHub omitted them. */
  permissions: GitHubRepositoryPermissions | null;
}

/** Status of `head` relative to `base` in `GET /repos/{o}/{r}/compare/{base}...{head}`. */
export type GitHubCompareStatus = "ahead" | "behind" | "identical" | "diverged";

export interface GitHubPullRequestSummary {
  number: number;
  userId: number | null;
  mergedAt: string | null;
}

export interface GitHubCommitSummary {
  sha: string;
  authorId: number | null;
  committerId: number | null;
  isVerified: boolean;
}

/**
 * Read-only GitHub REST calls used by the authorization gate. Implementations must never
 * expose the token they hold.
 */
export interface GitHubClient {
  getAuthenticatedUser(): Promise<GitHubUser>;
  listUserInstallations(): Promise<GitHubInstallation[]>;
  listInstallationRepositoryIds(installationId: number): Promise<number[]>;
  /** Throws `GitHubAuthError` with code `not_found` when the user cannot see the repo. */
  getRepository(owner: string, name: string): Promise<GitHubRepository>;
  /** Returns `null` when GitHub cannot compare the refs (e.g. unknown SHA). */
  compareCommits(
    owner: string,
    name: string,
    base: string,
    head: string,
  ): Promise<GitHubCompareStatus | null>;
  listPullRequestsForCommit(
    owner: string,
    name: string,
    sha: string,
  ): Promise<GitHubPullRequestSummary[]>;
  /** Returns `null` when the commit does not exist on GitHub. */
  getCommit(owner: string, name: string, sha: string): Promise<GitHubCommitSummary | null>;
}

export interface GitHubClientOptions {
  token: string;
  fetch?: FetchLike;
  baseUrl?: string;
  signal?: AbortSignal;
}

const SEGMENT_PATTERN = /^[A-Za-z0-9._-]{1,100}$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const BRANCH_PATTERN = /^[A-Za-z0-9._\/-]{1,255}$/;

function encodeSegment(value: string, label: string): string {
  if (!SEGMENT_PATTERN.test(value) || value === "." || value === "..") {
    throw new GitHubAuthError("unexpected_response", `Invalid GitHub ${label}.`);
  }
  return encodeURIComponent(value);
}

function encodeRef(value: string): string {
  if (SHA_PATTERN.test(value)) {
    return value;
  }
  if (!BRANCH_PATTERN.test(value) || value.includes("..")) {
    throw new GitHubAuthError("unexpected_response", "Invalid Git reference.");
  }
  return value.split("/").map(encodeURIComponent).join("/");
}

function requireSha(value: string): string {
  if (!SHA_PATTERN.test(value)) {
    throw new GitHubAuthError("unexpected_response", "Invalid commit SHA.");
  }
  return value;
}

function parseAccount(value: unknown): (GitHubAccount & { type: string }) | null {
  const record = asRecord(value);
  const id = asInteger(record?.id);
  const login = asString(record?.login);
  if (id === null || login === null) {
    return null;
  }
  return { id, login, type: asString(record?.type) ?? "" };
}

function parsePermissions(value: unknown): GitHubRepositoryPermissions | null {
  const record = asRecord(value);
  if (!record) {
    return null;
  }
  return {
    admin: record.admin === true,
    maintain: record.maintain === true,
    push: record.push === true,
    triage: record.triage === true,
    pull: record.pull === true,
  };
}

function malformed(what: string): GitHubAuthError {
  return new GitHubAuthError("unexpected_response", `GitHub returned a malformed ${what}.`);
}

/**
 * Creates a client bound to a user access token. The token is kept in this closure only; it is
 * not a property of the returned object and is never included in errors.
 */
export function createGitHubClient(options: GitHubClientOptions): GitHubClient {
  const { token } = options;
  const fetchImpl = options.fetch ?? defaultFetch;
  const baseUrl = options.baseUrl ?? GITHUB_API_BASE_URL;

  async function request(path: string): Promise<FetchResponseLike> {
    let response: FetchResponseLike;
    try {
      response = await fetchImpl(`${baseUrl}${path}`, {
        method: "GET",
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${token}`,
          "X-GitHub-Api-Version": API_VERSION,
          "User-Agent": "pgard",
        },
        redirect: "follow",
        ...(options.signal ? { signal: options.signal } : {}),
      });
    } catch (error) {
      if (options.signal?.aborted) {
        throw new GitHubAuthError("cancelled", "The GitHub request was cancelled.");
      }
      throw new GitHubAuthError("network_error", "Could not reach the GitHub API.");
    }
    return response;
  }

  async function getJson(path: string, allowNotFound: boolean): Promise<unknown | null> {
    const response = await request(path);
    if (allowNotFound && (response.status === 404 || response.status === 422)) {
      return null;
    }
    if (response.status === 404) {
      throw new GitHubAuthError("not_found", "GitHub resource not found or not visible.", 404);
    }
    if (!response.ok) {
      throw new GitHubAuthError(
        "http_error",
        `GitHub API request failed with status ${response.status}.`,
        response.status,
      );
    }
    try {
      return await response.json();
    } catch {
      throw malformed("response body");
    }
  }

  async function getPaged(basePath: string, key: string): Promise<unknown[]> {
    const items: unknown[] = [];
    for (let page = 1; page <= MAX_PAGES; page += 1) {
      const separator = basePath.includes("?") ? "&" : "?";
      const body = asRecord(
        await getJson(`${basePath}${separator}per_page=${PAGE_SIZE}&page=${page}`, false),
      );
      const pageItems = body?.[key];
      if (!Array.isArray(pageItems)) {
        throw malformed(`${key} listing`);
      }
      items.push(...pageItems);
      if (pageItems.length < PAGE_SIZE) {
        break;
      }
    }
    return items;
  }

  return {
    async getAuthenticatedUser() {
      const body = asRecord(await getJson("/user", false));
      const id = asInteger(body?.id);
      const login = asString(body?.login);
      if (id === null || login === null) {
        throw malformed("user");
      }
      return { id, login, name: asString(body?.name), email: asString(body?.email) };
    },

    async listUserInstallations() {
      const raw = await getPaged("/user/installations", "installations");
      return raw.map((item) => {
        const record = asRecord(item);
        const id = asInteger(record?.id);
        const account = parseAccount(record?.account);
        const targetType = asString(record?.target_type);
        if (id === null || account === null || targetType === null) {
          throw malformed("installation");
        }
        return { id, targetType, account: { id: account.id, login: account.login } };
      });
    },

    async listInstallationRepositoryIds(installationId) {
      if (!Number.isSafeInteger(installationId) || installationId <= 0) {
        throw malformed("installation id");
      }
      const raw = await getPaged(
        `/user/installations/${installationId}/repositories`,
        "repositories",
      );
      return raw.map((item) => {
        const id = asInteger(asRecord(item)?.id);
        if (id === null) {
          throw malformed("repository listing");
        }
        return id;
      });
    },

    async getRepository(owner, name) {
      const path = `/repos/${encodeSegment(owner, "owner")}/${encodeSegment(name, "repository")}`;
      const body = asRecord(await getJson(path, false));
      const id = asInteger(body?.id);
      const fullName = asString(body?.full_name);
      const repoOwner = parseAccount(body?.owner);
      const defaultBranch = asString(body?.default_branch);
      if (id === null || fullName === null || repoOwner === null || defaultBranch === null) {
        throw malformed("repository");
      }
      return {
        id,
        fullName,
        owner: repoOwner,
        defaultBranch,
        permissions: parsePermissions(body?.permissions),
      };
    },

    async compareCommits(owner, name, base, head) {
      const path =
        `/repos/${encodeSegment(owner, "owner")}/${encodeSegment(name, "repository")}` +
        `/compare/${encodeRef(base)}...${encodeRef(head)}?per_page=1`;
      const body = asRecord(await getJson(path, true));
      if (body === null) {
        return null;
      }
      const status = asString(body.status);
      if (
        status === "ahead" ||
        status === "behind" ||
        status === "identical" ||
        status === "diverged"
      ) {
        return status;
      }
      throw malformed("comparison");
    },

    async listPullRequestsForCommit(owner, name, sha) {
      const path =
        `/repos/${encodeSegment(owner, "owner")}/${encodeSegment(name, "repository")}` +
        `/commits/${requireSha(sha)}/pulls?per_page=${PAGE_SIZE}`;
      const body = await getJson(path, true);
      if (body === null) {
        return [];
      }
      if (!Array.isArray(body)) {
        throw malformed("pull request listing");
      }
      return body.map((item) => {
        const record = asRecord(item);
        const number = asInteger(record?.number);
        if (number === null) {
          throw malformed("pull request");
        }
        return {
          number,
          userId: asInteger(asRecord(record?.user)?.id),
          mergedAt: asString(record?.merged_at),
        };
      });
    },

    async getCommit(owner, name, sha) {
      const path =
        `/repos/${encodeSegment(owner, "owner")}/${encodeSegment(name, "repository")}` +
        `/commits/${requireSha(sha)}`;
      const body = asRecord(await getJson(path, true));
      if (body === null) {
        return null;
      }
      const commitSha = asString(body.sha);
      if (commitSha === null) {
        throw malformed("commit");
      }
      const verification = asRecord(asRecord(body.commit)?.verification);
      return {
        sha: commitSha,
        authorId: asInteger(asRecord(body.author)?.id),
        committerId: asInteger(asRecord(body.committer)?.id),
        isVerified: verification?.verified === true,
      };
    },
  };
}
