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
const REDIRECT_STATUSES: readonly number[] = [301, 302, 307, 308];

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
  /**
   * `repository_selection` as GitHub reports it. `null` when it is missing or not exactly `all`
   * or `selected`; callers must not guess in that case.
   */
  repositorySelection: "all" | "selected" | null;
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

/**
 * The signed-in user's membership in an organization (`GET /user/memberships/orgs/{org}`).
 * `state` and `role` are GitHub's raw values (`active`/`pending`, `admin`/`member`/...), so
 * callers decide what counts; only `active` + `admin` means organization owner.
 */
export interface GitHubOrganizationMembership {
  state: string;
  role: string;
  organization: GitHubAccount;
  user: GitHubAccount;
}

/** Status of `head` relative to `base` in `GET /repos/{o}/{r}/compare/{base}...{head}`. */
export type GitHubCompareStatus = "ahead" | "behind" | "identical" | "diverged";

export interface GitHubPullRequestSummary {
  number: number;
  userId: number | null;
  mergedAt: string | null;
  /** Branch the PR targets (`base.ref`). */
  baseRef: string | null;
  /** Repository the PR targets (`base.repo.id`). */
  baseRepositoryId: number | null;
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
  /**
   * The signed-in user's membership in `org`. Throws `GitHubAuthError` with code `forbidden`
   * (403, e.g. the App lacks the organization Members permission), `not_found` (404),
   * `rate_limited`, `unauthorized`, `http_error`, `network_error` or `unexpected_response`.
   */
  getOrganizationMembership(org: string): Promise<GitHubOrganizationMembership>;
  /**
   * A user or organization account by login (`GET /users/{login}`, public, works for both).
   * Throws `GitHubAuthError` with code `not_found` when no such account exists.
   */
  getAccount(login: string): Promise<GitHubAccount & { type: string }>;
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

  /**
   * Redirects are never followed automatically, so the token is only ever sent to the API origin
   * (like the OAuth calls, which use `redirect: "error"`). One flow needs a redirect: GitHub
   * answers a renamed or transferred repository with a 301/307 to
   * `https://api.github.com/repositories/{id}...`. That one hop is repeated by hand, but only
   * when the target is the same API origin and an id-based `/repositories/{id}` path; anything
   * else is refused with a clear message.
   */
  async function send(url: string): Promise<FetchResponseLike> {
    try {
      return await fetchImpl(url, {
        method: "GET",
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${token}`,
          "X-GitHub-Api-Version": API_VERSION,
          "User-Agent": "pgard",
        },
        redirect: "manual",
        ...(options.signal ? { signal: options.signal } : {}),
      });
    } catch (error) {
      if (options.signal?.aborted) {
        throw new GitHubAuthError("cancelled", "The GitHub request was cancelled.");
      }
      throw new GitHubAuthError("network_error", "Could not reach the GitHub API.");
    }
  }

  function redirectTarget(response: FetchResponseLike, from: string): string {
    const refusal = new GitHubAuthError(
      "http_error",
      "GitHub redirected the request (for example, the repository was renamed or moved) and PGARD does not follow that automatically. Update the repository's remote URL to its current name and try again.",
      response.status,
    );
    const location = response.headers?.get("location") ?? null;
    if (location === null) throw refusal;
    let target: URL;
    try {
      target = new URL(location, from);
    } catch {
      throw refusal;
    }
    if (
      target.origin !== new URL(baseUrl).origin ||
      target.username !== "" ||
      target.password !== "" ||
      !/^\/repositories\/[0-9]+(\/|$)/.test(target.pathname)
    ) {
      throw refusal;
    }
    return target.toString();
  }

  async function request(path: string): Promise<FetchResponseLike> {
    const url = `${baseUrl}${path}`;
    const response = await send(url);
    if (!REDIRECT_STATUSES.includes(response.status)) return response;
    const second = await send(redirectTarget(response, url));
    if (REDIRECT_STATUSES.includes(second.status)) {
      throw new GitHubAuthError(
        "http_error",
        "GitHub redirected the request more than once; PGARD stopped.",
        second.status,
      );
    }
    return second;
  }

  /**
   * `allowNotFound`: 404 and 422 mean "no such object" and return `null`. `alsoNull` adds
   * statuses that mean the same for one endpoint.
   */
  async function getJson(
    path: string,
    allowNotFound: boolean,
    alsoNull: readonly number[] = [],
  ): Promise<unknown | null> {
    const response = await request(path);
    if (
      allowNotFound &&
      (response.status === 404 || response.status === 422 || alsoNull.includes(response.status))
    ) {
      return null;
    }
    if (response.status === 401) {
      throw new GitHubAuthError(
        "unauthorized",
        "The GitHub sign-in is no longer valid (expired or revoked).",
        401,
      );
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

  /** Like `getJson`, but tells a rate limit and a permission 403 apart from other failures. */
  async function getJsonDistinguishingForbidden(path: string): Promise<unknown> {
    const response = await request(path);
    const remaining = response.headers?.get("x-ratelimit-remaining") ?? null;
    // A secondary rate limit is a 403 with `retry-after` (and possibly requests remaining).
    const retryAfter = response.headers?.get("retry-after") ?? null;
    const isRateLimited403 = response.status === 403 && (remaining === "0" || retryAfter !== null);
    if (response.status === 429 || isRateLimited403) {
      throw new GitHubAuthError(
        "rate_limited",
        "GitHub API rate limit reached; try again later.",
        response.status,
      );
    }
    if (response.status === 403) {
      throw new GitHubAuthError("forbidden", "GitHub refused the request (403).", 403);
    }
    if (response.status === 401) {
      throw new GitHubAuthError(
        "unauthorized",
        "The GitHub sign-in is no longer valid (expired or revoked).",
        401,
      );
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
        return items;
      }
    }
    // Never return a silently truncated listing: callers would treat "not found" as proof.
    throw new GitHubAuthError(
      "result_truncated",
      `GitHub returned more ${key} than PGARD examines (${MAX_PAGES * PAGE_SIZE}).`,
    );
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
        const selection = record?.repository_selection;
        return {
          id,
          targetType,
          account: { id: account.id, login: account.login },
          repositorySelection: selection === "all" || selection === "selected" ? selection : null,
        };
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

    async getOrganizationMembership(org) {
      const body = asRecord(
        await getJsonDistinguishingForbidden(
          `/user/memberships/orgs/${encodeSegment(org, "organization")}`,
        ),
      );
      const state = asString(body?.state);
      const role = asString(body?.role);
      const organization = parseAccount(body?.organization);
      const user = parseAccount(body?.user);
      if (state === null || role === null || organization === null || user === null) {
        throw malformed("organization membership");
      }
      return {
        state,
        role,
        organization: { id: organization.id, login: organization.login },
        user: { id: user.id, login: user.login },
      };
    },

    async getAccount(login) {
      const body = asRecord(await getJson(`/users/${encodeSegment(login, "account")}`, false));
      const account = parseAccount(body);
      if (account === null) {
        throw malformed("account");
      }
      return account;
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
      // 409 is GitHub's answer for an empty repository: no commit of it can contain `base`.
      const body = asRecord(await getJson(path, true, [409]));
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
      if (body.length >= PAGE_SIZE) {
        throw new GitHubAuthError(
          "result_truncated",
          `GitHub returned more pull requests for a commit than PGARD examines (${PAGE_SIZE}).`,
        );
      }
      return body.map((item) => {
        const record = asRecord(item);
        const number = asInteger(record?.number);
        if (number === null) {
          throw malformed("pull request");
        }
        const base = asRecord(record?.base);
        return {
          number,
          userId: asInteger(asRecord(record?.user)?.id),
          mergedAt: asString(record?.merged_at),
          baseRef: asString(base?.ref),
          baseRepositoryId: asInteger(asRecord(base?.repo)?.id),
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
