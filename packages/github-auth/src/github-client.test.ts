import { describe, expect, it } from "vitest";
import {
  DEFAULT_GITHUB_APP_CLIENT_ID,
  INVALID_CLIENT_ID_OVERRIDE_MESSAGE,
  resolveGitHubAppClientId,
} from "./env.js";
import type { FetchLike } from "./fetch.js";
import { createGitHubClient } from "./github-client.js";

function jsonResponse(status: number, body: unknown) {
  return { status, ok: status >= 200 && status < 300, json: async () => body };
}

function routeFetch(routes: Record<string, [number, unknown]>): {
  fetch: FetchLike;
  urls: string[];
} {
  const urls: string[] = [];
  const fetch: FetchLike = async (url) => {
    urls.push(url);
    const path = url.replace("https://api.github.com", "");
    const route = routes[path];
    return route ? jsonResponse(route[0], route[1]) : jsonResponse(404, {});
  };
  return { fetch, urls };
}

const SHA = "a".repeat(40);

describe("createGitHubClient", () => {
  it("parses repository permissions and owner type", async () => {
    const { fetch } = routeFetch({
      "/repos/octo/app": [
        200,
        {
          id: 1,
          full_name: "octo/app",
          owner: { id: 7, login: "octo", type: "User" },
          default_branch: "main",
          permissions: { pull: true, push: false },
        },
      ],
    });
    const client = createGitHubClient({ token: "t", fetch });
    const repo = await client.getRepository("octo", "app");
    expect(repo.owner).toEqual({ id: 7, login: "octo", type: "User" });
    expect(repo.permissions?.pull).toBe(true);
    expect(repo.permissions?.admin).toBe(false);
  });

  it("throws not_found for invisible repositories", async () => {
    const client = createGitHubClient({ token: "t", fetch: routeFetch({}).fetch });
    await expect(client.getRepository("octo", "secret")).rejects.toMatchObject({
      code: "not_found",
    });
  });

  it("rejects path-injection in owner/repo before any request", async () => {
    const { fetch, urls } = routeFetch({});
    const client = createGitHubClient({ token: "t", fetch });
    await expect(client.getRepository("..", "x")).rejects.toThrow();
    await expect(client.getRepository("a/b", "x")).rejects.toThrow();
    await expect(client.getCommit("o", "r", "HEAD")).rejects.toThrow();
    expect(urls).toEqual([]);
  });

  it("returns null comparison for unknown SHAs and parses status", async () => {
    const { fetch } = routeFetch({
      [`/repos/o/r/compare/${SHA}...main?per_page=1`]: [200, { status: "ahead" }],
    });
    const client = createGitHubClient({ token: "t", fetch });
    expect(await client.compareCommits("o", "r", SHA, "main")).toBe("ahead");
    expect(await client.compareCommits("o", "r", "b".repeat(40), "main")).toBeNull();
  });

  it("paginates installations and repositories with a bound", async () => {
    const page = Array.from({ length: 100 }, (_, index) => ({ id: index + 1 }));
    const { fetch, urls } = routeFetch({
      "/user/installations/5/repositories?per_page=100&page=1": [
        200,
        { total_count: 101, repositories: page },
      ],
      "/user/installations/5/repositories?per_page=100&page=2": [
        200,
        { total_count: 101, repositories: [{ id: 999 }] },
      ],
    });
    const client = createGitHubClient({ token: "t", fetch });
    const ids = await client.listInstallationRepositoryIds(5);
    expect(ids).toHaveLength(101);
    expect(urls).toHaveLength(2);
  });

  it("reads commit verification and pull request authors", async () => {
    const { fetch } = routeFetch({
      [`/repos/o/r/commits/${SHA}`]: [
        200,
        {
          sha: SHA,
          author: { id: 7 },
          committer: { id: 7 },
          commit: { verification: { verified: true } },
        },
      ],
      [`/repos/o/r/commits/${SHA}/pulls?per_page=100`]: [
        200,
        [
          {
            number: 3,
            user: { id: 7 },
            merged_at: "2026-01-01T00:00:00Z",
            base: { ref: "main", repo: { id: 55 } },
          },
        ],
      ],
    });
    const client = createGitHubClient({ token: "t", fetch });
    expect(await client.getCommit("o", "r", SHA)).toEqual({
      sha: SHA,
      authorId: 7,
      committerId: 7,
      isVerified: true,
    });
    expect(await client.listPullRequestsForCommit("o", "r", SHA)).toEqual([
      {
        number: 3,
        userId: 7,
        mergedAt: "2026-01-01T00:00:00Z",
        baseRef: "main",
        baseRepositoryId: 55,
      },
    ]);
  });

  it("refuses to return truncated listings", async () => {
    const full = Array.from({ length: 100 }, (_, index) => ({ id: index + 1 }));
    const routes: Record<string, [number, unknown]> = {};
    for (let page = 1; page <= 10; page += 1) {
      routes[`/user/installations/5/repositories?per_page=100&page=${page}`] = [
        200,
        { repositories: full },
      ];
    }
    routes[`/repos/o/r/commits/${SHA}/pulls?per_page=100`] = [
      200,
      Array.from({ length: 100 }, (_, index) => ({ number: index + 1 })),
    ];
    const client = createGitHubClient({ token: "t", fetch: routeFetch(routes).fetch });
    await expect(client.listInstallationRepositoryIds(5)).rejects.toMatchObject({
      code: "result_truncated",
    });
    await expect(client.listPullRequestsForCommit("o", "r", SHA)).rejects.toMatchObject({
      code: "result_truncated",
    });
  });

  it("maps 401 to unauthorized", async () => {
    const { fetch } = routeFetch({ "/user": [401, { message: "Bad credentials" }] });
    const client = createGitHubClient({ token: "t", fetch });
    await expect(client.getAuthenticatedUser()).rejects.toMatchObject({ code: "unauthorized" });
  });

  it("reports HTTP failures without echoing response bodies", async () => {
    const { fetch } = routeFetch({ "/user": [500, { message: "internal secret detail" }] });
    const client = createGitHubClient({ token: "t", fetch });
    const error = await client.getAuthenticatedUser().catch((caught: unknown) => caught);
    expect(error).toMatchObject({ code: "http_error", status: 500 });
    expect((error as Error).message).not.toContain("secret detail");
  });
});

describe("resolveGitHubAppClientId", () => {
  const builtIn = { clientId: DEFAULT_GITHUB_APP_CLIENT_ID, source: "default" };

  it("ships the public client id of the PGARD GitHub App as the default", () => {
    expect(DEFAULT_GITHUB_APP_CLIENT_ID).toBe("Iv23liKDf0mhnPl2c7zj");
  });

  it("uses the built-in App when the override is unset, empty or whitespace-only", () => {
    expect(resolveGitHubAppClientId({})).toEqual(builtIn);
    expect(resolveGitHubAppClientId({ PGARD_GITHUB_APP_CLIENT_ID: "" })).toEqual(builtIn);
    expect(resolveGitHubAppClientId({ PGARD_GITHUB_APP_CLIENT_ID: " \t " })).toEqual(builtIn);
  });

  it("lets a non-empty override win, trimmed", () => {
    expect(resolveGitHubAppClientId({ PGARD_GITHUB_APP_CLIENT_ID: " Iv23liExample\n" })).toEqual({
      clientId: "Iv23liExample",
      source: "env",
    });
  });

  it("reports an override equal to the built-in id as coming from the env", () => {
    expect(
      resolveGitHubAppClientId({ PGARD_GITHUB_APP_CLIENT_ID: DEFAULT_GITHUB_APP_CLIENT_ID }),
    ).toEqual({ ...builtIn, source: "env" });
  });

  it("resolves a malformed override to invalid with no client id, never to the built-in App", () => {
    for (const value of ["a b", '"bad id"', "Iv23/li", "x".repeat(101)]) {
      expect(resolveGitHubAppClientId({ PGARD_GITHUB_APP_CLIENT_ID: value })).toEqual({
        clientId: null,
        source: "invalid",
      });
    }
  });

  it("has a fixed reason for an invalid override that tells how to recover", () => {
    expect(INVALID_CLIENT_ID_OVERRIDE_MESSAGE).toBe(
      "PGARD_GITHUB_APP_CLIENT_ID is set but is not a valid client id; unset it to use the built-in PGARD App.",
    );
  });
});
