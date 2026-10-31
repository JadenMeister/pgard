import { describe, expect, it } from "vitest";
import {
  DEFAULT_GITHUB_APP_CLIENT_ID,
  DEFAULT_GITHUB_APP_SLUG,
  INVALID_APP_SLUG_OVERRIDE_MESSAGE,
  INVALID_CLIENT_ID_OVERRIDE_MESSAGE,
  resolveGitHubAppClientId,
} from "./env.js";
import { GITHUB_REQUEST_TIMEOUT_MS, type FetchLike } from "./fetch.js";
import { createGitHubClient } from "./github-client.js";
import { TIME_FACTOR, itScaled } from "../../../tests/support/timing.js";

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

describe("getAccount", () => {
  it("reads a user or organization from the public /users endpoint", async () => {
    const { fetch, urls } = routeFetch({
      "/users/acme": [200, { id: 42, login: "acme", type: "Organization" }],
    });
    const client = createGitHubClient({ token: "t", fetch });
    expect(await client.getAccount("acme")).toEqual({
      id: 42,
      login: "acme",
      type: "Organization",
    });
    expect(urls).toEqual(["https://api.github.com/users/acme"]);
  });

  it("maps 404 to not_found, rejects malformed bodies and unsafe logins", async () => {
    const { fetch, urls } = routeFetch({ "/users/bad": [200, { login: "bad" }] });
    const client = createGitHubClient({ token: "t", fetch });
    await expect(client.getAccount("ghost")).rejects.toMatchObject({ code: "not_found" });
    await expect(client.getAccount("bad")).rejects.toMatchObject({ code: "unexpected_response" });
    urls.length = 0;
    for (const unsafe of ["a/b", "..", "a?b", "a#b", "a b", ""]) {
      await expect(client.getAccount(unsafe)).rejects.toMatchObject({
        code: "unexpected_response",
      });
    }
    // Rejected before any request is made.
    expect(urls).toEqual([]);
  });
});

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

  it("returns null comparison for an empty repository (409) but throws on other errors", async () => {
    const { fetch } = routeFetch({
      [`/repos/o/empty/compare/${SHA}...main?per_page=1`]: [
        409,
        { message: "Git Repository is empty." },
      ],
      [`/repos/o/broken/compare/${SHA}...main?per_page=1`]: [500, {}],
    });
    const client = createGitHubClient({ token: "t", fetch });
    expect(await client.compareCommits("o", "empty", SHA, "main")).toBeNull();
    await expect(client.compareCommits("o", "broken", SHA, "main")).rejects.toMatchObject({
      code: "http_error",
    });
  });

  it("reads repository_selection of installations, null unless exactly all or selected", async () => {
    const base = { target_type: "User", account: { id: 1, login: "me" } };
    const { fetch } = routeFetch({
      "/user/installations?per_page=100&page=1": [
        200,
        {
          total_count: 5,
          installations: [
            { ...base, id: 1, repository_selection: "all" },
            { ...base, id: 2, repository_selection: "selected" },
            { ...base, id: 3 },
            { ...base, id: 4, repository_selection: "ALL" },
            { ...base, id: 5, repository_selection: 7 },
          ],
        },
      ],
    });
    const client = createGitHubClient({ token: "t", fetch });
    const installations = await client.listUserInstallations();
    expect(installations.map((item) => item.repositorySelection)).toEqual([
      "all",
      "selected",
      null,
      null,
      null,
    ]);
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

describe("createGitHubClient: getOrganizationMembership", () => {
  const MEMBERSHIP_PATH = "/user/memberships/orgs/acme";
  const MEMBERSHIP = {
    state: "active",
    role: "admin",
    organization: { id: 42, login: "acme" },
    user: { id: 7, login: "octo" },
  };

  function membershipFetch(
    status: number,
    body: unknown,
    headers: Record<string, string> = {},
  ): { fetch: FetchLike; urls: string[]; auth: string[] } {
    const urls: string[] = [];
    const auth: string[] = [];
    const fetch: FetchLike = async (url, init) => {
      urls.push(url);
      auth.push(init.headers.Authorization ?? "");
      return {
        ...jsonResponse(status, body),
        headers: { get: (name: string) => headers[name.toLowerCase()] ?? null },
      };
    };
    return { fetch, urls, auth };
  }

  it("reads state, role, organization and user with the same bearer token", async () => {
    const { fetch, urls, auth } = membershipFetch(200, MEMBERSHIP);
    const client = createGitHubClient({ token: "tok", fetch });
    expect(await client.getOrganizationMembership("acme")).toEqual({
      state: "active",
      role: "admin",
      organization: { id: 42, login: "acme" },
      user: { id: 7, login: "octo" },
    });
    expect(urls).toEqual([`https://api.github.com${MEMBERSHIP_PATH}`]);
    expect(auth).toEqual(["Bearer tok"]);
  });

  it.each([
    ["403 without a rate limit", 403, {}, "forbidden"],
    ["403 with no remaining requests", 403, { "x-ratelimit-remaining": "0" }, "rate_limited"],
    [
      "403 with retry-after (secondary rate limit)",
      403,
      { "x-ratelimit-remaining": "4999", "retry-after": "60" },
      "rate_limited",
    ],
    ["429", 429, {}, "rate_limited"],
    ["404", 404, {}, "not_found"],
    ["401", 401, {}, "unauthorized"],
    ["502", 502, {}, "http_error"],
  ] as const)("maps %s to %s", async (_label, status, headers, code) => {
    const client = createGitHubClient({
      token: "tok",
      fetch: membershipFetch(status, { message: "secret detail" }, headers).fetch,
    });
    const error = await client.getOrganizationMembership("acme").catch((caught: unknown) => caught);
    expect(error).toMatchObject({ code, status });
    expect((error as Error).message).not.toContain("secret detail");
    expect((error as Error).message).not.toContain("tok");
  });

  it.each([
    ["no role", { ...MEMBERSHIP, role: undefined }],
    ["no state", { ...MEMBERSHIP, state: 1 }],
    ["no organization", { ...MEMBERSHIP, organization: null }],
    ["no user", { ...MEMBERSHIP, user: { login: "octo" } }],
    ["an array", [MEMBERSHIP]],
  ])("rejects a membership with %s as malformed", async (_label, body) => {
    const client = createGitHubClient({ token: "tok", fetch: membershipFetch(200, body).fetch });
    await expect(client.getOrganizationMembership("acme")).rejects.toMatchObject({
      code: "unexpected_response",
    });
  });

  it("reports a network failure without contacting anything else", async () => {
    const fetch: FetchLike = async () => {
      throw new Error("ECONNRESET");
    };
    const client = createGitHubClient({ token: "tok", fetch });
    await expect(client.getOrganizationMembership("acme")).rejects.toMatchObject({
      code: "network_error",
    });
  });

  it("rejects an organization name that is not a single path segment", async () => {
    const { fetch, urls } = membershipFetch(200, MEMBERSHIP);
    const client = createGitHubClient({ token: "tok", fetch });
    await expect(client.getOrganizationMembership("../acme")).rejects.toThrow();
    await expect(client.getOrganizationMembership("a/b")).rejects.toThrow();
    expect(urls).toEqual([]);
  });
});

describe("resolveGitHubAppClientId", () => {
  const builtIn = {
    clientId: DEFAULT_GITHUB_APP_CLIENT_ID,
    slug: DEFAULT_GITHUB_APP_SLUG,
    source: "default",
  };

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
      slug: null,
      source: "env",
    });
  });

  it("reports an override equal to the built-in id as coming from the env", () => {
    expect(
      resolveGitHubAppClientId({ PGARD_GITHUB_APP_CLIENT_ID: DEFAULT_GITHUB_APP_CLIENT_ID }),
    ).toEqual({ ...builtIn, slug: null, source: "env" });
  });

  it("resolves a malformed override to invalid with no client id, never to the built-in App", () => {
    for (const value of ["a b", '"bad id"', "Iv23/li", "x".repeat(101)]) {
      expect(resolveGitHubAppClientId({ PGARD_GITHUB_APP_CLIENT_ID: value })).toEqual({
        clientId: null,
        slug: null,
        source: "invalid",
        message: INVALID_CLIENT_ID_OVERRIDE_MESSAGE,
      });
    }
  });

  it("has a fixed reason for an invalid override that tells how to recover", () => {
    expect(INVALID_CLIENT_ID_OVERRIDE_MESSAGE).toBe(
      "PGARD_GITHUB_APP_CLIENT_ID is set but is not a valid client id; unset it to use the built-in PGARD App.",
    );
  });

  it("ships the public slug of the PGARD GitHub App", () => {
    expect(DEFAULT_GITHUB_APP_SLUG).toBe("pgard-jadenmeister");
  });

  it("uses PGARD_GITHUB_APP_SLUG when set, trimmed, with or without a client id override", () => {
    expect(resolveGitHubAppClientId({ PGARD_GITHUB_APP_SLUG: " my-fork-app " })).toEqual({
      ...builtIn,
      slug: "my-fork-app",
    });
    expect(
      resolveGitHubAppClientId({
        PGARD_GITHUB_APP_CLIENT_ID: "Iv23liExample",
        PGARD_GITHUB_APP_SLUG: "my-fork-app",
      }),
    ).toEqual({ clientId: "Iv23liExample", slug: "my-fork-app", source: "env" });
  });

  it("gives no slug (no install link) when the client id is overridden without a slug", () => {
    expect(resolveGitHubAppClientId({ PGARD_GITHUB_APP_CLIENT_ID: "Iv23liExample" }).slug).toBe(
      null,
    );
  });

  it("blocks on a malformed slug override, never falling back to the built-in App", () => {
    for (const value of ["My-App", "a b", "../x", "app?x=1", "a".repeat(101), "app/1"]) {
      expect(resolveGitHubAppClientId({ PGARD_GITHUB_APP_SLUG: value })).toEqual({
        clientId: null,
        slug: null,
        source: "invalid",
        message: INVALID_APP_SLUG_OVERRIDE_MESSAGE,
      });
    }
    expect(INVALID_APP_SLUG_OVERRIDE_MESSAGE).not.toContain("My-App");
  });
});

describe("redirects on authenticated calls", () => {
  const repoBody = {
    id: 7,
    full_name: "acme/new-name",
    owner: { id: 1, login: "acme", type: "Organization" },
    default_branch: "main",
  };
  function redirecting(location: string | null, status = 301) {
    const calls: { url: string; redirect: string | undefined }[] = [];
    const fetch: FetchLike = async (url, init) => {
      calls.push({ url, redirect: init.redirect });
      if (url === "https://api.github.com/repos/acme/old-name") {
        return {
          status,
          ok: false,
          headers: { get: (name: string) => (name === "location" ? location : null) },
          json: async () => ({}),
        };
      }
      return jsonResponse(200, repoBody);
    };
    return { fetch, calls };
  }

  it("never lets fetch follow redirects on its own", async () => {
    const seen: (string | undefined)[] = [];
    const fetch: FetchLike = async (_url, init) => {
      seen.push(init.redirect);
      return jsonResponse(200, { id: 1, login: "a" });
    };
    await createGitHubClient({ token: "t", fetch }).getAuthenticatedUser();
    expect(seen).toEqual(["manual"]);
  });

  it("repeats a renamed-repository redirect once, to the API origin's /repositories/{id}", async () => {
    const { fetch, calls } = redirecting("https://api.github.com/repositories/7");
    const repo = await createGitHubClient({ token: "t", fetch }).getRepository("acme", "old-name");
    expect(repo.fullName).toBe("acme/new-name");
    expect(calls.map((call) => call.url)).toEqual([
      "https://api.github.com/repos/acme/old-name",
      "https://api.github.com/repositories/7",
    ]);
    expect(calls.every((call) => call.redirect === "manual")).toBe(true);
  });

  it("refuses redirects to another host, another path, plain http or with no location", async () => {
    for (const location of [
      "https://evil.example/repositories/7",
      "http://api.github.com/repositories/7",
      "https://api.github.com/user",
      "https://user:pw@api.github.com/repositories/7",
      "https://user@api.github.com/repositories/7",
      "https://api.github.com/x/repositories/7",
      "https://api.github.com/repositories/7/../../user",
      null,
    ]) {
      const { fetch, calls } = redirecting(location);
      await expect(
        createGitHubClient({ token: "t", fetch }).getRepository("acme", "old-name"),
      ).rejects.toMatchObject({ code: "http_error", status: 301 });
      expect(calls).toHaveLength(1);
    }
  });

  it("stops after one hop", async () => {
    let calls = 0;
    const fetch: FetchLike = async () => {
      calls += 1;
      return {
        status: 307,
        ok: false,
        headers: { get: () => "https://api.github.com/repositories/7" },
        json: async () => ({}),
      };
    };
    await expect(
      createGitHubClient({ token: "t", fetch }).getRepository("acme", "old-name"),
    ).rejects.toMatchObject({ code: "http_error", status: 307 });
    expect(calls).toBe(2);
  });
});

describe("a stalled network", () => {
  itScaled(
    "ends a request at its time limit with network_error, even if fetch ignores the signal",
    async () => {
      let seen: AbortSignal | undefined;
      // Never answers and never looks at the signal.
      const fetch: FetchLike = (_url, init) => {
        seen = init.signal;
        return new Promise(() => undefined);
      };
      const client = createGitHubClient({ token: "t", fetch, requestTimeoutMs: 20 });
      const started = Date.now();
      await expect(client.getAuthenticatedUser()).rejects.toMatchObject({
        code: "network_error",
        message: "The GitHub API did not answer within 1 s.",
      });
      expect(Date.now() - started).toBeLessThan(Math.min(5_000 * TIME_FACTOR, 8_000));
      expect(seen?.aborted).toBe(true);
    },
    15_000,
  );

  it("covers reading the body with the same limit", async () => {
    let seen: AbortSignal | undefined;
    const fetch: FetchLike = async (_url, init) => {
      seen = init.signal;
      return { status: 200, ok: true, json: () => new Promise(() => undefined) };
    };
    const client = createGitHubClient({ token: "t", fetch, requestTimeoutMs: 20 });
    await expect(client.getAuthenticatedUser()).rejects.toMatchObject({
      code: "network_error",
      message: "The GitHub API did not answer within 1 s.",
    });
    expect(seen?.aborted).toBe(true);
  });

  it("leaves no listener on the caller's signal, read or unread", async () => {
    const controller = new AbortController();
    let added = 0;
    let removed = 0;
    const signal = controller.signal;
    const add = signal.addEventListener.bind(signal);
    const remove = signal.removeEventListener.bind(signal);
    signal.addEventListener = ((...args: Parameters<AbortSignal["addEventListener"]>) => {
      added += 1;
      add(...args);
    }) as AbortSignal["addEventListener"];
    signal.removeEventListener = ((...args: Parameters<AbortSignal["removeEventListener"]>) => {
      removed += 1;
      remove(...args);
    }) as AbortSignal["removeEventListener"];
    let status = 404;
    const fetch: FetchLike = async () => ({
      status,
      ok: status === 200,
      json: async () => ({ id: 7, login: "octo", name: null, email: null }),
    });
    const client = createGitHubClient({ token: "t", fetch, signal });
    // 404, 401 and 403: the body is never read.
    for (const code of [404, 401, 403]) {
      status = code;
      await expect(client.getAuthenticatedUser()).rejects.toBeDefined();
    }
    status = 200;
    await client.getAuthenticatedUser();
    expect(added).toBeGreaterThan(0);
    expect(removed).toBe(added);
  });

  it("allows 10 s per request by default", () => {
    expect(GITHUB_REQUEST_TIMEOUT_MS).toBe(10_000);
  });
});
