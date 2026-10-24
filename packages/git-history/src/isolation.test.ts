import { writeFileSync } from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readRepositoryIsolation } from "./isolation.js";
import { createGitFixture, type GitFixture } from "./test-support/git-fixture.js";

describe("readRepositoryIsolation", () => {
  const fixtures: GitFixture[] = [];
  const create = () => {
    const fixture = createGitFixture();
    fixtures.push(fixture);
    return fixture;
  };
  afterEach(() => {
    for (const fixture of fixtures.splice(0)) {
      fixture.cleanup();
    }
  });

  it("accepts a self-contained repository", async () => {
    const repo = create();
    repo.commit({});
    expect(await readRepositoryIsolation(repo.root)).toEqual({ isIsolated: true });
  });

  it("rejects object alternates pointing at another repository", async () => {
    const sibling = create();
    sibling.commit({ files: { "secret.txt": "from sibling\n" } });
    const repo = create();
    repo.commit({});
    writeFileSync(
      path.join(repo.root, ".git", "objects", "info", "alternates"),
      `${path.join(sibling.root, ".git", "objects")}\n`,
    );
    const result = await readRepositoryIsolation(repo.root);
    expect(result.isIsolated).toBe(false);
    expect(!result.isIsolated && result.reason).toMatch(/alternates/);
  });

  it("rejects grafts", async () => {
    const repo = create();
    const first = repo.commit({});
    const second = repo.commit({});
    writeFileSync(path.join(repo.root, ".git", "info", "grafts"), `${second} ${first}\n`);
    expect((await readRepositoryIsolation(repo.root)).isIsolated).toBe(false);
  });

  it("rejects replace refs", async () => {
    const repo = create();
    const first = repo.commit({});
    const second = repo.commit({});
    repo.git("replace", first, second);
    const result = await readRepositoryIsolation(repo.root);
    expect(result.isIsolated).toBe(false);
    expect(!result.isIsolated && result.reason).toMatch(/replace/);
  });
});
