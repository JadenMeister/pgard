import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { collectDependencies } from "./collect.js";

let root: string;
beforeEach(async () => {
  root = await mkdtemp(path.join(os.tmpdir(), "pgard-collect-test-"));
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

async function put(relative: string, content: string): Promise<void> {
  const file = path.join(root, relative);
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, content);
}

const npmLock = (deps: Record<string, string>): string =>
  JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { dependencies: Object.fromEntries(Object.keys(deps).map((n) => [n, "*"])) },
      ...Object.fromEntries(
        Object.entries(deps).map(([n, v]) => [`node_modules/${n}`, { version: v }]),
      ),
    },
  });

describe("collectDependencies", () => {
  it("finds lockfiles in a monorepo, with repository-relative paths, and skips ignored directories", async () => {
    await put("package.json", '{"dependencies":{"a":"1"}}');
    await put("package-lock.json", npmLock({ a: "1.0.0" }));
    await put("services/api/go.mod", "module api\n\ngo 1.22\n\nrequire github.com/x/y v1.0.0\n");
    await put("services/api/go.sum", "github.com/x/y v1.0.0 h1:a=\n");
    await put(
      "web/pnpm-lock.yaml",
      "lockfileVersion: '9.0'\npackages:\n  b@2.0.0:\n    resolution: {integrity: x}\n",
    );
    await put("node_modules/dep/package-lock.json", npmLock({ ignored: "9.9.9" }));
    await put("dist/yarn.lock", '# yarn lockfile v1\n\nignored@^1:\n  version "1.0.0"\n');
    await put("vendor/go.mod", "module v\ngo 1.22\nrequire github.com/ignored/v v1.0.0\n");
    await put("go.mod", "module root\ngo 1.22\n");
    const result = await collectDependencies(root);
    expect(
      result.dependencies.map((d) => `${d.ecosystem}:${d.name}@${d.version} <- ${d.path}`).sort(),
    ).toEqual([
      "Go:github.com/x/y@v1.0.0 <- services/api/go.mod",
      "npm:a@1.0.0 <- package-lock.json",
      "npm:b@2.0.0 <- web/pnpm-lock.yaml",
    ]);
    expect(result.coverage.map((c) => `${c.path}:${c.status}`)).toEqual([
      "go.mod:parsed",
      "package-lock.json:parsed",
      "services/api/go.mod:parsed",
      "web/pnpm-lock.yaml:parsed",
    ]);
    expect(result.isTruncated).toBe(false);
  });

  it("reports unsupported lockfiles and manifests without a lockfile, never as clean", async () => {
    await put("package.json", '{"dependencies":{"left-pad":"^1.0.0"}}');
    await put("tools/package.json", '{"devDependencies":{"x":"1"}}');
    await put("tools/bun.lockb", "binary");
    await put("py/poetry.lock", "[[package]]\n");
    await put("empty/package.json", '{"name":"no-deps"}');
    const result = await collectDependencies(root);
    expect(result.dependencies).toEqual([]);
    const byPath = new Map(result.coverage.map((c) => [c.path, c]));
    expect(byPath.get("package.json")).toMatchObject({
      status: "missing-lockfile",
      kind: "package.json",
    });
    expect(byPath.get("tools/package.json")?.status).toBe("missing-lockfile");
    expect(byPath.get("tools/bun.lockb")).toMatchObject({ status: "unsupported" });
    expect(byPath.get("tools/bun.lockb")?.note).toContain("Bun");
    expect(byPath.get("py/poetry.lock")?.status).toBe("unsupported");
    expect(byPath.has("empty/package.json")).toBe(false);
  });

  it("covers workspace members with the root lockfile, and a broken root lockfile covers nothing", async () => {
    await put("package.json", '{"workspaces":["packages/*"]}');
    await put("packages/a/package.json", '{"dependencies":{"z":"1"}}');
    await put("package-lock.json", npmLock({ z: "1.0.0" }));
    expect(
      (await collectDependencies(root)).coverage.some((c) => c.status === "missing-lockfile"),
    ).toBe(false);
    await put("package-lock.json", "{ broken");
    const broken = await collectDependencies(root);
    expect(broken.coverage.find((c) => c.path === "package-lock.json")?.status).toBe("failed");
    expect(broken.coverage.find((c) => c.path === "packages/a/package.json")?.status).toBe(
      "missing-lockfile",
    );
  });

  it("marks yarn direct dependencies from the package.json files below the lockfile", async () => {
    await put("package.json", '{"dependencies":{"lodash":"^4"}}');
    await put(
      "yarn.lock",
      '# yarn lockfile v1\n\nlodash@^4:\n  version "4.17.21"\n\nqs@^6:\n  version "6.0.0"\n',
    );
    const result = await collectDependencies(root);
    expect(result.dependencies.map((d) => [d.name, d.direct])).toEqual([
      ["lodash", true],
      ["qs", false],
    ]);
  });

  it("uses a go.sum next to a go.mod and reads a standalone go.sum", async () => {
    await put("old/go.mod", "module old\ngo 1.16\nrequire github.com/a/a v1.0.0\n");
    await put("old/go.sum", "github.com/a/a v1.0.0 h1:x=\ngithub.com/t/t v0.2.0 h1:y=\n");
    await put("solo/go.sum", "github.com/s/s v1.1.1 h1:z=\n");
    const result = await collectDependencies(root);
    expect(result.dependencies.map((d) => `${d.name}@${d.version} <- ${d.path}`).sort()).toEqual([
      "github.com/a/a@v1.0.0 <- old/go.mod",
      "github.com/s/s@v1.1.1 <- solo/go.sum",
      "github.com/t/t@v0.2.0 <- old/go.mod",
    ]);
    expect(result.coverage.map((c) => c.path)).toEqual(["old/go.mod", "solo/go.sum"]);
  });

  it("does not read oversized lockfiles or follow symlinks, and reports both", async () => {
    await put(
      "big/package-lock.json",
      `{"lockfileVersion":3,"packages":{},"pad":"${"x".repeat(65 * 1024 * 1024)}"}`,
    );
    await put("real/yarn.lock", '# yarn lockfile v1\n\nsecret@^1:\n  version "1.0.0"\n');
    await mkdir(path.join(root, "link-parent"), { recursive: true });
    await symlink(
      path.join(root, "real", "yarn.lock"),
      path.join(root, "link-parent", "yarn.lock"),
    );
    await symlink(path.join(root, "real"), path.join(root, "linked-dir"));
    const result = await collectDependencies(root);
    expect(result.coverage.find((c) => c.path === "big/package-lock.json")).toMatchObject({
      status: "too-large",
    });
    expect(result.coverage.map((c) => c.path)).toEqual(["big/package-lock.json", "real/yarn.lock"]);
  });
});

describe("collectDependencies limits and unreadable manifests", () => {
  it("sets isTruncated when there are more lockfiles than the limit", async () => {
    for (let index = 0; index < 205; index += 1) {
      await put(`m${String(index).padStart(3, "0")}/go.sum`, "github.com/a/b v1.0.0 h1:x=\n");
    }
    const result = await collectDependencies(root);
    expect(result.isTruncated).toBe(true);
    expect(result.coverage).toHaveLength(200);
  });

  it("sets isTruncated when there are more package.json files than the limit", async () => {
    for (let index = 0; index < 1005; index += 1) {
      await put(`p${index}/package.json`, "{}");
    }
    expect((await collectDependencies(root)).isTruncated).toBe(true);
  });

  it("gives a coverage line to package.json files that are malformed, oversized or unreadable", async () => {
    await put("bad/package.json", "{ not json");
    await put("big/package.json", `{"name":"${"x".repeat(1_100_000)}"}`);
    await put("arr/package.json", "[1]");
    await put("ok/package.json", '{"name":"fine"}');
    const result = await collectDependencies(root);
    const byPath = new Map(result.coverage.map((c) => [c.path, c]));
    expect(byPath.get("bad/package.json")).toMatchObject({
      kind: "package.json",
      status: "failed",
    });
    expect(byPath.get("arr/package.json")?.status).toBe("failed");
    expect(byPath.get("big/package.json")).toMatchObject({ status: "too-large" });
    expect(byPath.has("ok/package.json")).toBe(false);
  });
});

describe("collectDependencies skips what the scanner skips", () => {
  const lock = '# yarn lockfile v1\n\nsecret@^1:\n  version "1.0.0"\n';

  it("does not enter virtualenvs, site-packages, Maven target or Gradle cache directories", async () => {
    await put("venv/pyvenv.cfg", "home = /usr/bin\n");
    await put("venv/bin/activate", "");
    await put("venv/yarn.lock", lock);
    await put("lib/python3.12/site-packages/yarn.lock", lock);
    await put("svc/pom.xml", "<project/>");
    await put("svc/target/yarn.lock", lock);
    await put("app/build.gradle", "");
    await put("app/.gradle/yarn.lock", lock);
    await put("real/yarn.lock", lock);
    const result = await collectDependencies(root);
    expect(result.coverage.map((c) => c.path)).toEqual(["real/yarn.lock"]);
  });

  it("still enters first-party directories that only share those names", async () => {
    await put("venv/server.js", "");
    await put("venv/yarn.lock", lock); // no pyvenv.cfg: not an environment
    await put("target/yarn.lock", lock); // no pom.xml beside it
    await put("site-packages/yarn.lock", lock); // not under lib/python3.x
    const result = await collectDependencies(root);
    expect(result.coverage.map((c) => c.path)).toEqual([
      "site-packages/yarn.lock",
      "target/yarn.lock",
      "venv/yarn.lock",
    ]);
  });
});
