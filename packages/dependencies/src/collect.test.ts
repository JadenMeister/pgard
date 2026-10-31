import { link, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { collectDependencies } from "./collect.js";
import { TIME_FACTOR, itScaled } from "../../../tests/support/timing.js";

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

describe("collectDependencies hostile-repository limits (L5)", () => {
  const lock = (name: string, version = "1.0.0"): string =>
    `# yarn lockfile v1\n\n${name}@^1:\n  version "${version}"\n`;

  itScaled(
    "reads many hard links to one big lockfile once, in bounded time and memory",
    async () => {
      const big = JSON.stringify({
        lockfileVersion: 3,
        packages: { "node_modules/a": { version: "1.0.0" } },
        pad: "x".repeat(20 * 1024 * 1024),
      });
      await put("origin/package-lock.json", big);
      const source = path.join(root, "origin", "package-lock.json");
      for (let index = 0; index < 150; index += 1) {
        const dir = path.join(root, `link${String(index).padStart(3, "0")}`);
        await mkdir(dir);
        await link(source, path.join(dir, "package-lock.json"));
      }
      const started = Date.now();
      const result = await collectDependencies(root);
      const elapsedMs = Date.now() - started;
      // 151 names for one inode: 20 MiB were read, not 3 GiB.
      expect(result.bytesRead).toBeLessThan(big.length + 1024);
      expect(result.bytesRead).toBeGreaterThanOrEqual(big.length);
      expect(result.coverage.filter((c) => c.status === "parsed")).toHaveLength(1);
      const duplicates = result.coverage.filter((c) => c.status === "duplicate");
      expect(duplicates).toHaveLength(150);
      expect(duplicates[0]?.note).toContain("Hard link to ");
      expect(result.dependencies).toHaveLength(1);
      expect(elapsedMs).toBeLessThan(10_000 * TIME_FACTOR);
    },
    30_000,
  );

  it("reads a hard-linked package.json once as well", async () => {
    await put("a/package.json", '{"dependencies":{"x":"1"}}');
    await mkdir(path.join(root, "b"));
    await link(path.join(root, "a", "package.json"), path.join(root, "b", "package.json"));
    const result = await collectDependencies(root);
    expect(result.coverage.filter((c) => c.status === "missing-lockfile")).toHaveLength(2);
  });

  it("stops reading at the total byte limit and says which files were not read", async () => {
    for (let index = 0; index < 6; index += 1) {
      await put(`m${index}/yarn.lock`, lock(`pkg${index}`) + "#".repeat(1000));
    }
    const result = await collectDependencies(root, { limits: { totalBytes: 2500 } });
    const statuses = result.coverage.map((c) => c.status);
    expect(statuses.filter((s) => s === "parsed")).toHaveLength(2);
    expect(statuses.filter((s) => s === "not-read")).toHaveLength(4);
    expect(result.isTruncated).toBe(true);
    expect(result.limitNotes.join(" ")).toContain("limit on all lockfile data");
    expect(result.bytesRead).toBeLessThanOrEqual(2500);
  });

  it("caps the packages kept across all lockfiles and marks the file partial", async () => {
    await put(
      "a/yarn.lock",
      "# yarn lockfile v1\n\n" +
        ["p1", "p2", "p3"].map((n) => `${n}@^1:\n  version "1.0.0"\n`).join("\n"),
    );
    await put("b/yarn.lock", lock("other"));
    const result = await collectDependencies(root, { limits: { totalDependencies: 2 } });
    expect(result.dependencies).toHaveLength(2);
    const byPath = new Map(result.coverage.map((c) => [c.path, c]));
    expect(byPath.get("a/yarn.lock")?.status).toBe("partial");
    expect(byPath.get("a/yarn.lock")?.note).toContain("Only the first 2 packages");
    expect(byPath.get("b/yarn.lock")?.status).toBe("not-read");
    expect(result.isTruncated).toBe(true);
  });

  /** A clock that reads 0 for the first `free` calls (constructor + walk) and 1000 ms after. */
  function clockAfter(free: number): () => number {
    let calls = 0;
    return () => {
      calls += 1;
      return calls <= free ? 0 : 1000;
    };
  }

  it("counts the reads against the time budget and lists the files it did not read", async () => {
    await put("a/yarn.lock", lock("one"));
    await put("b/yarn.lock", lock("two"));
    // 1 constructor call + 3 directories in the walk, then the first lockfile check is late.
    const result = await collectDependencies(root, { timeBudgetMs: 100, now: clockAfter(4) });
    expect(result.isTruncated).toBe(true);
    expect(result.limitNotes.join(" ")).toContain("time budget");
    expect(result.coverage.map((c) => `${c.path}:${c.status}`)).toEqual([
      "a/yarn.lock:not-read",
      "b/yarn.lock:not-read",
    ]);
  });

  it("keeps what was read before the time budget ran out", async () => {
    await put("a/yarn.lock", lock("one"));
    await put("b/yarn.lock", lock("two"));
    const result = await collectDependencies(root, { timeBudgetMs: 100, now: clockAfter(5) });
    expect(result.coverage.map((c) => `${c.path}:${c.status}`)).toEqual([
      "a/yarn.lock:parsed",
      "b/yarn.lock:not-read",
    ]);
    expect(result.dependencies.map((d) => d.name)).toEqual(["one"]);
  });

  it("rejects when the signal aborts in the middle of a run", async () => {
    await put("a/yarn.lock", lock("one"));
    await put("b/yarn.lock", lock("two"));
    const controller = new AbortController();
    let calls = 0;
    const run = collectDependencies(root, {
      signal: controller.signal,
      now: () => {
        calls += 1;
        if (calls === 5) controller.abort(); // after the first lockfile was read
        return 0;
      },
    });
    await expect(run).rejects.toMatchObject({ name: "AbortError" });
  });

  it("honours an abort signal", async () => {
    await put("a/yarn.lock", lock("one"));
    const controller = new AbortController();
    controller.abort();
    await expect(collectDependencies(root, { signal: controller.signal })).rejects.toMatchObject({
      name: "AbortError",
    });
  });

  it("does not follow a symlink even when it names a lockfile", async () => {
    await put("real/yarn.lock", lock("secret"));
    await mkdir(path.join(root, "l"));
    await symlink(path.join(root, "real", "yarn.lock"), path.join(root, "l", "yarn.lock"));
    const result = await collectDependencies(root);
    expect(result.coverage.map((c) => c.path)).toEqual(["real/yarn.lock"]);
  });
});

describe("collectDependencies: pools, hard links across kinds, go.sum, hostile shapes", () => {
  const lock = (name: string): string => `# yarn lockfile v1\n\n${name}@^1:\n  version "1.0.0"\n`;

  it("gives package.json files their own byte pool, so padding cannot starve a lockfile", async () => {
    for (let index = 0; index < 4; index += 1) {
      await put(`pad${index}/package.json`, "{}" + " ".repeat(1000));
    }
    await put("real/yarn.lock", lock("real"));
    const result = await collectDependencies(root, {
      limits: { totalBytes: 1000, manifestBytes: 2000 },
    });
    const byPath = new Map(result.coverage.map((c) => [c.path, c]));
    expect(byPath.get("real/yarn.lock")?.status).toBe("parsed");
    const notRead = result.coverage.filter((c) => c.status === "not-read");
    expect(notRead.length).toBeGreaterThan(0);
    expect(result.isTruncated).toBe(true); // every not-read sets it
    expect(result.limitNotes.join(" ")).toContain("package.json data");
  });

  it("does not let a hard link across kinds hide a file from its own reader", async () => {
    const body = JSON.stringify({
      name: "x",
      lockfileVersion: 3,
      packages: { "": {}, "node_modules/evil": { version: "6.6.6" } },
    });
    await put("package.json", body);
    await link(path.join(root, "package.json"), path.join(root, "package-lock.json"));
    const result = await collectDependencies(root);
    expect(result.dependencies.map((d) => d.name)).toEqual(["evil"]);
    expect(result.coverage.find((c) => c.path === "package-lock.json")?.status).toBe("parsed");
  });

  it("gives every link to a file that was too large the same outcome, not 'read once, there'", async () => {
    await put("a/yarn.lock", lock("x") + "#".repeat(5000));
    await mkdir(path.join(root, "b"));
    await link(path.join(root, "a", "yarn.lock"), path.join(root, "b", "yarn.lock"));
    const result = await collectDependencies(root, { limits: { lockfileBytes: 1000 } });
    expect(result.coverage.map((c) => `${c.path}:${c.status}`)).toEqual([
      "a/yarn.lock:too-large",
      "b/yarn.lock:too-large",
    ]);
  });

  it("counts a duplicate lockfile as covering its directory", async () => {
    await put("a/yarn.lock", lock("x"));
    await put("a/package.json", '{"dependencies":{"x":"^1"}}');
    await put("b/package.json", '{"dependencies":{"x":"^1"}}');
    await link(path.join(root, "a", "yarn.lock"), path.join(root, "b", "yarn.lock"));
    const result = await collectDependencies(root);
    expect(result.coverage.find((c) => c.path === "b/yarn.lock")?.status).toBe("duplicate");
    expect(result.coverage.some((c) => c.status === "missing-lockfile")).toBe(false);
  });

  it("says when a go.sum was not read, with its own wording", async () => {
    await put("go.mod", "module x\n\ngo 1.16\n\nrequire example.com/a v1.0.0\n");
    await put("go.sum", "example.com/b v1.0.0 h1:abc=\n".repeat(100));
    const result = await collectDependencies(root, { limits: { totalBytes: 200 } });
    expect(result.isTruncated).toBe(true);
    const line = result.coverage.find((c) => c.path === "go.mod");
    expect(line?.status).toBe("partial");
    expect(line?.note).toContain("go.sum was not read");
    expect(line?.note).not.toContain("there is no go.sum");
  });

  it("does not parse a hostile file below the byte cap: too many lines, deep or wide JSON", async () => {
    await put("lines/yarn.lock", "a:\n".repeat(60_000));
    await put("deep/package-lock.json", "[".repeat(100_000) + "]".repeat(100_000));
    await put("wide/package-lock.json", "[" + "1,".repeat(100_000) + "1]");
    const result = await collectDependencies(root, {
      limits: { lines: 50_000, jsonTokens: 50_000 },
    });
    for (const line of result.coverage) {
      expect(line.status, line.path).toBe("too-large");
      expect(line.note).toContain("Not parsed");
    }
    expect(result.coverage).toHaveLength(3);
  });

  it("stops a yarn.lock at the package cap instead of building every block", async () => {
    await put("yarn.lock", "a:\n".repeat(600_000));
    const result = await collectDependencies(root, { limits: { lines: 1_000_000 } });
    const line = result.coverage[0];
    expect(["partial", "failed"]).toContain(line?.status);
  });

  itScaled(
    "skips a FIFO named like a lockfile without waiting for it",
    async () => {
      if (process.platform === "win32") return;
      const { execFileSync } = await import("node:child_process");
      try {
        execFileSync("mkfifo", [path.join(root, "package-lock.json")]);
      } catch {
        return; // no mkfifo on this system
      }
      const started = Date.now();
      const result = await collectDependencies(root);
      expect(Date.now() - started).toBeLessThan(5000 * TIME_FACTOR);
      expect(result.dependencies).toEqual([]);
    },
    15_000,
  );
});
