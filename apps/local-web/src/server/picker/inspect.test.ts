import {
  chmodSync,
  existsSync,
  mkdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { inspectCandidate, runInspectorJob, type InspectorDeps } from "./inspect.js";
import type { ChildMessage, InspectorJob, RawCandidate } from "./protocol.js";
import {
  createInspectorDeps,
  createRepo,
  createScopeTree,
  GITHUB_REMOTES,
  overridingFs,
  rootOf,
  type ScopeTree,
  type StatOverride,
} from "./test-support/fixtures.js";

/** The picker is not available on Windows (modes, owners and inodes are POSIX facts). */
const posixDescribe = describe.skipIf(process.platform === "win32");

let tree: ScopeTree;
afterEach(() => tree?.cleanup());

interface SearchOutcome {
  found: Array<{ name: string; segments: string[] }>;
  inspected: Map<number, RawCandidate>;
  done: Extract<ChildMessage, { t: "done" }>;
  messages: ChildMessage[];
}

async function search(
  name: string,
  options: {
    source?: "drop" | "typed";
    deps?: Partial<InspectorDeps>;
    /** Runs when the walk reports a match (to move an injected clock at that moment). */
    onFound?: () => void;
  } = {},
): Promise<SearchOutcome> {
  const { deps, messages } = createInspectorDeps(options.deps);
  const collect = deps.emit;
  deps.emit = (message) => {
    collect(message);
    if (message.t === "found") options.onFound?.();
  };
  const job: InspectorJob = {
    kind: "search",
    roots: [tree.rootStat],
    name,
    source: options.source ?? "drop",
    platform: process.platform,
  };
  await runInspectorJob(deps, job);
  const found: SearchOutcome["found"] = [];
  const inspected = new Map<number, RawCandidate>();
  let done: SearchOutcome["done"] | undefined;
  for (const message of messages) {
    if (message.t === "found") {
      found.push({
        name: message.segments.at(-1)?.name ?? "",
        segments: message.segments.map((s) => s.name),
      });
    } else if (message.t === "inspected") inspected.set(message.key, message.candidate);
    else if (message.t === "done") done = message;
  }
  if (done === undefined) throw new Error("no done message");
  return { found, inspected, done, messages };
}

function repoAt(...segments: string[]): string {
  return createRepo(path.join(tree.root, ...segments), { remotes: GITHUB_REMOTES });
}

/** Whether a directory name differing only by case is a different directory here. */
function isCaseSensitive(): boolean {
  const probe = path.join(tree.root, "CaseProbe");
  mkdirSync(probe);
  const isSensitive = !existsSync(path.join(tree.root, "caseprobe"));
  rmSync(probe, { recursive: true });
  return isSensitive;
}

posixDescribe("directory walk (T3, T4, T5)", () => {
  it("finds a repository by its exact name and reports it as selectable", async () => {
    tree = createScopeTree();
    repoAt("work", "shop");
    repoAt("work", "other");
    const outcome = await search("shop");
    expect(outcome.found.map((entry) => entry.segments)).toEqual([["work", "shop"]]);
    const candidate = outcome.inspected.get(0);
    expect(candidate?.block).toBeNull();
    expect(candidate?.remote).toEqual({ status: "github", owner: "acme", name: "shop" });
    expect(candidate?.gitIdentity).not.toBeNull();
    expect(outcome.done.stoppedBy).toBeNull();
  });

  it("matches a typed name as a prefix or substring", async () => {
    tree = createScopeTree();
    repoAt("shop-api");
    repoAt("my-shop");
    repoAt("blog");
    const outcome = await search("shop", { source: "typed" });
    expect(outcome.found.map((entry) => entry.name).sort()).toEqual(["my-shop", "shop-api"]);
    const exactOnly = await search("shop", { source: "drop" });
    expect(exactOnly.found).toEqual([]);
  });

  it("does not search inside a found repository (no nested search)", async () => {
    tree = createScopeTree();
    repoAt("shop");
    repoAt("shop", "vendor", "nested");
    const outcome = await search("nested", { source: "typed" });
    expect(outcome.found).toEqual([]);
  });

  it("skips dot-folders and the fixed skip list", async () => {
    tree = createScopeTree();
    repoAt(".hidden", "shop");
    repoAt("node_modules", "shop");
    repoAt("Library", "shop");
    const outcome = await search("shop");
    // `Library` is skipped on macOS only.
    const expected = process.platform === "darwin" ? [] : [["Library", "shop"]];
    expect(outcome.found.map((entry) => entry.segments)).toEqual(expected);
    expect(outcome.done.skipped.find((entry) => entry.reason === "skipped_folder")).toBeDefined();
  });

  it("respects the depth limit of 4 below the root", async () => {
    tree = createScopeTree();
    repoAt("a", "b", "c", "d", "deep");
    repoAt("a", "b", "c", "edge");
    const outcome = await search("deep");
    expect(outcome.found).toEqual([]);
    const edge = await search("edge");
    expect(edge.found).toHaveLength(1);
  });

  it("stops at the entry limit and says so", async () => {
    tree = createScopeTree();
    for (let index = 0; index < 12; index += 1) mkdirSync(path.join(tree.root, `dir${index}`));
    repoAt("zzz-shop");
    const outcome = await search("shop", { deps: { limits: { maxEntriesVisited: 5 } } });
    expect(outcome.done.stoppedBy).toBe("entries");
  });

  it("skips a directory with more entries than the per-directory limit", async () => {
    tree = createScopeTree();
    for (let index = 0; index < 6; index += 1) mkdirSync(path.join(tree.root, `d${index}`));
    const outcome = await search("x", { deps: { limits: { maxEntriesPerDirectory: 3 } } });
    expect(outcome.done.skipped.some((entry) => entry.reason === "folder_too_large")).toBe(true);
  });

  it("stops at 20 candidates", async () => {
    tree = createScopeTree();
    for (let index = 0; index < 22; index += 1) repoAt(`app${index}`);
    const outcome = await search("app", { source: "typed" });
    expect(outcome.found).toHaveLength(20);
    expect(outcome.done.stoppedBy).toBe("candidates");
  });

  it("reports partial results with not-inspected folders when the deadline passes (injected clock)", async () => {
    tree = createScopeTree();
    repoAt("shop");
    // The clock jumps past the hard budget once the walk found the match: nothing can be inspected.
    let clock = 0;
    const outcome = await search("shop", {
      deps: { now: () => clock },
      onFound: () => {
        clock = 9_000;
      },
    });
    expect(outcome.found).toHaveLength(1);
    expect(outcome.inspected.size).toBe(0); // found, never silently dropped, but not inspected
    expect(outcome.done.stoppedBy).toBe("time");
  });

  it("stops walking at the soft budget (injected clock)", async () => {
    tree = createScopeTree();
    repoAt("a", "shop");
    let ticks = 0;
    const outcome = await search("shop", {
      deps: { now: () => (ticks += 2_600) },
    });
    expect(outcome.done.stoppedBy).toBe("time");
  });

  it("does not offer a symlink to a repository outside the scope", async () => {
    tree = createScopeTree();
    const outside = createRepo(path.join(tree.root, "..", "outside-shop"), {
      remotes: GITHUB_REMOTES,
    });
    symlinkSync(outside, path.join(tree.root, "shop"));
    const outcome = await search("shop");
    expect(outcome.found).toEqual([]);
    rmSync(outside, { recursive: true, force: true });
  });

  it("survives a symlink loop", async () => {
    tree = createScopeTree();
    mkdirSync(path.join(tree.root, "a"));
    symlinkSync(tree.root, path.join(tree.root, "a", "loop"));
    repoAt("shop");
    const outcome = await search("shop");
    expect(outcome.found).toHaveLength(1);
  });

  it("does not enter a directory on another file system (injected dev)", async () => {
    tree = createScopeTree();
    repoAt("mounted", "shop");
    const mounted = path.join(tree.root, "mounted");
    const outcome = await search("shop", {
      deps: { fs: overridingFs(new Map([[mounted, { dev: tree.rootStat.dev + 1 }]])) },
    });
    expect(outcome.found).toEqual([]);
    expect(outcome.done.skipped.some((entry) => entry.reason === "other_file_system")).toBe(true);
  });

  it("offers both directories that differ only by case on a case-sensitive file system", async () => {
    tree = createScopeTree();
    if (!isCaseSensitive()) return; // APFS default: the two names are the same directory
    repoAt("Shop");
    repoAt("shop");
    const outcome = await search("shop");
    expect(outcome.found.map((entry) => entry.name).sort()).toEqual(["Shop", "shop"]);
  });

  it("finds Shop for shop on a case-insensitive file system, and NFD for NFC names", async () => {
    tree = createScopeTree();
    repoAt("Shop");
    const folded = await search("shop");
    expect(folded.found.map((entry) => entry.name)).toEqual(["Shop"]);
    repoAt("café");
    const nfd = await search("café");
    expect(nfd.found.map((entry) => entry.name)).toEqual(["café"]);
  });
});

posixDescribe("candidate checks (T8, T13)", () => {
  async function inspectNamed(
    name: string,
    deps: Partial<InspectorDeps> = {},
  ): Promise<RawCandidate> {
    const outcome = await search(name, { deps });
    const candidate = outcome.inspected.get(0);
    if (candidate === undefined) throw new Error(`${name} was not inspected`);
    return candidate;
  }

  const blockCases: Array<[string, Record<string, string> | undefined, string, string]> = [
    ["no remote", {}, "no_remote", "none"],
    ["another host", { origin: "https://example.com/o/r.git" }, "remote_not_github", "not_github"],
    [
      "GitHub Enterprise",
      { origin: "https://github.example.org/o/r.git" },
      "remote_not_github",
      "not_github",
    ],
    [
      "two remotes",
      { origin: "https://github.com/a/b.git", other: "https://github.com/c/d.git" },
      "remote_ambiguous",
      "ambiguous",
    ],
  ];

  for (const [label, remotes, code, status] of blockCases) {
    it(`blocks ${label} with ${code}`, async () => {
      tree = createScopeTree();
      createRepo(path.join(tree.root, "shop"), { remotes: remotes ?? {} });
      const candidate = await inspectNamed("shop");
      expect(candidate.block?.code).toBe(code);
      expect(candidate.remote.status).toBe(status);
    });
  }

  it("never reports a credential, URL or remote name", async () => {
    tree = createScopeTree();
    createRepo(path.join(tree.root, "shop"), {
      remotes: { "evil-name-ZZZ": "https://user:secret-TOKEN@example.com/o/r.git" },
    });
    const candidate = await inspectNamed("shop");
    expect(candidate.block?.code).toBe("remote_not_github");
    const text = JSON.stringify(candidate);
    expect(text).not.toContain("secret-TOKEN");
    expect(text).not.toContain("example.com");
    expect(text).not.toContain("evil-name-ZZZ");
  });

  it("blocks a repository without commits", async () => {
    tree = createScopeTree();
    createRepo(path.join(tree.root, "shop"), { remotes: GITHUB_REMOTES, isCommitted: false });
    expect((await inspectNamed("shop")).block?.code).toBe("no_commit_history");
  });

  it("blocks a repository with alternates", async () => {
    tree = createScopeTree();
    const dir = repoAt("shop");
    writeFileSync(path.join(dir, ".git", "objects", "info", "alternates"), "/elsewhere/objects\n");
    expect((await inspectNamed("shop")).block?.code).toBe("isolation_failed");
  });

  it("never runs programs named in a hostile .git/config", async () => {
    tree = createScopeTree();
    const dir = repoAt("shop");
    const marker = path.join(tree.root, "..", "pwned-marker");
    const script = path.join(tree.root, "..", "evil.sh");
    writeFileSync(script, `#!/bin/sh\ntouch ${marker}\n`, { mode: 0o755 });
    writeFileSync(
      path.join(dir, ".git", "config"),
      `[core]\n\trepositoryformatversion = 0\n\tfsmonitor = ${script}\n\thooksPath = ${path.join(tree.root, "..")}\n\tsshCommand = ${script}\n[remote "origin"]\n\turl = https://github.com/acme/shop.git\n`,
    );
    const candidate = await inspectNamed("shop");
    expect(existsSync(marker)).toBe(false);
    expect(candidate.block).toBeNull();
  });

  it("blocks a .git file (worktree, submodule, gitdir pointer)", async () => {
    tree = createScopeTree();
    const dir = path.join(tree.root, "shop");
    mkdirSync(dir);
    writeFileSync(path.join(dir, ".git"), "gitdir: /elsewhere/.git/worktrees/shop\n");
    expect((await inspectNamed("shop")).block?.code).toBe("gitfile_unsupported");
  });

  it("blocks a Git directory that is a symlink", async () => {
    tree = createScopeTree();
    const real = repoAt("real-repo");
    const dir = path.join(tree.root, "shop");
    mkdirSync(dir);
    symlinkSync(path.join(real, ".git"), path.join(dir, ".git"));
    expect((await inspectNamed("shop")).block?.code).toBe("git_dir_unsupported");
  });

  it("blocks a commondir that points outside the project", async () => {
    tree = createScopeTree();
    const other = repoAt("other");
    const dir = repoAt("shop");
    writeFileSync(path.join(dir, ".git", "commondir"), `${path.join(other, ".git")}\n`);
    expect((await inspectNamed("shop")).block?.code).toBe("git_dir_unsupported");
  });

  describe("ownership and write bits with an injected fs", () => {
    function setup(): { repo: string; git: string; config: string; parent: string } {
      tree = createScopeTree();
      const repo = repoAt("work", "shop");
      return {
        repo,
        git: path.join(repo, ".git"),
        config: path.join(repo, ".git", "config"),
        parent: path.join(tree.root, "work"),
      };
    }
    const withOverrides = (entries: Array<[string, StatOverride]>): Partial<InspectorDeps> => ({
      fs: overridingFs(new Map(entries)),
    });

    it("blocks a parent owned by another uid", async () => {
      const { parent } = setup();
      const uid = (process.getuid?.() ?? 0) + 1;
      const candidate = await inspectNamed("shop", withOverrides([[parent, { uid }]]));
      expect(candidate.block).toEqual({ code: "not_owned_by_you", paths: [parent] });
    });

    it("blocks a group-writable ancestor, a world-writable ancestor and the scope root", async () => {
      const { parent } = setup();
      const group = await inspectNamed("shop", withOverrides([[parent, { mode: 0o40775 }]]));
      expect(group.block).toEqual({ code: "group_or_world_writable", paths: [parent] });
      const world = await inspectNamed("shop", withOverrides([[parent, { mode: 0o40757 }]]));
      expect(world.block?.code).toBe("group_or_world_writable");
      const root = await inspectNamed("shop", withOverrides([[tree.root, { mode: 0o40777 }]]));
      expect(root.block).toEqual({ code: "group_or_world_writable", paths: [tree.root] });
    });

    it("blocks a group-writable .git and .git/config", async () => {
      const { git, config } = setup();
      const gitWritable = await inspectNamed("shop", withOverrides([[git, { mode: 0o40775 }]]));
      expect(gitWritable.block).toEqual({ code: "group_or_world_writable", paths: [git] });
      const configWritable = await inspectNamed(
        "shop",
        withOverrides([[config, { mode: 0o100664 }]]),
      );
      expect(configWritable.block).toEqual({ code: "group_or_world_writable", paths: [config] });
    });

    it("lists every failing path at once", async () => {
      const { parent, repo, git, config } = setup();
      const candidate = await inspectNamed(
        "shop",
        withOverrides([
          [parent, { mode: 0o40775 }],
          [repo, { mode: 0o40777 }],
          [git, { mode: 0o40775 }],
          [config, { mode: 0o100666 }],
        ]),
      );
      expect(candidate.block?.code).toBe("group_or_world_writable");
      expect(candidate.block?.paths).toEqual([parent, repo, git, config]);
    });

    it("does not run Git for a blocked candidate", async () => {
      const { parent } = setup();
      let isGitCalled = false;
      const candidate = await inspectNamed("shop", {
        ...withOverrides([[parent, { uid: (process.getuid?.() ?? 0) + 1 }]]),
        runGit: async () => {
          isGitCalled = true;
          return "";
        },
      });
      expect(candidate.block?.code).toBe("not_owned_by_you");
      expect(isGitCalled).toBe(false);
    });

    it("applies the same checks to a root owned by another user", async () => {
      setup();
      const candidate = await inspectNamed(
        "shop",
        withOverrides([[tree.root, { uid: (process.getuid?.() ?? 0) + 1 }]]),
      );
      expect(candidate.block?.code).toBe("not_owned_by_you");
    });
  });

  it("bounds every Git call to 3 seconds and blocks as unreadable when one times out", async () => {
    tree = createScopeTree();
    repoAt("shop");
    const timeouts: Array<number | undefined> = [];
    const candidate = await inspectNamed("shop", {
      runGit: async (_invocation, options) => {
        timeouts.push(options.timeoutMs);
        throw Object.assign(new Error("git command timed out"), { kind: "timeout" });
      },
    });
    expect(timeouts.length).toBeGreaterThan(0);
    expect(timeouts.every((ms) => ms === 3_000)).toBe(true);
    expect(candidate.block?.code).toBe("unreadable");
  });
});

posixDescribe("re-inspection (T7)", () => {
  async function candidateOf(name: string): Promise<RawCandidate> {
    const outcome = await search(name);
    const candidate = outcome.inspected.get(0);
    if (candidate === undefined) throw new Error("not inspected");
    return candidate;
  }

  async function reinspect(
    candidate: RawCandidate,
    mode: "full" | "recheck" = "full",
  ): Promise<ChildMessage[]> {
    const { deps, messages } = createInspectorDeps();
    await runInspectorJob(deps, {
      kind: "inspect",
      root: tree.rootStat,
      segments: candidate.segments,
      mode,
    });
    return messages;
  }

  it("gives the same identity again for an unchanged candidate", async () => {
    tree = createScopeTree();
    repoAt("shop");
    const first = await candidateOf("shop");
    const messages = await reinspect(first);
    const inspected = messages.find((m) => m.t === "inspected");
    expect(inspected?.t === "inspected" && inspected.candidate.gitIdentity).toEqual(
      first.gitIdentity,
    );
  });

  it("reports changed when the directory is renamed", async () => {
    tree = createScopeTree();
    repoAt("shop");
    const first = await candidateOf("shop");
    renameSync(path.join(tree.root, "shop"), path.join(tree.root, "moved"));
    expect((await reinspect(first)).some((m) => m.t === "changed")).toBe(true);
  });

  it("reports changed when the directory is replaced by a symlink", async () => {
    tree = createScopeTree();
    repoAt("shop");
    const first = await candidateOf("shop");
    const elsewhere = createRepo(path.join(tree.root, "..", "elsewhere"), {
      remotes: GITHUB_REMOTES,
    });
    rmSync(path.join(tree.root, "shop"), { recursive: true });
    symlinkSync(elsewhere, path.join(tree.root, "shop"));
    expect((await reinspect(first)).some((m) => m.t === "changed")).toBe(true);
    rmSync(elsewhere, { recursive: true, force: true });
  });

  it("gives a different identity when the directory is replaced by another repository", async () => {
    tree = createScopeTree();
    repoAt("shop");
    const first = await candidateOf("shop");
    // The old directory stays, so the new one cannot reuse its inode number.
    renameSync(path.join(tree.root, "shop"), path.join(tree.root, "shop-old"));
    createRepo(path.join(tree.root, "shop"), { remotes: GITHUB_REMOTES });
    const messages = await reinspect(first);
    // The new directory has another inode, so the recorded chain no longer matches.
    expect(messages.some((m) => m.t === "changed")).toBe(true);
  });

  it("shows a changed remote on a full re-inspection", async () => {
    tree = createScopeTree();
    const dir = repoAt("shop");
    const first = await candidateOf("shop");
    const git = (args: string[]): void => {
      // Rewrite the remote in place (same inode for .git/config is not guaranteed; the remote differs either way).
      const configPath = path.join(dir, ".git", "config");
      writeFileSync(
        configPath,
        `[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = ${args[0]}\n`,
      );
    };
    git(["https://github.com/acme/other.git"]);
    const inspected = (await reinspect(first)).find((m) => m.t === "inspected");
    expect(inspected?.t === "inspected" && inspected.candidate.remote).toEqual({
      status: "github",
      owner: "acme",
      name: "other",
    });
  });

  it("the identity-only re-check notices a group-writable .git without running Git", async () => {
    tree = createScopeTree();
    const dir = repoAt("shop");
    const first = await candidateOf("shop");
    chmodSync(path.join(dir, ".git"), 0o775);
    const { deps, messages } = createInspectorDeps({
      runGit: async () => {
        throw new Error("Git must not run in a re-check");
      },
    });
    await runInspectorJob(deps, {
      kind: "inspect",
      root: tree.rootStat,
      segments: first.segments,
      mode: "recheck",
    });
    const inspected = messages.find((m) => m.t === "inspected");
    expect(inspected?.t === "inspected" && inspected.candidate.block?.code).toBe(
      "group_or_world_writable",
    );
  });
});

posixDescribe("recent entries (T9) and containment by identity (T4)", () => {
  async function recent(paths: string[]): Promise<ChildMessage[]> {
    const { deps, messages } = createInspectorDeps();
    await runInspectorJob(deps, {
      kind: "recent",
      roots: [tree.rootStat],
      entries: paths.map((entryPath, index) => ({
        entryId: `${String(index).padStart(22, "a")}`,
        path: entryPath,
      })),
    });
    return messages;
  }
  const outcomes = (messages: ChildMessage[]) =>
    messages.flatMap((m) => (m.t === "recent" ? [m.outcome.status] : []));

  it("validates an entry inside the scope as a fresh candidate", async () => {
    tree = createScopeTree();
    const dir = repoAt("shop");
    expect(outcomes(await recent([dir]))).toEqual(["candidate"]);
  });

  it("marks an entry outside the scope and one that no longer exists", async () => {
    tree = createScopeTree();
    repoAt("shop");
    const result = await recent([
      "/etc/passwd",
      path.join(tree.root, "missing"),
      `${tree.root}/../scope-evil/shop`,
      path.join(tree.root, ".."),
    ]);
    expect(outcomes(result)).toEqual(["outside_scope", "gone", "outside_scope", "outside_scope"]);
  });

  it("does not accept a look-alike of the scope root (string prefix is not containment)", async () => {
    tree = createScopeTree();
    const lookAlike = `${tree.root}-evil`;
    mkdirSync(lookAlike);
    createRepo(path.join(lookAlike, "shop"), { remotes: GITHUB_REMOTES });
    expect(outcomes(await recent([path.join(lookAlike, "shop")]))).toEqual(["outside_scope"]);
    rmSync(lookAlike, { recursive: true, force: true });
  });

  it("does not accept a directory reached through a symlinked ancestor", async () => {
    tree = createScopeTree();
    const outside = path.join(tree.root, "..", "outside-tree");
    mkdirSync(outside);
    createRepo(path.join(outside, "shop"), { remotes: GITHUB_REMOTES });
    symlinkSync(outside, path.join(tree.root, "link"));
    expect(outcomes(await recent([path.join(tree.root, "link", "shop")]))).toEqual(["gone"]);
    rmSync(outside, { recursive: true, force: true });
  });

  it("does not accept a case-different directory next to the real root on a case-sensitive volume", async () => {
    tree = createScopeTree();
    if (!isCaseSensitive()) return;
    const parent = path.dirname(tree.root);
    const lookAlike = path.join(parent, "SCOPE");
    mkdirSync(lookAlike);
    createRepo(path.join(lookAlike, "shop"), { remotes: GITHUB_REMOTES });
    expect(outcomes(await recent([path.join(lookAlike, "shop")]))).toEqual(["outside_scope"]);
    rmSync(lookAlike, { recursive: true, force: true });
  });

  it("shows a tampered entry that points at a non-repository as a blocked candidate", async () => {
    tree = createScopeTree();
    const plain = path.join(tree.root, "plain");
    mkdirSync(plain);
    const messages = await recent([plain]);
    const entry = messages.find((m) => m.t === "recent");
    expect(
      entry?.t === "recent" &&
        entry.outcome.status === "candidate" &&
        entry.outcome.candidate.block?.code,
    ).toBe("not_a_git_root");
  });
});

posixDescribe("inspectCandidate chain checks", () => {
  it("throws for a root whose identity changed", async () => {
    tree = createScopeTree();
    repoAt("shop");
    const { deps } = createInspectorDeps();
    const wrongRoot = { ...rootOf(tree.root), ino: tree.rootStat.ino + 1 };
    await expect(
      inspectCandidate(deps, wrongRoot, 0, [{ name: "shop" }], "full"),
    ).rejects.toThrow();
  });
});
