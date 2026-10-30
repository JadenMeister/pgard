import { chmodSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runInspectorJob } from "./inspect.js";
import type { ChildMessage, InspectorJob } from "./protocol.js";
import { validateChildMessage } from "./validate-message.js";
import {
  createInspectorDeps,
  createRepo,
  createScopeTree,
  GITHUB_REMOTES,
  type ScopeTree,
} from "./test-support/fixtures.js";

/** PROTOTYPE (#414): the `resolve` job behind the OS folder dialog and the pasted path. */

const posixDescribe = describe.skipIf(process.platform === "win32");

let tree: ScopeTree;
afterEach(() => tree?.cleanup());

async function resolve(target: string, homeDir: string): Promise<ChildMessage[]> {
  const { deps, messages } = createInspectorDeps();
  const job = { kind: "resolve", path: target, homeDir } as const;
  await runInspectorJob(deps, job);
  // Every message must also pass the server's validation.
  for (const message of messages) expect(validateChildMessage(message, job)).not.toBeNull();
  return messages;
}

function first<T extends ChildMessage["t"]>(
  messages: ChildMessage[],
  t: T,
): Extract<ChildMessage, { t: T }> | undefined {
  return messages.find((message) => message.t === t) as Extract<ChildMessage, { t: T }> | undefined;
}

posixDescribe("resolve job (prototype #414)", () => {
  it("resolves a GitHub repository inside the home folder like a search candidate", async () => {
    tree = createScopeTree();
    const home = path.dirname(tree.root);
    createRepo(path.join(tree.root, "shop"), { remotes: GITHUB_REMOTES });
    const messages = await resolve(path.join(tree.root, "shop"), home);
    const resolved = first(messages, "resolved");
    expect(resolved?.root.path).toBe(home);
    expect(resolved?.candidate.segments.map((s) => s.name)).toEqual(["scope", "shop"]);
    expect(resolved?.candidate.block).toBeNull();
    expect(resolved?.candidate.remote).toEqual({ status: "github", owner: "acme", name: "shop" });
    expect(resolved?.folderBlock).toBeNull();
    expect(messages.at(-1)?.t).toBe("done");
  });

  it("resolves a folder without Git: the candidate is blocked, the folder chain is fine", async () => {
    tree = createScopeTree();
    mkdirSync(path.join(tree.root, "notes"));
    const resolved = first(
      await resolve(path.join(tree.root, "notes"), path.dirname(tree.root)),
      "resolved",
    );
    expect(resolved?.candidate.block?.code).toBe("not_a_git_root");
    expect(resolved?.folderBlock).toBeNull();
  });

  it("follows a symbolic link to the real folder, never by the link's name", async () => {
    tree = createScopeTree();
    mkdirSync(path.join(tree.root, "real"));
    symlinkSync(path.join(tree.root, "real"), path.join(tree.root, "alias"));
    const resolved = first(
      await resolve(path.join(tree.root, "alias"), path.dirname(tree.root)),
      "resolved",
    );
    expect(resolved?.candidate.segments.at(-1)?.name).toBe("real");
  });

  it("reports a folder another user could change", async () => {
    tree = createScopeTree();
    const open = path.join(tree.root, "open");
    mkdirSync(open);
    chmodSync(open, 0o777);
    const resolved = first(await resolve(open, path.dirname(tree.root)), "resolved");
    expect(resolved?.folderBlock?.code).toBe("group_or_world_writable");
  });

  it("resolves a folder outside the home folder from the highest folder still ours", async () => {
    tree = createScopeTree();
    mkdirSync(path.join(tree.root, "elsewhere"));
    const resolved = first(
      await resolve(path.join(tree.root, "elsewhere"), "/nonexistent-home-for-test"),
      "resolved",
    );
    expect(resolved).toBeDefined();
    expect(path.join(resolved!.root.path, ...resolved!.candidate.segments.map((s) => s.name))).toBe(
      path.join(tree.root, "elsewhere"),
    );
  });

  it("refuses the home folder, its parents, the top level, a file and a missing path", async () => {
    tree = createScopeTree();
    const home = path.dirname(tree.root);
    writeFileSync(path.join(tree.root, "file.txt"), "x");
    const reason = async (target: string): Promise<string | undefined> =>
      first(await resolve(target, home), "refused")?.reason;
    expect(await reason(home)).toBe("too_broad");
    expect(await reason(path.dirname(home))).toBe("too_broad");
    expect(await reason("/")).toBe("too_broad");
    expect(await reason("/usr")).toBe("too_broad");
    expect(await reason(path.join(tree.root, "file.txt"))).toBe("not_a_directory");
    expect(await reason(path.join(tree.root, "nope"))).toBe("missing");
    expect(await reason("relative/path")).toBe("missing");
  });
});

describe("resolve message validation", () => {
  it("rejects a resolve message for another job and an unknown refusal", () => {
    const searchJob: InspectorJob = {
      kind: "search",
      roots: [],
      name: "x",
      source: "typed",
      platform: "linux",
    };
    expect(
      validateChildMessage({ t: "refused", reason: "missing", paths: [] }, searchJob),
    ).toBeNull();
    const job = { kind: "resolve", path: "/a/b", homeDir: "/a" } as const;
    expect(validateChildMessage({ t: "refused", reason: "nope", paths: [] }, job)).toBeNull();
    expect(validateChildMessage({ t: "refused", reason: "missing", paths: [] }, job)).toEqual({
      t: "refused",
      reason: "missing",
      paths: [],
    });
  });
});
