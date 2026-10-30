import { describe, expect, it } from "vitest";
import { folderSafetyProblem, type ScopeStat } from "./web-scope.js";

const ME = 501;

function stat(uid: number, mode: number): ScopeStat {
  return { isDirectory: true, isFile: false, isSymbolicLink: false, uid, mode, dev: 1, ino: 1 };
}

/** A fake file system: path -> [uid, mode]. A missing path is unreadable. */
function lstatOf(entries: Record<string, [number, number]>) {
  return async (target: string): Promise<ScopeStat> => {
    const entry = entries[target];
    if (entry === undefined) throw new Error("ENOENT");
    return stat(entry[0], entry[1]);
  };
}

describe("folderSafetyProblem (the web chooser's ownership and permission rule, #427)", () => {
  const home = "/home/me";

  it("allows a folder inside home that this user owns without group or other write", async () => {
    const fs = lstatOf({
      "/home": [0, 0o40755],
      "/home/me": [ME, 0o40750],
      "/home/me/code": [ME, 0o40755],
      "/home/me/code/app": [ME, 0o40755],
    });
    expect(await folderSafetyProblem("/home/me/code/app", home, ME, fs)).toBeNull();
  });

  it("refuses a folder owned by another user, naming it", async () => {
    const fs = lstatOf({
      "/home": [0, 0o40755],
      "/home/me": [ME, 0o40750],
      "/home/me/code": [ME, 0o40755],
      "/home/me/code/app": [502, 0o40755],
    });
    expect(await folderSafetyProblem("/home/me/code/app", home, ME, fs)).toEqual({
      problem: "not_owned_by_you",
      path: "/home/me/code/app",
    });
  });

  it("refuses a folder, or one above it inside home, writable by group or others", async () => {
    const fs = lstatOf({
      "/home": [0, 0o40755],
      "/home/me": [ME, 0o40750],
      "/home/me/code": [ME, 0o40775],
      "/home/me/code/app": [ME, 0o40755],
    });
    expect(await folderSafetyProblem("/home/me/code/app", home, ME, fs)).toEqual({
      problem: "group_or_world_writable",
      path: "/home/me/code",
    });
    const writable = lstatOf({
      ...{ "/home": [0, 0o40755] as [number, number] },
      "/home/me": [ME, 0o40750],
      "/home/me/x": [ME, 0o40757],
    });
    expect((await folderSafetyProblem("/home/me/x", home, ME, writable))?.problem).toBe(
      "group_or_world_writable",
    );
  });

  it("outside home: anchors at the highest folder this user owns; a world-writable parent without the sticky bit refuses", async () => {
    const sticky = lstatOf({
      "/srv": [0, 0o41777],
      "/srv/work": [ME, 0o40755],
      "/srv/work/app": [ME, 0o40755],
    });
    expect(await folderSafetyProblem("/srv/work/app", home, ME, sticky)).toBeNull();
    const notSticky = lstatOf({
      "/srv": [0, 0o40777],
      "/srv/work": [ME, 0o40755],
      "/srv/work/app": [ME, 0o40755],
    });
    expect(await folderSafetyProblem("/srv/work/app", home, ME, notSticky)).toEqual({
      problem: "group_or_world_writable",
      path: "/srv",
    });
  });

  it("skips what cannot be read, and trusts nothing without a user id", async () => {
    expect(await folderSafetyProblem("/gone/app", home, ME, lstatOf({}))).toBeNull();
    const fs = lstatOf({ "/srv": [0, 0o40755], "/srv/app": [ME, 0o40755] });
    expect((await folderSafetyProblem("/srv/app", home, undefined, fs))?.problem).toBe(
      "not_owned_by_you",
    );
  });
});
