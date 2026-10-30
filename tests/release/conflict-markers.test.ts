import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = path.resolve(import.meta.dirname, "..", "..");
const BINARY = /\.(?:png|jpe?g|gif|ico|webp|woff2?|ttf|otf|pdf|zip|gz|tgz|wasm|node)$/i;

describe("committed files", () => {
  it("hold no unresolved merge conflict markers", () => {
    const tracked = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" })
      .split("\0")
      .filter((file) => file !== "" && !BINARY.test(file));
    const offenders: string[] = [];
    for (const file of tracked) {
      let text: string;
      try {
        text = readFileSync(path.join(root, file), "utf8");
      } catch {
        continue;
      }
      if (/^(?:<{7} |>{7} )/m.test(text)) offenders.push(file);
    }
    expect(offenders).toEqual([]);
  });
});
