import path from "node:path";
import { describe, expect, it } from "vitest";
import { toRepositoryRelativePath } from "./paths.js";

describe("toRepositoryRelativePath", () => {
  const root = "/work/app";

  it.each([
    ["/work/app/src/a.ts", "src/a.ts"],
    ["src/a.ts", "src/a.ts"],
    ["./src/a.ts", "src/a.ts"],
    ["src/../lib/b.go", "lib/b.go"],
  ])("maps %s to %s", (input, expected) => {
    expect(toRepositoryRelativePath(root, input)).toBe(expected);
  });

  it.each(["/etc/passwd", "../outside.ts", "src/../../outside.ts", "/work/app", "C:\\x\\y.ts"])(
    "drops %s",
    (input) => {
      expect(toRepositoryRelativePath(root, input)).toBeNull();
    },
  );

  it.skipIf(path.sep === "\\")("keeps a literal backslash in a POSIX name distinct (#376)", () => {
    expect(toRepositoryRelativePath(root, "src\\a.ts")).toBe("src\\a.ts");
    expect(toRepositoryRelativePath(root, "src\\a.ts")).not.toBe(
      toRepositoryRelativePath(root, "src/a.ts"),
    );
    // A Windows absolute path is still a separator path (and escapes the root here).
    expect(toRepositoryRelativePath(root, "C:\\x\\y.ts")).toBeNull();
  });
});
