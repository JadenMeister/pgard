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
});
