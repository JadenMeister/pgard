import { describe, expect, it } from "vitest";
import {
  MAX_LISTED_DEPENDENCY_DIRECTORIES,
  describeCommittedDependencyDirectories,
  findCommittedDependencyDirectories,
} from "./dependency-directories.js";

const REVISION = "0123456789abcdef0123456789abcdef01234567";

describe("findCommittedDependencyDirectories", () => {
  it("returns one entry per root with its tracked file count, largest first", () => {
    expect(
      findCommittedDependencyDirectories([
        "src/index.ts",
        "node_modules/a/index.js",
        "node_modules/a/node_modules/b/index.js",
        "node_modules/c/package.json",
        "packages/web/node_modules/d/index.js",
        "ios/Pods/Alamofire/Session.swift",
        "ios/Pods/Manifest.lock",
        "bower_components/jquery/jquery.js",
        "jspm_packages/npm/x.js",
      ]),
    ).toEqual([
      { root: "node_modules", fileCount: 3 },
      { root: "ios/Pods", fileCount: 2 },
      { root: "bower_components", fileCount: 1 },
      { root: "jspm_packages", fileCount: 1 },
      { root: "packages/web/node_modules", fileCount: 1 },
    ]);
  });

  it("returns nothing when no dependency directory is tracked", () => {
    expect(
      findCommittedDependencyDirectories([
        "src/vendored.ts",
        "my_node_modules_x/index.js",
        "dist/bundle.js",
        "build/app.js",
        "node_modules",
        "k8s/pods/a.yaml",
      ]),
    ).toEqual([]);
  });

  it("does not flag third_party/, even with a dependency directory inside it", () => {
    expect(
      findCommittedDependencyDirectories([
        "third_party/zlib/zlib.h",
        "third_party/x/node_modules/a.js",
      ]),
    ).toEqual([]);
  });

  it("skips Go module vendoring (go.mod and vendor/modules.txt) but flags other vendor/ copies", () => {
    const goVendor = ["go.mod", "vendor/modules.txt", "vendor/github.com/pkg/errors/errors.go"];
    expect(findCommittedDependencyDirectories(goVendor)).toEqual([]);
    expect(
      findCommittedDependencyDirectories([
        "svc/go.mod",
        "svc/vendor/modules.txt",
        "svc/vendor/golang.org/x/a.go",
      ]),
    ).toEqual([]);
    // Without modules.txt (or without go.mod) it is a plain copy, e.g. PHP Composer's vendor/.
    expect(
      findCommittedDependencyDirectories(["go.mod", "vendor/github.com/pkg/errors/errors.go"]),
    ).toEqual([{ root: "vendor", fileCount: 1 }]);
    expect(
      findCommittedDependencyDirectories([
        "composer.json",
        "vendor/autoload.php",
        "vendor/modules.txt",
      ]),
    ).toEqual([{ root: "vendor", fileCount: 2 }]);
    // go.mod must sit next to the vendor/ directory.
    expect(
      findCommittedDependencyDirectories(["go.mod", "web/vendor/modules.txt", "web/vendor/a.go"]),
    ).toEqual([{ root: "web/vendor", fileCount: 2 }]);
  });
});

describe("describeCommittedDependencyDirectories", () => {
  it("names the directory, its file count and the fix", () => {
    const text = describeCommittedDependencyDirectories(
      [{ root: "node_modules", fileCount: 11098 }],
      REVISION,
    );
    expect(text.evidence).toBe(
      "1 dependency directory is tracked in commit 0123456789ab: node_modules/ (11098 tracked files)",
    );
    expect(text.recommendation).toContain("(git rm -r --cached node_modules)");
    expect(text.recommendation).toContain(".gitignore");
  });

  it(`lists at most ${MAX_LISTED_DEPENDENCY_DIRECTORIES} directories and counts the rest`, () => {
    const directories = Array.from({ length: 8 }, (_, index) => ({
      root: `packages/p${index}/node_modules`,
      fileCount: 8 - index,
    }));
    const text = describeCommittedDependencyDirectories(directories, REVISION);
    expect(text.evidence).toContain("8 dependency directories are tracked");
    expect(text.evidence).toContain("packages/p4/node_modules/ (4 tracked files)");
    expect(text.evidence).not.toContain("packages/p5/node_modules");
    expect(text.evidence).toMatch(/, and 3 more$/);
    expect(text.recommendation).toContain(
      "git rm -r --cached packages/p0/node_modules packages/p1/node_modules packages/p2/node_modules packages/p3/node_modules packages/p4/node_modules)",
    );
  });

  it("quotes unusual paths in the suggested command", () => {
    const text = describeCommittedDependencyDirectories(
      [{ root: "my app/node_modules", fileCount: 1 }],
      REVISION,
    );
    expect(text.recommendation).toContain("git rm -r --cached 'my app/node_modules')");
  });
});
