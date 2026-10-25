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

  it("does not flag third_party/ itself, but flags a dependency directory nested in it", () => {
    expect(findCommittedDependencyDirectories(["third_party/zlib/zlib.h"])).toEqual([]);
    expect(
      findCommittedDependencyDirectories([
        "third_party/zlib/zlib.h",
        "third_party/x/node_modules/a.js",
        "third_party/x/node_modules/b/c.js",
      ]),
    ).toEqual([{ root: "third_party/x/node_modules", fileCount: 2 }]);
  });

  it("flags a dependency directory nested in Go module vendoring", () => {
    expect(
      findCommittedDependencyDirectories([
        "go.mod",
        "vendor/modules.txt",
        "vendor/github.com/pkg/errors/errors.go",
        "vendor/node_modules/x/index.js",
        "vendor/github.com/acme/ui/bower_components/y.js",
      ]),
    ).toEqual([
      { root: "vendor/github.com/acme/ui/bower_components", fileCount: 1 },
      { root: "vendor/node_modules", fileCount: 1 },
    ]);
  });

  it("counts a dependency directory nested in a flagged vendor/ toward that root", () => {
    expect(
      findCommittedDependencyDirectories([
        "composer.json",
        "vendor/autoload.php",
        "vendor/acme/assets/node_modules/a.js",
      ]),
    ).toEqual([{ root: "vendor", fileCount: 2 }]);
  });

  it("never flags first-party vendor/ modules under src/, app/ or lib/", () => {
    expect(
      findCommittedDependencyDirectories([
        "package.json",
        "src/vendor/vendor.module.ts",
        "src/vendor/vendor.service.ts",
        "app/vendor/client.rb",
        "lib/vendor/a.js",
        "src/integrations/third_party/x.ts",
      ]),
    ).toEqual([]);
    // Even next to a manifest, a vendor/ inside src/ is not dependency code.
    expect(findCommittedDependencyDirectories(["src/composer.json", "src/vendor/a.php"])).toEqual(
      [],
    );
    // The source directory name matches in any letter case.
    expect(findCommittedDependencyDirectories(["Src/composer.json", "Src/vendor/a.php"])).toEqual(
      [],
    );
  });

  it("flags vendor/ only at the repository root or next to composer.json, go.mod or Gemfile", () => {
    expect(findCommittedDependencyDirectories(["composer.json", "vendor/autoload.php"])).toEqual([
      { root: "vendor", fileCount: 1 },
    ]);
    // At the root even without a manifest.
    expect(findCommittedDependencyDirectories(["vendor/a.js"])).toEqual([
      { root: "vendor", fileCount: 1 },
    ]);
    expect(
      findCommittedDependencyDirectories([
        "api/composer.json",
        "api/vendor/autoload.php",
        "web/Gemfile",
        "web/vendor/bundle/x.rb",
        "svc/go.mod",
        "svc/vendor/a.go",
        "tools/vendor/script.sh",
      ]),
    ).toEqual([
      { root: "api/vendor", fileCount: 1 },
      { root: "svc/vendor", fileCount: 1 },
      { root: "web/vendor", fileCount: 1 },
    ]);
  });

  it("spares Rails importmap pins in vendor/javascript/ but still flags vendor/bundle/", () => {
    const rails = [
      "Gemfile",
      "config/importmap.rb",
      "vendor/.keep",
      "vendor/javascript/.keep",
      "vendor/javascript/stimulus.min.js",
      "vendor/javascript/@hotwired--turbo.js",
    ];
    expect(findCommittedDependencyDirectories(rails)).toEqual([]);
    expect(
      findCommittedDependencyDirectories([
        ...rails,
        "vendor/bundle/ruby/3.3.0/gems/rack-3.0.0/lib/rack.rb",
        "vendor/bundle/ruby/3.3.0/gems/rack-3.0.0/README.md",
      ]),
    ).toEqual([{ root: "vendor/bundle", fileCount: 2 }]);
    // A Rails app in a subdirectory.
    expect(
      findCommittedDependencyDirectories([
        "web/Gemfile",
        "web/config/importmap.rb",
        "web/vendor/javascript/a.js",
        "web/vendor/bundle/x.rb",
      ]),
    ).toEqual([{ root: "web/vendor/bundle", fileCount: 1 }]);
    // Without config/importmap.rb, vendor/javascript/ is an ordinary committed vendor/.
    expect(
      findCommittedDependencyDirectories(["Gemfile", "vendor/javascript/stimulus.min.js"]),
    ).toEqual([{ root: "vendor", fileCount: 1 }]);
    const description = describeCommittedDependencyDirectories(
      findCommittedDependencyDirectories([...rails, "vendor/bundle/x.rb"]),
      REVISION,
    );
    expect(description.recommendation).toContain("(git rm -r --cached vendor/bundle)");
  });

  const importmapRails = ["Gemfile", "config/importmap.rb", "vendor/javascript/stimulus.min.js"];

  it("still counts loose files directly in vendor/ of an importmap Rails app", () => {
    expect(
      findCommittedDependencyDirectories([
        ...importmapRails,
        "vendor/jquery.min.js",
        "vendor/legacy.js",
      ]),
    ).toEqual([{ root: "vendor", fileCount: 2 }]);
  });

  it("still flags a dependency directory nested in importmap pins", () => {
    const rails = importmapRails;
    expect(
      findCommittedDependencyDirectories([
        ...rails,
        "vendor/javascript/node_modules/react/index.js",
        "vendor/javascript/node_modules/react/package.json",
        "vendor/javascript/x/bower_components/y.js",
      ]),
    ).toEqual([
      { root: "vendor/javascript/node_modules", fileCount: 2 },
      { root: "vendor/javascript/x/bower_components", fileCount: 1 },
    ]);
  });

  it("does not count placeholder files such as vendor/.keep", () => {
    expect(findCommittedDependencyDirectories(["Gemfile", "vendor/.keep"])).toEqual([]);
    expect(
      findCommittedDependencyDirectories(["node_modules/.gitkeep", "node_modules/a/index.js"]),
    ).toEqual([{ root: "node_modules", fileCount: 1 }]);
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
    // A nested vendor/ with no manifest next to it (go.mod is in the parent) is not flagged.
    expect(
      findCommittedDependencyDirectories(["go.mod", "web/vendor/modules.txt", "web/vendor/a.go"]),
    ).toEqual([]);
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
