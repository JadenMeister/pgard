import { describe, expect, it } from "vitest";
import { parseGoMod, parseGoSum } from "./go.js";
import { parseNpmLock } from "./npm.js";
import { parsePnpmLock } from "./pnpm.js";
import { parseYarnLock } from "./yarn.js";

const names = (parsed: { dependencies: { name: string; version: string }[] }): string[] =>
  parsed.dependencies.map((dependency) => `${dependency.name}@${dependency.version}`).sort();

describe("parseNpmLock", () => {
  const v3 = JSON.stringify({
    name: "app",
    lockfileVersion: 3,
    requires: true,
    packages: {
      "": {
        name: "app",
        dependencies: { express: "^4.18.0" },
        devDependencies: { vitest: "^1.0.0" },
      },
      "node_modules/express": {
        version: "4.18.2",
        resolved: "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      },
      "node_modules/qs": { version: "6.11.0" },
      "node_modules/express/node_modules/qs": { version: "6.5.3" },
      "node_modules/@scope/pkg": { version: "1.0.0", dev: true },
      "node_modules/vitest": { version: "1.6.0", dev: true },
      "node_modules/my-alias": { name: "real-pkg", version: "2.0.0" },
      "node_modules/ws-member": { resolved: "packages/ws-member", link: true },
      "packages/ws-member": {
        name: "ws-member",
        version: "0.0.1",
        dependencies: { "@scope/pkg": "^1.0.0" },
      },
    },
  });

  it("reads v3 packages with direct and transitive marks and nested copies", () => {
    const parsed = parseNpmLock(v3);
    expect(parsed.isComplete).toBe(true);
    expect(names(parsed)).toEqual([
      "@scope/pkg@1.0.0",
      "express@4.18.2",
      "qs@6.11.0",
      "qs@6.5.3",
      "real-pkg@2.0.0",
      "vitest@1.6.0",
    ]);
    const byName = new Map(parsed.dependencies.map((d) => [`${d.name}@${d.version}`, d.direct]));
    expect(byName.get("express@4.18.2")).toBe(true);
    expect(byName.get("vitest@1.6.0")).toBe(true);
    expect(byName.get("@scope/pkg@1.0.0")).toBe(true); // declared by a workspace member
    expect(byName.get("qs@6.11.0")).toBe(false);
    expect(byName.get("qs@6.5.3")).toBe(false);
    expect(byName.get("real-pkg@2.0.0")).toBe(false);
    expect(parsed.notes.join(" ")).toContain("linked workspace package");
  });

  it("reads the v1 nested layout without claiming direct/transitive", () => {
    const parsed = parseNpmLock(
      JSON.stringify({
        lockfileVersion: 1,
        dependencies: {
          a: { version: "1.0.0", dependencies: { b: { version: "2.0.0" } } },
          local: { version: "file:../local" },
        },
      }),
    );
    expect(names(parsed)).toEqual(["a@1.0.0", "b@2.0.0"]);
    expect(parsed.dependencies.every((d) => d.direct === undefined)).toBe(true);
    expect(parsed.notes.join(" ")).toContain("v1");
  });

  it("flags malformed JSON, non-objects and unknown layouts as incomplete", () => {
    expect(parseNpmLock("{ not json").isComplete).toBe(false);
    expect(parseNpmLock("[1,2]").isComplete).toBe(false);
    expect(parseNpmLock("{}").isComplete).toBe(false);
    const truncated = parseNpmLock(v3.slice(0, v3.length - 40));
    expect(truncated.isComplete).toBe(false);
    expect(truncated.dependencies).toEqual([]);
  });

  it("accepts an empty v3 lockfile as complete and flags entries without versions", () => {
    expect(parseNpmLock('{"lockfileVersion":3,"packages":{"":{}}}')).toMatchObject({
      dependencies: [],
      isComplete: true,
    });
    const partial = parseNpmLock(
      '{"lockfileVersion":3,"packages":{"node_modules/x":{},"node_modules/y":{"version":"1.0.0"}}}',
    );
    expect(partial.isComplete).toBe(false);
    expect(names(partial)).toEqual(["y@1.0.0"]);
  });

  it("does not pollute prototypes from a hostile lockfile", () => {
    const parsed = parseNpmLock(
      '{"lockfileVersion":3,"packages":{"node_modules/__proto__":{"version":"1.0.0"},"":{"__proto__":{"polluted":true}}}}',
    );
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
    expect(names(parsed)).toEqual(["__proto__@1.0.0"]);
  });
});

describe("parsePnpmLock", () => {
  const v9 = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      express:
        specifier: ^4.18.0
        version: 4.18.2
    devDependencies:
      '@types/node':
        specifier: ^20.0.0
        version: 20.11.0
      local-lib:
        specifier: workspace:*
        version: link:../local-lib

packages:

  '@types/node@20.11.0':
    resolution: {integrity: sha512-abc}

  express@4.18.2:
    resolution: {integrity: sha512-def}
    engines: {node: '>= 0.10.0'}

  qs@6.11.0:
    resolution: {integrity: sha512-ghi}

  react-dom@18.2.0:
    resolution: {integrity: sha512-jkl}
    peerDependencies:
      react: ^18.2.0

  tarball-dep@https://example.com/x.tgz:
    resolution: {tarball: https://example.com/x.tgz}

snapshots:

  '@types/node@20.11.0':
    dependencies:
      undici-types: 5.26.5

  express@4.18.2:
    dependencies:
      qs: 6.11.0

  qs@6.11.0: {}

  react-dom@18.2.0(react@18.2.0):
    dependencies:
      react: 18.2.0

  react@18.2.0: {}
`;

  it("reads v9 packages, snapshots, direct marks, and marks non-registry sources as partial", () => {
    const parsed = parsePnpmLock(v9);
    expect(parsed.isComplete).toBe(false); // the tarball dependency's version is unknown
    expect(names(parsed)).toEqual([
      "@types/node@20.11.0",
      "express@4.18.2",
      "qs@6.11.0",
      "react-dom@18.2.0",
      "react@18.2.0",
    ]);
    const direct = new Map(parsed.dependencies.map((d) => [d.name, d.direct]));
    expect(direct.get("express")).toBe(true);
    expect(direct.get("@types/node")).toBe(true);
    expect(direct.get("qs")).toBe(false);
    expect(parsed.notes.join(" ")).toContain("tarball, git or directory");
  });

  it("reads the v6 and v5 key styles", () => {
    const v6 = `lockfileVersion: '6.0'
dependencies:
  lodash:
    specifier: ^4.17.21
    version: 4.17.21
packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-a}
    dev: false
  /@babel/core@7.23.0(supports-color@5.5.0):
    resolution: {integrity: sha512-b}
    dev: true
`;
    expect(names(parsePnpmLock(v6))).toEqual(["@babel/core@7.23.0", "lodash@4.17.21"]);
    const v5 = `lockfileVersion: 5.4
specifiers:
  lodash: ^4.17.21
dependencies:
  lodash: 4.17.21
packages:
  /lodash/4.17.21:
    resolution: {integrity: sha512-a}
    dev: false
  /@babel/core/7.20.0_supports-color@5.5.0:
    resolution: {integrity: sha512-b}
    dev: true
`;
    const parsed = parsePnpmLock(v5);
    expect(names(parsed)).toEqual(["@babel/core@7.20.0", "lodash@4.17.21"]);
    expect(parsed.dependencies.find((d) => d.name === "lodash")?.direct).toBe(true);
  });

  it("reads both documents of a multi-document lockfile", () => {
    const text = `---
lockfileVersion: '9.0'
importers:
  .:
    configDependencies: {}
packages:
  pnpm-plugin@1.0.0:
    resolution: {integrity: sha512-a}
---
lockfileVersion: '9.0'
packages:
  qs@6.11.0:
    resolution: {integrity: sha512-b}
`;
    expect(names(parsePnpmLock(text))).toEqual(["pnpm-plugin@1.0.0", "qs@6.11.0"]);
  });

  it("refuses YAML tags, anchors and aliases instead of guessing", () => {
    for (const hostile of [
      "lockfileVersion: '9.0'\npackages:\n  a@1.0.0: !!python/object/apply:os.system ['id']\n",
      "lockfileVersion: '9.0'\npackages:\n  a@1.0.0: &x\n    b: 1\n  c@1.0.0: *x\n",
      "lockfileVersion: '9.0'\npackages:\n  <<: *base\n",
    ]) {
      const parsed = parsePnpmLock(hostile);
      expect(parsed.isComplete).toBe(false);
      expect(parsed.dependencies).toEqual([]);
      expect(parsed.notes.join(" ")).toContain("does not read");
    }
  });

  it("flags files that are not pnpm lockfiles or are malformed", () => {
    expect(parsePnpmLock("hello world").isComplete).toBe(false);
    expect(parsePnpmLock("packages:\n  a@1.0.0:\n    resolution: {}\n").isComplete).toBe(false);
    expect(parsePnpmLock("lockfileVersion: '9.0'\n\t\tbroken: [\n").isComplete).toBe(false);
    expect(parsePnpmLock("").isComplete).toBe(false);
  });
});

describe("parseYarnLock", () => {
  const v1 = `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.12.13"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz#dcfc826beef65e75c50e21d3837d7d95798dd658"
  integrity sha512-HV1Cm0Q3ZrpCR93tkWOYiuYIgLxZXZFVG2VgK+MBWjUqZTundupbfx2aXarXuw5Ko5aMcjtJgbSs4vUGBS5v6g==
  dependencies:
    "@babel/highlight" "^7.12.13"

lodash@^4.17.15, lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#679591c564c3bffaae8454cf0b3df370c3d6911c"

"left-pad@git+https://github.com/x/left-pad.git":
  version "1.3.0"
  resolved "git+https://github.com/x/left-pad.git#abc"
`;

  it("reads yarn v1 and marks direct dependencies from package.json names", () => {
    const parsed = parseYarnLock(v1, new Set(["lodash"]));
    expect(parsed.isComplete).toBe(true);
    expect(names(parsed)).toEqual([
      "@babel/code-frame@7.12.13",
      "left-pad@1.3.0",
      "lodash@4.17.21",
    ]);
    expect(parsed.dependencies.find((d) => d.name === "lodash")?.direct).toBe(true);
    expect(parsed.dependencies.find((d) => d.name === "@babel/code-frame")?.direct).toBe(false);
    expect(parseYarnLock(v1).dependencies.every((d) => d.direct === undefined)).toBe(true);
  });

  const berry = `# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 8
  cacheKey: 10c0

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
  languageName: unknown
  linkType: soft

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: 10c0/abc
  languageName: node
  linkType: hard

"@babel/core@npm:^7.0.0, @babel/core@npm:^7.12.3":
  version: 7.23.0
  resolution: "@babel/core@npm:7.23.0"
  dependencies:
    "@babel/types": "npm:^7.23.0"
  languageName: node
  linkType: hard

"resolve@patch:resolve@npm%3A^1.1.7#optional!builtin<compat/resolve>":
  version: 1.22.8
  resolution: "resolve@patch:resolve@npm%3A1.22.8#optional!builtin<compat/resolve>::version=1.22.8&hash=c3c19d"
  languageName: node
  linkType: hard
`;

  it("reads berry registry entries and counts workspace and patch entries", () => {
    const parsed = parseYarnLock(berry);
    expect(parsed.isComplete).toBe(true);
    expect(names(parsed)).toEqual(["@babel/core@7.23.0", "lodash@4.17.21"]);
    expect(parsed.notes.join(" ")).toContain("2 non-registry");
  });

  it("flags garbage and entries it cannot read", () => {
    expect(parseYarnLock("this is not a lockfile\n<<<<<<< HEAD\n").isComplete).toBe(false);
    const broken = parseYarnLock('foo@^1.0.0:\n  resolved "x"\n');
    expect(broken.isComplete).toBe(false);
    expect(broken.dependencies).toEqual([]);
    expect(parseYarnLock("# yarn lockfile v1\n\n").isComplete).toBe(true);
  });
});

describe("parseGoMod / parseGoSum", () => {
  const goMod = `module example.com/app

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	golang.org/x/net v0.17.0 // indirect
	github.com/local/thing v1.0.0
	github.com/old/dep v1.2.3
)

require github.com/stretchr/testify v1.8.4

replace github.com/local/thing => ../thing

replace github.com/old/dep v1.2.3 => github.com/fork/dep v1.2.4

exclude golang.org/x/text v0.3.0
`;

  it("reads require lists, indirect marks and replace directives", () => {
    const parsed = parseGoMod(goMod);
    expect(parsed.isComplete).toBe(true);
    expect(names(parsed)).toEqual([
      "github.com/fork/dep@v1.2.4",
      "github.com/gin-gonic/gin@v1.9.1",
      "github.com/stretchr/testify@v1.8.4",
      "golang.org/x/net@v0.17.0",
    ]);
    const direct = new Map(parsed.dependencies.map((d) => [d.name, d.direct]));
    expect(direct.get("golang.org/x/net")).toBe(false);
    expect(direct.get("github.com/gin-gonic/gin")).toBe(true);
    expect(parsed.notes.join(" ")).toContain("replaced by a local path");
  });

  it("adds transitive modules from go.sum only for go < 1.17", () => {
    const sum = `github.com/gin-gonic/gin v1.9.1 h1:a=
github.com/gin-gonic/gin v1.9.1/go.mod h1:b=
golang.org/x/sys v0.1.0 h1:c=
golang.org/x/sys v0.13.0 h1:d=
golang.org/x/sys v0.13.0/go.mod h1:e=
golang.org/x/text v0.3.0/go.mod h1:f=
`;
    const old = parseGoMod("module m\n\ngo 1.16\n\nrequire github.com/gin-gonic/gin v1.9.1\n", sum);
    expect(names(old)).toEqual(["github.com/gin-gonic/gin@v1.9.1", "golang.org/x/sys@v0.13.0"]);
    expect(old.notes.join(" ")).toContain("before 1.17");
    const modern = parseGoMod(
      "module m\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n",
      sum,
    );
    expect(names(modern)).toEqual(["github.com/gin-gonic/gin@v1.9.1"]);
    const noSum = parseGoMod("module m\n\ngo 1.16\n\nrequire github.com/gin-gonic/gin v1.9.1\n");
    expect(noSum.isComplete).toBe(false);
  });

  it("flags files that are not go.mod, and skips malformed require lines", () => {
    expect(parseGoMod("hello").isComplete).toBe(false);
    const parsed = parseGoMod(
      "module m\ngo 1.21\nrequire github.com/a/b notaversion\nrequire github.com/c/d v1.0.0\n",
    );
    expect(parsed.isComplete).toBe(false);
    expect(names(parsed)).toEqual(["github.com/c/d@v1.0.0"]);
  });

  it("reads a standalone go.sum without go.mod hash lines and says what it cannot know", () => {
    const parsed = parseGoSum(
      "github.com/a/b v1.0.0 h1:x=\ngithub.com/a/b v1.0.0/go.mod h1:y=\ngithub.com/a/b v1.0.0 h1:x=\n",
    );
    expect(names(parsed)).toEqual(["github.com/a/b@v1.0.0"]);
    expect(parsed.notes.join(" ")).toContain("No go.mod");
    expect(parseGoSum("garbage line\n").isComplete).toBe(false);
  });
});

describe("hostile input", () => {
  const BOUND_MS = 1500;
  const timed = <T>(run: () => T): { result: T; ms: number } => {
    const start = performance.now();
    const result = run();
    return { result, ms: performance.now() - start };
  };

  it("pnpm: long adversarial lines parse in bounded time and mark the file partial", () => {
    const head = "lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    resolution: {integrity: x}\n";
    const hostile = [
      `  k:${" ".repeat(1_000_000)}\r\n`,
      `  k: ${" ".repeat(1_000_000)}x\n`,
      `  k: ${"a ".repeat(500_000)}\n`,
      `${"  k:".repeat(250_000)}\n`,
      `  '${"'".repeat(1_000_000)}\n`,
    ];
    for (const line of hostile) {
      const { result, ms } = timed(() => parsePnpmLock(head + line));
      expect(ms).toBeLessThan(BOUND_MS);
      expect(result.isComplete).toBe(false);
      expect(result.notes.join(" ")).toContain("longer than");
      expect(names(result)).toEqual(["a@1.0.0"]);
    }
  });

  it("pnpm: adversarial lines just under the cap are also fast", () => {
    const head = "lockfileVersion: '9.0'\npackages:\n";
    for (const line of [
      `  k:${" ".repeat(16_000)}\r`,
      `  k: ${" ".repeat(16_000)}x`,
      `  k: ${"a ".repeat(8_000)}`,
      `  '${"''".repeat(8_000)}`,
    ]) {
      const { ms } = timed(() => parsePnpmLock(`${head}${line}\n`.repeat(50)));
      expect(ms).toBeLessThan(BOUND_MS);
    }
  });

  it("yarn, go and npm: megabyte-long lines parse in bounded time", () => {
    const long = "x".repeat(1_000_000);
    const spaces = " ".repeat(1_000_000);
    expect(
      timed(() => parseYarnLock(`# yarn lockfile v1\n\n${long}@^1:\n  version${spaces}"1"\n`)).ms,
    ).toBeLessThan(BOUND_MS);
    expect(
      timed(() => parseYarnLock(`# yarn lockfile v1\n\n  version: ${spaces}\n  ${long}:`)).ms,
    ).toBeLessThan(BOUND_MS);
    expect(
      timed(() => parseGoMod(`module m\ngo 1.21\nrequire ${long} ${spaces}\n${long}${spaces}(\n`))
        .ms,
    ).toBeLessThan(BOUND_MS);
    expect(timed(() => parseGoSum(`${long} ${spaces} ${long}\n`.repeat(3))).ms).toBeLessThan(
      BOUND_MS,
    );
    expect(
      timed(() =>
        parseNpmLock(
          `{"lockfileVersion":3,"packages":{"node_modules/${long}":{"version":"1.0.0"}}}`,
        ),
      ).ms,
    ).toBeLessThan(BOUND_MS);
  });

  it("yarn v1: a block without a readable version makes the file incomplete even with other entries", () => {
    const parsed = parseYarnLock(
      '# yarn lockfile v1\n\ngood@^1:\n  version "1.0.0"\n\nbad@^1:\n  resolved "x"\n',
    );
    expect(names(parsed)).toEqual(["good@1.0.0"]);
    expect(parsed.isComplete).toBe(false);
    expect(parsed.notes.join(" ")).toContain("without a readable name or version");
  });

  it("npm v1: counts dependencies from file, link, git and tarball sources in a note", () => {
    const parsed = parseNpmLock(
      JSON.stringify({
        lockfileVersion: 1,
        dependencies: {
          a: { version: "1.0.0" },
          b: { version: "file:../b" },
          c: { version: "git+https://example.com/c.git#abc" },
          d: { version: "github:user/d#abc" },
          e: { version: "https://example.com/e.tgz" },
          f: { version: "link:../f" },
        },
      }),
    );
    expect(names(parsed)).toEqual(["a@1.0.0"]);
    expect(parsed.notes.join(" ")).toContain("5 dependencies from file:, link:, git");
  });
});
