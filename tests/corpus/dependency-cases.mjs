// Dependency corpus: each case is a throwaway project (lockfiles) plus a small fixture OSV
// dataset the runner writes into a temporary "app data" folder. The real per-user store is never
// read. Time is fixed (NOW), so "stale" and "fresh" do not depend on the day the corpus runs.
//
// A case: { rule, kind: "positive"|"negative", name, expect: [rule ids], files: {path: content},
// data: { npm?: { advisories, options? }, Go?: ... }, area?: { "deps:npm": "completed" } (the
// coverage status the case must produce), confidence?: "low" (every finding must be at that
// confidence) }.
export const NOW = Date.parse("2026-10-29T00:00:00Z");
const FRESH = { fetchedAt: "2026-10-28T00:00:00Z", modifiedMax: "2026-10-27T00:00:00Z" };
const STALE = { fetchedAt: "2026-10-01T00:00:00Z", modifiedMax: "2026-09-30T00:00:00Z" };

const npmLock = (packages) =>
  JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { dependencies: { pkg: "*" } },
      ...Object.fromEntries(
        Object.entries(packages).map(([name, value]) => [`node_modules/${name}`, value]),
      ),
    },
  });
const adv = (id, name, events, extra = {}) => ({
  id,
  modified: "2026-10-20T00:00:00Z",
  affected: [{ name, ranges: [{ type: "SEMVER", events }] }],
  ...extra,
});
const upTo = (fixed) => [{ introduced: "0" }, { fixed }];
const goMod = (module, version) =>
  `module example.com/app\n\ngo 1.22\n\nrequire ${module} ${version}\n`;

export const DEPENDENCY_CASES = [
  {
    rule: "PG-DEP-001",
    kind: "positive",
    name: "npm-version-below-fix",
    expect: ["PG-DEP-001"],
    files: { "package-lock.json": npmLock({ pkg: { version: "1.2.2" } }) },
    data: { npm: { advisories: [adv("GHSA-aaaa-0001", "pkg", upTo("1.2.3"))], options: FRESH } },
    area: { "deps:npm": "completed" },
  },
  {
    rule: "PG-DEP-001",
    kind: "positive",
    name: "npm-introduced-edge-is-inclusive",
    expect: ["PG-DEP-001"],
    files: { "package-lock.json": npmLock({ pkg: { version: "2.0.0" } }) },
    data: {
      npm: {
        advisories: [adv("GHSA-aaaa-0002", "pkg", [{ introduced: "2.0.0" }, { fixed: "2.0.5" }])],
        options: FRESH,
      },
    },
  },
  {
    rule: "PG-DEP-001",
    kind: "positive",
    name: "npm-prerelease-below-the-fix",
    expect: ["PG-DEP-001"],
    files: { "package-lock.json": npmLock({ pkg: { version: "3.0.0-rc.1" } }) },
    data: { npm: { advisories: [adv("GHSA-aaaa-0003", "pkg", upTo("3.0.0"))], options: FRESH } },
  },
  {
    rule: "PG-DEP-001",
    kind: "positive",
    name: "npm-last-affected-is-inclusive",
    expect: ["PG-DEP-001"],
    files: { "package-lock.json": npmLock({ pkg: { version: "4.1.0" } }) },
    data: {
      npm: {
        advisories: [
          adv("GHSA-aaaa-0004", "pkg", [{ introduced: "0" }, { last_affected: "4.1.0" }]),
        ],
        options: FRESH,
      },
    },
  },
  {
    rule: "PG-DEP-001",
    kind: "positive",
    name: "npm-dev-only-is-reported-at-low-confidence",
    expect: ["PG-DEP-001"],
    confidence: "low",
    files: { "package-lock.json": npmLock({ pkg: { version: "1.0.0", dev: true } }) },
    data: { npm: { advisories: [adv("GHSA-aaaa-0005", "pkg", upTo("1.0.1"))], options: FRESH } },
  },
  {
    rule: "PG-DEP-001",
    kind: "positive",
    name: "yarn-lockfile",
    expect: ["PG-DEP-001"],
    files: { "yarn.lock": '# yarn lockfile v1\n\npkg@^1:\n  version "1.0.0"\n' },
    data: { npm: { advisories: [adv("GHSA-aaaa-0006", "pkg", upTo("1.0.1"))], options: FRESH } },
  },
  {
    rule: "PG-DEP-001",
    kind: "positive",
    name: "stale-data-still-reports-and-is-partial",
    expect: ["PG-DEP-001"],
    files: { "package-lock.json": npmLock({ pkg: { version: "1.0.0" } }) },
    data: { npm: { advisories: [adv("GHSA-aaaa-0007", "pkg", upTo("1.0.1"))], options: STALE } },
    area: { "deps:npm": "partial" },
  },
  {
    rule: "PG-DEP-001",
    kind: "positive",
    name: "go-module-below-fix",
    expect: ["PG-DEP-001"],
    files: { "go.mod": goMod("example.com/lib", "v1.4.0") },
    data: {
      Go: { advisories: [adv("GO-2026-0001", "example.com/lib", upTo("1.4.1"))], options: FRESH },
    },
    area: { "deps:Go": "completed" },
  },
  {
    rule: "PG-DEP-001",
    kind: "positive",
    name: "pnpm-lockfile",
    expect: ["PG-DEP-001"],
    files: {
      "pnpm-lock.yaml":
        "lockfileVersion: '9.0'\n\npackages:\n\n  pkg@1.0.0:\n    resolution: {integrity: sha512-x}\n\nsnapshots:\n\n  pkg@1.0.0: {}\n",
    },
    data: { npm: { advisories: [adv("GHSA-aaaa-0008", "pkg", upTo("1.0.1"))], options: FRESH } },
    area: { "deps:npm": "completed" },
  },
  {
    rule: "PG-DEP-001",
    kind: "positive",
    name: "go-pseudo-version-below-the-fix-with-introduced-0",
    expect: ["PG-DEP-001"],
    files: { "go.mod": goMod("golang.org/x/crypto", "v0.0.0-20200622213623-75b288015ac9") },
    data: {
      Go: {
        advisories: [
          adv("GO-2022-0229", "golang.org/x/crypto", upTo("0.0.0-20201216223049-8b5274cf687f")),
        ],
        options: FRESH,
      },
    },
    area: { "deps:Go": "completed" },
  },
  {
    rule: "PG-DEP-001",
    kind: "negative",
    name: "go-pseudo-version-at-the-fix",
    expect: [],
    files: { "go.mod": goMod("golang.org/x/crypto", "v0.0.0-20201216223049-8b5274cf687f") },
    data: {
      Go: {
        advisories: [
          adv("GO-2022-0229", "golang.org/x/crypto", upTo("0.0.0-20201216223049-8b5274cf687f")),
        ],
        options: FRESH,
      },
    },
  },
  {
    rule: "PG-DEP-001",
    kind: "positive",
    name: "go-incompatible-suffix-and-two-records-of-one-issue",
    expect: ["PG-DEP-001"],
    files: { "go.mod": goMod("example.com/old", "v2.1.0+incompatible") },
    data: {
      Go: {
        advisories: [
          adv("GO-2026-0002", "example.com/old", upTo("2.2.0"), { aliases: ["GHSA-gggg-0002"] }),
          adv("GHSA-gggg-0002", "example.com/old", upTo("2.2.0"), { aliases: ["GO-2026-0002"] }),
        ],
        options: FRESH,
      },
    },
  },
  {
    rule: "PG-DEP-001",
    kind: "negative",
    name: "npm-fixed-version-edge-is-not-affected",
    expect: [],
    files: { "package-lock.json": npmLock({ pkg: { version: "1.2.3" } }) },
    data: { npm: { advisories: [adv("GHSA-bbbb-0001", "pkg", upTo("1.2.3"))], options: FRESH } },
    area: { "deps:npm": "completed" },
  },
  {
    rule: "PG-DEP-001",
    kind: "negative",
    name: "npm-below-introduced",
    expect: [],
    files: { "package-lock.json": npmLock({ pkg: { version: "1.9.9" } }) },
    data: {
      npm: {
        advisories: [adv("GHSA-bbbb-0002", "pkg", [{ introduced: "2.0.0" }, { fixed: "2.1.0" }])],
        options: FRESH,
      },
    },
  },
  {
    rule: "PG-DEP-001",
    kind: "negative",
    name: "npm-prerelease-below-introduced",
    expect: [],
    files: { "package-lock.json": npmLock({ pkg: { version: "2.0.0-beta.1" } }) },
    data: {
      npm: {
        advisories: [adv("GHSA-bbbb-0003", "pkg", [{ introduced: "2.0.0" }, { fixed: "2.1.0" }])],
        options: FRESH,
      },
    },
  },
  {
    rule: "PG-DEP-001",
    kind: "negative",
    name: "withdrawn-advisory-is-skipped",
    expect: [],
    files: { "package-lock.json": npmLock({ pkg: { version: "1.0.0" } }) },
    data: {
      npm: {
        advisories: [
          adv("GHSA-bbbb-0004", "pkg", [{ introduced: "0" }], {
            withdrawn: "2026-10-10T00:00:00Z",
          }),
        ],
        options: FRESH,
      },
    },
    area: { "deps:npm": "completed" },
  },
  {
    rule: "PG-DEP-001",
    kind: "negative",
    name: "missing-data-is-not-tested-not-clean",
    expect: [],
    files: { "package-lock.json": npmLock({ pkg: { version: "1.0.0" } }) },
    data: {},
    area: { "deps:npm": "not_tested" },
  },
  {
    rule: "PG-DEP-001",
    kind: "negative",
    name: "unknown-version-scheme-is-not-tested-for-that-package",
    expect: [],
    files: { "package-lock.json": npmLock({ pkg: { version: "1.0" } }) },
    data: {
      npm: { advisories: [adv("GHSA-bbbb-0005", "pkg", [{ introduced: "0" }])], options: FRESH },
    },
    area: { "deps:npm": "partial" },
  },
  {
    rule: "PG-DEP-001",
    kind: "negative",
    name: "malformed-lockfile-makes-the-area-partial",
    expect: [],
    files: { "package-lock.json": "{ not json" },
    data: {
      npm: { advisories: [adv("GHSA-bbbb-0006", "pkg", [{ introduced: "0" }])], options: FRESH },
    },
    area: { "deps:npm": "partial" },
  },
  {
    rule: "PG-DEP-001",
    kind: "negative",
    name: "go-fixed-version-edge",
    expect: [],
    files: { "go.mod": goMod("example.com/lib", "v1.4.1") },
    data: {
      Go: { advisories: [adv("GO-2026-0003", "example.com/lib", upTo("1.4.1"))], options: FRESH },
    },
  },
  {
    rule: "PG-DEP-001",
    kind: "negative",
    name: "other-package-name",
    expect: [],
    files: { "package-lock.json": npmLock({ pkg: { version: "1.0.0" } }) },
    data: {
      npm: {
        advisories: [adv("GHSA-bbbb-0007", "pkg-other", [{ introduced: "0" }])],
        options: FRESH,
      },
    },
  },
];
