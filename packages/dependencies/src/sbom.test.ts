import { readFileSync } from "node:fs";
import { Ajv } from "ajv";
import { describe, expect, it } from "vitest";
import {
  buildCycloneDxSbom,
  purlFor,
  ROOT_REF,
  type BuildSbomOptions,
  type CycloneDxBom,
  type SbomDependency,
} from "./sbom.js";
import type { DependencyCoverage } from "./types.js";

const fixture = (name: string): Record<string, unknown> =>
  JSON.parse(
    readFileSync(new URL(`../test-fixtures/cyclonedx/${name}`, import.meta.url), "utf8"),
  ) as Record<string, unknown>;

/**
 * The official CycloneDX 1.6 JSON schema (vendored, Apache-2.0, see the fixture folder). `format`
 * checks are off because Ajv's format set needs another package; the two formats that matter
 * (the `urn:uuid` serial number and the timestamp) are checked below.
 */
function validator() {
  const ajv = new Ajv({ strict: false, validateFormats: false, allErrors: true });
  ajv.addSchema(fixture("spdx.schema.json"));
  ajv.addSchema(fixture("jsf-0.82.schema.json"));
  return ajv.compile(fixture("bom-1.6.schema.json"));
}

const OPTIONS: BuildSbomOptions = {
  serialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  timestamp: "2026-10-28T09:00:00.000Z",
  toolVersion: "0.1.0",
  repository: "owner/name",
  revision: "0123456789abcdef0123456789abcdef01234567",
};

const dep = (
  overrides: Partial<SbomDependency> & Pick<SbomDependency, "name">,
): SbomDependency => ({
  ecosystem: "npm",
  version: "1.0.0",
  path: "package-lock.json",
  ...overrides,
});

const line = (overrides: Partial<DependencyCoverage>): DependencyCoverage => ({
  path: "package-lock.json",
  kind: "npm",
  status: "parsed",
  dependencyCount: 1,
  note: null,
  ...overrides,
});

function build(
  dependencies: SbomDependency[],
  coverage: DependencyCoverage[] = [],
  isTruncated = false,
): CycloneDxBom {
  return buildCycloneDxSbom({ dependencies, coverage, isTruncated }, OPTIONS);
}

const unparsedValues = (bom: CycloneDxBom): string[] =>
  bom.metadata.properties
    .filter((property) => property.name === "pgard:unparsed-lockfile")
    .map((property) => property.value);

describe("purlFor", () => {
  it("npm: plain, scoped (the @ is encoded) and odd versions", () => {
    expect(purlFor("npm", "left-pad", "1.3.0")).toBe("pkg:npm/left-pad@1.3.0");
    expect(purlFor("npm", "@angular/core", "17.0.1")).toBe("pkg:npm/%40angular/core@17.0.1");
    expect(purlFor("npm", "@types/node", "26.6.5-beta.1+build.7")).toBe(
      "pkg:npm/%40types/node@26.6.5-beta.1%2Bbuild.7",
    );
    expect(purlFor("npm", "@scope", "1.0.0")).toBeNull();
    expect(purlFor("npm", "@/x", "1.0.0")).toBeNull();
    expect(purlFor("npm", "x", "")).toBeNull();
  });

  it("Go: keeps the case of the module path, encodes + and keeps the v", () => {
    expect(purlFor("Go", "golang.org/x/text", "v0.14.0")).toBe(
      "pkg:golang/golang.org/x/text@v0.14.0",
    );
    expect(purlFor("Go", "github.com/Azure/azure-sdk-for-go", "v68.0.0+incompatible")).toBe(
      "pkg:golang/github.com/Azure/azure-sdk-for-go@v68.0.0%2Bincompatible",
    );
    expect(purlFor("Go", "github.com/BurntSushi/toml", "v1.3.2")).toBe(
      "pkg:golang/github.com/BurntSushi/toml@v1.3.2",
    );
    // Two paths that differ only by case are two modules and stay two purls.
    expect(purlFor("Go", "github.com/a/B", "v1.0.0")).not.toBe(
      purlFor("Go", "github.com/a/b", "v1.0.0"),
    );
    expect(purlFor("Go", "example.com//x", "v1.0.0")).toBeNull();
  });

  it("Maven: group:artifact becomes group/artifact", () => {
    expect(purlFor("Maven", "org.apache.logging.log4j:log4j-core", "2.17.1")).toBe(
      "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
    );
    expect(purlFor("Maven", "log4j-core", "2.17.1")).toBeNull();
    expect(purlFor("Maven", "a:b:c", "1")).toBeNull();
  });

  it("PyPI and Composer: normalised to lowercase", () => {
    expect(purlFor("PyPI", "Django_Rest.Framework", "3.14.0")).toBe(
      "pkg:pypi/django-rest-framework@3.14.0",
    );
    expect(purlFor("Packagist", "Symfony/Console", "v6.4.0")).toBe(
      "pkg:composer/symfony/console@v6.4.0",
    );
    expect(purlFor("Packagist", "console", "1.0.0")).toBeNull();
  });
});

describe("buildCycloneDxSbom", () => {
  const sample = (): CycloneDxBom =>
    build(
      [
        dep({ name: "zeta", direct: false }),
        dep({ name: "@scope/pkg", version: "2.0.0", direct: true }),
        dep({ name: "alpha", direct: true }),
        dep({
          ecosystem: "Go",
          name: "github.com/Azure/azure-sdk-for-go",
          version: "v68.0.0+incompatible",
          path: "svc/go.mod",
          direct: false,
        }),
        // The same package in a second lockfile is one component with two lockfile properties.
        dep({ name: "alpha", path: "web/package-lock.json", direct: false }),
      ],
      [line({}), line({ path: "svc/go.mod", kind: "go.mod" })],
    );

  it("has the required top level, tool and repository component", () => {
    const bom = sample();
    expect(bom.bomFormat).toBe("CycloneDX");
    expect(bom.specVersion).toBe("1.6");
    expect(bom.serialNumber).toMatch(/^urn:uuid:[0-9a-f-]{36}$/);
    expect(bom.metadata.timestamp).toBe("2026-10-28T09:00:00.000Z");
    expect(bom.metadata.tools.components).toEqual([
      { type: "application", name: "pgard", version: "0.1.0" },
    ]);
    expect(bom.metadata.component).toEqual({
      type: "application",
      "bom-ref": ROOT_REF,
      name: "owner/name",
      version: OPTIONS.revision,
    });
  });

  it("validates against the official CycloneDX 1.6 JSON schema", () => {
    const validate = validator();
    for (const bom of [
      sample(),
      build([]),
      build(
        [dep({ name: "x" })],
        [line({ path: "yarn.lock", kind: "yarn", status: "failed" })],
        true,
      ),
    ]) {
      const valid = validate(JSON.parse(JSON.stringify(bom)));
      expect(validate.errors ?? []).toEqual([]);
      expect(valid).toBe(true);
    }
  });

  it("the schema check is not vacuous: it rejects a broken document", () => {
    const validate = validator();
    const broken = { ...JSON.parse(JSON.stringify(sample())), specVersion: 7 };
    expect(validate(broken)).toBe(false);
    const extra = { ...JSON.parse(JSON.stringify(sample())), surprise: true };
    expect(validate(extra)).toBe(false);
  });

  it("gives every component a unique bom-ref, the purl, group and name", () => {
    const bom = sample();
    const refs = bom.components.map((component) => component["bom-ref"]);
    expect(new Set(refs).size).toBe(refs.length);
    const scoped = bom.components.find((component) => component.name === "pkg");
    expect(scoped).toMatchObject({
      type: "library",
      group: "@scope",
      version: "2.0.0",
      purl: "pkg:npm/%40scope/pkg@2.0.0",
      "bom-ref": "pkg:npm/%40scope/pkg@2.0.0",
    });
    const go = bom.components.find((component) => component.name.includes("azure"));
    expect(go?.purl).toBe("pkg:golang/github.com/Azure/azure-sdk-for-go@v68.0.0%2Bincompatible");
    expect(go?.properties).toContainEqual({ name: "pgard:ecosystem", value: "Go" });
  });

  it("merges the same package from two lockfiles and keeps both paths", () => {
    const alpha = sample().components.filter((component) => component.name === "alpha");
    expect(alpha).toHaveLength(1);
    expect(alpha[0]?.properties).toEqual([
      { name: "pgard:ecosystem", value: "npm" },
      { name: "pgard:lockfile", value: "package-lock.json" },
      { name: "pgard:lockfile", value: "web/package-lock.json" },
      { name: "pgard:direct", value: "true" },
    ]);
  });

  it("links only the direct dependencies from the repository, and says so", () => {
    const bom = sample();
    expect(bom.dependencies).toEqual([
      {
        ref: ROOT_REF,
        dependsOn: ["pkg:npm/%40scope/pkg@2.0.0", "pkg:npm/alpha@1.0.0"],
      },
    ]);
    expect(bom.metadata.properties).toContainEqual({
      name: "pgard:dependency-graph",
      value: "direct-only",
    });
    // Every dependsOn target is a component, so the graph has no dangling edge.
    const refs = new Set(bom.components.map((component) => component["bom-ref"]));
    for (const ref of bom.dependencies[0]?.dependsOn ?? []) expect(refs.has(ref)).toBe(true);
  });

  it("sorts the components and is byte-for-byte deterministic whatever the input order", () => {
    const input = [
      dep({ name: "b" }),
      dep({ name: "a" }),
      dep({ name: "@x/c" }),
      dep({ ecosystem: "Go", name: "example.com/m", version: "v1.0.0", path: "go.mod" }),
    ];
    const coverage = [
      line({ path: "z.lock", kind: "unsupported", status: "unsupported" }),
      line({ path: "a/yarn.lock", kind: "yarn", status: "failed" }),
    ];
    const first = build(input, coverage);
    const second = build([...input].reverse(), [...coverage].reverse());
    expect(JSON.stringify(second)).toBe(JSON.stringify(first));
    const refs = first.components.map((component) => component["bom-ref"]);
    expect(refs).toEqual([...refs].sort());
    expect(unparsedValues(first)).toEqual(["a/yarn.lock (failed)", "z.lock (unsupported)"]);
  });

  it("lists lockfiles that were not understood, and marks the SBOM incomplete", () => {
    const bom = build(
      [dep({ name: "x" })],
      [
        line({}),
        line({ path: "a/package-lock.json", status: "partial" }),
        line({ path: "composer.lock", kind: "unsupported", status: "unsupported" }),
        line({ path: "big/yarn.lock", kind: "yarn", status: "too-large" }),
        line({ path: "late/yarn.lock", kind: "yarn", status: "not-read" }),
        line({ path: "web/package.json", kind: "package.json", status: "missing-lockfile" }),
        line({ path: "bad/pnpm-lock.yaml", kind: "pnpm", status: "failed" }),
      ],
    );
    expect(unparsedValues(bom)).toEqual([
      "a/package-lock.json (partial)",
      "bad/pnpm-lock.yaml (failed)",
      "big/yarn.lock (too-large)",
      "composer.lock (unsupported)",
      "late/yarn.lock (not-read)",
      "web/package.json (missing-lockfile)",
    ]);
    expect(bom.metadata.properties).toContainEqual({ name: "pgard:complete", value: "false" });
    expect(bom.compositions).toEqual([{ aggregate: "incomplete", assemblies: [ROOT_REF] }]);
  });

  it("a fully parsed repository has no unparsed property and no incomplete composition", () => {
    const bom = build([dep({ name: "x" })], [line({})]);
    expect(unparsedValues(bom)).toEqual([]);
    expect(bom.metadata.properties).toContainEqual({ name: "pgard:complete", value: "true" });
    expect(bom.compositions).toBeUndefined();
  });

  it("a truncated search is marked incomplete even when every file parsed", () => {
    const bom = build([dep({ name: "x" })], [line({})], true);
    expect(bom.metadata.properties).toContainEqual({ name: "pgard:truncated", value: "true" });
    expect(bom.metadata.properties).toContainEqual({ name: "pgard:complete", value: "false" });
    expect(bom.compositions).toHaveLength(1);
  });

  it("refuses dot segments in a purl and falls back to the pgard ref", () => {
    expect(purlFor("Go", "github.com/a/../../etc", "v1.0.0")).toBeNull();
    expect(purlFor("Go", "./x", "v1.0.0")).toBeNull();
    expect(purlFor("npm", "@s/..", "1.0.0")).toBeNull();
    expect(purlFor("npm", "..", "1.0.0")).toBeNull();
    expect(purlFor("PyPI", "Foo.Bar-_baz", "1")).toBe("pkg:pypi/foo-bar-baz@1");
    const bom = build([
      dep({ ecosystem: "Go", name: "github.com/a/../../etc", version: "v1.0.0", path: "go.mod" }),
      dep({ name: "@s/..", version: "1.0.0" }),
    ]);
    expect(bom.components.map((component) => component.purl)).toEqual([undefined, undefined]);
    expect(bom.components.map((component) => component["bom-ref"])).toEqual([
      "pgard:Go:github.com/a/../../etc@v1.0.0",
      "pgard:npm:@s/..@1.0.0",
    ]);
  });

  it("keeps a package whose name does not fit its ecosystem, without a purl", () => {
    const bom = build([dep({ ecosystem: "Maven", name: "no-colon", version: "1" })]);
    expect(bom.components[0]?.purl).toBeUndefined();
    expect(bom.components[0]?.["bom-ref"]).toBe("pgard:Maven:no-colon@1");
    expect(validator()(JSON.parse(JSON.stringify(bom)))).toBe(true);
  });

  it("masks secrets and drops absolute paths in names, versions and paths", () => {
    const secret = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
    const bom = build(
      [
        dep({
          name: "pkg",
          version: `git+https://user:${secret}@host/x.git`,
          path: `dir/${secret}/yarn.lock`,
        }),
      ],
      [line({ path: `/Users/someone/${secret}/pnpm-lock.yaml`, status: "failed" })],
    );
    const text = JSON.stringify(bom);
    expect(text).not.toContain(secret);
    expect(text).not.toContain("/Users/someone");
    expect(unparsedValues(bom)).toEqual(["~/[REDACTED:github_token]/pnpm-lock.yaml (failed)"]);
  });

  it("marks control and bidi characters in a path as visible text", () => {
    const bom = build([dep({ name: "x", path: "evil‮file\u001b[31m/package-lock.json" })]);
    const text = JSON.stringify(bom);
    expect(text).not.toContain("‮");
    expect(text).not.toContain("\u001b");
    expect(text).toContain("\\\\u202e");
  });

  it("leaves ordinary names and paths untouched", () => {
    const bom = build([
      dep({ name: "@babel/core", version: "7.24.0" }),
      dep({ ecosystem: "Go", name: "golang.org/x/text", version: "v0.14.0", path: "a/b/go.mod" }),
    ]);
    expect(bom.components.map((component) => component.purl)).toEqual([
      "pkg:golang/golang.org/x/text@v0.14.0",
      "pkg:npm/%40babel/core@7.24.0",
    ]);
    expect(JSON.stringify(bom)).toContain('"a/b/go.mod"');
  });
});
