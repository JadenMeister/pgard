import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");
const manifestPath = join(root, "packaging/pgard/package.json");
const packDir = join(root, ".pack");

type Manifest = Record<string, unknown> & {
  name?: string;
  version?: string;
  repository?: { type?: string; url?: string };
  bin?: Record<string, string>;
  publishConfig?: { access?: string; provenance?: boolean };
  files?: string[];
};

function expectPublishable(manifest: Manifest): void {
  expect(manifest.name).toBe("pgard");
  expect(manifest.private).not.toBe(true);
  expect(manifest.license).toBe("MIT");
  expect(manifest.repository?.url).toBe("git+https://github.com/JadenMeister/pgard.git");
  expect(manifest.homepage).toMatch(/^https:\/\/github\.com\/JadenMeister\/pgard/);
  expect((manifest.bugs as { url?: string } | undefined)?.url).toMatch(
    /^https:\/\/github\.com\/JadenMeister\/pgard\/issues/,
  );
  expect(manifest.engines).toHaveProperty("node");
  expect(manifest.files?.length).toBeGreaterThan(0);
  expect(manifest.bin).toEqual({ pgard: "./dist/pgard.js" });
  expect(manifest.publishConfig).toEqual({ access: "public", provenance: true });
  expect(manifest.scripts).toBeUndefined();
}

describe("published package manifest", () => {
  it("packaging/pgard/package.json has the publishing metadata and is not private", () => {
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Manifest;
    expectPublishable(manifest);
    const versionSource = readFileSync(join(root, "packages/scan-core/src/version.ts"), "utf8");
    expect(manifest.version).toBe(/PGARD_VERSION = "([^"]+)"/.exec(versionSource)?.[1]);
  });

  const tarball = existsSync(packDir)
    ? readdirSync(packDir).find((name) => /^pgard-.*\.tgz$/.test(name))
    : undefined;
  it.skipIf(tarball === undefined)("the packed tarball carries the same manifest", () => {
    const out = spawnSync("tar", ["-xOzf", join(packDir, tarball ?? ""), "package/package.json"], {
      encoding: "utf8",
    });
    expect(out.status).toBe(0);
    expectPublishable(JSON.parse(out.stdout) as Manifest);
  });
});
