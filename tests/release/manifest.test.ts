import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");

// The manifest of the packed tarball is checked against the same fields by
// `npm run smoke:pack` (on the tarball of the current pack run) and by `pack:pgard`.
describe("published package manifest", () => {
  const manifest = JSON.parse(readFileSync(join(root, "packaging/pgard/package.json"), "utf8")) as {
    [key: string]: unknown;
    version?: string;
    repository?: { url?: string };
    bugs?: { url?: string };
    files?: string[];
  };

  it("has the publishing metadata and is not private", () => {
    expect(manifest.name).toBe("pgard");
    expect(manifest.private).not.toBe(true);
    expect(manifest.license).toBe("MIT");
    expect(manifest.repository?.url).toBe("git+https://github.com/JadenMeister/pgard.git");
    expect(manifest.homepage).toMatch(/^https:\/\/github\.com\/JadenMeister\/pgard/);
    expect(manifest.bugs?.url).toMatch(/^https:\/\/github\.com\/JadenMeister\/pgard\/issues/);
    expect(manifest.engines).toHaveProperty("node");
    expect(manifest.files?.length).toBeGreaterThan(0);
    expect(manifest.bin).toEqual({ pgard: "./dist/pgard.js" });
    expect(manifest.publishConfig).toEqual({ access: "public", provenance: true });
    expect(manifest.scripts).toBeUndefined();
  });

  it("has the version the code reports", () => {
    const source = readFileSync(join(root, "packages/scan-core/src/version.ts"), "utf8");
    expect(manifest.version).toBe(/PGARD_VERSION = "([^"]+)"/.exec(source)?.[1]);
  });
});

describe("release workflow", () => {
  const workflow = readFileSync(join(root, ".github/workflows/release.yml"), "utf8");

  it("uploads only from a visible path (upload-artifact skips hidden directories)", () => {
    const paths = [...workflow.matchAll(/^\s+path:\s*(\S+)/gm)].map((m) => m[1] ?? "");
    const uploads = paths.filter((p) => p.includes("*"));
    expect(uploads.length).toBeGreaterThan(0);
    for (const p of uploads) {
      expect(p.split("/").some((segment) => segment.startsWith("."))).toBe(false);
    }
  });

  it("runs only on tags and manual dispatch, and pins every action to a SHA", () => {
    expect(workflow).toMatch(/^on:\n {2}workflow_dispatch:[\s\S]*\n {2}push:\n {4}tags:/m);
    expect(workflow).not.toMatch(/pull_request/);
    expect(workflow).toMatch(/^permissions: \{\}$/m);
    for (const m of workflow.matchAll(/uses:\s*(\S+)/g)) {
      expect(m[1]).toMatch(/@[0-9a-f]{40}$/);
    }
  });
});
