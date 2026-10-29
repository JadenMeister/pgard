import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCodeOnlyScan } from "./index.js";
import { scanWorkingTreeSecrets, WORKING_TREE_SECRETS_AREA } from "./working-tree-secrets.js";

// The AWS documentation key with its last letter changed (EXAMPLE itself reads as a placeholder).
const FAKE_KEY = `${"AKIA"}IOSFODNN7EXAMPLQ`;

let dir: string | null = null;
afterEach(async () => {
  if (dir !== null) await rm(dir, { recursive: true, force: true });
  dir = null;
});

async function project(files: Record<string, string>): Promise<string> {
  dir = await mkdtemp(path.join(os.tmpdir(), "pgard-codeonly-"));
  for (const [name, content] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(dir, name)), { recursive: true });
    await writeFile(path.join(dir, name), content);
  }
  return dir;
}

describe("scanWorkingTreeSecrets (prototype, #414)", () => {
  it("finds a secret and a .env file on disk, never puts the value in a finding", async () => {
    const root = await project({
      "src/config.js": `export const aws = { accessKeyId: "${FAKE_KEY}" };\n`,
      ".env": "TOKEN=x\n",
      "node_modules/pkg/index.js": `const k = "${FAKE_KEY}";\n`,
    });
    const output = await scanWorkingTreeSecrets({ projectRoot: root, projectConfig: null });
    const rules = output.findings.map((finding) => `${finding.ruleId} ${finding.location.path}`);
    expect(rules).toContain("PG-SECRET-001 .env");
    expect(rules.some((entry) => entry.startsWith("PG-SECRET-002 src/config.js"))).toBe(true);
    expect(rules.some((entry) => entry.includes("node_modules"))).toBe(false);
    expect(JSON.stringify(output)).not.toContain(FAKE_KEY);
    expect(output.coverage[0]).toMatchObject({
      area: WORKING_TREE_SECRETS_AREA,
      scope: "code",
      status: "completed",
    });
  });

  it("never follows a symbolic link", async () => {
    const root = await project({ "real/secret.txt": `key=${FAKE_KEY}\n`, "app/a.js": "" });
    const outside = await mkdtemp(path.join(os.tmpdir(), "pgard-outside-"));
    try {
      await writeFile(path.join(outside, "s.js"), `const k = "${FAKE_KEY}";\n`);
      await symlink(outside, path.join(root, "app", "linked"));
      await symlink(path.join(outside, "s.js"), path.join(root, "app", "file-link.js"));
      const output = await scanWorkingTreeSecrets({ projectRoot: root, projectConfig: null });
      const paths = output.findings.map((finding) => finding.location.path);
      expect(paths.some((entry) => entry?.startsWith("app/"))).toBe(false);
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });
});

describe("runCodeOnlyScan on a real folder without Git (prototype, #414)", () => {
  it("scans a folder that is not a Git repository and labels the result", async () => {
    const root = await project({
      "src/config.js": `export const aws = { accessKeyId: "${FAKE_KEY}" };\n`,
    });
    const result = await runCodeOnlyScan({ projectRoot: root }, { advisoryDataDir: null });
    expect(result.authorization.decision).toBe("blocked");
    expect(result.findings.some((finding) => finding.ruleId === "PG-SECRET-002")).toBe(true);
    expect(result.coverage.some((entry) => entry.area === WORKING_TREE_SECRETS_AREA)).toBe(true);
    expect(JSON.stringify(result)).not.toContain(root);
    expect(JSON.stringify(result)).not.toContain(FAKE_KEY);
  });
});
