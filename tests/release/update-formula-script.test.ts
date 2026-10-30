import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  EXPECTED_REPOSITORY,
  EXPECTED_WORKFLOW,
} from "../../packaging/homebrew/verify-provenance.mjs";

// Runs packaging/homebrew/update-formula.sh against stubbed npm, curl and gh (nothing touches the
// network). The stubbed registry serves a FORGED attestation: its claims match the tarball but
// its signature is "AAAA". Only a signature check or the release run's sha256 may accept it.
const script = path.resolve(import.meta.dirname, "../../packaging/homebrew/update-formula.sh");
const version = "0.2.0";
const tarball = Buffer.from("pretend this is pgard-0.2.0.tgz");
const sha256 = createHash("sha256").update(tarball).digest("hex");
const sha512 = createHash("sha512").update(tarball).digest("hex");
const integrity = `sha512-${createHash("sha512").update(tarball).digest("base64")}`;

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function which(tool: string): string {
  return execFileSync("sh", ["-c", `command -v ${tool}`], { encoding: "utf8" }).trim();
}

function forgedAttestations() {
  const statement = {
    subject: [{ name: `pkg:npm/pgard@${version}`, digest: { sha512 } }],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        externalParameters: {
          workflow: {
            repository: EXPECTED_REPOSITORY,
            path: EXPECTED_WORKFLOW,
            ref: `refs/tags/v${version}`,
          },
        },
      },
    },
  };
  return {
    attestations: [
      {
        predicateType: "https://slsa.dev/provenance/v1",
        bundle: {
          dsseEnvelope: {
            payload: Buffer.from(JSON.stringify(statement)).toString("base64"),
            signatures: [{ sig: "AAAA" }],
          },
        },
      },
    ],
  };
}

function setup(ghExit: number | null) {
  const root = mkdtempSync(path.join(tmpdir(), "pgard formula test "));
  dirs.push(root);
  const bin = path.join(root, "bin");
  mkdirSync(bin);
  const files = path.join(root, "files");
  mkdirSync(files);
  writeFileSync(path.join(files, "pgard.tgz"), tarball);
  writeFileSync(path.join(files, "attestations.json"), JSON.stringify(forgedAttestations()));
  const stub = (name: string, body: string) => {
    const file = path.join(bin, name);
    writeFileSync(file, `#!${process.execPath}\n${body}\n`);
    chmodSync(file, 0o755);
  };
  stub(
    "npm",
    `const a = process.argv.slice(2);
if (a.includes("dist.integrity")) console.log(${JSON.stringify(integrity)});
else if (a.includes("dist.attestations.url")) console.log("https://registry.npmjs.org/-/npm/v1/attestations/pgard@${version}");
else process.exit(1);`,
  );
  stub(
    "curl",
    `const fs = require("node:fs");
const a = process.argv.slice(2);
const url = a.find((x) => x.startsWith("https://"));
const out = a[a.indexOf("-o") + 1];
fs.copyFileSync(${JSON.stringify(files)} + (url.endsWith(".tgz") ? "/pgard.tgz" : "/attestations.json"), out);`,
  );
  symlinkSync(process.execPath, path.join(bin, "node"));
  for (const tool of ["shasum", "openssl", "tr", "cut", "mktemp", "rm", "sed", "dirname"]) {
    symlinkSync(which(tool), path.join(bin, tool));
  }
  const ghLog = path.join(root, "gh-args.txt");
  if (ghExit !== null) {
    stub(
      "gh",
      `require("node:fs").writeFileSync(${JSON.stringify(ghLog)}, process.argv.slice(2).join(" "));
process.exit(${ghExit});`,
    );
  }
  const formula = path.join(root, "pgard.rb");
  writeFileSync(
    formula,
    `class Pgard < Formula\n  url "https://example.invalid/x.tgz"\n  sha256 "${"0".repeat(64)}"\nend\n`,
  );
  const run = (env: Record<string, string> = {}) =>
    spawnSync(which("bash"), [script, version, formula], {
      encoding: "utf8",
      env: { PATH: bin, ...env },
    });
  return { run, formula, ghLog };
}

describe.skipIf(process.platform === "win32")("update-formula.sh provenance (L3 of #358)", () => {
  it("refuses a forged attestation when gh did not run and no EXPECTED_SHA256 is given", () => {
    const { run, formula } = setup(null);
    const result = run();
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("nothing independent of the registry verified");
    expect(readFileSync(formula, "utf8")).toContain("0".repeat(64));
  });

  it("does not say verified for the claim-only step", () => {
    const { run } = setup(null);
    const result = run();
    expect(result.stdout).toContain("consistency check");
    expect(result.stdout).not.toMatch(/\bverified\b/i);
  });

  it("accepts the release run's sha256 as an independent root", () => {
    const { run, formula } = setup(null);
    const result = run({ EXPECTED_SHA256: sha256 });
    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(formula, "utf8")).toContain(sha256);
  });

  it("refuses a sha256 that differs from the release run's", () => {
    const { run, formula } = setup(null);
    const result = run({ EXPECTED_SHA256: "1".repeat(64) });
    expect(result.status).toBe(1);
    expect(readFileSync(formula, "utf8")).not.toContain(sha256);
  });

  it("the explicit override writes the formula with a loud warning", () => {
    const { run, formula } = setup(null);
    const result = run({ PGARD_I_ACCEPT_UNVERIFIED_PROVENANCE: "1" });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toContain("WARNING");
    expect(readFileSync(formula, "utf8")).toContain(sha256);
    // The old skip switch is gone and no longer lets a forged statement through.
    const old = setup(null).run({ PGARD_SKIP_GH_ATTESTATION: "1" });
    expect(old.status).toBe(1);
  });

  it("a failing gh attestation verify stops the update", () => {
    const { run, formula } = setup(1);
    const result = run({ EXPECTED_SHA256: sha256 });
    expect(result.status).not.toBe(0);
    expect(readFileSync(formula, "utf8")).not.toContain(sha256);
  });

  it("a passing gh attestation verify is enough, and pins the ref and hosted runners", () => {
    const { run, formula, ghLog } = setup(0);
    const result = run();
    expect(result.status, result.stderr).toBe(0);
    const args = readFileSync(ghLog, "utf8");
    expect(args).toContain(`--source-ref refs/tags/v${version}`);
    expect(args).toContain("--deny-self-hosted-runners");
    expect(args).toContain("--digest-alg sha512");
    expect(args).toContain("--signer-workflow JadenMeister/pgard/.github/workflows/release.yml");
    expect(readFileSync(formula, "utf8")).toContain(sha256);
  });
});
