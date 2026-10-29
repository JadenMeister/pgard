import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Finding } from "@pgard/findings";
import { afterEach, describe, expect, it } from "vitest";
import { attachFixSuggestions } from "./attach-fixes.js";

let root: string | null = null;
afterEach(() => {
  if (root !== null) rmSync(root, { recursive: true, force: true });
  root = null;
});

const COOKIE = 'res.cookie("sid", token);\n';

const finding = (
  ruleId: string,
  filePath: string | null,
  line: number | null,
  kind: "file" | "url" = "file",
): Finding => ({
  id: `${ruleId}:${filePath}:${line}`,
  ruleId,
  title: "t",
  category: "misconfiguration",
  severity: "medium",
  status: "suspected",
  confidence: "medium",
  location: { kind, path: filePath, line, url: null, commit: null },
  evidence: "res.cookie(session-like name) without httpOnly, secure, sameSite",
  impact: "i",
  recommendation: "r",
  references: { cwe: [], owasp: [], cve: [] },
  sources: ["code"],
});

function project(): string {
  root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-attach-")));
  writeFileSync(path.join(root, "a.js"), COOKIE);
  return root;
}

describe("attachFixSuggestions", () => {
  it("adds a diff to a fixable finding and leaves others and the input untouched", async () => {
    const dir = project();
    const input = [finding("PG-COOKIE-001", "a.js", 1), finding("PG-SQL-001", "a.js", 1)];
    const output = await attachFixSuggestions(input, dir);
    expect(output[0]?.fix?.kind).toBe("diff");
    expect(output[1]).toBe(input[1]);
    expect(input[0]?.fix).toBeUndefined();
  });

  it("gives guidance when the file is missing, a symbolic link or outside the project", async () => {
    const dir = project();
    mkdirSync(path.join(dir, "real"));
    writeFileSync(path.join(dir, "real", "b.js"), COOKIE);
    symlinkSync(path.join(dir, "real"), path.join(dir, "linked"));
    symlinkSync(path.join(dir, "a.js"), path.join(dir, "c.js"));
    const outside = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-outside-")));
    writeFileSync(path.join(outside, "x.js"), COOKIE);
    try {
      for (const filePath of ["missing.js", "linked/b.js", "c.js", "../x.js", "/etc/passwd", ""]) {
        const [output] = await attachFixSuggestions([finding("PG-COOKIE-001", filePath, 1)], dir);
        expect(output?.fix, filePath).toEqual({
          kind: "guidance",
          confidence: "low",
          reason: "source_unavailable",
        });
      }
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("gives guidance when the file changed since the scan", async () => {
    const dir = project();
    writeFileSync(path.join(dir, "a.js"), "// moved\n" + COOKIE);
    const [output] = await attachFixSuggestions([finding("PG-COOKIE-001", "a.js", 1)], dir);
    expect(output?.fix).toMatchObject({ kind: "guidance", reason: "context_not_supported" });
  });

  it("skips findings without a file location", async () => {
    const dir = project();
    const input = [
      finding("PG-COOKIE-001", null, null),
      finding("PG-COOKIE-001", "a.js", 1, "url"),
    ];
    const output = await attachFixSuggestions(input, dir);
    expect(output[0]).toBe(input[0]);
    expect(output[1]).toBe(input[1]);
  });

  it("does not read a file over the size limit", async () => {
    const dir = project();
    writeFileSync(path.join(dir, "big.js"), `${COOKIE}${"x".repeat(1024 * 1024)}`);
    const [output] = await attachFixSuggestions([finding("PG-COOKIE-001", "big.js", 1)], dir);
    expect(output?.fix).toMatchObject({ kind: "guidance", reason: "source_unavailable" });
  });

  it("is deterministic", async () => {
    const dir = project();
    const input = [finding("PG-COOKIE-001", "a.js", 1)];
    expect(JSON.stringify(await attachFixSuggestions(input, dir))).toBe(
      JSON.stringify(await attachFixSuggestions(input, dir)),
    );
  });

  it("limits the number of files read", async () => {
    const dir = project();
    const input: Finding[] = [];
    for (let index = 0; index < 205; index += 1) {
      writeFileSync(path.join(dir, `f${index}.js`), COOKIE);
      input.push(finding("PG-COOKIE-001", `f${index}.js`, 1));
    }
    const output = await attachFixSuggestions(input, dir);
    expect(output.filter((entry) => entry.fix?.kind === "diff")).toHaveLength(200);
    expect(output[204]?.fix).toMatchObject({ kind: "guidance", reason: "too_many" });
  });
});
