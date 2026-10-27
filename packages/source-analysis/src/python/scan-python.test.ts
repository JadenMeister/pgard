import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanSourceCode } from "../scan-source.js";

const roots: string[] = [];
function project(files: Record<string, string>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-py-")));
  roots.push(root);
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
    writeFileSync(path.join(root, name), content);
  }
  return root;
}
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

const FLASK = `import sqlite3
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/user")
def user():
    cur = sqlite3.connect("x.db").cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + request.args["name"] + "'")
    subprocess.run("ping " + request.args["host"], shell=True)
    return ""
`;

describe("scanSourceCode with Python", () => {
  it("reports findings and per-area coverage for both rules", async () => {
    const root = project({
      "app/main.py": FLASK,
      "requirements.txt": "Flask==3.0\nrequests\n",
    });
    const output = await scanSourceCode(root);
    expect(output.findings.map((f) => [f.ruleId, f.location.path, f.confidence]).sort()).toEqual([
      ["PG-CMD-004", "app/main.py", "high"],
      ["PG-SQL-006", "app/main.py", "high"],
    ]);
    const entry = output.coverage.find((item) => item.area === "source:python");
    expect(entry).toMatchObject({ status: "completed", ruleIds: ["PG-SQL-006", "PG-CMD-004"] });
    expect(entry?.note).toMatch(/^1 Python file\(s\); frameworks: Flask; tree-sitter syntax trees/);
    expect(entry?.note).toContain("SQL injection (PG-SQL-006)");
    // The categories without a rule are shown as not tested, never as clean.
    expect(
      output.coverage.find((item) => item.area === "source:python:other-categories"),
    ).toMatchObject({
      status: "not_tested",
      ruleIds: [],
    });
    expect(
      output.coverage.some((item) => /Python detected, no rules yet/.test(item.note ?? "")),
    ).toBe(false);
    for (const ruleId of ["PG-SQL-006", "PG-CMD-004"]) {
      expect(
        output.ruleStats?.find((row) => row.ruleId === ruleId && row.area === "source:python"),
      ).toMatchObject({
        status: "completed",
        findings: 1,
      });
    }
  });

  it("detects Django and FastAPI from pyproject.toml and imports", async () => {
    const output = await scanSourceCode(
      project({
        "pyproject.toml": '[project]\ndependencies = ["django>=5"]\n',
        "api.py": "from fastapi import FastAPI\napp = FastAPI()\n",
      }),
    );
    const note = output.coverage.find((item) => item.area === "source:python")?.note ?? "";
    expect(note).toContain("frameworks: Django, FastAPI");
  });

  it("does not list a Python area when there are no Python files", async () => {
    const output = await scanSourceCode(project({ "a.js": "console.log(1)\n" }));
    expect(output.coverage.some((item) => item.area.startsWith("source:python"))).toBe(false);
  });

  it("marks the area partial when a file is too large to parse", async () => {
    const big = `x = 1\n${"# padding padding padding padding padding padding\n".repeat(25_000)}`;
    expect(big.length).toBeGreaterThan(1024 * 1024);
    const output = await scanSourceCode(project({ "big.py": big, "main.py": FLASK }));
    const entry = output.coverage.find((item) => item.area === "source:python");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("big.py");
    expect(entry?.note).toContain("not a safe result");
    expect(output.findings.some((f) => f.location.path === "main.py")).toBe(true);
  });

  it("marks the area partial for code nested too deeply and for calls it cannot follow", async () => {
    const deep = `import os\ndef f(x):\n    os.system(${"(".repeat(2000)}x${")".repeat(2000)})\n`;
    const dynamic = 'import os\ngetattr(os, "system")("ls " + input())\n';
    const output = await scanSourceCode(project({ "deep.py": deep, "dyn.py": dynamic }));
    const entry = output.coverage.find((item) => item.area === "source:python");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("nested too deeply");
    expect(entry?.note).toContain("calls through getattr(...)");
    expect(entry?.note).toContain("dyn.py");
  });

  it("adds a partial area for libraries with their own process or SQL API", async () => {
    const output = await scanSourceCode(
      project({ "a.py": "import sh\nimport pony.orm\nsh.ls('-l')\n" }),
    );
    expect(output.coverage.find((item) => item.area === "source:process:sh")).toMatchObject({
      status: "partial",
      ruleIds: ["PG-CMD-004"],
    });
    expect(output.coverage.find((item) => item.area === "source:orm:pony-orm")).toMatchObject({
      status: "partial",
      ruleIds: ["PG-SQL-006"],
    });
  });

  it("counts files that hit the per-file cap and files with syntax errors", async () => {
    const calls = Array.from({ length: 40 }, (_, i) => `    os.system("a" + x${i})`).join("\n");
    const params = Array.from({ length: 40 }, (_, i) => `x${i}`).join(", ");
    const output = await scanSourceCode(
      project({
        "many.py": `import os\ndef f(${params}):\n${calls}\n`,
        "broken.py": "def f(:\n    os.system(\n",
      }),
    );
    const entry = output.coverage.find((item) => item.area === "source:python");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("per-file finding cap");
    expect(entry?.note).toContain("syntax errors");
    expect(output.findings.filter((f) => f.ruleId === "PG-CMD-004")).toHaveLength(25);
  });

  it("leaves excluded Python files out", async () => {
    const output = await scanSourceCode(project({ "a.py": FLASK, "gen/b.py": FLASK }), {
      projectConfig: {
        version: 1,
        exclude: ["gen/**"],
        testDirectories: [],
        suppressions: [],
      } as never,
    });
    expect(
      output.findings.filter((f) => f.ruleId === "PG-SQL-006").map((f) => f.location.path),
    ).toEqual(["a.py"]);
  });
});
