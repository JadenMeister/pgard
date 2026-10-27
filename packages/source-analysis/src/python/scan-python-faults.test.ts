import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { scanSourceCode } from "../scan-source.js";

vi.mock("./analyze-python.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("./analyze-python.js")>();
  return {
    ...real,
    analyzePythonTree: (...args: Parameters<typeof real.analyzePythonTree>) => {
      if (args[1].includes("EXPLODE")) throw new Error("analysis failed");
      return real.analyzePythonTree(...args);
    },
  };
});

const roots: string[] = [];
function project(files: Record<string, string>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-pyf-")));
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

const VULNERABLE = `import os
from flask import request
os.system("ls " + request.args["a"])
`;

describe("Python scan faults", () => {
  it("C4: a file whose analysis crashes makes the area partial, and the others are still analyzed", async () => {
    const output = await scanSourceCode(
      project({ "boom.py": "# EXPLODE\nx = 1\n", "ok.py": VULNERABLE }),
    );
    const entry = output.coverage.find((item) => item.area === "source:python");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("1 file(s) could not be analyzed");
    expect(entry?.note).toContain("not a safe result");
    expect(output.findings.map((f) => f.location.path)).toEqual(["ok.py"]);
  });

  it("C3: syntax errors alone make the area partial and name the file", async () => {
    const output = await scanSourceCode(project({ "broken.py": "def f(:\n    pass\n" }));
    const entry = output.coverage.find((item) => item.area === "source:python");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("broken.py");
    expect(entry?.note).toContain("syntax errors");
  });
});
