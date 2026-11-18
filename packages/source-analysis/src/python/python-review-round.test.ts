import { afterAll, describe, expect, it } from "vitest";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzePythonTree, type PythonAnalysis, type PythonOptions } from "./analyze-python.js";

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

async function analyze(source: string, options: PythonOptions = {}): Promise<PythonAnalysis> {
  const outcome = await runtime.parse("python", source);
  if (outcome.status !== "parsed") throw new Error(outcome.status);
  try {
    return analyzePythonTree(outcome.tree.rootNode, source, "app.py", options);
  } finally {
    outcome.dispose();
  }
}
async function summarize(source: string, options: PythonOptions = {}): Promise<string[]> {
  return (await analyze(source, options)).findings.map(
    (finding) => `${finding.ruleId} ${finding.confidence}/${finding.severity}`,
  );
}

const FLASK = `from flask import Flask, request, abort
import sqlite3, os, subprocess, shlex, re
app = Flask(__name__)
`;
const view = (body: string): string =>
  `${FLASK}@app.route("/x")\ndef view():\n${[
    'col = request.args["c"]',
    'host = request.args["h"]',
    'cur = sqlite3.connect("x").cursor()',
    ...body.split("\n"),
  ]
    .map((line) => `    ${line}`)
    .join("\n")}\n`;

describe("review round: guards and receivers (#326)", () => {
  it("does not count '-' removal in a shape check (a leading dash passes)", async () => {
    const source = view(
      'if not host.replace("-", "").isalnum():\n    return "bad"\nsubprocess.run("ping " + host, shell=True)',
    );
    expect(await summarize(source)).toEqual(["PG-CMD-004 high/critical"]);
    const dots = view(
      'if not host.replace("_", "").replace(".", "").isalnum():\n    return "bad"\nsubprocess.run("ping " + host, shell=True)',
    );
    expect(await summarize(dots)).toEqual(["PG-CMD-004 low/medium"]);
  });

  it("keeps a sink inside finally or inside the handler itself high", async () => {
    const inFinally = view(
      'try:\n    if col not in ("a", "b"):\n        raise ValueError("x")\nexcept ValueError:\n    raise\nfinally:\n    cur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(inFinally)).toEqual(["PG-SQL-006 high/high"]);
    const inHandler = view(
      'try:\n    if col not in ("a", "b"):\n        raise ValueError("x")\nexcept ValueError:\n    return cur.execute("SELECT " + col)',
    );
    expect(await summarize(inHandler)).toEqual(["PG-SQL-006 high/high"]);
    const inElse = view(
      'try:\n    if col not in ("a", "b"):\n        raise ValueError("x")\nexcept ValueError:\n    raise\nelse:\n    cur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(inElse)).toEqual(["PG-SQL-006 low/medium"]);
    const after = view(
      'try:\n    if col not in ("a", "b"):\n        raise ValueError("x")\nexcept ValueError:\n    raise\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(after)).toEqual(["PG-SQL-006 low/medium"]);
  });

  it("does not take a list built from the input itself as an allowlist", async () => {
    const source = view(
      'for a in [col]:\n    if col == a:\n        break\nelse:\n    abort(400)\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(source)).toEqual(["PG-SQL-006 high/high"]);
    const inList = view(
      'if col not in [col]:\n    abort(400)\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(inList)).toEqual(["PG-SQL-006 high/high"]);
    const literal = view(
      'for a in ["x", "y"]:\n    if col == a:\n        break\nelse:\n    abort(400)\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(literal)).toEqual(["PG-SQL-006 low/medium"]);
  });

  it("keeps .extra() high on a queryset held in a variable or another file's model", async () => {
    for (const setup of [
      "products = Book.objects.filter(a=1)",
      "products = Book.objects",
      "products = queryset",
      "products = Item.objects.all()",
      "products = self.model.objects.all()",
      "products = get_rows()",
    ]) {
      const source = `def view(self, request, queryset):\n    ${setup}\n    products.extra(where=["a = " + request.GET["x"]])\n`;
      expect(await summarize(source), setup).toEqual(["PG-SQL-006 high/high"]);
    }
    const splat = `def view(request):\n    kw = {"where": ["a = " + request.GET["x"]]}\n    Book.objects.extra(**kw)\n`;
    expect(await summarize(splat)).toEqual(["PG-SQL-006 high/high"]);
  });

  it("demotes .extra() only on an instance of a base-less class of the file", async () => {
    const own = `class Ctx:\n    def extra(self, where=()):\n        return where\n\ndef view(request):\n    c = Ctx()\n    c.extra(where=["a = " + request.GET["x"]])\n`;
    expect(await summarize(own)).toEqual([]);
    expect(await summarize(own, { django: true })).toEqual(["PG-SQL-006 low/medium"]);
    const derived = `class Ctx(Base):\n    pass\n\ndef view(request):\n    Ctx().extra(where=["a = " + request.GET["x"]])\n`;
    expect(await summarize(derived)).toEqual(["PG-SQL-006 high/high"]);
  });

  it("maps lambda arguments only for a plain signature", async () => {
    for (const lam of [
      "lambda a, /, b, c: subprocess.run(b, shell=True)",
      'lambda *args, cmd="id": subprocess.run(cmd, shell=True)',
      "lambda a, *, b: subprocess.run(b, shell=True)",
    ]) {
      const source = `${FLASK}@app.route("/x")\ndef view():\n    f = ${lam}\n    f("a", "ls", request.args["x"])\n`;
      expect(await summarize(source), lam).toEqual(["PG-CMD-004 low/medium"]);
    }
    const defaults = `${FLASK}@app.route("/x")\ndef view():\n    f = lambda a, b="ls": subprocess.run(b, shell=True)\n    f(1, request.args["x"])\n`;
    expect(await summarize(defaults)).toEqual(["PG-CMD-004 high/critical"]);
  });
});

describe("bounded recursion (#326)", () => {
  it("does not overflow on 6500 nested calls in a for/else iterable and still sees later findings", async () => {
    const nested = `${"list(".repeat(6500)}x${")".repeat(6500)}`;
    const source = view(
      `for a in ${nested}:\n    if col == a:\n        break\nelse:\n    abort(400)\ncur.execute(f"SELECT {col} FROM t")`,
    );
    const result = await analyze(source);
    expect(result.incomplete).toBe(true);
    expect(result.findings.map((f) => f.ruleId)).toContain("PG-SQL-006");
  });

  it("does not overflow on a long boolean chain", async () => {
    const chain = Array.from({ length: 7500 }, (_, i) => `a${i}`).join(" or ");
    const source = view(`if ${chain}:\n    pass\ncur.execute(f"SELECT {col} FROM t")`);
    const result = await analyze(source);
    expect(result.findings.map((f) => f.ruleId)).toContain("PG-SQL-006");
  });
});
