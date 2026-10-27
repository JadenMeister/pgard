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
/** A route handler whose body starts with `col`, `flag` and a cursor. */
const sql = (body: string): string =>
  `${FLASK}@app.route("/x")\ndef view():\n${[
    'col = request.args["c"]',
    'flag = request.args.get("f")',
    'cur = sqlite3.connect("x").cursor()',
    ...body.split("\n"),
  ]
    .map((line) => `    ${line}`)
    .join("\n")}\n`;

describe("review fixes (#321)", () => {
  it("keeps a .get() default that the caller chooses (M1)", async () => {
    const source = `${FLASK}ALIASES = {"x": "ls"}\n@app.route("/x")\ndef view():\n    k = request.args["k"]\n    tool = ALIASES.get(k, k)\n    subprocess.run(tool, shell=True)\n    ok = ALIASES.get(k, "ls")\n    subprocess.run(ok, shell=True)\n`;
    const result = await analyze(source);
    expect(result.findings.map((f) => f.confidence)).toEqual(["high", "low"]);
  });

  it("follows **mapping arguments of .format() (M2)", async () => {
    expect(await summarize(sql('cur.execute("SELECT {c} FROM t".format(**request.args))'))).toEqual(
      ["PG-SQL-006 high/high"],
    );
  });

  it("reports .extra() and .raw() without a django import (M3)", async () => {
    const source = `from .models import X\ndef view(request):\n    X.objects.extra(select={"a": "1" + request.GET["c"]})\n    X.objects.raw("SELECT " + request.GET["c"])\n`;
    expect(await summarize(source)).toEqual(["PG-SQL-006 high/high", "PG-SQL-006 high/high"]);
    // A manager under another name is Django's only when the manifests say so.
    const other = "def f(m, x):\n    m.raw('q: ' + x)\n";
    expect(await summarize(other)).toEqual([]);
    expect(await summarize(other, { django: true })).toEqual(["PG-SQL-006 low/medium"]);
  });

  it("ends a break/continue guard with the loop (M4)", async () => {
    const afterLoop = sql(
      'for c2 in [1]:\n    if col not in ("a", "b"):\n        break\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(afterLoop)).toEqual(["PG-SQL-006 high/high"]);
    const insideLoop = sql(
      'for c2 in [1]:\n    if col not in ("a", "b"):\n        continue\n    cur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(insideLoop)).toEqual(["PG-SQL-006 low/medium"]);
    const nested = sql(
      'if flag:\n    if col not in ("a", "b"):\n        return "bad"\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(nested)).toEqual(["PG-SQL-006 high/high"]);
  });

  it("does not count a raise that an except swallows as an exit (M4)", async () => {
    const swallowed = sql(
      'try:\n    if col not in ("a", "b"):\n        raise ValueError(col)\nexcept ValueError:\n    pass\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(swallowed)).toEqual(["PG-SQL-006 high/high"]);
    const notCaught = sql(
      'if col not in ("a", "b"):\n    raise ValueError(col)\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(notCaught)).toEqual(["PG-SQL-006 low/medium"]);
  });

  it("keeps a fixed text() with bindparams fixed", async () => {
    const source = `from sqlalchemy import text\nfrom flask import request\ndef f(session):\n    session.execute(text("SELECT * FROM t WHERE a = :a").bindparams(a=request.args["a"]))\n`;
    expect(await summarize(source)).toEqual([]);
  });

  it("treats sys.argv, input() and argparse/click arguments as untrusted input", async () => {
    expect(await summarize('import os, sys\nos.system("ls " + sys.argv[1])\n')).toEqual([
      "PG-CMD-004 high/critical",
    ]);
    expect(await summarize('import os\nos.system("ls " + input())\n')).toEqual([
      "PG-CMD-004 high/critical",
    ]);
    expect(
      await summarize(
        'import os, argparse\np = argparse.ArgumentParser()\nargs = p.parse_args()\nos.system("ls " + args.path)\n',
      ),
    ).toEqual(["PG-CMD-004 high/critical"]);
    const click = await analyze(
      'import os, click\n@click.command()\n@click.option("--path")\ndef main(path):\n    os.system("ls " + path)\n',
    );
    expect(click.findings[0]?.evidence).toContain("command-line input");
    expect(click.findings[0]).toMatchObject({ confidence: "high" });
  });

  it("words every low-confidence finding with '; inferred'", async () => {
    const source =
      'import sqlite3, os\ndef run(cur, name):\n    cur.execute(f"SELECT {name}")\n    os.system("a" + name)\n';
    const result = await analyze(source);
    expect(result.findings).toHaveLength(2);
    for (const finding of result.findings) {
      expect(finding.evidence).toMatch(/; no input source identified; inferred$/);
    }
  });

  it("names a shape check as one, not as an allowlist", async () => {
    const shape = await analyze(
      sql('if not col.isalnum():\n    abort(400)\ncur.execute(f"SELECT {col} FROM t")'),
    );
    expect(shape.findings[0]?.evidence).toContain("shape check");
    expect(shape.findings[0]?.evidence).not.toContain("allowlist");
    const regex = await analyze(
      sql(
        'if not re.fullmatch(r"[a-z]+", col):\n    abort(400)\ncur.execute(f"SELECT {col} FROM t")',
      ),
    );
    expect(regex.findings[0]?.evidence).toContain("regular expression");
    const list = await analyze(
      sql('if col not in ("a", "b"):\n    abort(400)\ncur.execute(f"SELECT {col} FROM t")'),
    );
    expect(list.findings[0]?.evidence).toContain("allowlist");
  });

  it("does not take a substring test on a string for an allowlist", async () => {
    const source = `${FLASK}NAMES = "name,date"\n@app.route("/x")\ndef view():\n    c = request.args["c"]\n    if c not in NAMES:\n        abort(400)\n    if c not in "name,date":\n        abort(400)\n    sqlite3.connect("x").cursor().execute(f"SELECT {c} FROM t")\n`;
    expect(await summarize(source)).toEqual(["PG-SQL-006 high/high"]);
  });

  it("makes an unresolved getattr alias partial", async () => {
    for (const line of ['fn = getattr(conn, "execute")', 'fn = getattr(conn, "exec" + "ute")']) {
      const result = await analyze(
        `import sqlite3\nconn = sqlite3.connect("x")\n${line}\nfn("SELECT 1")\n`,
      );
      expect(result.unsupportedForms, line).toEqual(["calls through getattr(...)"]);
    }
    const plain = await analyze('import sqlite3\nx = getattr(obj, "name")\n');
    expect(plain.unsupportedForms).toEqual([]);
  });

  it("follows a walrus check and the names captured by a match statement", async () => {
    const walrus = sql(
      'if not (m := re.fullmatch(r"[a-z_]+", col)):\n    return "bad"\ncur.execute("SELECT * FROM " + col)',
    );
    expect(await summarize(walrus)).toEqual(["PG-SQL-006 low/medium"]);
    const match = `import os, sys\ndef main():\n    match sys.argv[1:]:\n        case ["clean", target]:\n            os.system(f"rm -rf {target}")\n`;
    expect(await summarize(match)).toEqual(["PG-CMD-004 high/critical"]);
  });
});

describe("guard soundness", () => {
  it("G8: a check whose else branch exits guards what follows", async () => {
    const source = sql(
      'if col in ("a", "b"):\n    pass\nelse:\n    return "bad"\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(source)).toEqual(["PG-SQL-006 low/medium"]);
  });

  it("G10: `or` guards a name only when both sides check it", async () => {
    const eitherSide = sql(
      'if col in ("a", "b") or flag:\n    cur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(eitherSide)).toEqual(["PG-SQL-006 high/high"]);
    const bothSides = sql(
      'if col in ("a", "b") or col in ("c",):\n    cur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(bothSides)).toEqual(["PG-SQL-006 low/medium"]);
  });

  it("G11: `and` guards the false side only for names every part checks", async () => {
    const one = sql(
      'if col not in ("a", "b") and flag:\n    return "bad"\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(one)).toEqual(["PG-SQL-006 high/high"]);
    const both = sql(
      'if col not in ("a", "b") and col not in ("c",):\n    return "bad"\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(both)).toEqual(["PG-SQL-006 low/medium"]);
  });

  it("F1: a request object is not a constant", async () => {
    const source = `from flask import request\nimport sqlite3\nR = request\ndef f():\n    sqlite3.connect("x").cursor().execute("SELECT " + R.args["a"])\n`;
    expect((await summarize(source)).length).toBe(1);
  });

  it("F2: a dynamic program is not mistaken for a fixed one", async () => {
    const source = sql(
      'tool = request.args["t"]\nsubprocess.run([tool, "-c", "ls"])\nsubprocess.run(["sh", "-c", tool])',
    );
    expect(await summarize(source)).toEqual([
      "PG-CMD-004 high/critical",
      "PG-CMD-004 high/critical",
    ]);
  });

  it("F4: a name declared global somewhere is not a constant", async () => {
    const source = `import sqlite3\nfrom flask import request\nTABLE = "users"\ndef set_table():\n    global TABLE\n    TABLE = request.args["t"]\ndef q():\n    sqlite3.connect("x").cursor().execute(f"SELECT * FROM {TABLE}")\n`;
    const result = await analyze(source);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ confidence: "low" });
    const fixed = `import sqlite3\nTABLE = "users"\ndef q():\n    sqlite3.connect("x").cursor().execute(f"SELECT * FROM {TABLE}")\n`;
    expect(await summarize(fixed)).toEqual([]);
  });

  it("F6: an f-string is not a literal to compare against", async () => {
    const source = sql(
      'other = request.args["o"]\nif col != f"{other}":\n    return "bad"\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(source)).toEqual(["PG-SQL-006 high/high"]);
    const literal = sql('if col != "id":\n    return "bad"\ncur.execute(f"SELECT {col} FROM t")');
    expect(await summarize(literal)).toEqual(["PG-SQL-006 low/medium"]);
  });

  it("F7: membership in a list the caller controls is not an allowlist", async () => {
    const source = sql(
      'user_list = request.args.getlist("l")\nif col not in user_list:\n    return "bad"\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(source)).toEqual(["PG-SQL-006 high/high"]);
  });
});
