import { afterAll, describe, expect, it } from "vitest";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzePythonTree, type PythonAnalysis } from "./analyze-python.js";

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

async function analyze(source: string): Promise<PythonAnalysis> {
  const outcome = await runtime.parse("python", source);
  if (outcome.status !== "parsed") throw new Error(outcome.status);
  try {
    return analyzePythonTree(outcome.tree.rootNode, source, "app.py");
  } finally {
    outcome.dispose();
  }
}

/** `RULE confidence/severity` per finding, in line order. */
async function summarize(source: string): Promise<string[]> {
  return (await analyze(source)).findings.map(
    (finding) => `${finding.ruleId} ${finding.confidence}/${finding.severity}`,
  );
}

const FLASK = `from flask import Flask, request, abort
import sqlite3, os, subprocess, shlex, re, asyncio
app = Flask(__name__)
`;
const handler = (body: string): string =>
  `${FLASK}@app.route("/x")\ndef view():\n${body
    .split("\n")
    .map((line) => `    ${line}`)
    .join("\n")}\n`;

describe("PG-SQL-006: DB-API", () => {
  it.each([
    ["f-string", "cur.execute(f\"SELECT * FROM t WHERE a = '{name}'\")"],
    ["percent", "cur.execute(\"SELECT * FROM t WHERE a = '%s'\" % name)"],
    ["concatenation", 'cur.execute("SELECT * FROM t WHERE a = \'" + name + "\'")'],
    ["format", "cur.execute(\"SELECT * FROM t WHERE a = '{}'\".format(name))"],
    ["executemany", 'cur.executemany("INSERT INTO t VALUES (" + name + ")", [])'],
    ["executescript", 'cur.executescript("DROP TABLE " + name)'],
    ["through a variable", 'q = f"SELECT * FROM t WHERE a = {name}"\ncur.execute(q)'],
  ])("flags request input built into SQL (%s)", async (_label, line) => {
    const source = handler(
      `name = request.args.get("a")\ncur = sqlite3.connect("x").cursor()\n${line}`,
    );
    expect(await summarize(source)).toEqual(["PG-SQL-006 high/high"]);
  });

  it("reports the direct and the via-variable form with different status", async () => {
    const direct = await analyze(
      handler('cur = sqlite3.connect("x").cursor()\ncur.execute("SELECT " + request.args["a"])'),
    );
    expect(direct.findings[0]).toMatchObject({ status: "confirmed", confidence: "high" });
    expect(direct.findings[0]?.evidence).toBe(
      "request input (request.args) -> concatenation -> cur.execute",
    );
    const indirect = await analyze(
      handler(
        'a = request.args["a"]\ncur = sqlite3.connect("x").cursor()\ncur.execute("SELECT " + a)',
      ),
    );
    expect(indirect.findings[0]).toMatchObject({ status: "suspected", confidence: "high" });
    expect(indirect.findings[0]?.evidence).toContain("via variable");
  });

  it.each([
    ["parameterised %s", 'cur.execute("SELECT * FROM t WHERE a = %s", (name,))'],
    ["parameterised ?", 'cur.execute("SELECT * FROM t WHERE a = ?", [name])'],
    ["named", 'cur.execute("SELECT * FROM t WHERE a = :a", {"a": name})'],
    ["constant f-string", 'cur.execute(f"SELECT * FROM {TABLE} WHERE a = ?", (name,))'],
    ["constant concatenation", 'cur.execute(QUERY + " ORDER BY id")'],
    ["literal percent", 'cur.execute("SELECT %s" % "x")'],
    ["built in steps", 'q = "SELECT 1"\nq += " UNION SELECT 2"\ncur.execute(q)'],
    [
      "placeholders",
      'ph = ",".join(["?"] * len(ids))\ncur.execute(f"SELECT * FROM t WHERE a IN ({ph})", ids)',
    ],
    ["loop over literals", 'for t in ("a", "b"):\n    cur.execute(f"SELECT * FROM {t}")'],
    ["class constant", 'cur.execute(f"SELECT * FROM {Repo.TABLE}")'],
    ["not SQL", "executor.execute(task)"],
  ])("stays silent on fixed text (%s)", async (_label, line) => {
    const source = `${FLASK}TABLE = "users"\nQUERY = "SELECT * FROM users"\nclass Repo:\n    TABLE = "accounts"\n@app.route("/x")\ndef view(ids):\n    name = request.args.get("a")\n    cur = sqlite3.connect("x").cursor()\n${line
      .split("\n")
      .map((l) => `    ${l}`)
      .join("\n")}\n`;
    expect(await summarize(source)).toEqual([]);
  });

  it("demotes inferred safety to low confidence, medium severity at most, with '; inferred'", async () => {
    const guarded = await analyze(
      handler(
        'col = request.args["c"]\nif col not in ("a", "b"):\n    abort(400)\ncur = sqlite3.connect("x").cursor()\ncur.execute(f"SELECT {col} FROM t")',
      ),
    );
    expect(guarded.findings).toHaveLength(1);
    expect(guarded.findings[0]).toMatchObject({ confidence: "low", severity: "medium" });
    expect(guarded.findings[0]?.evidence).toMatch(/; inferred$/);

    const numeric = await analyze(
      handler(
        'n = int(request.args["n"])\ncur = sqlite3.connect("x").cursor()\ncur.execute(f"SELECT * FROM t LIMIT {n}")',
      ),
    );
    expect(numeric.findings[0]).toMatchObject({ confidence: "low", severity: "medium" });
    expect(numeric.findings[0]?.evidence).toMatch(/int\(\) gives a number.*; inferred$/);

    const table = await analyze(
      handler(
        'ORDER = {"asc": "ASC", "desc": "DESC"}\nd = ORDER.get(request.args.get("d"), "ASC")\ncur = sqlite3.connect("x").cursor()\ncur.execute("SELECT * FROM t ORDER BY a " + d)',
      ),
    );
    expect(table.findings[0]).toMatchObject({ confidence: "low", severity: "medium" });
    expect(table.findings[0]?.evidence).toMatch(/fixed allowlist table; inferred$/);
  });

  it("counts a guard only when it exits on failure, or when the use is in the success branch", async () => {
    const noExit = await summarize(
      handler(
        'col = request.args["c"]\nif col not in ("a", "b"):\n    print("bad")\ncur = sqlite3.connect("x").cursor()\ncur.execute(f"SELECT {col} FROM t")',
      ),
    );
    expect(noExit).toEqual(["PG-SQL-006 high/high"]);
    const exits = await summarize(
      handler(
        'col = request.args["c"]\nif col not in ("a", "b"):\n    return "bad"\ncur = sqlite3.connect("x").cursor()\ncur.execute(f"SELECT {col} FROM t")',
      ),
    );
    expect(exits).toEqual(["PG-SQL-006 low/medium"]);
    const success = await summarize(
      handler(
        'col = request.args["c"]\ncur = sqlite3.connect("x").cursor()\nif col in ("a", "b"):\n    cur.execute(f"SELECT {col} FROM t")\ncur.execute(f"SELECT {col} FROM u")',
      ),
    );
    expect(success).toEqual(["PG-SQL-006 low/medium", "PG-SQL-006 high/high"]);
    const otherVariable = await summarize(
      handler(
        'col = request.args["c"]\nother = "x"\nif other not in ("a", "b"):\n    abort(400)\ncur = sqlite3.connect("x").cursor()\ncur.execute(f"SELECT {col} FROM t")',
      ),
    );
    expect(otherVariable).toEqual(["PG-SQL-006 high/high"]);
    const reassigned = await summarize(
      handler(
        'col = request.args["c"]\nif col not in ("a", "b"):\n    abort(400)\ncol = request.args["d"]\ncur = sqlite3.connect("x").cursor()\ncur.execute(f"SELECT {col} FROM t")',
      ),
    );
    expect(reassigned).toEqual(["PG-SQL-006 high/high"]);
  });

  it("recognizes allowlist, shape and regex checks", async () => {
    for (const check of [
      "if not col.isalnum():\n    abort(400)",
      'if not re.fullmatch(r"[a-z]+", col):\n    abort(400)',
      'if col != "id":\n    abort(400)',
      "if not is_valid_column(col):\n    abort(400)",
    ]) {
      const source = handler(
        `col = request.args["c"]\n${check}\ncur = sqlite3.connect("x").cursor()\ncur.execute(f"SELECT {col} FROM t")`,
      );
      expect(await summarize(source), check).toEqual(["PG-SQL-006 low/medium"]);
    }
  });

  it("reports a value from a helper or with no source at low confidence", async () => {
    const helper = await analyze(
      handler('cur = sqlite3.connect("x").cursor()\ncur.execute(build_sql(request.args["a"]))'),
    );
    expect(helper.findings[0]).toMatchObject({ confidence: "low", severity: "medium" });
    expect(helper.findings[0]?.evidence).toContain("build_sql()");
    const unknownParam = await analyze(
      "import sqlite3\ndef run(cur, name):\n    cur.execute(f\"SELECT * FROM t WHERE a = '{name}'\")\n",
    );
    expect(unknownParam.findings[0]).toMatchObject({ confidence: "low", severity: "medium" });
    expect(unknownParam.findings[0]?.evidence).toContain("no input source identified");
  });
});

describe("PG-SQL-006: SQLAlchemy and Django", () => {
  const SA = "from sqlalchemy import text\nfrom flask import request\n";
  it("flags text() with a built string once, even when session.execute wraps it", async () => {
    const source = `${SA}def f(session):\n    n = request.args["n"]\n    session.execute(text(f"SELECT * FROM t WHERE a = '{n}'"))\n    stmt = text("SELECT " + n)\n    session.execute(stmt)\n`;
    const result = await analyze(source);
    expect(result.findings.map((f) => [f.line, f.confidence])).toEqual([
      [5, "high"],
      [6, "high"],
    ]);
    expect(result.findings[0]?.evidence).toContain("sqlalchemy.text");
  });

  it("treats text() with bound parameters as safe", async () => {
    const source = `${SA}def f(session):\n    n = request.args["n"]\n    session.execute(text("SELECT * FROM t WHERE a = :n"), {"n": n})\n`;
    expect(await summarize(source)).toEqual([]);
  });

  it("flags session.execute and engine.execute with a built string", async () => {
    const source = `from flask import request\nfrom sqlalchemy import create_engine\nengine = create_engine("sqlite://")\ndef f():\n    with engine.connect() as conn:\n        conn.execute("SELECT * FROM t WHERE a = " + request.args["a"])\n`;
    expect(await summarize(source)).toEqual(["PG-SQL-006 high/high"]);
  });

  it("flags Django raw, extra, RawSQL and connection.cursor", async () => {
    const source = `from django.db import connection
from django.db.models.expressions import RawSQL
from .models import User
def view(request):
    q = request.GET.get("q")
    User.objects.raw("SELECT * FROM u WHERE n = '%s'" % q)
    User.objects.extra(where=["n = '%s'" % q])
    User.objects.annotate(x=RawSQL("select " + q, []))
    with connection.cursor() as c:
        c.execute("DELETE FROM t WHERE a = " + q)
`;
    expect(await summarize(source)).toEqual(Array(4).fill("PG-SQL-006 high/high"));
  });

  it("treats Django parameterised calls as safe", async () => {
    const source = `from django.db import connection
from .models import User
def view(request):
    q = request.GET.get("q")
    User.objects.raw("SELECT * FROM u WHERE n = %s", [q])
    User.objects.extra(where=["n = %s"], params=[q])
    with connection.cursor() as c:
        c.execute("DELETE FROM t WHERE a = %s", [q])
`;
    expect(await summarize(source)).toEqual([]);
  });

  it("treats FastAPI route parameters as request input and numeric ones as inferred", async () => {
    const source = `from fastapi import FastAPI
app = FastAPI()
@app.get("/u/{name}")
def u(name: str, uid: int, db):
    db.execute(f"SELECT * FROM t WHERE n = '{name}'")
    db.execute(f"SELECT * FROM t WHERE id = {uid}")
`;
    const result = await analyze(source);
    expect(result.findings.map((f) => [f.confidence, f.status])).toEqual([
      ["high", "confirmed"],
      ["low", "suspected"],
    ]);
    expect(result.findings[1]?.evidence).toContain("int parameter uid; inferred");
  });

  it("reads psycopg2.sql composition as inferred", async () => {
    const source = `from psycopg2 import sql
from flask import request
def f(cur):
    col = request.args["c"]
    cur.execute(sql.SQL("SELECT {} FROM t").format(sql.Identifier(col)))
`;
    const result = await analyze(source);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ confidence: "low", severity: "medium" });
  });
});

describe("PG-CMD-004", () => {
  const run = (body: string): Promise<string[]> =>
    summarize(handler(`host = request.args["h"]\n${body}`));

  it.each([
    ['os.system("ping " + host)', "PG-CMD-004 high/critical"],
    ['os.popen(f"ping {host}")', "PG-CMD-004 high/critical"],
    ['subprocess.run(f"ping {host}", shell=True)', "PG-CMD-004 high/critical"],
    ['subprocess.check_output("ping %s" % host, shell=True)', "PG-CMD-004 high/critical"],
    ['subprocess.Popen(["sh", "-c", "ping " + host])', "PG-CMD-004 high/critical"],
    ['subprocess.run(["env", "A=1", "bash", "-lc", host])', "PG-CMD-004 high/critical"],
    ['subprocess.run([host, "-v"])', "PG-CMD-004 high/critical"],
    ['subprocess.run("ping " + host)', "PG-CMD-004 high/critical"],
    ['subprocess.run(["ping", "-c1", host])', "PG-CMD-004 medium/medium"],
    ['subprocess.run(["ping", "--", host])', "PG-CMD-004 low/low"],
  ])("%s", async (line, expected) => {
    expect(await run(line)).toEqual([expected]);
  });

  it.each([
    'os.system("ls -l")',
    'subprocess.run(["ls", "-l"])',
    'subprocess.run("ls -l", shell=True)',
    'subprocess.run(["git", "log", "--oneline"], check=True)',
    'cmd = ["ls"]\ncmd.append("-l")\nsubprocess.run(cmd)',
    'BASE = ["git", "log"]\nsubprocess.run(BASE + ["-n", "5"])',
    'subprocess.run(["git", *["log", "-n", "5"]])',
    "print(host)",
  ])("stays silent on fixed commands (%s)", async (line) => {
    expect(await run(line)).toEqual([]);
  });

  it("still reports shlex.quote with shell=True, demoted but not silent", async () => {
    const result = await analyze(
      handler('host = request.args["h"]\nsubprocess.run("ping " + shlex.quote(host), shell=True)'),
    );
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ confidence: "low", severity: "medium" });
    expect(result.findings[0]?.evidence).toMatch(/shlex\.quote\(\).*; inferred$/);
  });

  it("does not let shlex.quote protect SQL", async () => {
    const source = handler(
      'n = shlex.quote(request.args["n"])\ncur = sqlite3.connect("x").cursor()\ncur.execute("SELECT " + n)',
    );
    expect(await summarize(source)).toEqual(["PG-SQL-006 high/high"]);
  });

  it("finds shell wrappers behind launchers and arguments built in steps", async () => {
    expect(
      await run(
        'subprocess.run(["sudo", "-u", "app", "timeout", "5", "sh", "-c", "echo " + host])',
      ),
    ).toEqual(["PG-CMD-004 high/critical"]);
    expect(await run('cmd = ["git", "log"]\ncmd.append(host)\nsubprocess.run(cmd)')).toEqual([
      "PG-CMD-004 medium/medium",
    ]);
    expect(await run('subprocess.run(["git", *host.split()])')).toEqual([
      "PG-CMD-004 medium/medium",
    ]);
    expect(await run('subprocess.run(shlex.split("tool " + host))')).toEqual([
      "PG-CMD-004 medium/medium",
    ]);
  });

  it("handles asyncio and os.exec*/spawn*", async () => {
    expect(await run('asyncio.create_subprocess_shell("ping " + host)')).toEqual([
      "PG-CMD-004 high/critical",
    ]);
    expect(await run('asyncio.create_subprocess_exec("ping", host)')).toEqual([
      "PG-CMD-004 medium/medium",
    ]);
    expect(await run('os.execv(host, ["x"])')).toEqual(["PG-CMD-004 high/critical"]);
    expect(await run('os.spawnl(os.P_WAIT, "/bin/ls", "ls", host)')).toEqual([
      "PG-CMD-004 medium/medium",
    ]);
  });

  it("resolves import aliases and leaves look-alikes alone", async () => {
    const aliased = `from flask import request\nimport subprocess as sp\nfrom os import system as sh\ndef f():\n    sp.run("a " + request.args["a"], shell=True)\n    sh("b " + request.args["b"])\n`;
    expect(await summarize(aliased)).toEqual([
      "PG-CMD-004 high/critical",
      "PG-CMD-004 high/critical",
    ]);
    const lookalike = `from flask import request\nclass Runner:\n    def system(self, c): pass\ndef f(runner):\n    runner.system("a " + request.args["a"])\n    shell = request.args["s"]\n    run = print\n    run(shell)\n`;
    expect(await summarize(lookalike)).toEqual([]);
  });

  it("reports a non-constant shell flag and an unknown source at low confidence", async () => {
    const dynamic = await analyze(
      "import subprocess\ndef f(cmd, use_shell):\n    subprocess.run('ls ' + cmd, shell=use_shell)\n",
    );
    expect(dynamic.findings).toHaveLength(1);
    expect(dynamic.findings[0]).toMatchObject({ confidence: "low", severity: "medium" });
  });
});

describe("coverage signals", () => {
  it("reports frameworks from imports", async () => {
    const result = await analyze(
      "import django\nfrom flask import Flask\nfrom fastapi import FastAPI\n",
    );
    expect(result.frameworks).toEqual(["Django", "Flask", "FastAPI"]);
  });

  it("names forms whose target cannot be seen and libraries it does not follow", async () => {
    const result = await analyze(
      'import os\nimport sh\nimport pony\nfrom os import *\ngetattr(os, "system")(cmd)\n__import__("os").system(cmd)\n',
    );
    expect(result.unsupportedForms.sort()).toEqual([
      "calls through __import__(...)",
      "calls through getattr(...)",
      "star imports from os",
    ]);
    expect(result.unsupportedProcessLibraries).toEqual(["sh"]);
    expect(result.unsupportedLibraries).toEqual(["Pony ORM"]);
  });

  it("marks a file nested too deeply as incomplete instead of failing", async () => {
    const deep = `import os\ndef f(x):\n    os.system(${"(".repeat(2000)}x${")".repeat(2000)})\n`;
    const result = await analyze(deep);
    expect(result.incomplete).toBe(true);
  });

  it("handles a very long concatenation without recursing", async () => {
    const chain = Array.from({ length: 20000 }, () => '"a"').join(" + ");
    const result = await analyze(
      `import os\nfrom flask import request\ndef f():\n    os.system(${chain} + request.args["a"])\n`,
    );
    expect(result.findings).toHaveLength(1);
    expect(result.incomplete).toBe(false);
  });

  it("caps findings per rule per file", async () => {
    const calls = Array.from({ length: 40 }, (_, i) => `    os.system("a" + x${i})`).join("\n");
    const params = Array.from({ length: 40 }, (_, i) => `x${i}`).join(", ");
    const result = await analyze(`import os\ndef f(${params}):\n${calls}\n`);
    expect(result.findings).toHaveLength(25);
    expect(result.capped).toBe(true);
  });
});
