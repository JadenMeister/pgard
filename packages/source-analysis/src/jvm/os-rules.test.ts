import { readdirSync, readFileSync } from "node:fs";
import { afterAll, describe, expect, it } from "vitest";
import type { RawSourceFinding } from "../finding-factory.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzeJvmTree } from "./analyze-jvm.js";
import { pathGuardedWhenFalse, pathGuardedWhenTrue } from "./guards.js";

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

async function run(source: string, path = "A.java") {
  const language = path.endsWith(".kt") ? "kotlin" : "java";
  const outcome = await runtime.parse(language, source);
  if (outcome.status !== "parsed") throw new Error(`not parsed: ${outcome.status}`);
  try {
    return analyzeJvmTree(outcome.tree.rootNode, source, path, language);
  } finally {
    outcome.dispose();
  }
}

type Analysis = Awaited<ReturnType<typeof run>>;
const CMD = "PG-CMD-003";
const PATH = "PG-PATH-002";
const of = (analysis: Analysis, ruleId: string): RawSourceFinding[] =>
  analysis.findings.filter((finding) => finding.ruleId === ruleId);

/** Words for what a finding says: the design's own terms. */
function kind(findings: RawSourceFinding[]): string {
  if (findings.length === 0) return "none";
  const finding = findings[0] as RawSourceFinding;
  if (finding.confidence === "low") {
    return finding.evidence.includes("inferred") ? "inferred" : "untraced";
  }
  return `${finding.severity}/${finding.status}`;
}

const SERVLET =
  "import javax.servlet.http.*;\nimport java.io.*;\nimport java.nio.file.*;\nimport java.util.*;\n";
const SPRING =
  "import org.springframework.web.bind.annotation.*;\nimport java.io.*;\nimport java.nio.file.*;\nimport java.util.*;\n";

const java = (imports: string, members: string): string => `${imports}\nclass A {\n${members}\n}\n`;
/** A method with request input in `p` (a handler parameter) and the body given. */
const handler = (body: string, imports = SPRING, fields = ""): string =>
  java(
    imports,
    `${fields}\n@GetMapping("/x") void h(@RequestParam String p, @RequestParam String q) throws Exception {\n${body}\n}`,
  );
const servlet = (body: string, fields = ""): string =>
  java(
    SERVLET,
    `${fields}\nvoid h(HttpServletRequest req) throws Exception {\nString p = req.getParameter("p");\nString q = req.getParameter("q");\n${body}\n}`,
  );
const kotlin = (body: string, imports = ""): string =>
  `package a\nimport org.springframework.web.bind.annotation.*\nimport java.io.File\nimport java.nio.file.*\n${imports}\n@RestController\nclass K {\n@GetMapping("/x")\nfun h(@RequestParam p: String, @RequestParam q: String) {\n${body}\n}\n}\n`;

// ====================================================================== commands

describe("PG-CMD-003: exec(String) and command strings", () => {
  it("reports request input in Runtime.exec(String) as critical", async () => {
    const analysis = await run(handler('Runtime.getRuntime().exec("ping -c 1 " + p);'));
    const [finding] = of(analysis, CMD);
    expect(of(analysis, CMD)).toHaveLength(1);
    expect(finding).toMatchObject({
      severity: "critical",
      status: "confirmed",
      confidence: "high",
      cause: "Runtime.exec:string",
    });
    expect(finding?.evidence).toContain("@RequestParam p");
  });

  it("says suspected when the input went through a variable", async () => {
    const analysis = await run(
      handler('String c = "ls " + p; c += q; Runtime.getRuntime().exec(c);'),
    );
    expect(kind(of(analysis, CMD))).toBe("critical/suspected");
  });

  it("does not report fixed text, constants or a literal-only concatenation", async () => {
    const analysis = await run(
      java(
        SPRING,
        `static final String CMD = "uptime";
         static final String BASE = "ls " + "-l";
         void h() throws Exception {
           Runtime.getRuntime().exec("uptime");
           Runtime.getRuntime().exec(CMD);
           Runtime.getRuntime().exec(BASE + " /tmp");
           new ProcessBuilder("sh", "-c", "echo " + "done").start();
         }`,
      ),
    );
    expect(of(analysis, CMD)).toEqual([]);
  });

  it("reports a field that can change as an unknown value, not as fixed text", async () => {
    const analysis = await run(
      java(
        SPRING,
        `String base = "ls"; void h() throws Exception { Runtime.getRuntime().exec(base + " x"); }`,
      ),
    );
    expect(kind(of(analysis, CMD))).toBe("untraced");
  });

  it("recognizes the runtime by call, declared type, variable value or usual name", async () => {
    const forms = [
      'Runtime.getRuntime().exec("a " + p);',
      'java.lang.Runtime.getRuntime().exec("a " + p);',
      'Runtime r = Runtime.getRuntime(); r.exec("a " + p);',
      'var r = Runtime.getRuntime(); r.exec("a " + p);',
      'Runtime runtime = null; runtime.exec("a " + p);',
    ];
    for (const form of forms) {
      const analysis = await run(handler(form));
      expect(kind(of(analysis, CMD)), form).toBe("critical/confirmed");
    }
  });

  it("recognizes the runtime by a getRuntime() call or by its declared type alone", async () => {
    const byCall = await run(
      java(
        SPRING,
        `Holder holder; interface Holder { Object getRuntime(); } void h(@RequestParam String p) throws Exception { holder.getRuntime().exec("a " + p); }`,
      ),
    );
    expect(kind(of(byCall, CMD))).toBe("critical/confirmed");
    const byType = await run(
      java(
        SPRING,
        `void h(Runtime proc, @RequestParam String p) throws Exception { proc.exec("a " + p); }`,
      ),
    );
    expect(kind(of(byType, CMD))).toBe("critical/confirmed");
    const split = await run(handler('Runtime.getRuntime().exec(p.split(" "));'));
    expect(of(split, CMD)[0]?.cause).toBe("Runtime.exec:program");
    const joined = await run(handler('Runtime.getRuntime().exec(("a " + p).split(" "));'));
    expect(of(joined, CMD)[0]?.cause).toMatch(/^Runtime\.exec:/);
  });

  it("notes an exec on some other receiver at low confidence only when request input reaches it", async () => {
    const other = await run(
      handler(
        'Shell s = null; s.exec("a " + p);',
        SPRING,
        "interface Shell { void exec(String c); }",
      ),
    );
    expect(kind(of(other, CMD))).toBe("inferred");
    expect(of(other, CMD)[0]?.evidence).toContain("receiver not recognized");
    const fixed = await run(
      handler('Shell s = null; s.exec("a");', SPRING, "interface Shell { void exec(String c); }"),
    );
    expect(of(fixed, CMD)).toEqual([]);
    const unknown = await run(
      java(
        SPRING,
        `interface Shell { void exec(String c); } void h(Shell s, String x) { s.exec("a " + x); }`,
      ),
    );
    expect(of(unknown, CMD)).toEqual([]);
  });

  it("reports a helper result, a value with no source and a bare parameter at low confidence", async () => {
    const helper = await run(
      handler(
        "String c = build(p); Runtime.getRuntime().exec(c);",
        SPRING,
        "String build(String s) { return s; }",
      ),
    );
    expect(kind(of(helper, CMD))).toBe("inferred");
    expect(of(helper, CMD)[0]?.evidence).toContain("build()");
    const own = await run(
      java(
        SPRING,
        `void h(String a, String b) throws Exception { Runtime.getRuntime().exec(a + " " + b); }`,
      ),
    );
    expect(kind(of(own, CMD))).toBe("untraced");
    const bare = await run(
      java(SPRING, `void h(String a) throws Exception { Runtime.getRuntime().exec(a); }`),
    );
    expect(of(bare, CMD)[0]).toMatchObject({ confidence: "low", severity: "medium" });
    expect(of(bare, CMD)[0]?.evidence).toContain("parameter");
    expect(of(bare, CMD)[0]?.evidence).toContain("callers not followed");
  });

  it("reports the result of an own method with no arguments at low confidence", async () => {
    const analysis = await run(
      java(
        SPRING,
        `String command() { return "ls"; } void h() throws Exception { Runtime.getRuntime().exec(command()); }`,
      ),
    );
    expect(kind(of(analysis, CMD))).toBe("inferred");
    expect(of(analysis, CMD)[0]?.evidence).toContain("command()");
  });

  it("reports a number or a constant from another file at low confidence, bare or in a longer string", async () => {
    const number = await run(
      java(
        SPRING,
        `void h(@RequestParam int n) throws Exception { Runtime.getRuntime().exec("ping -c " + n); }`,
      ),
    );
    expect(kind(of(number, CMD))).toBe("inferred");
    const bare = await run(
      java(SPRING, `void h() throws Exception { Runtime.getRuntime().exec(Config.COMMAND); }`),
    );
    expect(kind(of(bare, CMD))).toBe("inferred");
    const composed = await run(
      java(
        SPRING,
        `void h() throws Exception { Runtime.getRuntime().exec(Config.COMMAND + " -v"); }`,
      ),
    );
    expect(kind(of(composed, CMD))).toBe("inferred");
  });
});

describe("PG-CMD-003: argument lists", () => {
  const exec = (argv: string) => handler(`new ProcessBuilder(${argv}).start();`);

  it.each([
    ['"sh", "-c", "ls " + p', "sh -c script"],
    ['"bash", "-lc", p', "bash -lc script"],
    ['"/bin/sh", "-c", p', "sh -c script"],
    ['"zsh", "-c", p', "zsh -c script"],
    ['"cmd.exe", "/c", "dir " + p', "cmd /c script"],
    ['"cmd", "/S", "/C", "dir " + p', "cmd /C script"],
    ['"powershell", "-Command", p', "powershell -Command script"],
    ['"pwsh", "-c", p', "pwsh -c script"],
  ])("treats %s as a shell wrapper: critical", async (argv, label) => {
    const analysis = await run(exec(argv));
    const [finding] = of(analysis, CMD);
    expect(kind(of(analysis, CMD))).toBe("critical/confirmed");
    expect(finding?.evidence).toContain(label);
    expect(finding?.cause).toBe("ProcessBuilder:shell");
  });

  it("treats everything after `cmd /c` as the script, and only one argument after `sh -c`", async () => {
    const cmd = await run(exec('"cmd.exe", "/c", "echo", p'));
    expect(of(cmd, CMD)[0]).toMatchObject({ severity: "critical", cause: "ProcessBuilder:shell" });
    const sh = await run(exec('"sh", "-c", "echo", p'));
    expect(of(sh, CMD)[0]).toMatchObject({ severity: "medium", cause: "ProcessBuilder:argument" });
    const both = await run(exec('"sh", "-c", p, q'));
    expect(of(both, CMD)[0]).toMatchObject({ severity: "critical", cause: "ProcessBuilder:shell" });
  });

  it("looks for the flag only among switches", async () => {
    const analysis = await run(exec('"bash", "run.sh", "-c", p'));
    expect(of(analysis, CMD)[0]).toMatchObject({
      severity: "medium",
      cause: "ProcessBuilder:argument",
    });
  });

  it("treats a dynamic value where the flag should be as a shell script", async () => {
    const analysis = await run(exec('"sh", p'));
    expect(kind(of(analysis, CMD))).toBe("critical/confirmed");
  });

  it("does not call a shell with a script file a wrapper", async () => {
    const analysis = await run(exec('"bash", "run.sh", p'));
    expect(kind(of(analysis, CMD))).toBe("medium/suspected");
    expect(of(analysis, CMD)[0]?.cause).toBe("ProcessBuilder:argument");
  });

  it("reports the arguments after the script of `sh -c` as argument injection", async () => {
    const analysis = await run(exec('"sh", "-c", "echo $1", "sh", p'));
    expect(of(analysis, CMD)[0]).toMatchObject({
      severity: "medium",
      status: "suspected",
      confidence: "medium",
      cause: "ProcessBuilder:argument",
    });
  });

  it("reports a tainted argument of a fixed program as argument injection, not as a shell", async () => {
    const analysis = await run(exec('"git", "log", "--oneline", p'));
    const [finding] = of(analysis, CMD);
    expect(of(analysis, CMD)).toHaveLength(1);
    expect(finding).toMatchObject({
      severity: "medium",
      status: "suspected",
      confidence: "medium",
    });
    expect(finding?.evidence).toContain("argument injection");
    expect(finding?.evidence).toContain("argument of git");
  });

  it("reports a tainted program name as critical", async () => {
    const analysis = await run(exec('p, "--version"'));
    expect(of(analysis, CMD)[0]).toMatchObject({
      severity: "critical",
      cause: "ProcessBuilder:program",
    });
  });

  it("keeps a value after `--` at low confidence and one before it at medium", async () => {
    const after = await run(exec('"grep", "-r", "--", p, "/var/log"'));
    expect(kind(of(after, CMD))).toBe("inferred");
    expect(of(after, CMD)[0]?.evidence).toContain("--");
    const before = await run(exec('"grep", "-r", p, "--", "/var/log"'));
    expect(kind(of(before, CMD))).toBe("medium/suspected");
    const endOfOptions = await run(exec('"git", "log", "--end-of-options", p'));
    expect(kind(of(endOfOptions, CMD))).toBe("inferred");
  });

  it("reports one finding per call: the strongest", async () => {
    const analysis = await run(exec('p, "-x", q'));
    expect(of(analysis, CMD)).toHaveLength(1);
    expect(of(analysis, CMD)[0]?.severity).toBe("critical");
  });

  it("does not report a fixed argument list", async () => {
    const analysis = await run(exec('"git", "log", "--oneline"'));
    expect(of(analysis, CMD)).toEqual([]);
  });

  it("reports a number argument at low severity and an unknown one at low confidence", async () => {
    const number = await run(
      java(
        SPRING,
        `void h(@RequestParam int n) throws Exception { new ProcessBuilder("tail", "-n", "" + n, "f").start(); }`,
      ),
    );
    expect(of(number, CMD)[0]).toMatchObject({ severity: "low", confidence: "low" });
    const unknown = await run(
      java(
        SPRING,
        `void h(String a) throws Exception { new ProcessBuilder("tail", "x" + a).start(); }`,
      ),
    );
    expect(of(unknown, CMD)[0]).toMatchObject({ severity: "low", confidence: "low" });
  });

  it("reads argument lists written as array initializers, Arrays.asList and List.of", async () => {
    const forms = [
      'Runtime.getRuntime().exec(new String[] {"sh", "-c", p});',
      'new ProcessBuilder(Arrays.asList("sh", "-c", p)).start();',
      'new ProcessBuilder(List.of("sh", "-c", p)).start();',
      'String[] c = {"sh", "-c", p}; Runtime.getRuntime().exec(c);',
      'List<String> c = Arrays.asList("sh", "-c", p); new ProcessBuilder(c).start();',
      'new ProcessBuilder(new ArrayList<>(Arrays.asList("sh", "-c", p))).start();',
    ];
    for (const form of forms) {
      const analysis = await run(handler(form));
      expect(kind(of(analysis, CMD)), form).toBe("critical/confirmed");
      expect(of(analysis, CMD)[0]?.cause, form).toMatch(/:shell$/);
    }
  });

  it("follows a list that is filled in steps", async () => {
    const added = await run(
      handler(
        'List<String> c = new ArrayList<>(); c.add("convert"); c.add(p); new ProcessBuilder(c).start();',
      ),
    );
    expect(of(added, CMD)[0]).toMatchObject({
      severity: "medium",
      cause: "ProcessBuilder:argument",
    });
    const shell = await run(
      handler(
        'List<String> c = new ArrayList<>(); c.add("sh"); c.add("-c"); c.add(p); new ProcessBuilder(c).start();',
      ),
    );
    expect(of(shell, CMD)[0]).toMatchObject({
      severity: "critical",
      cause: "ProcessBuilder:shell",
    });
    const first = await run(
      handler(
        'List<String> c = new ArrayList<>(); c.add(p); c.add("-v"); new ProcessBuilder(c).start();',
      ),
    );
    expect(of(first, CMD)[0]).toMatchObject({
      severity: "critical",
      cause: "ProcessBuilder:program",
    });
    const all = await run(
      handler(
        'List<String> c = new ArrayList<>(List.of("sh", "-c")); c.addAll(List.of(p)); new ProcessBuilder(c).start();',
      ),
    );
    expect(of(all, CMD)[0]).toMatchObject({ severity: "critical", cause: "ProcessBuilder:shell" });
    const collections = await run(
      handler(
        'List<String> c = new ArrayList<>(); Collections.addAll(c, "convert", p); new ProcessBuilder(c).start();',
      ),
    );
    expect(of(collections, CMD)[0]).toMatchObject({ severity: "medium" });
  });

  it("sees what a later iteration puts into a list that an earlier statement of the loop uses", async () => {
    const analysis = await run(
      handler(
        'List<String> c = new ArrayList<>(); c.add("convert"); for (int i = 0; i < 2; i++) { new ProcessBuilder(c).start(); c.add(p); }',
      ),
    );
    expect(of(analysis, CMD)[0]).toMatchObject({
      severity: "medium",
      cause: "ProcessBuilder:argument",
    });
    const array = await run(
      handler(
        'String[] c = new String[2]; c[0] = "convert"; for (int i = 0; i < 2; i++) { Runtime.getRuntime().exec(c); c[1] = p; }',
      ),
    );
    expect(of(array, CMD)[0]).toMatchObject({ severity: "medium" });
  });

  it("does not report a list of constants that was filled in steps", async () => {
    const analysis = await run(
      handler(
        'List<String> c = new ArrayList<>(); c.add("ls"); c.add("-l"); new ProcessBuilder(c).start();',
      ),
    );
    expect(of(analysis, CMD)).toEqual([]);
    const array = await run(
      handler(
        'String[] c = new String[2]; c[0] = "ls"; c[1] = "-l"; Runtime.getRuntime().exec(c);',
      ),
    );
    expect(of(array, CMD)).toEqual([]);
  });

  it("follows an array filled by index", async () => {
    const analysis = await run(
      handler(
        'String[] c = new String[3]; c[0] = "convert"; c[1] = p; c[2] = "o.png"; Runtime.getRuntime().exec(c);',
      ),
    );
    expect(of(analysis, CMD)[0]).toMatchObject({
      severity: "medium",
      cause: "Runtime.exec:argument",
    });
  });

  it("reports an argument list that is a bare parameter at low confidence", async () => {
    const analysis = await run(
      java(
        SPRING,
        "void h(List<String> c, String[] d) throws Exception { new ProcessBuilder(c).start(); Runtime.getRuntime().exec(d); }",
      ),
    );
    expect(of(analysis, CMD)).toHaveLength(2);
    expect(of(analysis, CMD).every((finding) => finding.confidence === "low")).toBe(true);
  });

  it("reports a split command line", async () => {
    const analysis = await run(handler('Runtime.getRuntime().exec(p.split(" "));'));
    expect(kind(of(analysis, CMD))).toBe("critical/confirmed");
  });
});

describe("PG-CMD-003: ProcessBuilder.command and Commons Exec", () => {
  it("reads command(...) on a ProcessBuilder by type, value or construction", async () => {
    const forms = [
      'ProcessBuilder pb = new ProcessBuilder(); pb.command("sh", "-c", p);',
      'var pb = new ProcessBuilder(); pb.command("sh", "-c", p);',
      'new ProcessBuilder().command("sh", "-c", p);',
      'ProcessBuilder pb = new ProcessBuilder("x"); pb.command(Arrays.asList("sh", "-c", p));',
    ];
    for (const form of forms) {
      const analysis = await run(handler(form));
      expect(of(analysis, CMD)[0], form).toMatchObject({ severity: "critical" });
    }
  });

  it("reads exec and command without a receiver or on a variable of unknown type, in a file that runs processes", async () => {
    const kotlinApply = await run(
      kotlin('ProcessBuilder().apply { command("git", "log", p) }.start()'),
      "K.kt",
    );
    expect(of(kotlinApply, CMD)[0]).toMatchObject({ severity: "medium" });
    const kotlinShell = await run(
      kotlin(
        'ProcessBuilder().also { it.command("ls", p) }.start(); with(Runtime.getRuntime()) { exec("ls " + p) }',
      ),
      "K.kt",
    );
    expect(
      of(kotlinShell, CMD)
        .map((finding) => finding.severity)
        .sort(),
    ).toEqual(["critical", "medium"]);
    const apply = await run(
      kotlin('Runtime.getRuntime().apply { exec(arrayOf("sh", "-c", p)) }'),
      "K.kt",
    );
    expect(of(apply, CMD)[0]).toMatchObject({ severity: "critical", cause: "Runtime.exec:shell" });
    const unknownType = await run(
      java(
        SPRING,
        `Object make() { return null; } void h(@RequestParam String p) { var r = make(); Runtime.getRuntime(); r.exec("ls " + p); }`,
      ),
    );
    expect(of(unknownType, CMD)[0]).toMatchObject({ severity: "critical" });
    const unrelated = await run(
      kotlin('val s = Shell(); s.exec("ls " + p); s.command("a", p)'),
      "K.kt",
    );
    expect(of(unrelated, CMD).every((finding) => finding.confidence === "low")).toBe(true);
    expect(of(unrelated, CMD).some((finding) => finding.cause === "exec:unrecognized")).toBe(true);
  });

  it("reads command(...) on a variable of unknown type in a file that makes a ProcessBuilder", async () => {
    const analysis = await run(
      java(
        SPRING,
        `Object make() { return null; }
         void h(@RequestParam String p) throws Exception {
           new ProcessBuilder("ls").start();
           var other = make();
           other.command("git", "log", p);
         }`,
      ),
    );
    expect(of(analysis, CMD).map((finding) => finding.cause)).toEqual([
      "ProcessBuilder.command:argument",
    ]);
    expect(of(analysis, CMD)[0]?.confidence).toBe("medium");
    const unrelated = await run(
      java(
        SPRING,
        `Object make() { return null; } void h(@RequestParam String p) { var other = make(); other.command("git", "log", p); }`,
      ),
    );
    // The receiver's type is not written down: a low note, for request input only.
    expect(of(unrelated, CMD).map((finding) => finding.cause)).toEqual(["command:unrecognized"]);
    expect(of(unrelated, CMD)[0]?.confidence).toBe("low");
  });

  it("reads command(...) on a ProcessBuilder made earlier or in the same expression", async () => {
    const value = await run(handler('var pb = new ProcessBuilder(); pb.command("git", "log", p);'));
    expect(of(value, CMD)[0]).toMatchObject({
      severity: "medium",
      cause: "ProcessBuilder.command:argument",
    });
    const made = await run(handler('new ProcessBuilder().command("git", "log", p);'));
    expect(of(made, CMD)[0]).toMatchObject({
      severity: "medium",
      cause: "ProcessBuilder.command:argument",
    });
    const typed = await run(
      java(
        SPRING,
        `void h(ProcessBuilder b, @RequestParam String p) { b.command("git", "log", p); }`,
      ),
    );
    expect(of(typed, CMD)[0]).toMatchObject({ severity: "medium" });
  });

  it("reads a shell wrapper in command(...) whatever the receiver is", async () => {
    const analysis = await run(
      java(
        SPRING,
        `Object make() { return null; } void h(@RequestParam String p) { var pb = make(); pb.command("sh", "-c", p); }`,
      ),
    );
    expect(of(analysis, CMD)[0]).toMatchObject({ severity: "critical" });
  });

  it("does not read command(...) on something that is not a ProcessBuilder", async () => {
    const analysis = await run(
      java(
        SPRING,
        `interface Cmd { void command(String a, String b); } void h(@RequestParam String p, Cmd c) { c.command("a", p); }`,
      ),
    );
    expect(of(analysis, CMD)).toEqual([]);
  });

  it("reads additions to pb.command()", async () => {
    const add = await run(
      handler('ProcessBuilder pb = new ProcessBuilder("ls"); pb.command().add(p);'),
    );
    expect(of(add, CMD)[0]).toMatchObject({
      severity: "medium",
      cause: "ProcessBuilder.command:argument",
    });
    const all = await run(
      handler(
        'ProcessBuilder pb = new ProcessBuilder("ls"); pb.command().addAll(Arrays.asList("sh", "-c", p));',
      ),
    );
    expect(of(all, CMD)[0]).toMatchObject({ severity: "critical" });
    const fixed = await run(
      handler('ProcessBuilder pb = new ProcessBuilder("ls"); pb.command().add("-l");'),
    );
    expect(of(fixed, CMD)).toEqual([]);
  });

  const EXEC = "import org.apache.commons.exec.*;\n";

  it("reports CommandLine.parse like exec(String), and a new CommandLine program as a program", async () => {
    const parse = await run(
      handler('CommandLine l = CommandLine.parse("nslookup " + p);', SPRING + EXEC),
    );
    expect(of(parse, CMD)[0]).toMatchObject({
      severity: "critical",
      cause: "CommandLine.parse:string",
    });
    const program = await run(handler("CommandLine l = new CommandLine(p);", SPRING + EXEC));
    expect(of(program, CMD)[0]).toMatchObject({
      severity: "critical",
      cause: "CommandLine:program",
    });
    const fixed = await run(handler('CommandLine l = CommandLine.parse("uptime");', SPRING + EXEC));
    expect(of(fixed, CMD)).toEqual([]);
  });

  it("reports addArgument as argument injection, and addArgument(x, false) as high", async () => {
    const quoted = await run(
      handler('CommandLine l = new CommandLine("convert"); l.addArgument(p);', SPRING + EXEC),
    );
    expect(of(quoted, CMD)[0]).toMatchObject({ severity: "medium", confidence: "medium" });
    const raw = await run(
      handler(
        'CommandLine l = new CommandLine("convert"); l.addArgument(p, false);',
        SPRING + EXEC,
      ),
    );
    expect(of(raw, CMD)[0]).toMatchObject({ severity: "high", confidence: "medium" });
    expect(of(raw, CMD)[0]?.evidence).toContain("quoting off");
    const explicitTrue = await run(
      handler('CommandLine l = new CommandLine("convert"); l.addArgument(p, true);', SPRING + EXEC),
    );
    expect(of(explicitTrue, CMD)[0]).toMatchObject({ severity: "medium" });
    const chain = await run(
      handler(
        'new CommandLine("convert").addArgument(p, false).addArgument("o.png");',
        SPRING + EXEC,
      ),
    );
    expect(of(chain, CMD)[0]).toMatchObject({ severity: "high" });
    const fixed = await run(
      handler(
        'CommandLine l = new CommandLine("convert"); l.addArgument("a.png", false);',
        SPRING + EXEC,
      ),
    );
    expect(of(fixed, CMD)).toEqual([]);
  });

  it("reads addArgument only where Commons Exec is imported", async () => {
    const analysis = await run(
      handler(
        "Builder b = null; b.addArgument(p, false);",
        SPRING,
        "interface Builder { Builder addArgument(String a, boolean b); }",
      ),
    );
    expect(of(analysis, CMD)).toEqual([]);
  });
});

describe("PG-CMD-003: checks on the input", () => {
  it("demotes a value that passed an allowlist check to low, with `; inferred`", async () => {
    const forms = [
      "if (!TOOLS.contains(p)) throw new IllegalArgumentException(); Runtime.getRuntime().exec(p);",
      "if (TOOLS.contains(p)) { Runtime.getRuntime().exec(p); }",
      'String c = TOOLS.contains(p) ? p : "ls"; Runtime.getRuntime().exec(c);',
    ];
    for (const form of forms) {
      const analysis = await run(
        handler(form, SPRING, 'static final Set<String> TOOLS = Set.of("a", "b");'),
      );
      expect(kind(of(analysis, CMD)), form).toBe("inferred");
      expect(of(analysis, CMD)[0]?.evidence.endsWith("; inferred"), form).toBe(true);
    }
  });

  it("does not let a check on another variable demote the one that is used", async () => {
    const analysis = await run(
      handler(
        "if (!TOOLS.contains(q)) throw new IllegalArgumentException(); Runtime.getRuntime().exec(p);",
        SPRING,
        'static final Set<String> TOOLS = Set.of("a", "b");',
      ),
    );
    expect(kind(of(analysis, CMD))).toBe("critical/confirmed");
  });

  it("does not keep the check after the value is assigned again", async () => {
    const analysis = await run(
      handler(
        "if (!TOOLS.contains(p)) throw new IllegalArgumentException(); String c = p; c = q; Runtime.getRuntime().exec(c);",
        SPRING,
        'static final Set<String> TOOLS = Set.of("a", "b");',
      ),
    );
    expect(kind(of(analysis, CMD))).toBe("critical/suspected");
  });

  it("does not take a check inside a branch for the code after it", async () => {
    const analysis = await run(
      handler(
        "if (TOOLS.contains(p)) { System.out.println(p); } Runtime.getRuntime().exec(p);",
        SPRING,
        'static final Set<String> TOOLS = Set.of("a", "b");',
      ),
    );
    expect(kind(of(analysis, CMD))).toBe("critical/confirmed");
  });

  it("takes a lookup in a fixed table as inferred", async () => {
    const analysis = await run(
      handler(
        'String tool = TOOLS.get(p); new ProcessBuilder(tool, "-v").start();',
        SPRING,
        'static final Map<String, String> TOOLS = Map.of("a", "gzip");',
      ),
    );
    expect(kind(of(analysis, CMD))).toBe("inferred");
  });
});

describe("PG-CMD-003: Kotlin", () => {
  it.each([
    ['Runtime.getRuntime().exec("ls $p")', "critical/confirmed"],
    ['Runtime.getRuntime().exec(arrayOf("sh", "-c", p))', "critical/confirmed"],
    ['ProcessBuilder("sh", "-c", "ls ${p}").start()', "critical/confirmed"],
    ['ProcessBuilder(listOf("git", "log", p)).start()', "medium/suspected"],
    ['ProcessBuilder(*arrayOf("git", "log", p)).start()', "medium/suspected"],
    [
      'val c = mutableListOf("sh", "-c"); c.add(p); ProcessBuilder(c).start()',
      "critical/confirmed",
    ],
    ['val pb = ProcessBuilder(); pb.command("sh", "-c", p)', "critical/confirmed"],
    ["ProcessBuilder(p).start()", "critical/confirmed"],
  ])("reports %s", async (code, expected) => {
    const analysis = await run(kotlin(code), "K.kt");
    expect(kind(of(analysis, CMD)), code).toBe(expected);
  });

  it("does not report fixed Kotlin commands", async () => {
    const analysis = await run(
      kotlin(
        'Runtime.getRuntime().exec("uptime"); ProcessBuilder("git", "log").start(); ProcessBuilder(listOf("ls", "-l")).start()',
      ),
      "K.kt",
    );
    expect(of(analysis, CMD)).toEqual([]);
  });

  it("reads Commons Exec in Kotlin", async () => {
    const analysis = await run(
      kotlin(
        'val l = CommandLine.parse("traceroute $p")',
        "import org.apache.commons.exec.CommandLine",
      ),
      "K.kt",
    );
    expect(kind(of(analysis, CMD))).toBe("critical/confirmed");
  });

  it("reads the Ktor call parameters", async () => {
    const analysis = await run(
      `import io.ktor.server.routing.*
fun Route.r() {
    get("/x") {
        val host = call.parameters["host"]!!
        ProcessBuilder("sh", "-c", "ping $host").start()
    }
}
`,
      "K.kt",
    );
    expect(kind(of(analysis, CMD))).toBe("critical/suspected");
  });
});

describe("PG-CMD-003: coverage", () => {
  it("lists anonymous classes, local classes and Kotlin local forms that run a process", async () => {
    const anonymous = await run(
      java(
        SPRING,
        `void h() { Runnable r = new Runnable() { public void run() { try { Runtime.getRuntime().exec("x"); } catch (Exception e) {} } }; }`,
      ),
    );
    expect(anonymous.unsupportedForms).toContain("anonymous class");
    const local = await run(
      java(
        SPRING,
        `void h() { class L { void f() throws Exception { new ProcessBuilder("a").start(); } } }`,
      ),
    );
    expect(local.unsupportedForms).toContain("local class");
    const kotlinLocal = await run(
      `package a\nfun f() {\n  fun inner(p: String) { ProcessBuilder("sh", "-c", p).start() }\n  val o = object : Runnable { override fun run() { Runtime.getRuntime().exec("x") } }\n}\n`,
      "K.kt",
    );
    expect(kotlinLocal.unsupportedForms).toEqual(
      expect.arrayContaining(["local function", "anonymous object"]),
    );
  });

  it("does not list an anonymous class with nothing to follow", async () => {
    const analysis = await run(
      java(
        SPRING,
        `void h() { Runnable r = new Runnable() { public void run() { System.out.println("x"); } }; }`,
      ),
    );
    expect(analysis.unsupportedForms).toEqual([]);
  });

  it("names process and file libraries the rules do not follow", async () => {
    const zt = await run(java("import org.zeroturnaround.exec.ProcessExecutor;\n", "int x;"));
    expect(zt.unsupportedOsLibraries).toEqual([{ label: "zt-exec", kind: "process" }]);
    const okio = await run(java("import okio.FileSystem;\nimport okio.Path;\n", "int x;"));
    expect(okio.unsupportedOsLibraries).toEqual([{ label: "Okio", kind: "file" }]);
    const none = await run(java(SPRING, "int x;"));
    expect(none.unsupportedOsLibraries).toEqual([]);
  });
});

// ====================================================================== paths

describe("PG-PATH-002: where a path is reported", () => {
  it("reports a path once, where it is used, not where it was made", async () => {
    const analysis = await run(
      handler('File f = new File("/srv/" + p); new FileInputStream(f).close();'),
    );
    const found = of(analysis, PATH);
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({
      severity: "high",
      status: "suspected",
      confidence: "high",
      cause: "FileInputStream",
    });
  });

  it("reports a path that is never used where it was made", async () => {
    const forms: Array<[string, string]> = [
      ['return new File("/srv/" + p);', "new File"],
      ['Paths.get("/srv", p);', "Paths.get"],
      ["Path.of(p);", "Path.of"],
      ['Paths.get("/srv").resolve(p);', "Path.resolve"],
      ['Paths.get("/srv").resolveSibling(p);', "Path.resolveSibling"],
      ['getServletContext().getRealPath("/a/" + p);', "ServletContext.getRealPath"],
    ];
    for (const [code, cause] of forms) {
      const analysis = await run(
        java(
          SPRING,
          `ServletContext getServletContext() { return null; } Object h(@RequestParam String p) throws Exception { ${code} }`,
        ),
      );
      expect(
        of(analysis, PATH).map((finding) => finding.cause),
        code,
      ).toContain(cause);
      expect(kind(of(analysis, PATH)), code).toMatch(/^high\//);
    }
  });

  it("reports a path stored, returned or handed to another method", async () => {
    const stored = await run(
      java(SPRING, `File saved; void h(@RequestParam String p) { saved = new File("/srv/" + p); }`),
    );
    expect(kind(of(stored, PATH))).toBe("high/confirmed");
    const passed = await run(
      java(
        SPRING,
        `void use(File f) {} void h(@RequestParam String p) { use(new File("/srv/" + p)); }`,
      ),
    );
    expect(kind(of(passed, PATH))).toBe("high/confirmed");
    const field = await run(java(SPRING, `final File f = new File(System.getProperty("x"));`));
    expect(of(field, PATH).every((finding) => finding.confidence === "low")).toBe(true);
  });

  it.each([
    ["Files.readAllBytes", "Files.readAllBytes(Paths.get(p));"],
    ["Files.readString", "Files.readString(Path.of(p));"],
    ["Files.readAllLines", "Files.readAllLines(Path.of(p));"],
    ["Files.lines", "Files.lines(Path.of(p)).close();"],
    ["Files.newInputStream", "Files.newInputStream(Path.of(p));"],
    ["Files.newOutputStream", "Files.newOutputStream(Path.of(p));"],
    ["Files.newBufferedReader", "Files.newBufferedReader(Path.of(p));"],
    ["Files.newBufferedWriter", "Files.newBufferedWriter(Path.of(p));"],
    ["Files.write", "Files.write(Path.of(p), new byte[0]);"],
    ["Files.writeString", 'Files.writeString(Path.of(p), "x");'],
    ["Files.delete", "Files.delete(Path.of(p));"],
    ["Files.deleteIfExists", "Files.deleteIfExists(Path.of(p));"],
    ["Files.createFile", "Files.createFile(Path.of(p));"],
    ["Files.createDirectories", "Files.createDirectories(Path.of(p));"],
    ["Files.list", "Files.list(Path.of(p));"],
    ["Files.walk", "Files.walk(Path.of(p));"],
    ["Files.copy", 'Files.copy(Path.of(p), Path.of("/tmp/x"));'],
    ["Files.copy", 'Files.copy(Path.of("/tmp/x"), Path.of(p));'],
    ["Files.copy", "Files.copy(System.in, Path.of(p));"],
    ["Files.move", 'Files.move(Path.of("/tmp/x"), Path.of(p));'],
    ["FileInputStream", "new FileInputStream(p);"],
    ["FileOutputStream", "new FileOutputStream(p);"],
    ["FileReader", "new FileReader(p);"],
    ["FileWriter", "new FileWriter(p);"],
    ["RandomAccessFile", 'new RandomAccessFile(p, "r");'],
    ["File.delete", "new File(p).delete();"],
    ["File.mkdirs", "new File(p).mkdirs();"],
    ["File.listFiles", "new File(p).listFiles();"],
    ["File.renameTo", 'new File(p).renameTo(new File("/tmp/y"));'],
    ["FileUtils.readFileToString", "FileUtils.readFileToString(new File(p));"],
    ["FileUtils.copyFile", 'FileUtils.copyFile(new File("/tmp/x"), new File(p));'],
    ["FileUtils.deleteDirectory", "FileUtils.deleteDirectory(new File(p));"],
    [
      "ResourceLoader.getResource",
      'ResourceLoader loader = null; loader.getResource("file:" + p);',
    ],
  ])("reports %s at the call that uses the path", async (cause, code) => {
    const analysis = await run(
      handler(
        code,
        `${SPRING}import org.apache.commons.io.FileUtils;\nimport org.springframework.core.io.ResourceLoader;\n`,
      ),
    );
    const found = of(analysis, PATH);
    expect(found.map((finding) => finding.cause)).toContain(cause);
    expect(
      found.every((finding) => finding.severity === "high" && finding.confidence === "high"),
      code,
    ).toBe(true);
  });

  it("reports Files.exists, isDirectory and size at low confidence, once each (no content is read or changed)", async () => {
    const analysis = await run(
      handler("Files.exists(Path.of(p)); Files.isDirectory(Path.of(p)); Files.size(Path.of(p));"),
    );
    expect(
      of(analysis, PATH)
        .map((finding) => finding.cause)
        .sort(),
    ).toEqual(["Files.exists", "Files.isDirectory", "Files.size"]);
    expect(
      of(analysis, PATH).every(
        (finding) => finding.confidence === "low" && finding.severity === "low",
      ),
    ).toBe(true);
    const file = await run(handler("new File(p).exists(); new File(q).length();"));
    expect(
      of(file, PATH)
        .map((finding) => finding.cause)
        .sort(),
    ).toEqual(["File.exists", "File.length"]);
  });

  it("reports one finding for a chain of path operations", async () => {
    const analysis = await run(
      handler(
        'Files.readString(Paths.get("/srv").resolve(p).resolve(q).normalize().toAbsolutePath());',
      ),
    );
    expect(of(analysis, PATH)).toHaveLength(1);
    expect(of(analysis, PATH)[0]?.cause).toBe("Files.readString");
  });

  it("reports one finding for either branch of a conditional path", async () => {
    const analysis = await run(
      handler(
        'File f = p.isEmpty() ? new File("/a/" + p) : new File("/b/" + q); f.delete(); new FileInputStream(f).close();',
      ),
    );
    expect(
      of(analysis, PATH)
        .map((finding) => finding.cause)
        .sort(),
    ).toEqual(["File.delete", "FileInputStream"]);
  });

  it("reports a path built in a loop once per use", async () => {
    const analysis = await run(
      handler('for (int i = 0; i < 3; i++) { File f = new File("/srv/" + p + i); f.delete(); }'),
    );
    expect(of(analysis, PATH)).toHaveLength(1);
  });

  it("reports a path built in a lambda", async () => {
    const analysis = await run(handler('List.of(p).forEach(n -> new File("/srv", n).delete());'));
    expect(kind(of(analysis, PATH))).toBe("high/suspected");
  });
});

describe("PG-PATH-002: fixed values and untraced values", () => {
  it("does not report fixed paths or constants", async () => {
    const analysis = await run(
      java(
        SPRING,
        `static final String DIR = "/etc/app";
         static final Path ROOT = Paths.get("/srv");
         void h() throws Exception {
           new File("/etc/hosts").delete();
           new File(DIR, "a.properties").delete();
           Files.readAllBytes(Paths.get(DIR + "/b"));
           Files.readAllBytes(ROOT.resolve("c"));
         }`,
      ),
    );
    expect(of(analysis, PATH)).toEqual([]);
  });

  it("reports a field that can change as unknown", async () => {
    const analysis = await run(
      java(SPRING, `String dir = "/etc"; void h() { new File(dir, "x").delete(); }`),
    );
    expect(kind(of(analysis, PATH))).toBe("untraced");
  });

  it("reports a path made of own parameters, and a lone parameter, at low confidence", async () => {
    const two = await run(
      java(SPRING, "void h(File dir, String name) { new File(dir, name).delete(); }"),
    );
    expect(kind(of(two, PATH))).toBe("untraced");
    const one = await run(java(SPRING, "void h(String name) { new File(name).delete(); }"));
    expect(of(one, PATH)[0]).toMatchObject({ confidence: "low", severity: "low" });
    expect(of(one, PATH)[0]?.evidence).toContain("callers not followed");
  });

  it("reports a helper result at low confidence", async () => {
    const analysis = await run(
      handler("new File(clean(p)).delete();", SPRING, "String clean(String s) { return s; }"),
    );
    expect(kind(of(analysis, PATH))).toBe("inferred");
    expect(of(analysis, PATH)[0]?.evidence).toContain("clean()");
  });

  it("reports a number or UUID at low confidence, bare or inside a longer path", async () => {
    const number = await run(
      java(SPRING, 'void h(@RequestParam long id) { new File("/srv", id + ".pdf").delete(); }'),
    );
    expect(kind(of(number, PATH))).toBe("inferred");
    const bare = await run(
      java(SPRING, "void h(@RequestParam long id) { new File(Long.toString(id)).delete(); }"),
    );
    expect(kind(of(bare, PATH))).toBe("inferred");
  });

  it("does not report a stream first argument of Files.copy", async () => {
    const analysis = await run(
      java(
        SPRING,
        'void h(java.util.zip.ZipFile z, java.util.zip.ZipEntry e) throws Exception { Files.copy(z.getInputStream(e), Paths.get("/srv/fixed")); }',
      ),
    );
    expect(of(analysis, PATH)).toEqual([]);
  });

  it("does not take resolve(...) on a DNS-like receiver for a path", async () => {
    const analysis = await run(
      java(
        SPRING,
        "interface R { String resolve(String s); } void h(@RequestParam String p, R resolver) { resolver.resolve(p); }",
      ),
    );
    expect(of(analysis, PATH)).toEqual([]);
  });

  it("takes a resolve on a path-like receiver by its name or its declared type", async () => {
    const byName = await run(
      java(
        SPRING,
        `interface Cfg { Object getRoot(); } void h(Cfg cfg, @RequestParam String p) { cfg.getRoot().resolve(p); }`,
      ),
    );
    expect(kind(of(byName, PATH))).toBe("high/confirmed");
    const byType = await run(
      java(SPRING, "void h(Path x, @RequestParam String p) { x.resolve(p); }"),
    );
    expect(kind(of(byType, PATH))).toBe("high/confirmed");
    const byFile = await run(
      java(SPRING, "void h(File x, @RequestParam String p) { x.toPath().resolve(p); }"),
    );
    expect(kind(of(byFile, PATH))).toBe("high/confirmed");
  });

  it("notes a resolve on a receiver of unknown type at low confidence", async () => {
    const analysis = await run(
      java(
        SPRING,
        "Object make() { return null; } void h(@RequestParam String p) { var x = make(); x.resolve(p); }",
      ),
    );
    expect(kind(of(analysis, PATH))).toBe("inferred");
    expect(of(analysis, PATH)[0]?.evidence).toContain("receiver not known to be a path");
  });
});

describe("PG-PATH-002: path guards", () => {
  const BASE = 'final Path base = Paths.get("/srv").toAbsolutePath().normalize();';
  const guarded = [
    "Path x = base.resolve(p).normalize(); if (!x.startsWith(base)) throw new SecurityException(); Files.readAllBytes(x);",
    "Path x = base.resolve(p).normalize(); if (x.startsWith(base)) { Files.readAllBytes(x); }",
    "Path x = base.resolve(p).normalize(); if (!x.startsWith(base)) { return; } Files.readAllBytes(x);",
    "Path x = base.resolve(p); if (!x.normalize().startsWith(base)) throw new SecurityException(); Files.readAllBytes(x);",
    "if (!base.resolve(p).normalize().startsWith(base)) throw new SecurityException(); Files.readAllBytes(base.resolve(p));",
    "Path x = base.resolve(p).toRealPath(); if (!x.startsWith(base)) throw new SecurityException(); Files.readAllBytes(x);",
    "Path x = base.resolve(p).normalize(); assert x.startsWith(base); Files.readAllBytes(x);",
    "Path x = base.resolve(p).normalize(); Files.readAllBytes(x.startsWith(base) ? x : base);",
    'File f = new File("/srv", p); if (!f.getCanonicalPath().startsWith("/srv/")) throw new IOException(); new FileInputStream(f).close();',
    'File f = new File("/srv", p); String c = f.getCanonicalPath(); if (!c.startsWith("/srv/")) throw new IOException(); new FileInputStream(f).close();',
    'File f = new File("/srv", p); File c = f.getCanonicalFile(); if (!c.toPath().startsWith("/srv/")) throw new IOException(); new FileInputStream(f).close();',
    'if (p.contains("..")) { return; } Files.readAllBytes(base.resolve(p));',
    'if (p.contains("..") || p.contains("/")) throw new SecurityException(); Files.readAllBytes(base.resolve(p));',
    'if (!p.contains("..")) { Files.readAllBytes(base.resolve(p)); }',
  ];

  it.each(guarded)("demotes to low, with `; inferred`: %s", async (code) => {
    const analysis = await run(handler(code, SPRING, BASE));
    const found = of(analysis, PATH);
    expect(found.length, code).toBeGreaterThan(0);
    expect(
      found.every(
        (finding) => finding.confidence === "low" && finding.evidence.endsWith("; inferred"),
      ),
      code,
    ).toBe(true);
  });

  const unguarded = [
    // not canonical: a prefix test on an unresolved path
    "Path x = base.resolve(p); if (!x.startsWith(base)) throw new SecurityException(); Files.readAllBytes(x);",
    'Path x = base.resolve(p); if (!x.toString().startsWith("/srv")) throw new SecurityException(); Files.readAllBytes(x);',
    // a different variable is checked
    "Path x = base.resolve(p).normalize(); Path y = base.resolve(q).normalize(); if (!y.startsWith(base)) throw new SecurityException(); Files.readAllBytes(x);",
    "Path y = base.resolve(q).normalize(); if (!y.startsWith(base)) throw new SecurityException(); Files.readAllBytes(base.resolve(p));",
    'if (q.contains("..")) { return; } Files.readAllBytes(base.resolve(p));',
    'File f = new File("/srv", p); File g = new File("/srv", q); if (!g.getCanonicalPath().startsWith("/srv/")) throw new IOException(); new FileInputStream(f).close();',
    // the use is another variable, made again from the same input
    "Path x = base.resolve(p); if (!base.resolve(p).normalize().startsWith(base)) throw new SecurityException(); Files.readAllBytes(x);",
    // the check does not cover the use
    "Path x = base.resolve(p).normalize(); if (x.startsWith(base)) { System.out.println(); } Files.readAllBytes(x);",
    "Path x = base.resolve(p).normalize(); if (!x.startsWith(base)) { System.out.println(); } Files.readAllBytes(x);",
    "Path x = base.resolve(p).normalize(); Files.readAllBytes(x); if (!x.startsWith(base)) throw new SecurityException();",
    'if (p.contains("..")) { System.out.println(); } Files.readAllBytes(base.resolve(p));',
    // the value is replaced after the check
    "Path x = base.resolve(p).normalize(); if (!x.startsWith(base)) throw new SecurityException(); x = base.resolve(q); Files.readAllBytes(x);",
    // the check is on the base
    'Path x = base.resolve(p).normalize(); if (!base.startsWith("/srv")) throw new SecurityException(); Files.readAllBytes(x);',
  ];

  it.each(unguarded)("keeps it high: %s", async (code) => {
    const analysis = await run(handler(code, SPRING, BASE));
    expect(
      of(analysis, PATH).some((finding) => finding.confidence === "high"),
      code,
    ).toBe(true);
  });

  it("demotes a path that is checked and then only returned or stored", async () => {
    const returned = await run(
      java(
        SPRING,
        `final Path base = Paths.get("/srv").toAbsolutePath().normalize();
         Path h(@RequestParam String p) { Path x = base.resolve(p).normalize(); if (!x.startsWith(base)) throw new SecurityException(); return x; }`,
      ),
    );
    expect(kind(of(returned, PATH))).toBe("inferred");
    const unchecked = await run(
      java(
        SPRING,
        `final Path base = Paths.get("/srv").toAbsolutePath().normalize();
         Path h(@RequestParam String p) { Path x = base.resolve(p).normalize(); return x; }`,
      ),
    );
    expect(kind(of(unchecked, PATH))).toBe("high/confirmed");
  });

  it("demotes a check on a value that has no known source too", async () => {
    const analysis = await run(
      java(
        SPRING,
        'void h(String name) { if (name.contains("..")) return; new File("/srv", name).delete(); }',
      ),
    );
    expect(kind(of(analysis, PATH))).toBe("inferred");
    expect(of(analysis, PATH)[0]?.evidence).toContain("path guard");
  });

  it("does not let a check inside a loop body cover the code after the loop", async () => {
    const analysis = await run(
      handler(
        "Path x = base.resolve(p).normalize(); for (int i = 0; i < 2; i++) { if (i > 0 && x.startsWith(base)) { Files.readAllBytes(x); } } Files.readAllBytes(x);",
        SPRING,
        BASE,
      ),
    );
    expect(of(analysis, PATH).some((finding) => finding.confidence === "high")).toBe(true);
  });

  it("covers only what every alternative of `||` checked, and what both sides of `&&` checked", async () => {
    const either = await run(
      handler(
        "Path x = base.resolve(p).normalize(); Path y = base.resolve(q).normalize(); if (x.startsWith(base) || y.startsWith(base)) { Files.readAllBytes(x); }",
        SPRING,
        BASE,
      ),
    );
    expect(of(either, PATH).some((finding) => finding.confidence === "high")).toBe(true);
    const both = await run(
      handler(
        "Path x = base.resolve(p).normalize(); Path y = base.resolve(q).normalize(); if (x.startsWith(base) && y.startsWith(base)) { Files.readAllBytes(x); Files.readAllBytes(y); }",
        SPRING,
        BASE,
      ),
    );
    expect(of(both, PATH).every((finding) => finding.confidence === "low")).toBe(true);
    const failed = await run(
      handler(
        "Path x = base.resolve(p).normalize(); Path y = base.resolve(q).normalize(); if (x.startsWith(base) && y.startsWith(base)) { return; } else { Files.readAllBytes(x); }",
        SPRING,
        BASE,
      ),
    );
    expect(of(failed, PATH).some((finding) => finding.confidence === "high")).toBe(true);
    const oneOfTwo = await run(
      handler(
        "Path x = base.resolve(p).normalize(); Path y = base.resolve(q).normalize(); if (!x.startsWith(base) && !y.startsWith(base)) { throw new SecurityException(); } Files.readAllBytes(x);",
        SPRING,
        BASE,
      ),
    );
    expect(of(oneOfTwo, PATH).some((finding) => finding.confidence === "high")).toBe(true);
    const rejected = await run(
      handler(
        "Path x = base.resolve(p).normalize(); Path y = base.resolve(q).normalize(); if (!x.startsWith(base) || !y.startsWith(base)) { throw new SecurityException(); } Files.readAllBytes(x); Files.readAllBytes(y);",
        SPRING,
        BASE,
      ),
    );
    expect(of(rejected, PATH).every((finding) => finding.confidence === "low")).toBe(true);
  });

  it("keeps a check for a lambda that runs after the branch that holds it", async () => {
    const analysis = await run(
      handler(
        "Path x = base.resolve(p).normalize(); if (x.startsWith(base)) { List.of(1).forEach(n -> { try { Files.readAllBytes(x); } catch (Exception e) {} }); }",
        SPRING,
        BASE,
      ),
    );
    expect(of(analysis, PATH).length).toBeGreaterThan(0);
    expect(of(analysis, PATH).every((finding) => finding.confidence === "low")).toBe(true);
  });

  it("demotes an allowlist check on a path variable too", async () => {
    const analysis = await run(
      handler(
        "if (!NAMES.contains(p)) throw new IllegalArgumentException(); Files.readAllBytes(base.resolve(p));",
        SPRING,
        `${BASE}\nstatic final Set<String> NAMES = Set.of("a");`,
      ),
    );
    expect(kind(of(analysis, PATH))).toBe("inferred");
  });

  it("does not let a path check demote the SQL rule", async () => {
    const analysis = await run(
      java(
        `${SPRING}import java.sql.*;\n`,
        `void h(@RequestParam String p, Statement st) throws Exception {
           if (p.contains("..")) { return; }
           st.executeQuery("SELECT * FROM t WHERE n = '" + p + "'");
         }`,
      ),
    );
    expect(of(analysis, "PG-SQL-005")[0]).toMatchObject({ confidence: "high", severity: "high" });
  });
});

describe("PG-PATH-002: only the last element is kept", () => {
  it.each([
    'new File("/srv", FilenameUtils.getName(p)).delete();',
    'new File("/srv", org.apache.commons.io.FilenameUtils.getBaseName(p)).delete();',
    'Files.delete(Paths.get("/srv").resolve(Paths.get(p).getFileName()));',
    'new File("/srv", new File(p).getName()).delete();',
    'new File("/srv", StringUtils.getFilename(p)).delete();',
    'String n = FilenameUtils.getName(p); new File("/srv/" + n).delete();',
  ])("demotes %s to low", async (code) => {
    const analysis = await run(
      handler(
        code,
        `${SPRING}import org.apache.commons.io.FilenameUtils;\nimport org.springframework.util.StringUtils;\n`,
      ),
    );
    expect(kind(of(analysis, PATH)), code).toBe("inferred");
    expect(of(analysis, PATH)).toHaveLength(1);
  });

  it("keeps a path that is only trimmed or replaced as high", async () => {
    const analysis = await run(
      handler('new File("/srv", p.trim().replace("\\\\", "/")).delete();'),
    );
    expect(kind(of(analysis, PATH))).toBe("high/confirmed");
  });
});

describe("PG-PATH-002: archive entries (zip slip)", () => {
  const ZIP = "import java.util.zip.*;\n";

  it("takes the name of a typed archive entry as a source", async () => {
    const analysis = await run(
      java(
        `${SPRING}${ZIP}`,
        `void h(ZipInputStream z, File d) throws Exception { ZipEntry e = z.getNextEntry(); new File(d, e.getName()).mkdirs(); }`,
      ),
    );
    expect(of(analysis, PATH)[0]).toMatchObject({
      severity: "high",
      status: "suspected",
      confidence: "high",
    });
    expect(of(analysis, PATH)[0]?.evidence).toContain("archive entry name");
    expect(of(analysis, PATH)[0]?.evidence).not.toContain("request input");
  });

  it.each([
    "ZipEntry e = z.getNextEntry(); new File(d, e.getName()).mkdirs();",
    "new File(d, z.getNextEntry().getName()).mkdirs();",
    "ZipEntry entry; while ((entry = z.getNextEntry()) != null) { new File(d, entry.getName()).mkdirs(); }",
    "for (ZipEntry e : java.util.Collections.list(zf.entries())) { new File(d, e.getName()).mkdirs(); }",
    "JarEntry je = null; new File(d, je.getName()).mkdirs();",
    "TarArchiveEntry t = null; new File(d, t.getName()).mkdirs();",
    "ZipArchiveEntry t = null; new File(d, t.getName()).mkdirs();",
    "FileHeader fh = null; new File(d, fh.getFileName()).mkdirs();",
    "zf.stream().forEach(entry -> new File(d, entry.getName()).mkdirs());",
    "String name = e0.getName(); new File(d, name).mkdirs();",
  ])("reports %s", async (code) => {
    const analysis = await run(
      java(
        `${SPRING}${ZIP}import java.util.jar.JarEntry;\nimport org.apache.commons.compress.archivers.tar.TarArchiveEntry;\nimport org.apache.commons.compress.archivers.zip.ZipArchiveEntry;\nimport net.lingala.zip4j.model.FileHeader;\n`,
        `void h(ZipInputStream z, ZipFile zf, File d, ZipEntry e0) throws Exception { ${code} }`,
      ),
    );
    expect(kind(of(analysis, PATH)), code).toBe("high/suspected");
  });

  it("does not take the name of other objects as a source", async () => {
    const analysis = await run(
      java(
        `${SPRING}${ZIP}`,
        `void h(File d, Thing t, ZipInputStream z) throws Exception { new File(d, t.getName()).mkdirs(); new File(d, new File("x").getName()).mkdirs(); }
        interface Thing { String getName(); }`,
      ),
    );
    expect(of(analysis, PATH).every((finding) => finding.confidence === "low")).toBe(true);
  });

  it("reads a name like `entry` as an entry only where an archive library is imported and no other type is written down", async () => {
    const without = await run(
      java(
        SPRING,
        `void h(File d, Object entry) throws Exception { new File(d, entry.getName()).mkdirs(); }`,
      ),
    );
    expect(of(without, PATH).every((finding) => finding.confidence === "low")).toBe(true);
    const typedOther = await run(
      java(
        `${SPRING}${ZIP}`,
        `void h(File d, LogEntry logEntry) throws Exception { new File(d, logEntry.getName()).mkdirs(); } interface LogEntry { String getName(); }`,
      ),
    );
    expect(of(typedOther, PATH).every((finding) => finding.confidence === "low")).toBe(true);
    const untyped = await run(
      java(
        `${SPRING}${ZIP}`,
        `Object make() { return null; } void h(File d) throws Exception { var entry = make(); new File(d, entry.getName()).mkdirs(); }`,
      ),
    );
    expect(of(untyped, PATH)[0]).toMatchObject({ severity: "high", confidence: "medium" });
    expect(of(untyped, PATH)[0]?.evidence).toContain("known by its name only");
  });

  it("demotes a canonical check on the extracted file", async () => {
    const analysis = await run(
      java(
        `${SPRING}${ZIP}`,
        `void h(ZipInputStream z, File d) throws Exception {
           ZipEntry e = z.getNextEntry();
           File out = new File(d, e.getName());
           if (!out.getCanonicalPath().startsWith(d.getCanonicalPath() + File.separator)) {
             throw new IOException("zip slip");
           }
           new FileOutputStream(out).close();
         }`,
      ),
    );
    expect(kind(of(analysis, PATH))).toBe("inferred");
  });

  it("reads Kotlin entry names", async () => {
    const analysis = await run(
      `import java.io.File
import java.util.zip.ZipInputStream
fun unzip(zis: ZipInputStream, dest: File) {
    var entry = zis.nextEntry
    while (entry != null) {
        File(dest, entry.name).outputStream().close()
        entry = zis.nextEntry
    }
    File(dest, zis.nextEntry.name).mkdirs()
    zis.entries().forEach { File(dest, it.name).delete() }
}
`,
      "Z.kt",
    );
    expect(of(analysis, PATH).map((finding) => finding.confidence)).toEqual([
      "high",
      "high",
      "high",
    ]);
  });
});

describe("PG-PATH-002: request sources", () => {
  it("reads the client's file name as request input", async () => {
    const analysis = await run(
      java(
        SPRING,
        `void h(@RequestParam("f") org.springframework.web.multipart.MultipartFile f) throws Exception { new File(f.getOriginalFilename()).delete(); }`,
      ),
    );
    expect(kind(of(analysis, PATH))).toBe("high/confirmed");
  });

  it("reads servlet and Ktor sources", async () => {
    const servlet = await run(
      java(
        SERVLET,
        `void h(HttpServletRequest r) throws Exception { new File(r.getPathInfo()).delete(); }`,
      ),
    );
    expect(kind(of(servlet, PATH))).toBe("high/confirmed");
    const ktor = await run(
      `import io.ktor.server.routing.*
import java.io.File
fun Route.r() {
    get("/x") {
        val name = call.parameters["name"]!!
        File("/srv", name).delete()
    }
}
`,
      "K.kt",
    );
    expect(kind(of(ktor, PATH))).toBe("high/suspected");
  });
});

describe("PG-PATH-002: Kotlin", () => {
  it.each([
    ['File("/srv/" + p).readText()', "high/confirmed"],
    ['File("/srv", p).writeText("x")', "high/confirmed"],
    ['File("/srv/$p").delete()', "high/confirmed"],
    ['File("/srv").resolve(p).readBytes()', "high/confirmed"],
    ['Paths.get("/srv", p).toFile().deleteRecursively()', "high/confirmed"],
    ["Files.readAllBytes(Path.of(p))", "high/confirmed"],
    ['val f = File("/srv", p); f.inputStream().close()', "high/suspected"],
    ['File("/srv", p).canonicalFile.readText()', "high/confirmed"],
    ["File(p).name", "none"],
    ['File("/srv", File(p).name).readText()', "inferred"],
    ['File("/srv", "a.txt").readText()', "none"],
  ])("reports %s", async (code, expected) => {
    const analysis = await run(kotlin(code), "K.kt");
    expect(kind(of(analysis, PATH)), code).toBe(expected);
  });

  it("demotes a canonical check", async () => {
    const analysis = await run(
      kotlin(
        'val f = File("/srv", p).canonicalFile; require(f.path.startsWith("/srv/")); f.readText()',
      ),
      "K.kt",
    );
    expect(kind(of(analysis, PATH))).toBe("inferred");
  });

  it("keeps a check on another variable from demoting", async () => {
    const analysis = await run(
      kotlin(
        'val f = File("/srv", p).canonicalFile; val g = File("/srv", q).canonicalFile; require(g.path.startsWith("/srv/")); f.readText()',
      ),
      "K.kt",
    );
    expect(kind(of(analysis, PATH))).toBe("high/suspected");
  });
});

describe("names that are written another way", () => {
  it("reads Files and FileUtils methods that are imported statically", async () => {
    const files = await run(
      java(
        `${SPRING}import static java.nio.file.Files.readAllBytes;\nimport static java.nio.file.Files.*;\n`,
        "byte[] h(@RequestParam String p) throws Exception { return readAllBytes(Paths.get(p)); }",
      ),
    );
    expect(of(files, PATH).map((finding) => finding.cause)).toEqual(["Files.readAllBytes"]);
    const utils = await run(
      java(
        `${SPRING}import static org.apache.commons.io.FileUtils.readFileToString;\n`,
        "String h(@RequestParam String p) throws Exception { return readFileToString(new File(p)); }",
      ),
    );
    expect(of(utils, PATH).map((finding) => finding.cause)).toEqual(["FileUtils.readFileToString"]);
    const other = await run(
      java(
        `${SPRING}import static java.nio.file.Files.readAllBytes;\n`,
        "byte[] h(@RequestParam String p) throws Exception { return write(p); } byte[] write(String s) { return null; }",
      ),
    );
    expect(of(other, PATH)).toEqual([]);
  });

  it("reads fully qualified class names", async () => {
    const java1 = await run(
      java(
        SPRING,
        "void h(@RequestParam String p) throws Exception { java.nio.file.Files.delete(new java.io.File(p).toPath()); }",
      ),
    );
    expect(of(java1, PATH).map((finding) => finding.cause)).toEqual(["Files.delete"]);
    const java2 = await run(
      java(
        SPRING,
        'void h(@RequestParam String p) throws Exception { new java.lang.ProcessBuilder("sh", "-c", p).start(); }',
      ),
    );
    expect(kind(of(java2, CMD))).toBe("critical/confirmed");
    const kt = await run(
      kotlin('java.io.File("/srv/" + p).delete(); java.lang.ProcessBuilder("sh", "-c", p).start()'),
      "K.kt",
    );
    expect(of(kt, PATH)).toHaveLength(1);
    expect(of(kt, CMD)).toHaveLength(1);
  });

  it("reads Kotlin import aliases", async () => {
    const analysis = await run(
      `import java.io.File as JFile
import java.nio.file.Files as NioFiles
import java.nio.file.Paths as P
import java.lang.ProcessBuilder as PB
import java.lang.Runtime as RT
import org.springframework.web.bind.annotation.*
@RestController
class K {
    @GetMapping("/x")
    fun h(@RequestParam p: String) {
        JFile("/srv/" + p).delete()
        NioFiles.readAllBytes(P.get(p))
        PB("sh", "-c", p).start()
        RT.getRuntime().exec("ls " + p)
    }
    fun typed(f: JFile, @RequestParam q: String) { f.resolve(q) }
}
`,
      "K.kt",
    );
    expect(
      of(analysis, PATH)
        .map((finding) => finding.cause)
        .sort(),
    ).toEqual(["File.delete", "Files.readAllBytes", "Path.resolve"]);
    expect(
      of(analysis, CMD)
        .map((finding) => finding.cause)
        .sort(),
    ).toEqual(["ProcessBuilder:shell", "Runtime.exec:string"]);
  });
});

describe("PG-PATH-002: coverage", () => {
  it("lists anonymous classes and local functions that open files", async () => {
    const anonymous = await run(
      java(
        SPRING,
        `void h() { Runnable r = new Runnable() { public void run() { new File("/x").delete(); } }; }`,
      ),
    );
    expect(anonymous.unsupportedForms).toContain("anonymous class");
    const kotlinLocal = await run(
      `package a\nimport java.io.File\nfun f() {\n  fun inner(p: String) { File(p).delete() }\n}\n`,
      "K.kt",
    );
    expect(kotlinLocal.unsupportedForms).toContain("local function");
  });
});

// ====================================================================== guard text

describe("path guard conditions", () => {
  const g = (name: string, needsCanon: boolean) => ({ name, needsCanon });

  it("reads a prefix test on a resolved path", () => {
    expect(pathGuardedWhenTrue("p.normalize().startsWith(base)")).toEqual([g("p", false)]);
    expect(pathGuardedWhenTrue("f.getCanonicalPath().startsWith(root)")).toEqual([g("f", false)]);
    expect(
      pathGuardedWhenTrue("base.resolve(name).normalize().startsWith(base)").map((x) => x.name),
    ).toEqual(["base", "name"]);
    expect(pathGuardedWhenTrue("p.startsWith(base)")).toEqual([g("p", true)]);
    expect(pathGuardedWhenTrue("p.toString().startsWith(base)")).toEqual([g("p", true)]);
    expect(pathGuardedWhenTrue("(p.startsWith(base))")).toEqual([g("p", true)]);
  });

  it("reads the negation on the other side", () => {
    expect(pathGuardedWhenTrue("!p.startsWith(base)")).toEqual([]);
    expect(pathGuardedWhenFalse("!p.startsWith(base)")).toEqual([g("p", true)]);
    expect(pathGuardedWhenFalse("p.startsWith(base)")).toEqual([]);
    expect(pathGuardedWhenFalse("!p.normalize().startsWith(base)")).toEqual([g("p", false)]);
  });

  it("reads a rejection of `..` and of separators", () => {
    expect(pathGuardedWhenFalse('name.contains("..")')).toEqual([g("name", false)]);
    expect(pathGuardedWhenFalse('name.contains("/")')).toEqual([g("name", false)]);
    expect(pathGuardedWhenFalse('name.contains("\\\\")')).toEqual([g("name", false)]);
    expect(pathGuardedWhenTrue('!name.contains("..")')).toEqual([g("name", false)]);
    expect(pathGuardedWhenTrue('name.contains("..")')).toEqual([]);
    expect(pathGuardedWhenFalse('name.contains("x")')).toEqual([]);
    expect(pathGuardedWhenFalse("name.contains(other)")).toEqual([]);
  });

  it("combines conditions", () => {
    expect(pathGuardedWhenFalse('a.contains("..") || b.contains("..")').map((x) => x.name)).toEqual(
      ["a", "b"],
    );
    expect(pathGuardedWhenTrue("a.startsWith(x) && b.startsWith(x)").map((x) => x.name)).toEqual([
      "a",
      "b",
    ]);
    expect(pathGuardedWhenTrue("a.startsWith(x) || b.startsWith(x)")).toEqual([]);
    expect(pathGuardedWhenTrue("a.startsWith(x) || a.startsWith(y)")).toEqual([g("a", true)]);
    expect(pathGuardedWhenFalse("!a.startsWith(x) && !b.startsWith(x)")).toEqual([]);
    expect(pathGuardedWhenFalse("!a.startsWith(x) || !b.startsWith(x)").map((x) => x.name)).toEqual(
      ["a", "b"],
    );
  });

  it("ignores conditions that are not checks", () => {
    for (const text of [
      "p.isEmpty()",
      "p.startsWith(a) != null",
      "p == null",
      "x.foo(p.startsWith(a))",
    ]) {
      expect(pathGuardedWhenTrue(text), text).toEqual([]);
      expect(pathGuardedWhenFalse(text), text).toEqual([]);
    }
  });
});

// ====================================================================== review round

const JDBC = `${SPRING}import java.sql.*;\n`;

describe("last-element helpers lower only the path rule", () => {
  const helpers = [
    "new File(p).getName()",
    "FilenameUtils.getName(p)",
    "FilenameUtils.getBaseName(p)",
    "Paths.get(p).getFileName()",
    "StringUtils.getFilename(p)",
  ];
  const imports = `${JDBC}import org.apache.commons.io.FilenameUtils;\nimport org.springframework.util.StringUtils;\n`;

  it.each(helpers)("%s: SQL in a longer string stays high", async (helper) => {
    const analysis = await run(
      java(
        imports,
        `void h(@RequestParam String p, Statement st) throws Exception { st.executeQuery("SELECT * FROM t WHERE n = '" + ${helper} + "'"); }`,
      ),
    );
    expect(of(analysis, "PG-SQL-005")[0]).toMatchObject({ severity: "high", confidence: "high" });
  });

  it.each(helpers)("%s: a bare SQL argument is what any unknown call gives", async (helper) => {
    const analysis = await run(
      java(
        imports,
        `void h(@RequestParam String p, Statement st) throws Exception { st.executeQuery(${helper}); }`,
      ),
    );
    expect(of(analysis, "PG-SQL-005")[0]).toMatchObject({ confidence: "low" });
    expect(of(analysis, "PG-SQL-005")[0]?.evidence).toContain("not followed");
  });

  it.each(helpers)("%s: a command in a longer string stays critical", async (helper) => {
    const forms = [
      `Runtime.getRuntime().exec(new String[] {"sh", "-c", "convert /in/" + ${helper}});`,
      `Runtime.getRuntime().exec("convert /in/" + ${helper});`,
      `new ProcessBuilder("sh", "-c", "convert " + ${helper}).start();`,
    ];
    for (const form of forms) {
      const analysis = await run(handler(form, imports));
      expect(of(analysis, CMD)[0], form).toMatchObject({
        severity: "critical",
        confidence: "high",
      });
    }
  });

  it.each(helpers)("%s: the path rule still lowers it", async (helper) => {
    const analysis = await run(handler(`new File("/srv", ${helper}).delete();`, imports));
    expect(kind(of(analysis, PATH))).toBe("inferred");
  });

  it("keeps Kotlin File(path).name tainted for SQL and commands", async () => {
    const sql = await run(
      `import java.io.File
import java.sql.Connection
import org.springframework.web.bind.annotation.*
@RestController
class K {
    @GetMapping("/x")
    fun h(@RequestParam p: String, c: Connection) {
        c.createStatement().executeQuery("SELECT * FROM t WHERE n = '" + File(p).name + "'")
        Runtime.getRuntime().exec("convert " + File(p).name)
    }
}
`,
      "K.kt",
    );
    expect(of(sql, "PG-SQL-005")[0]).toMatchObject({ severity: "high", confidence: "high" });
    expect(of(sql, CMD)[0]).toMatchObject({ severity: "critical", confidence: "high" });
  });

  it("does not let a path conversion turn a bare SQL value into request input read directly", async () => {
    const analysis = await run(
      java(
        JDBC,
        "void h(@RequestParam String p, Statement st) throws Exception { st.executeQuery(new File(p).getAbsolutePath()); }",
      ),
    );
    expect(of(analysis, "PG-SQL-005")[0]).toMatchObject({ confidence: "low" });
  });
});

describe("archive entry names and upload names are sources for every rule", () => {
  it("makes an archive entry name request-like input for SQL (intentional)", async () => {
    const analysis = await run(
      java(
        `${JDBC}import java.util.zip.*;\n`,
        'void h(ZipInputStream z, Statement st) throws Exception { ZipEntry e = z.getNextEntry(); st.executeUpdate("INSERT INTO files(name) VALUES (\'" + e.getName() + "\')"); }',
      ),
    );
    expect(of(analysis, "PG-SQL-005")[0]).toMatchObject({ severity: "high", confidence: "high" });
    expect(of(analysis, "PG-SQL-005")[0]?.evidence).toContain("archive entry name");
  });

  it("makes an uploaded file name request input in any class", async () => {
    const sql = await run(
      java(
        `${JDBC}import org.springframework.web.multipart.MultipartFile;\n`,
        'void store(MultipartFile file, Statement st) throws Exception { st.executeUpdate("INSERT INTO f(n) VALUES (\'" + file.getOriginalFilename() + "\')"); }',
      ),
    );
    expect(of(sql, "PG-SQL-005")[0]).toMatchObject({ severity: "high", confidence: "high" });
    const service = await run(
      java(
        `${SPRING}import org.springframework.web.multipart.MultipartFile;\n`,
        'File dir = new File("/srv"); void store(MultipartFile file) { new File(dir, file.getOriginalFilename()).delete();\n new File("/srv/" + file.getOriginalFilename()).delete(); }',
      ),
    );
    expect(of(service, PATH).map((finding) => finding.confidence)).toEqual(["high", "high"]);
    const part = await run(
      java(
        SERVLET,
        "void h(Part part) throws Exception { new File(part.getSubmittedFileName()).delete(); }",
      ),
    );
    expect(kind(of(part, PATH))).toBe("high/confirmed");
    const ktor = await run(
      `import io.ktor.http.content.PartData
import java.io.File
fun save(part: PartData.FileItem) { File("/srv/" + part.originalFileName).writeBytes(ByteArray(0)) }
`,
      "K.kt",
    );
    expect(kind(of(ktor, PATH))).toBe("high/confirmed");
    const other = await run(
      java(
        SPRING,
        'interface Thing { String getOriginalFilename(); } void h(Thing t) { new File("/srv/" + t.getOriginalFilename()).delete(); }',
      ),
    );
    expect(of(other, PATH).every((finding) => finding.confidence === "low")).toBe(true);
  });
});

describe("a parameter or other-file constant at a sink is low, never silent", () => {
  it.each([
    [
      "Process run(String cmd) throws Exception { return Runtime.getRuntime().exec(cmd); }",
      CMD,
      "medium",
    ],
    [
      "void run(List<String> argv) throws Exception { new ProcessBuilder(argv).start(); }",
      CMD,
      "medium",
    ],
    [
      "void run(String[] argv) throws Exception { Runtime.getRuntime().exec(argv); }",
      CMD,
      "medium",
    ],
    [
      'void run(String tool) throws Exception { new ProcessBuilder(tool, "-v").start(); }',
      CMD,
      "medium",
    ],
    [
      'void run(String arg) throws Exception { new ProcessBuilder("git", arg).start(); }',
      CMD,
      "low",
    ],
    [
      "byte[] read(String path) throws Exception { return Files.readAllBytes(Paths.get(path)); }",
      PATH,
      "low",
    ],
    ["void read(String path) throws Exception { new FileInputStream(path).close(); }", PATH, "low"],
    ["void read(String path) { new File(path).delete(); }", PATH, "low"],
    ["void read(Path path) throws Exception { Files.delete(path); }", PATH, "low"],
    [
      "void read(int n) throws Exception { Runtime.getRuntime().exec(String.valueOf(n)); }",
      CMD,
      "medium",
    ],
    ["void read() throws Exception { new File(Config.DIR).delete(); }", PATH, "medium"],
  ])("%s", async (code, ruleId, severity) => {
    const analysis = await run(java(SPRING, code));
    const found = of(analysis, ruleId);
    expect(found, code).toHaveLength(1);
    expect(found[0], code).toMatchObject({ confidence: "low", severity });
    expect(found[0]?.evidence, code).toMatch(/inferred$/);
  });

  it("keeps a same-file literal-only constant silent", async () => {
    const analysis = await run(
      java(
        SPRING,
        'static final String DIR = "/srv"; void h() throws Exception { new File(DIR).delete(); Runtime.getRuntime().exec(DIR); }',
      ),
    );
    expect(analysis.findings.filter((finding) => finding.ruleId !== "PG-SQL-005")).toEqual([]);
  });

  it("does not change what the SQL rule does with a bare value", async () => {
    const analysis = await run(
      java(JDBC, "void h(String q, Statement st) throws Exception { st.executeQuery(q); }"),
    );
    expect(of(analysis, "PG-SQL-005")).toEqual([]);
  });
});

describe("file openers that take a name", () => {
  it.each([
    ['new PrintWriter("/srv/out/" + p);', "PrintWriter"],
    ['new PrintStream("/srv/out/" + p);', "PrintStream"],
    ['new Formatter("/srv/out/" + p);', "Formatter"],
    ['new ZipFile("/srv/archives/" + p);', "ZipFile"],
    ['new JarFile("/srv/archives/" + p);', "JarFile"],
    ['new ZipFile(new File("/srv/archives", p));', "ZipFile"],
    ['new java.util.logging.FileHandler("/srv/log/" + p);', "FileHandler"],
    ['new UrlResource("file:/srv/files/" + p);', "UrlResource"],
    ["new PrintWriter(p);", "PrintWriter"],
    ['new FileSystemResource("/srv/" + p);', "FileSystemResource"],
  ])("reports %s", async (code, cause) => {
    const analysis = await run(
      handler(
        code,
        `${SPRING}import java.util.zip.*;\nimport java.util.jar.JarFile;\nimport org.springframework.core.io.*;\n`,
      ),
    );
    expect(
      of(analysis, PATH).map((finding) => finding.cause),
      code,
    ).toContain(cause);
    expect(
      of(analysis, PATH).some((finding) => finding.severity === "high"),
      code,
    ).toBe(true);
  });

  it("does not take a stream or a writer for a file name", async () => {
    const analysis = await run(
      java(
        SPRING,
        `void h(java.io.OutputStream out, java.io.Writer w, javax.servlet.http.HttpServletResponse r) throws Exception {
           new PrintWriter(out); new PrintWriter(w); new PrintStream(out); new Formatter(w); new PrintWriter(r.getWriter());
         }`,
      ),
    );
    expect(of(analysis, PATH)).toEqual([]);
  });

  it("takes UrlResource for a file only with a file: URL", async () => {
    const analysis = await run(
      handler(
        'new UrlResource("https://example.org/" + p); new UrlResource(p);',
        `${SPRING}import org.springframework.core.io.*;\n`,
      ),
    );
    expect(of(analysis, PATH)).toEqual([]);
  });
});

describe("shell wrappers behind launchers", () => {
  it.each([
    ['"/usr/bin/env", "bash", "-c", p'],
    ['"env", "FOO=1", "sh", "-c", p'],
    ['"env", "-i", "sh", "-c", p'],
    ['"sudo", "-u", "app", "sh", "-c", p'],
    ['"sudo", "-n", "bash", "-c", p'],
    ['"nohup", "sh", "-c", p'],
    ['"timeout", "10", "sh", "-c", p'],
    ['"timeout", "-s", "KILL", "10s", "bash", "-c", p'],
    ['"nice", "-n", "5", "sh", "-c", p'],
    ['"nice", "sh", "-c", p'],
    ['"xargs", "-n", "1", "sh", "-c", p'],
    ['"sudo", "env", "sh", "-c", p'],
  ])("%s is critical", async (argv) => {
    const analysis = await run(handler(`new ProcessBuilder(${argv}).start();`));
    expect(of(analysis, CMD)[0], argv).toMatchObject({
      severity: "critical",
      cause: "ProcessBuilder:shell",
    });
  });

  it("is still an argument of a program behind a launcher when no shell follows", async () => {
    const analysis = await run(handler('new ProcessBuilder("env", "git", "log", p).start();'));
    expect(of(analysis, CMD)[0]).toMatchObject({
      severity: "medium",
      cause: "ProcessBuilder:argument",
    });
    const arrays = await run(
      handler('Runtime.getRuntime().exec(new String[] {"sudo", "-u", "app", "sh", "-c", p});'),
    );
    expect(of(arrays, CMD)[0]).toMatchObject({ severity: "critical" });
  });

  it("reads a launcher and a shell in a list filled in steps", async () => {
    const analysis = await run(
      handler(
        'List<String> c = new ArrayList<>(List.of("sudo", "-u", "app", "bash", "-c")); c.add(p); new ProcessBuilder(c).start();',
      ),
    );
    expect(of(analysis, CMD)[0]).toMatchObject({
      severity: "critical",
      cause: "ProcessBuilder:shell",
    });
  });
});

describe("Kotlin list appends", () => {
  it("reads `cmd += listOf(...)` and `cmd + x` as more arguments, not as the program", async () => {
    const forms = [
      'var cmd = mutableListOf("ffmpeg"); cmd += listOf("-i", p); ProcessBuilder(cmd).start()',
      'var cmd = listOf("ffmpeg"); cmd = cmd + listOf("-i", p); ProcessBuilder(cmd).start()',
      'val cmd = mutableListOf("ffmpeg"); cmd.addAll(listOf("-i", p)); ProcessBuilder(cmd).start()',
      'var cmd = mutableListOf("ffmpeg"); cmd += p; ProcessBuilder(cmd).start()',
    ];
    for (const form of forms) {
      const analysis = await run(kotlin(form), "K.kt");
      expect(of(analysis, CMD)[0], form).toMatchObject({
        severity: "medium",
        cause: "ProcessBuilder:argument",
      });
    }
  });
});

describe("archive entry sources are narrow", () => {
  const ZIPK = "import java.util.zip.ZipFile\nimport java.util.zip.ZipInputStream\n";

  it("reads Kotlin loops and sequences over the entries of an archive", async () => {
    const analysis = await run(
      `import java.io.File
${ZIPK}
fun a(zip: ZipFile, dest: File) {
    for (e in zip.entries()) { File(dest, e.name).mkdirs() }
}
fun b(zip: ZipFile, dest: File) {
    zip.entries().asSequence().forEach { File(dest, it.name).mkdirs() }
}
fun d(zip: ZipFile, dest: File) {
    zip.stream().forEach { entry -> File(dest, entry.name).mkdirs() }
}
`,
      "K.kt",
    );
    expect(of(analysis, PATH).map((finding) => finding.line)).toEqual([6, 9, 12]);
    expect(of(analysis, PATH).every((finding) => finding.confidence === "high")).toBe(true);
  });

  it("does not take other objects named entry, or the files of a directory, for archive entries", async () => {
    const analysis = await run(
      `import java.io.File
${ZIPK}
class LogEntry(val name: String)
fun a(dest: File, logEntry: LogEntry) {
    File(dest, logEntry.name).mkdirs()
}
fun b(dir: File, dest: File) {
    dir.listFiles()!!.forEach { File(dest, it.name).mkdirs() }
}
fun c(items: List<LogEntry>, dest: File) {
    items.forEach { File(dest, it.name).mkdirs() }
    for (entry: LogEntry in items) { File(dest, entry.name).mkdirs() }
}
`,
      "K.kt",
    );
    expect(of(analysis, PATH).length).toBeGreaterThan(0);
    expect(of(analysis, PATH).every((finding) => finding.confidence === "low")).toBe(true);
  });

  it("does not let a Java variable typed as something else be an entry", async () => {
    const analysis = await run(
      java(
        `${SPRING}import java.util.zip.*;\n`,
        "void h(File d, LogEntry logEntry, File[] files) throws Exception { new File(d, logEntry.getName()).mkdirs(); for (File f : files) { new File(d, f.getName()).mkdirs(); } } interface LogEntry { String getName(); }",
      ),
    );
    expect(of(analysis, PATH).every((finding) => finding.confidence === "low")).toBe(true);
  });
});

describe("narrow corners", () => {
  it("reports a probe only for request input", async () => {
    const own = await run(
      java(SPRING, "void h(String name) { Files.exists(Path.of(name)); new File(name).exists(); }"),
    );
    expect(of(own, PATH)).toEqual([]);
  });

  it("takes entries() and stream() for archive entries only on an archive", async () => {
    const other = await run(
      `import java.io.File
import java.util.zip.ZipFile
class Catalog { fun entries(): List<Item> = emptyList() }
class Item(val name: String)
fun a(catalog: Catalog, dest: File) { for (e in catalog.entries()) { File(dest, e.name).mkdirs() } }
`,
      "K.kt",
    );
    expect(of(other, PATH).every((finding) => finding.confidence === "low")).toBe(true);
  });
});

describe("a check counts only when the code exits on failure or the use is inside the success branch", () => {
  const BASE2 = 'final Path base = Paths.get("/srv").toAbsolutePath().normalize();';

  it("does not let an ignored check demote a returned or stored path", async () => {
    const forms = [
      'File f = new File("/srv", p); if (f.getCanonicalPath().startsWith("/srv/")) { System.out.println("ok"); } return f;',
      'File f = new File("/srv", p); if (!f.getCanonicalPath().startsWith("/srv/")) { System.out.println("bad"); } return f;',
      'File f = new File("/srv", p); f.getCanonicalPath().startsWith("/srv/"); return f;',
    ];
    for (const form of forms) {
      const analysis = await run(
        java(SPRING, `File h(@RequestParam String p) throws Exception { ${form} }`),
      );
      expect(kind(of(analysis, PATH)), form).toBe("high/confirmed");
      expect(of(analysis, PATH), form).toHaveLength(1);
    }
  });

  it("demotes a path returned from the success branch or after an exiting check", async () => {
    const forms = [
      'File f = new File("/srv", p); if (f.getCanonicalPath().startsWith("/srv/")) { return f; } return null;',
      'File f = new File("/srv", p); if (!f.getCanonicalPath().startsWith("/srv/")) { throw new IOException(); } return f;',
      'File f = new File("/srv", p); if (!f.getCanonicalPath().startsWith("/srv/")) { return null; } return f;',
    ];
    for (const form of forms) {
      const analysis = await run(
        java(SPRING, `File h(@RequestParam String p) throws Exception { ${form} }`),
      );
      expect(kind(of(analysis, PATH)), form).toBe("inferred");
    }
  });

  it("reports a path that is checked and never seen used at low confidence", async () => {
    const analysis = await run(
      handler(
        "Path x = base.resolve(p).normalize(); if (!x.startsWith(base)) throw new SecurityException();",
        SPRING,
        BASE2,
      ),
    );
    expect(kind(of(analysis, PATH))).toBe("inferred");
  });

  it("reports a checked path used by a call the rules do not know, or stored in a field, as low", async () => {
    const forms = [
      "Path x = base.resolve(p).normalize(); if (!x.startsWith(base)) throw new SecurityException(); x.toFile().setReadOnly();",
      "Path x = base.resolve(p).normalize(); if (!x.startsWith(base)) throw new SecurityException(); current = x;",
      "Path x = base.resolve(p).normalize(); if (!x.startsWith(base)) throw new SecurityException(); this.current = x;",
      "Path x = base.resolve(p).normalize(); if (!x.startsWith(base)) throw new SecurityException(); registry.keep(x);",
    ];
    for (const form of forms) {
      const analysis = await run(
        handler(
          form,
          SPRING,
          `${BASE2}\nPath current; Registry registry; interface Registry { void keep(Path p); }`,
        ),
      );
      expect(kind(of(analysis, PATH)), form).toBe("inferred");
      expect(of(analysis, PATH), form).toHaveLength(1);
    }
    const unchecked = await run(
      handler("Path x = base.resolve(p).normalize(); x.toFile().setReadOnly();", SPRING, BASE2),
    );
    expect(kind(of(unchecked, PATH))).toBe("high/confirmed");
    const file = await run(
      java(
        SPRING,
        'File current; void h(@RequestParam String p) throws Exception { File f = new File("/srv", p).getCanonicalFile(); if (!f.getPath().startsWith("/srv/")) throw new IOException(); current = f; }',
      ),
    );
    expect(kind(of(file, PATH))).toBe("inferred");
    const fileUnchecked = await run(
      java(
        SPRING,
        'File current; void h(@RequestParam String p) throws Exception { File f = new File("/srv", p).getCanonicalFile(); current = f; }',
      ),
    );
    expect(kind(of(fileUnchecked, PATH))).toBe("high/confirmed");
  });

  it("still reports the use of another variable next to a checked one that is never used", async () => {
    const analysis = await run(
      handler(
        "Path x = base.resolve(q).normalize(); if (!x.startsWith(base)) throw new SecurityException(); Files.readAllBytes(base.resolve(p));",
        SPRING,
        BASE2,
      ),
    );
    expect(of(analysis, PATH)).toHaveLength(2);
    expect(
      of(analysis, PATH)
        .map((finding) => finding.confidence)
        .sort(),
    ).toEqual(["high", "low"]);
  });
});

describe("assertion helpers, archive iterators and launchers with dynamic arguments", () => {
  const BASE3 = 'final Path base = Paths.get("/srv").toAbsolutePath().normalize();';
  const imports = `${SPRING}import com.google.common.base.Preconditions;\nimport org.springframework.util.Assert;\nimport org.apache.commons.lang3.Validate;\nimport static com.google.common.base.Preconditions.checkArgument;\n`;

  it.each([
    "Preconditions.checkArgument(x.startsWith(base));",
    'Preconditions.checkState(x.startsWith(base), "outside");',
    "com.google.common.base.Preconditions.checkArgument(x.startsWith(base));",
    "checkArgument(x.startsWith(base));",
    'Assert.isTrue(x.startsWith(base), "outside");',
    'Assert.state(x.startsWith(base), "outside");',
    "Validate.isTrue(x.startsWith(base));",
  ])("%s throws on failure, so the check counts", async (check) => {
    const analysis = await run(
      handler(
        `Path x = base.resolve(p).normalize(); ${check} Files.readAllBytes(x);`,
        imports,
        BASE3,
      ),
    );
    expect(kind(of(analysis, PATH)), check).toBe("inferred");
  });

  it("does not take other isTrue / state calls, or a check on another variable, for a guard", async () => {
    const other = await run(
      handler(
        "Path x = base.resolve(p).normalize(); Other.isTrue(x.startsWith(base)); Files.readAllBytes(x);",
        imports,
        `${BASE3}\nstatic class Other { static void isTrue(boolean b) {} }`,
      ),
    );
    expect(kind(of(other, PATH))).toBe("high/suspected");
    const wrong = await run(
      handler(
        "Path x = base.resolve(p).normalize(); Path y = base.resolve(q).normalize(); Preconditions.checkArgument(y.startsWith(base)); Files.readAllBytes(x);",
        imports,
        BASE3,
      ),
    );
    expect(wrong.findings.some((finding) => finding.confidence === "high")).toBe(true);
  });

  it("reads the assertion helpers in Kotlin", async () => {
    const analysis = await run(
      kotlin(
        'val x = Paths.get("/srv").resolve(p).normalize(); Preconditions.checkArgument(x.startsWith(Paths.get("/srv"))); Files.readAllBytes(x)',
        "import com.google.common.base.Preconditions\nimport org.springframework.util.Assert",
      ),
      "K.kt",
    );
    expect(kind(of(analysis, PATH))).toBe("inferred");
  });

  it("takes the Kotlin property forms of the next-entry calls for archive entries", async () => {
    const forms = [
      "zis.nextZipEntry",
      "tis.nextTarEntry",
      "jis.nextJarEntry",
      "cis.nextCpioEntry",
      "ais.nextArEntry",
    ];
    for (const form of forms) {
      const analysis = await run(
        `import java.io.File
import java.util.zip.ZipInputStream
fun a(zis: Any, tis: Any, jis: Any, cis: Any, ais: Any, dest: File) { File(dest, ${form}.name).mkdirs() }
`,
        "K.kt",
      );
      expect(of(analysis, PATH)[0], form).toMatchObject({ severity: "high", confidence: "high" });
    }
  });

  it("still finds `sh -c script` behind a launcher with a dynamic argument", async () => {
    const forms = [
      'new ProcessBuilder("timeout", q, "sh", "-c", p).start();',
      'new ProcessBuilder("sudo", "-u", q, "bash", "-lc", p).start();',
      'Runtime.getRuntime().exec(new String[] {"nice", "-n", q, "sh", "-c", p});',
    ];
    for (const form of forms) {
      const analysis = await run(handler(form));
      expect(of(analysis, CMD)[0], form).toMatchObject({
        severity: "critical",
        cause: expect.stringMatching(/:shell$/),
      });
    }
    const none = await run(handler('new ProcessBuilder("timeout", q, "git", "log", p).start();'));
    expect(of(none, CMD)[0]).toMatchObject({ severity: "medium" });
  });
});

describe("receivers and the names the README documents", () => {
  it("treats a static receiver's exec and an untyped builder's command as notes at low confidence", async () => {
    const stat = await run(
      handler(
        'Shell.exec("sh -c " + p);',
        SPRING,
        "static class Shell { static void exec(String c) {} }",
      ),
    );
    expect(of(stat, CMD)[0]).toMatchObject({ confidence: "low", cause: "exec:unrecognized" });
    const builder = await run(
      handler('builder().command(p, "-v");', SPRING, "Object builder() { return null; }"),
    );
    expect(of(builder, CMD)[0]).toMatchObject({ confidence: "low", cause: "command:unrecognized" });
    const fixed = await run(
      handler(
        'Shell.exec("sh -c ls");',
        SPRING,
        "static class Shell { static void exec(String c) {} }",
      ),
    );
    expect(of(fixed, CMD)).toEqual([]);
  });

  it("does not call a class-path lookup a ResourceLoader", async () => {
    const forms = [
      'getClass().getClassLoader().getResource("templates/" + p);',
      'ClassLoader.getSystemClassLoader().getResource("templates/" + p);',
      "Thread.currentThread().getContextClassLoader().getResource(p);",
      'Class.forName("x").getResource("/t/" + p);',
    ];
    for (const form of forms) {
      const analysis = await run(handler(form));
      expect(of(analysis, PATH), form).toEqual([]);
    }
    const loader = await run(
      handler(
        'loader.getResource("file:" + p);',
        `${SPRING}import org.springframework.core.io.ResourceLoader;\n`,
        "ResourceLoader loader;",
      ),
    );
    expect(of(loader, PATH)[0]).toMatchObject({
      cause: "ResourceLoader.getResource",
      severity: "high",
    });
    const context = await run(
      handler(
        'applicationContext.getResource("file:" + p);',
        SPRING,
        "org.springframework.context.ApplicationContext applicationContext;",
      ),
    );
    expect(of(context, PATH)[0]).toMatchObject({ cause: "ResourceLoader.getResource" });
    const other = await run(
      handler('registry.getResource("file:" + p);', SPRING, "Object registry;"),
    );
    expect(of(other, PATH)[0]).toMatchObject({ cause: "getResource(file:)" });
  });
});

describe("severity and confidence", () => {
  it("never pairs low confidence with more than medium severity, in any corpus sample", async () => {
    const root = new URL("../../../../tests/corpus/", import.meta.url);
    let checked = 0;
    for (const rule of ["PG-CMD-003", "PG-PATH-002", "PG-SQL-005"]) {
      for (const kindDir of ["positive", "negative"]) {
        const dir = new URL(`${rule}/${kindDir}/`, root);
        for (const name of readdirSync(dir)) {
          if (!/\.(?:java|kt)$/.test(name)) continue;
          const source = readFileSync(new URL(name, dir), "utf8");
          const analysis = await run(source, name);
          for (const finding of analysis.findings) {
            if (finding.confidence !== "low") continue;
            checked += 1;
            expect(
              ["medium", "low", "info"],
              `${rule}/${kindDir}/${name} ${finding.evidence}`,
            ).toContain(finding.severity);
          }
        }
      }
    }
    expect(checked).toBeGreaterThan(50);
  });
});

// ====================================================================== the rules together

describe("the rules in one file", () => {
  const source = java(
    `${SPRING}import java.sql.*;\n`,
    `@GetMapping("/a") void a(@RequestParam String p, Statement st) throws Exception {
       st.executeQuery("SELECT * FROM t WHERE n = '" + p + "'");
       Runtime.getRuntime().exec("ls " + p);
       new File("/srv/" + p).delete();
     }`,
  );

  it("reports each rule once, with its own id", async () => {
    const analysis = await run(source);
    expect(analysis.findings.map((finding) => finding.ruleId).sort()).toEqual([
      CMD,
      PATH,
      "PG-SQL-005",
    ]);
    expect(analysis.capped).toBe(false);
  });

  it("caps each rule on its own: a flood of one rule never hides another", async () => {
    const execs = Array.from(
      { length: 40 },
      (_, i) => `Runtime.getRuntime().exec("c${i} " + p);`,
    ).join("\n");
    const analysis = await run(
      java(
        `${SPRING}import java.sql.*;\n`,
        `@GetMapping("/a") void a(@RequestParam String p, Statement st) throws Exception {
           ${execs}
           new File("/srv/" + p).delete();
           st.executeQuery("SELECT * FROM t WHERE n = '" + p + "'");
         }`,
      ),
    );
    expect(of(analysis, CMD)).toHaveLength(25);
    expect(of(analysis, PATH)).toHaveLength(1);
    expect(of(analysis, "PG-SQL-005")).toHaveLength(1);
    expect(analysis.capped).toBe(true);
  });

  it("keeps the strongest findings when a rule is capped", async () => {
    const weak = Array.from(
      { length: 30 },
      (_, i) => `Runtime.getRuntime().exec("c${i} " + a);`,
    ).join("\n");
    const analysis = await run(
      java(
        SPRING,
        `@GetMapping("/a") void a(String a, @RequestParam String p) throws Exception {\n${weak}\nRuntime.getRuntime().exec("z " + p);\n}`,
      ),
    );
    expect(of(analysis, CMD)).toHaveLength(25);
    expect(of(analysis, CMD).some((finding) => finding.severity === "critical")).toBe(true);
  });

  it("is a pure function of the file: the same input gives the same findings", async () => {
    const first = await run(source);
    const second = await run(source);
    expect(second.findings).toEqual(first.findings);
  });
});

// ====================================================================== speed

const SLOW = process.platform === "win32" ? 3 : 1;

describe("performance", () => {
  const method = (i: number): string => `
  @GetMapping("/m${i}")
  void m${i}(@RequestParam String a, @RequestParam String b) throws Exception {
    List<String> argv = new ArrayList<>();
    argv.add("tool${i}");
    argv.add(a);
    for (int k = 0; k < 3; k++) { argv.add(b + k); }
    new ProcessBuilder(argv).start();
    Path base = Paths.get("/srv/d${i}");
    Path p = base.resolve(a).normalize();
    if (!p.startsWith(base)) { throw new IllegalArgumentException(); }
    Files.readAllBytes(p);
    new File(base.toFile(), b).delete();
  }
`;
  const build = (count: number): string =>
    java(SPRING, Array.from({ length: count }, (_, i) => method(i)).join(""));

  it("analyzes a file near the size limit in linear time", async () => {
    const full = build(1800);
    const quarter = build(450);
    expect(Buffer.byteLength(full)).toBeGreaterThan(500_000);
    expect(Buffer.byteLength(full)).toBeLessThan(1024 * 1024);
    const started = performance.now();
    const analysis = await run(full);
    const large = performance.now() - started;
    const smallStart = performance.now();
    await run(quarter);
    const small = performance.now() - smallStart;
    expect(large).toBeLessThan(8000 * SLOW);
    expect(large / Math.max(small, 1)).toBeLessThan(12);
    expect(analysis.capped).toBe(true);
  }, 120_000);

  it("a long chain of path operations stays fast", async () => {
    const chain = Array.from({ length: 3000 }, (_, i) => `.resolve(a${i % 5})`).join("");
    const started = performance.now();
    const analysis = await run(
      java(
        SPRING,
        `void h(String a0, String a1, String a2, String a3, String a4) throws Exception { Files.delete(Paths.get("/srv")${chain}); }`,
      ),
    );
    expect(performance.now() - started).toBeLessThan(5000 * SLOW);
    expect(of(analysis, PATH)).toHaveLength(1);
    expect(of(analysis, PATH)[0]?.cause).toBe("Files.delete");
  }, 60_000);
});
