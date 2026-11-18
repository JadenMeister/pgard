import { describe, expect, it } from "vitest";
import { detectSecrets } from "./secret-patterns.js";
import { createSourceLookups } from "./string-regions.js";

// Runtime-assembled so no secret-looking literal is committed (synthetic values).
const j = (...parts: string[]) => parts.join("");
const CODE_SHAPED = j("Prod.Xk9q", ")m2Lq8");

function scan(text: string, path: string) {
  return detectSecrets(text, { path });
}

describe("a password in comment prose is reported wherever the comment starts (#460)", () => {
  it.each([
    `// user, password: ${CODE_SHAPED}`,
    `// user,password: ${CODE_SHAPED}`,
    `// creds (password: ${CODE_SHAPED})`,
    `// {user: a, password: ${CODE_SHAPED}}`,
    `/* {password:${CODE_SHAPED}} */`,
    `// login(password=${CODE_SHAPED}`,
    `// do not commit, password: ${CODE_SHAPED}`,
    `connect(); // user,password: ${CODE_SHAPED}`,
    `x = 1 /* creds,password=${CODE_SHAPED} */`,
  ])("reports %s", (line) => {
    for (const path of ["src/app.js", "src/App.java", "src/app.kt", "src/main.go"]) {
      expect(scan(`${line}\n`, path)).toHaveLength(1);
    }
  });

  it("reports hash comments and a password inside a multi-line block comment", () => {
    expect(scan(`# user,password: ${CODE_SHAPED}\n`, "tool.py")).toHaveLength(1);
    const block = `/*\n * creds,\n * user, password: ${CODE_SHAPED}\n */\nx=1\n`;
    expect(scan(block, "a.js")).toHaveLength(1);
    const doc = `/** @param user, password: ${CODE_SHAPED}\n*/\nclass A {}\n`;
    expect(scan(doc, "A.java")).toHaveLength(1);
  });

  it("still keeps minified code quiet, including a string that contains //", () => {
    const quiet = [
      "function f(e,t){return a({password:e.target.value}),(e.password==t.password)||g(e.password==e.pass)||h()}",
      "x=e.secret===t.secret&&n,y={apiKey:r.config.apikey});",
      'var u="see //cdn";if(t.password==e.pass)||y',
      'var s="a//b";f(a,password:e.target.value})',
      "const re=/\\/\\/,password:e.target.value}/;g(a)",
    ];
    for (const line of quiet) expect(scan(`${line}\n`, "dist/a.js")).toHaveLength(0);
  });

  it("does not take a // inside a string as a comment", () => {
    const text = `f("http://x/",password:${CODE_SHAPED}})\n`;
    expect(scan(text, "dist/a.js")).toHaveLength(0);
  });
});

describe("rare minified shapes stay quiet (#460 R2)", () => {
  it.each([
    "a?password:e.target.value}",
    "o[password]=e.target.value}",
    "a|password:e.target.x||y",
  ])("ignores %s", (line) => {
    expect(scan(`${line}\n`, "dist/a.js")).toHaveLength(0);
  });

  it("keeps a URL query password: `?` before `=` and `&` are not code tokens", () => {
    const text = `see(?password=${CODE_SHAPED}\nsee&password=${CODE_SHAPED}\n`;
    expect(scan(text, "tool.py").length).toBeGreaterThanOrEqual(1);
  });
});

describe("comment lookup", () => {
  const lookups = (text: string, path = "a.js") => createSourceLookups(text, path);

  it("finds line and block comments, not openers inside strings, regexes or after division", () => {
    const text = 'a=1; // c\nb="//x"; /* y */ d=/\\/\\//; e=a/b\n';
    const { inComment } = lookups(text);
    expect(inComment(text.indexOf("// c") + 3)).toBe(true);
    expect(inComment(text.indexOf("/* y") + 4)).toBe(true);
    expect(inComment(text.indexOf("//x") + 1)).toBe(false);
    expect(inComment(text.indexOf("e=a"))).toBe(false);
    expect(inComment(text.length - 2)).toBe(false);
  });

  it("uses the comment syntax of the language", () => {
    const python = "x = 1  # note\ny = 2 // 3\n";
    const { inComment } = lookups(python, "a.py");
    expect(inComment(python.indexOf("note"))).toBe(true);
    expect(inComment(python.indexOf("// 3"))).toBe(false);
  });

  it("treats an unterminated block comment as a string (reported), not a comment", () => {
    const found = lookups("/* never closed\nx\n");
    expect(found.inComment(5)).toBe(false);
    expect(found.stringStart(5)).toBe(0);
  });

  it("stays fast on hostile 1 MB inputs (generous bound, linear scan)", () => {
    const inputs = [
      "/".repeat(1_000_000),
      `/*${"*/".repeat(500_000)}`,
      `// ${"x".repeat(1_000_000)}`,
    ];
    const started = performance.now();
    for (const input of inputs) lookups(`${input}\n`).inComment(10);
    expect(performance.now() - started).toBeLessThan(10_000);
  });
});
