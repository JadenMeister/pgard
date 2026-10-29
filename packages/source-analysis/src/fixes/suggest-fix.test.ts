import { applyLineReplacementDiff, type Finding } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import { SOURCE_RULES } from "../rules.js";
import { FIXABLE_RULE_IDS, suggestFix } from "./suggest-fix.js";

type Subject = Pick<Finding, "ruleId" | "location" | "evidence">;

const subject = (ruleId: string, path: string, line: number, evidence: string): Subject => ({
  ruleId,
  evidence,
  location: { kind: "file", path, line, url: null, commit: null },
});

const COOKIE = "res.cookie(session-like name) without httpOnly, secure, sameSite";
const cookie = (line: string, path = "src/a.js") =>
  suggestFix(subject("PG-COOKIE-001", path, 1, COOKIE), line);
const spring = (flag: "Secure" | "HttpOnly", line: string, path: string) =>
  suggestFix(
    subject(
      "PG-COOKIE-001",
      path,
      1,
      `server.servlet.session.cookie.${flag === "Secure" ? "secure" : "http-only"}=false sends the session cookie without ${flag} (profile x)`,
    ),
    line,
  );
const random = (text: string, line: number, path = "src/A.java") =>
  suggestFix(
    subject("PG-CRYPTO-003", path, line, "non-cryptographic random bytes written into salt"),
    text,
  );

function diffOf(fix: ReturnType<typeof cookie>): string {
  expect(fix?.kind).toBe("diff");
  return fix?.diff ?? "";
}

describe("fixable rules", () => {
  it("rules.ts marks exactly the rules that have a fixer", () => {
    const declared = SOURCE_RULES.filter((rule) => "fixable" in rule && rule.fixable === true).map(
      (rule) => rule.id,
    );
    expect([...declared].sort()).toEqual([...FIXABLE_RULE_IDS].sort());
  });

  it("gives nothing for a rule that is not fixable", () => {
    expect(suggestFix(subject("PG-SQL-001", "a.js", 1, "x"), "pool.query(`${x}`)")).toBeNull();
    expect(suggestFix(subject("PG-CRYPTO-001", "a.js", 1, "x"), "md5(password)")).toBeNull();
  });
});

describe("PG-COOKIE-001 Express res.cookie", () => {
  it("adds all three flags to a call without options", () => {
    const diff = diffOf(cookie('  res.cookie("sid", token);'));
    expect(diff).toContain(
      '+  res.cookie("sid", token, { httpOnly: true, secure: true, sameSite: "lax" });',
    );
  });

  it("adds only the missing flags and keeps the existing options", () => {
    const diff = diffOf(
      cookie('res.cookie("session", issue(req), { maxAge: 3600000, httpOnly: true });'),
    );
    expect(diff).toContain(
      '+res.cookie("session", issue(req), { maxAge: 3600000, httpOnly: true, secure: true, sameSite: "lax" });',
    );
  });

  it("keeps the quote style of the cookie name", () => {
    const diff = diffOf(cookie("res.cookie('sid', token);"));
    expect(diff).toContain("sameSite: 'lax'");
  });

  it("is idempotent: the rewritten line gets no second diff", () => {
    const fix = cookie('  res.cookie("sid", token);');
    const after = applyLineReplacementDiff('  res.cookie("sid", token);', fix?.diff ?? "");
    expect(after).not.toBeNull();
    expect(cookie(after ?? "")).toEqual({
      kind: "guidance",
      confidence: "low",
      reason: "context_not_supported",
    });
  });

  it("gives guidance, not a diff, when the context is ambiguous", () => {
    const ambiguous = [
      'res.cookie("sid", token, opts);', // options not a literal
      'res.cookie("sid", token, { ...base });', // spread
      'res.cookie("sid", token, { httpOnly: false });', // explicit off: a decision for a person
      'res.cookie("sid", token, { secure: isProd });', // flag from a variable
      'res.cookie("sid", token, { sameSite: "lax" }, extra);',
      'res.cookie("sid", token, { nested: { a: 1 } });',
      'res.status(200).cookie("sid", token);', // chained
      'res.cookie("sid", token); res.send();', // two statements
      'res.cookie("sid", token); // note', // comment
      "res.cookie(name, token);", // non literal name
      'res.cookie("sid", `${token}`);', // template
      'res.cookie("sid", "literal-secret-value");', // a string value could be a secret
      'res.cookie("sid", token,',
    ];
    for (const line of ambiguous) {
      const fix = cookie(line);
      expect(fix, line).toMatchObject({ kind: "guidance", reason: "context_not_supported" });
      expect(fix?.diff).toBeUndefined();
    }
  });

  it("needs the finding to be about this call and a JS or TS file", () => {
    expect(
      suggestFix(
        subject("PG-COOKIE-001", "src/a.js", 1, "express-session cookie without secure"),
        'res.cookie("sid", token);',
      ),
    ).toMatchObject({ kind: "guidance" });
    expect(cookie('res.cookie("sid", token);', "src/a.py")).toMatchObject({ kind: "guidance" });
  });

  it("gives guidance for CRLF lines and for a line number outside the file", () => {
    expect(cookie('res.cookie("sid", token);\r')).toMatchObject({ kind: "guidance" });
    expect(suggestFix(subject("PG-COOKIE-001", "src/a.js", 9, COOKIE), "one line")).toMatchObject({
      kind: "guidance",
    });
  });

  it("never echoes a secret", () => {
    // The pattern accepts identifiers only; a secret-looking name or value is still refused.
    const secretish = [
      'res.cookie("sid", token, { path: "/", domain: "AKIAABCDEFGHIJKLMNOP" });',
      'res.cookie("sid", token, { secret: "hunter2" });',
      'res.cookie("sid", ghp_abcdefghijklmnopqrstuvwxyz0123456789);',
    ];
    for (const line of secretish) {
      expect(cookie(line)?.diff, line).toBeUndefined();
    }
    const diff = cookie('res.cookie("password=hunter2", token);')?.diff;
    expect(diff).toBeUndefined();
  });
});

describe("PG-COOKIE-001 Spring configuration", () => {
  it("turns an explicit off value into true, keeping separator, indent and quotes", () => {
    const cases: Array<[string, string, string, "Secure" | "HttpOnly", string]> = [
      [
        "server.servlet.session.cookie.secure=false",
        "server.servlet.session.cookie.secure=true",
        "application.properties",
        "Secure",
        "",
      ],
      [
        "server.servlet.session.cookie.http-only = no",
        "server.servlet.session.cookie.http-only = true",
        "application.properties",
        "HttpOnly",
        "",
      ],
      ["        http-only: false", "        http-only: true", "application.yml", "HttpOnly", ""],
      [
        '        "http-only": "off"',
        '        "http-only": "true"',
        "application.yaml",
        "HttpOnly",
        "",
      ],
      [
        "server.servlet.session.cookie.secure: 0",
        "server.servlet.session.cookie.secure: true",
        "application.yml",
        "Secure",
        "",
      ],
    ];
    for (const [before, after, path, flag] of cases) {
      const fix = spring(flag, before, path);
      expect(fix?.kind, before).toBe("diff");
      expect(applyLineReplacementDiff(before, fix?.diff ?? "")).toBe(after);
    }
  });

  it("is idempotent", () => {
    expect(
      spring("Secure", "server.servlet.session.cookie.secure=true", "a.properties"),
    ).toMatchObject({
      kind: "guidance",
    });
  });

  it("gives guidance when the line is not exactly one off flag of the flagged kind", () => {
    const lines: Array<[string, string, "Secure" | "HttpOnly"]> = [
      ["server.servlet.session.cookie.secure=false # dev", "a.properties", "Secure"],
      ["server.servlet.session.cookie.secure=${SECURE:false}", "a.properties", "Secure"],
      ["server.servlet.session.cookie.secure=false", "a.properties", "HttpOnly"], // evidence says HttpOnly
      ["  secure: false", "a.txt", "Secure"],
    ];
    for (const [line, path, flag] of lines) {
      expect(spring(flag, line, path), line).toMatchObject({ kind: "guidance" });
    }
  });
});

describe("PG-CRYPTO-003 java.util.Random", () => {
  const javaFile = (body: string, imports = "import java.util.*;") =>
    ["// corpus", imports, "class A {", body, "}"].join("\n");

  it("replaces a no-argument constructor on the flagged line by a fully qualified SecureRandom", () => {
    const text = javaFile("    new Random().nextBytes(salt);");
    const fix = random(text, 4);
    expect(fix).toMatchObject({ kind: "diff", confidence: "high" });
    expect(applyLineReplacementDiff(text, fix?.diff ?? "")).toContain(
      "    new java.security.SecureRandom().nextBytes(salt);",
    );
  });

  it("accepts an explicit java.util.Random import", () => {
    expect(
      random(javaFile("    new Random().nextBytes(salt);", "import java.util.Random;"), 4),
    ).toMatchObject({
      kind: "diff",
    });
  });

  it("is idempotent", () => {
    const fix = random(javaFile("    new Random().nextBytes(salt);"), 4);
    const after =
      applyLineReplacementDiff(javaFile("    new Random().nextBytes(salt);"), fix?.diff ?? "") ??
      "";
    expect(random(after, 4)).toMatchObject({ kind: "guidance" });
  });

  it("gives guidance when the generator is not created on the flagged line", () => {
    const text = javaFile("    RND.nextBytes(salt);");
    expect(random(text, 4)).toEqual({
      kind: "guidance",
      confidence: "low",
      reason: "context_not_supported",
    });
  });

  it("gives guidance for a seeded generator, another Random class or an unclear import", () => {
    expect(random(javaFile("    new Random(42).nextBytes(salt);"), 4)).toMatchObject({
      kind: "guidance",
    });
    expect(
      random(javaFile("    new Random().nextBytes(salt);", "import com.acme.Random;"), 4),
    ).toMatchObject({ kind: "guidance" });
    expect(
      random(
        javaFile(
          "    new Random().nextBytes(salt);",
          "import java.util.*;\nimport com.acme.Random;",
        ),
        4,
      ),
    ).toMatchObject({ kind: "guidance" });
    expect(
      random(javaFile("    new Random().nextBytes(salt);", "import java.io.*;"), 4),
    ).toMatchObject({ kind: "guidance" });
    expect(random(javaFile("    new Random().nextBytes(salt); // todo"), 4)).toMatchObject({
      kind: "guidance",
    });
    expect(random(javaFile('    var s = "x" + new Random().nextInt();'), 4)).toMatchObject({
      kind: "guidance",
    });
    expect(
      random(javaFile("    new Random().nextBytes(a); new Random().nextBytes(b);"), 4),
    ).toMatchObject({ kind: "guidance" });
  });

  it("handles a Kotlin java.util.Random() on the flagged line only", () => {
    const text = "import java.util.*\nfun f() {\n    java.util.Random().nextBytes(b)\n}";
    const fix = random(text, 3, "src/A.kt");
    expect(applyLineReplacementDiff(text, fix?.diff ?? "")).toContain(
      "java.security.SecureRandom().nextBytes(b)",
    );
    expect(random("    Random().nextBytes(b)", 1, "src/A.kt")).toMatchObject({ kind: "guidance" });
  });

  it("only handles random findings and Java or Kotlin files", () => {
    const text = javaFile("    new Random().nextBytes(salt);");
    expect(
      suggestFix(
        subject("PG-CRYPTO-003", "A.java", 4, 'Cipher.getInstance("AES/ECB/PKCS5Padding")'),
        text,
      ),
    ).toMatchObject({ kind: "guidance" });
    expect(random(text, 4, "src/A.js")).toMatchObject({ kind: "guidance" });
  });
});

describe("determinism and bounds", () => {
  it("gives the same answer every time", () => {
    const line = '  res.cookie("sid", token);';
    expect(JSON.stringify(cookie(line))).toBe(JSON.stringify(cookie(line)));
  });

  it("never builds a diff over the size bound", () => {
    const long = `res.cookie("sid", ${"a".repeat(380)});`;
    const fix = cookie(long);
    expect(fix).toMatchObject({ kind: "guidance" });
    expect(cookie(`res.cookie("sid", ${"a".repeat(42)});`)).toMatchObject({ kind: "guidance" });
    for (const candidate of [fix, cookie('  res.cookie("sid", token);')]) {
      expect((candidate?.diff ?? "").length).toBeLessThanOrEqual(2000);
    }
  });

  it("returns guidance with a too_large reason for a very long flagged line", () => {
    expect(cookie(`res.cookie("sid", ${"a".repeat(500)});`)).toEqual({
      kind: "guidance",
      confidence: "low",
      reason: "too_large",
    });
  });
});
