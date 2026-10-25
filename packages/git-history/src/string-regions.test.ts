import { describe, expect, it } from "vitest";
import { createStringLookup } from "./string-regions.js";

/** Whether the first occurrence of `marker` in `text` is inside a string literal. */
function inside(text: string, path: string, marker = "MARK"): boolean {
  const index = text.indexOf(marker);
  if (index === -1) throw new Error(`no ${marker} in the text`);
  return createStringLookup(text, path)(index) !== -1;
}

describe("createStringLookup (#145)", () => {
  it.each([
    ["double quotes", 'const a = "x MARK";', "a.ts"],
    ["single quotes", "const a = 'x MARK';", "a.ts"],
    ["a template literal on a later line", "const a = `\nMARK\n`;", "a.ts"],
    [
      "a template after an interpolation with a nested template",
      "const a = `${`x`}\nMARK`;",
      "a.ts",
    ],
    ["a string after a regex literal holding a quote", 'const r = /"/; const a = "MARK";', "a.ts"],
    [
      "a template after a regex literal holding a backtick",
      "const r = /`/;\nconst a = `\nMARK`;",
      "a.ts",
    ],
    ["a Python triple-quoted block", 'a = """\nMARK\n"""', "a.py"],
    ["a Python single-quoted triple block", "a = '''\nMARK\n'''", "a.py"],
    ["a Go raw string", "a := `\nMARK\n`", "a.go"],
    ["a Ruby heredoc", "a = <<~EOS\n  MARK\nEOS", "a.rb"],
    ["a Ruby multi-line string", 'a = "\nMARK\n"', "a.rb"],
    ["a PHP heredoc", "$a = <<<EOT\nMARK\nEOT;", "a.php"],
    ["a PHP nowdoc", "$a = <<<'EOT'\nMARK\nEOT;", "a.php"],
    ["a Java text block", 'String a = """\nMARK\n""";', "A.java"],
    ["a Kotlin raw string", 'val a = """\nMARK\n"""', "a.kt"],
    ["a C# verbatim string", 'var a = @"\n""q"" MARK\n";', "a.cs"],
    ["a Rust raw string", 'let a = r#"\n"q" MARK\n"#;', "a.rs"],
    ["a Rust multi-line string", 'let a = "\nMARK\n";', "a.rs"],
    ["a C++ raw string", 'auto a = R"x(\n")" MARK\n)x";', "a.cpp"],
    ["a Swift multi-line string", 'let a = """\nMARK\n"""', "a.swift"],
    ["a string with an escaped quote", 'const a = "x\\" MARK";', "a.ts"],
    ["a string continued with a backslash", 'const a = "x \\\nMARK";', "a.ts"],
  ])("finds text inside %s", (_label, text, path) => {
    expect(inside(text, path)).toBe(true);
  });

  it.each([
    ["code after a closed template", "const a = `x`;\nconst MARK = 1;", "a.ts"],
    ["code after a closed multi-line template", "const a = `\nx\n`;\nMARK", "a.ts"],
    ["code after a line comment with an apostrophe", "// don't\nMARK", "a.ts"],
    ["code after a line comment with a backtick", "// a ` b\nMARK", "a.ts"],
    ["code after a block comment with quotes", '/* it\'s "q" ` */ MARK', "a.ts"],
    ["code after a regex literal holding quotes", "const r = /['\"`]/;\nMARK", "a.ts"],
    ["code after a division", 'const r = a / b; const s = "/";\nMARK', "a.ts"],
    ["code after a Python comment", "# it's\nMARK", "a.py"],
    ["code after a closed Python block", 'a = """x"""\nMARK', "a.py"],
    ["code after a Ruby heredoc", "a = <<~EOS\n  x\nEOS\nMARK", "a.rb"],
    ["code after a Go raw string", "a := `\nx\n`\nMARK", "a.go"],
    ["a Rust lifetime's next line", "fn f<'a>(x: &'a str) {}\nMARK", "a.rs"],
    ["a JS string's next line (strings end at a newline)", "const a = 'it\nMARK", "a.ts"],
  ])("finds %s outside strings", (_label, text, path) => {
    expect(inside(text, path)).toBe(false);
  });

  it.each([
    ["an unterminated template literal", "const a = `x\nMARK", "a.ts"],
    ["an unterminated block comment", "const a = 1; /* x\nMARK", "a.ts"],
    ["an unterminated Python block", 'a = """\nMARK', "a.py"],
    ["an unterminated heredoc", "a = <<~EOS\nMARK", "a.rb"],
    ["an unterminated quote on the same line", "it's MARK", "a.ts"],
  ])("treats the rest after %s as inside a string (reported)", (_label, text, path) => {
    expect(inside(text, path)).toBe(true);
  });

  it("stays linear on large and pathological inputs", () => {
    const shapes = [
      "const x = { a: `${`${'\"/[",
      "(/[",
      'x <<~A <<<B r#"',
      'a = """ \' " `\n',
      "/* // ' \" ` */ ",
    ];
    const time = (text: string) => {
      const start = performance.now();
      const lookup = createStringLookup(text, "big.ts");
      lookup(text.length - 1);
      createStringLookup(text, "big.rb")(0);
      createStringLookup(text, "big.py")(0);
      return performance.now() - start;
    };
    for (const shape of shapes) {
      const unit = shape.repeat(Math.ceil(1_250_000 / shape.length));
      time(unit.slice(0, 100_000)); // warm up
      const small = time(unit.slice(0, 1_250_000));
      const large = time(unit.repeat(4));
      // 4x the input should take roughly 4x the time (16x if quadratic). Only the ratio is
      // checked tightly: CI runners are much slower than local machines.
      expect(large / Math.max(small, 1)).toBeLessThan(10);
      expect(large).toBeLessThan(10_000);
    }
  }, 120_000);
});
