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
    ["a Rust string after a 'static lifetime", 'const A: &\'static str = "\nMARK\n";', "a.rs"],
    ["a Rust string after lifetimes", "fn f<'a>(x: &'a str) -> &'a str { \"\nMARK\n\" }", "a.rs"],
    ["a Rust string after a char literal", "let q = 'a'; let a = \"\nMARK\n\";", "a.rs"],
    ["a Rust string after an escaped char", "let q = '\\n'; let a = \"\nMARK\n\";", "a.rs"],
    ["a Rust string after a quote char", 'let q = \'"\'; let a = "\nMARK\n";', "a.rs"],
    ["a Rust string after a byte char", 'let q = b\'"\'; let a = "\nMARK\n";', "a.rs"],
    ["a Rust string after a unicode char", "let q = '😀'; let a = \"\nMARK\n\";", "a.rs"],
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
    [
      "code after a closed string with a 'static lifetime",
      'const A: &\'static str = "\nx\n";\nMARK',
      "a.rs",
    ],
    ["code after a Rust loop label", "'outer: loop { break 'outer; }\nMARK", "a.rs"],
    ["code after a Rust char literal", "let q = 'a'; MARK", "a.rs"],
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
    ["an unterminated quote, past a closed string", 'it\'s "q" MARK', "a.ts"],
  ])("treats the rest after %s as inside a string (reported)", (_label, text, path) => {
    expect(inside(text, path)).toBe(true);
  });

  it.each([
    [
      "a template after a regex that follows if (…)",
      "if (x) /`/.test(s);\nconst a = `\nMARK`;",
      "a.ts",
    ],
    [
      "a template after a regex that follows while (…)",
      "while (f(x)) /`/.exec(s);\nconst a = `\nMARK`;",
      "a.ts",
    ],
    ["a template after a BOM and a regex", "﻿/`/.test(x);\nconst a = `\nMARK`;", "a.ts"],
    [
      "a template after a regex over 512 characters",
      `const r = /${"x".repeat(600)}\`/;\nconst a = \`\nMARK\`;`,
      "a.ts",
    ],
    [
      "a template after an apostrophe and a stray backtick in JSX text",
      "const x = <p>Don't press the ` key</p>;\nconst a = `\nMARK`;",
      "a.tsx",
    ],
    [
      "a template after an apostrophe and a stray /* in JSX text",
      "const x = <p>Don't type /* here</p>;\nconst a = `\nMARK`;\n// */",
      "a.tsx",
    ],
    [
      "a template in a Vue file after an apostrophe and a backtick",
      "<template><p>Don't press `</p></template>\n<script>const a = `\nMARK`</script>",
      "a.vue",
    ],
    [
      "a Python block after an apostrophe and a triple quote",
      'y = \'it"""\nDSN = """\nMARK\n"""',
      "a.py",
    ],
    ["a Ruby string after a shift of a quoted string", "items <<'x'\nq = \"\nx\nMARK\n\"", "a.rb"],
    ["a Ruby string after a bare lowercase shift", 'x = <<item\nq = "\nitem\nMARK\n"', "a.rb"],
    ["a Ruby string after a shift of a negative name", 'y = a <<-n\nq = "\nn\nMARK\n"', "a.rb"],
    [
      "a template after a division by a parenthesized value and a quote",
      'const r = (a) / "/"; const t = `\nMARK`;',
      "a.ts",
    ],
    ["a lowercase Ruby heredoc", "a = <<~eos\n  MARK\neos", "a.rb"],
    ["a lowercase Ruby heredoc with a dash", "a = <<-eos\n  MARK\n  eos", "a.rb"],
    ["a quoted lowercase Ruby heredoc", "a = <<'eos'\n  MARK\neos", "a.rb"],
    [
      "a C# interpolated verbatim string with quotes in a hole",
      'var a = $@"{(b ? "x" : "y")}\nMARK\n";',
      "a.cs",
    ],
    ["a C# @$ interpolated verbatim string", 'var a = @$"{f("}")} {{\nMARK\n";', "a.cs"],
    [
      "a Rust raw string with more than 8 #",
      'let a = r##########"\n"#; MARK\n"##########;',
      "a.rs",
    ],
    [
      "a Swift raw string with more than 8 #",
      'let a = ##########"\n"#; MARK\n"##########',
      "a.swift",
    ],
  ])("finds text inside %s (#158)", (_label, text, path) => {
    expect(inside(text, path)).toBe(true);
  });

  it.each([
    [
      "code after a division by a parenthesized value",
      'const r = (a) / b / c; const s = "/";\nMARK',
      "a.ts",
    ],
    ["code after a call divided twice", "const r = f(a) / 2 / g(b);\nMARK", "a.ts"],
    [
      "code after a closed C# interpolated verbatim string",
      'var a = $@"{(b ? "x" : "y")}\n";\nMARK',
      "a.cs",
    ],
    ["code after a closed lowercase Ruby heredoc", "a = <<~eos\n  x\neos\nMARK", "a.rb"],
    ["code after a Ruby shift into a lowercase name", "list <<item\nMARK", "a.rb"],
    [
      "code after a Rust raw string with more than 8 #",
      'let a = r##########"\n"#;\n"##########;\nMARK',
      "a.rs",
    ],
  ])("finds %s outside strings (#158)", (_label, text, path) => {
    expect(inside(text, path)).toBe(false);
  });

  it("stays linear on long lines with many quotes (#158)", () => {
    const text = (shape: string, prefix: string, suffix: string) =>
      prefix + shape.repeat(Math.ceil(1_000_000 / shape.length)) + suffix;
    const inputs: [string, string][] = [
      // A stray apostrophe in JSX text, then JSON escaped inside a single-quoted string.
      [
        text('\\"k\\":\\"v\\",', "const a = <p>Don't</p>, j = JSON.parse('{", "}');\n"),
        "bundle.js",
      ],
      [text('\\"', '"', "\nconst z = 1;\n"), "a.ts"],
      [text('\\"', '"', "\nz = 1\n"), "a.py"],
      [text("\\'", "'", "\nlet z = 1;\n"), "a.rs"],
      [text("'\\", "'", "\nconst z = 1;\n"), "a.ts"],
      [text("it's ", "x = 1\n", "\n"), "a.ts"],
    ];
    for (const [input, path] of inputs) {
      const start = performance.now();
      const lookup = createStringLookup(input, path);
      lookup(input.length - 1);
      // Quadratic scanning of a 1 MB line takes minutes; linear takes tens of milliseconds.
      expect(performance.now() - start).toBeLessThan(2_000);
    }
  }, 180_000);

  it("stays linear on large and pathological inputs", () => {
    const shapes = [
      "const x = { a: `${`${'\"/[",
      "(/[",
      'x <<~A <<<B r#"',
      'a = """ \' " `\n',
      "/* // ' \" ` */ ",
    ];
    // Best of 3 runs per size: a single run is noisy when other test files run in parallel.
    const time = (text: string) => {
      let best = Infinity;
      for (let run = 0; run < 3; run += 1) {
        const start = performance.now();
        const lookup = createStringLookup(text, "big.ts");
        lookup(text.length - 1);
        createStringLookup(text, "big.rb")(0);
        createStringLookup(text, "big.py")(0);
        best = Math.min(best, performance.now() - start);
      }
      return best;
    };
    for (const shape of shapes) {
      const unit = shape.repeat(Math.ceil(5_000_000 / shape.length)).slice(0, 5_000_000);
      time(unit.slice(0, 100_000)); // warm up
      const small = time(unit);
      const large = time(unit.repeat(8)); // 40 MB
      // 8x the input should take roughly 8x the time (64x if quadratic). The ratio limit is
      // generous so a loaded machine does not fail it; the absolute bound is loose because CI
      // runners are much slower than local machines.
      expect(large / Math.max(small, 1)).toBeLessThan(40);
      expect(large).toBeLessThan(10_000);
    }
  }, 180_000);
});
