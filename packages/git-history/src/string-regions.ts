/**
 * Finds where string literals (also multi-line ones) sit in a source file, so the secret detector
 * knows whether a line that looks like code is really code or text inside a string.
 *
 * This is a small per-language state machine over the text, not a lexer. It runs once over the
 * text (linear time). Whenever it cannot tell (an unterminated string, comment or heredoc), it
 * treats the rest as inside a string: callers report what is inside a string, so confusion errs
 * towards reporting.
 */

interface Syntax {
  /** Line comment openers. */
  lineComments: readonly string[];
  /** C-style block comments. */
  blockComments: boolean;
  /** JS template literals (with `${…}`), Go raw strings, or none. */
  backtick: "template" | "raw" | "none";
  /** `"""` and `'''` blocks. */
  tripleQuotes: boolean;
  /** Quote characters whose strings may span lines (all others end at a newline). */
  multiLineQuotes: string;
  heredoc: "ruby" | "php" | "none";
  /** `/…/` regex literals after an operator or keyword. */
  regexLiterals: boolean;
  /** C# `@"…"` verbatim strings. */
  verbatimAt: boolean;
  /** Rust `r#"…"#`, C++ `R"d(…)d"` or Swift `#"…"#` raw strings. */
  rawStrings: "rust" | "cpp" | "swift" | "none";
}

const C_LIKE: Syntax = {
  lineComments: ["//"],
  blockComments: true,
  backtick: "none",
  tripleQuotes: false,
  multiLineQuotes: "",
  heredoc: "none",
  regexLiterals: false,
  verbatimAt: false,
  rawStrings: "none",
};

const SYNTAX_BY_EXTENSION: Record<string, Syntax> = {
  js: { ...C_LIKE, backtick: "template", regexLiterals: true },
  py: { ...C_LIKE, lineComments: ["#"], blockComments: false, tripleQuotes: true },
  rb: {
    ...C_LIKE,
    lineComments: ["#"],
    blockComments: false,
    multiLineQuotes: "\"'",
    heredoc: "ruby",
    regexLiterals: true,
  },
  php: { ...C_LIKE, lineComments: ["//", "#"], multiLineQuotes: "\"'", heredoc: "php" },
  go: { ...C_LIKE, backtick: "raw" },
  rs: { ...C_LIKE, multiLineQuotes: '"', rawStrings: "rust" },
  cs: { ...C_LIKE, tripleQuotes: true, verbatimAt: true },
  cpp: { ...C_LIKE, rawStrings: "cpp" },
  swift: { ...C_LIKE, tripleQuotes: true, rawStrings: "swift" },
  triple: { ...C_LIKE, tripleQuotes: true },
};

const EXTENSION_SYNTAX: Record<string, keyof typeof SYNTAX_BY_EXTENSION> = {
  js: "js",
  jsx: "js",
  mjs: "js",
  cjs: "js",
  ts: "js",
  tsx: "js",
  mts: "js",
  cts: "js",
  vue: "js",
  svelte: "js",
  py: "py",
  rb: "rb",
  php: "php",
  go: "go",
  rs: "rs",
  cs: "cs",
  cc: "cpp",
  cpp: "cpp",
  hpp: "cpp",
  h: "cpp",
  swift: "swift",
  java: "triple",
  kt: "triple",
  kts: "triple",
  scala: "triple",
  groovy: "triple",
  dart: "triple",
};

function syntaxFor(path: string): Syntax {
  const extension = /\.([A-Za-z0-9]+)$/.exec(path)?.[1]?.toLowerCase() ?? "";
  const name = EXTENSION_SYNTAX[extension];
  return name === undefined ? C_LIKE : (SYNTAX_BY_EXTENSION[name] as Syntax);
}

/**
 * A regex literal body longer than this is not taken as one. The scan stays linear at any limit
 * because a failed attempt is never searched again (`failedRegexUntil`).
 */
const MAX_REGEX_LENGTH = 4096;
/** Deeper `${…}` nesting than this is treated as confusion (inside a string). */
const MAX_TEMPLATE_DEPTH = 32;
const REGEX_BEFORE_CHARS = "(,=:[!&|?{};+-*%<>~^";
const REGEX_BEFORE_WORDS = new Set([
  "return",
  "typeof",
  "case",
  "do",
  "else",
  "in",
  "of",
  "new",
  "delete",
  "void",
  "throw",
  "yield",
  "await",
  "when",
  "if",
  "unless",
  "and",
  "or",
  "not",
]);
/** Keywords whose `( … )` condition may be followed by a regex literal. */
const CONTROL_WORDS = new Set(["if", "while", "for", "with", "unless", "until", "elsif"]);
const IDENTIFIER_CHAR = /[\w$]/;

class Scanner {
  /** Flat, sorted `[start, end)` pairs of string regions. */
  readonly regions: number[] = [];
  private readonly text: string;
  private readonly syntax: Syntax;
  /** Heredoc terminators waiting for the end of the current line. */
  private pendingHeredocs: { id: string; php: boolean }[] = [];
  /**
   * End of the last failed regex literal attempt. A `/` before it is taken as division, so no
   * stretch of text is searched for a closing `/` twice (keeps the scan linear).
   */
  private failedRegexUntil = -1;

  constructor(text: string, syntax: Syntax) {
    this.text = text;
    this.syntax = syntax;
  }

  private add(start: number, end: number, record: boolean): void {
    if (record && end > start) this.regions.push(start, end);
  }

  /**
   * Scans code from `start`. With `untilBrace`, stops at the `}` closing a template
   * interpolation and returns its index; otherwise scans to the end. Regions are recorded only
   * at depth 0 (nested ones lie inside the enclosing template's region).
   */
  scanCode(start: number, untilBrace: boolean, depth: number): number {
    const { text, syntax } = this;
    const record = depth === 0;
    let braces = 0;
    let last = ""; // last significant code character
    let lineStart = true; // only whitespace or comments so far on this line
    /** Per open `(`: whether a control keyword (`if (`, `while (`) comes before it. */
    const parens: boolean[] = [];
    let closedControlParen = false; // the last `)` closed `if (…)`, `while (…)`...
    let index = start;
    while (index < text.length) {
      const char = text[index] as string;
      if (char === "\n") {
        if (this.pendingHeredocs.length > 0) {
          index = this.scanHeredocs(index + 1, record);
          lineStart = true;
          continue;
        }
        lineStart = true;
        index += 1;
        continue;
      }
      if (char === " " || char === "\t" || char === "\r" || char === "\uFEFF") {
        index += 1;
        continue;
      }
      if (syntax.lineComments.some((opener) => text.startsWith(opener, index))) {
        const end = text.indexOf("\n", index);
        index = end === -1 ? text.length : end;
        continue;
      }
      if (syntax.blockComments && text.startsWith("/*", index)) {
        const end = text.indexOf("*/", index + 2);
        if (end === -1) {
          this.add(index, text.length, record); // unterminated: confused, report
          return text.length;
        }
        index = end + 2;
        continue;
      }
      const atLineStart = lineStart;
      lineStart = false;
      if (
        syntax.regexLiterals &&
        char === "/" &&
        index >= this.failedRegexUntil &&
        this.regexAllowed(index, last, closedControlParen)
      ) {
        const end = this.regexEnd(index);
        if (end !== -1) {
          index = end;
          last = "a";
          continue;
        }
      }
      if (
        syntax.heredoc !== "none" &&
        char === "<" &&
        this.readHeredoc(index, atLineStart ? "" : last)
      ) {
        index += 2;
        last = "<";
        continue;
      }
      const stringEnd = this.stringAt(index, depth);
      if (stringEnd !== -1) {
        // A quote left open at the end of its line (an apostrophe in JSX text, `it's`) is
        // confusion: the rest of the line is a string region (reported) and is not scanned. The
        // scan must not resume inside it: after a stray quote, a backtick or `/*` may be stray
        // too, and reading it as an opener would hide a later real template.
        this.add(index, stringEnd, record);
        index = stringEnd;
        last = '"';
        continue;
      }
      if (syntax.regexLiterals) {
        if (char === "(") parens.push(CONTROL_WORDS.has(this.wordBefore(index)));
        else if (char === ")") closedControlParen = parens.pop() === true;
      }
      if (untilBrace) {
        if (char === "{") braces += 1;
        else if (char === "}") {
          if (braces === 0) return index;
          braces -= 1;
        }
      }
      last = char;
      index += 1;
    }
    return text.length;
  }

  /** End (exclusive) of a string literal starting at `index`, or -1 if none starts there. */
  private stringAt(index: number, depth: number): number {
    const { text, syntax } = this;
    const char = text[index] as string;
    const before = index > 0 ? (text[index - 1] as string) : "";
    if (
      syntax.rawStrings === "rust" &&
      (char === "r" || char === "b") &&
      !IDENTIFIER_CHAR.test(before)
    ) {
      const r = text[index] === "b" ? index + 1 : index;
      if (text[r] === "r") {
        const hashes = this.hashesAt(r + 1);
        if (text[r + 1 + hashes] === '"') {
          const close = `"${"#".repeat(hashes)}`;
          const end = text.indexOf(close, r + 2 + hashes);
          return end === -1 ? text.length : end + close.length;
        }
      }
    }
    if (syntax.rawStrings === "cpp" && char === "R" && !IDENTIFIER_CHAR.test(before)) {
      const raw = /^R"([^()\\\s]{0,16})\(/.exec(text.slice(index, index + 20));
      if (raw) {
        const close = `)${raw[1] ?? ""}"`;
        const end = text.indexOf(close, index + raw[0].length);
        return end === -1 ? text.length : end + close.length;
      }
    }
    if (syntax.rawStrings === "swift" && char === "#" && before !== "#") {
      const hashes = this.hashesAt(index);
      if (text[index + hashes] === '"') {
        const close = `"${"#".repeat(hashes)}`;
        const end = text.indexOf(close, index + hashes + 1);
        return end === -1 ? text.length : end + close.length;
      }
    }
    if (char === "`") {
      if (syntax.backtick === "raw") {
        const end = text.indexOf("`", index + 1);
        return end === -1 ? text.length : end + 1;
      }
      if (syntax.backtick === "template") {
        return this.templateEnd(index + 1, depth);
      }
    }
    if (char !== '"' && char !== "'") return -1;
    if (syntax.rawStrings === "rust" && char === "'" && this.isRustLifetime(index)) return -1;
    if (syntax.tripleQuotes && text.startsWith(char.repeat(3), index)) {
      return this.quotedEnd(index + 3, char.repeat(3), true);
    }
    if (
      syntax.verbatimAt &&
      char === '"' &&
      (before === "@" || (before === "$" && text[index - 2] === "@"))
    ) {
      return this.verbatimEnd(index + 1, before === "$" || text[index - 2] === "$", depth);
    }
    return this.quotedEnd(index + 1, char, syntax.multiLineQuotes.includes(char));
  }

  /**
   * Whether the `'` at `index` starts a Rust lifetime or loop label (`&'static`, `<'a>`,
   * `'outer:`) rather than a char literal (`'a'`, `'\n'`, `'\u{1F600}'`, `'"'`): an identifier
   * follows and no `'` closes it as a single character.
   */
  private isRustLifetime(index: number): boolean {
    const { text } = this;
    const next = text.codePointAt(index + 1);
    if (next === undefined) return false;
    const width = next > 0xffff ? 2 : 1;
    if (text[index + 1 + width] === "'") return false; // a one-character literal
    return /[A-Za-z_]/.test(text[index + 1] as string);
  }

  /**
   * End (exclusive) of a C# verbatim string whose body starts at `start`. `""` is an escaped
   * quote and there are no backslash escapes. In an interpolated one (`$@"…"`), a `{…}` hole is
   * code that may hold strings of its own (`{(a ? "x" : "y")}`); `{{` is a literal brace.
   */
  private verbatimEnd(start: number, interpolated: boolean, depth: number): number {
    const { text } = this;
    for (let cursor = start; cursor < text.length; cursor += 1) {
      const char = text[cursor];
      if (char === '"') {
        if (text[cursor + 1] !== '"') return cursor + 1;
        cursor += 1;
      } else if (interpolated && char === "{") {
        if (text[cursor + 1] === "{") cursor += 1;
        else if (depth >= MAX_TEMPLATE_DEPTH) return text.length;
        else cursor = this.scanCode(cursor + 1, true, depth + 1);
      }
    }
    return text.length;
  }

  /** Number of `#` characters at `index` (at most 255, as in Rust raw strings). */
  private hashesAt(index: number): number {
    let count = 0;
    while (count < 255 && this.text[index + count] === "#") count += 1;
    return count;
  }

  /** End (exclusive) of a quoted string whose body starts at `start`. */
  private quotedEnd(start: number, close: string, multiLine: boolean): number {
    const { text } = this;
    for (let cursor = start; cursor < text.length; cursor += 1) {
      const char = text[cursor];
      if (char === "\\") cursor += 1;
      else if (char === "\n" && !multiLine)
        return cursor; // unterminated: the rest of the line
      else if (char === close[0] && text.startsWith(close, cursor)) return cursor + close.length;
    }
    return text.length;
  }

  /** End (exclusive) of a template literal whose body starts at `start`. */
  private templateEnd(start: number, depth: number): number {
    const { text } = this;
    if (depth >= MAX_TEMPLATE_DEPTH) return text.length;
    for (let cursor = start; cursor < text.length; cursor += 1) {
      const char = text[cursor];
      if (char === "\\") cursor += 1;
      else if (char === "`") return cursor + 1;
      else if (char === "$" && text[cursor + 1] === "{") {
        cursor = this.scanCode(cursor + 2, true, depth + 1);
      }
    }
    return text.length;
  }

  /**
   * Whether a `/` after the code character `last` starts a regex literal. After `)` it does only
   * when the parenthesis closed a control condition (`if (x) /re/.test(s)`); otherwise a `)`
   * followed by `/` is division.
   */
  private regexAllowed(index: number, last: string, closedControlParen: boolean): boolean {
    const next = this.text[index + 1];
    if (next === "/" || next === "*") return false;
    if (last === "") return true;
    if (last === ")") return closedControlParen;
    if (REGEX_BEFORE_CHARS.includes(last)) return true;
    if (!IDENTIFIER_CHAR.test(last)) return false;
    return REGEX_BEFORE_WORDS.has(this.wordBefore(index));
  }

  /** The identifier (up to 16 characters) right before `index`, skipping whitespace. */
  private wordBefore(index: number): string {
    const { text } = this;
    let cursor = index - 1;
    while (cursor >= 0 && /\s/.test(text[cursor] as string)) cursor -= 1;
    const wordEnd = cursor + 1;
    while (cursor >= 0 && wordEnd - cursor <= 16 && IDENTIFIER_CHAR.test(text[cursor] as string)) {
      cursor -= 1;
    }
    return text.slice(cursor + 1, wordEnd);
  }

  /** End (exclusive, after flags) of a regex literal at `index` on its line, or -1. */
  private regexEnd(index: number): number {
    const { text } = this;
    let inClass = false;
    const limit = Math.min(text.length, index + MAX_REGEX_LENGTH);
    let cursor = index + 1;
    for (; cursor < limit; cursor += 1) {
      const char = text[cursor];
      if (char === "\n") break;
      if (char === "\\") cursor += 1;
      else if (char === "[") inClass = true;
      else if (char === "]") inClass = false;
      else if (char === "/" && !inClass) {
        let end = cursor + 1;
        while (end < text.length && /[a-z]/i.test(text[end] as string)) end += 1;
        return end;
      }
    }
    this.failedRegexUntil = cursor;
    return -1;
  }

  /** Records a heredoc opened at `index` (`<<~EOS`, `<<-EOS`, `<<<EOT`), if there is one. */
  private readHeredoc(index: number, last: string): boolean {
    const php = this.syntax.heredoc === "php";
    const opener = php
      ? /^<<<[ \t]{0,4}(["']?)([A-Za-z_]\w{0,63})\1/
      : /^<<([~-]?)(["'`]?)([A-Za-z_][A-Za-z0-9_]{0,63})\2/;
    const match = opener.exec(this.text.slice(index, index + 80));
    if (!match) return false;
    // `send :<<'x'` is the symbol `:<<`, not a heredoc.
    if (!php && this.text[index - 1] === ":") return false;
    // A lowercase name is a heredoc only where a value can start (`x = <<~eos`, `f(<<~eos`,
    // `a, <<~eos`) and not after an operand (`list <<'x'`, `a <<-n` are shifts). A bare `<<name`
    // is always a shift. A wrong guess could hide a later string, so doubtful cases are code.
    if (!php && /^[a-z]/.test(match[3] as string)) {
      if (match[1] === "" && match[2] === "") return false;
      if (last !== "" && !"=(,[{|&:?".includes(last)) return false;
    }
    this.pendingHeredocs.push({ id: (php ? match[2] : match[3]) as string, php });
    return true;
  }

  /** Records the bodies of pending heredocs starting at `start`; returns where code resumes. */
  private scanHeredocs(start: number, record: boolean): number {
    const { text } = this;
    let cursor = start;
    for (const { id } of this.pendingHeredocs) {
      const bodyStart = cursor;
      const terminator = new RegExp(`^[ \\t]*${id}(?![\\w])`);
      for (;;) {
        if (cursor >= text.length) {
          this.add(bodyStart, text.length, record); // unterminated: confused, report
          this.pendingHeredocs = [];
          return text.length;
        }
        const lineEnd = text.indexOf("\n", cursor);
        const end = lineEnd === -1 ? text.length : lineEnd;
        if (terminator.test(text.slice(cursor, Math.min(end, cursor + 80)))) {
          this.add(bodyStart, cursor, record);
          cursor = lineEnd === -1 ? text.length : lineEnd + 1;
          break;
        }
        cursor = end + 1;
      }
    }
    this.pendingHeredocs = [];
    return cursor;
  }
}

/**
 * Returns a lookup giving the start of the string literal that `index` lies inside in the source
 * file at `path`, or -1 when it is not inside one. The whole file is judged, so strings that
 * started on an earlier line count.
 */
export function createStringLookup(text: string, path: string): (index: number) => number {
  const scanner = new Scanner(text, syntaxFor(path));
  scanner.scanCode(0, false, 0);
  const { regions } = scanner;
  return (index) => {
    // Last region whose start is <= index.
    let low = 0;
    let high = regions.length / 2;
    while (low < high) {
      const middle = (low + high) >> 1;
      if ((regions[middle * 2] as number) <= index) low = middle + 1;
      else high = middle;
    }
    if (low === 0 || index >= (regions[(low - 1) * 2 + 1] as number)) return -1;
    return regions[(low - 1) * 2] as number;
  };
}
