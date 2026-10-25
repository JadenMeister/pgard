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

/** A regex literal body longer than this is not taken as one (keeps the scan linear). */
const MAX_REGEX_LENGTH = 512;
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
    let index = start;
    while (index < text.length) {
      const char = text[index] as string;
      if (char === "\n") {
        if (this.pendingHeredocs.length > 0) {
          index = this.scanHeredocs(index + 1, record);
          continue;
        }
        index += 1;
        continue;
      }
      if (char === " " || char === "\t" || char === "\r") {
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
      if (
        syntax.regexLiterals &&
        char === "/" &&
        index >= this.failedRegexUntil &&
        this.regexAllowed(index, last)
      ) {
        const end = this.regexEnd(index);
        if (end !== -1) {
          index = end;
          last = "a";
          continue;
        }
      }
      if (syntax.heredoc !== "none" && char === "<" && this.readHeredoc(index)) {
        index += 2;
        last = "<";
        continue;
      }
      const stringEnd = this.stringAt(index, depth);
      if (stringEnd !== -1) {
        this.add(index, stringEnd, record);
        index = stringEnd;
        last = '"';
        continue;
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
      const raw = /^b?r(#{0,8})"/.exec(text.slice(index, index + 12));
      if (raw) {
        const close = `"${raw[1] ?? ""}`;
        const end = text.indexOf(close, index + raw[0].length);
        return end === -1 ? text.length : end + close.length;
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
    if (syntax.rawStrings === "swift" && char === "#") {
      const raw = /^(#{1,8})"/.exec(text.slice(index, index + 10));
      if (raw) {
        const close = `"${raw[1] ?? ""}`;
        const end = text.indexOf(close, index + raw[0].length);
        return end === -1 ? text.length : end + close.length;
      }
    }
    if (char === "`") {
      if (syntax.backtick === "raw") {
        const end = text.indexOf("`", index + 1);
        return end === -1 ? text.length : end + 1;
      }
      if (syntax.backtick === "template") return this.templateEnd(index + 1, depth);
    }
    if (char !== '"' && char !== "'") return -1;
    if (syntax.tripleQuotes && text.startsWith(char.repeat(3), index)) {
      return this.quotedEnd(index + 3, char.repeat(3), true);
    }
    if (
      syntax.verbatimAt &&
      char === '"' &&
      (before === "@" || (before === "$" && text[index - 2] === "@"))
    ) {
      // `""` is an escaped quote; there are no backslash escapes.
      let cursor = index + 1;
      for (;;) {
        const end = text.indexOf('"', cursor);
        if (end === -1) return text.length;
        if (text[end + 1] !== '"') return end + 1;
        cursor = end + 2;
      }
    }
    return this.quotedEnd(index + 1, char, syntax.multiLineQuotes.includes(char));
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

  private regexAllowed(index: number, last: string): boolean {
    const { text } = this;
    const next = text[index + 1];
    if (next === "/" || next === "*") return false;
    if (last === "") return true;
    if (REGEX_BEFORE_CHARS.includes(last)) return true;
    if (!IDENTIFIER_CHAR.test(last)) return false;
    let cursor = index - 1;
    while (cursor >= 0 && /\s/.test(text[cursor] as string)) cursor -= 1;
    const wordEnd = cursor + 1;
    while (cursor >= 0 && wordEnd - cursor <= 16 && IDENTIFIER_CHAR.test(text[cursor] as string)) {
      cursor -= 1;
    }
    return REGEX_BEFORE_WORDS.has(text.slice(cursor + 1, wordEnd));
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
  private readHeredoc(index: number): boolean {
    const php = this.syntax.heredoc === "php";
    const opener = php
      ? /^<<<[ \t]{0,4}(["']?)([A-Za-z_]\w{0,63})\1/
      : /^<<([~-]?)(["'`]?)([A-Z_][A-Za-z0-9_]{0,63})\2/;
    const match = opener.exec(this.text.slice(index, index + 80));
    if (!match) return false;
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
