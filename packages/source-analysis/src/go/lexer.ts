/**
 * Minimal Go lexer for syntax-level analysis. It removes comments and replaces every string or
 * rune literal with a placeholder `"#<n>"`, keeping line breaks so positions map to the
 * original lines. Patterns can then be matched on code without being fooled by text inside
 * strings or comments. It does not build an AST and has no type information.
 */
export interface MaskedGoSource {
  code: string;
  literals: string[];
}

export function maskGoSource(source: string): MaskedGoSource {
  const literals: string[] = [];
  let output = "";
  let index = 0;
  const length = source.length;
  const pushLiteral = (raw: string, content: string) => {
    const newlines = raw.split("\n").length - 1;
    output += `"#${literals.length}"${"\n".repeat(newlines)}`;
    literals.push(content);
  };
  while (index < length) {
    const char = source[index];
    const next = source[index + 1];
    if (char === "/" && next === "/") {
      while (index < length && source[index] !== "\n") index += 1;
      continue;
    }
    if (char === "/" && next === "*") {
      const end = source.indexOf("*/", index + 2);
      const stop = end === -1 ? length : end + 2;
      output += source.slice(index, stop).replace(/[^\n]/g, " ");
      index = stop;
      continue;
    }
    if (char === "`") {
      const end = source.indexOf("`", index + 1);
      const stop = end === -1 ? length : end + 1;
      const raw = source.slice(index, stop);
      pushLiteral(raw, raw.slice(1, -1));
      index = stop;
      continue;
    }
    if (char === '"' || char === "'") {
      let cursor = index + 1;
      while (cursor < length && source[cursor] !== char && source[cursor] !== "\n") {
        cursor += source[cursor] === "\\" ? 2 : 1;
      }
      const stop = Math.min(cursor + 1, length);
      const raw = source.slice(index, stop);
      pushLiteral(raw, raw.slice(1, -1));
      index = stop;
      continue;
    }
    output += char;
    index += 1;
  }
  return { code: output, literals };
}

export function lineAt(code: string, offset: number): number {
  let line = 1;
  for (let index = 0; index < offset && index < code.length; index += 1) {
    if (code.charCodeAt(index) === 10) line += 1;
  }
  return line;
}

/** Splits the argument list of a call whose `(` is at `openIndex`, at top-level commas. */
export function readCallArguments(
  code: string,
  openIndex: number,
): { args: string[]; end: number } {
  const args: string[] = [];
  let depth = 0;
  let current = "";
  for (let index = openIndex; index < code.length; index += 1) {
    const char = code[index] as string;
    if (char === "(" || char === "[" || char === "{") {
      depth += 1;
      if (depth === 1) continue;
    } else if (char === ")" || char === "]" || char === "}") {
      depth -= 1;
      if (depth === 0) {
        if (current.trim().length > 0) args.push(current.trim());
        return { args, end: index };
      }
    } else if (char === "," && depth === 1) {
      args.push(current.trim());
      current = "";
      continue;
    }
    current += char;
  }
  return { args, end: code.length };
}

export const LITERAL_PATTERN = /^"#(\d+)"$/;

export function literalValue(arg: string, literals: string[]): string | null {
  const match = LITERAL_PATTERN.exec(arg.trim());
  return match ? (literals[Number(match[1])] ?? null) : null;
}
