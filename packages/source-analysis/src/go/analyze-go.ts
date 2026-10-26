import type { Confidence, FindingStatus, Severity } from "@pgard/findings";
import type { RawSourceFinding } from "../finding-factory.js";
import type { SourceRuleId } from "../rules.js";
import {
  LITERAL_PATTERN,
  createLineLookup,
  literalValue,
  maskGoSource,
  readCallArguments,
} from "./lexer.js";

/**
 * Syntax-level Go analysis (lexer + patterns, no type checking). Request input, string building
 * and sinks are recognized by well-known package/method names within one file.
 */
export interface GoAnalysis {
  findings: RawSourceFinding[];
  imports: string[];
  /** Unbalanced braces/parens after masking: the file is likely not valid Go. */
  hasParseErrors: boolean;
  /** Rules whose per-file finding cap was reached. */
  cappedRules: string[];
}

const MAX_FINDINGS_PER_RULE_PER_FILE = 25;
const MAX_CALL_ARGUMENT_CHARS = 4000;
const IDENTIFIER_TOKENS = /(?<![\w.])[A-Za-z_]\w*/g;

function hasBalancedDelimiters(code: string): boolean {
  let braces = 0;
  let parens = 0;
  for (let index = 0; index < code.length; index += 1) {
    const char = code.charCodeAt(index);
    if (char === 123) braces += 1;
    else if (char === 125) braces -= 1;
    else if (char === 40) parens += 1;
    else if (char === 41) parens -= 1;
    if (braces < 0 || parens < 0) return false;
  }
  return braces === 0 && parens === 0;
}

const SOURCE_PATTERN =
  /\b\w+\.(?:URL\.Query\(\)|FormValue\(|PostFormValue\(|PostForm\b|Form\b|URL\.Path\b|URL\.RawQuery\b|Header\.Get\()|\bmux\.Vars\(|\bchi\.URLParam\(|\b(?:c|ctx)\.(?:Query|Param|PostForm|DefaultQuery|DefaultPostForm|FormValue|QueryParam|Params|GetQuery)\(/;
const SANITIZER_PATTERN =
  /\b(?:filepath\.Base|path\.Base|strconv\.(?:Atoi|ParseInt|ParseUint|ParseFloat|ParseBool)|uuid\.Parse|url\.QueryEscape|html\.EscapeString|template\.HTMLEscapeString)\(/;
const IDENTIFIER = /^[A-Za-z_]\w*$/;
const PASSWORD_TEXT = /pass(word)?|pwd/i;
const SHELLS = new Set([
  "sh",
  "bash",
  "/bin/sh",
  "/bin/bash",
  "zsh",
  "cmd",
  "cmd.exe",
  "powershell",
  "pwsh",
]);
const SESSION_COOKIE_NAME = /sess|sid|token|auth|jwt|login|remember/i;

interface Evidence {
  severity: Severity;
  status: FindingStatus;
  confidence: Confidence;
  flow: string;
}

function readImports(code: string, literals: string[]): string[] {
  const imports: string[] = [];
  const block = /\bimport\s*\(([^)]*)\)/g;
  for (const match of code.matchAll(block)) {
    for (const literal of (match[1] ?? "").matchAll(/"#(\d+)"/g)) {
      imports.push(literals[Number(literal[1])] ?? "");
    }
  }
  for (const match of code.matchAll(/\bimport\s+(?:[\w.]+\s+)?"#(\d+)"/g)) {
    imports.push(literals[Number(match[1])] ?? "");
  }
  return imports;
}

export function analyzeGoSource(source: string, path: string): GoAnalysis {
  const { code, literals } = maskGoSource(source);
  const imports = readImports(code, literals);
  const has = (prefix: string) =>
    imports.some((name) => name === prefix || name.startsWith(`${prefix}/`));
  const usesSql =
    has("database/sql") || has("github.com/jmoiron/sqlx") || has("github.com/jackc/pgx");
  const usesGorm = has("gorm.io/gorm") || has("github.com/jinzhu/gorm");
  const findings: RawSourceFinding[] = [];
  const cappedRules = new Set<string>();
  const perRuleCount = new Map<string, number>();
  const lineOf = createLineLookup(code);

  // Flow-insensitive, file-level variable facts. Identifiers are looked up in a Set (one pass
  // over the expression), so cost stays linear in the file size.
  const tainted = new Set<string>();
  const dynamic = new Set<string>();
  const referencesAny = (expression: string, names: Set<string>) => {
    if (names.size === 0) return false;
    for (const match of expression.matchAll(IDENTIFIER_TOKENS)) {
      if (names.has(match[0])) return true;
    }
    return false;
  };
  const isTaintedExpr = (expression: string): boolean =>
    !SANITIZER_PATTERN.test(expression) &&
    (SOURCE_PATTERN.test(expression) || referencesAny(expression, tainted));
  // Names whose value is fixed: `const`s, and numbers parsed with strconv. A name counts only when
  // it is bound exactly once in the whole file: a parameter, `:=`, `var`, assignment or second
  // declaration of the same name anywhere (any function) makes it untrusted.
  interface FunctionSpan {
    signature: string;
    start: number;
    end: number;
  }
  const functionSpans: FunctionSpan[] = [];
  const bound = new Map<string, number>();
  const constDeclarations = new Map<string, number>();
  const constPositions = new Map<string, number>();
  const bump = (map: Map<string, number>, name: string) => map.set(name, (map.get(name) ?? 0) + 1);
  const bumpTokens = (text: string) => {
    for (const token of text.matchAll(/[A-Za-z_]\w*/g)) bump(bound, token[0]);
  };
  // Strict: package-level constants. Inferred: block-local constants and strconv-parsed numbers.
  const inertNames = new Set<string>();
  const inferredNames = new Set<string>();
  {
    // `const` declarations: counted separately, then blanked so they do not look like assignments.
    let withoutConsts = "";
    let cursor = 0;
    for (const match of code.matchAll(/\bconst\b/g)) {
      const at = match.index ?? 0;
      if (at < cursor) continue;
      let end = code.indexOf("\n", at);
      if (end === -1) end = code.length;
      const afterKeyword = /^[ \t]*\(/.exec(code.slice(at + 5));
      const lineNames: string[] = [];
      if (afterKeyword) {
        let depth = 0;
        let index = at + 5 + afterKeyword[0].length - 1;
        for (; index < code.length; index += 1) {
          if (code[index] === "(") depth += 1;
          else if (code[index] === ")" && (depth -= 1) === 0) break;
        }
        end = Math.min(index + 1, code.length);
        for (const line of code.slice(at + 5, end).split("\n")) {
          const names = /^[ \t(]*([A-Za-z_]\w*(?:[ \t]*,[ \t]*[A-Za-z_]\w*)*)/.exec(line)?.[1];
          if (names) lineNames.push(...names.split(",").map((name) => name.trim()));
        }
      } else {
        const names = /^[ \t]*([A-Za-z_]\w*(?:[ \t]*,[ \t]*[A-Za-z_]\w*)*)/.exec(
          code.slice(at + 5, end),
        )?.[1];
        if (names) lineNames.push(...names.split(",").map((name) => name.trim()));
      }
      for (const name of lineNames) {
        bump(constDeclarations, name);
        constPositions.set(name, at);
      }
      withoutConsts += code.slice(cursor, at) + code.slice(at, end).replace(/[^\n]/g, " ");
      cursor = end;
    }
    withoutConsts += code.slice(cursor);
    // Function signatures: parameters, receivers and named results are bindings; every token in
    // the signature counts (over-inclusive on purpose).
    for (const match of withoutConsts.matchAll(/\bfunc\b/g)) {
      const at = match.index ?? 0;
      let depth = 0;
      let index = at + 4;
      for (; index < withoutConsts.length; index += 1) {
        const char = withoutConsts[index];
        if (char === "(" || char === "[") depth += 1;
        else if (char === ")" || char === "]") depth -= 1;
        else if (char === "\n" && depth === 0) break;
        else if (char === "{" && depth === 0) {
          if (/\b(?:interface|struct)\s*$/.test(withoutConsts.slice(at, index))) {
            let inner = 0;
            for (; index < withoutConsts.length; index += 1) {
              if (withoutConsts[index] === "{") inner += 1;
              else if (withoutConsts[index] === "}" && (inner -= 1) === 0) break;
            }
            continue;
          }
          break;
        }
      }
      const signature = withoutConsts.slice(at + 4, index);
      bumpTokens(signature);
      if (withoutConsts[index] === "{") {
        let braces = 0;
        let close = index;
        for (; close < withoutConsts.length; close += 1) {
          if (withoutConsts[close] === "{") braces += 1;
          else if (withoutConsts[close] === "}" && (braces -= 1) === 0) break;
        }
        functionSpans.push({ signature, start: index, end: close });
      }
    }
    for (const match of withoutConsts.matchAll(
      /([A-Za-z_]\w*(?:[ \t]*,[ \t]*[A-Za-z_]\w*)*)[ \t]*(?::=|(?:[-+*/|&^%]|<<|>>|&\^)?=(?!=))/g,
    )) {
      const before = withoutConsts[(match.index ?? 0) - 1];
      if (before === "." || before === "]") continue;
      for (const name of (match[1] ?? "").split(",")) bump(bound, name.trim());
    }
    for (const match of withoutConsts.matchAll(/\bvar\b/g)) {
      const at = (match.index ?? 0) + 3;
      const tail = withoutConsts.slice(at);
      if (/^[ \t]*\(/.test(tail)) {
        let depth = 0;
        let index = tail.indexOf("(");
        const first = index;
        for (; index < tail.length; index += 1) {
          if (tail[index] === "(") depth += 1;
          else if (tail[index] === ")" && (depth -= 1) === 0) break;
        }
        for (const line of tail.slice(first + 1, index).split("\n")) {
          const names = /^[ \t]*([A-Za-z_]\w*(?:[ \t]*,[ \t]*[A-Za-z_]\w*)*)/.exec(line)?.[1];
          if (names) for (const name of names.split(",")) bump(bound, name.trim());
        }
      } else {
        const names = /^[ \t]*([A-Za-z_]\w*(?:[ \t]*,[ \t]*[A-Za-z_]\w*)*)/.exec(tail)?.[1];
        if (names) for (const name of names.split(",")) bump(bound, name.trim());
      }
    }
    for (const [name, count] of constDeclarations) {
      if (count !== 1 || bound.has(name)) continue;
      // A const declared inside a block is trusted only when every use of the name is inside that
      // same innermost `{...}`: elsewhere the name may mean a package variable of another file.
      const at = constPositions.get(name) ?? 0;
      let open = -1;
      const stack: number[] = [];
      for (let index = 0; index < at; index += 1) {
        if (code[index] === "{") stack.push(index);
        else if (code[index] === "}") stack.pop();
      }
      open = stack[stack.length - 1] ?? -1;
      if (open === -1) {
        inertNames.add(name);
        continue;
      }
      let depth = 0;
      let close = open;
      for (; close < code.length; close += 1) {
        if (code[close] === "{") depth += 1;
        else if (code[close] === "}" && (depth -= 1) === 0) break;
      }
      let outside = false;
      for (const use of code.matchAll(new RegExp(`(?<![\\w.])${name}\\b`, "g"))) {
        const index = use.index ?? 0;
        if (index < open || index > close) {
          outside = true;
          break;
        }
      }
      if (!outside) inferredNames.add(name);
    }
    // `n, err := strconv.Atoi(...)`: a number, trusted only when this is the name's only binding.
    for (const match of withoutConsts.matchAll(
      /([A-Za-z_]\w*(?:[ \t]*,[ \t]*[A-Za-z_]\w*)*)[ \t]*:=[ \t]*strconv\.(?:Atoi|ParseInt|ParseUint|ParseFloat|ParseBool)\(/g,
    )) {
      const names = (match[1] ?? "").split(",").map((name) => name.trim());
      const [first] = names;
      if (first && first !== "_" && bound.get(first) === 1 && !constDeclarations.has(first))
        inferredNames.add(first);
    }
  }
  const splitTopLevelPlus = (text: string): string[] => {
    const parts: string[] = [];
    let depth = 0;
    let current = "";
    for (const char of text) {
      if (char === "(" || char === "[" || char === "{") depth += 1;
      else if (char === ")" || char === "]" || char === "}") depth -= 1;
      if (char === "+" && depth === 0) {
        parts.push(current);
        current = "";
      } else {
        current += char;
      }
    }
    parts.push(current);
    return parts;
  };
  /**
   * "strict" when the expression can only produce a fixed or numeric string by itself (literals,
   * package constants, `strconv.Itoa` of the whole expression); "inferred" when that relies on a
   * block-local constant or a parsed number; null otherwise.
   */
  type Inertness = "strict" | "inferred" | null;
  const isInertExpr = (expression: string, depth = 0): Inertness => {
    const trimmed = expression.trim();
    if (depth > 4 || trimmed === "") return null;
    if (LITERAL_PATTERN.test(trimmed) || /^\d+$/.test(trimmed)) return "strict";
    if (IDENTIFIER.test(trimmed))
      return inertNames.has(trimmed) ? "strict" : inferredNames.has(trimmed) ? "inferred" : null;
    if (/^strconv\.Itoa\(/.test(trimmed)) {
      // Only when the call is the whole expression: `strconv.Itoa(id) + clause` is not fixed.
      const { end } = readCallArguments(trimmed, trimmed.indexOf("("));
      return end === trimmed.length - 1 ? "strict" : null;
    }
    const combine = (parts: string[]): Inertness => {
      let result: Inertness = "strict";
      for (const part of parts) {
        const level = isInertExpr(part, depth + 1);
        if (level === null) return null;
        if (level === "inferred") result = "inferred";
      }
      return result;
    };
    if (/^fmt\.Sprintf\(/.test(trimmed)) {
      const { args, end } = readCallArguments(trimmed, trimmed.indexOf("("));
      return end === trimmed.length - 1 && args.length > 0 ? combine(args) : null;
    }
    const parts = splitTopLevelPlus(trimmed);
    return parts.length > 1 ? combine(parts) : null;
  };
  const isDynamicExpr = (expression: string): boolean => {
    const trimmed = expression.trim();
    if (LITERAL_PATTERN.test(trimmed)) return false;
    if (isInertExpr(trimmed) === "strict") return false;
    if (/\bfmt\.Sprintf\(|\bstrings\.Join\(|\bstrings\.Replace(All)?\(/.test(trimmed)) return true;
    if (/\+/.test(trimmed) && !/^("#\d+"\s*\+\s*)*"#\d+"$/.test(trimmed)) return true;
    return IDENTIFIER.test(trimmed) && dynamic.has(trimmed);
  };
  for (let pass = 0; pass < 2; pass += 1) {
    for (const match of code.matchAll(
      /(^|\n)[ \t]*(?:var[ \t]+)?([\w, ]{1,200}?)(?:[ \t]+[\w.*[\]]{1,100})?[ \t]*(:=|=|\+=)[ \t]*([^\n]+)/g,
    )) {
      const names = (match[2] ?? "")
        .split(",")
        .map((name) => name.trim())
        .filter((name) => IDENTIFIER.test(name) && name !== "_" && name !== "err");
      const value = match[4] ?? "";
      for (const name of names) {
        if (isTaintedExpr(value)) tainted.add(name);
        // A constant `q += " AND x"` keeps the string static.
        if ((match[3] === "+=" && !LITERAL_PATTERN.test(value.trim())) || isDynamicExpr(value)) {
          dynamic.add(name);
        }
      }
    }
  }

  const report = (ruleId: SourceRuleId, offset: number, evidence: Evidence, cause: string) => {
    const count = (perRuleCount.get(ruleId) ?? 0) + 1;
    perRuleCount.set(ruleId, count);
    if (count > MAX_FINDINGS_PER_RULE_PER_FILE) {
      cappedRules.add(ruleId);
      return;
    }
    findings.push({
      ruleId,
      path,
      line: lineOf(offset),
      severity: evidence.severity,
      status: evidence.status,
      confidence: evidence.confidence,
      evidence: evidence.flow,
      cause,
    });
  };

  const describe = (expression: string) =>
    /fmt\.Sprintf\(/.test(expression)
      ? "fmt.Sprintf"
      : /\+/.test(expression)
        ? "string concatenation"
        : "dynamically built string";

  const forEachCall = (
    pattern: RegExp,
    handler: (args: string[], offset: number, name: string) => void,
  ) => {
    for (const match of code.matchAll(pattern)) {
      const offset = match.index ?? 0;
      const open = offset + match[0].length - 1;
      handler(
        readCallArguments(code, open, MAX_CALL_ARGUMENT_CHARS).args,
        offset,
        match[1] ?? match[0],
      );
    }
  };

  const INFERRED_NOTE =
    "value inferred to be fixed through a local constant or a parsed number; verify it cannot hold request input";
  const demote = (evidence: Evidence, note: string): Evidence => ({
    ...evidence,
    severity:
      evidence.severity === "critical" || evidence.severity === "high"
        ? "medium"
        : evidence.severity,
    status: "suspected",
    confidence: "low",
    flow: `${evidence.flow} (${note})`,
  });
  const sqlEvidence = (expression: string, sink: string): Evidence | null => {
    const evidence = sqlEvidenceRaw(expression, sink);
    return evidence && isInertExpr(expression) === "inferred"
      ? demote(evidence, INFERRED_NOTE)
      : evidence;
  };
  const sqlEvidenceRaw = (expression: string, sink: string): Evidence | null => {
    if (LITERAL_PATTERN.test(expression.trim())) return null;
    if (isInertExpr(expression) === "strict") return null;
    if (!isDynamicExpr(expression)) {
      // Request input passed straight in as SQL (e.g. db.Order(c.Query("sort"))).
      if (!isTaintedExpr(expression)) return null;
      const isDirect = SOURCE_PATTERN.test(expression);
      return {
        severity: "high",
        status: isDirect ? "confirmed" : "suspected",
        confidence: "high",
        flow: `request input ${isDirect ? "" : "(via variable) "}used directly as SQL -> ${sink}`,
      };
    }
    if (isTaintedExpr(expression)) {
      const isDirect = SOURCE_PATTERN.test(expression);
      return {
        severity: "high",
        status: isDirect ? "confirmed" : "suspected",
        confidence: "high",
        flow: `request input ${isDirect ? "" : "(via variable) "}-> ${describe(expression)} -> ${sink}`,
      };
    }
    return {
      severity: "medium",
      status: "suspected",
      confidence: "medium",
      flow: `${describe(expression)} -> ${sink} (no input source identified)`,
    };
  };

  const isContextArg = (arg: string | undefined) =>
    arg !== undefined && /^(ctx|c|context\.\w+\(\)|\w+\.Context\(\))$/.test(arg.trim());

  // PG-SQL-003 database/sql, sqlx, pgx.
  if (usesSql) {
    forEachCall(
      /\.(QueryRowContext|QueryContext|ExecContext|QueryRow|Query|Exec|Get|Select|Queryx|QueryRowx|MustExec|NamedExec)\s*\(/g,
      (args, offset, name) => {
        if (usesGorm && (name === "Exec" || name === "Select")) return; // handled as GORM
        let sqlIndex = name.endsWith("Context") || isContextArg(args[0]) ? 1 : 0;
        if (name === "Get" || name === "Select") sqlIndex += 1;
        const expression = args[sqlIndex];
        if (!expression) return;
        const evidence = sqlEvidence(expression, `${name}()`);
        if (evidence) report("PG-SQL-003", offset, evidence, name);
      },
    );
  }

  // PG-SQL-004 GORM.
  if (usesGorm) {
    forEachCall(
      /\.(Raw|Exec|Where|Or|Not|Having|Order|Group|Joins|Select)\s*\(/g,
      (args, offset, name) => {
        const expression = args[0];
        if (!expression) return;
        const evidence = sqlEvidence(expression, `gorm ${name}()`);
        if (evidence) report("PG-SQL-004", offset, evidence, name);
      },
    );
  }

  /** `exec.Command("sh", args...)`: the slice holds the flag and script, so judge its elements. */
  const reportShellSlice = (slice: string, shell: string, offset: number, name: string) => {
    const unresolved = () =>
      // Parameter, reassigned or other origin: the shell receives arguments we cannot see.
      // Keep a weak finding instead of going silent.
      report(
        "PG-CMD-002",
        offset,
        {
          severity: "medium",
          status: "suspected",
          confidence: "low",
          flow: `${shell} invoked with an argument slice (${slice}...) whose contents cannot be resolved`,
        },
        `${name}-shell-slice`,
      );
    // Only the innermost function around the call is searched, and the name must be declared
    // once there, not be a parameter, and never be indexed or reassigned.
    const owner = functionSpans
      .filter((span) => span.start <= offset && offset <= span.end)
      .sort((a, b) => b.start - a.start)[0];
    if (owner === undefined) return unresolved();
    const body = code.slice(owner.start, owner.end);
    const declarations = [
      ...body.matchAll(
        new RegExp(
          `(?:^|\\n)[ \\t]*(?:var[ \\t]+)?${slice}[ \\t]*(?::=|=)[ \\t]*\\[\\]string[ \\t]*\\{`,
          "g",
        ),
      ),
    ];
    const declaration = declarations[0];
    const identifier = new RegExp(`\\b${slice}\\b`);
    const writes = [
      ...body.matchAll(
        new RegExp(
          `\\b${slice}\\b[ \\t]*(?:\\[[^\\]]*\\][ \\t]*)?(?::|[-+*/|&^%]|<<|>>)?=(?!=)`,
          "g",
        ),
      ),
    ];
    const appends = [
      ...body.matchAll(new RegExp(`\\b${slice}[ \\t]*=[ \\t]*append\\(\\s*${slice}\\s*,`, "g")),
    ];
    // Writes other than the declaration and `slice = append(slice, ...)` (indexing, reassignment).
    const otherWrites = writes.length - declarations.length - appends.length;
    if (
      declarations.length !== 1 ||
      declaration === undefined ||
      identifier.test(owner.signature) ||
      otherWrites > 0 ||
      new RegExp(`\\b${slice}\\b[ \\t]*,[^=\\n]*:=`).test(body)
    )
      return unresolved();
    const elementsStart = owner.start + (declaration.index ?? 0) + declaration[0].length - 1;
    const elements = readCallArguments(code, elementsStart).args;
    const appended: string[] = [];
    for (const append of appends) {
      const open = owner.start + (append.index ?? 0) + append[0].indexOf("(");
      appended.push(...readCallArguments(code, open).args.slice(1));
    }
    const flag = literalValue(elements[0] ?? "", literals);
    if (flag !== null && !/^[-/]c$/i.test(flag)) return; // runs a script file, not inline text
    const items = [...elements.slice(flag === null ? 0 : 1), ...appended];
    const dynamicItems = items.filter(
      (item) => !LITERAL_PATTERN.test(item.trim()) && isInertExpr(item) !== "strict",
    );
    if (flag !== null && dynamicItems.length === 0) {
      // Resolved through the slice declaration, which is an inference: keep a weak finding.
      report(
        "PG-CMD-002",
        offset,
        {
          severity: "medium",
          status: "suspected",
          confidence: "low",
          flow: `${shell} -c with an argument slice resolved to fixed values; verify nothing else changes ${slice}`,
        },
        `${name}-shell-slice`,
      );
      return;
    }
    const isTainted = dynamicItems.some((item) => isTaintedExpr(item));
    report(
      "PG-CMD-002",
      offset,
      isTainted
        ? {
            severity: "critical",
            status: dynamicItems.some((item) => SOURCE_PATTERN.test(item))
              ? "confirmed"
              : "suspected",
            confidence: "high",
            flow: `request input -> argument slice -> ${shell} -c`,
          }
        : {
            severity: "high",
            status: "suspected",
            confidence: "medium",
            flow: `non-constant argument slice -> ${shell}`,
          },
      `${name}-shell-slice`,
    );
  };

  // PG-CMD-002 os/exec.
  if (has("os/exec")) {
    forEachCall(/\bexec\.(Command|CommandContext)\s*\(/g, (args, offset, name) => {
      const rest = name === "CommandContext" ? args.slice(1) : args;
      const program = rest[0];
      if (!program) return;
      const programLiteral = literalValue(program, literals);
      const spread = /^(\w+)\.\.\.$/.exec((rest[1] ?? "").trim());
      if (
        programLiteral !== null &&
        SHELLS.has(programLiteral) &&
        rest.length === 2 &&
        spread?.[1]
      ) {
        reportShellSlice(spread[1], programLiteral, offset, name);
        return;
      }
      if (
        programLiteral !== null &&
        SHELLS.has(programLiteral) &&
        literalValue(rest[1] ?? "", literals)?.match(/^[-/]c$/i)
      ) {
        const script = rest[2];
        if (!script || LITERAL_PATTERN.test(script.trim()) || isInertExpr(script) === "strict")
          return;
        const isTainted = isTaintedExpr(script);
        const scriptEvidence: Evidence = isTainted
          ? {
              severity: "critical",
              status: SOURCE_PATTERN.test(script) ? "confirmed" : "suspected",
              confidence: "high",
              flow: `request input -> ${describe(script)} -> ${programLiteral} -c`,
            }
          : {
              severity: "high",
              status: "suspected",
              confidence: "medium",
              flow: `non-constant script -> ${programLiteral} -c`,
            };
        report(
          "PG-CMD-002",
          offset,
          isInertExpr(script) === "inferred"
            ? demote(scriptEvidence, INFERRED_NOTE)
            : scriptEvidence,
          `${name}-shell`,
        );
        return;
      }
      if (programLiteral === null && isTaintedExpr(program)) {
        report(
          "PG-CMD-002",
          offset,
          {
            severity: "high",
            status: "suspected",
            confidence: "medium",
            flow: "request input -> exec.Command program",
          },
          `${name}-program`,
        );
      }
    });
  }

  // PG-SSRF-001 net/http client.
  if (has("net/http")) {
    forEachCall(
      /\bhttp\.(Get|Post|Head|PostForm|NewRequest|NewRequestWithContext)\s*\(/g,
      (args, offset, name) => {
        const index = name === "NewRequest" ? 1 : name === "NewRequestWithContext" ? 2 : 0;
        const target = args[index];
        if (target && isTaintedExpr(target)) {
          report(
            "PG-SSRF-001",
            offset,
            {
              severity: "high",
              status: "suspected",
              confidence: SOURCE_PATTERN.test(target) ? "high" : "medium",
              flow: `request input -> http.${name} URL`,
            },
            `http.${name}`,
          );
        }
      },
    );
  }

  // PG-PATH-001 file reads and downloads.
  forEachCall(
    /\b(?:os|ioutil|http|c)\.(Open|ReadFile|OpenFile|ServeFile|File|FileAttachment|SendFile)\s*\(/g,
    (args, offset, name) => {
      const target = name === "ServeFile" ? args[2] : args[0];
      if (target && isTaintedExpr(target)) {
        report(
          "PG-PATH-001",
          offset,
          {
            severity: "high",
            status: "suspected",
            confidence: SOURCE_PATTERN.test(target) ? "high" : "medium",
            flow: `request input -> ${name}() path`,
          },
          name,
        );
      }
    },
  );

  // PG-CRYPTO-001 weak password hash.
  if (has("crypto/md5") || has("crypto/sha1")) {
    forEachCall(/\b(md5|sha1)\.(Sum|New)\s*\(/g, (args, offset, algorithm) => {
      const window = code.slice(offset, offset + 300);
      if (
        args.some((arg) => PASSWORD_TEXT.test(arg)) ||
        /\.Write\([^)]*pass(word)?|pwd/i.test(window)
      ) {
        report(
          "PG-CRYPTO-001",
          offset,
          {
            severity: "high",
            status: "suspected",
            confidence: "medium",
            flow: `${algorithm} digest of a password-like value`,
          },
          algorithm,
        );
      }
    });
  }

  // PG-CRYPTO-002 hardcoded keys: []byte("...") passed to signing/encryption APIs.
  // A package-level `const`/`var` bound once, to a literal, and never written, taken by address or
  // indexed: `var signingKey = []byte("...")`. A `var` can still be overwritten from another file
  // of the package (an init() reading the environment), so it is reported at medium confidence.
  const packageKeyCache = new Map<string, "const" | "var" | null>();
  const packageKey = (name: string): "const" | "var" | null => {
    if (!IDENTIFIER.test(name)) return null;
    const cached = packageKeyCache.get(name);
    if (cached !== undefined) return cached;
    let result: "const" | "var" | null = null;
    const escaped = name.replace(/[$]/g, "\\$");
    const declaration = new RegExp(
      `(?:^|\\n)[ \\t]*(?:(var|const)[ \\t]+)?${escaped}(?:[ \\t]+[\\w.*[\\]]{1,60})?[ \\t]*=[ \\t]*(?:\\[\\]byte\\([ \\t]*"#\\d+"[ \\t]*\\)|"#\\d+")[ \\t]*(?=\\n|$)`,
      "g",
    );
    const matches = [...code.matchAll(declaration)];
    const only = matches.length === 1 ? matches[0] : undefined;
    if (only) {
      const at = (only.index ?? 0) + (only[0].startsWith("\n") ? 1 : 0);
      let depth = 0;
      for (let index = 0; index < at; index += 1) {
        if (code[index] === "{") depth += 1;
        else if (code[index] === "}") depth -= 1;
      }
      // A keyword-less line sits in a `var (` or `const (` block: the nearest opener names it.
      const keyword =
        only[1] ?? [...code.slice(0, at).matchAll(/(?:^|\n)(var|const)[ \t]*\(/g)].pop()?.[1];
      // Every write or re-declaration of the name anywhere makes it untrusted.
      let writes = 0;
      for (const assignment of code.matchAll(
        /([A-Za-z_]\w*(?:[ \t]*,[ \t]*[A-Za-z_]\w*)*)[ \t]*(?::=|(?:[-+*/|&^%]|<<|>>|&\^)?=(?!=))/g,
      )) {
        const before = code[(assignment.index ?? 0) - 1];
        if (before === "." || before === "]") continue;
        if ((assignment[1] ?? "").split(",").some((part) => part.trim() === name)) writes += 1;
      }
      const redeclared = new RegExp(`\\bvar[ \\t]+(?:\\([^)]*)?(?<![\\w.])${escaped}\\b`, "g");
      const inSignature = new RegExp(`\\bfunc\\b[^\\n{]*(?<![\\w.])${escaped}\\b`);
      const mutated = new RegExp(`&${escaped}\\b|(?<![\\w.])${escaped}\\[|\\bcopy\\(${escaped}\\b`);
      if (
        depth === 0 &&
        writes === 1 &&
        [...code.matchAll(redeclared)].length <= 1 &&
        !inSignature.test(code) &&
        !mutated.test(code)
      )
        result = keyword === "const" ? "const" : "var";
    }
    packageKeyCache.set(name, result);
    return result;
  };
  forEachCall(
    /\b(SignedString|NewCipher|hmac\.New|SigningKey|NewGCM)\s*\(/g,
    (args, offset, name) => {
      if (args.some((arg) => /^\[\]byte\(\s*"#\d+"\s*\)$/.test(arg.trim()))) {
        report(
          "PG-CRYPTO-002",
          offset,
          {
            severity: "high",
            status: "confirmed",
            confidence: "high",
            flow: `string literal (value redacted) used as ${name} key`,
          },
          name,
        );
        return;
      }
      for (const arg of args) {
        const trimmed = arg.trim();
        const held = /^\[\]byte\(\s*([A-Za-z_]\w*)\s*\)$/.exec(trimmed)?.[1] ?? trimmed;
        const kind = packageKey(held);
        if (kind === null) continue;
        report(
          "PG-CRYPTO-002",
          offset,
          kind === "const"
            ? {
                severity: "high",
                status: "confirmed",
                confidence: "high",
                flow: `string literal (value redacted) held in package constant ${held} used as ${name} key`,
              }
            : {
                severity: "high",
                status: "suspected",
                confidence: "medium",
                flow: `string literal (value redacted) held in package variable ${held} used as ${name} key (verify no other file of the package overwrites it from the environment)`,
              },
          name,
        );
        return;
      }
    },
  );
  for (const match of code.matchAll(/\breturn\s+\[\]byte\(\s*"#\d+"\s*\)/g)) {
    const before = code.slice(Math.max(0, (match.index ?? 0) - 300), match.index ?? 0);
    if (/jwt\.|Keyfunc|\*jwt\.Token/.test(before)) {
      report(
        "PG-CRYPTO-002",
        match.index ?? 0,
        {
          severity: "high",
          status: "confirmed",
          confidence: "high",
          flow: "string literal (value redacted) returned as JWT verification key",
        },
        "jwt-keyfunc",
      );
    }
  }

  // PG-COOKIE-001 http.Cookie literals.
  for (const match of code.matchAll(/\bhttp\.Cookie\s*\{/g)) {
    const offset = match.index ?? 0;
    const { args, end } = readCallArguments(code, offset + match[0].length - 1);
    void end;
    const fields = new Map<string, string>();
    for (const arg of args) {
      const field = /^(\w+)\s*:\s*([\s\S]+)$/.exec(arg);
      if (field?.[1] && field[2]) fields.set(field[1], field[2].trim());
    }
    const missing = [
      ...(fields.get("HttpOnly") === "true" ? [] : ["HttpOnly"]),
      ...(fields.get("Secure") === "true" ? [] : ["Secure"]),
      ...(fields.has("SameSite") ? [] : ["SameSite"]),
    ];
    if (missing.length === 0) continue;
    const name = literalValue(fields.get("Name") ?? "", literals) ?? "";
    const isSession = SESSION_COOKIE_NAME.test(name);
    report(
      "PG-COOKIE-001",
      offset,
      {
        severity: isSession ? "medium" : "low",
        status: "suspected",
        confidence: isSession ? "medium" : "low",
        flow: `http.Cookie without ${missing.join(", ")}`,
      },
      `cookie:${name}`,
    );
  }

  return {
    findings,
    imports,
    hasParseErrors: !hasBalancedDelimiters(code),
    cappedRules: [...cappedRules],
  };
}
