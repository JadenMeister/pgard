import type { Confidence, FindingStatus, Severity } from "@pgard/findings";
import type { RawSourceFinding } from "../finding-factory.js";
import type { SourceRuleId } from "../rules.js";
import { LITERAL_PATTERN, lineAt, literalValue, maskGoSource, readCallArguments } from "./lexer.js";

/**
 * Syntax-level Go analysis (lexer + patterns, no type checking). Request input, string building
 * and sinks are recognized by well-known package/method names within one file.
 */
export interface GoAnalysis {
  findings: RawSourceFinding[];
  imports: string[];
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

  // Flow-insensitive, file-level variable facts.
  const tainted = new Set<string>();
  const dynamic = new Set<string>();
  const referencesAny = (expression: string, names: Set<string>) =>
    [...names].some((name) => new RegExp(`(^|[^\\w.])${name}\\b`).test(expression));
  const isTaintedExpr = (expression: string): boolean =>
    !SANITIZER_PATTERN.test(expression) &&
    (SOURCE_PATTERN.test(expression) || referencesAny(expression, tainted));
  const isDynamicExpr = (expression: string): boolean => {
    const trimmed = expression.trim();
    if (LITERAL_PATTERN.test(trimmed)) return false;
    if (/\bfmt\.Sprintf\(|\bstrings\.Join\(|\bstrings\.Replace(All)?\(/.test(trimmed)) return true;
    if (/\+/.test(trimmed) && !/^("#\d+"\s*\+\s*)*"#\d+"$/.test(trimmed)) return true;
    return IDENTIFIER.test(trimmed) && dynamic.has(trimmed);
  };
  for (let pass = 0; pass < 2; pass += 1) {
    for (const match of code.matchAll(/(^|\n)\s*([\w, ]+?)\s*(:=|=|\+=)\s*([^\n]+)/g)) {
      const names = (match[2] ?? "")
        .split(",")
        .map((name) => name.trim())
        .filter((name) => IDENTIFIER.test(name) && name !== "_" && name !== "err");
      const value = match[4] ?? "";
      for (const name of names) {
        if (isTaintedExpr(value)) tainted.add(name);
        if (match[3] === "+=" || isDynamicExpr(value)) dynamic.add(name);
      }
    }
  }

  const report = (ruleId: SourceRuleId, offset: number, evidence: Evidence, cause: string) => {
    findings.push({
      ruleId,
      path,
      line: lineAt(code, offset),
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
      handler(readCallArguments(code, open).args, offset, match[1] ?? match[0]);
    }
  };

  const sqlEvidence = (expression: string, sink: string): Evidence | null => {
    if (!isDynamicExpr(expression)) return null;
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

  // PG-CMD-002 os/exec.
  if (has("os/exec")) {
    forEachCall(/\bexec\.(Command|CommandContext)\s*\(/g, (args, offset, name) => {
      const rest = name === "CommandContext" ? args.slice(1) : args;
      const program = rest[0];
      if (!program) return;
      const programLiteral = literalValue(program, literals);
      if (
        programLiteral !== null &&
        SHELLS.has(programLiteral) &&
        literalValue(rest[1] ?? "", literals)?.match(/^[-/]c$/i)
      ) {
        const script = rest[2];
        if (!script || LITERAL_PATTERN.test(script.trim())) return;
        const isTainted = isTaintedExpr(script);
        report(
          "PG-CMD-002",
          offset,
          isTainted
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
              },
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

  return { findings, imports };
}
