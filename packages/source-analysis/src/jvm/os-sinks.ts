import type { Confidence, FindingStatus, Severity } from "@pgard/findings";
import {
  addLeaves,
  baseType,
  consumeOrigin,
  copy,
  guardOrigin,
  inferred,
  join,
  literalText,
  nonConst,
  sourcesOf,
  value,
  type Binding,
  type Context,
  type Leaf,
  type Origin,
  type Value,
} from "./flow-values.js";
import type { Expr } from "./ir.js";
import {
  ARCHIVE_ENTRIES,
  ARCHIVE_ENTRY_NAME,
  ARCHIVE_ENTRY_TYPE,
  ARCHIVE_NEXT,
  ARCHIVE_RECEIVER_NAME,
  ARCHIVE_RECEIVER_TYPE,
  FILE_PROBES,
  FILES_PROBES,
  LAUNCHERS,
  POLY_OPENERS,
  UPLOAD_TYPES,
  URL_OPENERS,
  ELEMENT_ADD,
  CANONICALIZERS,
  CLIENT_FILE_NAMES,
  COLLECTION_RESULTS,
  COLLECTION_TYPE,
  FILE_METHODS,
  FILE_OPENERS,
  FILES_SINKS,
  FILES_TWO_PATH,
  FILEUTILS_SINKS,
  LAST_ELEMENT,
  PATH_KEEPERS,
  PATH_NAME,
  RUNTIME_NAME,
  SHELL_FLAG_CMD,
  SHELL_FLAG_PD,
  SHELL_FLAG_POSIX,
  SHELL_PROGRAMS,
} from "./os-names.js";

export type OsRuleId = "PG-CMD-003" | "PG-PATH-002";

/** A finding before the path is attached. */
export interface OsFinding {
  ruleId: OsRuleId;
  line: number;
  severity: Severity;
  status: FindingStatus;
  confidence: Confidence;
  evidence: string;
  cause: string;
}

export interface OsHost {
  typeOfExpr: (expr: Expr, ctx: Context) => string | null;
  /** The class an unqualified call belongs to through `import static` (`Files`, `FileUtils`), if any. */
  staticOwner: (name: string) => string | null;
  record: (finding: OsFinding, rank: number) => void;
  /** The file imports an archive library, so a variable named like an entry is one. */
  hasArchiveLibrary: boolean;
  /** The file imports Apache Commons Exec, so `addArgument` is a `CommandLine` call. */
  hasCommonsExec: boolean;
  /** The file makes a `ProcessBuilder`: a `command(...)` call anywhere in it is probably its. */
  readonly usesProcessBuilder: boolean;
  /** The file gets a `Runtime`: an `exec(...)` call anywhere in it is probably its. */
  readonly usesRuntime: boolean;
}

type CallExpr = Extract<Expr, { k: "call" }>;
type MemberExpr = Extract<Expr, { k: "member" }>;
type SourceLeaf = Extract<Leaf, { k: "source" }>;

const PATH_GUARD_WHY = "checked by a path guard (canonical prefix test or '..' rejection)";
/** Leaves that stand for the collection object itself, not for anything put into it. */
const COLLECTION_OBJECT = /^(?:ArrayList|LinkedList|HashSet|HashMap|new \w+|\w+Of\(\))$/;

type Kind = "tainted" | "helper" | "unknown" | "inferred";
interface Judged {
  kind: Kind;
  tainted: SourceLeaf[];
  helper: string;
  reasons: string[];
  shape: string;
  /** The whole value, not a part of a longer one. */
  bare: boolean;
}

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** A path check on the variable replaces what it could carry with "inferred". */
const demotePathGuard = (leaves: readonly Leaf[]): Leaf[] => {
  const out: Leaf[] = [];
  addLeaves(
    out,
    leaves.map((leaf): Leaf =>
      (leaf.k === "source" || leaf.k === "unknown") && leaf.pg === true
        ? { k: "inferred", why: leaf.pgWhy ?? PATH_GUARD_WHY }
        : leaf,
    ),
  );
  return out;
};

/** The fixed text of a value, or null when any part of it is dynamic. */
function fixedText(v: Value | undefined): string | null {
  if (v === undefined || v.leaves.length === 0) return null;
  if (nonConst(v.leaves).length > 0) return null;
  return literalText(v.leaves);
}

const programName = (text: string | null): string | null => {
  if (text === null) return null;
  const first = (text.trim().split(/\s+/)[0] ?? "").split(/[\\/]/).pop() ?? "";
  return first.toLowerCase().replace(/\.exe$/, "");
};

const SUDO_WITH_VALUE = new Set(["-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-r", "-t", "-U"]);
const XARGS_WITH_VALUE = new Set(["-I", "-n", "-P", "-d", "-L", "-s", "-E", "-a"]);

/**
 * Where the program starts after launchers (`env`, `sudo -u app`, `nohup`, `timeout 5`, `nice -n 5`,
 * `xargs`). Null when something dynamic stands where a launcher's own argument should be.
 */
function afterLaunchers(texts: ReadonlyArray<string | null>): number | null {
  let i = 0;
  for (let hops = 0; hops < 6; hops += 1) {
    const program = programName(texts[i] ?? null);
    if (program === null || !LAUNCHERS.has(program)) return i;
    i += 1;
    const skipOptions = (withValue: ReadonlySet<string>): boolean => {
      for (;;) {
        const text = texts[i];
        if (text === undefined) return true;
        if (text === null) return false;
        if (withValue.has(text)) i += 2;
        else if (text.startsWith("-")) i += 1;
        else return true;
      }
    };
    if (program === "env") {
      for (;;) {
        const text = texts[i];
        if (text === undefined) return i;
        if (text === null) return null;
        if (text === "-u" || text === "-C" || text === "-S") i += 2;
        else if (text.startsWith("-") || /^\w+=/.test(text)) i += 1;
        else break;
      }
    } else if (program === "sudo" || program === "doas") {
      if (!skipOptions(SUDO_WITH_VALUE)) return null;
    } else if (program === "timeout") {
      if (!skipOptions(new Set(["-s", "-k"]))) return null;
      i += 1;
    } else if (program === "nice") {
      if (texts[i] === "-n") i += 2;
      else if (/^-\d+$/.test(texts[i] ?? "")) i += 1;
    } else if (program === "xargs") {
      if (!skipOptions(XARGS_WITH_VALUE)) return null;
    }
  }
  return null;
}

/** A shell program followed by its script flag (`sh -c`, `cmd /c`, `bash -lc`), or by something that may be one. */
function findWrapper(
  texts: ReadonlyArray<string | null>,
): { program: string; flagIndex: number; flag: string | null } | null {
  const at = afterLaunchers(texts);
  if (at === null) {
    // A launcher argument is dynamic (`timeout secs sh -c script`): a shell with its flag later on
    // is still the script's.
    if (!LAUNCHERS.has(programName(texts[0] ?? null) ?? "")) return null;
    for (let j = 1; j < Math.min(texts.length - 1, 8); j += 1) {
      const program = programName(texts[j] ?? null);
      const flag = texts[j + 1] ?? null;
      if (
        program !== null &&
        SHELL_PROGRAMS.has(program) &&
        flag !== null &&
        shellFlag(program, flag)
      ) {
        return { program, flagIndex: j + 1, flag };
      }
    }
    return null;
  }
  const program = programName(texts[at] ?? null);
  if (program === null || !SHELL_PROGRAMS.has(program) || texts.length < at + 2) return null;
  for (let i = at + 1; i < Math.min(texts.length, at + 5); i += 1) {
    const text = texts[i] ?? null;
    // Something dynamic where the flag should be: it may well be the flag, so the rest is a script.
    if (text === null) return i === at + 1 ? { program, flagIndex: at, flag: null } : null;
    if (shellFlag(program, text)) return { program, flagIndex: i, flag: text };
    if (!/^[-/]/.test(text)) return null;
  }
  return null;
}

function shellFlag(program: string, text: string): boolean {
  if (program === "cmd") return SHELL_FLAG_CMD.test(text);
  if (program === "powershell" || program === "pwsh") return SHELL_FLAG_PD.test(text);
  return SHELL_FLAG_POSIX.test(text);
}

const nameHint = (expr: Expr | null): string =>
  expr === null ? "" : expr.k === "id" || expr.k === "member" || expr.k === "call" ? expr.name : "";

export function createOsSinks(host: OsHost) {
  const origins: Origin[] = [];

  // ---------------------------------------------------------------- judging a value

  /**
   * What a value is worth at a sink. `path`: the path rule, for which a path check (a `pg` leaf)
   * means the value is inferred safe; the command rule ignores those marks.
   */
  function judge(
    v: Value,
    extra: readonly Leaf[] = [],
    composed = v.composed,
    path = false,
  ): Judged | null {
    const leaves: Leaf[] = [];
    addLeaves(leaves, path ? demotePathGuard(v.leaves) : v.leaves);
    addLeaves(leaves, path ? demotePathGuard(extra) : extra);
    const present = v.coll
      ? leaves.filter((leaf) => !(leaf.k === "unknown" && COLLECTION_OBJECT.test(leaf.name)))
      : leaves;
    const dynamic = nonConst(present);
    if (dynamic.length === 0) return null;
    const callName = v.opaque.replace(/\(\)$/, "");
    // These calls keep what is in them: the file name a client chose, the pieces of a split string,
    // a path converted to another form.
    const opaque =
      CLIENT_FILE_NAMES.has(callName) ||
      COLLECTION_RESULTS.has(callName) ||
      (path && PATH_KEEPERS.has(callName))
        ? ""
        : v.opaque;
    const tainted = sourcesOf(present) as SourceLeaf[];
    const helperLeaf = dynamic.find(
      (leaf) => leaf.k === "unknown" && /\(\)$|^mutable field /.test(leaf.name),
    );
    const helper = opaque !== "" ? opaque : helperLeaf?.k === "unknown" ? helperLeaf.name : "";
    const reasons = [
      ...new Set(dynamic.map((leaf) => (leaf.k === "inferred" ? leaf.why : "")).filter(Boolean)),
    ];
    const shape = v.shape || (composed ? "built value" : "value");
    const base = { tainted, helper, reasons, shape, bare: !composed };
    if (!composed) {
      // A bare value: request input read directly is reported; so is the result of a helper, a
      // guard or lookup, a number or a constant from another file, and a plain parameter, each at
      // low confidence (an unknown value is never silent).
      if (opaque !== "") return { kind: "helper", ...base, tainted: [] };
      if (tainted.length > 0) return { kind: "tainted", ...base };
      if (helper !== "") return { kind: "helper", ...base };
      if (reasons.length > 0 && !dynamic.some((leaf) => leaf.k === "unknown")) {
        return { kind: "inferred", ...base };
      }
      return { kind: "unknown", ...base };
    }
    if (tainted.length > 0) return { kind: "tainted", ...base };
    if (dynamic.some((leaf) => leaf.k === "unknown")) return { kind: "unknown", ...base };
    return { kind: "inferred", ...base };
  }

  const sourceText = (judged: Judged): { text: string; source: SourceLeaf } => {
    const source = (judged.tainted.find((leaf) => leaf.direct) ?? judged.tainted[0]) as SourceLeaf;
    const from = source.label.startsWith("archive entry")
      ? source.label
      : `request input (${source.label})`;
    return { text: `${from}${source.direct ? "" : " via variable"}`, source };
  };

  /** Why a low-confidence finding is low. */
  const lowReason = (judged: Judged): string =>
    judged.kind === "helper"
      ? `value from ${judged.helper}, not followed; inferred`
      : judged.kind === "unknown"
        ? judged.bare
          ? "a value with no identified source (such as a parameter) reaches it; callers not followed; inferred"
          : "(no input source identified)"
        : `${judged.reasons.slice(0, 2).join("; ")}; inferred`;

  const rankOf = (kind: Kind): number => (kind === "tainted" ? 3 : kind === "unknown" ? 2 : 1);

  // ---------------------------------------------------------------- path findings

  function pathFinding(
    judged: Judged,
    line: number,
    label: string,
  ): { finding: OsFinding; rank: number } {
    const base = { ruleId: "PG-PATH-002" as const, line, cause: label };
    if (judged.kind === "tainted") {
      const { text, source } = sourceText(judged);
      return {
        finding: {
          ...base,
          severity: "high",
          status: source.direct ? "confirmed" : "suspected",
          confidence: source.label.includes("by its name") ? "medium" : "high",
          evidence: `${text} -> ${judged.shape} -> ${label}`,
        },
        rank: 3,
      };
    }
    const why = lowReason(judged);
    const joiner = judged.kind === "unknown" && !judged.bare ? " " : "; ";
    return {
      finding: {
        ...base,
        severity: judged.kind === "unknown" && judged.bare ? "low" : "medium",
        status: "suspected",
        confidence: "low",
        evidence: `${judged.shape} -> ${label}${joiner}${why}`,
      },
      rank: rankOf(judged.kind),
    };
  }

  function reportPath(v: Value, line: number, label: string, ctx: Context): void {
    if (!ctx.report) return;
    const judged = judge(v, [], v.composed, true);
    if (judged === null) return;
    const { finding, rank } = pathFinding(judged, line, label);
    host.record(finding, rank);
  }

  /** A path is used (read, written, deleted): the use is where the finding is. */
  function consume(v: Value, line: number, label: string, ctx: Context): void {
    consumeOrigin(v.origin);
    reportPath(v, line, label, ctx);
  }

  /** Makes a path value; the finding for it waits until it is known whether it is used. */
  function makePath(
    parts: Value[],
    line: number,
    label: string,
    ctx: Context,
    composed: boolean,
  ): Value {
    for (const part of parts) consumeOrigin(part.origin);
    const merged = parts.length === 1 ? copy(parts[0] as Value) : join("path", ...parts);
    const result: Value = {
      ...merged,
      path: true,
      canon: false,
      composed,
      shape: merged.shape || (composed ? "built path" : ""),
      elems: null,
      coll: false,
      origin: null,
    };
    if (ctx.report && nonConst(result.leaves).length > 0) {
      const origin: Origin = {
        consumed: false,
        guarded: false,
        checked: false,
        report: (guarded) => {
          const view = guarded ? { ...result, leaves: guardedLeaves(result.leaves) } : result;
          const judged = judge(view, [], view.composed, true);
          if (judged === null) return;
          const { finding, rank } = pathFinding(judged, line, label);
          host.record(finding, rank);
        },
      };
      origins.push(origin);
      result.origin = origin;
    }
    return result;
  }

  const guardedLeaves = (leaves: readonly Leaf[]): Leaf[] => {
    const out: Leaf[] = [];
    addLeaves(
      out,
      leaves.map((leaf): Leaf =>
        leaf.k === "source" || leaf.k === "unknown" ? { ...leaf, pg: true } : leaf,
      ),
    );
    return out;
  };

  // ---------------------------------------------------------------- command findings

  type Scope = "string" | "shell" | "program" | "argument" | "unquoted";
  interface Candidate {
    finding: OsFinding;
    rank: number;
  }

  function commandFinding(
    judged: Judged,
    line: number,
    sink: string,
    scope: Scope,
    detail: string,
  ): Candidate {
    const critical = scope === "string" || scope === "shell" || scope === "program";
    const base = { ruleId: "PG-CMD-003" as const, line, cause: `${sink}:${scope}` };
    if (judged.kind === "tainted") {
      const { text, source } = sourceText(judged);
      if (critical) {
        return {
          finding: {
            ...base,
            severity: "critical",
            status: source.direct ? "confirmed" : "suspected",
            confidence: "high",
            evidence: `${text} -> ${judged.shape} -> ${detail}`,
          },
          rank: 3,
        };
      }
      return {
        finding: {
          ...base,
          severity: scope === "unquoted" ? "high" : "medium",
          status: "suspected",
          confidence: "medium",
          evidence: `${text} -> ${judged.shape} -> ${detail}; argument injection (${
            scope === "unquoted" ? "quoting off" : "fixed program, no shell"
          })`,
        },
        rank: 3,
      };
    }
    const why = lowReason(judged);
    return {
      finding: {
        ...base,
        severity: critical ? "medium" : "low",
        status: "suspected",
        confidence: "low",
        evidence: `${judged.shape} -> ${detail}${judged.kind === "unknown" && !judged.bare ? " " : "; "}${why}`,
      },
      rank: rankOf(judged.kind),
    };
  }

  const best = (candidates: Candidate[]): Candidate | null =>
    candidates.reduce<Candidate | null>((top, next) => {
      if (top === null) return next;
      const a = top.rank * 10 + (SEVERITY_RANK[top.finding.severity] ?? 0);
      const b = next.rank * 10 + (SEVERITY_RANK[next.finding.severity] ?? 0);
      return b > a ? next : top;
    }, null);

  /** What the value of `expr` can be written to by `add`, `set` or an index assignment. */
  function writtenLeaves(expr: Expr | undefined, ctx: Context): Leaf[] {
    if (expr === undefined || expr.k !== "id") return [];
    return ctx.scope.find(expr.name)?.written ?? [];
  }

  /** An array or list of arguments (not a single string). */
  function isCollection(expr: Expr | undefined, v: Value, ctx: Context): boolean {
    if (expr === undefined) return false;
    if (v.elems !== null || v.coll || expr.k === "array") return true;
    const type = host.typeOfExpr(expr, ctx);
    if (type !== null && COLLECTION_TYPE.test(type)) return true;
    return expr.k === "call" && COLLECTION_RESULTS.has(expr.name);
  }

  const expandItems = (v: Value, depth = 0): Value[] | null => {
    if (v.elems === null || depth > 4) return null;
    if (v.elems.length === 1 && (v.elems[0] as Value).coll) {
      return expandItems(v.elems[0] as Value, depth + 1) ?? null;
    }
    return v.elems;
  };

  function commandString(v: Value, line: number, sink: string, ctx: Context): void {
    if (!ctx.report) return;
    const judged = judge(v);
    if (judged === null) return;
    const candidate = commandFinding(judged, line, sink, "string", `${sink} (command string)`);
    host.record(candidate.finding, candidate.rank);
  }

  /** An argument list: a shell wrapper, the program name, or the arguments of a fixed program. */
  function commandArgv(
    items: Value[] | null,
    flat: Value,
    extra: readonly Leaf[],
    line: number,
    sink: string,
    ctx: Context,
    forceScope?: Scope,
  ): void {
    if (!ctx.report) return;
    const candidates: Candidate[] = [];
    const add = (
      v: Value,
      composed: boolean,
      scope: Scope,
      detail: string,
      extras: readonly Leaf[] = [],
    ): void => {
      const judged = judge(v, extras, composed);
      if (judged !== null) candidates.push(commandFinding(judged, line, sink, scope, detail));
    };
    if (items !== null && extra.length === 0) {
      const texts = items.map(fixedText);
      const found = findWrapper(texts);
      const program = found?.program ?? programName(texts[0] ?? null);
      if (found !== null) {
        // `cmd /c` and PowerShell take the rest of the line; other shells take one argument and
        // treat the following ones as positional parameters of the script.
        const restOfLine =
          found.program === "cmd" || found.program === "powershell" || found.program === "pwsh";
        const start = found.flagIndex + 1;
        const scriptEnd = restOfLine ? items.length : start + 1;
        const script = items.slice(start, scriptEnd);
        const scriptValue = script.length === 1 ? (script[0] as Value) : join("script", ...script);
        add(
          scriptValue,
          script.length === 1 ? scriptValue.composed : true,
          "shell",
          `${found.program} ${found.flag ?? "<flag>"} script`,
        );
        for (const item of items.slice(scriptEnd)) {
          add(item, item.composed, "argument", `${sink} (argument of ${found.program})`);
        }
      } else {
        const first = items[0];
        if (first !== undefined) add(first, first.composed, "program", `${sink} (program name)`);
        let separated = false;
        for (let i = 1; i < items.length; i += 1) {
          const item = items[i] as Value;
          const text = texts[i];
          if (text === "--" || text === "--end-of-options") separated = true;
          const detail = `${sink} (argument of ${program ?? "a program"})`;
          if (separated && text !== "--" && text !== "--end-of-options") {
            const judged = judge(item, [], item.composed);
            if (judged !== null) {
              const after: Judged =
                judged.kind === "tainted"
                  ? {
                      ...judged,
                      kind: "inferred",
                      reasons: ["placed after a -- option separator"],
                    }
                  : judged;
              candidates.push(commandFinding(after, line, sink, "argument", detail));
            }
          } else {
            add(item, item.composed, "argument", detail);
          }
        }
      }
    } else {
      // The list is built in steps or its form is not known: judge it as a whole. Its first
      // element, when that is fixed text, is the program.
      const present = [...flat.leaves, ...extra].filter(
        (leaf) => !(leaf.k === "unknown" && COLLECTION_OBJECT.test(leaf.name)),
      );
      const words = present.flatMap((leaf) => (leaf.k === "const" ? leaf.text.split(/\s+/) : []));
      const shell = words
        .map((word) => programName(word))
        .find((word) => word !== null && SHELL_PROGRAMS.has(word));
      const wrapper = shell !== undefined && words.some((word) => shellFlag(shell as string, word));
      const scope: Scope =
        forceScope ?? (wrapper ? "shell" : present[0]?.k === "const" ? "argument" : "program");
      add(
        flat,
        flat.composed || extra.length > 0,
        scope,
        wrapper
          ? `${shell} script`
          : scope === "program"
            ? `${sink} (program name)`
            : `${sink} (argument)`,
        extra,
      );
    }
    const top = best(candidates);
    if (top !== null) host.record(top.finding, top.rank);
  }

  /** The command given to `exec`, `ProcessBuilder` or `command(...)`: a string or an argument list. */
  function commandFrom(
    argExprs: Expr[],
    args: Value[],
    line: number,
    sink: string,
    ctx: Context,
    stringOnly = false,
  ): void {
    const first = args[0];
    if (first === undefined) return;
    const single = args.length === 1;
    if (single && isCollection(argExprs[0], first, ctx)) {
      const written = writtenLeaves(argExprs[0], ctx);
      const known = expandItems(first);
      // A list that was filled in steps: what it started with, then what was put into it.
      const extra =
        written.length > 0 ? [...(known ?? []).flatMap((item) => item.leaves), ...written] : [];
      commandArgv(written.length > 0 ? null : known, first, extra, line, sink, ctx);
      return;
    }
    if (stringOnly) {
      commandString(first, line, sink, ctx);
      return;
    }
    commandArgv(args, first, [], line, sink, ctx);
  }

  const isRuntime = (recvExpr: Expr, recv: Value | null, ctx: Context): boolean => {
    if (recv?.rt === true) return true;
    if (recvExpr.k === "call" && recvExpr.name === "getRuntime") return true;
    const type = host.typeOfExpr(recvExpr, ctx);
    if (type !== null && baseType(type) === "Runtime") return true;
    return recvExpr.k === "id" || recvExpr.k === "member"
      ? RUNTIME_NAME.test(recvExpr.name)
      : false;
  };

  const isProcessBuilder = (recvExpr: Expr, recv: Value | null, ctx: Context): boolean =>
    recv?.proc === true || baseType(host.typeOfExpr(recvExpr, ctx)) === "ProcessBuilder";

  // ---------------------------------------------------------------- archives

  const ARCHIVE_LABEL = "archive entry name (getName)";
  const ARCHIVE_WEAK_LABEL = "archive entry name (variable known by its name only)";

  /** The entries of an archive, or one of them: what the author of the archive chose. */
  const archiveSource = (weak = false): Value =>
    value([{ k: "source", label: weak ? ARCHIVE_WEAK_LABEL : ARCHIVE_LABEL, direct: false }]);

  const carriesArchive = (v: Value | null): boolean =>
    v !== null &&
    v.leaves.some((leaf) => leaf.k === "source" && leaf.label.startsWith("archive entry"));

  /** A receiver that is an archive: `ZipFile`, `ZipInputStream`, a variable named `zip`... */
  function archiveReceiver(recvExpr: Expr | null, ctx: Context): boolean {
    if (recvExpr === null) return false;
    const type = baseType(host.typeOfExpr(recvExpr, ctx));
    if (type !== "" && ARCHIVE_RECEIVER_TYPE.test(type)) return true;
    return type === "" && ARCHIVE_RECEIVER_NAME.test(nameHint(recvExpr));
  }

  /**
   * `entry.getName()` where `entry` is an archive entry: by its declared type, by being the
   * result of `getNextEntry()`, or (weakly) by a name like `entry` when no type is written down and
   * an archive library is imported.
   */
  function archiveEntry(recvExpr: Expr | null, ctx: Context): "typed" | "named" | null {
    if (recvExpr === null) return null;
    const type = host.typeOfExpr(recvExpr, ctx);
    if (type !== null && ARCHIVE_ENTRY_TYPE.test(baseType(type))) return "typed";
    if ((recvExpr.k === "call" || recvExpr.k === "member") && ARCHIVE_NEXT.has(recvExpr.name)) {
      return "typed";
    }
    if (!host.hasArchiveLibrary) return null;
    if (type !== null && !/^(?:var|val)$/.test(type)) return null;
    return (recvExpr.k === "id" || recvExpr.k === "member") &&
      ARCHIVE_ENTRY_NAME.test(recvExpr.name)
      ? "named"
      : null;
  }

  /** An upload (`MultipartFile`, `Part`): the file name the client chose is request input. */
  function uploadName(recvExpr: Expr | null, ctx: Context): boolean {
    return recvExpr !== null && UPLOAD_TYPES.has(baseType(host.typeOfExpr(recvExpr, ctx)));
  }

  const uploadSource = (name: string): Value =>
    value([{ k: "source", label: `uploaded file name (${name})`, direct: true }]);

  // ---------------------------------------------------------------- paths

  /**
   * Whether the receiver of `resolve(...)` is a path: `yes` (a path value, a `Path` or `File`, a
   * name like `baseDir`), `maybe` (a variable whose type is not written down), or `no`.
   */
  function pathKind(recvExpr: Expr, recv: Value | null, ctx: Context): "yes" | "maybe" | "no" {
    if (recv?.path === true) return "yes";
    const type = baseType(host.typeOfExpr(recvExpr, ctx));
    if (type === "Path" || type === "File") return "yes";
    if (PATH_NAME.test(nameHint(recvExpr))) return "yes";
    if (recvExpr.k === "id") {
      const binding = ctx.scope.find(recvExpr.name);
      if (binding !== null && (binding.type === null || /^(?:var|val)$/.test(binding.type))) {
        return "maybe";
      }
    }
    return "no";
  }

  /**
   * The value of a path conversion (`toPath()`, `normalize()`, ...): the same path, maybe resolved.
   * For the other rules it reads as an unknown call that carries the request input in it, exactly
   * as it does without these rules.
   */
  function keepPath(recv: Value, name: string): Value {
    return {
      ...recv,
      leaves: [...recv.leaves],
      opaque: sourcesOf(recv.leaves).length > 0 ? `${name}()` : "",
      path: true,
      canon: CANONICALIZERS.has(name) ? true : recv.canon,
      builder: false,
    };
  }

  /**
   * Only the last element of a path is left (`getFileName()`, `File.name`, `FilenameUtils.getName`).
   * For SQL and commands the value is what any unknown call gives (request input carried, nothing
   * more: the last element of `a;id` is `a;id`); only the path rule reads it as inferred safe.
   */
  function lastElement(from: readonly Value[], call: string, why: string, member = false): Value {
    for (const item of from) consumeOrigin(item.origin);
    const carried = sourcesOf(from.flatMap((item) => item.leaves));
    const mark = (leaf: Leaf): Leaf =>
      leaf.k === "source" || leaf.k === "unknown" ? { ...leaf, pg: true, pgWhy: why } : leaf;
    if (carried.length > 0) {
      return value(carried.map(mark), member ? {} : { opaque: `${call}()` });
    }
    return value([mark({ k: "unknown", name: member ? "name()" : `${call}()` })]);
  }

  /** A call that may be a process call on a receiver of unknown kind: a low note, only for request input. */
  function unrecognized(
    v: Value,
    extra: Leaf[],
    line: number,
    name: string,
    kind: string,
    ctx: Context,
  ): void {
    if (!ctx.report) return;
    const judged = judge(v, extra);
    if (judged === null || judged.kind !== "tainted") return;
    const { text } = sourceText(judged);
    host.record(
      {
        ruleId: "PG-CMD-003",
        line,
        severity: "medium",
        status: "suspected",
        confidence: "low",
        evidence: `${text} -> ${name}(); receiver not recognized as ${kind}; inferred`,
        cause: `${name}:unrecognized`,
      },
      1,
    );
  }

  /** A receiver whose type is not written down (a call result, `var`, a lambda parameter). */
  const untypedReceiver = (recvExpr: Expr, ctx: Context): boolean => {
    const type = host.typeOfExpr(recvExpr, ctx);
    if (type !== null && !/^(?:var|val)$/.test(type)) return false;
    return true;
  };

  const startsWithFileUrl = (v: Value): boolean => {
    const first = v.leaves[0];
    return first !== undefined && first.k === "const" && first.text.startsWith("file:");
  };

  /** Existence and size checks read no content: reported low, and only for request input. */
  function probe(v: Value, line: number, label: string, ctx: Context): void {
    consumeOrigin(v.origin);
    if (!ctx.report) return;
    const judged = judge(v, [], v.composed, true);
    if (judged === null || judged.kind !== "tainted") return;
    const { text } = sourceText(judged);
    host.record(
      {
        ruleId: "PG-PATH-002",
        line,
        severity: "low",
        status: "suspected",
        confidence: "low",
        evidence: `${text} -> ${label} (existence or size check, no content read); inferred`,
        cause: label,
      },
      1,
    );
  }

  function call(
    expr: CallExpr,
    recv: Value | null,
    args: Value[],
    typeReceiver: boolean,
    className: string,
    ctx: Context,
  ): Value | null {
    const { name, line } = expr;
    const recvExpr = expr.recv;
    if (recvExpr === null && !typeReceiver) {
      const owner = host.staticOwner(name);
      if (owner !== null) {
        typeReceiver = true;
        className = owner;
      }
    }
    if (recvExpr === null && /^(?:mutableListOf|arrayListOf|mutableSetOf)$/.test(name)) {
      // Still an unknown value for the SQL rule (the list can change); its elements are known here.
      const leaves: Leaf[] = [{ k: "unknown", name: `${name}()` }];
      for (const arg of args) addLeaves(leaves, arg.leaves);
      return value(leaves, { elems: args, coll: true });
    }
    // ---- values that come from, or keep, a path ----
    if (recvExpr !== null && args.length === 0 && recv?.path !== true) {
      if (ARCHIVE_NEXT.has(name) || (ARCHIVE_ENTRIES.has(name) && archiveReceiver(recvExpr, ctx))) {
        return archiveSource();
      }
      if (name === "getName" || name === "getFileName") {
        if (carriesArchive(recv)) return archiveSource();
        const entry = archiveEntry(recvExpr, ctx);
        if (entry !== null) return archiveSource(entry === "named");
      }
      if (CLIENT_FILE_NAMES.has(name) && uploadName(recvExpr, ctx)) return uploadSource(name);
    }
    if (recv?.path === true && recvExpr !== null) {
      if (args.length === 0 && LAST_ELEMENT.has(name)) {
        return lastElement([recv], name, "keeps only the last path element");
      }
      if (args.length === 0 && PATH_KEEPERS.has(name)) return keepPath(recv, name);
      if (FILE_METHODS.has(name)) {
        consume(recv, line, `File.${name}`, ctx);
        return null;
      }
      if (FILE_PROBES.has(name)) {
        probe(recv, line, `File.${name}`, ctx);
        return null;
      }
    }
    if (
      recvExpr !== null &&
      (name === "resolve" || name === "resolveSibling") &&
      args.length >= 1
    ) {
      const kind = pathKind(recvExpr, recv, ctx);
      if (kind === "yes" && recv !== null) {
        return makePath([recv, ...args], line, `Path.${name}`, ctx, true);
      }
      if (kind === "maybe" && ctx.report) {
        // The receiver's type is not written down: only request input in the argument is worth a note.
        const judged = judge(join("path", ...args), [], true, true);
        if (judged !== null && judged.kind === "tainted") {
          const { text } = sourceText(judged);
          host.record(
            {
              ruleId: "PG-PATH-002",
              line,
              severity: "medium",
              status: "suspected",
              confidence: "low",
              evidence: `${text} -> ${name}(); receiver not known to be a path; inferred`,
              cause: `Path.${name}`,
            },
            1,
          );
        }
      }
    }
    if (typeReceiver && className === "Files") {
      if (FILES_SINKS.has(name) && args[0] !== undefined) {
        consume(args[0], line, `Files.${name}`, ctx);
      } else if (FILES_PROBES.has(name) && args[0] !== undefined) {
        probe(args[0], line, `Files.${name}`, ctx);
      } else if (FILES_TWO_PATH.has(name)) {
        const wayIn = args[0];
        if (
          wayIn !== undefined &&
          (wayIn.path || /^(?:Path|File|String)$/.test(typeName(expr.args[0], ctx)))
        ) {
          consume(wayIn, line, `Files.${name}`, ctx);
        }
        if (args[1] !== undefined) consume(args[1], line, `Files.${name}`, ctx);
      }
      return null;
    }
    if (
      typeReceiver &&
      ((className === "FilenameUtils" && (name === "getName" || name === "getBaseName")) ||
        (className === "StringUtils" && name === "getFilename"))
    ) {
      return lastElement(args, name, `${className}.${name}() keeps only the last path element`);
    }
    if (typeReceiver && className === "FileUtils" && FILEUTILS_SINKS.has(name)) {
      if (args[0] !== undefined) consume(args[0], line, `FileUtils.${name}`, ctx);
      if (/^(?:copy|move)/.test(name) && args[1] !== undefined) {
        consume(args[1], line, `FileUtils.${name}`, ctx);
      }
      return null;
    }
    if (typeReceiver && (className === "Paths" || className === "Path") && args.length > 0) {
      if (name === "get" || name === "of") {
        return makePath(
          args,
          line,
          `${className}.${name}`,
          ctx,
          args.length > 1 || (args[0] as Value).composed,
        );
      }
    }
    if (
      name === "getPath" &&
      args.length > 0 &&
      recvExpr?.k === "call" &&
      recvExpr.name === "getDefault"
    ) {
      return makePath(
        args,
        line,
        "FileSystem.getPath",
        ctx,
        args.length > 1 || (args[0] as Value).composed,
      );
    }
    if (name === "getRealPath" && recvExpr !== null && args.length === 1) {
      return makePath(args, line, "ServletContext.getRealPath", ctx, (args[0] as Value).composed);
    }
    if (name === "getResource" && recvExpr !== null && args.length === 1) {
      // A Spring `ResourceLoader` / `ApplicationContext` opens `file:` URLs; `ClassLoader.getResource`
      // looks on the class path, which these rules do not claim. A `file:` prefix makes any receiver count.
      const type = baseType(host.typeOfExpr(recvExpr, ctx));
      const spring =
        /^(?:ResourceLoader|ApplicationContext|WebApplicationContext|ResourcePatternResolver)$/.test(
          type,
        ) ||
        (type === "" &&
          /^(?:resourceLoader|applicationContext|appContext|ctx)$/i.test(nameHint(recvExpr)));
      if (spring) consume(args[0] as Value, line, "ResourceLoader.getResource", ctx);
      else if (startsWithFileUrl(args[0] as Value)) {
        consume(args[0] as Value, line, "getResource(file:)", ctx);
      }
      return null;
    }

    // ---- command execution ----
    if (name === "exec") {
      const first = args[0];
      // Without a receiver (Kotlin `with(runtime) { exec(x) }`) or on a variable of unknown type, an
      // `exec` in a file that gets a Runtime is that Runtime's.
      if (
        first !== undefined &&
        !typeReceiver &&
        (recvExpr === null ? host.usesRuntime : isRuntime(recvExpr, recv, ctx) || host.usesRuntime)
      ) {
        const collection = isCollection(expr.args[0], first, ctx);
        commandFrom(
          expr.args.slice(0, 1),
          args.slice(0, 1),
          line,
          "Runtime.exec",
          ctx,
          !collection,
        );
      } else if (first !== undefined && ctx.report) {
        // Some other `exec`: only request input in its argument is worth a note.
        unrecognized(first, writtenLeaves(expr.args[0], ctx), line, "exec", "a Runtime", ctx);
      }
      return null;
    }
    if (typeReceiver && className === "Runtime" && name === "getRuntime") {
      return value([], { rt: true });
    }
    if (
      name === "command" &&
      args.length >= 3 &&
      (recvExpr === null || !isProcessBuilder(recvExpr, recv, ctx)) &&
      findWrapper(args.map(fixedText)) !== null
    ) {
      // A shell wrapper is a command whatever the receiver is.
      commandFrom(expr.args, args, line, "ProcessBuilder.command", ctx);
      return null;
    }
    if (
      name === "command" &&
      (recvExpr === null
        ? host.usesProcessBuilder
        : isProcessBuilder(recvExpr, recv, ctx) || host.usesProcessBuilder)
    ) {
      if (args.length === 0) return value([], { proc: true, coll: true });
      commandFrom(expr.args, args, line, "ProcessBuilder.command", ctx);
      return value([], { proc: true });
    }
    if (
      name === "command" &&
      args.length >= 1 &&
      recvExpr !== null &&
      untypedReceiver(recvExpr, ctx)
    ) {
      // Some other `command(...)`: only request input in its arguments is worth a note.
      unrecognized(join("arguments", ...args), [], line, "command", "a ProcessBuilder", ctx);
    }
    if (ELEMENT_ADD.has(name) && recv?.proc === true && recv.coll && args.length > 0) {
      // `pb.command().add(x)`: appended to a command whose program is not known here.
      const added = args[args.length - 1] as Value;
      commandArgv(
        expandItems(added),
        { ...join("argument", added), composed: true },
        [],
        line,
        "ProcessBuilder.command",
        ctx,
        "argument",
      );
      return null;
    }
    if (typeReceiver && className === "CommandLine" && name === "parse" && args.length >= 1) {
      commandString(args[0] as Value, line, "CommandLine.parse", ctx);
      return value([], { proc: true });
    }
    if (
      host.hasCommonsExec &&
      recvExpr !== null &&
      (name === "addArgument" || name === "addArguments") &&
      args.length >= 1
    ) {
      const quotingOff = expr.args[1]?.k === "lit" && expr.args[1].raw === "false";
      const judged = judge(args[0] as Value, [], (args[0] as Value).composed);
      if (judged !== null && ctx.report) {
        const candidate = commandFinding(
          judged,
          line,
          "CommandLine.addArgument",
          quotingOff ? "unquoted" : "argument",
          "CommandLine.addArgument",
        );
        host.record(candidate.finding, candidate.rank);
      }
      return recv === null ? null : { ...recv };
    }
    return null;
  }

  const typeName = (expr: Expr | undefined, ctx: Context): string =>
    expr === undefined ? "" : baseType(host.typeOfExpr(expr, ctx));

  /** `new X(...)` / Kotlin `X(...)` for the types the rules know. Returns the value, or null. */
  function construct(
    type: string,
    line: number,
    argExprs: Expr[],
    args: Value[],
    ctx: Context,
    viaNew = true,
  ): Value | null {
    if (type === "ProcessBuilder") {
      if (args.length > 0) commandFrom(argExprs, args, line, "ProcessBuilder", ctx);
      return value([], { proc: true });
    }
    if (type === "CommandLine" && args.length >= 1) {
      const program = args[0] as Value;
      const judged = judge(program, [], program.composed);
      if (judged !== null && ctx.report) {
        const candidate = commandFinding(
          judged,
          line,
          "CommandLine",
          "program",
          "CommandLine (program name)",
        );
        host.record(candidate.finding, candidate.rank);
      }
      return value([], { proc: true });
    }
    if ((type === "File" || type === "Path") && args.length >= 1 && args.length <= 2) {
      // `File(URI)` and `File(String, String)` alike: every part is a piece of the path.
      return makePath(
        args,
        line,
        type === "File" ? (viaNew ? "new File" : "File") : "Path",
        ctx,
        args.length > 1 || (args[0] as Value).composed,
      );
    }
    if (FILE_OPENERS.has(type) && args[0] !== undefined) {
      const first = args[0];
      // A `PrintWriter` or `Formatter` also wraps a stream: only something that looks like a file name counts.
      const named =
        first.path ||
        sourcesOf(first.leaves).length > 0 ||
        ["str", "bin", "tmpl"].includes(argExprs[0]?.k ?? "") ||
        /^(?:String|File|Path)$/.test(typeName(argExprs[0], ctx));
      if (POLY_OPENERS.has(type) && !named) return null;
      if (URL_OPENERS.has(type) && !startsWithFileUrl(first)) return null;
      consume(first, line, type, ctx);
      return null;
    }
    return null;
  }

  /** Kotlin properties that mirror the conversions (`file.canonicalPath`, `file.name`) and zip entry names. */
  function member(expr: MemberExpr, recv: Value, ctx: Context): Value | null {
    if (recv.path) {
      if (LAST_ELEMENT.has(expr.name)) {
        return lastElement([recv], expr.name, "keeps only the last path element", true);
      }
      if (PATH_KEEPERS.has(expr.name)) return keepPath(recv, expr.name);
      return null;
    }
    if (ARCHIVE_NEXT.has(expr.name)) return archiveSource();
    if (ARCHIVE_ENTRIES.has(expr.name) && archiveReceiver(expr.obj, ctx)) return archiveSource();
    if (expr.name === "name" || expr.name === "fileName") {
      if (carriesArchive(recv)) return archiveSource();
      const entry = archiveEntry(expr.obj, ctx);
      if (entry !== null) return archiveSource(entry === "named");
    }
    if (CLIENT_FILE_NAMES.has(expr.name) && uploadName(expr.obj, ctx)) {
      return uploadSource(expr.name);
    }
    return null;
  }

  /** A path leaves the method (returned, stored, handed on) while a check on its variable held. */
  function escapes(v: Value): void {
    if (v.origin === null) return;
    const checked = v.leaves.some(
      (leaf) =>
        ((leaf.k === "source" || leaf.k === "unknown") && leaf.pg === true) ||
        (leaf.k === "inferred" && /allowlist/.test(leaf.why)),
    );
    if (checked) guardOrigin(v.origin);
  }

  /** Reports every path that was made and never used in a way the rule knows. */
  function flush(): void {
    for (const origin of origins) {
      if (origin.consumed) continue;
      // Checked and then used in a way the rules do not follow, or not used: inferred. Otherwise as made.
      origin.report(origin.guarded || origin.checked);
    }
  }

  /** The variable a path check or an assignment refers to. */
  const bindingOf = (expr: Expr, ctx: Context): Binding | null =>
    expr.k === "id" ? ctx.scope.find(expr.name) : null;

  return { call, construct, member, flush, bindingOf, escapes };
}
