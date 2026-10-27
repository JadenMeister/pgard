import type { Confidence, FindingStatus, Severity } from "@pgard/findings";
import {
  DIGEST_CONSTANTS,
  DTO_TYPE,
  FILLS_ARGUMENT,
  HASH_CALL,
  HASH_OWNER,
  HASH_TYPE,
  WEAK_PASSWORD_ENCODERS,
  isPasswordWord,
  isSecretContextName,
  JDBC_UPDATE_CALLS,
  PASSWORD_NAME,
  PERSIST_CALLS,
  RANDOM_METHODS,
  REPOSITORY_NAME,
  REQUEST_PARAM_ANNOTATIONS,
  STRONG_REQUEST_TYPE,
  WEAK_DIGEST,
  WEAK_DIGEST_GETTERS,
  WEAK_DIGEST_HELPERS,
  weakCipherReason,
} from "./crypto-names.js";
import type {
  Annotation,
  ClassInfo,
  Expr,
  FieldInfo,
  MethodInfo,
  ParamInfo,
  Stmt,
  Unit,
} from "./ir.js";
import { walkExpression, walkStatements } from "./ir-walk.js";

/**
 * The cryptography rules on Java and Kotlin files: PG-CRYPTO-001 (a weak hash of a password),
 * PG-CRYPTO-002 (a hardcoded key or signing secret), PG-CRYPTO-003 (a broken cipher, a fixed IV,
 * weak randomness for a key, IV, salt or token) and PG-AUTH-001 (a password stored without
 * hashing). They are pattern rules over one method of one file, like their JavaScript and Go
 * versions: a value is followed through single-assignment locals, constants and fields of the
 * file, never across methods or files.
 *
 * Only a syntactically fixed value is a strong result. A value that comes from configuration with
 * a literal default is medium; a value inferred from names only is low, with "; inferred".
 */

export interface CryptoFinding {
  ruleId: "PG-CRYPTO-001" | "PG-CRYPTO-002" | "PG-CRYPTO-003" | "PG-AUTH-001";
  line: number;
  severity: Severity;
  status: FindingStatus;
  confidence: Confidence;
  evidence: string;
  cause: string;
}

const MAX_FINDINGS = 200;
const MAX_DEPTH = 6;

interface Local {
  decls: number;
  init: Expr | null;
  assigns: number;
  /** An array local that is filled or overwritten after it is made. */
  mutated: boolean;
}

interface Ctx {
  cls: ClassInfo;
  method: MethodInfo | null;
  locals: Map<string, Local>;
  params: Map<string, ParamInfo>;
  body: Stmt[];
}

/**
 * What a fixed value is and where it came from. `reassigned` is a string literal in a variable or
 * field that something else may overwrite (low confidence).
 */
interface Fixed {
  conf: "high" | "medium" | "low";
  /** `literal`: written at the use or in a constant; `default`: a literal default of a config value; `field`: a literal in a field that is not final. */
  kind: "literal" | "default" | "field" | "reassigned";
  via: string | null;
  texts: string[];
  what: "string" | "bytes" | "zero";
  ann: Annotation | null;
}

type Call = Extract<Expr, { k: "call" }>;
type Level = "request" | "name" | null;

const simple = (name: string): string => name.slice(name.lastIndexOf(".") + 1);
const BYTES_OF = new Set([
  "getBytes",
  "toByteArray",
  "encodeToByteArray",
  "toCharArray",
  "trim",
  "strip",
  "toString",
  "intern",
]);
const DECODERS = new Set([
  "decode",
  "decodeBase64",
  "decodeHex",
  "parseHexBinary",
  "fromHex",
  "fromBase64",
]);
const DEFAULT_ARG: Record<string, number> = {
  getProperty: 1,
  getOrDefault: 1,
  requireNonNullElse: 1,
  orElse: 0,
};
const REQUEST_ALIAS_METHODS = new Set(["getParameter", "getHeader", "getAttribute"]);
const PLAIN_PASS_THROUGH = new Set([
  "trim",
  "strip",
  "toString",
  "toCharArray",
  "getBytes",
  "toByteArray",
  "valueOf",
  "requireNonNull",
  "requireNotNull",
  "orElse",
  "get",
  "intern",
]);
const KEY_PROPERTY =
  /secret|hmac|passphrase|private[-_.]?key|signing[-_.]?key|encryption[-_.]?key|crypto[-_.]?key|aes[-_.]?key|jwt[-_.]?key|(?:^|[-_.])key$/i;
const NOT_A_KEY_PROPERTY =
  /public|prefix|header|name|[-_.]id$|path|url|algorithm|expir|ttl|file|location|issuer|alias|length|size/i;
const NOT_A_KEY_PROPERTY_FULL =
  /publishable|site[-_.]?key|sort|cache|public|(?:^|[-_.])api[-_.]?id/i;
const PASSWORD_PROPERTY = /(?:^|[-_.])(?:password|passwd|passphrase)$/i;
const KEY_FIELD =
  /secret|signingKey|hmac|privateKey|encryptionKey|aesKey|jwtKey|^key$|^secretKey$/i;

/** `${name:default}` -> the default (after `${a:${B:default}}` nesting), or null when it is empty. */
function placeholderDefault(text: string): { name: string; def: string } | null {
  const match = /^\$\{\s*([^:}]*?)\s*:([\s\S]*)\}$/.exec(text.trim());
  if (match === null) return null;
  const name = match[1] as string;
  let def = (match[2] as string).trim();
  if (def.startsWith("${")) {
    const nested = placeholderDefault(def);
    if (nested === null) return null;
    def = nested.def;
  }
  if (def === "" || def.startsWith("#{") || def.includes("${")) return null;
  return { name, def };
}

export function cryptoFindings(unit: Unit): CryptoFinding[] {
  const found: CryptoFinding[] = [];
  const report = (finding: CryptoFinding): void => {
    if (found.length < MAX_FINDINGS) found.push(finding);
  };
  const real = (name: string): string => unit.aliases.get(name) ?? name;
  const kotlin = unit.language === "kotlin";
  const classes = [unit.top, ...unit.classes];
  const classByName = new Map<string, ClassInfo>();
  for (const cls of unit.classes) if (!classByName.has(cls.name)) classByName.set(cls.name, cls);
  const consumed = new Set<Annotation>();
  const importsSpringSecurity = unit.imports.some((name) =>
    name.startsWith("org.springframework.security"),
  );
  const importsJasypt = unit.imports.some((name) => name.startsWith("org.jasypt"));

  // ---------------------------------------------------------------- small readers

  /** `java.util` and the like: a chain of lower-case names. */
  const packagePath = (expr: Expr): boolean =>
    expr.k === "id"
      ? /^[a-z]/.test(expr.name)
      : expr.k === "member" && /^[a-z]/.test(expr.name) && packagePath(expr.obj);
  const typeOf = (expr: Expr): string | null => {
    if (expr.k === "new") return real(simple(expr.type.replace(/<[\s\S]*>/, "").trim()));
    if (expr.k === "call" && /^[A-Z]/.test(expr.name)) {
      // `SecretKeySpec(...)`, or Kotlin's `javax.crypto.spec.SecretKeySpec(...)`.
      if (expr.recv === null || packagePath(expr.recv)) return real(expr.name);
    }
    return null;
  };
  const ownerOf = (recv: Expr | null): string | null =>
    recv === null ? null : recv.k === "id" || recv.k === "member" ? real(recv.name) : null;
  const argsOf = (expr: Expr): Expr[] => (expr.k === "new" || expr.k === "call" ? expr.args : []);
  const annotationText = (annotation: Annotation): string | null => {
    const value = annotation.value ?? annotation.named.get("value") ?? null;
    return value !== null && value.k === "str" ? value.text : null;
  };

  const writeCache = new Map<ClassInfo, Map<string, number>>();
  const writesOf = (cls: ClassInfo): Map<string, number> => {
    const cached = writeCache.get(cls);
    if (cached !== undefined) return cached;
    const counts = new Map<string, number>();
    writeCache.set(cls, counts);
    const onStmt = (stmt: Stmt): void => {
      if (stmt.s !== "assign") return;
      const target = stmt.target;
      const name =
        target.k === "id"
          ? target.name
          : target.k === "member" && target.obj.k === "id" && target.obj.name === "this"
            ? target.name
            : null;
      if (name !== null) counts.set(name, (counts.get(name) ?? 0) + 1);
    };
    for (const method of cls.methods) walkStatements(method.body ?? [], () => {}, onStmt);
    walkStatements(cls.initializers, () => {}, onStmt);
    return counts;
  };

  const makeCtx = (cls: ClassInfo, method: MethodInfo | null, body: Stmt[]): Ctx => {
    const locals = new Map<string, Local>();
    const params = new Map<string, ParamInfo>();
    const entry = (name: string): Local => {
      let local = locals.get(name);
      if (local === undefined) {
        local = { decls: 0, init: null, assigns: 0, mutated: false };
        locals.set(name, local);
      }
      return local;
    };
    for (const param of method?.params ?? []) {
      entry(param.name).decls += 1;
      params.set(param.name, param);
    }
    walkStatements(
      body,
      (expr) => {
        if (expr.k === "lambda") for (const name of expr.params) entry(name).decls += 1;
        if (expr.k === "call" && FILLS_ARGUMENT.test(expr.name)) {
          for (const arg of expr.args) if (arg.k === "id") entry(arg.name).mutated = true;
        }
      },
      (stmt) => {
        if (stmt.s === "local") {
          const local = entry(stmt.name);
          local.decls += 1;
          if (local.decls === 1) local.init = stmt.init;
        } else if (stmt.s === "assign") {
          if (stmt.target.k === "id") entry(stmt.target.name).assigns += 1;
          else if (stmt.target.k === "index" && stmt.target.obj.k === "id")
            entry(stmt.target.obj.name).mutated = true;
        } else if (stmt.s === "loop" && stmt.each !== null) {
          entry(stmt.each.name).decls += 1;
        } else if (stmt.s === "block") {
          for (const name of stmt.params) entry(name).decls += 1;
        } else if (stmt.s === "arms") {
          for (const arm of stmt.arms) for (const name of arm.params) entry(name).decls += 1;
        }
      },
    );
    return { cls, method, locals, params, body };
  };

  // ---------------------------------------------------------------- fixed values

  const lookupField = (
    name: string,
    cls: ClassInfo,
  ): { field: FieldInfo; owner: ClassInfo } | null => {
    for (let current: ClassInfo | null = cls; current !== null; current = current.parent) {
      const field = current.fields.get(name);
      if (field !== undefined) return { field, owner: current };
    }
    const top = unit.top.fields.get(name);
    return top === undefined ? null : { field: top, owner: unit.top };
  };

  const configDefault = (annotation: Annotation): Fixed | null => {
    if (annotation.name !== "Value") return null;
    const text = annotationText(annotation);
    const parsed = text === null ? null : placeholderDefault(text);
    if (parsed === null) return null;
    return {
      conf: "medium",
      kind: "default",
      via: null,
      texts: [parsed.def],
      what: "string",
      ann: annotation,
    };
  };

  const withVia = (fixed: Fixed, via: string): Fixed => ({ ...fixed, via: fixed.via ?? via });

  const merge = (options: Fixed[], total: number): Fixed | null => {
    if (options.length === 0) return null;
    const texts = options.flatMap((option) => option.texts);
    const first = options[0] as Fixed;
    if (options.length === total && options.every((option) => option.kind === "literal")) {
      return {
        ...first,
        conf: options.every((option) => option.conf === "high") ? "high" : "medium",
        texts,
        via: null,
      };
    }
    return { ...first, conf: "medium", kind: "default", texts, via: null };
  };

  const fixedOf = (expr: Expr, ctx: Ctx, zero: boolean, depth = 0): Fixed | null => {
    if (depth > MAX_DEPTH) return null;
    const next = (inner: Expr): Fixed | null => fixedOf(inner, ctx, zero, depth + 1);
    const literal = (what: Fixed["what"], texts: string[]): Fixed => ({
      conf: "high",
      kind: "literal",
      via: null,
      texts,
      what,
      ann: null,
    });
    switch (expr.k) {
      case "str":
        return expr.text === "" ? null : literal("string", [expr.text]);
      case "lit":
        return zero && expr.raw === undefined ? literal("zero", []) : null;
      case "cast":
        return next(expr.expr);
      case "bin": {
        if (expr.op === "?:") {
          // A Kotlin elvis (`System.getenv("K") ?: "literal"`): one of its two sides.
          return merge(
            [next(expr.left), next(expr.right)].filter((value): value is Fixed => value !== null),
            2,
          );
        }
        if (expr.op !== "+") return null;
        const left = next(expr.left);
        const right = next(expr.right);
        if (
          left === null ||
          right === null ||
          left.kind !== "literal" ||
          right.kind !== "literal" ||
          left.what !== "string" ||
          right.what !== "string"
        )
          return null;
        return literal("string", [`${left.texts[0] ?? ""}${right.texts[0] ?? ""}`]);
      }
      case "array": {
        const filled =
          expr.elems.length > 0 &&
          expr.elems.every(
            (elem) => elem.k === "lit" || (elem.k === "cast" && elem.expr.k === "lit"),
          );
        return filled ? literal("bytes", []) : null;
      }
      case "call": {
        if (expr.name === "byteArrayOf" && expr.recv === null) {
          return expr.args.length > 0 && expr.args.every((arg) => arg.k === "lit")
            ? literal("bytes", [])
            : null;
        }
        if (expr.name === "ByteArray" && expr.recv === null)
          return zero ? literal("zero", []) : null;
        if (BYTES_OF.has(expr.name) && expr.recv !== null && expr.args.length <= 1) {
          const inner = next(expr.recv);
          if (inner === null || inner.what !== "string") return null;
          return inner;
        }
        if (DECODERS.has(expr.name) && expr.args[0] !== undefined) {
          const inner = next(expr.args[0]);
          return inner !== null && inner.kind === "literal" && inner.what === "string"
            ? { ...inner, what: "bytes" }
            : null;
        }
        const defaultAt = DEFAULT_ARG[expr.name];
        if (defaultAt !== undefined && expr.args[defaultAt] !== undefined) {
          const inner = next(expr.args[defaultAt] as Expr);
          if (inner !== null && inner.kind === "literal" && inner.what === "string") {
            return { ...inner, conf: "medium", kind: "default" };
          }
        }
        return null;
      }
      case "cond":
        return merge(
          [next(expr.a), next(expr.b)].filter((value): value is Fixed => value !== null),
          2,
        );
      case "alt":
        return merge(
          expr.options.map(next).filter((value): value is Fixed => value !== null),
          expr.options.length,
        );
      case "other": {
        // A Kotlin elvis (`System.getenv("K") ?: "literal"`) is read as one of its two sides.
        if (!kotlin || expr.kids.length !== 2) return null;
        return merge(
          expr.kids.map(next).filter((value): value is Fixed => value !== null),
          2,
        );
      }
      case "id": {
        const local = ctx.locals.get(expr.name);
        if (local !== undefined) {
          if (local.decls !== 1) return null;
          if (local.init === null) {
            if (local.assigns > 0) return null;
            const param = ctx.params.get(expr.name);
            for (const annotation of param?.annotations ?? []) {
              const value = configDefault(annotation);
              if (value !== null) return withVia(value, expr.name);
            }
            return null;
          }
          if (local.mutated) return null;
          const inner = next(local.init);
          if (inner === null) return null;
          if (local.assigns > 0) {
            return inner.what === "string"
              ? { ...withVia(inner, expr.name), conf: "low", kind: "reassigned" }
              : null;
          }
          return withVia(inner, expr.name);
        }
        return fieldValue(expr.name, ctx.cls, zero, depth);
      }
      case "member": {
        if (expr.obj.k !== "id") return null;
        if (expr.obj.name === "this") return fieldValue(expr.name, ctx.cls, zero, depth);
        const target = classByName.get(real(expr.obj.name));
        return target === undefined ? null : fieldValue(expr.name, target, zero, depth);
      }
      default:
        return null;
    }
  };

  const fieldValue = (name: string, cls: ClassInfo, zero: boolean, depth: number): Fixed | null => {
    const found = lookupField(name, cls);
    if (found === null) return null;
    const { field, owner } = found;
    for (const annotation of field.annotations ?? []) {
      const value = configDefault(annotation);
      if (value !== null) return withVia(value, name);
    }
    if (field.init === null) return null;
    const ctx: Ctx = { cls: owner, method: null, locals: new Map(), params: new Map(), body: [] };
    const inner = fixedOf(field.init, ctx, zero, depth + 1);
    if (inner === null) return null;
    if (field.isFinal || field.isConst) return withVia(inner, name);
    if ((writesOf(owner).get(name) ?? 0) > 0) {
      return inner.what === "string"
        ? { ...inner, conf: "low", kind: "reassigned", via: name }
        : null;
    }
    return {
      ...inner,
      conf: "medium",
      kind: inner.kind === "default" ? "default" : "field",
      via: name,
    };
  };

  // ---------------------------------------------------------------- evidence

  const describe = (fixed: Fixed): string => {
    const base =
      fixed.kind === "default"
        ? "default value in source (value redacted)"
        : fixed.what === "zero"
          ? "all-zero byte array"
          : fixed.what === "bytes"
            ? "byte array literal (value redacted)"
            : "string literal (value redacted)";
    const held =
      fixed.via === null
        ? ""
        : fixed.kind === "field"
          ? ` held in non-final field ${fixed.via}`
          : ` held in ${fixed.via}`;
    return `${base}${held}`;
  };

  const markUsed = (fixed: Fixed): void => {
    if (fixed.ann !== null) consumed.add(fixed.ann);
  };

  /** How sure a finding on a fixed value is (the value is a literal, a default, a field or reassigned). */
  const standing = (fixed: Fixed): { status: FindingStatus; confidence: Confidence } =>
    fixed.kind === "literal"
      ? { status: "confirmed", confidence: "high" }
      : fixed.kind === "reassigned"
        ? { status: "suspected", confidence: "low" }
        : { status: "suspected", confidence: "medium" };

  /** PG-CRYPTO-002: a fixed value used as a key, secret or password for key derivation. */
  const reportKey = (line: number, fixed: Fixed, where: string): void => {
    markUsed(fixed);
    const evidence = `${describe(fixed)} used as ${where}`;
    if (fixed.kind === "literal") {
      report({
        ruleId: "PG-CRYPTO-002",
        line,
        severity: "high",
        status: "confirmed",
        confidence: "high",
        evidence,
        cause: `key:${where}`,
      });
    } else if (fixed.kind === "reassigned") {
      report({
        ruleId: "PG-CRYPTO-002",
        line,
        severity: "medium",
        status: "suspected",
        confidence: "low",
        evidence: `${evidence}, but the variable is overwritten elsewhere; inferred`,
        cause: `key:${where}`,
      });
    } else if (fixed.kind === "default") {
      report({
        ruleId: "PG-CRYPTO-002",
        line,
        severity: "medium",
        status: "suspected",
        confidence: "medium",
        evidence: `${evidence}, used when the configuration value is missing`,
        cause: `key:${where}`,
      });
    } else {
      report({
        ruleId: "PG-CRYPTO-002",
        line,
        severity: "high",
        status: "suspected",
        confidence: "medium",
        evidence: `${evidence} (verify nothing else overwrites it)`,
        cause: `key:${where}`,
      });
    }
  };

  /** A fixed algorithm name: its possible texts, with how sure the value is. */
  const algorithmOf = (expr: Expr, ctx: Ctx): Fixed | null => {
    if (expr.k === "member") {
      const digest = DIGEST_CONSTANTS.get(expr.name);
      if (digest !== undefined && /Algorithms$/.test(ownerOf(expr.obj) ?? "")) {
        return {
          conf: "high",
          kind: "literal",
          via: null,
          texts: [digest],
          what: "string",
          ann: null,
        };
      }
    }
    const fixed = fixedOf(expr, ctx, false);
    return fixed !== null && fixed.what === "string" ? fixed : null;
  };

  // ---------------------------------------------------------------- per-body checks

  const bodies: Array<{ ctx: Ctx }> = [];
  for (const cls of classes) {
    for (const method of cls.methods) {
      if (method.body !== null) bodies.push({ ctx: makeCtx(cls, method, method.body) });
    }
    if (cls.initializers.length > 0) bodies.push({ ctx: makeCtx(cls, null, cls.initializers) });
    // A field initializer is read as the local it would be in a method.
    for (const field of cls.fields.values()) {
      if (field.init === null) continue;
      const local: Stmt = {
        s: "local",
        line: field.line,
        name: field.name,
        type: field.type,
        init: field.init,
        isFinal: field.isFinal,
      };
      bodies.push({ ctx: makeCtx(cls, null, [local]) });
    }
  }

  // Digest uses per method (phase 1), so a helper that digests its parameter can be matched to
  // callers that pass it a password.
  interface DigestUse {
    line: number;
    alg: string;
    low: boolean;
    args: Expr[];
  }
  const helperParams = new Map<string, { names: string[]; weak: Set<number> }>();

  const chainOf = (expr: Call): { base: Call; above: Call[] } => {
    const above: Call[] = [];
    let current: Call = expr;
    while (current.recv !== null && current.recv.k === "call") {
      above.push(current);
      current = current.recv;
    }
    return { base: current, above };
  };

  /** What digest a call gives (`MessageDigest.getInstance("MD5")`, `Hashing.sha1()`), if it is weak. */
  const weakDigestOf = (expr: Expr, ctx: Ctx): { alg: string; low: boolean } | null => {
    if (expr.k !== "call") return null;
    const owner = ownerOf(expr.recv);
    if (owner === "MessageDigest" && expr.name === "getInstance" && expr.args[0] !== undefined) {
      return weakAlgorithm(expr.args[0], ctx);
    }
    if (owner === "DigestUtils" && expr.name === "getDigest" && expr.args[0] !== undefined) {
      return weakAlgorithm(expr.args[0], ctx);
    }
    if (owner === "DigestUtils" && WEAK_DIGEST_GETTERS.has(expr.name)) {
      return { alg: WEAK_DIGEST_GETTERS.get(expr.name) as string, low: false };
    }
    if (
      owner === "Hashing" &&
      (expr.name === "md5" || expr.name === "sha1") &&
      expr.args.length === 0
    ) {
      return { alg: expr.name === "md5" ? "MD5" : "SHA-1", low: false };
    }
    return null;
  };
  const weakAlgorithm = (arg: Expr, ctx: Ctx): { alg: string; low: boolean } | null => {
    const fixed = algorithmOf(arg, ctx);
    if (fixed === null) return null;
    const alg = fixed.texts.find((text) => WEAK_DIGEST.test(text.trim()));
    if (alg === undefined) return null;
    markUsed(fixed);
    return { alg, low: fixed.kind === "default" };
  };

  const isPasswordish = (expr: Expr): boolean => {
    let hit = false;
    walkExpression(
      expr,
      (inner) => {
        if (
          (inner.k === "id" || inner.k === "member" || inner.k === "call") &&
          isPasswordWord(inner.name)
        )
          hit = true;
      },
      () => {},
    );
    return hit;
  };
  const mentions = (expr: Expr, names: ReadonlySet<string>): boolean => {
    let hit = false;
    walkExpression(
      expr,
      (inner) => {
        if (inner.k === "id" && names.has(inner.name)) hit = true;
      },
      () => {},
    );
    return hit;
  };

  /** The digests this body applies and to what (a chain, a variable, a Commons Codec helper). */
  const digestUses = (
    ctx: Ctx,
  ): { uses: DigestUse[]; made: Array<{ line: number; alg: string; low: boolean }> } => {
    const uses: DigestUse[] = [];
    const made: Array<{ line: number; alg: string; low: boolean }> = [];
    const vars = new Map<string, { alg: string; low: boolean }>();
    for (const [name, local] of ctx.locals) {
      if (local.decls !== 1 || local.assigns > 0 || local.init === null) continue;
      const digest = weakDigestOf(local.init, ctx);
      if (digest !== null) vars.set(name, digest);
    }
    for (const field of ctx.cls.fields.values()) {
      if (field.init === null || vars.has(field.name) || ctx.locals.has(field.name)) continue;
      const digest = weakDigestOf(field.init, ctx);
      if (digest !== null) vars.set(field.name, digest);
    }
    const seen = new Set<Call>();
    walkStatements(
      ctx.body,
      (expr) => {
        if (expr.k !== "call") return;
        const { base, above } = chainOf(expr);
        const digest = weakDigestOf(base, ctx);
        if (digest !== null && !seen.has(base)) {
          seen.add(base);
          made.push({ line: base.line, ...digest });
          const args = above.flatMap((call) => call.args);
          if (args.length > 0) uses.push({ line: expr.line, ...digest, args });
          return;
        }
        if (
          expr.recv !== null &&
          expr.recv.k === "id" &&
          vars.has(expr.recv.name) &&
          (expr.name === "update" || expr.name === "digest")
        ) {
          uses.push({
            line: expr.line,
            ...(vars.get(expr.recv.name) as { alg: string; low: boolean }),
            args: expr.args,
          });
          return;
        }
        const owner = ownerOf(expr.recv);
        const helper = owner === "DigestUtils" ? WEAK_DIGEST_HELPERS.get(expr.name) : undefined;
        if (helper !== undefined && !seen.has(expr)) {
          seen.add(expr);
          const args = expr.args;
          made.push({ line: expr.line, alg: helper, low: false });
          uses.push({ line: expr.line, alg: helper, low: false, args });
        }
      },
      () => {},
    );
    return { uses, made };
  };

  const digestPhase = new Map<Ctx, ReturnType<typeof digestUses>>();
  for (const { ctx } of bodies) {
    const result = digestUses(ctx);
    digestPhase.set(ctx, result);
    if (ctx.method !== null && result.uses.length > 0) {
      const names = ctx.method.params.map((param) => param.name);
      const weak = new Set<number>();
      names.forEach((name, index) => {
        if (result.uses.some((use) => use.args.some((arg) => mentions(arg, new Set([name]))))) {
          weak.add(index);
        }
      });
      if (weak.size > 0) {
        const known = helperParams.get(ctx.method.name);
        helperParams.set(ctx.method.name, {
          names,
          weak: new Set([...(known?.weak ?? []), ...weak]),
        });
      }
    }
  }

  // ---- randomness helpers (shared by bodies and field initializers)
  const weakGen = (expr: Expr): boolean => {
    if (expr.k === "cast") return weakGen(expr.expr);
    const type = typeOf(expr);
    if (type === "Random" || type === "SplittableRandom") return true;
    if (expr.k === "call" && expr.name === "current" && ownerOf(expr.recv) === "ThreadLocalRandom")
      return true;
    return (
      expr.k === "member" &&
      expr.name === "Default" &&
      expr.obj.k === "id" &&
      expr.obj.name === "Random"
    );
  };

  const random = (
    ctx: Ctx,
    weakObjects: Set<string>,
  ): {
    weakObj: (expr: Expr) => boolean;
    weakCall: (expr: Expr) => boolean;
    derived: (expr: Expr, weakValues: ReadonlySet<string>) => boolean;
  } => {
    const weakObj = (expr: Expr): boolean => {
      if (expr.k === "cast") return weakObj(expr.expr);
      if (weakGen(expr)) return true;
      if (expr.k === "id") {
        if (expr.name === "Random" && kotlin && !ctx.locals.has("Random")) return true;
        return weakObjects.has(expr.name);
      }
      if (expr.k === "member") {
        if (expr.name === "Random" && kotlin) return true;
        return expr.obj.k === "id" && expr.obj.name === "this" && weakObjects.has(expr.name);
      }
      return false;
    };
    const weakCall = (expr: Expr): boolean => {
      if (expr.k !== "call") return false;
      const owner = ownerOf(expr.recv);
      if (owner === "Math" && expr.name === "random") return true;
      if (owner === "RandomStringUtils" && expr.name.startsWith("random")) return true;
      if (owner === "RandomUtils" && expr.name.startsWith("next")) return true;
      return expr.recv !== null && RANDOM_METHODS.test(expr.name) && weakObj(expr.recv);
    };
    const derived = (expr: Expr, weakValues: ReadonlySet<string>): boolean => {
      let hit = false;
      walkExpression(
        expr,
        (inner) => {
          if (weakCall(inner) || (inner.k === "id" && weakValues.has(inner.name))) hit = true;
        },
        () => {},
      );
      return hit;
    };
    return { weakObj, weakCall, derived };
  };

  const weakObjectFields = (cls: ClassInfo): Set<string> => {
    const names = new Set<string>();
    for (let current: ClassInfo | null = cls; current !== null; current = current.parent) {
      for (const field of current.fields.values()) {
        if (field.init !== null && weakGen(field.init)) names.add(field.name);
      }
    }
    for (const field of unit.top.fields.values()) {
      if (field.init !== null && weakGen(field.init)) names.add(field.name);
    }
    return names;
  };

  const reportRandom = (line: number, evidence: string, low: boolean, cause: string): void => {
    report({
      ruleId: "PG-CRYPTO-003",
      line,
      severity: "medium",
      status: "suspected",
      confidence: low ? "low" : "medium",
      evidence: low ? `${evidence}; inferred` : evidence,
      cause,
    });
  };

  // ---- password helpers (PG-AUTH-001)
  const isRequestParam = (param: ParamInfo, ctx: Ctx): boolean => {
    if (param.annotations.some((annotation) => REQUEST_PARAM_ANNOTATIONS.has(annotation.name)))
      return true;
    const type = simple(
      param.type
        .replace(/<[\s\S]*>/, "")
        .replace(/[?[\]]/g, "")
        .trim(),
    );
    if (STRONG_REQUEST_TYPE.test(type)) return true;
    if (DTO_TYPE.test(type)) {
      const controller = (ctx.cls.annotations ?? []).some((annotation) =>
        /^(?:Rest)?Controller$/.test(annotation.name),
      );
      const mapped = (ctx.method?.annotations ?? []).some((annotation) =>
        /Mapping$/.test(annotation.name),
      );
      return controller || mapped;
    }
    return false;
  };
  const rootOf = (expr: Expr): Expr => {
    let current = expr;
    for (let i = 0; i < 20; i += 1) {
      if (current.k === "member") current = current.obj;
      else if (current.k === "call" && current.recv !== null) current = current.recv;
      else if (current.k === "cast") current = current.expr;
      else break;
    }
    return current;
  };
  const requestRoot = (expr: Expr, ctx: Ctx): boolean => {
    const root = rootOf(expr);
    if (root.k !== "id") return false;
    const param = ctx.params.get(root.name);
    return (
      param !== undefined &&
      (ctx.locals.get(root.name)?.decls ?? 0) === 1 &&
      isRequestParam(param, ctx)
    );
  };

  const plainLevel = (expr: Expr, ctx: Ctx, depth = 0): Level => {
    if (depth > 4) return null;
    const more = (inner: Expr): Level => plainLevel(inner, ctx, depth + 1);
    switch (expr.k) {
      case "member":
        return PASSWORD_NAME.test(expr.name) ? (requestRoot(expr, ctx) ? "request" : "name") : null;
      case "call": {
        if (REQUEST_ALIAS_METHODS.has(expr.name) && expr.args[0]?.k === "str") {
          return PASSWORD_NAME.test(expr.args[0].text) ? "request" : null;
        }
        const getter = /^get([A-Z]\w*)$/.exec(expr.name)?.[1] ?? expr.name;
        if (expr.recv !== null && expr.args.length === 0 && PASSWORD_NAME.test(getter)) {
          return requestRoot(expr, ctx) ? "request" : "name";
        }
        if (PLAIN_PASS_THROUGH.has(expr.name)) {
          if (expr.recv !== null && expr.recv.k !== "id") return more(expr.recv);
          if (expr.recv !== null && expr.args.length === 0) return more(expr.recv);
          if (expr.args[0] !== undefined) return more(expr.args[0]);
        }
        return null;
      }
      case "id": {
        const local = ctx.locals.get(expr.name);
        if (local === undefined) return null;
        if (local.decls !== 1 || local.assigns > 0) return null;
        if (local.init === null) {
          const param = ctx.params.get(expr.name);
          if (param === undefined || !PASSWORD_NAME.test(expr.name)) return null;
          return isRequestParam(param, ctx) ? "request" : "name";
        }
        if (
          PASSWORD_NAME.test(expr.name) &&
          local.init.k === "call" &&
          REQUEST_ALIAS_METHODS.has(local.init.name)
        )
          return "request";
        return more(local.init);
      }
      case "cast":
        return more(expr.expr);
      case "alt":
        return expr.options.map(more).find((level) => level !== null) ?? null;
      case "cond":
        return more(expr.a) ?? more(expr.b);
      default:
        return null;
    }
  };

  const hashesIn = (ctx: Ctx): boolean => {
    let hit = false;
    walkStatements(
      ctx.body,
      (expr) => {
        if (
          expr.k === "new" ||
          (expr.k === "call" && expr.recv === null && /^[A-Z]/.test(expr.name))
        ) {
          if (HASH_TYPE.test(typeOf(expr) ?? "")) hit = true;
        }
        if (expr.k === "call") {
          const owner = ownerOf(expr.recv);
          if (HASH_CALL.test(expr.name) && expr.recv === null) hit = true;
          if (
            HASH_CALL.test(expr.name) &&
            owner !== null &&
            (HASH_OWNER.test(owner) ||
              /^(?:BCrypt|Argon2|SCrypt|Hashing|DigestUtils|MessageDigest|Pbkdf2)/i.test(owner))
          )
            hit = true;
          if (
            HASH_CALL.test(expr.name) &&
            expr.recv !== null &&
            HASH_OWNER.test(rootName(expr.recv))
          )
            hit = true;
        }
      },
      () => {},
    );
    return hit;
  };
  const rootName = (expr: Expr): string => {
    const root = rootOf(expr);
    return root.k === "id" ? root.name : "";
  };

  const SQL_PASSWORD_WRITE = /\b(?:insert|update)\b[\s\S]*\b(?:password|passwd|pwd|pass)\b(?!\w)/i;

  // ---------------------------------------------------------------- the checks

  for (const { ctx } of bodies) {
    const { uses, made } = digestPhase.get(ctx) as ReturnType<typeof digestUses>;
    const weakObjects = weakObjectFields(ctx.cls);
    for (const [name, local] of ctx.locals) {
      // A local or parameter of the same name shadows the field.
      if (local.decls === 1 && local.init !== null && weakGen(local.init)) weakObjects.add(name);
      else weakObjects.delete(name);
    }
    const rng = random(ctx, weakObjects);
    const weakValues = new Set<string>();
    const carriers = new Map<string, Level>();
    const hashed = hashesIn(ctx);
    let sqlWrite = false;
    walkStatements(
      ctx.body,
      (expr) => {
        if (expr.k === "str" && SQL_PASSWORD_WRITE.test(expr.text)) sqlWrite = true;
      },
      () => {},
    );
    const methodName = ctx.method?.name ?? "";

    // PG-CRYPTO-001: weak digest of a password.
    let reportedDigest = false;
    for (const use of uses) {
      if (!use.args.some(isPasswordish)) continue;
      reportedDigest = true;
      report({
        ruleId: "PG-CRYPTO-001",
        line: use.line,
        severity: use.low ? "medium" : "high",
        status: "suspected",
        confidence: use.low ? "low" : "medium",
        evidence: use.low
          ? `${use.alg} digest of a password-like value; algorithm not fixed; inferred`
          : `${use.alg} digest of a password-like value`,
        cause: "weak-digest",
      });
    }
    if (
      !reportedDigest &&
      made.length > 0 &&
      (isPasswordWord(methodName) || isPasswordWord(ctx.cls.name))
    ) {
      const first = made[0] as { line: number; alg: string; low: boolean };
      report({
        ruleId: "PG-CRYPTO-001",
        line: first.line,
        severity: "medium",
        status: "suspected",
        confidence: "low",
        evidence: `${first.alg} digest in a password-named method or class; inferred`,
        cause: "weak-digest",
      });
    }

    const onExpr = (expr: Expr): void => {
      if (expr.k !== "call" && expr.k !== "new") {
        return;
      }
      const type = typeOf(expr);
      const name = expr.k === "call" ? expr.name : "";
      const owner = expr.k === "call" ? ownerOf(expr.recv) : null;
      const args = argsOf(expr);
      const line = expr.line;

      // ---- PG-CRYPTO-002: hardcoded keys
      let keyArg: Expr | undefined;
      let keyWhere = "";
      if (type === "SecretKeySpec") {
        keyArg = args[0];
        keyWhere = "SecretKeySpec key";
      } else if (type === "MACSigner" || type === "MACVerifier") {
        keyArg = args[0];
        keyWhere = `${type} secret`;
      } else if (type === "PBEKeySpec") {
        keyArg = args[0];
        keyWhere = "PBEKeySpec password";
      } else if (owner === "Keys" && name === "hmacShaKeyFor") {
        keyArg = args[0];
        keyWhere = "hmacShaKeyFor key";
      } else if (owner === "Algorithm" && /^HMAC(?:256|384|512)$/.test(name)) {
        keyArg = args[0];
        keyWhere = `${name} secret`;
      } else if (name === "setCipherKey" && args.length === 1) {
        keyArg = args[0];
        keyWhere = "Shiro rememberMe cipher key";
      } else if (name === "setSigningKey" && args.length === 1) {
        keyArg = args[0];
        keyWhere = "JWT signing key";
      }
      if (keyArg !== undefined) {
        const fixed = fixedOf(keyArg, ctx, keyWhere === "PBEKeySpec password" ? false : true);
        if (fixed !== null) reportKey(line, fixed, keyWhere);
      } else if (name === "signWith") {
        for (const arg of args) {
          const fixed = fixedOf(arg, ctx, false);
          if (fixed !== null) {
            reportKey(line, fixed, "JWT signWith key");
            break;
          }
        }
      }

      // ---- PG-CRYPTO-003: ciphers
      const algorithmArg =
        owner === "Cipher" && name === "getInstance"
          ? { arg: args[0], transformation: true, where: "Cipher.getInstance" }
          : (owner === "KeyGenerator" || owner === "SecretKeyFactory") && name === "getInstance"
            ? { arg: args[0], transformation: false, where: `${owner}.getInstance` }
            : type === "SecretKeySpec"
              ? { arg: args[1], transformation: false, where: "SecretKeySpec algorithm" }
              : importsJasypt && name === "setAlgorithm"
                ? { arg: args[0], transformation: false, where: "setAlgorithm" }
                : null;
      if (algorithmArg !== null && algorithmArg.arg !== undefined) {
        const fixed = algorithmOf(algorithmArg.arg, ctx);
        const reason =
          fixed === null
            ? undefined
            : fixed.texts
                .map((text) => weakCipherReason(text, algorithmArg.transformation))
                .find((value): value is string => value !== null);
        if (fixed !== null && reason !== undefined) {
          markUsed(fixed);
          const evidence = `weak cipher: ${reason}${fixed.via === null ? "" : ` (held in ${fixed.via})`}`;
          if (fixed.kind === "default") {
            report({
              ruleId: "PG-CRYPTO-003",
              line,
              severity: "medium",
              status: "suspected",
              confidence: "low",
              evidence: `${evidence} (the default of a configured value); algorithm not fixed; inferred`,
              cause: "weak-cipher",
            });
          } else {
            report({
              ruleId: "PG-CRYPTO-003",
              line,
              severity: "medium",
              status: standing(fixed).status,
              confidence: standing(fixed).confidence,
              evidence: standing(fixed).confidence === "low" ? `${evidence}; inferred` : evidence,
              cause: "weak-cipher",
            });
          }
        }
      }

      // ---- PG-CRYPTO-003: fixed IV
      const ivArg =
        type === "IvParameterSpec" ? args[0] : type === "GCMParameterSpec" ? args[1] : undefined;
      if (ivArg !== undefined) {
        const fixed = fixedOf(ivArg, ctx, true);
        if (fixed !== null) {
          markUsed(fixed);
          const evidence = `fixed IV: ${describe(fixed)} used in ${type}${standing(fixed).confidence === "low" ? "; inferred" : ""}`;
          report({
            ruleId: "PG-CRYPTO-003",
            line,
            severity: "medium",
            status: standing(fixed).status,
            confidence: standing(fixed).confidence,
            evidence,
            cause: "fixed-iv",
          });
        }
        if (rng.derived(ivArg, weakValues))
          reportRandom(
            line,
            "non-cryptographic random value used as an IV",
            false,
            "weak-random:iv",
          );
      }

      // ---- PG-CRYPTO-003: weak randomness reaching a key, salt or secret API
      const randomArg =
        type === "SecretKeySpec" || type === "MACSigner" || type === "MACVerifier"
          ? { arg: args[0], what: "a key" }
          : type === "PBEKeySpec"
            ? { arg: args[1], what: "a salt" }
            : type === "PBEParameterSpec"
              ? { arg: args[0], what: "a salt" }
              : owner === "Keys" && name === "hmacShaKeyFor"
                ? { arg: args[0], what: "a key" }
                : owner === "Algorithm" && /^HMAC(?:256|384|512)$/.test(name)
                  ? { arg: args[0], what: "a secret" }
                  : null;
      if (
        randomArg !== null &&
        randomArg.arg !== undefined &&
        rng.derived(randomArg.arg, weakValues)
      ) {
        reportRandom(
          line,
          `non-cryptographic random value used as ${randomArg.what}`,
          false,
          `weak-random:${randomArg.what}`,
        );
      }
      // `random.nextBytes(buffer)` makes the buffer weak.
      if (
        expr.k === "call" &&
        expr.name === "nextBytes" &&
        expr.recv !== null &&
        rng.weakObj(expr.recv)
      ) {
        for (const arg of expr.args) {
          if (arg.k !== "id") continue;
          weakValues.add(arg.name);
          if (isSecretContextName(arg.name)) {
            reportRandom(
              line,
              `non-cryptographic random bytes written into ${arg.name} (a key, IV, salt or token by name)`,
              true,
              "weak-random:name",
            );
          }
        }
      }
      // A setter or builder method named for a secret.
      if (expr.k === "call" && expr.recv !== null) {
        const target = expr.name.replace(/^set(?=[A-Z])/, "");
        if (isSecretContextName(target) && expr.args.some((arg) => rng.derived(arg, weakValues))) {
          reportRandom(
            line,
            `non-cryptographic random value stored through ${expr.name}() (a token, key, IV or salt by name)`,
            true,
            "weak-random:name",
          );
        }
      }

      // ---- PG-CRYPTO-001: deprecated Spring Security password encoders
      if (type !== null && WEAK_PASSWORD_ENCODERS.has(type)) {
        // A project class that happens to share the name is not the Spring one.
        const qualified =
          (expr.k === "new" && expr.type.includes("org.springframework.security")) ||
          (expr.k === "call" && expr.recv !== null && packagePath(expr.recv));
        const sure = qualified || importsSpringSecurity;
        report({
          ruleId: "PG-CRYPTO-001",
          line,
          severity: sure ? "high" : "medium",
          status: sure ? "confirmed" : "suspected",
          confidence: sure ? "high" : "low",
          evidence: sure
            ? `deprecated ${type}: a fast, weakly salted hash for passwords`
            : `${type} by name only, no Spring Security import: a fast, weakly salted hash for passwords; inferred`,
          cause: "weak-password-encoder",
        });
      }

      // ---- PG-AUTH-001
      if (
        type === "NoOpPasswordEncoder" ||
        (owner === "NoOpPasswordEncoder" && name === "getInstance")
      ) {
        report({
          ruleId: "PG-AUTH-001",
          line,
          severity: "high",
          status: "confirmed",
          confidence: "high",
          evidence: "NoOpPasswordEncoder stores and compares passwords as plain text",
          cause: "password:noop",
        });
      }
      if (expr.k === "call" && !hashed && expr.lambdas.length > 0) {
        // `u.apply { password = pw }` and `with(u) { this.password = pw }` on an existing variable.
        const target =
          expr.name === "with" && expr.args[0]?.k === "id"
            ? expr.args[0].name
            : expr.recv?.k === "id"
              ? expr.recv.name
              : null;
        if (target !== null) {
          for (const lambda of expr.lambdas) {
            const level = lambdaLevel(lambda);
            if (level !== null) carriers.set(target, level);
          }
        }
      }
      if (expr.k === "call" && !hashed) {
        const setter = /^set([A-Z]\w*)$/.exec(expr.name)?.[1];
        if (setter !== undefined && PASSWORD_NAME.test(setter) && expr.recv?.k === "id") {
          const level = expr.args[0] === undefined ? null : plainLevel(expr.args[0], ctx);
          if (level !== null && !mentions(expr.args[0] as Expr, new Set([expr.recv.name])))
            carriers.set(expr.recv.name, level);
        }
        const direct =
          args.length > 0
            ? (args.map((arg) => plainLevel(arg, ctx)).find((l) => l !== null) ?? null)
            : null;
        const sqlText =
          JDBC_UPDATE_CALLS.has(expr.name) && args.length > 1
            ? fixedOf(args[0] as Expr, ctx, false)
            : null;
        const jdbcWrite =
          sqlText !== null &&
          sqlText.what === "string" &&
          SQL_PASSWORD_WRITE.test(sqlText.texts[0] ?? "");
        if (jdbcWrite) {
          const level = anyPlain(args.slice(1));
          if (level !== null)
            reportPassword(
              line,
              level,
              "raw SQL write of a password without a hashing call in the same method",
              "password:sql",
            );
        } else if (PERSIST_CALLS.has(expr.name)) {
          const repoLike =
            owner === null ||
            REPOSITORY_NAME.test(owner) ||
            /^(?:save|persist|merge|insert)/.test(expr.name);
          let level: Level = null;
          for (const arg of args) {
            level = carrierLevel(arg) ?? idsCarrier(arg) ?? requestEntity(arg);
            if (level !== null) break;
          }
          if (level !== null && repoLike) {
            reportPassword(
              line,
              level,
              `${expr.name}() without a hashing call in the same method`,
              `password:${expr.name}`,
            );
          }
        } else if (
          direct !== null &&
          isPasswordWord(expr.name) &&
          owner !== null &&
          REPOSITORY_NAME.test(owner)
        ) {
          reportPassword(
            line,
            direct,
            `${expr.name}() without a hashing call in the same method`,
            `password:${expr.name}`,
          );
        } else if (
          sqlWrite &&
          (expr.name === "setString" || expr.name === "setObject") &&
          args[1] !== undefined
        ) {
          const level = plainLevel(args[1], ctx);
          if (level !== null)
            reportPassword(
              line,
              level,
              "bound into a password column without a hashing call in the same method",
              "password:sql",
            );
        }
      }
    };

    const reportPassword = (line: number, level: Level, what: string, cause: string): void => {
      report({
        ruleId: "PG-AUTH-001",
        line,
        severity: level === "request" ? "high" : "medium",
        status: "suspected",
        confidence: level === "request" ? "medium" : "low",
        evidence: `password value -> ${what}${level === "request" ? "" : "; inferred"}`,
        cause,
      });
    };

    /** A value that holds a plain password: `new User(email, password)`, `User.builder().password(p)`. */
    /** A scope-function lambda (`apply`, `also`, `with`, `run`) that sets a plain password. */
    const lambdaLevel = (lambda: { body: Stmt[] }): Level => {
      const found: Level[] = [];
      walkStatements(
        lambda.body,
        () => {},
        (stmt) => {
          if (stmt.s !== "assign") return;
          const target = stmt.target;
          const name = target.k === "id" ? target.name : target.k === "member" ? target.name : "";
          if (PASSWORD_NAME.test(name)) found.push(plainLevel(stmt.value, ctx));
        },
      );
      walkStatements(
        lambda.body,
        (inner) => {
          const setter = inner.k === "call" ? /^set([A-Z]\w*)$/.exec(inner.name)?.[1] : undefined;
          if (inner.k === "call" && setter !== undefined && PASSWORD_NAME.test(setter)) {
            found.push(inner.args[0] === undefined ? null : plainLevel(inner.args[0], ctx));
          }
        },
        () => {},
      );
      return found.find((l) => l !== null) ?? null;
    };
    const carrierLevel = (expr: Expr): Level => {
      if (expr.k === "id") return carriers.get(expr.name) ?? null;
      if (expr.k !== "call" && expr.k !== "new") return null;
      let current: Expr | null = expr;
      for (let i = 0; current !== null && i < 20; i += 1) {
        if (
          current.k === "new" ||
          (current.k === "call" && current.recv === null && /^[A-Z]/.test(current.name))
        ) {
          const level = argsOf(current)
            .map((arg) => plainLevel(arg, ctx))
            .find((l) => l !== null);
          if (level !== undefined) return level;
        }
        if (current.k === "call") {
          // Kotlin `User().apply { password = pw }` and builder DSL lambdas.
          for (const lambda of current.lambdas) {
            const level = lambdaLevel(lambda);
            if (level !== null) return level;
          }
        }
        if (current.k === "call" && /password|passwd|pwd|copy/i.test(current.name)) {
          const level = current.args.map((arg) => plainLevel(arg, ctx)).find((l) => l !== null);
          if (level !== undefined) return level;
        }
        current = current.k === "call" ? current.recv : null;
      }
      return null;
    };
    const idsCarrier = (expr: Expr): Level => {
      const seen: Level[] = [];
      walkExpression(
        expr,
        (inner) => {
          if (inner.k === "id" && carriers.has(inner.name))
            seen.push(carriers.get(inner.name) ?? null);
        },
        () => {},
      );
      return seen.find((level) => level !== null) ?? null;
    };
    /** The first plain password anywhere in these expressions. */
    const anyPlain = (list: Expr[]): Level => {
      const seen: Level[] = [];
      for (const item of list) {
        walkExpression(
          item,
          (inner) => {
            seen.push(plainLevel(inner, ctx));
          },
          () => {},
        );
      }
      return seen.find((level) => level !== null) ?? null;
    };
    /** `repo.save(dto)` with a request body that has a password field (in this file). */
    const requestEntity = (expr: Expr): Level => {
      if (expr.k !== "id") return null;
      const param = ctx.params.get(expr.name);
      if (param === undefined || (ctx.locals.get(expr.name)?.decls ?? 0) !== 1) return null;
      if (!param.annotations.some((annotation) => annotation.name === "RequestBody")) return null;
      const target = classByName.get(simple(param.type.replace(/<[\s\S]*>/, "").trim()));
      if (target === undefined) return null;
      return [...target.fields.keys()].some((field) => PASSWORD_NAME.test(field))
        ? "request"
        : null;
    };

    const onStmt = (stmt: Stmt): void => {
      if (stmt.s === "local" && stmt.init !== null) {
        if (rng.derived(stmt.init, weakValues)) {
          weakValues.add(stmt.name);
          if (isSecretContextName(stmt.name)) {
            reportRandom(
              stmt.line,
              `non-cryptographic random value stored in ${stmt.name} (a token, key, IV or salt by name)`,
              true,
              "weak-random:name",
            );
          }
        }
        if (!hashed) {
          const level = carrierLevel(stmt.init);
          if (level !== null && stmt.init.k !== "id") carriers.set(stmt.name, level);
          else if (level !== null) carriers.set(stmt.name, level);
        }
      } else if (stmt.s === "assign") {
        const target = stmt.target;
        const targetName =
          target.k === "id" ? target.name : target.k === "member" ? target.name : null;
        if (targetName !== null && rng.derived(stmt.value, weakValues)) {
          if (target.k === "id") weakValues.add(target.name);
          if (isSecretContextName(targetName)) {
            reportRandom(
              stmt.line,
              `non-cryptographic random value stored in ${targetName} (a token, key, IV or salt by name)`,
              true,
              "weak-random:name",
            );
          }
        }
        if (
          !hashed &&
          target.k === "member" &&
          target.obj.k === "id" &&
          PASSWORD_NAME.test(target.name)
        ) {
          const level = plainLevel(stmt.value, ctx);
          if (level !== null && !mentions(stmt.value, new Set([target.obj.name])))
            carriers.set(target.obj.name, level);
        }
      } else if (stmt.s === "exit" && stmt.ret === true && stmt.value !== null) {
        const target = methodName.replace(
          /^(?:get|generate|create|new|make|next|random|build)(?=[A-Z_])/,
          "",
        );
        if (target !== "" && isSecretContextName(target) && rng.derived(stmt.value, weakValues)) {
          reportRandom(
            stmt.line,
            `non-cryptographic random value returned from ${methodName}() (a token, key, IV or salt by name)`,
            true,
            "weak-random:name",
          );
        }
      }
    };

    // The cipher checks above need the walk to see statements before the expressions in them.
    walkStatements(ctx.body, onExpr, onStmt);

    // PG-CRYPTO-001 through a helper of this file that digests its parameter.
    walkStatements(
      ctx.body,
      (expr) => {
        if (
          expr.k !== "call" ||
          (expr.recv !== null && !(expr.recv.k === "id" && expr.recv.name === "this"))
        )
          return;
        const helper = helperParams.get(expr.name);
        if (helper === undefined || ctx.method?.name === expr.name) return;
        for (const index of helper.weak) {
          const arg = expr.args[index];
          if (arg !== undefined && isPasswordish(arg)) {
            report({
              ruleId: "PG-CRYPTO-001",
              line: expr.line,
              severity: "high",
              status: "suspected",
              confidence: "medium",
              evidence: `weak digest (MD5 or SHA-1) of a password-like value through ${expr.name}()`,
              cause: "weak-digest",
            });
            return;
          }
        }
      },
      () => {},
    );
  }

  // ---------------------------------------------------------------- annotations

  // `@Value("${jwt.secret:literal}")` on a field or parameter that is not read at a key API.
  const annotationLine = (annotation: Annotation): number => annotation.line;
  const checkValue = (annotations: Annotation[] | undefined, fieldName: string): void => {
    for (const annotation of annotations ?? []) {
      if (consumed.has(annotation)) continue;
      const text = annotation.name === "Value" ? annotationText(annotation) : null;
      const parsed = text === null ? null : placeholderDefault(text);
      if (parsed === null) continue;
      const last = parsed.name.slice(parsed.name.lastIndexOf(".") + 1);
      const excluded = NOT_A_KEY_PROPERTY.test(last) || NOT_A_KEY_PROPERTY_FULL.test(parsed.name);
      const keyed =
        !excluded &&
        (KEY_PROPERTY.test(last) ||
          PASSWORD_PROPERTY.test(last) ||
          (KEY_FIELD.test(fieldName) && !NOT_A_KEY_PROPERTY.test(fieldName)));
      if (!keyed) continue;
      consumed.add(annotation);
      // Only the name says it is a key: low confidence. A default that reaches a key API is
      // reported there, at medium.
      report({
        ruleId: "PG-CRYPTO-002",
        line: annotationLine(annotation),
        severity: "medium",
        status: "suspected",
        confidence: "low",
        evidence: `default value in source (value redacted) for configuration key ${parsed.name}, which is named like a secret; inferred`,
        cause: "key:@Value default",
      });
    }
  };
  for (const cls of classes) {
    for (const field of cls.fields.values()) checkValue(field.annotations, field.name);
    for (const method of cls.methods) {
      for (const param of method.params) checkValue(param.annotations, param.name);
    }
  }

  return found;
}
