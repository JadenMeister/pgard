/**
 * Language-neutral form of the Java and Kotlin constructs the SQL rule reads. The Java and Kotlin
 * adapters translate a syntax tree into it; one engine (`sql-engine.ts`) analyzes it.
 */

interface Base {
  /** 1-based line. */
  line: number;
}

export type Expr = Base &
  (
    | { k: "str"; text: string }
    /** Number, boolean, char or null literal (`raw` is the text of a boolean). */
    | { k: "lit"; raw?: string }
    | { k: "id"; name: string }
    | { k: "member"; obj: Expr; name: string }
    | { k: "index"; obj: Expr; index: Expr }
    | { k: "call"; recv: Expr | null; name: string; args: Expr[]; lambdas: LambdaExpr[] }
    | { k: "new"; type: string; args: Expr[] }
    | { k: "bin"; op: string; left: Expr; right: Expr }
    /** Kotlin string template: literal text and embedded expressions in order. */
    | { k: "tmpl"; parts: Array<string | Expr> }
    | { k: "cond"; test: Expr; testText: string; a: Expr; b: Expr }
    /** One of several values (switch/when results, elvis). */
    | { k: "alt"; options: Expr[] }
    | { k: "cast"; type: string; expr: Expr }
    | { k: "array"; elems: Expr[] }
    | ({ k: "lambda" } & LambdaBody)
    /** Anything else; `spread` marks a Kotlin `*array` argument. */
    | { k: "other"; kids: Expr[]; spread?: boolean }
  );

export interface LambdaBody {
  params: string[];
  body: Stmt[];
}
export type LambdaExpr = Extract<Expr, { k: "lambda" }>;

export type Stmt = Base &
  (
    | { s: "local"; name: string; type: string | null; init: Expr | null; isFinal: boolean }
    | { s: "assign"; target: Expr; op: string; value: Expr }
    | { s: "expr"; expr: Expr }
    | { s: "if"; test: Expr; testText: string; then: Stmt[]; else: Stmt[] | null }
    | {
        s: "loop";
        init: Stmt[];
        test: Expr | null;
        update: Stmt[];
        /** `for (x in xs)`: the loop variable and the iterated value. */
        each: { name: string; type: string | null; iter: Expr } | null;
        body: Stmt[];
      }
    /** Statements run in order in their own scope (blocks, try bodies, resources). */
    | { s: "block"; body: Stmt[]; params: string[] }
    /** Alternatives of which some run (switch/when arms, catch clauses). */
    | { s: "arms"; subject: Expr | null; arms: Array<{ params: string[]; body: Stmt[] }> }
    /** `ret`: a return (the value is what the method gives back), not a throw, break or continue. */
    | { s: "exit"; value: Expr | null; ret?: boolean }
    | { s: "assert"; test: Expr; testText: string }
  );

export interface Annotation {
  /** Simple name (`Select`), without a package or `@`. */
  name: string;
  /** Positional (or `value =`) argument, then the named ones. */
  value: Expr | null;
  named: Map<string, Expr>;
  line: number;
}

export interface ParamInfo {
  name: string;
  type: string;
  annotations: Annotation[];
}

export interface MethodInfo {
  name: string;
  params: ParamInfo[];
  annotations: Annotation[];
  body: Stmt[] | null;
  line: number;
  /** The declared return type, as written, when the language adapter read it. */
  returnType?: string | null;
}

export interface FieldInfo {
  name: string;
  type: string | null;
  isFinal: boolean;
  isStatic: boolean;
  /** Kotlin `const val`. */
  isConst: boolean;
  /** Kotlin `var`, or a Java field that is not final. */
  isMutable: boolean;
  /** Kotlin `open`, `abstract` or `override`: a subclass can change what it holds. */
  overridable: boolean;
  init: Expr | null;
  line: number;
  /** Annotations on the field (`@Value("${jwt.secret:x}")`), when the language adapter read them. */
  annotations?: Annotation[];
}

export interface ClassInfo {
  name: string;
  isEnum: boolean;
  enumConstants: string[];
  fields: Map<string, FieldInfo>;
  methods: MethodInfo[];
  /** Field initializers and initializer blocks, run as a method with no parameters. */
  initializers: Stmt[];
  parent: ClassInfo | null;
  /** Names of the classes and interfaces it extends or implements. */
  supers: string[];
  /** Annotations on the class (`@RestController`), when the language adapter read them. */
  annotations?: Annotation[];
}

export interface Unit {
  language: "java" | "kotlin";
  classes: ClassInfo[];
  /** Kotlin top-level declarations (and the file scope for lookups). */
  top: ClassInfo;
  /** The file's `import` names, as written (`java.sql.Statement`, `org.foo.*`). */
  imports: string[];
  /** Kotlin `import a.b.C as D`: `D` -> `C`. */
  aliases: Map<string, string>;
  /** The tree was deeper than the converter follows; part of the file was not analyzed. */
  incomplete: boolean;
  /**
   * Forms the analysis does not follow (anonymous classes, local classes, local functions) that
   * contain a call that looks like a SQL call. They make the file's coverage partial.
   */
  unsupported: string[];
}
