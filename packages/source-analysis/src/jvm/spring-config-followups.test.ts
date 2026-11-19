import { afterAll, describe, expect, it } from "vitest";
import type { RawSourceFinding } from "../finding-factory.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzeJvmTree } from "./analyze-jvm.js";

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

async function run(source: string, path: string) {
  const language = path.endsWith(".kt") ? "kotlin" : "java";
  const outcome = await runtime.parse(language, source);
  if (outcome.status !== "parsed") throw new Error(`not parsed: ${outcome.status}`);
  try {
    return analyzeJvmTree(outcome.tree.rootNode, source, path, language);
  } finally {
    outcome.dispose();
  }
}

/** "none", or severity/confidence of the PG-CSRF-001 finding. */
async function csrf(source: string, path = "A.java"): Promise<string> {
  const findings: RawSourceFinding[] = (await run(source, path)).findings.filter(
    (finding) => finding.ruleId === "PG-CSRF-001",
  );
  const first = findings[0];
  return first === undefined ? "none" : `${first.severity}/${first.confidence}`;
}

const SEC =
  "import org.springframework.security.config.annotation.web.builders.HttpSecurity;\nimport org.springframework.security.web.SecurityFilterChain;\nimport org.springframework.security.config.http.SessionCreationPolicy;\n";
const DISABLE = "http.csrf(c -> c.disable());";
const STATELESS_BEARER =
  "http.csrf(c -> c.disable()).sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)).oauth2ResourceServer(o -> o.jwt());";
const chain = (body: string, extra = ""): string =>
  `${SEC}\nclass C {\n  SecurityFilterChain f(HttpSecurity http) throws Exception {\n${body}\n    return http.build();\n  }\n${extra}\n}\n`;
const KSEC =
  "import org.springframework.security.config.annotation.web.builders.HttpSecurity\nimport org.springframework.security.web.SecurityFilterChain\n";
const kchain = (body: string): string =>
  `${KSEC}\nclass C {\n  fun f(http: HttpSecurity): SecurityFilterChain {\n${body}\n    return http.build()\n  }\n}\n`;

const FULL = "medium/medium";
const LOW = "medium/low";

describe("an uncaught throw aborts the configuration (#367)", () => {
  it("does not make the code after it conditional", async () => {
    expect(await csrf(chain(`if (flag()) throw new IllegalStateException();\n${DISABLE}`))).toBe(
      FULL,
    );
    expect(
      await csrf(
        chain(`for (String s : names()) { if (s == null) throw new Error(); }\n${DISABLE}`),
      ),
    ).toBe(FULL);
    expect(
      await csrf(chain(`if (flag()) throw new IllegalStateException();\n${STATELESS_BEARER}`)),
    ).toBe("none");
  });

  it("still makes it conditional for a return, however it is written", async () => {
    expect(await csrf(chain(`if (flag()) return null;\n${DISABLE}`))).toBe(LOW);
    expect(await csrf(chain(`if (flag()) { return null; }\n${DISABLE}`))).toBe(LOW);
    expect(
      await csrf(chain(`if (flag()) throw new Error();\nif (other()) return null;\n${DISABLE}`)),
    ).toBe(LOW);
  });

  it("stays conditional when a try with a catch may swallow the throw", async () => {
    expect(
      await csrf(
        chain(`try { if (flag()) throw new Error(); } catch (Exception e) { log(e); }\n${DISABLE}`),
      ),
    ).toBe(LOW);
    expect(
      await csrf(
        chain(
          `try { for (String s : names()) { if (s == null) throw new Error(); } } catch (Exception e) { }\n${DISABLE}`,
        ),
      ),
    ).toBe(LOW);
    // A throw in a handler or in a try that has no catch is not caught by that try.
    expect(
      await csrf(
        chain(`try { prep(); } finally { cleanup(); }\nif (flag()) throw new Error();\n${DISABLE}`),
      ),
    ).toBe(FULL);
  });

  it("stays conditional for a throw in a lambda or in a helper the caller may wrap", async () => {
    expect(await csrf(chain(`Runnable r = () -> { throw new Error(); };\n${DISABLE}`))).toBe(LOW);
    expect(
      await csrf(
        chain(
          `helper(http);`,
          `  void helper(HttpSecurity http) throws Exception {\n    if (flag()) throw new Error();\n    ${DISABLE}\n  }`,
        ),
      ),
    ).toBe(LOW);
  });

  it("stays conditional when another method of the file calls the chain method", async () => {
    expect(
      await csrf(
        chain(
          `if (flag()) throw new Error();\n${DISABLE}`,
          `  void other(HttpSecurity http) throws Exception {\n    try { f(http); } catch (Exception e) { }\n  }`,
        ),
      ),
    ).toBe(LOW);
    // Overloads: the name no longer says which one is called.
    expect(
      await csrf(
        chain(
          `if (flag()) throw new Error();\n${DISABLE}`,
          `  SecurityFilterChain f(HttpSecurity http, int x) throws Exception {\n    return null;\n  }`,
        ),
      ),
    ).toBe(LOW);
  });

  it("does not change what a throw after the disabling call means", async () => {
    expect(await csrf(chain(`${DISABLE}\nif (flag()) throw new Error();`))).toBe(FULL);
  });
});

describe("an uncaught throw in Kotlin (#367)", () => {
  const disable = "    http.csrf { it.disable() }";

  it("does not make the code after it conditional", async () => {
    expect(
      await csrf(
        kchain(`    val v = System.getenv("X") ?: throw IllegalStateException()\n${disable}`),
        "A.kt",
      ),
    ).toBe(FULL);
    expect(
      await csrf(kchain(`    if (flag()) throw IllegalStateException()\n${disable}`), "A.kt"),
    ).toBe(FULL);
  });

  it("stays conditional for a return, a catch, a lambda and a return from an elvis", async () => {
    expect(
      await csrf(
        kchain(`    val v = System.getenv("X") ?: return http.build()\n${disable}`),
        "A.kt",
      ),
    ).toBe(LOW);
    expect(
      await csrf(
        kchain(`    try { if (flag()) throw Error() } catch (e: Exception) { }\n${disable}`),
        "A.kt",
      ),
    ).toBe(LOW);
    expect(await csrf(kchain(`    run { if (flag()) throw Error() }\n${disable}`), "A.kt")).toBe(
      LOW,
    );
  });
});

describe("a finally block always runs (#367)", () => {
  it("counts a call in finally as unconditional", async () => {
    expect(await csrf(chain(`try { prep(); } finally { ${DISABLE} }`))).toBe(FULL);
    expect(
      await csrf(chain(`try { prep(); } catch (Exception e) { log(e); } finally { ${DISABLE} }`)),
    ).toBe(FULL);
    expect(await csrf(chain(`try { prep(); } finally { ${STATELESS_BEARER} }`))).toBe("none");
  });

  it("keeps a call in a catch or in the try body conditional where it was", async () => {
    expect(await csrf(chain(`try { prep(); } catch (Exception e) { ${DISABLE} }`))).toBe(LOW);
    expect(
      await csrf(
        chain(`try { prep(); } catch (Exception e) { ${DISABLE} } finally { cleanup(); }`),
      ),
    ).toBe(LOW);
  });

  it("does not make a finally unconditional when its try is not", async () => {
    expect(await csrf(chain(`if (flag()) { try { prep(); } finally { ${DISABLE} } }`))).toBe(LOW);
    expect(
      await csrf(chain(`if (flag()) return null;\ntry { prep(); } finally { ${DISABLE} }`)),
    ).toBe(LOW);
    expect(
      await csrf(chain(`for (String s : names()) { try { prep(); } finally { ${DISABLE} } }`)),
    ).toBe(LOW);
  });

  it("works in Kotlin", async () => {
    expect(
      await csrf(kchain(`    try { prep() } finally { http.csrf { it.disable() } }`), "A.kt"),
    ).toBe(FULL);
    expect(
      await csrf(
        kchain(`    try { prep() } catch (e: Exception) { http.csrf { it.disable() } }`),
        "A.kt",
      ),
    ).toBe(LOW);
  });
});

describe("Kotlin labels (#367)", () => {
  const body = (lambda: string): string => `    ${lambda}\n    http.csrf { it.disable() }`;

  it("resolves an explicit label", async () => {
    expect(await csrf(kchain(body(`run outer@{ if (flag()) return@outer; prep() }`)), "A.kt")).toBe(
      FULL,
    );
    expect(await csrf(kchain(body(`run outer@{ return@outer }`)), "A.kt")).toBe(FULL);
  });

  it("does not take the function name for the label of a lambda that has its own", async () => {
    expect(await csrf(kchain(body(`run outer@{ if (flag()) return@run; prep() }`)), "A.kt")).toBe(
      LOW,
    );
  });

  it("a label of another lambda, a bare return and a throw still leave", async () => {
    expect(await csrf(kchain(body(`run inner@{ if (flag()) return@other; prep() }`)), "A.kt")).toBe(
      LOW,
    );
    expect(await csrf(kchain(body(`run outer@{ if (flag()) return null; prep() }`)), "A.kt")).toBe(
      LOW,
    );
    expect(
      await csrf(kchain(body(`run outer@{ if (flag()) throw Error(); prep() }`)), "A.kt"),
    ).toBe(LOW);
  });

  it("keeps the implicit label of a lambda without one", async () => {
    expect(await csrf(kchain(body(`run { if (flag()) return@run; prep() }`)), "A.kt")).toBe(FULL);
    expect(await csrf(kchain(body(`run { if (flag()) return; prep() }`)), "A.kt")).toBe(LOW);
  });

  it("a return in an anonymous function leaves only that function", async () => {
    expect(await csrf(kchain(body(`val g = fun() { return }`)), "A.kt")).toBe(FULL);
    expect(await csrf(kchain(body(`prep(fun(x: Int): Int { return x })`)), "A.kt")).toBe(FULL);
    // A return to the enclosing labelled lambda ends that lambda only; a throw, a return to the function (`return@f`) and a return outside the anonymous function leave.
    expect(await csrf(kchain(body(`val g = fun() { throw Error() }`)), "A.kt")).toBe(LOW);
    expect(await csrf(kchain(body(`run outer@{ val g = fun() { return@outer } }`)), "A.kt")).toBe(
      FULL,
    );
    expect(await csrf(kchain(body(`run outer@{ val g = fun() { return@f } }`)), "A.kt")).toBe(LOW);
    expect(
      await csrf(
        kchain(
          `    val g = fun() { return }\n    if (flag()) return http.build()\n    http.csrf { it.disable() }`,
        ),
        "A.kt",
      ),
    ).toBe(LOW);
  });
});
