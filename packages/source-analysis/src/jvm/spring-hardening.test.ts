import { afterAll, describe, expect, it } from "vitest";
import type { RawSourceFinding } from "../finding-factory.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzeJvmTree } from "./analyze-jvm.js";
import {
  analyzeSpringConfig,
  MAX_CONFIG_LINE,
  parseProperties,
  parseYaml,
} from "./spring-config.js";

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

async function run(source: string, path = "A.java") {
  const language = path.endsWith(".kt") ? "kotlin" : "java";
  const outcome = await runtime.parse(language, source);
  if (outcome.status !== "parsed") throw new Error(`not parsed: ${outcome.status}`);
  try {
    return analyzeJvmTree(outcome.tree.rootNode, source, path, language);
  } finally {
    outcome.dispose();
  }
}
const of = (findings: RawSourceFinding[], ruleId: string) =>
  findings.filter((finding) => finding.ruleId === ruleId);
function kind(findings: RawSourceFinding[]): string {
  const first = findings[0];
  if (first === undefined) return "none";
  return `${first.severity}/${first.confidence}${first.evidence.includes("inferred") ? "/inferred" : ""}`;
}
const SEC =
  "import org.springframework.security.config.annotation.web.builders.HttpSecurity;\nimport org.springframework.security.web.SecurityFilterChain;\nimport org.springframework.security.config.http.SessionCreationPolicy;\n";
const chain = (body: string): string =>
  `${SEC}class C {\n  SecurityFilterChain f(HttpSecurity http) throws Exception {\n${body}\n    return http.build();\n  }\n}\n`;
const STATELESS = "s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)";
const csrf = async (body: string) => kind(of((await run(chain(body))).findings, "PG-CSRF-001"));

describe("YAML and properties readers stay linear (no ReDoS)", () => {
  const BIG = 255 * 1024;
  const pathological = [
    `"a"${" ".repeat(BIG)}"b"`,
    `-a${" ".repeat(BIG)}b`,
    `a${" \t".repeat(BIG / 2)}b`,
    `${"a ".repeat(BIG / 2)}`,
    `k:${" ".repeat(BIG)}[`,
    `{${"a: ".repeat(BIG / 3)}`,
    `'${"''".repeat(BIG / 2)}`,
  ];
  for (const [index, line] of pathological.entries()) {
    it(`parses a ${(line.length / 1024) | 0} KiB line (${index}) in under 200 ms and marks it malformed`, () => {
      const started = performance.now();
      const yaml = parseYaml(`a: 1\n${line}\nb: 2\n`);
      const props = parseProperties(`a=1\n${line}\nb=2\n`);
      expect(performance.now() - started).toBeLessThan(200);
      expect(yaml.malformedLine).toBe(2);
      expect(props.malformedLine).toBe(2);
      // The lines around it are still read.
      expect(yaml.documents[0]?.map((entry) => entry.key)).toEqual(["a", "b"]);
    });
  }

  it("a continuation line of backslashes does not take quadratic time", () => {
    const started = performance.now();
    parseProperties(`a=${"\\\\".repeat(BIG / 2)}x\n`);
    parseProperties(`a=${"\\".repeat(MAX_CONFIG_LINE - 10)}\nb=1\n`);
    expect(performance.now() - started).toBeLessThan(200);
  });

  it("a hostile literal in Java does not stall the cookie name check", async () => {
    const name = "A".repeat(200_000);
    const started = performance.now();
    await run(
      `import javax.servlet.http.Cookie;\nclass C {\n  void f(HttpServletResponse r) {\n    r.addCookie(new Cookie("${name}", "v"));\n  }\n}\n`,
    );
    expect(performance.now() - started).toBeLessThan(1000);
  });
});

describe("YAML forms that are not followed make the file malformed (M7)", () => {
  const cases: Array<[string, string]> = [
    ["anchor", "base: &x\n  a: 1\n"],
    ["alias", "other: *x\n"],
    ["merge key", "a:\n  <<: {b: 1}\n"],
    ["nested flow map", "a: {b: {c: 1}}\n"],
    ["nested flow list", "a: [[1], 2]\n"],
    ["alias in a flow map", "a: {b: *x}\n"],
    ["alias in a list", "a:\n  - *x\n"],
    ["tab indentation", "a:\n\tb: 1\n"],
  ];
  for (const [name, text] of cases) {
    it(name, () => {
      expect(parseYaml(text).malformedLine).not.toBeNull();
    });
  }
  it("plain YAML is not malformed", () => {
    expect(parseYaml("a:\n  b: [1, 'x']\n  c: {d: 2}\n# note\n").malformedLine).toBeNull();
  });
  it("the properties reader drops a byte order mark", () => {
    expect(parseProperties("\uFEFFa.b=1\n").documents[0]?.[0]?.key).toBe("a.b");
    expect(parseYaml("\uFEFFa: 1\n").documents[0]?.[0]?.key).toBe("a");
  });
});

describe("configuration flag values (M6)", () => {
  const confidence = (value: string, name = "application.properties") =>
    analyzeSpringConfig(
      `server.servlet.session.cookie.secure=${value}\n`,
      name,
      "properties",
    ).findings.map(
      (finding) =>
        `${finding.confidence}${finding.evidence.includes("inferred") ? "/inferred" : ""}`,
    );
  it("false, off, no and 0 are false, in any case and quoted", () => {
    for (const value of ["false", "FALSE", "off", "No", "0", '"false"', "'off'"]) {
      expect(confidence(value), value).toEqual(["medium"]);
    }
  });
  it("true, on, yes and 1 are the only safe values", () => {
    for (const value of ["true", "On", "yes", "1", '"true"'])
      expect(confidence(value), value).toEqual([]);
  });
  it("anything that is not a literal is low and inferred", () => {
    for (const value of [
      "${SECURE}",
      "${X:off}",
      "${X:true}",
      "@token@",
      "!!bool false",
      "maybe",
      "",
    ]) {
      expect(confidence(value), value).toEqual(["low/inferred"]);
    }
  });
});

describe("CSRF: tokens, resolvers and basic credentials (M1, M2, m1)", () => {
  it("a filter known only by its name is low, not silent", async () => {
    expect(
      await csrf(
        `http.csrf(c -> c.disable()).sessionManagement(${STATELESS}).addFilterBefore(new JwtAuthFilter(), X.class);`,
      ),
    ).toBe("medium/low/inferred");
  });
  it("only STATELESS with the default resource server is silent", async () => {
    expect(
      await csrf(
        `http.csrf(c -> c.disable()).sessionManagement(${STATELESS}).oauth2ResourceServer(o -> o.jwt());`,
      ),
    ).toBe("none");
  });
  it("httpBasic next to STATELESS is medium, even with a resource server", async () => {
    expect(
      await csrf(
        `http.csrf(c -> c.disable()).sessionManagement(${STATELESS}).oauth2ResourceServer(o -> o.jwt()).httpBasic(b -> {});`,
      ),
    ).toBe("medium/medium");
    expect(
      await csrf(`http.csrf(c -> c.disable()).sessionManagement(${STATELESS}).httpBasic(b -> {});`),
    ).toBe("medium/medium");
  });
  it("a disabled httpBasic does not count", async () => {
    expect(
      await csrf(
        `http.csrf(c -> c.disable()).sessionManagement(${STATELESS}).oauth2ResourceServer(o -> o.jwt()).httpBasic(AbstractHttpConfigurer::disable);`,
      ),
    ).toBe("none");
  });
  it("a custom bearerTokenResolver or a form or query token is low", async () => {
    const base = `http.csrf(c -> c.disable()).sessionManagement(${STATELESS})`;
    expect(
      await csrf(`${base}.oauth2ResourceServer(o -> o.jwt().bearerTokenResolver(resolver));`),
    ).toBe("medium/low/inferred");
    expect(
      await csrf(`${base}.oauth2ResourceServer(o -> o.jwt().allowFormEncodedBodyParameter(true));`),
    ).toBe("medium/low/inferred");
    expect(
      await csrf(`${base}.oauth2ResourceServer(o -> o.jwt().allowUriQueryParameter(flag));`),
    ).toBe("medium/low/inferred");
    expect(
      await csrf(`${base}.oauth2ResourceServer(o -> o.jwt().allowUriQueryParameter(false));`),
    ).toBe("none");
  });
  it("STATELESS with formLogin or rememberMe is medium, bearer or not (M03)", async () => {
    const base = `http.csrf(c -> c.disable()).sessionManagement(${STATELESS})`;
    expect(await csrf(`${base}.oauth2ResourceServer(o -> o.jwt()).formLogin();`)).toBe(
      "medium/medium",
    );
    expect(await csrf(`${base}.rememberMe(r -> {});`)).toBe("medium/medium");
    expect(
      await csrf(
        `${base}.oauth2ResourceServer(o -> o.jwt()).formLogin(AbstractHttpConfigurer::disable);`,
      ),
    ).toBe("none");
  });
  it("a policy that is unknown stays unknown whatever order it is mixed in (M08)", async () => {
    const unknown = "s -> s.sessionCreationPolicy(policy)";
    expect(
      await csrf(
        `http.csrf(c -> c.disable()).sessionManagement(${STATELESS}).sessionManagement(${unknown});`,
      ),
    ).toBe("medium/low/inferred");
    expect(
      await csrf(
        `http.csrf(c -> c.disable()).sessionManagement(${unknown}).sessionManagement(${STATELESS});`,
      ),
    ).toBe("medium/low/inferred");
    expect(
      await csrf(
        `http.csrf(c -> c.disable()).sessionManagement(${unknown}).oauth2ResourceServer(o -> o.jwt());`,
      ),
    ).toBe("medium/low/inferred");
  });
  it("a NoOp security context repository means stateless (reactive)", async () => {
    const source =
      "import org.springframework.security.config.web.server.ServerHttpSecurity;\nimport org.springframework.security.web.server.SecurityWebFilterChain;\nclass C {\n  SecurityWebFilterChain f(ServerHttpSecurity http) {\n    return http.csrf(ServerHttpSecurity.CsrfSpec::disable).securityContextRepository(NoOpServerSecurityContextRepository.getInstance()).oauth2ResourceServer(o -> o.jwt()).build();\n  }\n}\n";
    expect(kind(of((await run(source)).findings, "PG-CSRF-001"))).toBe("none");
  });
  it("an unreadable chain with nothing else known is low, a readable one is medium (M36)", async () => {
    expect(await csrf("http.csrf(c -> c.disable());")).toBe("medium/medium");
    expect(await csrf("http.csrf(c -> c.disable());\n    Elsewhere.configure(http);")).toBe(
      "medium/low/inferred",
    );
    // Evidence in the file wins over the unreadable part.
    expect(
      await csrf("http.csrf(c -> c.disable()).formLogin();\n    Elsewhere.configure(http);"),
    ).toBe("medium/medium");
  });
  it("a customizer that cannot be read makes the area partial", async () => {
    const analysis = await run(chain("http.csrf(customizer);"));
    expect(analysis.unsupportedSecurityForms).toHaveLength(1);
    expect(analysis.findings).toEqual([]);
  });
});

describe("CSRF: partial and conditional disabling (M3, M4)", () => {
  it("ignoringRequestMatchers for some paths is low and names them", async () => {
    const analysis = await run(
      chain('http.csrf(c -> c.ignoringRequestMatchers("/api/**", "/hook")).formLogin();'),
    );
    const [finding] = of(analysis.findings, "PG-CSRF-001");
    expect(finding?.confidence).toBe("low");
    expect(finding?.evidence).toContain("/api/**, /hook");
    expect(finding?.evidence).toContain("inferred");
  });
  it("the older chain form is read too", async () => {
    expect(await csrf('http.csrf().ignoringAntMatchers("/api/**").and().formLogin();')).toBe(
      "medium/low/inferred",
    );
  });
  it('"/**" and anyRequest() are a full disable', async () => {
    expect(await csrf('http.csrf(c -> c.ignoringRequestMatchers("/**")).formLogin();')).toBe(
      "medium/medium",
    );
    expect(await csrf("http.csrf(c -> c.ignoringRequestMatchers(anyRequest())).formLogin();")).toBe(
      "medium/medium",
    );
    expect(await csrf('http.csrf().ignoringAntMatchers("/**").and().formLogin();')).toBe(
      "medium/medium",
    );
  });
  it("a disable in a branch of the csrf customizer is low", async () => {
    expect(await csrf("http.csrf(c -> { if (flag) c.disable(); }).formLogin();")).toBe(
      "medium/low/inferred",
    );
    expect(await csrf("http.csrf(c -> { c.disable(); }).formLogin();")).toBe("medium/medium");
    expect(
      await csrf(
        "http.csrf(c -> { if (flag) { c.disable(); } else { c.disable(); } }).formLogin();",
      ),
    ).toBe("medium/low/inferred");
  });
  it("Kotlin: a branch in the DSL block", async () => {
    const source =
      "import org.springframework.security.config.annotation.web.builders.HttpSecurity\nclass C {\n  fun f(http: HttpSecurity): SecurityFilterChain = http {\n    csrf { if (flag) disable() }\n    formLogin { }\n  }\n}\n";
    expect(kind(of((await run(source, "A.kt")).findings, "PG-CSRF-001"))).toBe(
      "medium/low/inferred",
    );
  });
});

describe("authorization rules (m2)", () => {
  it("matchers inside securityMatchers(...) are not later authorization rules", async () => {
    const source = chain(
      'http.authorizeHttpRequests(a -> a.anyRequest().permitAll()).securityMatchers(m -> m.requestMatchers("/a/**"));',
    );
    expect(of((await run(source)).findings, "PG-CONF-001")).toHaveLength(1);
  });
  it("a real later rule still shadows the catch-all", async () => {
    const source = chain(
      'http.authorizeHttpRequests(a -> a.requestMatchers("/**").permitAll().requestMatchers("/x").authenticated());',
    );
    expect(of((await run(source)).findings, "PG-CONF-001")).toEqual([]);
  });
});

describe("cookies: conditional clearing and header attributes (M5, m7)", () => {
  const servlet = (body: string) =>
    `import javax.servlet.http.Cookie;\nclass C {\n  void f(HttpServletResponse r, String id, boolean x) {\n${body}\n  }\n}\n`;
  const cookie = async (body: string) =>
    kind(of((await run(servlet(body))).findings, "PG-COOKIE-001"));
  it("setMaxAge(0) clears only when it always runs", async () => {
    expect(
      await cookie('Cookie c = new Cookie("sid", id);\n c.setMaxAge(0);\n r.addCookie(c);'),
    ).toBe("none");
    expect(
      await cookie(
        'Cookie c = new Cookie("sid", id);\n if (x) { c.setMaxAge(0); }\n r.addCookie(c);',
      ),
    ).toBe("medium/medium");
    expect(
      await cookie(
        'Cookie c = new Cookie("sid", id);\n c.setMaxAge(x ? 0 : 60);\n r.addCookie(c);',
      ),
    ).toBe("medium/medium");
  });
  it("Kotlin maxAge = 0 in a branch does not clear", async () => {
    const kotlin = (body: string) =>
      `import javax.servlet.http.Cookie\nclass C {\n  fun f(r: HttpServletResponse, id: String, x: Boolean) {\n${body}\n  }\n}\n`;
    const result = async (body: string) =>
      kind(of((await run(kotlin(body), "C.kt")).findings, "PG-COOKIE-001"));
    expect(await result('val c = Cookie("sid", id)\n c.maxAge = 0\n r.addCookie(c)')).toBe("none");
    expect(await result('val c = Cookie("sid", id)\n if (x) c.maxAge = 0\n r.addCookie(c)')).toBe(
      "medium/medium",
    );
  });
  it("attributes are whole tokens, not substrings", async () => {
    expect(
      await cookie('r.addHeader("Set-Cookie", "sid=" + id + "; Path=/; Insecure; HttpOnlyish");'),
    ).toBe("medium/medium");
    expect(await cookie('r.addHeader("Set-Cookie", "sid=" + id + ";  Secure ;httponly");')).toBe(
      "none",
    );
    expect(await cookie('r.addHeader("Set-Cookie", "sid=" + id + "; Path=/" + extra());')).toBe(
      "medium/low/inferred",
    );
  });
});
