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
import { TIME_FACTOR } from "../../../../tests/support/timing.js";

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
      expect(performance.now() - started).toBeLessThan(Math.min(200 * TIME_FACTOR, 1000));
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
    expect(performance.now() - started).toBeLessThan(Math.min(200 * TIME_FACTOR, 1000));
  });

  it("a hostile literal in Java does not stall the cookie name check", async () => {
    const name = "A".repeat(200_000);
    const started = performance.now();
    await run(
      `import javax.servlet.http.Cookie;\nclass C {\n  void f(HttpServletResponse r) {\n    r.addCookie(new Cookie("${name}", "v"));\n  }\n}\n`,
    );
    expect(performance.now() - started).toBeLessThan(Math.min(1000 * TIME_FACTOR, 3000));
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
    ).toBe("medium/medium");
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
  it("the last session policy wins, as in Spring; an unknown value is unknown (M08)", async () => {
    const unknown = "s -> s.sessionCreationPolicy(policy)";
    expect(
      await csrf(
        `http.csrf(c -> c.disable()).sessionManagement(${STATELESS}).sessionManagement(${unknown});`,
      ),
    ).toBe("medium/low/inferred");
    expect(
      await csrf(
        `http.csrf(c -> c.disable()).sessionManagement(${unknown}).sessionManagement(${STATELESS}).oauth2ResourceServer(o -> o.jwt());`,
      ),
    ).toBe("none");
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

describe("review round 3", () => {
  it("a placeholder with a long run of spaces is read in linear time (flagOf)", () => {
    const line = `server.servlet.session.cookie.secure=\${A:${" ".repeat(4000)}b`;
    const started = performance.now();
    for (let index = 0; index < 20; index += 1) {
      analyzeSpringConfig(`${line}\n`, "application.properties", "properties");
      analyzeSpringConfig(
        `server.servlet.session.cookie.secure: \${A:${" ".repeat(4000)}}\n`,
        "application.yml",
        "yaml",
      );
    }
    expect((performance.now() - started) / 40).toBeLessThan(Math.min(50 * TIME_FACTOR, 200));
  });

  it("the 4 KiB line cap is exact in YAML (M43)", () => {
    const fits = `a: ${"x".repeat(MAX_CONFIG_LINE - 3)}`;
    expect(fits).toHaveLength(MAX_CONFIG_LINE);
    expect(parseYaml(`${fits}\n`).malformedLine).toBeNull();
    expect(parseYaml(`${fits}x\n`).malformedLine).toBe(1);
  });

  it("a securityMatcher without an earlier restriction lowers the catch-all (M10)", async () => {
    const source = chain(
      'http.securityMatcher("/public/**").authorizeHttpRequests(a -> a.anyRequest().permitAll());',
    );
    expect(kind(of((await run(source)).findings, "PG-CONF-001"))).toBe("medium/low/inferred");
    const plain = chain("http.authorizeHttpRequests(a -> a.anyRequest().permitAll());");
    expect(kind(of((await run(plain)).findings, "PG-CONF-001"))).toBe("medium/medium");
  });

  it("setAllowFormEncodedBodyParameter(true) on the bearer resolver is medium", async () => {
    expect(
      await csrf(
        `http.csrf(c -> c.disable()).sessionManagement(${STATELESS}).oauth2ResourceServer(o -> o.jwt().bearerTokenResolver(resolver));\n    resolver.setAllowFormEncodedBodyParameter(true);`,
      ),
    ).toBe("medium/medium");
  });

  describe("a conditional disable passed as the customizer", () => {
    it("Java ternary", async () => {
      expect(
        await csrf(
          "http.csrf(flag ? Customizer.withDefaults() : AbstractHttpConfigurer::disable).formLogin();",
        ),
      ).toBe("medium/low/inferred");
      expect(
        await csrf(
          "http.csrf(flag ? AbstractHttpConfigurer::disable : AbstractHttpConfigurer::disable).formLogin();",
        ),
      ).toBe("medium/medium");
      expect(
        await csrf(
          "http.csrf(flag ? Customizer.withDefaults() : Customizer.withDefaults()).formLogin();",
        ),
      ).toBe("none");
    });
    it("Java ternary of lambdas", async () => {
      expect(
        await csrf("http.csrf(flag ? c -> c.disable() : Customizer.withDefaults()).formLogin();"),
      ).toBe("medium/low/inferred");
    });
    it("a customizer variable", async () => {
      expect(
        await csrf(
          "Customizer<CsrfConfigurer<HttpSecurity>> custom = flag ? Customizer.withDefaults() : AbstractHttpConfigurer::disable;\n    http.csrf(custom).formLogin();",
        ),
      ).toBe("medium/low/inferred");
      expect(
        await csrf(
          "Customizer<CsrfConfigurer<HttpSecurity>> custom = c -> c.disable();\n    http.csrf(custom).formLogin();",
        ),
      ).toBe("medium/medium");
      expect(
        await csrf(
          "Customizer<CsrfConfigurer<HttpSecurity>> custom = Customizer.withDefaults();\n    http.csrf(custom).formLogin();",
        ),
      ).toBe("none");
    });
    it("a customizer from elsewhere stays partial, and withDefaults() is not partial", async () => {
      expect(
        (await run(chain("http.csrf(customizer).formLogin();"))).unsupportedSecurityForms,
      ).toHaveLength(1);
      expect(
        (await run(chain("http.csrf(Customizer.withDefaults()).formLogin();")))
          .unsupportedSecurityForms,
      ).toEqual([]);
    });
    it("Kotlin if expression, when expression and variable", async () => {
      const kotlin = (body: string) =>
        `import org.springframework.security.config.annotation.web.builders.HttpSecurity\nclass C {\n  fun f(http: HttpSecurity, flag: Boolean): SecurityFilterChain {\n${body}\n    return http.build()\n  }\n}\n`;
      const result = async (body: string) =>
        kind(of((await run(kotlin(body), "C.kt")).findings, "PG-CSRF-001"));
      expect(
        await result(
          "    http.csrf(if (flag) Customizer.withDefaults() else AbstractHttpConfigurer::disable)\n    http.formLogin()",
        ),
      ).toBe("medium/low/inferred");
      expect(
        await result(
          "    val c = if (flag) Customizer.withDefaults() else Customizer { it.disable() }\n    http.csrf(c)\n    http.formLogin()",
        ),
      ).toBe("medium/low/inferred");
      expect(
        await result(
          "    http.csrf(when { flag -> Customizer.withDefaults() else -> AbstractHttpConfigurer::disable })\n    http.formLogin()",
        ),
      ).toBe("medium/low/inferred");
    });
  });
});

describe("review round 4", () => {
  const CUSTOM = "Customizer<CsrfConfigurer<HttpSecurity>>";
  it("a reassigned customizer variable is not read at its first value (Java)", async () => {
    expect(
      await csrf(
        `${CUSTOM} custom = Customizer.withDefaults();\n    if (legacy) { custom = AbstractHttpConfigurer::disable; }\n    http.csrf(custom).formLogin();`,
      ),
    ).toBe("medium/low/inferred");
    expect(
      await csrf(
        `${CUSTOM} custom = Customizer.withDefaults();\n    custom = AbstractHttpConfigurer::disable;\n    http.csrf(custom).formLogin();`,
      ),
    ).toBe("medium/low/inferred");
    expect(
      await csrf(
        `${CUSTOM} custom = AbstractHttpConfigurer::disable;\n    custom = Customizer.withDefaults();\n    http.csrf(custom).formLogin();`,
      ),
    ).toBe("medium/low/inferred");
    expect(
      await csrf(
        `${CUSTOM} custom = Customizer.withDefaults();\n    custom = Customizer.withDefaults();\n    http.csrf(custom).formLogin();`,
      ),
    ).toBe("none");
    // One straight-line assignment is still fixed.
    expect(
      await csrf(`${CUSTOM} custom = c -> c.disable();\n    http.csrf(custom).formLogin();`),
    ).toBe("medium/medium");
    // A declaration inside a branch is not fixed.
    expect(
      await csrf(
        `${CUSTOM} custom;\n    if (legacy) { ${CUSTOM} inner = AbstractHttpConfigurer::disable; custom = inner; } else { custom = Customizer.withDefaults(); }\n    http.csrf(custom).formLogin();`,
      ),
    ).toBe("medium/low/inferred");
  });
  it("a reassigned customizer variable (Kotlin var)", async () => {
    const kotlin = (body: string) =>
      `import org.springframework.security.config.annotation.web.builders.HttpSecurity\nclass C {\n  fun f(http: HttpSecurity, legacy: Boolean): SecurityFilterChain {\n${body}\n    return http.build()\n  }\n}\n`;
    const result = async (body: string) =>
      kind(of((await run(kotlin(body), "C.kt")).findings, "PG-CSRF-001"));
    expect(
      await result(
        "    var custom = Customizer.withDefaults<CsrfConfigurer<HttpSecurity>>()\n    if (legacy) { custom = Customizer { it.disable() } }\n    http.csrf(custom)\n    http.formLogin()",
      ),
    ).toBe("medium/low/inferred");
    expect(
      await result(
        "    var custom = Customizer.withDefaults<CsrfConfigurer<HttpSecurity>>()\n    custom = Customizer { it.disable() }\n    http.csrf(custom)\n    http.formLogin()",
      ),
    ).toBe("medium/low/inferred");
  });

  it("a session policy set only in a branch is not fixed (Java)", async () => {
    const bearer = ".oauth2ResourceServer(o -> o.jwt())";
    expect(
      await csrf(
        `http.csrf(c -> c.disable()).sessionManagement(s -> { if (api) s.sessionCreationPolicy(SessionCreationPolicy.STATELESS); })${bearer};`,
      ),
    ).toBe("medium/low/inferred");
    expect(
      await csrf(
        `http.csrf(c -> c.disable())${bearer};\n    if (api) { http.sessionManagement(${STATELESS}); }`,
      ),
    ).toBe("medium/low/inferred");
    expect(
      await csrf(
        `http.csrf(c -> c.disable()).sessionManagement(s -> s.sessionCreationPolicy(api ? SessionCreationPolicy.STATELESS : SessionCreationPolicy.IF_REQUIRED))${bearer};`,
      ),
    ).toBe("medium/low/inferred");
  });
  it("a session policy set only in a branch is not fixed (Kotlin DSL)", async () => {
    const source =
      "import org.springframework.security.config.annotation.web.builders.HttpSecurity\nclass C {\n  fun f(http: HttpSecurity, api: Boolean): SecurityFilterChain = http {\n    csrf { disable() }\n    sessionManagement {\n      if (api) { sessionCreationPolicy = SessionCreationPolicy.STATELESS }\n    }\n    oauth2ResourceServer { jwt { } }\n  }\n}\n";
    expect(kind(of((await run(source, "C.kt")).findings, "PG-CSRF-001"))).toBe(
      "medium/low/inferred",
    );
    const fixed = source.replace(
      "if (api) { sessionCreationPolicy = SessionCreationPolicy.STATELESS }",
      "sessionCreationPolicy = SessionCreationPolicy.STATELESS",
    );
    expect(kind(of((await run(fixed, "C.kt")).findings, "PG-CSRF-001"))).toBe("none");
  });

  it("a disable inside an if statement is low (m1)", async () => {
    expect(await csrf("if (apiOnly) http.csrf(c -> c.disable());\n    http.formLogin();")).toBe(
      "medium/low/inferred",
    );
    expect(await csrf("if (apiOnly) { http.csrf().disable(); }\n    http.formLogin();")).toBe(
      "medium/low/inferred",
    );
    expect(await csrf("http.csrf(c -> c.disable());\n    http.formLogin();")).toBe("medium/medium");
  });

  it("a later non-fixed or non-STATELESS policy overrides STATELESS (M08b)", async () => {
    const bearer = ".oauth2ResourceServer(o -> o.jwt())";
    expect(
      await csrf(
        `http.csrf(c -> c.disable()).sessionManagement(${STATELESS}).sessionManagement(s -> s.sessionCreationPolicy(policy))${bearer};`,
      ),
    ).toBe("medium/low/inferred");
    expect(
      await csrf(
        `http.csrf(c -> c.disable()).sessionManagement(${STATELESS}).sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))${bearer};`,
      ),
    ).toBe("medium/medium");
  });
});

describe("review round 5", () => {
  const bearer = ".oauth2ResourceServer(o -> o.jwt())";
  it("code after an early return in a policy lambda is conditional (Java)", async () => {
    expect(
      await csrf(
        `http.csrf(c -> c.disable()).sessionManagement(s -> { if (!stateless) return; s.sessionCreationPolicy(SessionCreationPolicy.STATELESS); })${bearer};`,
      ),
    ).toBe("medium/low/inferred");
    expect(
      await csrf(
        `http.csrf(c -> c.disable()).sessionManagement(s -> { if (legacy) { return; } s.sessionCreationPolicy(SessionCreationPolicy.STATELESS); })${bearer};`,
      ),
    ).toBe("medium/low/inferred");
    expect(
      await csrf(
        `http.csrf(c -> c.disable()).sessionManagement(s -> { if (legacy) { log(); } s.sessionCreationPolicy(SessionCreationPolicy.STATELESS); })${bearer};`,
      ),
    ).toBe("none");
  });
  it("code after an early return in the Kotlin DSL is conditional", async () => {
    const dsl = (guard: string) =>
      `import org.springframework.security.config.annotation.web.builders.HttpSecurity\nclass C {\n  fun f(http: HttpSecurity, legacy: Boolean): SecurityFilterChain = http {\n    csrf { disable() }\n    sessionManagement {\n      ${guard}\n      sessionCreationPolicy = SessionCreationPolicy.STATELESS\n    }\n    oauth2ResourceServer { jwt { } }\n  }\n}\n`;
    expect(
      kind(
        of(
          (await run(dsl("if (legacy) return@sessionManagement"), "C.kt")).findings,
          "PG-CSRF-001",
        ),
      ),
    ).toBe("medium/low/inferred");
    expect(
      kind(
        of(
          (await run(dsl("if (!legacy) return@sessionManagement"), "C.kt")).findings,
          "PG-CSRF-001",
        ),
      ),
    ).toBe("medium/low/inferred");
    expect(kind(of((await run(dsl(""), "C.kt")).findings, "PG-CSRF-001"))).toBe("none");
  });
  it("a guard before the csrf disable is low", async () => {
    expect(await csrf("http.csrf(c -> { if (prod) return; c.disable(); }).formLogin();")).toBe(
      "medium/low/inferred",
    );
    expect(
      await csrf(
        "if (prod) { return http.build(); }\n    http.csrf(c -> c.disable()).formLogin();",
      ),
    ).toBe("medium/low/inferred");
    expect(await csrf("http.csrf(c -> c.disable()).formLogin();")).toBe("medium/medium");
  });
  it("a loop with break or continue guards what follows only inside it", async () => {
    expect(
      await csrf(
        "for (String p : paths) { if (p.isEmpty()) continue; http.csrf(c -> c.disable()); }\n    http.formLogin();",
      ),
    ).toBe("medium/low/inferred");
  });
  it("a reassigned customizer has accurate wording and an unknown value makes the area partial", async () => {
    const source = chain(
      "Customizer<CsrfConfigurer<HttpSecurity>> custom = AbstractHttpConfigurer::disable;\n    custom = buildCsrf();\n    http.csrf(custom).formLogin();",
    );
    const analysis = await run(source);
    const [finding] = of(analysis.findings, "PG-CSRF-001");
    expect(finding?.confidence).toBe("low");
    expect(finding?.evidence).not.toContain("only in a branch of the csrf customizer");
    expect(finding?.evidence).toContain("reassigned customizer");
    expect(analysis.unsupportedSecurityForms).toHaveLength(1);
    const readable = await run(
      chain(
        "Customizer<CsrfConfigurer<HttpSecurity>> custom = AbstractHttpConfigurer::disable;\n    custom = Customizer.withDefaults();\n    http.csrf(custom).formLogin();",
      ),
    );
    expect(readable.unsupportedSecurityForms).toEqual([]);
  });
});

describe("review round 6: any statement that can leave makes the rest conditional", () => {
  const bearer = ".oauth2ResourceServer(o -> o.jwt())";
  const policy = async (inside: string) =>
    csrf(
      `http.csrf(c -> c.disable()).sessionManagement(s -> { ${inside} s.sessionCreationPolicy(SessionCreationPolicy.STATELESS); })${bearer};`,
    );
  const LOW = "medium/low/inferred";
  it("a return inside a loop", async () => {
    expect(await policy("for (String p : paths) { if (p.isEmpty()) return; }")).toBe(LOW);
    expect(await policy("while (more()) { return; }")).toBe(LOW);
  });
  it("a return inside try, catch or finally", async () => {
    expect(await policy("try { if (x) return; } finally { cleanup(); }")).toBe(LOW);
    expect(await policy("try { work(); } catch (Exception e) { return; }")).toBe(LOW);
    expect(await policy("try { work(); } finally { return; }")).toBe(LOW);
  });
  it("a return only in a switch arm, only in an else arm, or in a nested block", async () => {
    expect(await policy("switch (mode) { case 1: return; default: log(); }")).toBe(LOW);
    expect(await policy("if (x) { log(); } else { return; }")).toBe(LOW);
    expect(await policy("{ { if (x) { return; } } }")).toBe(LOW);
    expect(await policy("if (x) { if (y) { return; } }")).toBe(LOW);
  });
  it("a throw guard is conservative: low", async () => {
    expect(await policy("if (x) throw new IllegalStateException();")).toBe(LOW);
  });
  it("break and continue only leave their loop or switch", async () => {
    expect(await policy("switch (mode) { case 1: log(); break; default: break; }")).toBe("none");
    expect(
      await policy("for (String p : paths) { if (p.isEmpty()) break; if (p.isBlank()) continue; }"),
    ).toBe("none");
    // Inside the loop body, what follows a continue is conditional.
    expect(
      await csrf(
        "for (String p : paths) { if (p.isEmpty()) continue; http.csrf(c -> c.disable()); }\n    http.formLogin();",
      ),
    ).toBe(LOW);
  });
  it("a statement that cannot leave changes nothing", async () => {
    expect(
      await policy("if (x) { log(); } else { other(); } for (String p : paths) { use(p); }"),
    ).toBe("none");
    expect(await policy("try { work(); } catch (Exception e) { log(); }")).toBe("none");
  });
  it("a jump inside a Kotlin expression", async () => {
    const dsl = (line: string) =>
      `import org.springframework.security.config.annotation.web.builders.HttpSecurity\nclass C {\n  fun f(http: HttpSecurity): SecurityFilterChain = http {\n    csrf { disable() }\n    sessionManagement {\n      ${line}\n      sessionCreationPolicy = SessionCreationPolicy.STATELESS\n    }\n    oauth2ResourceServer { jwt { } }\n  }\n}\n`;
    const result = async (line: string) =>
      kind(of((await run(dsl(line), "C.kt")).findings, "PG-CSRF-001"));
    expect(await result('val cfg = System.getenv("X") ?: return@sessionManagement')).toBe(LOW);
    expect(await result('val cfg = System.getenv("X") ?: throw IllegalStateException()')).toBe(LOW);
    expect(await result('println(System.getenv("X") ?: return@sessionManagement)')).toBe(LOW);
    expect(await result('val cfg = System.getenv("X") ?: "default"')).toBe("none");
    expect(await result("for (i in 1..3) { if (i == 2) break }")).toBe("none");
  });
  it("a return in a nested lambda does not leave the outer one", async () => {
    expect(await policy("paths.forEach(p -> { if (p.isEmpty()) return; });")).toBe("none");
  });
  it("the cookie walk is not affected by early returns", async () => {
    const source =
      'import javax.servlet.http.Cookie;\nclass C {\n  void f(HttpServletResponse res, String token) {\n    if (token == null) return;\n    Cookie c = new Cookie("session", token);\n    c.setHttpOnly(true);\n    c.setSecure(true);\n    res.addCookie(c);\n  }\n}\n';
    expect((await run(source)).findings).toEqual([]);
    const kotlin =
      'import javax.servlet.http.Cookie\nclass C {\n  fun f(res: HttpServletResponse, token: String?) {\n    val t = token ?: return\n    val c = Cookie("session", t)\n    c.isHttpOnly = true\n    c.secure = true\n    res.addCookie(c)\n  }\n}\n';
    expect((await run(kotlin, "C.kt")).findings).toEqual([]);
  });
});

describe("review round 7: labelled returns, throws and long expressions", () => {
  const LOW = "medium/low/inferred";
  const dsl = (line: string) =>
    `import org.springframework.security.config.annotation.web.builders.HttpSecurity\nclass C {\n  fun f(http: HttpSecurity, legacy: Boolean): SecurityFilterChain = http {\n    csrf { disable() }\n    sessionManagement {\n      ${line}\n      sessionCreationPolicy = SessionCreationPolicy.STATELESS\n    }\n    oauth2ResourceServer { jwt { } }\n  }\n}\n`;
  const kotlin = async (line: string) =>
    kind(of((await run(dsl(line), "C.kt")).findings, "PG-CSRF-001"));

  it("a labelled return inside an inline lambda leaves the block (Kotlin)", async () => {
    expect(await kotlin("if (legacy) run { return@sessionManagement }")).toBe(LOW);
    expect(await kotlin("legacy.takeIf { it }?.let { return@sessionManagement }")).toBe(LOW);
    expect(
      await kotlin("listOf(1).forEach { x -> if (x > 0) { run { return@sessionManagement } } }"),
    ).toBe(LOW);
  });
  it("a return to the lambda's own label, or to one in between, does not leave", async () => {
    expect(await kotlin("sessionFixation { return@sessionFixation }")).toBe("none");
    expect(await kotlin("run { run { return@run } }")).toBe("none");
    expect(await kotlin("legacy.takeIf { it }?.let { return@let }")).toBe("none");
  });
  it("an unlabelled return in a nested lambda does not count", async () => {
    expect(await kotlin("listOf(1).forEach { if (it > 0) return@forEach }")).toBe("none");
  });
  it("a throw inside a nested lambda counts", async () => {
    expect(await kotlin("run { if (legacy) throw IllegalStateException() }")).toBe(LOW);
  });

  const javaPolicy = async (inside: string) =>
    csrf(
      `http.csrf(c -> c.disable()).sessionManagement(s -> { ${inside} s.sessionCreationPolicy(SessionCreationPolicy.STATELESS); }).oauth2ResourceServer(o -> o.jwt());`,
    );
  it("a throw makes the rest conditional, also inside loops, switches and catches", async () => {
    expect(
      await javaPolicy(
        "try { for (String r : required) { if (r == null) throw new IllegalArgumentException(); } s.sessionCreationPolicy(SessionCreationPolicy.STATELESS); } catch (IllegalArgumentException e) { }",
      ),
    ).toBe(LOW);
    expect(
      await javaPolicy(
        "for (String r : required) { if (r == null) throw new IllegalStateException(); }",
      ),
    ).toBe(LOW);
    expect(
      await javaPolicy(
        "switch (mode) { case 1: throw new IllegalStateException(); default: break; }",
      ),
    ).toBe(LOW);
    expect(
      await javaPolicy(
        "try { work(); } catch (Exception e) { throw new IllegalStateException(e); }",
      ),
    ).toBe(LOW);
    // A break in the same places still does not.
    expect(await javaPolicy("for (String r : required) { if (r == null) break; }")).toBe("none");
  });
  it("a Kotlin throw statement inside a loop counts", async () => {
    expect(await kotlin("for (i in 1..3) { if (i == 2) throw IllegalStateException() }")).toBe(LOW);
    expect(await kotlin("for (i in 1..3) { if (i == 2) break }")).toBe("none");
  });

  it("a very long string concatenation in the chain method does not lose the file (exits on)", async () => {
    const terms = Array.from({ length: 10_000 }, () => '"a"').join(" + ");
    const source = chain(`String banner = ${terms};\n    http.csrf(c -> c.disable()).formLogin();`);
    const analysis = await run(source);
    expect(analysis.incomplete).toBe(false);
    expect(kind(of(analysis.findings, "PG-CSRF-001"))).toBe("medium/medium");
  });
  it("a very long receiver chain in an expression does not overflow", async () => {
    const calls = Array.from({ length: 5_000 }, () => ".append(1)").join("");
    const source = chain(
      `Object x = new StringBuilder()${calls};\n    http.csrf(c -> c.disable()).formLogin();`,
    );
    expect(kind(of((await run(source)).findings, "PG-CSRF-001"))).toBe("medium/medium");
  });
});

describe("review round 8: a bare Kotlin return in an inline lambda leaves the function", () => {
  const LOW = "medium/low/inferred";
  const method = (guard: string) =>
    `import org.springframework.security.config.annotation.web.builders.HttpSecurity\nclass C {\n  fun f(http: HttpSecurity, mode: String): SecurityFilterChain {\n    http { csrf { disable() }; oauth2ResourceServer { jwt { } } }\n    ${guard}\n    http { sessionManagement { sessionCreationPolicy = SessionCreationPolicy.STATELESS } }\n    return http.build()\n  }\n}\n`;
  const fun = async (guard: string) =>
    kind(of((await run(method(guard), "C.kt")).findings, "PG-CSRF-001"));
  it("let, run and forEach with a bare return", async () => {
    expect(await fun('mode.takeIf { it == "legacy" }?.let { return http.build() }')).toBe(LOW);
    expect(await fun('run { if (mode == "x") return http.build() }')).toBe(LOW);
    expect(await fun('listOf(mode).forEach { if (it == "x") return http.build() }')).toBe(LOW);
    expect(await fun("listOf(mode).forEach { val v = it ?: return http.build() }")).toBe(LOW);
  });
  it("return@forEach and return@let stay inside the lambda", async () => {
    expect(await fun('listOf(mode).forEach { if (it == "x") return@forEach }')).toBe("none");
    expect(await fun('mode.takeIf { it == "legacy" }?.let { return@let }')).toBe("none");
  });
  it("a bare return in a Java lambda leaves only the lambda", async () => {
    expect(
      await csrf(
        "http.csrf(c -> c.disable()).oauth2ResourceServer(o -> o.jwt());\n    paths.forEach(p -> { if (p.isEmpty()) return; });\n    http.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));",
      ),
    ).toBe("none");
  });

  const dsl = (line: string) =>
    `import org.springframework.security.config.annotation.web.builders.HttpSecurity\nclass C {\n  fun f(http: HttpSecurity): SecurityFilterChain = http {\n    csrf { disable() }\n    sessionManagement {\n      ${line}\n      sessionCreationPolicy = SessionCreationPolicy.STATELESS\n    }\n    oauth2ResourceServer { jwt { } }\n  }\n}\n`;
  const block = async (line: string) =>
    kind(of((await run(dsl(line), "C.kt")).findings, "PG-CSRF-001"));
  it("T1: ?: throw inside run leaves", async () => {
    expect(await block('run { val v = System.getenv("X") ?: throw IllegalStateException() }')).toBe(
      LOW,
    );
  });
  it("L1: ?: return@forEach stays inside, ?: return@sessionManagement leaves", async () => {
    expect(await block('listOf(1).forEach { val v = System.getenv("X") ?: return@forEach }')).toBe(
      "none",
    );
    expect(
      await block('listOf(1).forEach { val v = System.getenv("X") ?: return@sessionManagement }'),
    ).toBe(LOW);
  });
});
