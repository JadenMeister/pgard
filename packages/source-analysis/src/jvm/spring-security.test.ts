import { afterAll, describe, expect, it } from "vitest";
import type { RawSourceFinding } from "../finding-factory.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzeJvmTree } from "./analyze-jvm.js";

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

/** "none", or severity/confidence, with "inferred" when the evidence says so. */
function kind(findings: RawSourceFinding[]): string {
  const first = findings[0];
  if (first === undefined) return "none";
  return `${first.severity}/${first.confidence}${first.evidence.includes("inferred") ? "/inferred" : ""}`;
}

const SEC =
  "import org.springframework.security.config.annotation.web.builders.HttpSecurity;\nimport org.springframework.security.web.SecurityFilterChain;\nimport org.springframework.security.config.http.SessionCreationPolicy;\n";
const chain = (body: string, extra = ""): string =>
  `${SEC}${extra}\nclass C {\n  SecurityFilterChain f(HttpSecurity http) throws Exception {\n${body}\n    return http.build();\n  }\n}\n`;
const KSEC =
  "import org.springframework.security.config.annotation.web.builders.HttpSecurity\nimport org.springframework.security.config.http.SessionCreationPolicy\n";
const kchain = (body: string): string =>
  `${KSEC}\nclass C {\n  fun f(http: HttpSecurity): SecurityFilterChain = http {\n${body}\n  }\n}\n`;

describe("PG-CSRF-001: Spring Security CSRF judgement", () => {
  const cases: Array<[string, string, string, string]> = [
    ["formLogin", "A.java", chain("http.csrf().disable().formLogin();"), "medium/medium"],
    [
      "lambda disable with session policy IF_REQUIRED",
      "A.java",
      chain(
        "http.csrf(c -> c.disable()).sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));",
      ),
      "medium/medium",
    ],
    [
      "no policy and nothing else: Spring's default creates sessions",
      "A.java",
      chain("http.csrf(AbstractHttpConfigurer::disable);"),
      "medium/medium",
    ],
    [
      "stateless and bearer: silent",
      "A.java",
      chain(
        "http.csrf(c -> c.disable()).sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)).oauth2ResourceServer(o -> o.jwt());",
      ),
      "none",
    ],
    [
      "stateless with a filter known only by its name: low, inferred",
      "A.java",
      chain(
        "http.csrf().disable().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().addFilterBefore(new JwtAuthFilter(), X.class);",
      ),
      "medium/low/inferred",
    ],
    [
      "stateless with httpBasic: basic credentials are ambient, medium",
      "A.java",
      chain(
        "http.csrf(c -> c.disable()).sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)).httpBasic(b -> {});",
      ),
      "medium/medium",
    ],
    [
      "policy from a variable: low, inferred",
      "A.java",
      chain("http.csrf(c -> c.disable()).sessionManagement(s -> s.sessionCreationPolicy(policy));"),
      "medium/low/inferred",
    ],
    [
      "csrf exempted for some paths: low, inferred",
      "A.java",
      chain('http.csrf(c -> c.ignoringRequestMatchers("/hook")).formLogin();'),
      "medium/low/inferred",
    ],
    ["Kotlin DSL", "A.kt", kchain("    csrf { disable() }\n    formLogin { }"), "medium/medium"],
    [
      "Kotlin DSL stateless resource server: silent",
      "A.kt",
      kchain(
        "    csrf { disable() }\n    sessionManagement { sessionCreationPolicy = SessionCreationPolicy.STATELESS }\n    oauth2ResourceServer { jwt { } }",
      ),
      "none",
    ],
    [
      "Kotlin it.disable()",
      "A.kt",
      `${KSEC}class C {\n  fun f(http: HttpSecurity): SecurityFilterChain {\n    http.csrf { it.disable() }\n    http.rememberMe { }\n    return http.build()\n  }\n}\n`,
      "medium/medium",
    ],
  ];
  for (const [name, path, source, expected] of cases) {
    it(name, async () => {
      expect(kind(of((await run(source, path)).findings, "PG-CSRF-001"))).toBe(expected);
    });
  }

  it("follows a helper of the same file", async () => {
    const source = `${SEC}class C {\n  SecurityFilterChain f(HttpSecurity http) throws Exception {\n    http.formLogin();\n    off(http);\n    return http.build();\n  }\n  void off(HttpSecurity http) throws Exception {\n    http.csrf(c -> c.disable());\n  }\n}\n`;
    const analysis = await run(source);
    expect(of(analysis.findings, "PG-CSRF-001")).toHaveLength(1);
    expect(analysis.unsupportedSecurityForms).toEqual([]);
  });

  it("reports a helper outside the file and a custom configurer as partial", async () => {
    const helper = await run(chain("http.csrf(c -> c.disable());\n    Other.apply(http);"));
    expect(helper.unsupportedSecurityForms).toHaveLength(1);
    const custom = await run(
      chain("http.with(new MyDsl(), d -> {});\n    http.csrf(c -> c.disable());"),
    );
    expect(custom.unsupportedSecurityForms[0]).toContain("custom configurer");
    const variable = await run(chain("http.csrf(customizer);"));
    expect(variable.unsupportedSecurityForms[0]).toContain("CSRF customizer");
  });

  it("ignores files that do not import Spring Security", async () => {
    const source = "class C {\n  void f(Builder http) {\n    http.csrf().disable();\n  }\n}\n";
    expect((await run(source)).findings).toEqual([]);
  });

  it("judges each filter chain of a file on its own", async () => {
    const source = `${SEC}class C {\n  SecurityFilterChain a(HttpSecurity http) throws Exception {\n    http.csrf(c -> c.disable()).sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)).oauth2ResourceServer(o -> {});\n    return http.build();\n  }\n  SecurityFilterChain b(HttpSecurity http) throws Exception {\n    http.csrf(c -> c.disable()).formLogin();\n    return http.build();\n  }\n}\n`;
    const findings = of((await run(source)).findings, "PG-CSRF-001");
    expect(findings.map((finding) => finding.line)).toEqual([10]);
  });
});

describe("PG-CONF-001: Spring Security misconfiguration", () => {
  const cases: Array<[string, string, string, string]> = [
    [
      "catch-all permitAll",
      "A.java",
      chain("http.authorizeHttpRequests(a -> a.anyRequest().permitAll());"),
      "medium/medium",
    ],
    [
      "/** permitAll",
      "A.java",
      chain('http.authorizeHttpRequests(a -> a.requestMatchers("/**").permitAll());'),
      "medium/medium",
    ],
    [
      "permitAll after restrictive rules: public by default",
      "A.java",
      chain(
        'http.authorizeHttpRequests(a -> a.requestMatchers("/admin").hasRole("A").anyRequest().permitAll());',
      ),
      "medium/low/inferred",
    ],
    [
      "/** permitAll that later rules shadow",
      "A.java",
      chain(
        'http.authorizeHttpRequests(a -> a.requestMatchers("/**").permitAll().anyRequest().authenticated());',
      ),
      "none",
    ],
    [
      "authenticated last",
      "A.java",
      chain("http.authorizeHttpRequests(a -> a.anyRequest().authenticated());"),
      "none",
    ],
    [
      "Kotlin authorize",
      "A.kt",
      kchain("    authorizeHttpRequests { authorize(anyRequest, permitAll) }"),
      "medium/medium",
    ],
    [
      "Kotlin authorize with an earlier restriction",
      "A.kt",
      kchain(
        '    authorizeHttpRequests {\n      authorize("/a", hasRole("A"))\n      authorize(anyRequest, permitAll)\n    }',
      ),
      "medium/low/inferred",
    ],
  ];
  for (const [name, path, source, expected] of cases) {
    it(name, async () => {
      expect(kind(of((await run(source, path)).findings, "PG-CONF-001"))).toBe(expected);
    });
  }

  const web = (call: string, extra = "") =>
    `${SEC}${extra}\nclass W {\n  Object c() {\n    return (Object) (web) -> web.ignoring()${call};\n  }\n}\n`;
  const ignoring: Array<[string, string, string]> = [
    ["static directories are fine", web('.requestMatchers("/css/**", "/js/**")'), "none"],
    ["a file extension pattern is fine", web('.requestMatchers("/**/*.css")'), "none"],
    [
      "the static resources helper is fine",
      web(".requestMatchers(PathRequest.toStaticResources().atCommonLocations())"),
      "none",
    ],
    ["an API path", web('.requestMatchers("/api/**")'), "medium/medium"],
    ["a mix of static and API paths", web('.antMatchers("/css/**", "/api/**")'), "medium/medium"],
    ["every request", web(".anyRequest()"), "medium/medium"],
    [
      "documentation endpoints: low",
      web('.requestMatchers("/swagger-ui/**")'),
      "medium/low/inferred",
    ],
    ["paths that cannot be read: low", web(".requestMatchers(openPaths())"), "medium/low/inferred"],
    [
      "a constant array is resolved",
      `${SEC}class W {\n  static final String[] OPEN = {"/internal/**"};\n  Object c() {\n    return (Object) (web) -> web.ignoring().requestMatchers(OPEN);\n  }\n}\n`,
      "medium/medium",
    ],
  ];
  for (const [name, source, expected] of ignoring) {
    it(`web.ignoring(): ${name}`, async () => {
      expect(kind(of((await run(source)).findings, "PG-CONF-001"))).toBe(expected);
    });
  }

  const cors = (body: string) =>
    `import org.springframework.web.cors.CorsConfiguration;\nimport java.util.List;\nclass K {\n  void f() {\n    CorsConfiguration c = new CorsConfiguration();\n${body}\n  }\n}\n`;
  const corsCases: Array<[string, string, string]> = [
    [
      "origins and credentials",
      cors('c.setAllowedOrigins(List.of("*"));\n c.setAllowCredentials(true);'),
      "medium/medium",
    ],
    [
      "origin pattern and credentials",
      cors('c.addAllowedOriginPattern("*");\n c.setAllowCredentials(true);'),
      "medium/medium",
    ],
    ["no credentials", cors('c.setAllowedOrigins(List.of("*"));'), "none"],
    [
      "credentials false",
      cors('c.setAllowedOrigins(List.of("*"));\n c.setAllowCredentials(false);'),
      "none",
    ],
    [
      "explicit origin",
      cors('c.setAllowedOrigins(List.of("https://a.example"));\n c.setAllowCredentials(true);'),
      "none",
    ],
    [
      "credentials from a variable: low",
      cors('c.setAllowedOrigins(List.of("*"));\n c.setAllowCredentials(flag);'),
      "medium/low/inferred",
    ],
  ];
  for (const [name, source, expected] of corsCases) {
    it(`CORS: ${name}`, async () => {
      expect(kind(of((await run(source)).findings, "PG-CONF-001"))).toBe(expected);
    });
  }

  it("CORS in Kotlin assignments and @CrossOrigin", async () => {
    const assignments =
      'import org.springframework.web.cors.CorsConfiguration\nclass K {\n  fun f() {\n    val c = CorsConfiguration()\n    c.allowedOrigins = listOf("*")\n    c.allowCredentials = true\n  }\n}\n';
    expect(kind(of((await run(assignments, "K.kt")).findings, "PG-CONF-001"))).toBe(
      "medium/medium",
    );
    const annotation =
      'import org.springframework.web.bind.annotation.CrossOrigin\n@CrossOrigin(origins = ["*"], allowCredentials = "true")\nclass K\n';
    expect(kind(of((await run(annotation, "K.kt")).findings, "PG-CONF-001"))).toBe("medium/medium");
    const javaCombined =
      'import org.springframework.web.bind.annotation.*;\n@CrossOrigin(origins = "*")\nclass K {\n  @CrossOrigin(allowCredentials = "true") @GetMapping("/x") void f() {}\n}\n';
    expect(kind(of((await run(javaCombined)).findings, "PG-CONF-001"))).toBe("medium/medium");
    const safe =
      'import org.springframework.web.bind.annotation.*;\n@CrossOrigin(origins = "*")\nclass K {}\n';
    expect((await run(safe)).findings).toEqual([]);
  });

  it("@EnableWebSecurity(debug = true) is low severity", async () => {
    const source =
      "import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;\n@EnableWebSecurity(debug = true)\nclass S {}\n";
    const findings = of((await run(source)).findings, "PG-CONF-001");
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("low");
  });
});

describe("PG-COOKIE-001 in Java and Kotlin", () => {
  const servlet = (body: string) =>
    `import javax.servlet.http.Cookie;\nclass C {\n  void f(HttpServletResponse r, String id, boolean flag) {\n${body}\n  }\n}\n`;
  const cases: Array<[string, string, string]> = [
    ["no flags", servlet('r.addCookie(new Cookie("sessionId", id));'), "medium/medium"],
    [
      "both flags",
      servlet(
        'Cookie c = new Cookie("sid", id);\n c.setHttpOnly(true);\n c.setSecure(true);\n r.addCookie(c);',
      ),
      "none",
    ],
    [
      "secure missing",
      servlet('Cookie c = new Cookie("sid", id);\n c.setHttpOnly(true);\n r.addCookie(c);'),
      "medium/medium",
    ],
    [
      "http-only false",
      servlet(
        'Cookie c = new Cookie("sid", id);\n c.setHttpOnly(false);\n c.setSecure(true);\n r.addCookie(c);',
      ),
      "medium/medium",
    ],
    [
      "flag from a variable",
      servlet(
        'Cookie c = new Cookie("sid", id);\n c.setHttpOnly(true);\n c.setSecure(flag);\n r.addCookie(c);',
      ),
      "medium/low/inferred",
    ],
    [
      "flag set in a branch",
      servlet(
        'Cookie c = new Cookie("sid", id);\n c.setHttpOnly(true);\n if (flag) c.setSecure(true);\n r.addCookie(c);',
      ),
      "medium/low/inferred",
    ],
    [
      "cookie handed to a helper",
      servlet('Cookie c = new Cookie("sid", id);\n harden(c);\n r.addCookie(c);'),
      "medium/low/inferred",
    ],
    ["not a session cookie", servlet('r.addCookie(new Cookie("theme", "dark"));'), "none"],
    [
      "deleted cookie",
      servlet('Cookie c = new Cookie("sid", id);\n c.setMaxAge(0);\n r.addCookie(c);'),
      "none",
    ],
    [
      "a user cookie is only suggested: low",
      servlet('r.addCookie(new Cookie("uid", id));'),
      "medium/low/inferred",
    ],
    [
      "raw header",
      servlet('r.addHeader("Set-Cookie", "sid=" + id + "; Path=/");'),
      "medium/medium",
    ],
    [
      "raw header with flags",
      servlet('r.addHeader("Set-Cookie", "sid=" + id + "; HttpOnly; Secure");'),
      "none",
    ],
  ];
  for (const [name, source, expected] of cases) {
    it(name, async () => {
      expect(kind(of((await run(source)).findings, "PG-COOKIE-001"))).toBe(expected);
    });
  }

  it("Cookie from another library is not judged", async () => {
    const source =
      'import io.ktor.http.Cookie;\nclass C {\n  Cookie f(String id) { return new Cookie("sessionId", id); }\n}\n';
    expect((await run(source)).findings).toEqual([]);
  });

  it("ResponseCookie needs HttpOnly, Secure and SameSite", async () => {
    const response = (chainText: string) =>
      `import org.springframework.http.ResponseCookie;\nclass C {\n  Object f(String id) {\n    return ${chainText};\n  }\n}\n`;
    const none = await run(response('ResponseCookie.from("session", id).build()'));
    expect(kind(of(none.findings, "PG-COOKIE-001"))).toBe("medium/medium");
    const noSameSite = await run(
      response('ResponseCookie.from("session", id).httpOnly(true).secure(true).build()'),
    );
    expect(of(noSameSite.findings, "PG-COOKIE-001")[0]?.evidence).toContain("SameSite not set");
    const all = await run(
      response(
        'ResponseCookie.from("session", id).httpOnly(true).secure(true).sameSite("Lax").build()',
      ),
    );
    expect(all.findings).toEqual([]);
  });

  it("Kotlin properties and apply blocks", async () => {
    const kotlin = (body: string) =>
      `import javax.servlet.http.Cookie\nclass C {\n  fun f(r: HttpServletResponse, id: String) {\n${body}\n  }\n}\n`;
    expect(
      kind(
        of((await run(kotlin('r.addCookie(Cookie("sid", id))'), "C.kt")).findings, "PG-COOKIE-001"),
      ),
    ).toBe("medium/medium");
    expect(
      (
        await run(
          kotlin('r.addCookie(Cookie("sid", id).apply { isHttpOnly = true; secure = true })'),
          "C.kt",
        )
      ).findings,
    ).toEqual([]);
    expect(
      (
        await run(
          kotlin(
            'val c = Cookie("sid", id)\n c.isHttpOnly = true\n c.secure = true\n r.addCookie(c)',
          ),
          "C.kt",
        )
      ).findings,
    ).toEqual([]);
  });

  it("session cookie settings set to false", async () => {
    const serializer = (call: string) =>
      `import org.springframework.session.web.http.DefaultCookieSerializer;\nclass S {\n  void f(DefaultCookieSerializer s) {\n    s.${call};\n  }\n}\n`;
    expect(
      kind(of((await run(serializer("setUseSecureCookie(false)"))).findings, "PG-COOKIE-001")),
    ).toBe("medium/medium");
    expect((await run(serializer("setUseSecureCookie(true)"))).findings).toEqual([]);
  });
});
