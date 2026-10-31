import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, afterEach, describe, expect, it } from "vitest";
import type { RawSourceFinding } from "../finding-factory.js";
import { scanSourceCode } from "../scan-source.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzeJvmTree } from "./analyze-jvm.js";
import { weakCipherReason, isPasswordWord, isSecretContextName } from "./crypto-names.js";
import { TIME_FACTOR, itScaled } from "../../../../tests/support/timing.js";

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

const RULES = ["PG-CRYPTO-001", "PG-CRYPTO-002", "PG-CRYPTO-003", "PG-AUTH-001"] as const;
type Best = "high" | "medium" | "low" | "none";

async function run(source: string, path: string): Promise<RawSourceFinding[]> {
  const language = path.endsWith(".kt") ? "kotlin" : "java";
  const outcome = await runtime.parse(language, source);
  if (outcome.status !== "parsed") throw new Error(`not parsed: ${outcome.status}`);
  try {
    return analyzeJvmTree(outcome.tree.rootNode, source, path, language).findings.filter(
      (finding) => (RULES as readonly string[]).includes(finding.ruleId),
    );
  } finally {
    outcome.dispose();
  }
}

const ORDER: Record<string, number> = { high: 3, medium: 2, low: 1 };
function best(findings: RawSourceFinding[], ruleId: string): Best {
  let top: Best = "none";
  for (const finding of findings) {
    if (finding.ruleId !== ruleId) continue;
    if (top === "none" || (ORDER[finding.confidence] ?? 0) > (ORDER[top] ?? 0)) {
      top = finding.confidence;
    }
  }
  return top;
}

const java = (members: string, imports = ""): string =>
  `import java.security.*;\nimport javax.crypto.*;\nimport javax.crypto.spec.*;\nimport java.util.*;\nimport java.nio.charset.StandardCharsets;\n${imports}\nclass A {\n${members}\n}\n`;
const kotlin = (body: string, imports = ""): string =>
  `import java.security.*\nimport javax.crypto.*\nimport javax.crypto.spec.*\n${imports}\n${body}\n`;

const V = "@org.springframework.beans.factory.annotation.Value";

interface Case {
  name: string;
  source: string;
  path?: string;
  /** Expected best confidence per rule; unlisted rules must stay silent. */
  expect: Partial<Record<(typeof RULES)[number], Best>>;
  evidence?: RegExp;
}

const CASES: Case[] = [
  // ---------------------------------------------------------------- PG-CRYPTO-001
  {
    name: "MD5 digest of a password through update and digest",
    source: java(
      `String h(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(password.getBytes());
        return Arrays.toString(md.digest());
      }`,
    ),
    expect: { "PG-CRYPTO-001": "medium" },
    evidence: /MD5 digest of a password-like value/,
  },
  {
    name: "SHA-1 chained digest of a password getter",
    source: java(
      `byte[] h(User user) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(user.getPassword().getBytes());
      }`,
    ),
    expect: { "PG-CRYPTO-001": "medium" },
  },
  {
    name: "SHA alone is SHA-1",
    source: java(
      `byte[] h(String pwd) throws Exception { return MessageDigest.getInstance("SHA").digest(pwd.getBytes()); }`,
    ),
    expect: { "PG-CRYPTO-001": "medium" },
  },
  {
    name: "algorithm held in a constant",
    source: java(
      `private static final String ALGO = "md5";
      byte[] h(String rawPassword) throws Exception {
        return MessageDigest.getInstance(ALGO).digest(rawPassword.getBytes());
      }`,
    ),
    expect: { "PG-CRYPTO-001": "medium" },
  },
  {
    name: "SHA-256 of a password is not this rule",
    source: java(
      `byte[] h(String password) throws Exception { return MessageDigest.getInstance("SHA-256").digest(password.getBytes()); }`,
    ),
    expect: {},
  },
  {
    name: "MD5 of a non-password value (ETag) is not reported",
    source: java(
      `byte[] etag(byte[] body) throws Exception { return MessageDigest.getInstance("MD5").digest(body); }`,
    ),
    expect: {},
  },
  {
    name: "bypass is not a password word",
    source: java(
      `byte[] h(String bypassKey) throws Exception { return MessageDigest.getInstance("MD5").digest(bypassKey.getBytes()); }`,
    ),
    expect: {},
  },
  {
    name: "weak digest in a password-named method without a visible password is low",
    source: java(
      `byte[] hashPassword(byte[] raw) throws Exception { return MessageDigest.getInstance("MD5").digest(raw); }`,
    ),
    expect: { "PG-CRYPTO-001": "low" },
    evidence: /; inferred$/,
  },
  {
    name: "a helper of the file that digests its parameter, called with a password",
    source: java(
      `static String md5(String s) throws Exception { return new String(MessageDigest.getInstance("MD5").digest(s.getBytes())); }
      String store(String password) throws Exception { return md5(password); }`,
    ),
    expect: { "PG-CRYPTO-001": "medium" },
  },
  {
    name: "Guava md5 of a password",
    source: java(
      `String h(String password) { return com.google.common.hash.Hashing.md5().hashString(password, StandardCharsets.UTF_8).toString(); }`,
    ),
    expect: { "PG-CRYPTO-001": "medium" },
  },
  {
    name: "Commons Codec md5Hex of a password",
    source: java(
      `String h(String password) { return org.apache.commons.codec.digest.DigestUtils.md5Hex(password); }`,
    ),
    expect: { "PG-CRYPTO-001": "medium" },
  },
  {
    name: "Commons Codec sha256Hex of a password is fine",
    source: java(
      `String h(String password) { return org.apache.commons.codec.digest.DigestUtils.sha256Hex(password); }`,
    ),
    expect: {},
  },
  {
    name: "algorithm from config with a weak default is low",
    source: java(
      `@org.springframework.beans.factory.annotation.Value("\${hash.algorithm:MD5}") String alg;
      byte[] h(String password) throws Exception { return MessageDigest.getInstance(alg).digest(password.getBytes()); }`,
    ),
    expect: { "PG-CRYPTO-001": "low" },
  },
  {
    name: "algorithm that is a parameter is not reported",
    source: java(
      `byte[] h(String alg, String password) throws Exception { return MessageDigest.getInstance(alg).digest(password.getBytes()); }`,
    ),
    expect: {},
  },
  {
    name: "Kotlin MD5 of a password",
    path: "A.kt",
    source: kotlin(
      `fun h(password: String): ByteArray = MessageDigest.getInstance("MD5").digest(password.toByteArray())`,
    ),
    expect: { "PG-CRYPTO-001": "medium" },
  },
  // ---------------------------------------------------------------- PG-CRYPTO-002
  {
    name: "SecretKeySpec from a string literal",
    source: java(
      `SecretKey k() { return new SecretKeySpec("0123456789abcdef".getBytes(), "AES"); }`,
    ),
    expect: { "PG-CRYPTO-002": "high" },
    evidence: /string literal \(value redacted\) used as SecretKeySpec key/,
  },
  {
    name: "SecretKeySpec from a literal byte array",
    source: java(
      `SecretKey k() { return new SecretKeySpec(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, "AES"); }`,
    ),
    expect: { "PG-CRYPTO-002": "high" },
    evidence: /byte array literal/,
  },
  {
    name: "key held in a static final constant",
    source: java(
      `private static final String KEY = "constant-key-material";
      SecretKey k() { return new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES"); }`,
    ),
    expect: { "PG-CRYPTO-002": "high" },
    evidence: /held in KEY/,
  },
  {
    name: "key held in a single-assignment local",
    source: java(
      `SecretKey k() { String s = "local-key-material"; return new SecretKeySpec(s.getBytes(), "AES"); }`,
    ),
    expect: { "PG-CRYPTO-002": "high" },
  },
  {
    name: "key from the environment is silent",
    source: java(
      `SecretKey k() { return new SecretKeySpec(System.getenv("APP_KEY").getBytes(), "AES"); }`,
    ),
    expect: {},
  },
  {
    name: "a key filled by SecureRandom is silent",
    source: java(
      `SecretKey k() { byte[] b = new byte[32]; new SecureRandom().nextBytes(b); return new SecretKeySpec(b, "AES"); }`,
    ),
    expect: {},
  },
  {
    name: "an all-zero key is a fixed key",
    source: java(`SecretKey k() { return new SecretKeySpec(new byte[32], "AES"); }`),
    expect: { "PG-CRYPTO-002": "high" },
  },
  {
    name: "an empty literal is not a key",
    source: java(`SecretKey k() { return new SecretKeySpec("".getBytes(), "AES"); }`),
    expect: {},
  },
  {
    name: "JJWT signWith with a literal secret",
    source: java(
      `String t() { return io.jsonwebtoken.Jwts.builder().setSubject("a").signWith(io.jsonwebtoken.SignatureAlgorithm.HS256, "jjwt-literal-secret").compact(); }`,
    ),
    expect: { "PG-CRYPTO-002": "high" },
  },
  {
    name: "Keys.hmacShaKeyFor of a literal",
    source: java(
      `Key k() { return io.jsonwebtoken.security.Keys.hmacShaKeyFor("hmac-literal-secret-0123456789abcdef".getBytes()); }`,
    ),
    expect: { "PG-CRYPTO-002": "high" },
  },
  {
    name: "Auth0 HMAC256 of a literal",
    source: java(
      `Object a() { return com.auth0.jwt.algorithms.Algorithm.HMAC256("auth0-literal-secret"); }`,
    ),
    expect: { "PG-CRYPTO-002": "high" },
  },
  {
    name: "Auth0 HMAC256 of an environment value",
    source: java(
      `Object a() { return com.auth0.jwt.algorithms.Algorithm.HMAC256(System.getenv("JWT_SECRET")); }`,
    ),
    expect: {},
  },
  {
    name: "Spring @Value with a literal default",
    source: java(
      `@org.springframework.beans.factory.annotation.Value("\${jwt.secret:default-secret-value}")
      private String secret;`,
    ),
    expect: { "PG-CRYPTO-002": "low" },
  },
  {
    name: "Spring @Value default read at a key API is reported once, at the API",
    source: java(
      `@org.springframework.beans.factory.annotation.Value("\${jwt.secret:default-secret-value}")
      private String secret;
      Object a() { return com.auth0.jwt.algorithms.Algorithm.HMAC256(secret); }`,
    ),
    expect: { "PG-CRYPTO-002": "medium" },
    evidence: /default value in source/,
  },
  {
    name: "Spring @Value without a default or with an empty default",
    source: java(
      `@org.springframework.beans.factory.annotation.Value("\${jwt.secret}") String a;
      @org.springframework.beans.factory.annotation.Value("\${jwt.secret:}") String b;`,
    ),
    expect: {},
  },
  {
    name: "Spring @Value default of something that is not a key",
    source: java(
      `@org.springframework.beans.factory.annotation.Value("\${server.port:8080}") int port;
      @org.springframework.beans.factory.annotation.Value("\${cache.key-prefix:app}") String prefix;
      @org.springframework.beans.factory.annotation.Value("\${jwt.public-key:classpath:pub.pem}") String pub;`,
    ),
    expect: {},
  },
  {
    name: "a literal reassigned elsewhere is low",
    source: java(
      `SecretKey k(boolean prod) {
        String s = "dev-key-material";
        if (prod) s = System.getenv("APP_KEY");
        return new SecretKeySpec(s.getBytes(), "AES");
      }`,
    ),
    expect: { "PG-CRYPTO-002": "low" },
    evidence: /; inferred$/,
  },
  {
    name: "Kotlin const val key",
    path: "A.kt",
    source: kotlin(
      `object K { const val SECRET = "kotlin-const-secret" }
      fun k() = SecretKeySpec(K.SECRET.toByteArray(), "AES")`,
    ),
    expect: { "PG-CRYPTO-002": "high" },
  },
  {
    name: "Kotlin @Value constructor parameter with a default",
    path: "A.kt",
    source: kotlin(
      `class S(@Value("\\\${app.signing-key:dev-signing-key}") val key: String)`,
      "import org.springframework.beans.factory.annotation.Value",
    ),
    expect: { "PG-CRYPTO-002": "low" },
  },
  {
    name: "Kotlin elvis fallback to a literal",
    path: "A.kt",
    source: kotlin(
      `fun k() = io.jsonwebtoken.security.Keys.hmacShaKeyFor((System.getenv("K") ?: "fallback-secret-0123456789abcdef0123").toByteArray())`,
    ),
    expect: { "PG-CRYPTO-002": "medium" },
  },
  // ---------------------------------------------------------------- PG-CRYPTO-003
  {
    name: "DES",
    source: java(
      `Cipher c() throws Exception { return Cipher.getInstance("DES/CBC/PKCS5Padding"); }`,
    ),
    expect: { "PG-CRYPTO-003": "high" },
    evidence: /DES cipher/,
  },
  {
    name: "bare AES means ECB",
    source: java(`Cipher c() throws Exception { return Cipher.getInstance("AES"); }`),
    expect: { "PG-CRYPTO-003": "high" },
    evidence: /ECB/,
  },
  {
    name: "AES/ECB",
    source: java(
      `Cipher c() throws Exception { return Cipher.getInstance("AES/ECB/PKCS5Padding"); }`,
    ),
    expect: { "PG-CRYPTO-003": "high" },
  },
  {
    name: "AES/GCM is fine",
    source: java(`Cipher c() throws Exception { return Cipher.getInstance("AES/GCM/NoPadding"); }`),
    expect: {},
  },
  {
    name: "RSA/ECB/PKCS1Padding is not block ECB",
    source: java(
      `Cipher c() throws Exception { return Cipher.getInstance("RSA/ECB/PKCS1Padding"); }`,
    ),
    expect: {},
  },
  {
    name: "algorithm held in a constant",
    source: java(
      `private static final String ALG = "RC4";
      Cipher c() throws Exception { return Cipher.getInstance(ALG); }`,
    ),
    expect: { "PG-CRYPTO-003": "high" },
  },
  {
    name: "algorithm that is not a literal stays silent",
    source: java(`Cipher c(String alg) throws Exception { return Cipher.getInstance(alg); }`),
    expect: {},
  },
  {
    name: "algorithm from config with a weak default is low and not fixed",
    source: java(
      `@org.springframework.beans.factory.annotation.Value("\${crypto.cipher:DES}") String alg;
      Cipher c() throws Exception { return Cipher.getInstance(alg); }`,
    ),
    expect: { "PG-CRYPTO-003": "low" },
    evidence: /algorithm not fixed; inferred/,
  },
  {
    name: "algorithm from config with a strong default is silent",
    source: java(
      `@org.springframework.beans.factory.annotation.Value("\${crypto.cipher:AES/GCM/NoPadding}") String alg;
      Cipher c() throws Exception { return Cipher.getInstance(alg); }`,
    ),
    expect: {},
  },
  {
    name: "fixed IV from a literal",
    source: java(
      `IvParameterSpec iv() { return new IvParameterSpec("1234567890123456".getBytes()); }`,
    ),
    expect: { "PG-CRYPTO-003": "high" },
    evidence: /fixed IV/,
  },
  {
    name: "zero IV",
    source: java(`IvParameterSpec iv() { return new IvParameterSpec(new byte[16]); }`),
    expect: { "PG-CRYPTO-003": "high" },
  },
  {
    name: "GCM with a literal nonce",
    source: java(
      `GCMParameterSpec g() { return new GCMParameterSpec(128, "fixed-nonce".getBytes()); }`,
    ),
    expect: { "PG-CRYPTO-003": "high" },
  },
  {
    name: "random IV written by SecureRandom is fine",
    source: java(
      `IvParameterSpec iv() { byte[] b = new byte[16]; new SecureRandom().nextBytes(b); return new IvParameterSpec(b); }`,
    ),
    expect: {},
  },
  {
    name: "IV read from the ciphertext is fine",
    source: java(
      `IvParameterSpec iv(java.io.InputStream in) throws Exception { byte[] b = new byte[16]; in.read(b); return new IvParameterSpec(b); }`,
    ),
    expect: {},
  },
  {
    name: "IV from java.util.Random",
    source: java(
      `IvParameterSpec iv() { byte[] b = new byte[16]; new Random().nextBytes(b); return new IvParameterSpec(b); }`,
    ),
    expect: { "PG-CRYPTO-003": "medium" },
  },
  {
    name: "key bytes from a Random field",
    source: java(
      `private static final Random RND = new Random();
      SecretKey k() { byte[] b = new byte[16]; RND.nextBytes(b); return new SecretKeySpec(b, "AES"); }`,
    ),
    expect: { "PG-CRYPTO-003": "medium" },
  },
  {
    name: "reset token from Random is a name-only match (low)",
    source: java(
      `String t() { String resetToken = String.valueOf(new Random().nextInt()); return resetToken; }`,
    ),
    expect: { "PG-CRYPTO-003": "low" },
    evidence: /; inferred$/,
  },
  {
    name: "Math.random for a token",
    source: java(
      `String make() { String token = Long.toHexString((long) (Math.random() * 1e15)); return token; }`,
    ),
    expect: { "PG-CRYPTO-003": "low" },
  },
  {
    name: "a method named for a token that returns a Random value",
    source: java(`String generateToken() { return Integer.toHexString(new Random().nextInt()); }`),
    expect: { "PG-CRYPTO-003": "low" },
  },
  {
    name: "SecureRandom token is fine",
    source: java(
      `String generateToken() { byte[] b = new byte[32]; new SecureRandom().nextBytes(b); return Base64.getEncoder().encodeToString(b); }`,
    ),
    expect: {},
  },
  {
    name: "Random used to pick an element is not reported",
    source: java(
      `String pick(List<String> xs) { return xs.get(new Random().nextInt(xs.size())); }
      long jitter() { return ThreadLocalRandom.current().nextLong(100); }
      double sample() { return Math.random(); }`,
    ),
    expect: {},
  },
  {
    name: "UUID is fine",
    source: java(`String t() { String token = UUID.randomUUID().toString(); return token; }`),
    expect: {},
  },
  {
    name: "Kotlin AES/ECB and a zero IV",
    path: "A.kt",
    source: kotlin(
      `fun c() = Cipher.getInstance("AES/ECB/PKCS5Padding")
      fun iv() = IvParameterSpec(ByteArray(16))`,
    ),
    expect: { "PG-CRYPTO-003": "high" },
  },
  {
    name: "Kotlin Random token",
    path: "A.kt",
    source: kotlin(
      `import kotlin.random.Random
      fun make(): String { val token = Random.nextInt().toString(); return token }`,
    ),
    expect: { "PG-CRYPTO-003": "low" },
  },
  // ---------------------------------------------------------------- PG-AUTH-001
  {
    name: "request DTO password to an entity then save",
    source: java(
      `void signup(@org.springframework.web.bind.annotation.RequestBody SignupRequest dto, UserRepository userRepository) {
        User user = new User();
        user.setEmail(dto.getEmail());
        user.setPassword(dto.getPassword());
        userRepository.save(user);
      }`,
    ),
    expect: { "PG-AUTH-001": "medium" },
  },
  {
    name: "hashed with an encoder before save",
    source: java(
      `void signup(@org.springframework.web.bind.annotation.RequestBody SignupRequest dto, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        User user = new User();
        user.setPassword(passwordEncoder.encode(dto.getPassword()));
        userRepository.save(user);
      }`,
    ),
    expect: {},
  },
  {
    name: "constructor and save in one call",
    source: java(
      `void signup(SignupRequest req, UserRepository userRepository) {
        userRepository.save(new User(req.getEmail(), req.getPassword()));
      }`,
    ),
    expect: { "PG-AUTH-001": "medium" },
  },
  {
    name: "a plain password parameter that is not read from a request is low",
    source: java(
      `void register(String email, String password, UserRepository repo) {
        User u = new User();
        u.setPassword(password);
        repo.save(u);
      }`,
    ),
    expect: { "PG-AUTH-001": "low" },
    evidence: /; inferred$/,
  },
  {
    name: "servlet parameter to a JDBC insert",
    source: java(
      `void add(javax.servlet.http.HttpServletRequest request, org.springframework.jdbc.core.JdbcTemplate jdbcTemplate) {
        String pw = request.getParameter("password");
        jdbcTemplate.update("INSERT INTO users (email, password) VALUES (?, ?)", "a@b.c", pw);
      }`,
    ),
    expect: { "PG-AUTH-001": "medium" },
  },
  {
    name: "JDBC insert of an email only",
    source: java(
      `void add(SignupRequest dto, org.springframework.jdbc.core.JdbcTemplate jdbcTemplate) {
        jdbcTemplate.update("INSERT INTO users (email) VALUES (?)", dto.getEmail());
      }`,
    ),
    expect: {},
  },
  {
    name: "setPassword without a save",
    source: java(
      `void f(SignupRequest dto) { User u = new User(); u.setPassword(dto.getPassword()); }`,
    ),
    expect: {},
  },
  {
    name: "a hash value from a DTO",
    source: java(
      `void f(SignupRequest dto, UserRepository repo) { User u = new User(); u.setPassword(dto.getPasswordHash()); repo.save(u); }`,
    ),
    expect: {},
  },
  {
    name: "NoOpPasswordEncoder",
    source: java(
      `PasswordEncoder e() { return org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance(); }`,
    ),
    expect: { "PG-AUTH-001": "high" },
  },
  {
    name: "Kotlin property assignment then save",
    path: "A.kt",
    source: kotlin(
      `fun signup(req: SignupRequest, userRepository: UserRepository) {
        val user = User()
        user.password = req.password
        userRepository.save(user)
      }`,
    ),
    expect: { "PG-AUTH-001": "medium" },
  },
  {
    name: "Kotlin named-argument constructor",
    path: "A.kt",
    source: kotlin(
      `fun signup(req: SignupRequest, userRepository: UserRepository) {
        userRepository.save(User(email = req.email, password = req.password))
      }`,
    ),
    expect: { "PG-AUTH-001": "medium" },
  },
  // ---------------------------------------------------------------- review round
  {
    name: "name-only @Value defaults of non-secrets are silent",
    source: java(
      `${V}("\${cache.key:users}") String a;
      ${V}("\${stripe.publishable-key:pk_test_123}") String b;
      ${V}("\${recaptcha.site-key:6Lc_test}") String c;
      ${V}("\${app.sort.key:createdAt}") String d;`,
    ),
    expect: {},
  },
  {
    name: "name-only @Value defaults of hmac and signing keys are low",
    source: java(
      `${V}("\${app.hmac.key:dev-hmac-material}") String a;
      ${V}("\${jwt.signing-key:dev-signing-material}") String b;
      ${V}("\${jwt.key:dev-key-material-x}") String c;`,
    ),
    expect: { "PG-CRYPTO-002": "low" },
    evidence: /; inferred$/,
  },
  {
    name: "a password property default is low",
    source: java(`${V}("\${jasypt.encryptor.password:changeit-value}") String p;`),
    expect: { "PG-CRYPTO-002": "low" },
  },
  {
    name: "a nested placeholder without a default is silent",
    source: java(`${V}("\${jwt.secret:\${JWT_SECRET}}") String s;`),
    expect: {},
  },
  {
    name: "a non-final field with a literal is medium, and low when written elsewhere",
    source: java(
      `private String secret = "non-final-field-material";
      Object a() { return com.auth0.jwt.algorithms.Algorithm.HMAC256(secret); }`,
    ),
    expect: { "PG-CRYPTO-002": "medium" },
    evidence: /non-final field secret/,
  },
  {
    name: "a non-final field overwritten elsewhere is low",
    source: java(
      `private String secret = "non-final-field-material";
      void load(String s) { this.secret = s; }
      Object a() { return com.auth0.jwt.algorithms.Algorithm.HMAC256(secret); }`,
    ),
    expect: { "PG-CRYPTO-002": "low" },
  },
  {
    name: "deprecated Spring password encoders",
    source: java(
      `Object a() { return new org.springframework.security.crypto.password.StandardPasswordEncoder("x"); }
      Object b() { return new MessageDigestPasswordEncoder("SHA-256"); }`,
    ),
    expect: { "PG-CRYPTO-001": "high" },
  },
  {
    name: "Shiro setCipherKey with a literal",
    source: java(
      `void f(org.apache.shiro.web.mgt.CookieRememberMeManager m) { m.setCipherKey("shiro-literal-cipher-key".getBytes()); }`,
    ),
    expect: { "PG-CRYPTO-002": "high" },
  },
  {
    name: "encoder.matches is not a hash call",
    source: java(
      `void f(SignupRequest dto, UserRepository repo, PasswordEncoder encoder, User u) {
        if (encoder.matches("a", "b")) return;
        u.setPassword(dto.getPassword());
        repo.save(u);
      }`,
    ),
    expect: { "PG-AUTH-001": "medium" },
  },
  {
    name: "a free hashPassword helper counts as hashing",
    source: java(
      `void f(SignupRequest dto, UserRepository repo, User u) {
        u.setPassword(hashPassword(dto.getPassword()));
        repo.save(u);
      }
      String hashPassword(String raw) { return raw; }`,
    ),
    expect: {},
  },
  {
    name: "NoOpPasswordEncoder through the constructor and getInstance, Java and Kotlin",
    source: java(
      `Object a() { return new NoOpPasswordEncoder(); }
      Object b() { return NoOpPasswordEncoder.getInstance(); }`,
    ),
    expect: { "PG-AUTH-001": "high" },
  },
  {
    name: "Kotlin NoOpPasswordEncoder",
    path: "A.kt",
    source: kotlin(`fun e() = NoOpPasswordEncoder.getInstance()`),
    expect: { "PG-AUTH-001": "high" },
  },
  {
    name: "Kotlin apply block sets the password, then save",
    path: "A.kt",
    source: kotlin(
      `fun signup(req: SignupRequest, repo: UserRepository) {
        val user = User().apply { password = req.password }
        repo.save(user)
      }`,
    ),
    expect: { "PG-AUTH-001": "medium" },
  },
  {
    name: "Kotlin apply block with this.password inline in save",
    path: "A.kt",
    source: kotlin(
      `fun signup(password: String, repo: UserRepository) {
        repo.save(User().apply { this.password = password })
      }`,
    ),
    expect: { "PG-AUTH-001": "low" },
  },
  {
    name: "a bare jwt.key default is low by name alone",
    source: java(`${V}("\${jwt.key:dev-key-material-x}") String c;`),
    expect: { "PG-CRYPTO-002": "low" },
  },
  {
    name: "an IV from a literal @Value default is medium, not high",
    source: java(
      `${V}("\${app.iv:fixed-iv-0123456}") String iv;
      IvParameterSpec spec() { return new IvParameterSpec(iv.getBytes()); }`,
    ),
    expect: { "PG-CRYPTO-003": "medium" },
  },
  {
    name: "an IV from a non-final field is medium",
    source: java(
      `private byte[] iv = "fixed-iv-0123456".getBytes();
      IvParameterSpec spec() { return new IvParameterSpec(iv); }`,
    ),
    expect: { "PG-CRYPTO-003": "medium" },
  },
  {
    name: "a deprecated encoder with a Spring Security import is high",
    source: java(
      `Object a() { return new StandardPasswordEncoder("x"); }`,
      "import org.springframework.security.crypto.password.StandardPasswordEncoder;",
    ),
    expect: { "PG-CRYPTO-001": "high" },
  },
  {
    name: "a deprecated encoder name without a Spring Security import is low",
    source: java(`Object a() { return new Md5PasswordEncoder(); }`),
    expect: { "PG-CRYPTO-001": "low" },
    evidence: /; inferred$/,
  },
  {
    name: "Kotlin apply with a setPassword call, then save",
    path: "A.kt",
    source: kotlin(
      `fun signup(password: String, repo: UserRepository) {
        val user = User().apply { setPassword(password) }
        repo.save(user)
      }`,
    ),
    expect: { "PG-AUTH-001": "low" },
  },
  {
    name: "Kotlin with(u) block sets this.password, then save",
    path: "A.kt",
    source: kotlin(
      `fun signup(req: SignupRequest, u: User, repo: UserRepository) {
        with(u) { this.password = req.password }
        repo.save(u)
      }`,
    ),
    expect: { "PG-AUTH-001": "medium" },
  },
  {
    name: "Kotlin u.apply block as a statement, then save",
    path: "A.kt",
    source: kotlin(
      `fun signup(password: String, u: User, repo: UserRepository) {
        u.apply { this.password = password }
        repo.save(u)
      }`,
    ),
    expect: { "PG-AUTH-001": "low" },
  },
];

describe("cryptography rules on the JVM engine", () => {
  for (const testCase of CASES) {
    it(testCase.name, async () => {
      const path = testCase.path ?? "A.java";
      const findings = await run(testCase.source, path);
      for (const rule of RULES) {
        expect({ rule, confidence: best(findings, rule) }).toEqual({
          rule,
          confidence: testCase.expect[rule] ?? "none",
        });
      }
      if (testCase.evidence !== undefined) {
        expect(findings.map((finding) => finding.evidence).join("\n")).toMatch(testCase.evidence);
      }
      for (const finding of findings) {
        if (finding.confidence === "low") expect(finding.severity).not.toBe("high");
        // Literal values are never copied into evidence.
        expect(finding.evidence).not.toMatch(/0123456789abcdef|literal-secret|dev-key-material/);
      }
    });
  }
});

describe("name helpers", () => {
  it("reads weak cipher names", () => {
    expect(weakCipherReason("DESede/CBC/PKCS5Padding", true)).toMatch(/DESede/);
    expect(weakCipherReason("AES", true)).toMatch(/ECB/);
    expect(weakCipherReason("AES", false)).toBeNull();
    expect(weakCipherReason("AES/CBC/PKCS5Padding", true)).toBeNull();
    expect(weakCipherReason("PBEWithMD5AndDES", true)).not.toBeNull();
    expect(weakCipherReason("RSA/ECB/OAEPPadding", true)).toBeNull();
  });
  it("splits names into words", () => {
    expect(isPasswordWord("getPassword")).toBe(true);
    expect(isPasswordWord("new_pwd")).toBe(true);
    expect(isPasswordWord("bypassCache")).toBe(false);
    expect(isSecretContextName("resetToken")).toBe(true);
    expect(isSecretContextName("iv")).toBe(true);
    expect(isSecretContextName("five")).toBe(false);
    expect(isSecretContextName("cacheKey")).toBe(false);
  });
});

describe("robustness", () => {
  it("a 5000-term literal concatenation does not overflow or slow the analysis", async () => {
    const chain = Array.from({ length: 5000 }, () => '"a"').join(" + ");
    const source = java(
      `SecretKey k() { String s = ${chain}; return new SecretKeySpec(s.getBytes(), "AES"); }`,
    );
    const started = Date.now();
    const findings = await run(source, "A.java");
    expect(Date.now() - started).toBeLessThan(3000 * TIME_FACTOR);
    expect(best(findings, "PG-CRYPTO-002")).toBe("none");
  });

  itScaled(
    "many methods stay linear",
    async () => {
      const methods = Array.from(
        { length: 1500 },
        (_, index) =>
          `byte[] m${index}(String password) throws Exception { return MessageDigest.getInstance("SHA-256").digest(password.getBytes()); }`,
      ).join("\n");
      const started = Date.now();
      const findings = await run(java(methods), "A.java");
      expect(Date.now() - started).toBeLessThan(4000 * TIME_FACTOR);
      expect(findings).toEqual([]);
    },
    10_000,
  );

  it("evidence never carries the literal", async () => {
    const findings = await run(
      java(
        `SecretKey k() { return new SecretKeySpec("zz-secret-material-zz".getBytes(), "AES"); }`,
      ),
      "A.java",
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).not.toContain("zz-secret-material-zz");
  });
});

describe("coverage", () => {
  const roots: string[] = [];
  afterEach(() => {
    for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
  });
  const scan = async (file: string, source: string) => {
    const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-crypto-")));
    roots.push(root);
    writeFileSync(path.join(root, file), source);
    return scanSourceCode(root);
  };

  it("lists the four rules for Java and finds a weak cipher through the scan", async () => {
    const output = await scan(
      "A.java",
      java(`Cipher c() throws Exception { return Cipher.getInstance("DES"); }`),
    );
    const area = output.coverage.find((item) => item.area === "source:java");
    expect(area?.ruleIds).toEqual(
      expect.arrayContaining(["PG-CRYPTO-001", "PG-CRYPTO-002", "PG-CRYPTO-003", "PG-AUTH-001"]),
    );
    expect(area?.status).toBe("completed");
    expect(output.findings.map((finding) => finding.ruleId)).toContain("PG-CRYPTO-003");
  });

  it("a cryptography call in an anonymous class makes the area partial", async () => {
    const output = await scan(
      "A.java",
      java(
        `Runnable r = new Runnable() { public void run() { try { Cipher.getInstance("DES"); } catch (Exception e) {} } };`,
      ),
    );
    const area = output.coverage.find((item) => item.area === "source:java");
    expect(area?.status).toBe("partial");
    expect(area?.note).toContain("cryptography calls inside anonymous class");
  });

  it("Bouncy Castle adds a partial crypto area", async () => {
    const output = await scan(
      "A.java",
      "import org.bouncycastle.crypto.engines.AESEngine;\nclass A { Object e = new AESEngine(); }\n",
    );
    const area = output.coverage.find((item) => item.area === "source:crypto:bouncy-castle");
    expect(area?.status).toBe("partial");
    expect(area?.ruleIds).toContain("PG-CRYPTO-003");
  });

  it("a Kotlin file is analyzed too", async () => {
    const output = await scan(
      "A.kt",
      kotlin(`fun c(): Cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")`),
    );
    expect(output.findings.map((finding) => finding.ruleId)).toContain("PG-CRYPTO-003");
  });

  it("a Bouncy Castle provider registration keeps the area completed", async () => {
    const output = await scan(
      "A.java",
      'import org.bouncycastle.jce.provider.BouncyCastleProvider;\nimport java.security.*;\nimport javax.crypto.*;\nclass A { void f() throws Exception { Security.addProvider(new BouncyCastleProvider()); Cipher.getInstance("AES/GCM/NoPadding"); } }\n',
    );
    expect(
      output.coverage.find((item) => item.area === "source:crypto:bouncy-castle"),
    ).toBeUndefined();
    expect(output.coverage.find((item) => item.area === "source:java")?.status).toBe("completed");
  });

  it("setPassword from the environment or a Random in a Comparator is not a partial form", async () => {
    const output = await scan(
      "A.java",
      java(
        `Object a(User u) { return new Runnable() { public void run() { u.setPassword(System.getenv("P")); } }; }
        Object b() { return new Comparator<String>() { public int compare(String x, String y) { return new Random().nextInt(3) - 1; } }; }`,
      ),
    );
    expect(output.coverage.find((item) => item.area === "source:java")?.status).toBe("completed");
  });

  it("a cryptography call in a Kotlin anonymous object makes the area partial", async () => {
    const output = await scan(
      "A.kt",
      kotlin(`val r = object : Runnable { override fun run() { Cipher.getInstance("DES") } }`),
    );
    expect(output.coverage.find((item) => item.area === "source:kotlin")?.status).toBe("partial");
  });
});
