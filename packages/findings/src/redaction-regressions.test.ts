/**
 * Every leak found in review is pinned here so a future change to the redaction rules cannot
 * silently reopen it. Add new cases; do not remove old ones. Fake values are assembled at
 * runtime so nothing secret-looking is committed.
 */
import { describe, expect, it } from "vitest";
import type { Finding } from "./contract.js";
import { capText, redactEvidence, redactFinding, redactSecrets } from "./redact.js";

const join = (...parts: string[]) => parts.join("");
const GH = join("ghp", "_", "Rg9", "Q".repeat(15), "x7Z", "k".repeat(15));

/** [issue, input, fragment that must not survive] */
const SECRET_LEAKS: [string, string, string][] = [
  ["#51 .env", "DB_PASSWORD=SuperSecret123", "SuperSecret123"],
  ["#51 yaml", "password: hunter2", "hunter2"],
  ["#51 yaml api key", "api_key: abcdef123456XYZ", "abcdef123456XYZ"],
  ["#51 query string", "/cb?code=1&access_token=abc123def456", "abc123def456"],
  ["#51 dotted", "SESSION_SECRET=foo.bar.baz123", "foo.bar.baz123"],
  ["#51 dotted 2", "DB_PASSWORD=hunter2.prod", "hunter2.prod"],
  ["#51 unbalanced call", "password=abc(def", "abc(def"],
  ["#52 spaces", 'password: "correct horse battery"', "correct horse battery"],
  ["#52 separators", 'password = "abc,def;ghi"', "abc,def;ghi"],
  ["#52 unterminated", 'password = "half open value', "half open value"],
  ["#56 password with @", "https://user:p@ss@host.example/x", "p@ss"],
  ["#56 password with /", "https://user:pa/ss@host.example", "pa/ss"],
  ["#56 token as user", "https://tok3nvalue@github.com/o/r.git", "tok3nvalue"],
  ["#56 json cookie", '{"cookie":"sid=abc123secret"}', "abc123secret"],
  ["#57 underscore suffix", `${GH}_backup`, GH],
  ["#57 underscore prefix", `x_${GH}`, GH],
  [
    "#57 lowercase bearer sk-",
    `authorization: bearer ${join("sk-", "proj-", "e".repeat(30))}`,
    join("sk-", "proj-"),
  ],
  ["#57 zero width", join("AKIA", "\u200b", "IOSFODNN7", "EXAMPLE"), "IOSFODNN7"],
  [
    "#69 JSON-escaped PEM",
    `{"key": "${join("-----BEGIN RSA ", "PRIVATE KEY-----")}\\n${join("MIIEowIBAAKC", "y".repeat(40))}"}`,
    "MIIEowIBAAKC",
  ],
  ["#70 call with literal arg", "password=Secret(123)", "Secret(123)"],
  ["#94 parenthesized", "password=(hunter2)", "hunter2"],
  ["#94 parenthesized yaml", "token: (abc123xyz)", "abc123xyz"],
  ["#94 parens inside", "password=p(a)ssw0rd", "ssw0rd"],
  ["#94 leading paren", "DB_PASSWORD=)s3cr3tValue", "s3cr3tValue"],
  ["#94 paren in middle", "api_key=k3y)tail", "tail"],
  [
    "pin: plain JWT",
    `auth ${join("eyJhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", ".", "SflKxwRJSMeKKF2QT4fwpM")}`,
    "SflKxwRJSMeKKF2QT4fwpM",
  ],
  [
    "pin: github_pat_",
    `token ${join("github", "_pat_", "11ABCDEFG", "0".repeat(20))}`,
    "11ABCDEFG",
  ],
  [
    "pin: multiline PEM with END",
    join(
      "-----BEGIN ",
      "PRIVATE KEY-----\n",
      "MIIEvQIBADANBgkqhkiG9w0",
      "\nabcDEF\n-----END ",
      "PRIVATE KEY-----",
    ),
    "MIIEvQIBADANBgkqhkiG9w0",
  ],
  ["pin: Cookie header", "Cookie: sid=s3ssionValue; theme=dark", "s3ssionValue"],
  ["pin: Set-Cookie header", "Set-Cookie: sid=s3ssionValue; HttpOnly", "s3ssionValue"],
  ["pin: single-quoted value", "secret='two words here'", "two words"],
  ["pin: backtick value", "password = `tick value 9`", "tick value"],
];

describe("redaction regressions", () => {
  it.each(SECRET_LEAKS)("%s stays masked", (_issue, input, fragment) => {
    expect(redactSecrets(input)).not.toContain(fragment);
    expect(redactEvidence(input)).not.toContain(fragment);
  });

  it("#53/#54 location fields and JSON never carry secrets or absolute paths", () => {
    const finding: Finding = {
      id: "x",
      ruleId: "R",
      title: "t",
      category: "secret_exposure",
      severity: "high",
      status: "confirmed",
      confidence: "high",
      location: {
        kind: "url",
        path: `keys/${GH}.pem`,
        line: null,
        url: "file:///Users/jaden/app/x?password=hunter2",
        commit: null,
      },
      evidence: "e",
      impact: "i",
      recommendation: "r",
      references: { cwe: [], owasp: [], cve: [] },
      sources: ["code"],
    };
    const json = JSON.stringify(redactFinding(finding));
    for (const fragment of [GH, "jaden", "hunter2"]) expect(json).not.toContain(fragment);
  });

  it("#55 adversarial input stays fast", () => {
    const start = performance.now();
    redactEvidence(`${"a".repeat(100_000)}://`);
    redactEvidence("x_password_".repeat(20_000));
    expect(performance.now() - start).toBeLessThan(500);
  });

  it("#59 absolute paths outside the project are masked", () => {
    for (const input of [
      "/opt/app/secrets/key.pem",
      "/private/tmp/build/x.log",
      "C:\\proj\\src\\a.ts",
    ]) {
      expect(redactEvidence(`read ${input}`)).toContain("<absolute-path>");
    }
  });

  it.each([
    ["/tmp/dump.sql,", "dump.sql"],
    ["(/tmp/dump.sql)", "dump.sql"],
    ["/etc/shadow", "shadow"],
    ["/root/.ssh", ".ssh"],
    ["/srv/app", "/srv/app"],
    ["/opt/secretproduct", "secretproduct"],
    ["/var/log/", "/var/log"],
    ["/code/x", "/code/x"],
    ["/opt/acme,inc/secrets/key.pem", "inc/secrets"],
    ["/srv/app;v2/config.yml", "v2/config"],
    ["/data/exports/a)b/report.csv", "report.csv"],
    ["C:\\acme,inc\\keys\\id.pem", "inc"],
    ["\\\\fileserver\\share,x\\secrets.txt", "secrets"],
    ["at /app/server.js:10:5", "server.js"],
  ])("#95 masks the filesystem path %s", (input, fragment) => {
    const output = redactEvidence(`see ${input} here`);
    expect(output).not.toContain(fragment);
    expect(output).toContain("<absolute-path>");
  });

  it.each([
    "POST /data/export",
    "GET /run/jobs",
    "/dev/tools",
    "probe /sys/health",
    "GET /app/settings",
  ])("#71/#95 keeps the short route %s", (text) => {
    expect(redactEvidence(text)).toBe(text);
  });

  it("#96 cutting never keeps a URL password prefix", () => {
    expect(capText("https://user:pa$$w0rd@host/x", 18)).not.toContain("pa$");
  });

  it("#96 only environment getters may take a string argument", () => {
    expect(redactSecrets('password=decode("HUNTER2PROD")')).not.toContain("HUNTER2PROD");
    expect(redactSecrets('password = os.getenv("DB_PASSWORD")')).toBe(
      'password = os.getenv("DB_PASSWORD")',
    );
  });

  it("#60 cut points never leave a partial token", () => {
    const token = join("ghp", "_", "w".repeat(36));
    expect(capText(`${"a;".repeat(2047)}x=${token};`, 4100)).not.toContain("ghp_w");
  });
});
