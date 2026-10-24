import { describe, expect, it } from "vitest";
import type { Finding } from "./contract.js";
import {
  createSessionSecretLabeler,
  redactEvidence,
  redactFinding,
  redactSecrets,
} from "./redact.js";

// Fake values assembled at runtime so no literal secret-looking string is committed.
const join = (...parts: string[]) => parts.join("");
const FAKE = {
  aws: join("AKIA", "IOSFODNN7", "EXAMPLE"),
  github: join("ghp", "_", "a".repeat(36)),
  githubPat: join("github", "_pat_", "B".repeat(30)),
  slack: join("xox", "b-", "1234567890-abcdefghij"),
  stripe: join("sk", "_live_", "c".repeat(24)),
  google: join("AI", "za", "d".repeat(35)),
  jwt: join("eyJ", "hbGciOiJIUzI1", ".", "eyJzdWIiOiIxMjM0", ".", "SflKxwRJSMeKKF2QT4"),
  password: join("hunter", "2-super-", "secret"),
  pemBody: join("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", "fakefakefake"),
};

describe("redactSecrets", () => {
  it.each([
    ["aws", `key ${FAKE.aws} here`, FAKE.aws, "aws_access_key_id"],
    ["github", `token=${FAKE.github}`, FAKE.github, "github_token"],
    ["github pat", `use ${FAKE.githubPat}`, FAKE.githubPat, "github_token"],
    ["slack", `hook ${FAKE.slack}`, FAKE.slack, "slack_token"],
    ["stripe", `stripe ${FAKE.stripe}`, FAKE.stripe, "stripe_key"],
    ["google", `g ${FAKE.google}`, FAKE.google, "google_api_key"],
    ["jwt", `jwt ${FAKE.jwt}`, FAKE.jwt, "jwt"],
    ["bearer", `Authorization: Bearer ${FAKE.password}`, FAKE.password, "token"],
    ["url creds", `postgres://admin:${FAKE.password}@db/app`, FAKE.password, "credentials"],
    ["cookie", `Cookie: sid=${FAKE.password}; theme=dark`, FAKE.password, "cookie"],
    ["assignment", `DB_PASSWORD="${FAKE.password}"`, FAKE.password, "value"],
    ["yaml", `api_key: ${FAKE.password}`, FAKE.password, "value"],
  ])("masks %s", (_label, input, secret, kind) => {
    const output = redactSecrets(input);
    expect(output).not.toContain(secret);
    expect(output).toContain(`[REDACTED:${kind}]`);
  });

  it("masks private key blocks entirely", () => {
    const pem = join(
      "-----BEGIN ",
      "PRIVATE KEY-----\n",
      FAKE.pemBody,
      "\n-----END ",
      "PRIVATE KEY-----",
    );
    const output = redactSecrets(`key:\n${pem}\nafter`);
    expect(output).not.toContain(FAKE.pemBody);
    expect(output).toContain("[REDACTED:private_key]");
    expect(output).toContain("after");
  });

  it.each([
    [".env", "DB_PASSWORD=SuperSecret123", "SuperSecret123"],
    ["yaml", "password: hunter2", "hunter2"],
    ["yaml api key", "api_key: abcdef123456XYZ", "abcdef123456XYZ"],
    ["query string", "GET /cb?code=1&access_token=abc123def456", "abc123def456"],
    ["query string middle", "/cb?access_token=abc123def456&x=1", "abc123def456"],
    ["quoted with spaces", 'password: "correct horse battery"', "correct horse battery"],
    ["quoted with separators", 'password = "abc,def;ghi"', "abc,def;ghi"],
    ["single quoted with spaces", "secret='two words here'", "two words"],
    ["unterminated quote", 'password = "half open value', "half open value"],
    ["json", '{"client_secret": "x y z", "id": 1}', "x y z"],
  ])("masks %s assignments (#51/#52)", (_label, input, secret) => {
    const output = redactSecrets(input);
    expect(output).not.toContain(secret);
    expect(output).toContain("[REDACTED:value]");
  });

  it.each([
    ["password with @", "https://user:p@ss@host.example/x", "p@ss", "credentials"],
    ["password with /", "https://user:pa/ss@host.example", "pa/ss", "credentials"],
    ["token as user", "https://tok3nvalue@github.com/o/r.git", "tok3nvalue", "credentials"],
    ["json cookie", '{"cookie":"sid=abc123secret"}', "abc123secret", "cookie"],
    ["single-quoted cookie", "cookie='sid=abc123secret'", "abc123secret", "cookie"],
  ])("masks %s (#56)", (_label, input, secret, kind) => {
    const output = redactSecrets(input);
    expect(output).not.toContain(secret);
    expect(output).toContain(`[REDACTED:${kind}]`);
  });

  it.each([
    "http://127.0.0.1:3000/login?next=a@b",
    "https://example.com/path?email=a@b.example",
    "https://example.com:8443/x",
  ])("leaves URLs without userinfo intact: %s", (url) => {
    expect(redactSecrets(url)).toBe(url);
  });

  it.each([
    ["underscore suffix", `${FAKE.github}_backup`, FAKE.github],
    ["underscore prefix", `x_${FAKE.github}`, FAKE.github],
    [
      "lowercase bearer sk-",
      `authorization: bearer ${join("sk-", "proj-", "e".repeat(30))}`,
      join("sk-", "proj-"),
    ],
    ["zero-width split", join("AKIA", "​", "IOSFODNN7", "EXAMPLE"), "IOSFODNN7"],
  ])("masks token variant: %s (#57)", (_label, input, secret) => {
    expect(redactSecrets(input)).not.toContain(secret);
  });

  it.each([
    "Rotate the token immediately",
    "Basic authentication is enabled",
    "Use a Bearer header",
  ])("leaves prose untouched: %s (#58)", (text) => {
    expect(redactSecrets(text)).toBe(text);
  });

  it("keeps code references that merely mention sensitive names", () => {
    expect(redactSecrets("password = req.body.password")).toBe("password = req.body.password");
    expect(redactSecrets("const token = getToken()")).toBe("const token = getToken()");
  });

  it("reveals no length or prefix of the secret", () => {
    const short = redactSecrets(`password="${"x".repeat(9)}"`);
    const long = redactSecrets(`password="${"y".repeat(90)}"`);
    expect(short).toBe('password="[REDACTED:value]"');
    expect(long).toBe('password="[REDACTED:value]"');
  });
});

describe("redactEvidence", () => {
  it("removes project root, home paths and control characters and truncates", () => {
    const output = redactEvidence(
      "read /work/app/src/a.ts and /Users/alice/.ssh/id_rsa\u0007 then\n\nmore",
      { projectRoot: "/work/app", maxLength: 60 },
    );
    expect(output).not.toContain("/work/app");
    expect(output).not.toContain("alice");
    expect(output).not.toContain("\u0007");
    expect(output.length).toBeLessThanOrEqual(60);
    expect(output.startsWith("read ./src/a.ts and ~/.ssh/id_rsa then more")).toBe(true);
  });
});

describe("absolute paths (#59)", () => {
  it.each([
    ["/opt/app/secrets/key.pem", "/opt/app"],
    ["/private/tmp/build/x.log", "/private/tmp"],
    ["C:\\proj\\src\\a.ts", "C:\\proj"],
    ["D:/work/app/config.yml", "D:/work"],
    ["file:///srv/app/x.txt", "/srv/app"],
  ])("removes %s", (input, fragment) => {
    const output = redactEvidence(`read ${input} done`);
    expect(output).not.toContain(fragment);
    expect(output).toContain("<absolute-path>");
  });

  it.each([
    "POST /api/login",
    "GET /v1/users/:id",
    "see src/db.ts:10",
    "http://127.0.0.1:3000/tmp",
  ])("keeps route paths and relative paths: %s", (text) => {
    expect(redactEvidence(text)).toBe(text);
  });
});

describe("redactFinding locations (#54)", () => {
  const base: Finding = {
    id: "x",
    ruleId: "PG-SECRET-001",
    title: "t",
    category: "secret_exposure",
    severity: "high",
    status: "confirmed",
    confidence: "high",
    location: { kind: "file", path: null, line: null, url: null, commit: null },
    evidence: "e",
    impact: "i",
    recommendation: "r",
    references: { cwe: [], owasp: [], cve: [] },
    sources: ["code"],
  };

  it("masks secrets in relative paths and drops absolute ones", () => {
    const withToken = redactFinding({
      ...base,
      location: { ...base.location, path: `keys/${FAKE.github}.pem` },
    });
    expect(withToken.location.path).not.toContain(FAKE.github);
    expect(withToken.location.path).toContain("keys/");
    const absolute = redactFinding({
      ...base,
      location: { ...base.location, path: "/opt/app/key.pem" },
    });
    expect(absolute.location.path).toBeNull();
  });

  it("scrubs home paths and secrets from URLs", () => {
    const result = redactFinding({
      ...base,
      location: {
        ...base.location,
        kind: "url",
        url: `file:///Users/jaden/app/x?password=${FAKE.password}`,
      },
    });
    expect(result.location.url).not.toContain("jaden");
    expect(result.location.url).not.toContain(FAKE.password);
  });
});

describe("redactFinding", () => {
  it("never leaves secrets in any field, including the JSON serialization", () => {
    const finding: Finding = {
      id: "x",
      ruleId: "PG-SECRET-001",
      title: `Hardcoded ${FAKE.aws}`,
      category: "secret_exposure",
      severity: "high",
      status: "confirmed",
      confidence: "high",
      location: {
        kind: "url",
        path: null,
        line: null,
        url: `http://user:${FAKE.password}@127.0.0.1:3000/`,
        commit: null,
      },
      evidence: `token ${FAKE.github} in /home/bob/app/config.js`,
      impact: `Anyone with ${FAKE.stripe} can charge cards`,
      recommendation: `Rotate ${FAKE.slack}`,
      references: { cwe: [], owasp: [], cve: [] },
      sources: ["code"],
    };
    const json = JSON.stringify(redactFinding(finding, { projectRoot: "/home/bob/app" }));
    for (const secret of [FAKE.aws, FAKE.password, FAKE.github, FAKE.stripe, FAKE.slack]) {
      expect(json).not.toContain(secret);
    }
    expect(json).not.toContain("/home/bob");
  });
});

describe("createSessionSecretLabeler", () => {
  it("labels equal values equally without exposing them", () => {
    const label = createSessionSecretLabeler();
    const first = label(FAKE.password);
    expect(label("other")).toBe("secret-2");
    expect(label(FAKE.password)).toBe(first);
    expect(first).toBe("secret-1");
    expect(createSessionSecretLabeler()(FAKE.password)).toBe("secret-1");
  });
});

describe("redaction performance (#55)", () => {
  const timed = (fn: () => void) => {
    const start = performance.now();
    fn();
    return performance.now() - start;
  };

  it.each([
    ["long word", "a".repeat(200_000)],
    ["dotted run", "a.".repeat(100_000)],
    ["scheme-like run", `${"a".repeat(100_000)}://`],
    ["sensitive key run", "password".repeat(25_000)],
    ["key with separators", "x_password_".repeat(20_000)],
    ["begin headers", "-----BEGIN PRIVATE KEY-----\n".repeat(5_000)],
    ["cookie lines", "cookie: a\n".repeat(20_000)],
  ])("redacts adversarial input (%s) quickly", (_label, input) => {
    expect(timed(() => redactEvidence(input))).toBeLessThan(250);
    expect(timed(() => redactSecrets(input))).toBeLessThan(1500);
  });

  it("caps very long input without leaving a partial secret at the cut", () => {
    const token = ["ghp", "_", "k".repeat(36)].join("");
    const input = `${"word ".repeat(13_105)}${token} tail`;
    const output = redactSecrets(input);
    expect(output.length).toBeLessThanOrEqual(64 * 1024 + 2);
    expect(output).not.toContain("ghp_k");
  });
});
