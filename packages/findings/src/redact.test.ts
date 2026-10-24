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
