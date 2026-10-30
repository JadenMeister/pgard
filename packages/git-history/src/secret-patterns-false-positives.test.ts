import { describe, expect, it } from "vitest";
import { detectSecrets, isDictionaryWordsValue } from "./secret-patterns.js";

// Runtime-assembled so no secret-looking literal is committed.
const j = (...parts: string[]) => parts.join("");
const REAL = j("Xk9v", "Lp8W", "z4qR", "t2mN7");
const AWS = j("AKIA", "Q7RT", "M2XW", "9KDP", "L3VZ");

const scan = (text: string, path?: string, omitGeneric?: boolean) =>
  detectSecrets(text, {
    ...(path === undefined ? {} : { path }),
    ...(omitGeneric ? { omitGeneric } : {}),
  });

describe("placeholder words (#445)", () => {
  it.each([
    "replace-with-a-long-random-secret",
    "REPLACE_WITH_YOUR_SECRET",
    "random-string-here",
    "generate-a-strong-key",
    "set_me_to_something",
    "insert-your-key-here",
    "put_your_secret_here",
  ])("does not report %s", (value) => {
    expect(scan(`SECRET_KEY=${value}\n`, ".env.example")).toEqual([]);
    expect(scan(`secret = ${value}\n`, "docs/setup.md")).toEqual([]);
  });

  it("keeps a passphrase made of those words in a config file", () => {
    for (const phrase of ["random-tiger-lamp-orbit", "Insert-Coin-Gizmo"]) {
      expect(scan(`secret: ${phrase}\n`, "config.yml")).toHaveLength(1);
    }
  });

  it("still reports a real value", () => {
    expect(scan(`SECRET_KEY=${REAL}\n`, "config/app.conf")).toHaveLength(1);
  });

  it.each([
    j("Random", "9xKq2", "LmP7vT"),
    j("Xq7insert", "Key9Lm2"),
    j("aZ9k/generate", "Q7mP2xL"),
    j("Random", "XkLmPqWzRtYu"),
  ])("keeps %s: the word is not a whole word of a word-shaped value", (value) => {
    expect(scan(`SECRET_KEY=${value}\n`, "config/app.conf")).toHaveLength(1);
  });

  it("does not let the words hide URL passwords or provider tokens", () => {
    const url = scan(`u = "postgres://app:${j("Random", "2024Xk")}@db.internal/app"\n`, "a.conf");
    expect(url.map((secret) => secret.kind)).toEqual(["url_credential"]);
    const token = scan(
      `t = ${j("ghp", "_Random", "Zq8aB3cD4eF5gLm4hJ6kL7mN8pPw7qR9sT0u")}\n`,
      "a.conf",
    );
    expect(token.map((secret) => secret.kind)).toEqual(["github_token"]);
  });
});

describe("dictionary words only", () => {
  it("accepts 3+ lowercase words of 2 to 12 letters", () => {
    expect(isDictionaryWordsValue("my-secret-key-value")).toBe(true);
    expect(isDictionaryWordsValue("my_secret.key")).toBe(true);
    expect(isDictionaryWordsValue("my-secret")).toBe(false);
    expect(isDictionaryWordsValue("my-Secret-key")).toBe(false);
    expect(isDictionaryWordsValue("my-secret-key2")).toBe(false);
    expect(isDictionaryWordsValue("a-secret-key")).toBe(false);
    expect(isDictionaryWordsValue("my-secretsecretsecret-key")).toBe(false);
  });

  it("skips an example value in docs (unquoted or in a code span) and in .env templates", () => {
    expect(scan('Set `api_key = "my-secret-key-value"` first.\n', "README.md")).toEqual([]);
    expect(scan("api_key = my-secret-key-value\n", "docs/guide.rst")).toEqual([]);
    expect(scan('```\napi_key = "my-secret-key-value"\n```\n', "README.md")).toEqual([]);
    expect(scan("API_KEY=my-secret-key-value\n", ".env.example")).toEqual([]);
    expect(scan("API_KEY=my-secret-key-value\n", "config/app.conf")).toHaveLength(1);
    expect(scan('api_key = "my-secret-key-value"\n', "src/app.py")).toHaveLength(1);
  });

  it("keeps a passphrase: no example word, a quoted prose value, or a .txt file", () => {
    const phrase = "correct-horse-battery-staple";
    expect(scan(`password=${phrase}\n`, "credentials.txt")).toHaveLength(1);
    expect(scan(`password=${phrase}\n`, "notes.txt")).toHaveLength(1);
    expect(scan(`password=${phrase}\n`, "README.md")).toHaveLength(1);
    expect(scan(`The password: "my-secret-key-value" is set.\n`, "README.md")).toHaveLength(1);
    expect(scan('x `password = "my-secret-key-value"`\n', "README.md")).toEqual([]);
  });

  it("reports a quoted value with digits and mixed case in docs", () => {
    expect(scan(`api_key = "${REAL}"\n`, "README.md")).toHaveLength(1);
  });
});

describe("template files report only real-looking values", () => {
  it("drops a lowercase-only short or low-entropy value", () => {
    expect(scan("DB_PASSWORD=supersecretpassword\n", ".env.example")).toEqual([]);
    expect(scan("DB_PASSWORD=aaaa1111bbbb\n", ".env.template")).toEqual([]);
  });

  it("keeps a high-entropy mixed-class value", () => {
    expect(scan(`DB_PASSWORD=${REAL}\n`, ".env.example")).toHaveLength(1);
    expect(scan("DB_PASSWORD=Hunter2x\n", ".env.sample")).toHaveLength(1);
    expect(scan("DB_PASSWORD=qz!kx#mw$vt\n", "prod.env.example")).toHaveLength(1);
  });

  it("keeps a long single-class random value", () => {
    expect(scan("DB_PASSWORD=qwkzmtrplxvbnhgfjdsacxzyuoeiw\n", ".env.example")).toHaveLength(1);
    expect(scan("DB_PASSWORD=QWKZMTRPLXVBNHGFJDSACXZYUOEIW\n", ".env.example")).toHaveLength(1);
  });

  it("applies the strict rule only to .env templates", () => {
    const text = "MasterUserPassword: qwkzmtrplxvbnhgf\n";
    expect(scan(text, "stack.template")).toHaveLength(1);
  });

  it("keeps provider-specific patterns", () => {
    const found = scan(`AWS_ACCESS_KEY_ID=${AWS}\n`, ".env.example");
    expect(found.map((secret) => secret.kind)).toEqual(["aws_access_key_id"]);
  });
});

describe("code-shaped unquoted values (minified code)", () => {
  it.each([
    "var a={password:e.target.value});",
    "if(e.password==e.pass)||t){}",
    "x=e.password==t.password}",
    "o={password:t.password,user:1}",
    "f({secret:e.target.secretvalue})",
    "if(a.apikey===b.apikey&&c){}",
  ])("does not report %s", (code) => {
    expect(scan(code, "build/static/js/main.js")).toEqual([]);
  });

  it("still reports a quoted high-entropy value in a bundle", () => {
    expect(scan(`var a={password:"${REAL}"};`, "dist/assets/app.js")).toHaveLength(1);
  });

  it.each([
    j("// admin password: Xk9", ")m2Lq8vBp"),
    j("# password=Zq8", "]Lm2x9Kp"),
    j("/* api_key=Zq8", "}Lm2x9Kp4 */"),
    j("// password=Xk9", "&&m2Lq8vB"),
  ])("keeps a password with a bracket or operator in a comment: %#", (text) => {
    expect(scan(`${text}\n`, "src/app.js")).toHaveLength(1);
  });

  it.each([
    j("// db password: Prod.Xk9q", ")m2Lq8"),
    j("# password=Abc.Zq8", "]Lm2x9Kp"),
    j("// password: =Xk9q2", "Lm8vBpZ"),
    j("// password==Xk9q2", "Lm8vBpZ"),
  ])("keeps a dotted or = prefixed password in a comment: %#", (text) => {
    expect(scan(`${text}\n`, "src/app.js")).toHaveLength(1);
  });

  it("stays fast on a large doc of example lines", () => {
    const text = 'Set `api_key = "my-secret-key-value"` here.\n'.repeat(25_000);
    const started = performance.now();
    expect(scan(text, "README.md")).toEqual([]);
    expect(performance.now() - started).toBeLessThan(1000);
    const fenced = ("```\n" + 'api_key = "my-secret-key-value"\n```\n').repeat(25_000);
    const startedFenced = performance.now();
    scan(fenced, "README.md");
    expect(performance.now() - startedFenced).toBeLessThan(1000);
  });

  it("keeps brackets in config text and in strings, and a leading = outside source code", () => {
    expect(scan(`password=${j("Xk9v", "]Lp8", "Wz4q")}\n`, "config/app.conf")).toHaveLength(1);
    const text = `const conf = "user=admin\\npassword=${j("Zx8c", ")Vb5n", "Mq2w")}\\n";\n`;
    expect(scan(text, "scripts/conf.js")).toHaveLength(1);
    expect(scan(`db.password==${j("Xk9", "#q2Lm7vBp")}\n`, "app.properties")).toHaveLength(1);
    expect(scan(`password = =${j("Xk9", "#q2Lm7vBp")}\n`, "app.ini")).toHaveLength(1);
  });
});

describe("omitGeneric", () => {
  it("drops generic credentials but keeps provider patterns", () => {
    const text = `DB_PASSWORD=${REAL}\nAWS_ACCESS_KEY_ID=${AWS}\n`;
    expect(
      scan(text, ".env")
        .map((secret) => secret.kind)
        .sort(),
    ).toEqual(["aws_access_key_id", "generic_credential"]);
    expect(scan(text, ".env", true).map((secret) => secret.kind)).toEqual(["aws_access_key_id"]);
  });
});
