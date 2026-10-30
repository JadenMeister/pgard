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
    "random-string-here1",
    "generate-a-strong-key1",
    "set_me_to_something1",
    "insert-your-key-here1",
    "put_your_secret_here1",
  ])("does not report %s", (value) => {
    expect(scan(`SECRET_KEY=${value}\n`, "config/app.conf")).toEqual([]);
    expect(scan(`secret = "${value}"\n`, "src/app.py")).toEqual([]);
  });

  it("still reports a real value", () => {
    expect(scan(`SECRET_KEY=${REAL}\n`, "config/app.conf")).toHaveLength(1);
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

  it("skips such a value in docs and templates, not in config or source", () => {
    const line = `api_key = "my-secret-key-value"\n`;
    expect(scan(line, "README.md")).toEqual([]);
    expect(scan(line, "docs/guide.rst")).toEqual([]);
    expect(scan("API_KEY=my-secret-key-value\n", ".env.example")).toEqual([]);
    expect(scan("API_KEY=my-secret-key-value\n", "config/app.conf")).toHaveLength(1);
    expect(scan(line, "src/app.py")).toHaveLength(1);
  });

  it("reports a quoted value with digits and mixed case in docs", () => {
    expect(scan(`api_key = "${REAL}"\n`, "README.md")).toHaveLength(1);
  });
});

describe("template files report only real-looking values", () => {
  it("drops a lowercase-only or low-entropy value", () => {
    expect(scan("DB_PASSWORD=supersecretpassword\n", ".env.example")).toEqual([]);
    expect(scan("DB_PASSWORD=aaaa1111bbbb\n", ".env.template")).toEqual([]);
  });

  it("keeps a high-entropy mixed-class value", () => {
    expect(scan(`DB_PASSWORD=${REAL}\n`, ".env.example")).toHaveLength(1);
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
    "k={password:arr[idx]};",
  ])("does not report %s", (code) => {
    expect(scan(code, "build/static/js/main.js")).toEqual([]);
  });

  it("still reports a quoted high-entropy value in a bundle", () => {
    expect(scan(`var a={password:"${REAL}"};`, "dist/assets/app.js")).toHaveLength(1);
  });

  it("keeps an unquoted value with brackets in config text and in strings", () => {
    expect(scan(`password=${j("Xk9v", "]Lp8", "Wz4q")}\n`, "config/app.conf")).toHaveLength(1);
    const text = `const conf = "user=admin\\npassword=${j("Zx8c", ")Vb5n", "Mq2w")}\\n";\n`;
    expect(scan(text, "scripts/conf.js")).toHaveLength(1);
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
