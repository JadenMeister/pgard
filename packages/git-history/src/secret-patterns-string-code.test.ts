import { describe, expect, it } from "vitest";
import { detectSecrets } from "./secret-patterns.js";

// Runtime-assembled so no secret-looking literal is committed.
const j = (...parts: string[]) => parts.join("");
const RANDOM = j("Xk9v", "Lp8W", "z4qR", "t2mN7");
const BRACKET = j("Xk9v", "]Lp8", "Wz4q");
const ANGLE = j("Qw3r", "<Ty7u", "Io9p");
const PAREN = j("Zx8c", ")Vb5n", "Mq2w");
const COLON = j("Hj6k", "Lm4n", "Pq2r:");
const CAPS_WORDS = j("MY_SUPER", "_SECRET", "_KEY");

function scan(text: string, path: string) {
  return detectSecrets(text, { path });
}

describe("code text inside a string literal is demoted, never dropped (#246)", () => {
  it("marks code in a double-quoted string with \\n escapes as code text", () => {
    const text = `const src = "const PASSWORD_RE = /^(pass|pwd)$/i;\\nconst x = 1;\\n";\n`;
    const found = scan(text, "test/cases.mjs");
    expect(found).toHaveLength(1);
    expect(found[0]?.codeText).toBe(true);
  });

  it("marks a type member and a constant assigned a constant name as code text", () => {
    const member = `const src = "interface C {\\n  apiKey: Record<string, string>;\\n}\\n";\n`;
    expect(scan(member, "test/gen.ts").map((secret) => secret.codeText)).toEqual([true]);
    const constant = `const src = 'export const SECRET = SECRET_ENV_NAME;\\nuse(SECRET);\\n';\n`;
    expect(scan(constant, "test/gen.js").map((secret) => secret.codeText)).toEqual([true]);
  });

  it("does not let a constant-name value alone demote a secret", () => {
    const text = `write(".env", "PORT=8080\\nJWT_SECRET=${CAPS_WORDS}\\n");\n`;
    const found = scan(text, "scripts/seed.js");
    expect(found).toHaveLength(1);
    expect(found[0]?.codeText).toBeUndefined();
    expect(found[0]?.value).toBe(CAPS_WORDS);
  });

  it.each([
    ["bracket", `const conf = "user=admin\\npassword=${BRACKET}\\n";\n`, BRACKET],
    ["angle bracket", `const yaml = "db:\\n  password: ${ANGLE}\\n";\n`, ANGLE],
    ["paren", `var cs = "Server=db;User=sa;Password=${PAREN};\\n";\n`, PAREN],
    ["ends with a colon", `conf = "user=admin\\npassword=${COLON}"\n`, COLON],
    [
      "caps value last in the string",
      `write(".env", "A=1\\nJWT_SECRET=${CAPS_WORDS}");\n`,
      CAPS_WORDS,
    ],
    [
      "caps value before a space",
      `exec("echo a\\n; ADMIN_PASSWORD=${CAPS_WORDS} node s.js");\n`,
      CAPS_WORDS,
    ],
    ["newline in another string", `log("done\\n"); const cfg = "api_key=${BRACKET}";\n`, BRACKET],
  ])("keeps a real secret at full confidence: %s", (_name, text, value) => {
    const found = scan(text, "src/app.js");
    expect(found.map((secret) => secret.value)).toEqual([value]);
    expect(found[0]?.codeText).toBeUndefined();
  });

  it("does not take a trailing \\n escape as part of the value", () => {
    const found = scan(`const env = "DB_PASSWORD=${RANDOM}\\nDEBUG=0";\n`, "scripts/env.js");
    expect(found.map((secret) => secret.value)).toEqual([RANDOM]);
  });

  it("keeps .env-style lines and quoted literals", () => {
    expect(scan(`DEBUG=1\nAPI_SECRET=${RANDOM}\n`, "app.env")).toHaveLength(1);
    expect(scan(`const password = "${RANDOM}";\n`, "src/a.js")).toHaveLength(1);
  });

  it("keeps a literal backslash-n inside a value in config files (W1, W3)", () => {
    const conf = scan(`DB_PASSWORD=Ab3\\nXy9Zk2Lm7Q\n`, "config/app.conf");
    expect(conf.map((secret) => secret.value)).toEqual(["Ab3\\nXy9Zk2Lm7Q"]);
    const props = scan(`db.password=P@s5\\nw0rdXk9vL\n`, "app.properties");
    expect(props.map((secret) => secret.value)).toEqual(["P@s5\\nw0rdXk9vL"]);
  });

  it("keeps an escaped backslash followed by n inside a value in source (W5)", () => {
    const found = scan(`const s = "password=Ab3\\\\nXy9Zk2Lm7Q";\n`, "src/f.ts");
    expect(found.map((secret) => secret.value)).toEqual(["Ab3\\\\nXy9Zk2Lm7Q"]);
  });

  it("reports a duplicate value once, at full confidence when either match is a real one", () => {
    const text = `const doc = "const api_key = ${BRACKET};"; const api_key = "${BRACKET}";\n`;
    const found = scan(text, "src/c.js");
    expect(found).toHaveLength(1);
    expect(found[0]?.codeText).toBeUndefined();
  });
});
