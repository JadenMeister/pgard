import { describe, expect, it } from "vitest";
import { detectSecrets } from "./secret-patterns.js";

// Runtime-assembled so no secret-looking literal is committed.
const VALUE = ["Xk9vLp8W", "z4qRt2mN7"].join("");

describe("detectSecrets on code text inside an escaped string (#246)", () => {
  it("ignores code kept in a double-quoted string with \\n escapes", () => {
    const text =
      'files: "export type K = string;\\nconst PASSWORD_NAME = /^(password|pwd)$/i;\\nfunction set(password: string): void {}\\n",\n';
    expect(detectSecrets(text, { path: "test/cases.mjs" })).toEqual([]);
  });

  it("ignores code in a single-quoted string", () => {
    const text =
      "const src = 'const SECRET_RE = /^(secret|token)$/i;\\nlet apiKey: string);\\n';\n";
    expect(detectSecrets(text, { path: "src/gen.ts" })).toEqual([]);
  });

  it("keeps a real value in a string with \\n escapes", () => {
    const text = `fs.writeFileSync(".env", "PORT=3000\\nDB_PASSWORD=${VALUE}\\n");\n`;
    const found = detectSecrets(text, { path: "scripts/seed.js" });
    expect(found).toHaveLength(1);
    expect(found[0]?.value.startsWith(VALUE)).toBe(true);
  });

  it("keeps a .env-style value and a quoted literal", () => {
    expect(detectSecrets(`DEBUG=1\nAPI_SECRET=${VALUE}\n`, { path: "app.env" })).toHaveLength(1);
    expect(detectSecrets(`const password = "${VALUE}";\n`, { path: "src/a.js" })).toHaveLength(1);
  });
});
