import { describe, expect, it } from "vitest";
import { createSourceFinding, type RawSourceFinding } from "./finding-factory.js";
import type { SourceRuleId } from "./rules.js";

const raw = (ruleId: SourceRuleId, path: string): RawSourceFinding => ({
  ruleId,
  path,
  line: 3,
  severity: "high",
  status: "suspected",
  confidence: "medium",
  evidence: "request input -> sink",
  cause: "sink",
});

describe("direct CERT Java references on findings", () => {
  it("adds them for findings in Java and Kotlin files", () => {
    expect(createSourceFinding(raw("PG-CMD-003", "src/A.java")).references.cert).toEqual([
      "IDS07-J",
    ]);
    expect(createSourceFinding(raw("PG-PATH-002", "src/A.kt")).references.cert).toEqual([
      "FIO16-J",
    ]);
    expect(createSourceFinding(raw("PG-SQL-005", "src/Repo.java")).references.cert).toEqual([
      "IDS00-J",
    ]);
    expect(createSourceFinding(raw("PG-CRYPTO-002", "src/K.java")).references.cert).toEqual([
      "MSC03-J",
    ]);
  });

  it("never adds one to a finding in another language, even for a rule shared with Java", () => {
    for (const [ruleId, path] of [
      ["PG-CMD-001", "src/a.js"],
      ["PG-CMD-002", "main.go"],
      ["PG-CMD-004", "app.py"],
      ["PG-CMD-005", "index.php"],
      ["PG-CRYPTO-002", "src/key.ts"],
      ["PG-CRYPTO-002", "key.go"],
      ["PG-SQL-001", "db.ts"],
    ] as const) {
      const { references } = createSourceFinding(raw(ruleId, path));
      expect(references.cert, `${ruleId} ${path}`).toBeUndefined();
      expect(Object.keys(references).sort()).toEqual(["cve", "cwe", "owasp"]);
    }
  });

  it("adds none for a Java rule that is marked as having no direct CERT rule", () => {
    expect(createSourceFinding(raw("PG-XSS-004", "src/A.java")).references.cert).toBeUndefined();
  });
});

describe("direct CERT references scoped to the cause of a finding", () => {
  const withEvidence = (ruleId: SourceRuleId, path: string, evidence: string) =>
    createSourceFinding({ ...raw(ruleId, path), evidence }).references.cert;

  it("gives MSC02-J to a weak random source finding and not to a cipher or fixed IV finding", () => {
    const random = [
      "non-cryptographic random value used as an IV",
      "non-cryptographic random value stored in token (a token, key, IV or salt by name); inferred",
      "non-cryptographic random bytes written into salt (a key, IV, salt or token by name); inferred",
    ];
    for (const evidence of random) {
      expect(withEvidence("PG-CRYPTO-003", "A.java", evidence), evidence).toEqual(["MSC02-J"]);
      expect(withEvidence("PG-CRYPTO-003", "A.kt", evidence), evidence).toEqual(["MSC02-J"]);
    }
    for (const evidence of [
      "weak cipher: DES cipher",
      "weak cipher: AES in ECB mode",
      "weak cipher: DESede cipher",
      "fixed IV: all-zero byte array used in IvParameterSpec",
    ]) {
      expect(withEvidence("PG-CRYPTO-003", "A.java", evidence), evidence).toBeUndefined();
    }
    // The same evidence in a JavaScript file never gets a Java CERT rule.
    expect(
      withEvidence("PG-CRYPTO-003", "a.ts", "non-cryptographic random value used as a key"),
    ).toBeUndefined();
  });

  it("gives IDS04-J to an archive entry path and FIO16-J to every other path finding", () => {
    expect(
      withEvidence(
        "PG-PATH-002",
        "Z.java",
        "archive entry name (getName) via variable -> path -> File.mkdirs",
      ),
    ).toEqual(["IDS04-J"]);
    for (const evidence of [
      "request input (@RequestParam name) -> path -> Files.readAllBytes",
      "request input (uploaded file name (getOriginalFilename)) -> new File",
      "path -> File.mkdirs (no input source identified)",
      "path -> FileOutputStream; checked by a path guard (canonical prefix test or '..' rejection); inferred",
    ]) {
      expect(withEvidence("PG-PATH-002", "P.kt", evidence), evidence).toEqual(["FIO16-J"]);
    }
  });
});
