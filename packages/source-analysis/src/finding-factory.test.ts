import { describe, expect, it } from "vitest";
import type { CertCause } from "@pgard/findings";
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
  const withCause = (
    ruleId: SourceRuleId,
    path: string,
    cause: string,
    certCause?: CertCause,
  ): string[] | undefined =>
    createSourceFinding({ ...raw(ruleId, path), cause, ...(certCause ? { certCause } : {}) })
      .references.cert;

  it("gives MSC02-J to the weak-random causes of the analyzer and not to cipher or IV causes", () => {
    for (const cause of ["weak-random:iv", "weak-random:name", "weak-random:salt"]) {
      expect(withCause("PG-CRYPTO-003", "A.java", cause), cause).toEqual(["MSC02-J"]);
      expect(withCause("PG-CRYPTO-003", "A.kt", cause), cause).toEqual(["MSC02-J"]);
    }
    for (const cause of ["weak-cipher", "fixed-iv"]) {
      expect(withCause("PG-CRYPTO-003", "A.java", cause), cause).toBeUndefined();
    }
    // The evidence text decides nothing, and a JavaScript file never gets a Java CERT rule.
    const worded = createSourceFinding({
      ...raw("PG-CRYPTO-003", "A.java"),
      cause: "weak-cipher",
      evidence: "non-cryptographic random value used as a key",
    });
    expect(worded.references.cert).toBeUndefined();
    expect(withCause("PG-CRYPTO-003", "a.ts", "weak-random:iv")).toBeUndefined();
  });

  it("gives IDS04-J to an archive entry path and FIO16-J to every other path finding", () => {
    expect(withCause("PG-PATH-002", "Z.java", "Files.copy", "archive-entry")).toEqual(["IDS04-J"]);
    expect(withCause("PG-PATH-002", "P.kt", "File", "other-than-archive-entry")).toEqual([
      "FIO16-J",
    ]);
    expect(withCause("PG-PATH-002", "P.kt", "File")).toEqual(["FIO16-J"]);
  });
});
