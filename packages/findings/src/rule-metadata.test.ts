import { describe, expect, it } from "vitest";
import { defineRule, type RuleDefinition } from "./rule-descriptor.js";
import { pickText, validateRuleMetadata, type LocalizedText } from "./rule-metadata.js";

const definition = (overrides: Partial<RuleDefinition> = {}): RuleDefinition => ({
  id: "PG-TEST-001",
  title: "Test rule",
  category: "injection",
  defaultSeverity: "high",
  scope: "code",
  languages: ["javascript"],
  standards: {
    owasp: ["A05:2025"],
    cwe: ["CWE-78"],
    cert: [{ kind: "via-cwe", id: "IDS07-J", cwe: "CWE-78" }],
  },
  rationale: { en: "Input can inject commands.", ko: "입력이 명령을 주입할 수 있습니다." },
  remediation: { en: "Avoid the shell.", ko: "셸을 사용하지 마세요." },
  ...overrides,
});

const problems = (overrides: Partial<RuleDefinition> = {}): string[] => {
  const { id, metadata } = defineRule(definition(overrides));
  return validateRuleMetadata({ id, metadata });
};

/** With the rule's languages, so the direct-CERT policy for Java and Kotlin rules is checked. */
const jvmProblems = (overrides: Partial<RuleDefinition>): string[] =>
  validateRuleMetadata(defineRule(definition(overrides)));

describe("defineRule", () => {
  it("derives the English flat fields from the metadata", () => {
    const rule = defineRule(definition());
    expect(rule.cwe).toEqual(["CWE-78"]);
    expect(rule.owasp).toEqual(["A05:2025"]);
    expect(rule.impact).toBe("Input can inject commands.");
    expect(rule.recommendation).toBe("Avoid the shell.");
    expect(rule.metadata.rationale.ko).toBe("입력이 명령을 주입할 수 있습니다.");
  });

  it("copies arrays so callers cannot mutate the definition", () => {
    const def = definition();
    const rule = defineRule(def);
    rule.cwe.push("CWE-1");
    rule.metadata.standards.cwe = [];
    expect(def.standards.cwe).toEqual(["CWE-78"]);
  });

  it("requires a Korean translation at compile time", () => {
    // @ts-expect-error ko is missing
    const missingKo: LocalizedText = { en: "only English" };
    // @ts-expect-error remediation must have both languages
    definition({ remediation: { en: "only English" } });
    expect(missingKo.en).toBe("only English");
  });
});

describe("pickText", () => {
  it("defaults to English and can select Korean", () => {
    const text = { en: "Hello", ko: "안녕하세요" };
    expect(pickText(text)).toBe("Hello");
    expect(pickText(text, "ko")).toBe("안녕하세요");
  });
});

// Deliberately wrong values: the types reject them, the validator must still catch them at runtime.
const wrong = (value: string): never => value as never;

describe("validateRuleMetadata", () => {
  it("accepts valid metadata, including a direct CERT reference and examples", () => {
    expect(problems()).toEqual([]);
    expect(
      problems({
        standards: {
          owasp: ["A05:2025"],
          cwe: ["CWE-89"],
          cert: [{ kind: "direct", id: "IDS00-J" }],
        },
        examples: [
          {
            language: "javascript",
            vulnerable: "db.query(`... ${id}`)",
            safe: "db.query('... $1', [id])",
            note: { en: "Bind values.", ko: "값을 바인딩하세요." },
          },
        ],
      }),
    ).toEqual([]);
  });

  it("rejects OWASP ids outside the 2025 list", () => {
    expect(
      problems({
        standards: { owasp: [wrong("A03:2021"), wrong("A11:2025")], cwe: [], cert: [] },
      }),
    ).toEqual([
      "PG-TEST-001: OWASP id A03:2021 is not an OWASP Top 10 2025 id",
      "PG-TEST-001: OWASP id A11:2025 is not an OWASP Top 10 2025 id",
    ]);
  });

  it("rejects malformed and duplicate CWE ids", () => {
    expect(problems({ standards: { owasp: [], cwe: ["79"], cert: [] } })).toEqual([
      "PG-TEST-001: CWE id 79 is malformed",
    ]);
    expect(
      problems({ standards: { owasp: ["A05:2025"], cwe: ["CWE-79", "CWE-79"], cert: [] } }),
    ).toEqual(["PG-TEST-001: duplicate CWE ids"]);
  });

  it("rejects malformed, unknown and duplicate CERT references", () => {
    const cert = (
      ...refs: NonNullable<RuleDefinition["standards"]>["cert"]
    ): Partial<RuleDefinition> => ({
      standards: { owasp: ["A05:2025"], cwe: ["CWE-78"], cert: refs },
    });
    expect(problems(cert({ kind: "direct", id: "ids00-j" }))).toEqual([
      "PG-TEST-001: CERT id ids00-j is malformed",
    ]);
    expect(problems(cert({ kind: "direct", id: "IDS00-K" }))).toEqual([
      "PG-TEST-001: CERT id IDS00-K is malformed",
    ]);
    expect(problems(cert({ kind: "direct", id: "ZZZ99-J" }))).toEqual([
      "PG-TEST-001: CERT rule ZZZ99-J is not in the CERT Java data",
    ]);
    expect(
      problems(cert({ kind: "direct", id: "IDS00-J" }, { kind: "direct", id: "IDS00-J" })),
    ).toEqual(["PG-TEST-001: duplicate CERT references"]);
    // The same rule can be both direct and via-cwe.
    expect(
      problems(
        cert({ kind: "direct", id: "IDS07-J" }, { kind: "via-cwe", id: "IDS07-J", cwe: "CWE-78" }),
      ),
    ).toEqual([]);
  });

  it("rejects via-cwe references the CERT rule or the rule itself does not back", () => {
    // IDS07-J exists but does not list CWE-89.
    expect(
      problems({
        standards: {
          owasp: ["A05:2025"],
          cwe: ["CWE-89"],
          cert: [{ kind: "via-cwe", id: "IDS07-J", cwe: "CWE-89" }],
        },
      }),
    ).toEqual(["PG-TEST-001: CERT IDS07-J does not list CWE-89"]);
    // The rule itself does not carry CWE-78.
    expect(
      problems({
        standards: {
          owasp: ["A05:2025"],
          cwe: ["CWE-89"],
          cert: [{ kind: "via-cwe", id: "IDS07-J", cwe: "CWE-78" }],
        },
      }),
    ).toEqual(["PG-TEST-001: CERT IDS07-J via CWE-78: rule has no such CWE"]);
  });

  it("rejects empty text and Korean text without Korean", () => {
    expect(problems({ rationale: { en: "ok", ko: "" } })).toEqual([
      "PG-TEST-001: rationale.ko is empty",
      "PG-TEST-001: rationale.ko contains no Korean",
    ]);
    expect(problems({ remediation: { en: "ok", ko: "TODO" } })).toEqual([
      "PG-TEST-001: remediation.ko contains no Korean",
    ]);
    expect(problems({ remediation: { en: " ", ko: "한국어" } })).toEqual([
      "PG-TEST-001: remediation.en is empty",
    ]);
  });

  it("checks example notes like any other prose, and tolerates examples without a note", () => {
    const example = { language: "go", vulnerable: "a", safe: "b" };
    expect(problems({ examples: [example] })).toEqual([]);
    expect(problems({ examples: [example, { ...example, note: { en: "Note", ko: "" } }] })).toEqual(
      [
        "PG-TEST-001: examples[1].note.ko is empty",
        "PG-TEST-001: examples[1].note.ko contains no Korean",
      ],
    );
    expect(problems({ examples: [{ ...example, note: { en: "", ko: "메모" } }] })).toEqual([
      "PG-TEST-001: examples[0].note.en is empty",
    ]);
  });

  describe("direct CERT policy for Java and Kotlin rules", () => {
    const direct = { kind: "direct", id: "IDS07-J" } as const;
    const marker = {
      en: "No SEI CERT Java rule is about this weakness.",
      ko: "이 약점을 다루는 SEI CERT Java 규칙이 없습니다.",
    };
    const standards = (
      cert: NonNullable<RuleDefinition["standards"]>["cert"],
      noDirectCert?: LocalizedText,
    ): RuleDefinition["standards"] => ({
      owasp: ["A05:2025"],
      cwe: ["CWE-78"],
      cert,
      ...(noDirectCert === undefined ? {} : { noDirectCert }),
    });

    it("needs a direct reference or the explicit marker on a Java or Kotlin rule", () => {
      for (const languages of [["java"], ["kotlin"], ["javascript", "kotlin"]] as const) {
        expect(jvmProblems({ languages, standards: standards([direct]) })).toEqual([]);
        expect(jvmProblems({ languages, standards: standards([], marker) })).toEqual([]);
        expect(jvmProblems({ languages, standards: standards([]) })).toEqual([
          "PG-TEST-001: applies to Java or Kotlin but has no direct CERT reference and no noDirectCert marker",
        ]);
      }
      // A link through a CWE is not a direct entry.
      expect(
        jvmProblems({
          languages: ["java"],
          standards: standards([{ kind: "via-cwe", id: "IDS07-J", cwe: "CWE-78" }]),
        }),
      ).toHaveLength(1);
    });

    it("rejects both a direct reference and the marker, and a marker without Korean", () => {
      expect(jvmProblems({ languages: ["java"], standards: standards([direct], marker) })).toEqual([
        "PG-TEST-001: has both a direct CERT reference and a noDirectCert marker",
      ]);
      expect(
        jvmProblems({
          languages: ["java"],
          standards: standards([], { en: "Reason.", ko: "reason" }),
        }),
      ).toEqual(["PG-TEST-001: standards.noDirectCert.ko contains no Korean"]);
    });

    it("allows noDirectCertOther only next to a direct reference scoped to a cause", () => {
      const other = { en: "Other causes.", ko: "다른 원인." };
      const scoped = { kind: "direct", id: "IDS07-J", cause: "weak-random" } as const;
      const withOther = (
        cert: NonNullable<RuleDefinition["standards"]>["cert"],
      ): Partial<RuleDefinition> => ({
        languages: ["java"],
        standards: { ...standards(cert), noDirectCertOther: other },
      });
      expect(jvmProblems(withOther([scoped]))).toEqual([]);
      expect(jvmProblems(withOther([direct]))).toEqual([
        "PG-TEST-001: has a noDirectCertOther marker but no direct CERT reference scoped to a cause",
      ]);
    });

    it("rejects a direct reference or marker on a rule that does not apply to Java or Kotlin", () => {
      expect(
        jvmProblems({ languages: ["javascript", "go"], standards: standards([direct]) }),
      ).toEqual(["PG-TEST-001: has a direct CERT reference but does not apply to Java or Kotlin"]);
      expect(jvmProblems({ languages: ["python"], standards: standards([], marker) })).toEqual([
        "PG-TEST-001: has a noDirectCert marker but does not apply to Java or Kotlin",
      ]);
      // Indirect links are fine for other languages.
      expect(jvmProblems({ languages: ["go"], standards: standards([]) })).toEqual([]);
    });
  });

  describe("mapping policy", () => {
    const standards = (
      owasp: readonly string[],
      cwe: readonly string[],
      mappingNote?: { discouragedCwe?: LocalizedText; owaspDeparture?: LocalizedText },
    ): RuleDefinition["standards"] =>
      ({ owasp, cwe, cert: [], ...(mappingNote === undefined ? {} : { mappingNote }) }) as never;
    const note = { en: "Reason.", ko: "이유입니다." };

    it("requires the OWASP categories to be the ones the CWEs map to", () => {
      expect(problems({ standards: standards(["A02:2025"], ["CWE-89"]) })).toEqual([
        "PG-TEST-001: OWASP A02:2025 does not match the categories of its CWEs (A05:2025); fix the mapping or add standards.mappingNote.owaspDeparture",
      ]);
      expect(problems({ standards: standards([], ["CWE-89"]) })).toHaveLength(1);
    });

    it("rejects duplicate OWASP ids", () => {
      expect(problems({ standards: standards(["A05:2025", "A05:2025"], ["CWE-89"]) })).toEqual([
        "PG-TEST-001: duplicate OWASP ids",
      ]);
    });

    it("accepts several categories when the CWEs map to several", () => {
      expect(
        problems({ standards: standards(["A01:2025", "A07:2025"], ["CWE-538", "CWE-798"]) }),
      ).toEqual([]);
      expect(problems({ standards: standards(["A07:2025"], ["CWE-538", "CWE-798"]) })).toHaveLength(
        1,
      );
    });

    it("accepts a CWE that is in no OWASP list alongside one that is", () => {
      expect(problems({ standards: standards(["A01:2025"], ["CWE-527", "CWE-538"]) })).toEqual([]);
    });

    it("accepts a documented OWASP departure, and rejects a note that is not needed", () => {
      expect(
        problems({ standards: standards(["A02:2025"], ["CWE-89"], { owaspDeparture: note }) }),
      ).toEqual([]);
      expect(
        problems({ standards: standards(["A05:2025"], ["CWE-89"], { owaspDeparture: note }) }),
      ).toEqual([
        "PG-TEST-001: standards.mappingNote.owaspDeparture is set but the OWASP categories follow the CWEs",
      ]);
    });

    it("requires a note for a CWE that MITRE marks DISCOURAGED", () => {
      expect(problems({ standards: standards(["A06:2025"], ["CWE-693"]) })).toEqual([
        "PG-TEST-001: CWE-693 is DISCOURAGED by MITRE; use a specific CWE or add standards.mappingNote.discouragedCwe",
      ]);
      expect(
        problems({ standards: standards(["A06:2025"], ["CWE-693"], { discouragedCwe: note }) }),
      ).toEqual([]);
      expect(
        problems({ standards: standards(["A05:2025"], ["CWE-89"], { discouragedCwe: note }) }),
      ).toEqual([
        "PG-TEST-001: standards.mappingNote.discouragedCwe is set but the rule has no DISCOURAGED CWE",
      ]);
    });

    it("does not let a note for one kind of departure excuse the other", () => {
      // The OWASP categories are wrong, and the note is only about the DISCOURAGED CWE.
      expect(
        problems({ standards: standards(["A02:2025"], ["CWE-693"], { discouragedCwe: note }) }),
      ).toEqual([
        "PG-TEST-001: OWASP A02:2025 does not match the categories of its CWEs (A06:2025); fix the mapping or add standards.mappingNote.owaspDeparture",
      ]);
      // The DISCOURAGED CWE has no note, and the note is only about the OWASP departure.
      expect(
        problems({ standards: standards(["A02:2025"], ["CWE-693"], { owaspDeparture: note }) }),
      ).toEqual([
        "PG-TEST-001: CWE-693 is DISCOURAGED by MITRE; use a specific CWE or add standards.mappingNote.discouragedCwe",
      ]);
    });

    it("checks each note like any other prose", () => {
      expect(
        problems({
          standards: standards(["A06:2025"], ["CWE-693"], {
            discouragedCwe: { en: "Reason.", ko: "" },
          }),
        }),
      ).toEqual([
        "PG-TEST-001: standards.mappingNote.discouragedCwe.ko is empty",
        "PG-TEST-001: standards.mappingNote.discouragedCwe.ko contains no Korean",
      ]);
    });

    it("requires a recorded MITRE mapping usage for every CWE", () => {
      expect(problems({ standards: standards([], ["CWE-9999"]) })).toEqual([
        "PG-TEST-001: CWE-9999 has no recorded MITRE mapping usage; read its Vulnerability Mapping Notes",
      ]);
    });

    it("copies the note so callers cannot mutate the definition", () => {
      const def = definition({
        standards: standards(["A06:2025"], ["CWE-693"], { discouragedCwe: note }),
      });
      const rule = defineRule(def);
      expect(rule.metadata.standards.mappingNote?.discouragedCwe).toEqual(note);
      expect(rule.metadata.standards.mappingNote?.discouragedCwe).not.toBe(note);
    });
  });

  it("rejects a mistyped OWASP id at compile time", () => {
    // @ts-expect-error A5:2025 is not an OWASP Top 10 2025 id
    definition({ standards: { owasp: ["A5:2025"], cwe: [], cert: [] } });
    expect(true).toBe(true);
  });
});
