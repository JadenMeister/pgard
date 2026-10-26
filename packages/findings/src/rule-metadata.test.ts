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

const problems = (overrides: Partial<RuleDefinition> = {}): string[] =>
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
      problems({ standards: { owasp: ["A03:2021", "A11:2025"], cwe: [], cert: [] } }),
    ).toHaveLength(2);
  });

  it("rejects malformed CWE ids and unknown or inconsistent CERT references", () => {
    expect(problems({ standards: { owasp: [], cwe: ["79"], cert: [] } })).toHaveLength(1);
    expect(
      problems({
        standards: { owasp: [], cwe: ["CWE-78"], cert: [{ kind: "direct", id: "ZZZ99-J" }] },
      }),
    ).toHaveLength(1);
    // IDS07-J exists but does not list CWE-89.
    expect(
      problems({
        standards: {
          owasp: [],
          cwe: ["CWE-89"],
          cert: [{ kind: "via-cwe", id: "IDS07-J", cwe: "CWE-89" }],
        },
      }),
    ).toHaveLength(1);
    // The rule itself does not carry CWE-78.
    expect(
      problems({
        standards: {
          owasp: [],
          cwe: ["CWE-89"],
          cert: [{ kind: "via-cwe", id: "IDS07-J", cwe: "CWE-78" }],
        },
      }),
    ).toHaveLength(1);
  });

  it("rejects empty text and Korean text without Korean", () => {
    expect(problems({ rationale: { en: "ok", ko: "" } })).toHaveLength(2);
    expect(problems({ remediation: { en: "ok", ko: "TODO" } })).toHaveLength(1);
    expect(problems({ remediation: { en: " ", ko: "한국어" } })).toHaveLength(1);
  });
});
