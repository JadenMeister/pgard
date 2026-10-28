import { buildRuleTextCatalog, type Finding } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import { renderHtmlReport } from "./render-html.js";
import { finding, scanResult } from "./test-fixtures.js";

const CATALOG = buildRuleTextCatalog([
  {
    id: "PG-CMD-003",
    title: "Command execution",
    metadata: {
      standards: {
        owasp: ["A05:2025"],
        cwe: ["CWE-78"],
        cert: [
          { kind: "direct", id: "IDS07-J" },
          { kind: "via-cwe", id: "IDS07-J", cwe: "CWE-78" },
        ],
      },
      rationale: { en: "Shell input.", ko: "셸 입력." },
      remediation: { en: "Avoid the shell.", ko: "셸을 피하세요." },
    },
  },
  {
    id: "PG-CRYPTO-003",
    title: "Weak crypto",
    metadata: {
      standards: {
        owasp: ["A04:2025"],
        cwe: ["CWE-327"],
        cert: [{ kind: "direct", id: "MSC02-J", cause: "weak-random" }],
        noDirectCertOther: {
          en: "Other causes: related recommendation MSC61-J.",
          ko: "다른 원인: 관련 권고 MSC61-J.",
        },
      },
      rationale: { en: "Weak.", ko: "약함." },
      remediation: { en: "Use strong.", ko: "강하게." },
    },
  },
  {
    id: "PG-XSS-004",
    title: "XSS",
    metadata: {
      standards: {
        owasp: ["A05:2025"],
        cwe: ["CWE-79"],
        cert: [],
        noDirectCert: { en: "No CERT rule covers XSS.", ko: "XSS를 다루는 CERT 규칙이 없습니다." },
      },
      rationale: { en: "XSS.", ko: "XSS." },
      remediation: { en: "Encode.", ko: "인코딩하세요." },
    },
  },
]);

const at = (ruleId: string, path: string): Finding =>
  finding({
    id: `${ruleId}-${path}`,
    ruleId,
    location: { kind: "file", path, line: 1, url: null, commit: null },
  });

const render = (findings: Finding[], lang: "en" | "ko" = "en"): string =>
  renderHtmlReport(scanResult({ findings }), { lang, ruleTexts: CATALOG });

describe("CERT Java links in the HTML report", () => {
  it("shows the direct link, labelled, on a Java finding", () => {
    const html = render([at("PG-CMD-003", "src/A.java")]);
    expect(html).toContain("IDS07-J</a>");
    expect(html).toContain("(direct, Java/Kotlin)");
    expect(html).not.toContain("indirect, via");
    expect(render([at("PG-CMD-003", "src/A.kt")], "ko")).toContain("(직접, Java/Kotlin)");
  });

  it("shows only the indirect link, labelled, on a finding in another language", () => {
    for (const path of ["src/a.ts", "main.go", "app.py", "index.php"]) {
      const html = render([at("PG-CMD-003", path)]);
      expect(html, path).toContain("(indirect, via CWE-78)");
      expect(html, path).not.toContain("direct, Java");
    }
    expect(render([at("PG-CMD-003", "a.js")], "ko")).toContain("(간접, CWE-78 경유)");
  });

  it("scopes a direct link to its cause and notes the other causes", () => {
    const random = {
      ...at("PG-CRYPTO-003", "A.java"),
      references: { cwe: [], owasp: [], cve: [], cert: ["MSC02-J"] },
    };
    const des = at("PG-CRYPTO-003", "B.java");
    expect(render([random])).toContain("MSC02-J</a>");
    expect(render([random])).not.toContain("related recommendation MSC61-J");
    const desHtml = render([des]);
    expect(desHtml).not.toContain("MSC02-J</a>");
    expect(desHtml).toContain(
      "SEI CERT Java: no direct rule: Other causes: related recommendation MSC61-J.",
    );
    expect(render([{ ...des, references: { cwe: [], owasp: [], cve: [] } }], "ko")).toContain(
      "다른 원인: 관련 권고 MSC61-J.",
    );
    expect(render([at("PG-CRYPTO-003", "b.ts")])).not.toContain("MSC61-J");
  });

  it("states the missing direct rule for Java and Kotlin findings only", () => {
    expect(render([at("PG-XSS-004", "A.java")])).toContain(
      "SEI CERT Java: no direct rule: No CERT rule covers XSS.",
    );
    expect(render([at("PG-XSS-004", "A.kt")], "ko")).toContain(
      "SEI CERT Java: 직접 대응하는 규칙 없음: XSS를 다루는 CERT 규칙이 없습니다.",
    );
    expect(render([at("PG-XSS-004", "a.ts")])).not.toContain("no direct rule");
  });
});
