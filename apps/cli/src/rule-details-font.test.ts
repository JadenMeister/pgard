import { isPdfFontCodePoint } from "@pgard/report";
import { describe, expect, it } from "vitest";
import { getRuleTextCatalog } from "./rule-texts.js";

/**
 * The PDF embeds a font subset (packages/report/fonts/subset.py). A rule text or example that
 * uses a character outside it would print as "?" in the KO or EN PDF, so a new rule must stay
 * inside the subset or the subset must be regenerated.
 */
describe("rule details and the PDF font subset", () => {
  it("uses only characters the embedded font has, in every rule text and example", () => {
    const missing: string[] = [];
    const check = (where: string, text: string): void => {
      for (const char of text) {
        const code = char.codePointAt(0) ?? 0;
        if (char !== "\n" && char !== "\t" && !isPdfFontCodePoint(code)) {
          missing.push(`${where}: U+${code.toString(16)} ${char}`);
        }
      }
    };
    for (const [id, entry] of getRuleTextCatalog()) {
      const details = entry.details;
      expect(details, id).toBeDefined();
      for (const locale of ["en", "ko"] as const) {
        check(`${id} title ${locale}`, entry.title[locale]);
        check(`${id} rationale ${locale}`, details?.rationale[locale] ?? "");
        check(`${id} remediation ${locale}`, details?.remediation[locale] ?? "");
        for (const example of details?.examples ?? []) {
          check(`${id} example note ${locale}`, example.note?.[locale] ?? "");
        }
      }
      for (const example of details?.examples ?? []) {
        check(`${id} example`, `${example.vulnerable}${example.safe}`);
      }
    }
    expect(missing).toEqual([]);
  });
});
