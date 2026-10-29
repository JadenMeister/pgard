import { UNSAFE_DISPLAY_CHARACTERS } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import { checkFolderName, matchRank } from "../../shared/folder-name.js";
import { BAD_NAME_HINT, foldName, parseFolderName } from "./name.js";

describe("folder names (T3)", () => {
  const bad: Array<[string, unknown, "typed" | "drop", string]> = [
    ["empty", "", "typed", "empty"],
    ["one character typed", "a", "typed", "too_short"],
    ["dot", ".", "drop", "dot"],
    ["dot dot", "..", "drop", "dot"],
    ["a path", "a/b", "typed", "slash"],
    ["a leading slash", "/etc", "drop", "slash"],
    ["a backslash", "a\\b", "typed", "slash"],
    ["NUL", "sh\0p", "typed", "control"],
    ["a control character", "sh\u0007p", "typed", "control"],
    ["a newline", "sh\nop", "typed", "control"],
    ["a right-to-left override", "shop‮gpj", "typed", "control"],
    ["a bidi isolate", "sh⁧op", "typed", "control"],
    ["a zero-width space", "sh​op", "typed", "control"],
    ["a BOM", "﻿shop", "typed", "control"],
    ["256 units", "x".repeat(256), "typed", "too_long"],
    ["a lone high surrogate", "sh\ud800op", "typed", "malformed"],
    ["a lone low surrogate", "sh\udc00op", "drop", "malformed"],
    ["a number", 42, "typed", "not_text"],
    ["null", null, "drop", "not_text"],
  ];

  for (const [label, value, source, reason] of bad) {
    it(`rejects ${label} with a message that says why and what to do`, () => {
      const parsed = parseFolderName(value, source);
      expect(parsed.ok).toBe(false);
      if (!parsed.ok) {
        expect(parsed.reason).toBe(reason);
        expect(parsed.message).toContain(BAD_NAME_HINT);
        // Never echoes the name back.
        if (typeof value === "string" && value.length > 3) {
          expect(parsed.message).not.toContain(value);
        }
      }
    });
  }

  it("accepts a one-character dropped name but not a typed one, and 255 units", () => {
    expect(parseFolderName("a", "drop").ok).toBe(true);
    expect(parseFolderName("a", "typed").ok).toBe(false);
    expect(parseFolderName("x".repeat(255), "typed").ok).toBe(true);
  });

  it("normalizes to NFC and matches NFC and NFD forms of the same name", () => {
    const nfc = "café";
    const nfd = "café";
    const parsedNfd = parseFolderName(nfd, "drop");
    expect(parsedNfd.ok && parsedNfd.name).toBe(nfc);
    const query = { name: nfc, folded: foldName(nfc) };
    expect(matchRank(nfd, query, "drop")).toBe(0);
    expect(matchRank(nfc, query, "drop")).toBe(0);
  });

  it("folds case without a locale: Turkish I only matches i", () => {
    const query = { name: "I", folded: foldName("I") };
    expect(query.folded).toBe("i");
    expect(matchRank("i", query, "drop")).toBe(1);
    expect(matchRank("ı", query, "drop")).toBeNull();
    // A process locale cannot change the result: only `toLowerCase()` is used.
    const original = String.prototype.toLocaleLowerCase;
    String.prototype.toLocaleLowerCase = function (): string {
      return "ı";
    };
    try {
      expect(foldName("I")).toBe("i");
    } finally {
      String.prototype.toLocaleLowerCase = original;
    }
  });

  it("ranks exact before folded before partial matches", () => {
    const query = { name: "shop", folded: "shop" };
    expect(matchRank("shop", query, "typed")).toBe(0);
    expect(matchRank("Shop", query, "typed")).toBe(1);
    expect(matchRank("my-shop-api", query, "typed")).toBe(2);
    expect(matchRank("my-shop-api", query, "drop")).toBeNull();
    expect(matchRank("store", query, "typed")).toBeNull();
  });

  it("rejects every character the display sanitizer would strip", () => {
    const stripped = new RegExp(UNSAFE_DISPLAY_CHARACTERS, "g");
    for (let code = 0; code < 0x3000; code += 1) {
      const char = String.fromCharCode(code);
      if (code >= 0xd800 && code <= 0xdfff) continue;
      if (!stripped.test(char)) {
        stripped.lastIndex = 0;
        continue;
      }
      stripped.lastIndex = 0;
      expect(checkFolderName(`a${char}b`, "typed").ok, `U+${code.toString(16)}`).toBe(false);
    }
  });
});
