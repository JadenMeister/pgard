import { describe, expect, it } from "vitest";
import {
  checkSite,
  checkSitePage,
  readCriteriaVersion,
} from "../../scripts/check-site-version.mjs";

const expected = { version: "0.3.0", criteria: "2026.10-mvp.6" };
const page = (hero: string, header: string) =>
  `<span class="state-unreleased">Pre-release, v0.1.0 not published yet</span><span class="state-released">${hero}</span>
<pre>127.0.0.1\n<b>${header}</b></pre>`;
const good = page("v0.3.0", "pgard 0.3.0 - detection criteria 2026.10-mvp.6");

describe("site version labels (#493)", () => {
  it("the real site matches package.json and RULE_CRITERIA_VERSION", () => {
    expect(checkSite()).toEqual([]);
  });

  it("accepts a consistent page and ignores the hidden state-unreleased text", () => {
    expect(checkSitePage("site/index.html", good, expected)).toEqual([]);
  });

  it("names the file, the found value and the expected value for a stale hero label", () => {
    const problems = checkSitePage(
      "site/ko/index.html",
      page("v0.2.0", "pgard 0.3.0 - detection criteria 2026.10-mvp.6"),
      expected,
    );
    expect(problems).toEqual(["site/ko/index.html: hero label says v0.2.0, expected v0.3.0"]);
  });

  it("flags a stale sample header version and criteria string", () => {
    const problems = checkSitePage(
      "site/index.html",
      page("v0.3.0", "pgard 0.2.0 - detection criteria 2026.10-mvp.5"),
      expected,
    );
    expect(problems).toEqual([
      "site/index.html: sample header says pgard 0.2.0, expected 0.3.0",
      "site/index.html: sample header says detection criteria 2026.10-mvp.5, expected 2026.10-mvp.6",
    ]);
  });

  it("fails when a label cannot be found, so a markup change cannot disable the check", () => {
    expect(checkSitePage("a.html", "<p>nothing</p>", expected)).toHaveLength(2);
    expect(checkSitePage("a.html", good.replace("state-released", "released"), expected)).toEqual([
      expect.stringContaining("found 0"),
    ]);
    expect(checkSitePage("a.html", good.replace("<b>", "<i>"), expected)).toEqual([
      expect.stringContaining("no sample header"),
    ]);
  });

  it("fails when the hero label appears twice", () => {
    expect(checkSitePage("a.html", good + good, expected)).toEqual([
      expect.stringContaining("found 2"),
    ]);
  });

  it("reads RULE_CRITERIA_VERSION and fails when it is missing", () => {
    expect(readCriteriaVersion('export const RULE_CRITERIA_VERSION = "2026.10-mvp.6";')).toBe(
      "2026.10-mvp.6",
    );
    expect(readCriteriaVersion("export const RULE_CRITERIA_VERSION: string = 'x.1';")).toBe("x.1");
    expect(() => readCriteriaVersion("const x = 1;")).toThrow(/RULE_CRITERIA_VERSION/);
  });
});
