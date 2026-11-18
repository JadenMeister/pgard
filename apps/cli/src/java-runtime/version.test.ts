import { describe, expect, it } from "vitest";
import { JAVA_ADVISORIES, latestListDate, type JavaAdvisory } from "./advisories.js";
import {
  compareJavaVersions,
  matchJavaAdvisories,
  parseJavaVersionOutput,
  parseJavaVersionToken,
} from "./version.js";

function parsed(text: string) {
  const version = parseJavaVersionOutput(text);
  if (version === null) throw new Error(`not parsed: ${text}`);
  return version;
}

function listedBy(token: string): string[] {
  const version = parseJavaVersionToken(token);
  if (version === null) throw new Error(`not parsed: ${token}`);
  return matchJavaAdvisories(version, JAVA_ADVISORIES).map((entry) => entry.cve);
}

describe("parseJavaVersionOutput", () => {
  it("reads the modern, legacy and build-suffixed forms", () => {
    expect(
      parsed('openjdk version "17.0.21" 2026-10-21\nOpenJDK Runtime Environment').parts,
    ).toEqual([17, 0, 21, 0]);
    const legacy = parsed('java version "1.8.0_511"\nJava(TM) SE Runtime Environment');
    expect(legacy.feature).toBe(8);
    expect(legacy.parts).toEqual([8, 0, 511, 0]);
    expect(legacy.display).toBe("1.8.0_511");
    const build = parsed('openjdk version "21.0.13+9"');
    expect(build.parts).toEqual([21, 0, 13, 0]);
    expect(build.display).toBe("21.0.13");
    expect(parsed('openjdk version "21" 2023-09-19').parts).toEqual([21, 0, 0, 0]);
  });

  it("reads output of every common vendor", () => {
    const vendors = [
      'openjdk version "17.0.21" 2026-10-21\nOpenJDK Runtime Environment Temurin-17.0.21+9 (build 17.0.21+9)',
      'openjdk version "17.0.21" 2026-10-21 LTS\nOpenJDK Runtime Environment Corretto-17.0.21.9.1 (build 17.0.21+9-LTS)',
      'openjdk version "17.0.21" 2026-10-21 LTS\nOpenJDK Runtime Environment Zulu17.60+17-CA',
      'openjdk version "17.0.21" 2026-10-21\nOpenJDK Runtime Environment (build 17.0.21+9)\nOpenJDK 64-Bit Server VM Liberica',
      'java version "17.0.21" 2026-10-21 LTS\nJava(TM) SE Runtime Environment (build 17.0.21+9-LTS-1)',
      'java version "21.0.13" 2026-10-21\nJava(TM) SE Runtime Environment Oracle GraalVM 21.0.13+9.1',
    ];
    for (const text of vendors)
      expect(parsed(text).feature, text).toBe(17 + (text.includes('"21') ? 4 : 0));
  });

  it("marks early-access and internal builds as pre-releases", () => {
    const ea = parsed('openjdk version "25-ea" 2027-03-17');
    expect(ea.isPreRelease).toBe(true);
    expect(ea.feature).toBe(25);
    expect(parsed('openjdk version "17.0.22-internal"').isPreRelease).toBe(true);
    expect(parsed('openjdk version "17.0.21"').isPreRelease).toBe(false);
  });

  it("skips JAVA_TOOL_OPTIONS noise before the version line", () => {
    const text =
      'Picked up JAVA_TOOL_OPTIONS: -Dfile.encoding=UTF-8\nPicked up _JAVA_OPTIONS: -Xmx1g\nopenjdk version "11.0.33" 2026-10-21';
    expect(parsed(text).parts).toEqual([11, 0, 33, 0]);
    expect(parsed(text.replace(/\n/g, "\r\n")).feature).toBe(11);
  });

  it("returns null for garbage, localized, empty and half-written output", () => {
    for (const text of [
      "",
      "   \n  ",
      "command not found: java",
      '자바 버전 "17.0.21"',
      'openjdk version "17.0.21',
      'openjdk version ""',
      'openjdk version "seventeen"',
      'python version "3.12.1"',
      'openjdk version "17.x.21"',
      'openjdk version "-ea"',
      'openjdk version "0.0.1"',
      'openjdk version "1234567.0.0"',
      '\u0000\u0001\u0002 version "17"',
    ]) {
      expect(parseJavaVersionOutput(text), JSON.stringify(text)).toBeNull();
    }
  });

  it("stays fast on huge or hostile output", () => {
    const started = Date.now();
    expect(parseJavaVersionOutput("x".repeat(5_000_000))).toBeNull();
    expect(
      parseJavaVersionOutput(`${"line\n".repeat(200_000)}openjdk version "17.0.21"`),
    ).toBeNull();
    expect(parseJavaVersionOutput(`${' version "'.repeat(100_000)}`)).toBeNull();
    expect(parseJavaVersionOutput(`openjdk version "${"1.".repeat(100_000)}"`)).toBeNull();
    expect(parseJavaVersionOutput(`openjdk version "${"9".repeat(100_000)}"`)).toBeNull();
    // A version line past the first lines is not looked for (bounded work), and not invented.
    expect(Date.now() - started).toBeLessThan(2000);
  });
});

describe("parseJavaVersionToken", () => {
  it("treats 8u511 and 1.8.0_511 as the same version", () => {
    const a = parseJavaVersionToken("8u511");
    const b = parseJavaVersionToken("1.8.0_511");
    expect(a).not.toBeNull();
    expect(b).not.toBeNull();
    expect(compareJavaVersions(a!, b!)).toBe(0);
  });
});

describe("matchJavaAdvisories", () => {
  it("lists the highest listed version and every older one of the same feature release", () => {
    for (const token of ["17.0.21", "17.0.20", "17.0.1", "17.0.0", "17", "21.0.13", "21.0.2"]) {
      expect(listedBy(token), token).toEqual(["CVE-2026-91403"]);
    }
    for (const token of ["1.8.0_511", "1.8.0_5", "1.8.0", "8u511", "11.0.33", "25.0.5", "27.0.1"]) {
      expect(listedBy(token), token).toEqual(["CVE-2026-91403"]);
    }
  });

  it("does not list a newer version of a listed release", () => {
    for (const token of [
      "17.0.22",
      "17.1.0",
      "21.0.14",
      "1.8.0_512",
      "8u512",
      "11.0.34",
      "27.0.2",
    ]) {
      expect(listedBy(token), token).toEqual([]);
    }
  });

  it("does not list other feature releases, however old or new", () => {
    for (const token of [
      "22.0.2",
      "23.0.1",
      "24.0.2",
      "26.0.1",
      "28",
      "7u80",
      "1.7.0_80",
      "9.0.4",
      "10.0.2",
    ]) {
      expect(listedBy(token), token).toEqual([]);
    }
  });

  it("compares an early-access build by its number", () => {
    expect(listedBy("17.0.22-ea")).toEqual([]);
    expect(listedBy("17.0.21-ea")).toEqual(["CVE-2026-91403"]);
  });

  it("returns every listing entry when several match", () => {
    const second: JavaAdvisory = {
      ...(JAVA_ADVISORIES[0] as JavaAdvisory),
      cve: "CVE-2026-00001",
    };
    const version = parseJavaVersionToken("17.0.21")!;
    expect(matchJavaAdvisories(version, [...JAVA_ADVISORIES, second]).map((e) => e.cve)).toEqual([
      "CVE-2026-91403",
      "CVE-2026-00001",
    ]);
  });
});

describe("the shipped table", () => {
  it("has a source URL, an ISO list date and parseable versions for every entry", () => {
    expect(JAVA_ADVISORIES.length).toBeGreaterThan(0);
    for (const entry of JAVA_ADVISORIES) {
      expect(entry.cve).toMatch(/^CVE-\d{4}-\d{4,}$/);
      expect(entry.sources.length).toBeGreaterThan(0);
      for (const source of entry.sources) expect(source).toMatch(/^https:\/\/[^\s]+$/);
      expect(entry.listDate).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(Number.isNaN(Date.parse(entry.listDate))).toBe(false);
      expect(entry.affected.length).toBeGreaterThan(0);
      for (const release of entry.affected) {
        const version = parseJavaVersionToken(release.highest);
        expect(version, release.highest).not.toBeNull();
        expect(version?.feature).toBe(release.feature);
      }
    }
    expect(latestListDate()).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it("starts with CVE-2026-91403 for the six feature releases", () => {
    const entry = JAVA_ADVISORIES.find((candidate) => candidate.cve === "CVE-2026-91403");
    expect(entry?.severity).toBe("critical");
    expect(entry?.affected.map((release) => release.feature)).toEqual([8, 11, 17, 21, 25, 27]);
    expect(entry?.sources).toContain(
      "https://www.oracle.com/security-alerts/alert-cve-2026-91403.html",
    );
  });
});
