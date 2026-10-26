import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { FINDING_CATEGORIES, type FindingCategory } from "@pgard/findings";
import {
  TREE_SITTER_EXTENSIONS,
  TREE_SITTER_LANGUAGES,
  type TreeSitterLanguage,
} from "../tree-sitter/languages.js";

/**
 * Fixture layout (documented in `fixtures/README.md`):
 *
 *   fixtures/<language>/<category>/vulnerable/<case>.<ext>
 *   fixtures/<language>/<category>/safe/<case>.<ext>
 *   fixtures/<language>/_parse/<case>.<ext>      parser smoke tests, not tied to a rule
 *
 * `<language>` is a TreeSitterLanguage, `<category>` a FindingCategory.
 */
export const FIXTURES_ROOT = fileURLToPath(new URL("../../fixtures", import.meta.url));

export type FixtureExpectation = "vulnerable" | "safe";

export interface FixtureCase {
  language: TreeSitterLanguage;
  category: FindingCategory;
  expectation: FixtureExpectation;
  /** File name without directory, e.g. `string-concat.java`. */
  name: string;
  absolutePath: string;
  /** Path below the fixtures root, POSIX separators. */
  relativePath: string;
}

export interface FixtureSelection {
  language?: TreeSitterLanguage;
  category?: FindingCategory;
  root?: string;
}

function directories(directory: string): string[] {
  try {
    return readdirSync(directory, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort();
  } catch {
    return [];
  }
}

function files(directory: string): string[] {
  try {
    return readdirSync(directory, { withFileTypes: true })
      .filter((entry) => entry.isFile())
      .map((entry) => entry.name)
      .sort();
  } catch {
    return [];
  }
}

/** Lists the vulnerable and safe fixtures, sorted, optionally for one language and category. */
export function listFixtures(selection: FixtureSelection = {}): FixtureCase[] {
  const root = selection.root ?? FIXTURES_ROOT;
  const cases: FixtureCase[] = [];
  for (const language of TREE_SITTER_LANGUAGES) {
    if (selection.language && selection.language !== language) continue;
    for (const category of directories(path.join(root, language))) {
      if (category.startsWith("_") || !(FINDING_CATEGORIES as readonly string[]).includes(category))
        continue;
      if (selection.category && selection.category !== category) continue;
      for (const expectation of ["vulnerable", "safe"] as const) {
        const directory = path.join(root, language, category, expectation);
        for (const name of files(directory)) {
          cases.push({
            language,
            category: category as FindingCategory,
            expectation,
            name,
            absolutePath: path.join(directory, name),
            relativePath: [language, category, expectation, name].join("/"),
          });
        }
      }
    }
  }
  return cases;
}

/** The parser smoke-test fixtures of a language (`fixtures/<language>/_parse/`). */
export function listParseFixtures(
  language: TreeSitterLanguage,
  root = FIXTURES_ROOT,
): { name: string; absolutePath: string }[] {
  const directory = path.join(root, language, "_parse");
  return files(directory).map((name) => ({ name, absolutePath: path.join(directory, name) }));
}

export function readFixture(fixture: { absolutePath: string }): string {
  return readFileSync(fixture.absolutePath, "utf8");
}

/** Returns a description of every place where the tree breaks the layout convention. */
export function validateFixtureLayout(root = FIXTURES_ROOT): string[] {
  const problems: string[] = [];
  const languages: readonly string[] = TREE_SITTER_LANGUAGES;
  for (const language of directories(root)) {
    if (!languages.includes(language)) {
      problems.push(`${language}/: not a supported language directory`);
      continue;
    }
    for (const category of directories(path.join(root, language))) {
      if (category === "_parse") continue;
      if (!(FINDING_CATEGORIES as readonly string[]).includes(category)) {
        problems.push(`${language}/${category}/: not a finding category`);
        continue;
      }
      const base = path.join(root, language, category);
      for (const child of directories(base)) {
        if (child !== "vulnerable" && child !== "safe") {
          problems.push(`${language}/${category}/${child}/: expected vulnerable/ or safe/`);
        }
      }
      for (const name of files(base)) {
        problems.push(`${language}/${category}/${name}: files belong in vulnerable/ or safe/`);
      }
      for (const expectation of ["vulnerable", "safe"]) {
        for (const name of files(path.join(base, expectation))) {
          const extension = path.extname(name);
          if (TREE_SITTER_EXTENSIONS[extension] !== language) {
            problems.push(
              `${language}/${category}/${expectation}/${name}: extension ${extension} is not ${language}`,
            );
          }
        }
      }
    }
  }
  return problems;
}

export interface FixtureReport {
  cases: number;
  /** Vulnerable fixtures where the detector found something. */
  truePositives: number;
  /** Vulnerable fixtures the detector missed. */
  missed: FixtureCase[];
  /** Safe fixtures where the detector found something. */
  falsePositives: FixtureCase[];
  /** Safe fixtures with no finding. */
  trueNegatives: number;
}

/**
 * Runs `detect` (returns the number of findings for a fixture's source) over `cases`. A rule's
 * test passes when `missed` and `falsePositives` are empty. The same report feeds the later
 * accuracy measurements.
 */
export async function runFixtures(
  cases: readonly FixtureCase[],
  detect: (fixture: FixtureCase, source: string) => number | Promise<number>,
): Promise<FixtureReport> {
  const report: FixtureReport = {
    cases: cases.length,
    truePositives: 0,
    missed: [],
    falsePositives: [],
    trueNegatives: 0,
  };
  for (const fixture of cases) {
    const found = await detect(fixture, readFixture(fixture));
    if (fixture.expectation === "vulnerable") {
      if (found > 0) report.truePositives += 1;
      else report.missed.push(fixture);
    } else if (found > 0) {
      report.falsePositives.push(fixture);
    } else {
      report.trueNegatives += 1;
    }
  }
  return report;
}
