export interface MeasureCase {
  id?: string;
  language: string;
  cwe: string[];
  doubtful: boolean;
  inScope: boolean;
  expect: { file: string; startLine?: number; endLine?: number }[];
}
export interface MeasureFinding {
  ruleId: string;
  path: string | null;
  line: number | null;
}
export interface MeasureCoverage {
  area: string;
  status: string;
  ruleIds: string[];
}
export interface MeasureResult extends MeasureCase {
  status: string;
  partial?: boolean;
}
export const LINE_TOLERANCE: number;
export const REPO_PATTERN: RegExp;
export const SHA_PATTERN: RegExp;
export function validRepo(repo: unknown): boolean;
export function validSha(sha: unknown): boolean;
export function cacheDirName(repo: string): string;
export function positiveInt(value: unknown): number | null;
export function gapAreas(coverage: MeasureCoverage[]): string[];
export function matchCase(
  testCase: Pick<MeasureCase, "cwe" | "expect">,
  findings: MeasureFinding[],
): {
  status: "hit" | "loose" | "miss";
  matchedRules: string[];
  sameFamilyInFile: number;
  anyFindingsInFile: number;
};
export function judgeCase(
  testCase: Pick<MeasureCase, "cwe" | "expect">,
  findings: MeasureFinding[],
  coverage: MeasureCoverage[],
): {
  status: "hit" | "loose" | "miss" | "not-tested" | "unsupported-language" | "no-rule";
  matchedRules: string[];
  sameFamilyInFile: number;
  anyFindingsInFile: number;
  partial: boolean;
  partialAreas: string[];
};
export function fixCheck(
  testCase: Pick<MeasureCase, "cwe" | "expect">,
  matchedRules: string[],
  fixFindings: MeasureFinding[],
  fixHasExpectedFile: boolean,
): { fixGone: boolean | null; fixNote: string | null };
export function tally(results: { status: string; partial?: boolean }[]): {
  n: number;
  ruleN: number;
  hit: number;
  loose: number;
  miss: number;
  notTested: number;
  noRule: number;
  unmeasured: number;
  partial: number;
  hitPct: string;
  loosePct: string;
};
export function renderMarkdown(
  results: MeasureResult[],
  meta: { date: string; version: string; filter?: string },
): string;
