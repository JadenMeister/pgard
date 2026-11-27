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
export interface MeasureResult extends MeasureCase {
  status: string;
  partial?: boolean;
}
export const LINE_TOLERANCE: number;
export function matchCase(
  testCase: Pick<MeasureCase, "cwe" | "expect">,
  findings: MeasureFinding[],
): {
  status: "hit" | "loose" | "miss";
  matchedRules: string[];
  sameFamilyInFile: number;
  anyFindingsInFile: number;
};
export function tally(results: { status: string }[]): {
  n: number;
  hit: number;
  loose: number;
  miss: number;
  unmeasured: number;
  hitPct: string;
  loosePct: string;
};
export function renderMarkdown(
  results: MeasureResult[],
  meta: { date: string; version: string; filter?: string },
): string;
export function hasSupportedLanguage(testCase: Pick<MeasureCase, "expect">): boolean;
