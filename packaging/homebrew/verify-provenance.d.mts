export const EXPECTED_REPOSITORY: string;
export const EXPECTED_WORKFLOW: string;
export function statementsOf(
  document: unknown,
): Array<{ predicateType?: string; statement: Record<string, unknown> }>;
export function provenanceProblems(input: {
  document: unknown;
  tarball: Buffer;
  version: string;
  expectedSha256?: string;
}): string[];
