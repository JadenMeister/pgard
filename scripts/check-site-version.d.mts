export function readCriteriaVersion(source: string): string;
export function checkSitePage(
  file: string,
  html: string,
  expected: { version: string; criteria: string },
): string[];
export function checkSite(repoRoot?: string): string[];
