export const VERSION_PATTERN: RegExp;
export const MIN_AGE_MS: number;
export function compareVersions(a: string, b: string): -1 | 0 | 1;
export function decideUpdate(input: {
  current: string;
  latest: string;
  requested?: string;
  time: unknown;
  now: number;
}): { version: string | null; reason: string };
