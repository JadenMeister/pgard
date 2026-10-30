export const EXTERNAL_PACKAGES: string[];
export const REQUIRE_BANNER: string;
export interface DynamicUseAllowance {
  module: string;
  line: RegExp;
  why: string;
}
export const ALLOWED_DYNAMIC_USES: DynamicUseAllowance[];
export function npmCommand(): { file: string; prefixArgs: string[] };
export function packageNameOf(specifier: string): string;
export function findExternalViolations(
  metafile: {
    outputs: Record<string, { imports: Array<{ path: string; kind: string; external?: boolean }> }>;
  },
  dependencies: Record<string, string>,
  options?: { allowBareBuiltins?: boolean },
): string[];
export function findDynamicCodeUses(
  file: string,
  code: string,
  allowed?: DynamicUseAllowance[],
): string[];
export function shippedGrammarsReadme(text: string): string;
export function shippedNotice(text: string): string;
