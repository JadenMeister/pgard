export const ALLOWED_LICENSES: string[];
export const LICENSE_OVERRIDES: Record<string, { license: string; text?: string }>;
export interface BundledPackage {
  name: string;
  version: string;
  license: string | null;
  dir: string;
  files: Array<{ name: string; text: string }>;
}
export function packageOfInput(inputPath: string): { name: string; dir: string } | null;
export function declaredLicense(manifest: Record<string, unknown>): string | null;
export function isAllowedExpression(expression: string, allowed?: string[]): boolean;
export function licenseFilesOf(packageDir: string): string[];
export function bundledPackages(
  metafile: {
    outputs: Record<string, { inputs: Record<string, { bytesInOutput: number }> }>;
  },
  root: string,
  overrides?: Record<string, { license: string; text?: string }>,
): BundledPackage[];
export function licenseProblems(packages: BundledPackage[], allowed?: string[]): string[];
export function renderBundledNotice(packages: BundledPackage[]): string;
export function noticeProblems(packages: BundledPackage[], notice: string): string[];
