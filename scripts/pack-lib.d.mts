export function npmCommand(): { file: string; prefixArgs: string[] };
export function packageNameOf(specifier: string): string;
export function findExternalViolations(
  metafile: {
    outputs: Record<string, { imports: Array<{ path: string; kind: string; external?: boolean }> }>;
  },
  dependencies: Record<string, string>,
): string[];
export function findDynamicCodeUses(file: string, code: string): string[];
export function shippedGrammarsReadme(text: string): string;
export function shippedNotice(text: string): string;
