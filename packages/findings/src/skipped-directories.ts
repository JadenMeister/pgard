/**
 * Build output, caches and VCS metadata: never entered by the source walk, at any depth. The one
 * list: the walk, the dependency collector and scan comparison all use it.
 */
export const SKIPPED_DIRECTORIES: ReadonlySet<string> = new Set([
  "dist",
  "build",
  "out",
  ".git",
  ".next",
  ".nuxt",
  ".output",
  ".svelte-kit",
  "coverage",
  ".turbo",
  ".cache",
]);

/**
 * True when the path lies below a JVM source root, `src/<set>/java` or `src/<set>/kotlin` (`main`,
 * `test`, `integrationTest`, ...). A directory named `build`, `out` or `dist` there is a package,
 * not build output, and so is a file in it. Pass a directory or a file path.
 */
export function isUnderJvmSourceRoot(relativePath: string): boolean {
  const segments = relativePath.split("/");
  for (let index = 0; index + 3 < segments.length; index += 1) {
    if (segments[index] === "src" && /^(java|kotlin)$/.test(segments[index + 2] ?? "")) return true;
  }
  return false;
}

const SOURCE_EXTENSIONS = /\.(go|py|php|java|kt|kts|ts|tsx)$/i;

/**
 * A file name that makes a skip-named directory first-party code (the walk enters such a
 * directory): Go, Python, PHP, Java, Kotlin and TypeScript source; never a `.d.ts` declaration.
 */
export function isSkipDirectorySourceFile(name: string): boolean {
  return SOURCE_EXTENSIONS.test(name) && !/\.d\.ts$/i.test(name);
}

/**
 * A source file directly inside a skip-named directory (`build/release.ts`, `scripts/build/a.go`).
 * The walk enters such a directory because of the file itself, so a finding there is an ordinary
 * finding and is never held back as "skipped".
 */
export function isFileInWalkedSkipDirectory(filePath: string): boolean {
  const segments = filePath.split("/");
  const parent = segments.at(-2);
  return (
    parent !== undefined &&
    SKIPPED_DIRECTORIES.has(parent) &&
    isSkipDirectorySourceFile(segments.at(-1) ?? "")
  );
}
