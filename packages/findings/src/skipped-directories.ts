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
