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
