// Light module (no compiler imports) so other packages can share the walker's ignore rules.

/** Build output, caches and VCS metadata: never entered, at any depth. */
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

/** Dependency directories that are never entered, at any depth, and listed in coverage. */
export const SKIPPED_DEPENDENCY_DIRECTORIES: ReadonlySet<string> = new Set([
  "node_modules",
  "bower_components",
]);
