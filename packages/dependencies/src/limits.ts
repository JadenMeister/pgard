/** A lockfile larger than this is not read (a huge monorepo lockfile is a few tens of MiB). */
export const MAX_LOCKFILE_BYTES = 64 * 1024 * 1024;
/** Upper bound on entries one lockfile may yield. */
export const MAX_ENTRIES_PER_LOCKFILE = 500_000;
export const MAX_LOCKFILES = 200;
export const MAX_VISITED_ENTRIES = 200_000;
export const MAX_MANIFEST_BYTES = 1024 * 1024;
export const MAX_MANIFESTS = 1000;
/** All lockfile and manifest bytes one collection may read (hard links count once). */
export const MAX_TOTAL_BYTES = 256 * 1024 * 1024;
/** Packages one collection may keep across all lockfiles. */
export const MAX_TOTAL_DEPENDENCIES = 500_000;
/** Wall-clock budget for the walk and the reads (parsing a single file cannot be interrupted). */
export const COLLECT_TIME_BUDGET_MS = 30_000;
/** Bytes of all `package.json` files one collection may read (their own pool, apart from lockfiles). */
export const MAX_MANIFEST_TOTAL_BYTES = 32 * 1024 * 1024;
/** Lines a line-based lockfile may have: a parser builds objects per line or block. */
export const MAX_LOCKFILE_LINES = 500_000;
/** JSON nesting depth and structural elements (`{`, `[`, `,`) of an npm lockfile. */
export const MAX_JSON_DEPTH = 512;
export const MAX_JSON_TOKENS = 1_500_000;
