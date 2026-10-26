/** A lockfile larger than this is not read (a huge monorepo lockfile is a few tens of MiB). */
export const MAX_LOCKFILE_BYTES = 64 * 1024 * 1024;
/** Upper bound on entries one lockfile may yield. */
export const MAX_ENTRIES_PER_LOCKFILE = 500_000;
export const MAX_LOCKFILES = 200;
export const MAX_VISITED_ENTRIES = 200_000;
export const MAX_MANIFEST_BYTES = 1024 * 1024;
export const MAX_MANIFESTS = 1000;
