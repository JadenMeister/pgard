import path from "node:path";

// The per-user data directory itself is resolved once, in the CLI, by the result-store resolver
// (`resolveStoreDirectory`); this package only decides where inside it advisory data lives.

/** Where verified OSV data lives: `<app data>/advisories/osv`. */
export function osvDataDir(appDataDir: string): string {
  return path.join(appDataDir, "advisories", "osv");
}
