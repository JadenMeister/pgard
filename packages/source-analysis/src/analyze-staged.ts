import path from "node:path";
import type { Finding } from "@pgard/findings";
import { analyzeFile } from "./analyze-file.js";
import { EXTENSIONS } from "./walk.js";

const MINIFIED_BUNDLE = /\.min\.(js|mjs|cjs)$/;

/**
 * Runs the file-local source rules on one file's text (JavaScript, TypeScript, Vue, Go), for
 * `pgard precommit`. Rules that need the whole project (a missing CSRF protection or an
 * unprotected route anywhere in it) are not evaluated here; `pgard scan` does that. Returns
 * `null` when the file is of a kind the source rules do not read, so the caller can say it was
 * not covered.
 */
export function analyzeStagedSource(relativePath: string, content: string): Finding[] | null {
  const name = path.posix.basename(relativePath);
  if (name.endsWith(".d.ts") || MINIFIED_BUNDLE.test(name)) return null;
  const language = EXTENSIONS[path.posix.extname(name)];
  if (language === undefined) return null;
  return analyzeFile({ relativePath, language }, content, "").findings;
}
