import path from "node:path";
import type { Finding } from "@pgard/findings";

/**
 * Converts a finding location path to a repository-relative POSIX path. Absolute paths inside
 * the project are relativized; paths that escape the project are dropped (`null`) so no
 * absolute or outside path reaches the result.
 */
export function toRepositoryRelativePath(projectRoot: string, filePath: string): string | null {
  const isAbsolute = path.isAbsolute(filePath) || path.win32.isAbsolute(filePath);
  const relative = isAbsolute ? path.relative(projectRoot, filePath) : filePath;
  const slashed = relative.split(path.sep).join("/").replace(/\\/g, "/");
  if (slashed === "") {
    return null;
  }
  const posix = path.posix.normalize(slashed);
  if (posix === "" || posix === "." || posix === "./") {
    return null;
  }
  if (
    posix === ".." ||
    posix.startsWith("../") ||
    path.posix.isAbsolute(posix) ||
    /^[A-Za-z]:/.test(posix)
  ) {
    return null;
  }
  return posix;
}

function scrubProjectRoot(text: string, projectRoot: string): string {
  if (projectRoot.length < 2) {
    return text;
  }
  return text.split(projectRoot).join(".");
}

/** Normalizes paths and strips the absolute project root from free-text fields. */
export function normalizeFindingPaths(finding: Finding, projectRoot: string): Finding {
  const location = { ...finding.location };
  if (location.path !== null) {
    location.path = toRepositoryRelativePath(projectRoot, location.path);
  }
  return {
    ...finding,
    location,
    title: scrubProjectRoot(finding.title, projectRoot),
    evidence: scrubProjectRoot(finding.evidence, projectRoot),
    impact: scrubProjectRoot(finding.impact, projectRoot),
    recommendation: scrubProjectRoot(finding.recommendation, projectRoot),
  };
}
