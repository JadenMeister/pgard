import type { AdvisoryDbStatus } from "@pgard/scan-core";
import type { CliDeps } from "../../deps.js";
import { safeText } from "./style.js";

const UNREADABLE_NOTE = "The advisory database status could not be read.";

/**
 * Reads the advisory DB status without letting a failure escape. A thrown error is reported as
 * `invalid` with a fixed note: the error message could contain the DB path, so it is never shown.
 */
export async function readAdvisoryStatusSafely(
  deps: CliDeps,
  env: Readonly<Record<string, string | undefined>>,
): Promise<AdvisoryDbStatus> {
  try {
    return await deps.readAdvisoryDbStatus(env);
  } catch {
    return {
      status: "invalid",
      version: null,
      updatedAt: null,
      advisoryCount: 0,
      note: UNREADABLE_NOTE,
    };
  }
}

/** One-line summary: `<status> - version <v>, updated <date> - <note>`. Never includes the path. */
export function formatAdvisoryStatus(status: AdvisoryDbStatus): string {
  const version = status.version === null ? "none" : safeText(status.version, 80);
  const updated = status.updatedAt === null ? "never" : safeText(status.updatedAt, 40);
  return `${status.status} - version ${version}, updated ${updated} - ${safeText(status.note, 300)}`;
}
