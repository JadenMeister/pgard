import type { OverallStatus } from "@pgard/findings";

/** Process exit codes, as documented in `pgard --help`. */
export const EXIT_CODES = {
  /** Requested scope completed (findings may exist). */
  ok: 0,
  /** Invalid command, option, value or combination. */
  usage: 2,
  /** Repository / authorization / contribution gate failed. */
  blocked: 3,
  /** Part of the scan or the report export failed. */
  partial: 4,
  /** Internal error. */
  internal: 5,
  /** Cancelled by the user. */
  cancelled: 130,
} as const;

export type ExitCode = (typeof EXIT_CODES)[keyof typeof EXIT_CODES];

export function exitCodeForStatus(status: OverallStatus): ExitCode {
  switch (status) {
    case "completed":
      return EXIT_CODES.ok;
    case "partial":
      return EXIT_CODES.partial;
    case "blocked":
      return EXIT_CODES.blocked;
    case "failed":
      return EXIT_CODES.internal;
  }
}
