import type { OverallStatus } from "@pgard/findings";

/** Process exit codes, as documented in `pgard --help`. */
export const EXIT_CODES = {
  /** Requested scope completed (findings may exist). */
  ok: 0,
  /** `pgard precommit` in block mode: the staged changes have findings, so the commit is stopped. */
  findings: 1,
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
  /** Ended by SIGTERM while the panel view was open. */
  terminated: 143,
} as const;

export type ExitCode = (typeof EXIT_CODES)[keyof typeof EXIT_CODES];

// 1 is `findings`, which only `pgard precommit` returns. A child process (the dashboard) ending
// with 1 is a crash, so it stays an internal error as before.
const KNOWN_EXIT_CODES = new Set<number>(
  Object.values(EXIT_CODES).filter((code) => code !== EXIT_CODES.findings),
);

/** Maps an exit code from another process to ours; anything unknown is an internal error. */
export function toKnownExitCode(code: number): ExitCode {
  return KNOWN_EXIT_CODES.has(code) ? (code as ExitCode) : EXIT_CODES.internal;
}

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
