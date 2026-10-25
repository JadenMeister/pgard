/**
 * Error codes are stable so callers can map them without parsing messages.
 * Messages never contain tokens, device codes or response bodies.
 */
export type GitHubAuthErrorCode =
  /**
   * `PGARD_GITHUB_APP_CLIENT_ID` or `PGARD_GITHUB_APP_SLUG` is set but malformed; identity cannot
   * be verified. The message is fixed text naming the override.
   */
  | "invalid_client_id_override"
  | "access_denied"
  | "expired_token"
  | "refresh_failed"
  | "device_flow_disabled"
  | "incorrect_client_credentials"
  | "cancelled"
  | "network_error"
  | "http_error"
  | "unauthorized"
  | "not_found"
  /** GitHub answered 403 (not a rate limit): the token or App lacks a required permission. */
  | "forbidden"
  /** GitHub's API rate limit was reached (429, or 403 with no remaining requests). */
  | "rate_limited"
  | "result_truncated"
  | "unexpected_response";

export class GitHubAuthError extends Error {
  readonly code: GitHubAuthErrorCode;
  /** HTTP status when the error came from a GitHub response. */
  readonly status: number | null;

  constructor(code: GitHubAuthErrorCode, message: string, status: number | null = null) {
    super(message);
    this.name = "GitHubAuthError";
    this.code = code;
    this.status = status;
  }
}

export function isGitHubAuthError(error: unknown): error is GitHubAuthError {
  return error instanceof GitHubAuthError;
}
