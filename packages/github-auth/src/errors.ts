/**
 * Error codes are stable so callers can map them without parsing messages.
 * Messages never contain tokens, device codes or response bodies.
 */
export type GitHubAuthErrorCode =
  | "missing_client_id"
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
