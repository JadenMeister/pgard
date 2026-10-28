import type { AuthStatus } from "../../../shared/api-types";

export type AuthState = "none" | "checking" | "signIn" | "allowed" | "blocked" | "failed";

/** One word for the header strip: where the authorization gate stands right now. */
export function authState(status: AuthStatus | null): AuthState {
  if (status === null) return "none";
  if (status.status === "running") return status.deviceCode === null ? "checking" : "signIn";
  if (status.status === "failed") return "failed";
  if (status.summary === null) return "none";
  return status.summary.decision === "allowed" ? "allowed" : "blocked";
}
