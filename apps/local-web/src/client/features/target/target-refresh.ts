import type { AuthStatus } from "../../../shared/api-types";

/**
 * What the confirmed web target depends on. The server clears the target on sign-out or when a
 * different GitHub account signs in, so the dashboard reads `GET /api/target` again whenever this
 * key changes: a finished check (each one has its own `expiresAt`), a blocked one, either
 * sign-out, or another account. `null` while a check is running: nothing to refetch yet.
 */
export function targetRefreshKey(auth: AuthStatus | null): string | null {
  if (auth === null || auth.status === "running") return null;
  return JSON.stringify([
    auth.status,
    auth.summary?.decision ?? null,
    auth.repo,
    auth.storedSignIn.status,
    auth.storedSignIn.status === "stored" ? auth.storedSignIn.login : null,
    auth.expiresAt,
  ]);
}
