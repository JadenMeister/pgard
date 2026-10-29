import { useCallback, useEffect, useState } from "react";
import type { AuthStatus, SignOutRequestDto } from "../../../shared/api-types";
import { apiGet, apiPost } from "../../api/client";
import { usePolling } from "../../hooks/use-polling";
import { useI18n } from "../../i18n/I18nProvider";

export interface Authorization {
  status: AuthStatus | null;
  error: string | null;
  verify: () => Promise<void>;
  signOut: (removeStored: boolean) => Promise<void>;
}

/**
 * The authorization gate's state for the whole dashboard: the header strip shows it and starts a
 * check, the overview shows the details. Loads the current state once (so a keychain sign-in is
 * visible before the first check) and polls while a check runs.
 */
export function useAuthorization(enabled: boolean): Authorization {
  const { m } = useI18n();
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  usePolling(
    async () => setStatus(await apiGet<AuthStatus>("/api/auth")),
    1000,
    status?.status === "running",
  );

  useEffect(() => {
    if (!enabled) return;
    void apiGet<AuthStatus>("/api/auth")
      .then(setStatus)
      .catch(() => undefined);
  }, [enabled]);

  const verify = useCallback(async (): Promise<void> => {
    setError(null);
    try {
      setStatus(await apiPost<AuthStatus>("/api/auth/verify"));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : m.common.requestFailed);
    }
  }, [m]);

  const signOut = useCallback(
    async (removeStored: boolean): Promise<void> => {
      setError(null);
      try {
        const body: SignOutRequestDto = { removeStored };
        setStatus(await apiPost<AuthStatus>("/api/auth/sign-out", body));
      } catch (caught) {
        setError(caught instanceof Error ? caught.message : m.common.requestFailed);
      }
    },
    [m],
  );

  return { status, error, verify, signOut };
}
