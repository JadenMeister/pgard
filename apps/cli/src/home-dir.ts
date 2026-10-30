import { userInfo } from "node:os";

/**
 * The home folder to refuse: `HOME` (or `USERPROFILE` on Windows) when set and not empty,
 * otherwise the account's own home folder. `null` when neither is known: the scan is refused
 * then, because a folder could not be checked against home.
 */
export function codeOnlyHome(
  env: Readonly<Record<string, string | undefined>>,
  accountHome: () => string = () => userInfo().homedir,
): string | null {
  for (const value of [env.HOME, env.USERPROFILE]) {
    if (value !== undefined && value.trim() !== "") return value;
  }
  try {
    const fromAccount = accountHome();
    return fromAccount.trim() === "" ? null : fromAccount;
  } catch {
    return null;
  }
}
