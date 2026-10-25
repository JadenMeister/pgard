import {
  GITHUB_APP_CLIENT_ID_ENV,
  resolveGitHubAppClientId,
  readStoredSignInStatus,
  type ResolvedGitHubAppClientId,
  type StoredSignInStatus,
} from "@pgard/scan-core";
import { out, type CommandContext } from "../context.js";
import { EXIT_CODES, type ExitCode } from "../exit-codes.js";
import {
  formatAdvisoryStatus,
  isAdvisoryStatusOk,
  readAdvisoryStatusSafely,
} from "../ui/formatters/advisory.js";
import { safeText } from "../ui/formatters/style.js";

const MIN_NODE_VERSION = [22, 12] as const;

export function isSupportedNodeVersion(version: string): boolean {
  const [major = 0, minor = 0] = version.split(".").map((part) => Number.parseInt(part, 10));
  return (
    major > MIN_NODE_VERSION[0] || (major === MIN_NODE_VERSION[0] && minor >= MIN_NODE_VERSION[1])
  );
}

interface DoctorCheck {
  label: string;
  isOk: boolean;
  detail: string;
  /** Required checks are marked [fail] (others [warn]) when they do not pass. */
  isRequired: boolean;
}

function formatTime(epochMs: number): string {
  return new Date(epochMs).toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * Which GitHub App PGARD signs in with. The client id is public (device flow, no client secret),
 * so it is shown. A malformed override is ignored and only warned about: PGARD still works with
 * the built-in App, but the user asked for another one.
 */
function describeGitHubApp(app: ResolvedGitHubAppClientId): DoctorCheck {
  const label = "GitHub App";
  if (app.source === "env") {
    return {
      label,
      isOk: true,
      detail: `${app.clientId} from ${GITHUB_APP_CLIENT_ID_ENV} (override)`,
      isRequired: false,
    };
  }
  const builtIn = `built-in PGARD App (${app.clientId})`;
  return app.isOverrideIgnored
    ? {
        label,
        isOk: false,
        detail: `${builtIn}; ${GITHUB_APP_CLIENT_ID_ENV} is not a valid client id and was ignored`,
        isRequired: false,
      }
    : { label, isOk: true, detail: builtIn, isRequired: false };
}

/**
 * Reads the keychain entry for this App without contacting GitHub. Shows the account login and
 * expiry only; never the token.
 */
async function describeStoredSignIn(
  context: CommandContext,
  clientId: string,
): Promise<{ isOk: boolean; detail: string }> {
  let status: StoredSignInStatus;
  try {
    status = await readStoredSignInStatus(context.deps.credentialStore, clientId);
  } catch {
    status = { status: "unavailable", reason: "the OS keychain could not be read" };
  }
  if (status.status === "unavailable") {
    return {
      isOk: false,
      detail: `OS keychain unavailable (${safeText(status.reason, 200)}); each run asks for a device code`,
    };
  }
  if (status.status === "none") {
    return {
      isOk: false,
      detail: "none - run `pgard login` once; until then each run asks for a device code",
    };
  }
  const login = safeText(status.login, 40);
  const now = Date.now();
  if (status.refreshExpiresAt !== null && status.refreshExpiresAt > now) {
    return {
      isOk: true,
      detail: `${login} (OS keychain; refreshed automatically until ${formatTime(status.refreshExpiresAt)})`,
    };
  }
  if (status.expiresAt === null) {
    return { isOk: true, detail: `${login} (OS keychain; the token does not expire)` };
  }
  if (status.expiresAt > now) {
    return {
      isOk: true,
      detail: `${login} (OS keychain; expires ${formatTime(status.expiresAt)}, then pgard signs in again)`,
    };
  }
  return {
    isOk: false,
    detail: `${login} (OS keychain; expired - the next scan removes it and asks for a device code)`,
  };
}

/**
 * `pgard doctor`: environment diagnosis only. It never authorizes a scan, never prints a token,
 * and works outside a project.
 */
export async function runDoctor(context: CommandContext): Promise<ExitCode> {
  const { deps, io, style } = context;
  const [gitVersion, gitRoot, isGitHubReachable, discovery, advisory] = await Promise.all([
    deps.readGitVersion(),
    deps.findGitRoot(io.cwd).catch(() => null),
    deps.checkGitHubReachable(),
    deps.discoverListeningPorts(),
    readAdvisoryStatusSafely(deps, io.env),
  ]);
  const app = resolveGitHubAppClientId(io.env);
  const signIn = await describeStoredSignIn(context, app.clientId);
  const checks: DoctorCheck[] = [
    {
      label: "Node.js",
      isOk: isSupportedNodeVersion(deps.nodeVersion),
      detail: `${deps.nodeVersion} (requires >= ${MIN_NODE_VERSION.join(".")})`,
      isRequired: true,
    },
    {
      label: "Git",
      isOk: gitVersion !== null,
      detail: gitVersion === null ? "not found" : safeText(gitVersion, 80),
      isRequired: true,
    },
    {
      label: "Current directory",
      isOk: gitRoot !== null,
      detail:
        gitRoot === null
          ? "not inside a Git repository (scans need one)"
          : "inside a Git repository",
      isRequired: false,
    },
    {
      label: "GitHub reachability",
      isOk: isGitHubReachable,
      detail: isGitHubReachable ? "api.github.com reachable" : "api.github.com not reachable",
      isRequired: true,
    },
    describeGitHubApp(app),
    { label: "Saved GitHub sign-in", ...signIn, isRequired: false },
    {
      label: "Local port discovery",
      isOk: discovery.isAvailable,
      detail: discovery.isAvailable
        ? `${discovery.method} available (lists can be incomplete; "Other port" is always offered)`
        : `unavailable (${safeText(discovery.note ?? "unknown reason", 120)})`,
      isRequired: false,
    },
    {
      label: "Advisory database",
      isOk: isAdvisoryStatusOk(advisory),
      detail: formatAdvisoryStatus(advisory),
      isRequired: false,
    },
  ];
  out(context, style.bold("pgard doctor (diagnosis only, not an authorization)"));
  for (const check of checks) {
    const mark = check.isOk
      ? style.green("[ok]  ")
      : check.isRequired
        ? style.red("[fail]")
        : style.yellow("[warn]");
    out(context, `  ${mark} ${check.label}: ${check.detail}`);
  }
  const failedCount = checks.filter((check) => check.isRequired && !check.isOk).length;
  out(
    context,
    failedCount === 0
      ? style.green("All required checks passed.")
      : style.yellow(`${failedCount} required check(s) need attention (see [fail] above).`),
  );
  // The diagnosis itself completed; problems are reported above, not via the exit code.
  return EXIT_CODES.ok;
}
