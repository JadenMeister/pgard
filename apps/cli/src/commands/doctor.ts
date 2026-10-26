import {
  GITHUB_APP_CLIENT_ID_ENV,
  resolveGitHubAppClientId,
  readStoredSignInStatus,
  type ResolvedGitHubAppClientId,
  type StoredSignInStatus,
} from "@pgard/scan-core";
import { out, type CommandContext } from "../context.js";
import { EXIT_CODES, type ExitCode } from "../exit-codes.js";
import { safeText } from "../ui/formatters/style.js";

/**
 * Oldest patched release per supported line, from the Node.js security
 * release of 2026-10-21 (CVE-2026-111497 Brotli RCE and others). Odd and
 * end-of-life lines get no fixes; lines newer than the last entry include them.
 */
const MIN_NODE_VERSIONS = [
  [22, 23, 4],
  [24, 22, 1],
  [26, 12, 1],
] as const;
const NEWEST_NODE_LINE = 26;
const MIN_NODE_VERSION_TEXT = MIN_NODE_VERSIONS.map((v) => v.join(".")).join(", ");

export function isSupportedNodeVersion(version: string): boolean {
  const [major = 0, minor = 0, patch = 0] = version
    .split(".")
    .map((part) => Number.parseInt(part, 10));
  if (major > NEWEST_NODE_LINE) return true;
  const floor = MIN_NODE_VERSIONS.find(([line]) => line === major);
  if (floor === undefined) return false;
  if (minor !== floor[1]) return minor > floor[1];
  return patch >= floor[2];
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
 * so it is shown. A malformed override is a [fail]: scans are blocked until it is fixed or unset.
 * The malformed value itself is never printed.
 */
function describeGitHubApp(app: ResolvedGitHubAppClientId): DoctorCheck {
  const label = "GitHub App";
  switch (app.source) {
    case "default":
      return {
        label,
        isOk: true,
        detail: `built-in PGARD App (${app.clientId})`,
        isRequired: true,
      };
    case "env":
      return {
        label,
        isOk: true,
        detail: `${app.clientId} from ${GITHUB_APP_CLIENT_ID_ENV} (override)`,
        isRequired: true,
      };
    case "invalid":
      return {
        label,
        isOk: false,
        detail: `${app.message} Until then GitHub identity is unverifiable and every scan is blocked.`,
        isRequired: true,
      };
  }
}

/**
 * Reads the keychain entry for this App without contacting GitHub. Shows the account login and
 * expiry only; never the token.
 */
async function describeStoredSignIn(
  context: CommandContext,
  clientId: string | null,
): Promise<{ isOk: boolean; detail: string }> {
  if (clientId === null) {
    return { isOk: false, detail: `not checked (${GITHUB_APP_CLIENT_ID_ENV} is not valid)` };
  }
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

/** Age of the downloaded OSV data, from local metadata only (no network). */
async function describeAdvisoryData(context: CommandContext): Promise<DoctorCheck> {
  const label = "Advisory data (OSV)";
  let status;
  try {
    status = await context.deps.readAdvisoryStatus(context.deps.appDataDir, context.deps.now());
  } catch {
    return { label, isOk: false, detail: "could not be read", isRequired: false };
  }
  const ages = status.ecosystems
    .map((entry) =>
      entry.fetchedAt === null
        ? `${entry.ecosystem} none`
        : `${entry.ecosystem} ${entry.fetchedAt.slice(0, 10)} (${entry.ageDays} day${entry.ageDays === 1 ? "" : "s"} old${entry.state === "damaged" ? ", files damaged" : ""})`,
    )
    .join(", ");
  switch (status.overall) {
    case "fresh":
      return { label, isOk: true, detail: ages, isRequired: false };
    case "stale":
      return {
        label,
        isOk: false,
        detail: `stale: ${ages}; run \`pgard advisories update\` (it downloads public OSV data, uploads nothing)`,
        isRequired: false,
      };
    case "damaged":
      return {
        label,
        isOk: false,
        detail: `damaged: ${ages}; run \`pgard advisories update\``,
        isRequired: false,
      };
    case "none":
      return {
        label,
        isOk: false,
        detail: `none: ${ages}; run \`pgard advisories update\` to download public OSV data (needed for dependency checks)`,
        isRequired: false,
      };
  }
}

/**
 * `pgard doctor`: environment diagnosis only. It never authorizes a scan, never prints a token,
 * and works outside a project.
 */
export async function runDoctor(context: CommandContext): Promise<ExitCode> {
  const { deps, io, style } = context;
  const [gitVersion, gitRoot, isGitHubReachable, discovery] = await Promise.all([
    deps.readGitVersion(),
    deps.findGitRoot(io.cwd).catch(() => null),
    deps.checkGitHubReachable(),
    deps.discoverListeningPorts(),
  ]);
  const app = resolveGitHubAppClientId(io.env);
  const signIn = await describeStoredSignIn(context, app.clientId);
  const checks: DoctorCheck[] = [
    {
      label: "Node.js",
      isOk: isSupportedNodeVersion(deps.nodeVersion),
      detail: `${deps.nodeVersion} (requires ${MIN_NODE_VERSION_TEXT} or a newer patch on that line)`,
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
    await describeAdvisoryData(context),
    {
      label: "Local port discovery",
      isOk: discovery.isAvailable,
      detail: discovery.isAvailable
        ? `${discovery.method} available (lists can be incomplete; "Other port" is always offered)`
        : `unavailable (${safeText(discovery.note ?? "unknown reason", 120)})`,
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
