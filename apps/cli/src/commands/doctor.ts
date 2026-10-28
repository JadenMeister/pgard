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
import { cliText, type CliText } from "../ui/i18n/cli-text.js";
import { localizeKeychainReason } from "../ui/i18n/command-text.js";

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
function describeGitHubApp(app: ResolvedGitHubAppClientId, t: CliText): DoctorCheck {
  const text = t.commands.doctor;
  const label = text.labels.app;
  switch (app.source) {
    case "default":
      return { label, isOk: true, detail: text.builtInApp(app.clientId), isRequired: true };
    case "env":
      return {
        label,
        isOk: true,
        detail: text.envApp(app.clientId, GITHUB_APP_CLIENT_ID_ENV),
        isRequired: true,
      };
    case "invalid":
      return { label, isOk: false, detail: text.invalidApp(app.message), isRequired: true };
  }
}

/**
 * Reads the keychain entry for this App without contacting GitHub. Shows the account login and
 * expiry only; never the token.
 */
async function describeStoredSignIn(
  context: CommandContext,
  clientId: string | null,
  t: CliText,
): Promise<{ isOk: boolean; detail: string }> {
  const text = t.commands.doctor;
  if (clientId === null) {
    return { isOk: false, detail: text.signInNotChecked(GITHUB_APP_CLIENT_ID_ENV) };
  }
  let status: StoredSignInStatus;
  try {
    status = await readStoredSignInStatus(context.deps.credentialStore, clientId);
  } catch {
    status = { status: "unavailable", reason: text.keychainUnreadable };
  }
  if (status.status === "unavailable") {
    return {
      isOk: false,
      detail: text.keychainUnavailable(
        localizeKeychainReason(safeText(status.reason, 200), t.commands.signIn),
      ),
    };
  }
  if (status.status === "none") {
    return { isOk: false, detail: text.signInNone };
  }
  const login = safeText(status.login, 40);
  const now = Date.now();
  if (status.refreshExpiresAt !== null && status.refreshExpiresAt > now) {
    return { isOk: true, detail: text.signInRefreshed(login, formatTime(status.refreshExpiresAt)) };
  }
  if (status.expiresAt === null) {
    return { isOk: true, detail: text.signInNoExpiry(login) };
  }
  if (status.expiresAt > now) {
    return { isOk: true, detail: text.signInExpires(login, formatTime(status.expiresAt)) };
  }
  return { isOk: false, detail: text.signInExpired(login) };
}

/** Age of the downloaded OSV data, from local metadata only (no network). */
async function describeAdvisoryData(context: CommandContext, t: CliText): Promise<DoctorCheck> {
  const text = t.commands.doctor;
  const label = text.labels.advisories;
  const appDataDir = context.deps.appDataDir;
  if (appDataDir === null) {
    return { label, isOk: false, detail: text.advisoryNoHome, isRequired: false };
  }
  let status;
  try {
    status = await context.deps.readAdvisoryStatus(appDataDir, context.deps.now());
  } catch {
    return { label, isOk: false, detail: text.advisoryUnreadable, isRequired: false };
  }
  const ages = status.ecosystems
    .map((entry) =>
      entry.fetchedAt === null
        ? text.advisoryNone(entry.ecosystem)
        : text.advisoryAge(
            entry.ecosystem,
            entry.fetchedAt.slice(0, 10),
            entry.ageDays,
            entry.state === "damaged",
            entry.modifiedMax === null ? null : entry.modifiedMax.slice(0, 10),
            entry.dataAgeDays,
          ),
    )
    .join(", ");
  switch (status.overall) {
    case "fresh":
      return { label, isOk: true, detail: ages, isRequired: false };
    case "stale":
      return { label, isOk: false, detail: text.advisoryStale(ages), isRequired: false };
    case "damaged":
      return { label, isOk: false, detail: text.advisoryDamaged(ages), isRequired: false };
    case "none":
      return { label, isOk: false, detail: text.advisoryMissing(ages), isRequired: false };
  }
}

/**
 * `pgard doctor`: environment diagnosis only. It never authorizes a scan, never prints a token,
 * and works outside a project.
 */
export async function runDoctor(context: CommandContext): Promise<ExitCode> {
  const { deps, io, style } = context;
  const t = cliText(context.ruleLocale);
  const text = t.commands.doctor;
  const [gitVersion, gitRoot, isGitHubReachable, discovery] = await Promise.all([
    deps.readGitVersion(),
    deps.findGitRoot(io.cwd).catch(() => null),
    deps.checkGitHubReachable(),
    deps.discoverListeningPorts(),
  ]);
  const app = resolveGitHubAppClientId(io.env);
  const signIn = await describeStoredSignIn(context, app.clientId, t);
  const checks: DoctorCheck[] = [
    {
      label: text.labels.node,
      isOk: isSupportedNodeVersion(deps.nodeVersion),
      detail: text.node(deps.nodeVersion, MIN_NODE_VERSION_TEXT),
      isRequired: true,
    },
    {
      label: text.labels.git,
      isOk: gitVersion !== null,
      detail: gitVersion === null ? text.gitNotFound : safeText(gitVersion, 80),
      isRequired: true,
    },
    {
      label: text.labels.directory,
      isOk: gitRoot !== null,
      detail: gitRoot === null ? text.notInRepository : text.inRepository,
      isRequired: false,
    },
    {
      label: text.labels.reachability,
      isOk: isGitHubReachable,
      detail: isGitHubReachable ? text.reachable : text.notReachable,
      isRequired: true,
    },
    describeGitHubApp(app, t),
    { label: text.labels.signIn, ...signIn, isRequired: false },
    await describeAdvisoryData(context, t),
    {
      label: text.labels.ports,
      isOk: discovery.isAvailable,
      detail: discovery.isAvailable
        ? text.portsAvailable(discovery.method)
        : text.portsUnavailable(safeText(discovery.note ?? text.unknownReason, 120)),
      isRequired: false,
    },
  ];
  out(context, style.bold(text.title));
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
    failedCount === 0 ? style.green(text.allPassed) : style.yellow(text.needAttention(failedCount)),
  );
  // The diagnosis itself completed; problems are reported above, not via the exit code.
  return EXIT_CODES.ok;
}
