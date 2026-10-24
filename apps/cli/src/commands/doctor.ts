import { GITHUB_APP_CLIENT_ID_ENV, readGitHubAppClientId } from "@pgard/scan-core";
import { out, type CommandContext } from "../context.js";
import { EXIT_CODES, type ExitCode } from "../exit-codes.js";
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
  /** Required checks make `doctor` exit 4 when they fail. */
  isRequired: boolean;
}

/**
 * `pgard doctor`: environment diagnosis only. It never authorizes a scan, never prints the
 * client id value, and works outside a project.
 */
export async function runDoctor(context: CommandContext): Promise<ExitCode> {
  const { deps, io, style } = context;
  const [gitVersion, gitRoot, isGitHubReachable, discovery] = await Promise.all([
    deps.readGitVersion(),
    deps.findGitRoot(io.cwd).catch(() => null),
    deps.checkGitHubReachable(),
    deps.discoverListeningPorts(),
  ]);
  const isClientIdSet = readGitHubAppClientId(io.env) !== null;
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
    {
      label: GITHUB_APP_CLIENT_ID_ENV,
      isOk: isClientIdSet,
      detail: isClientIdSet
        ? "set"
        : "not set or invalid - set it to the client id of a registered PGARD GitHub App; until then GitHub identity is unverifiable and every scan is blocked",
      isRequired: true,
    },
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
      isOk: false,
      detail: "not bundled in this build (dependency advisories reported as not tested)",
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
  const hasRequiredFailure = checks.some((check) => check.isRequired && !check.isOk);
  return hasRequiredFailure ? EXIT_CODES.partial : EXIT_CODES.ok;
}
