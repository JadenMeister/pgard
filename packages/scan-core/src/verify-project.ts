import {
  authorizeProject,
  type AuthorizationDependencies,
  type AuthorizationOutcome,
} from "@pgard/policy";

/**
 * `pgard project verify`: runs the same authorization gate a scan runs, without analysis.
 * The outcome is for display only and must not be reused to skip the gate in a later scan.
 */
export function verifyProject(
  projectRoot: string,
  deps: AuthorizationDependencies,
): Promise<AuthorizationOutcome> {
  return authorizeProject(projectRoot, deps);
}
