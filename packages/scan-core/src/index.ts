export { runScan, ScanRequestError, isValidConfirmedWebTarget } from "./run-scan.js";
export { toRepositoryRelativePath } from "./paths.js";
export { PGARD_VERSION } from "./version.js";
export { verifyProject } from "./verify-project.js";
export { listSupportedRules, type RuleDescriptor, type RuleLanguage } from "./rules.js";
export {
  ScanCancelledError,
  type AnalyzerContext,
  type LocalAnalyzer,
  type LocalAnalyzerOutput,
  type ScanDependencies,
  type ScanProgressEvent,
  type ScanStage,
  type WebScanOptions,
  type WebScanProgress,
  type WebScanner,
} from "./types.js";
// Launcher-facing re-exports so apps depend on scan-core (and findings) only.
export {
  AUTHORIZATION_CHECK_ORDER,
  isAuthorizationAllowed,
  type AuthorizationDependencies,
  type AuthorizationOutcome,
} from "@pgard/policy";
export {
  GITHUB_APP_AUTHORIZATIONS_URL,
  DEFAULT_GITHUB_APP_CLIENT_ID,
  GITHUB_APP_CLIENT_ID_ENV,
  GitHubAuthError,
  INVALID_CLIENT_ID_OVERRIDE_MESSAGE,
  createDeviceFlowSessionProvider,
  createInMemoryCredentialStore,
  createOsCredentialStore,
  createUnavailableCredentialStore,
  isGitHubAuthError,
  resolveGitHubAppClientId,
  readStoredSignInStatus,
  removeStoredSignIn,
  signInAndStore,
  type CredentialStore,
  type DeviceUserCode,
  type GitHubAppClientIdSource,
  type GitHubSessionProvider,
  type ResolvedGitHubAppClientId,
  type RemoveStoredSignInResult,
  type SignInNotice,
  type StoredSignInStatus,
} from "@pgard/github-auth";
export { findGitRoot } from "@pgard/git-history";
