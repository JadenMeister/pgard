export { runScan, ScanRequestError, isValidConfirmedWebTarget } from "./run-scan.js";
export { toRepositoryRelativePath } from "./paths.js";
export { PGARD_VERSION } from "./version.js";
export { verifyProject } from "./verify-project.js";
export { listSupportedRules, type RuleDescriptor, type RuleLanguage } from "./rules.js";
export {
  ADVISORY_DB_ENV,
  MAX_ADVISORY_AGE_DAYS,
  peekAdvisoryDb,
  readAdvisoryDbStatus,
  type AdvisoryDbState,
  type AdvisoryDbStatus,
} from "@pgard/advisory";
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
  GITHUB_APP_CLIENT_ID_ENV,
  GitHubAuthError,
  createDeviceFlowSessionProvider,
  createInMemoryCredentialStore,
  createOsCredentialStore,
  createUnavailableCredentialStore,
  isGitHubAuthError,
  readGitHubAppClientId,
  readStoredSignInStatus,
  removeStoredSignIn,
  signInAndStore,
  type CredentialStore,
  type DeviceUserCode,
  type GitHubSessionProvider,
  type RemoveStoredSignInResult,
  type SignInNotice,
  type StoredSignInStatus,
} from "@pgard/github-auth";
export { findGitRoot } from "@pgard/git-history";
