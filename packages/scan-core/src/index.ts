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
  AUTHORIZATION_REASON_MAX_LENGTH,
  GUIDED_INSTALL_GITHUB_COM_ONLY_MESSAGE,
  guidedInstallRemedy,
  isAuthorizationAllowed,
  recheckOwnerApproval,
  type AuthorizationDependencies,
  type AuthorizationOutcome,
  type OwnerApprovalRecheck,
  type InstallApproval,
  type OwnerApprovalRemedy,
} from "@pgard/policy";
export {
  GITHUB_APP_AUTHORIZATIONS_URL,
  DEFAULT_GITHUB_APP_CLIENT_ID,
  DEFAULT_GITHUB_APP_SLUG,
  GITHUB_APP_CLIENT_ID_ENV,
  GITHUB_APP_SLUG_ENV,
  GUIDED_INSTALL_NEEDS_SLUG_MESSAGE,
  INVALID_APP_SLUG_OVERRIDE_MESSAGE,
  GitHubAuthError,
  buildAppInstallUrl,
  isOpenableGitHubUrl,
  openGitHubUrl,
  INVALID_CLIENT_ID_OVERRIDE_MESSAGE,
  createDeviceFlowSessionProvider,
  createInMemoryCredentialStore,
  createOsCredentialStore,
  createUnavailableCredentialStore,
  isGitHubAuthError,
  MIXED_APP_OVERRIDE_MESSAGE,
  mixedAppOverrideWarning,
  resolveGitHubAppClientId,
  resolveKeychainClientId,
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
