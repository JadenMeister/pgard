export { runScan, ScanRequestError, isValidConfirmedWebTarget } from "./run-scan.js";
export {
  describeProjectConfig,
  loadProjectConfig,
  type ProjectConfigLoad,
} from "./project-config.js";
export { toRepositoryRelativePath } from "./paths.js";
export {
  STAGED_COVERAGE_AREA,
  STAGED_SCAN_BUDGET_MS,
  createStagedAnalyzer,
  describeStagedReport,
  isStagedReportIncomplete,
  type StagedScanReport,
  type StagedScanSettings,
} from "./staged-scan.js";
export {
  INCOMPLETE_SKIP_REASONS,
  STAGED_MAX_FILES,
  STAGED_MAX_FILE_BYTES,
  STAGED_MAX_TOTAL_BYTES,
  isPathInside,
  preflightIsolation,
  readRepositoryIsolation,
  readStagedTextFile,
  resolveHookIndexFile,
  resolveHooksLocation,
  type HookIndexFile,
  type HooksLocation,
  type PathModule,
  type StagedFileRead,
  type StagedSkip,
  type StagedSkipReason,
} from "@pgard/git-history";
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
  accessNoteFor,
  AUTHORIZATION_CHECK_ORDER,
  AUTHORIZATION_REASON_MAX_LENGTH,
  GUIDED_INSTALL_GITHUB_COM_ONLY_MESSAGE,
  guidedInstallRemedy,
  isAuthorizationAllowed,
  recheckOwnerApproval,
  type AccessNote,
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
  NOT_SIGNED_IN_NO_TERMINAL_MESSAGE,
  OS_KEYCHAIN_NOT_LOADED_MESSAGE,
  OS_KEYCHAIN_UNUSABLE_MESSAGE,
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
export { findGitRoot, resolveGitExecutable } from "@pgard/git-history";
export {
  blockingCoverage,
  computeAnalysisKey,
  planIncremental,
  type IncrementalBase,
  type IncrementalBaseLoad,
  type IncrementalDependencies,
  type IncrementalPlan,
} from "./incremental.js";
export {
  RULE_LOCALITY,
  unclassifiedRules,
  type RuleLocality,
  type RuleLocalityEntry,
} from "./rule-locality.js";
export {
  STALE_AFTER_DAYS as ADVISORY_STALE_AFTER_DAYS,
  osvDataDir,
  readAdvisoryStatus,
  type AdvisoryStatus,
} from "@pgard/dependencies";
