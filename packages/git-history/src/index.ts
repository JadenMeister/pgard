export {
  GitCommandError,
  buildGitArgs,
  buildGitEnv,
  runGit,
  killAllGitChildren,
  liveGitChildPids,
  type GitInvocation,
  type GitRunOptions,
  type GitRunner,
  type GitSubcommand,
} from "./run-git.js";
export { findGitRoot } from "./git-root.js";
export { resolveGitExecutable, trustedPathEntries } from "./git-executable.js";
export {
  parseGitHubRemoteUrl,
  readGitHubRemote,
  type GitHubRemoteResolution,
  type GitHubRepositoryRef,
} from "./remote.js";
export { listCommitCandidates, readHeadRevision, type CommitCandidate } from "./commits.js";
export {
  preflightIsolation,
  readRepositoryIsolation,
  type RepositoryIsolation,
} from "./isolation.js";
export {
  isAncestorCommit,
  listChangedPaths,
  scanGitHistory,
  type HistoryIncrementalBase,
  type HistoryScanMode,
  type HistoryScanOptions,
  type HistoryScanOutput,
} from "./scan-history.js";
export {
  isPathInside,
  resolveHookIndexFile,
  resolveHooksLocation,
  type HookIndexFile,
  type HooksLocation,
  type PathModule,
} from "./hook-paths.js";
export {
  INCOMPLETE_SKIP_REASONS,
  STAGED_MAX_FILES,
  STAGED_MAX_FILE_BYTES,
  STAGED_MAX_TOTAL_BYTES,
  BINARY_SNIFF_BYTES,
  decodeStagedBlob,
  isTextLike,
  readStagedChanges,
  type StagedChanges,
  type StagedFile,
  type StagedReadOptions,
  type StagedSkip,
  type StagedSkipReason,
} from "./staged.js";
export { readStagedTextFile, type StagedFileOptions, type StagedFileRead } from "./staged-file.js";
export {
  addedLineNumbers,
  scanStagedPaths,
  scanStagedSecrets,
  spanHasAddedLine,
  type StagedSecretScan,
} from "./staged-secrets.js";
export { HISTORY_RULES, listHistoryRules, type HistoryRuleId } from "./history-rules.js";
export {
  detectSecrets,
  isEnvironmentFile,
  type DetectedSecret,
  type DetectedSecretKind,
} from "./secret-patterns.js";
