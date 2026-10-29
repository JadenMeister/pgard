export { collectDependencies } from "./collect.js";
export { parseGoMod, parseGoSum } from "./lockfiles/go.js";
export { parseNpmLock } from "./lockfiles/npm.js";
export { parsePnpmLock } from "./lockfiles/pnpm.js";
export { parseYarnLock } from "./lockfiles/yarn.js";
export type {
  CoverageStatus,
  Dependency,
  DependencyCollection,
  DependencyCoverage,
  Ecosystem,
  LockfileKind,
  ParsedLockfile,
} from "./types.js";
export { osvDataDir } from "./app-data.js";
export {
  ALLOWED_DOWNLOAD_HOSTS,
  DownloadError,
  MAX_ARCHIVE_BYTES,
  OSV_EXPORT_HOST,
  osvArchiveUrl,
} from "./osv/download.js";
export {
  STALE_AFTER_DAYS,
  readAdvisoryStatus,
  type AdvisoryStatus,
  type AdvisoryState,
  type EcosystemAdvisoryStatus,
} from "./osv/status.js";
export type { OsvMeta } from "./osv/store.js";
export {
  OSV_ECOSYSTEMS,
  updateOsvData,
  type UpdateOptions,
  type UpdateOutcome,
} from "./osv/update.js";
export { DEPENDENCY_RULE_ID, listDependencyRules } from "./rules.js";
export {
  UPDATE_HINT,
  scanDependencies,
  type DependencyScanOutput,
  type ScanDependenciesOptions,
} from "./scan.js";
export {
  AdvisoryDataError,
  matchDependencies,
  type DependencyMatch,
  type MatchResult,
} from "./match/match.js";
export { versionScheme, type VersionScheme } from "./match/version.js";
export { evaluateAffected } from "./match/range.js";
export { cvss3BaseScore, advisorySeverity, severityFromScore } from "./match/severity.js";
export type { CollectOptions } from "./types.js";
export {
  buildCycloneDxSbom,
  CYCLONEDX_SPEC_VERSION,
  purlFor,
  ROOT_REF as SBOM_ROOT_REF,
  SBOM_FORMAT,
  type BuildSbomOptions,
  type CycloneDxBom,
  type CycloneDxComponent,
  type CycloneDxProperty,
  type SbomDependency,
  type SbomEcosystem,
} from "./sbom.js";
