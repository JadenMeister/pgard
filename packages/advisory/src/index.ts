export {
  scanDependencies,
  type DependencyScanOptions,
  type DependencyScanOutput,
} from "./scan-dependencies.js";
export {
  ADVISORY_DB_ENV,
  MAX_ADVISORY_AGE_DAYS,
  isVersionAffected,
  loadAdvisoryDb,
  parseOsvRecord,
  readAdvisoryDbStatus,
  type Advisory,
  type AdvisoryDbState,
  type AdvisoryDbStatus,
  type Ecosystem,
} from "./osv-db.js";
export { DEPENDENCY_RULE, listAdvisoryRules } from "./rules.js";
export {
  parseGoMod,
  parseGoSum,
  parsePackageLock,
  parsePnpmLock,
  parseYarnLock,
  type ResolvedPackage,
} from "./lockfiles.js";
export { compareVersions } from "./version.js";
