export * from "./constants.js";
export { sanitizeDisplayText } from "./display-text.js";
export {
  assertConfirmedWebTarget,
  buildLoopbackOrigin,
  InvalidTargetError,
  isValidPort,
  parseAllowedLoopbackUrl,
  parsePort,
  type LoopbackUrlOptions,
} from "./target.js";
export {
  fetchLoopback,
  LoopbackRequestError,
  requestLoopbackOnce,
  type LoopbackFetchResult,
  type LoopbackRequestOptions,
  type LoopbackResponse,
  type ReadOnlyMethod,
  type RedirectStop,
  type RedirectStopReason,
} from "./request.js";
export {
  discoverListeningPorts,
  parseLsofOutput,
  parseProcNetTcp,
  type ListeningPort,
  type PortDiscoveryDeps,
  type PortDiscoveryMethod,
  type PortDiscoveryResult,
} from "./discover-ports.js";
export {
  createConfirmedWebTarget,
  isExplicitYes,
  probeLocalService,
  type ProbeOptions,
  type ServiceIdentity,
} from "./probe.js";
export { WEB_RULE_IDS, WEB_RULE_LIST, WEB_RULES, type WebRule } from "./rules.js";
export {
  AUTHENTICATED_NOT_AVAILABLE_NOTE,
  scanLocalWeb,
  WEB_AREA_ANONYMOUS,
  WEB_AREA_AUTHENTICATED,
  type WebScanLimits,
  type WebScanner,
  type WebScanOptions,
  type WebScanProgress,
} from "./scan-local-web.js";
export {
  EMPTY_PROJECT_SIGNALS,
  KNOWN_TOOL_NAMES,
  nameTokens,
  relatedness,
  RELATEDNESS_LABEL_MAX,
  type ProjectSignals,
  type Relatedness,
  type RelatednessReason,
  type RelatednessVerdict,
  type ServiceSignals,
} from "./relatedness.js";
export { readProjectSignals } from "./project-signals.js";
