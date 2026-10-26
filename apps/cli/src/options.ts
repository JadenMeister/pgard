import { isValidPort } from "@pgard/http-local";
import { isReportFormat, type ReportFormat } from "@pgard/report";

export type ScanVariant = "default" | "code" | "history" | "web" | "all";
export type RuleLanguage = "js" | "ts" | "react" | "vue" | "go";
export const RULE_LANGUAGES: readonly RuleLanguage[] = ["js", "ts", "react", "vue", "go"];

export type OutputFormat = "text" | "json";
export const OUTPUT_FORMATS: readonly OutputFormat[] = ["text", "json"];

export interface ReportRequest {
  format: ReportFormat;
  outputDir: string;
}

export type ParsedCommand =
  | { kind: "menu" }
  | { kind: "help"; topic: HelpTopic }
  | { kind: "version" }
  | { kind: "project-verify"; noBrowser: boolean }
  | {
      kind: "scan";
      variant: ScanVariant;
      port: number | null;
      report: ReportRequest | null;
      noBrowser: boolean;
      /** `json` prints only the redacted ScanResult on stdout. */
      format: OutputFormat;
      /** List every finding and location instead of collapsing test, fixture and vendored ones. */
      allFindings: boolean;
      /** `--no-store`: do not keep this scan's result on this computer. */
      noStore?: boolean;
    }
  | { kind: "history-clear"; repo: string | null }
  | { kind: "dashboard"; targetPort: number | null; noBrowser: boolean }
  | { kind: "rules-list"; language: RuleLanguage | null }
  | { kind: "doctor" }
  | { kind: "advisories-update" }
  | { kind: "login"; noBrowser: boolean }
  | { kind: "logout" };

export type HelpTopic =
  | "main"
  | "project"
  | "project verify"
  | "scan"
  | "dashboard"
  | "rules"
  | "rules list"
  | "doctor"
  | "advisories"
  | "advisories update"
  | "login"
  | "logout"
  | "history"
  | "history clear";

export class UsageError extends Error {
  readonly helpTopic: HelpTopic;
  constructor(message: string, helpTopic: HelpTopic = "main") {
    super(message);
    this.name = "UsageError";
    this.helpTopic = helpTopic;
  }
}

type OptionName =
  "--port" | "--target-port" | "--report" | "--output-dir" | "--language" | "--format" | "--repo";
const VALUE_OPTIONS: readonly OptionName[] = [
  "--port",
  "--target-port",
  "--report",
  "--output-dir",
  "--language",
  "--format",
  "--repo",
];

/** Flag (no value): do not open GitHub pages in the browser automatically; links are printed. */
const NO_BROWSER_FLAG = "--no-browser";
/** Flag (no value), `pgard scan` only: do not keep this scan's result locally. */
const NO_STORE_FLAG = "--no-store";
/** Flag (no value), `pgard history clear` only: explicit "every repository" (the default). */
const ALL_FLAG = "--all";

/** Flag (no value): list every finding and location in the terminal result. */
const ALL_FINDINGS_FLAG = "--all-findings";

interface SplitArgs {
  positionals: string[];
  options: Map<OptionName, string>;
  isHelp: boolean;
  isVersion: boolean;
  noBrowser: boolean;
  noStore: boolean;
  all: boolean;
  allFindings: boolean;
}

/** Splits argv into positionals and known options; anything unknown is a usage error. */
function splitArgs(argv: readonly string[], topic: () => HelpTopic): SplitArgs {
  const positionals: string[] = [];
  const options = new Map<OptionName, string>();
  let isHelp = false;
  let isVersion = false;
  let noBrowser = false;
  let noStore = false;
  let all = false;
  let allFindings = false;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index] ?? "";
    if (arg === "--help" || arg === "-h") {
      isHelp = true;
      continue;
    }
    if (arg === "--version" || arg === "-V") {
      isVersion = true;
      continue;
    }
    if (arg === NO_BROWSER_FLAG) {
      if (noBrowser)
        throw new UsageError(`Option ${NO_BROWSER_FLAG} was given more than once.`, topic());
      noBrowser = true;
      continue;
    }
    if (arg === NO_STORE_FLAG || arg === ALL_FLAG) {
      const isStore = arg === NO_STORE_FLAG;
      if (isStore ? noStore : all) {
        throw new UsageError(`Option ${arg} was given more than once.`, topic());
      }
      if (isStore) noStore = true;
      else all = true;
      continue;
    }
    if (arg === ALL_FINDINGS_FLAG) {
      if (allFindings)
        throw new UsageError(`Option ${ALL_FINDINGS_FLAG} was given more than once.`, topic());
      allFindings = true;
      continue;
    }
    if (arg === "--") {
      throw new UsageError('"--" is not supported.', topic());
    }
    if (arg.startsWith("-")) {
      const equalsIndex = arg.indexOf("=");
      const name = (equalsIndex === -1 ? arg : arg.slice(0, equalsIndex)) as OptionName;
      if (!VALUE_OPTIONS.includes(name)) {
        throw new UsageError(`Unknown option: ${arg.slice(0, 40)}`, topic());
      }
      let value: string | undefined;
      if (equalsIndex !== -1) {
        value = arg.slice(equalsIndex + 1);
      } else {
        value = argv[index + 1];
        index += 1;
      }
      if (value === undefined || value === "" || (equalsIndex === -1 && value.startsWith("-"))) {
        throw new UsageError(`Option ${name} requires a value.`, topic());
      }
      if (options.has(name)) {
        throw new UsageError(`Option ${name} was given more than once.`, topic());
      }
      options.set(name, value);
      continue;
    }
    positionals.push(arg);
  }
  return { positionals, options, isHelp, isVersion, noBrowser, noStore, all, allFindings };
}

function parsePortOption(name: string, value: string, topic: HelpTopic): number {
  const port = /^[0-9]{1,5}$/.test(value) ? Number(value) : Number.NaN;
  if (!isValidPort(port)) {
    throw new UsageError(
      `${name} must be an integer from 1 to 65535 (got "${value.slice(0, 20)}").`,
      topic,
    );
  }
  return port;
}

function rejectOptions(
  split: SplitArgs,
  allowed: readonly OptionName[],
  topic: HelpTopic,
  where: string,
  allowNoBrowser = false,
  allowAllFindings = false,
): void {
  if (split.allFindings && !allowAllFindings) {
    throw new UsageError(`Option ${ALL_FINDINGS_FLAG} is not available for ${where}.`, topic);
  }
  if (split.noBrowser && !allowNoBrowser) {
    throw new UsageError(`Option ${NO_BROWSER_FLAG} is not available for ${where}.`, topic);
  }
  for (const name of split.options.keys()) {
    if (!allowed.includes(name)) {
      throw new UsageError(`Option ${name} is not available for ${where}.`, topic);
    }
  }
}

function rejectExtraPositionals(extra: readonly string[], topic: HelpTopic): void {
  if (extra.length > 0) {
    throw new UsageError(`Unexpected argument: ${(extra[0] ?? "").slice(0, 40)}`, topic);
  }
}

function parseReport(split: SplitArgs): ReportRequest | null {
  const format = split.options.get("--report");
  const outputDir = split.options.get("--output-dir");
  if (format === undefined && outputDir === undefined) return null;
  if (format === undefined || outputDir === undefined) {
    throw new UsageError("--report and --output-dir must be used together.", "scan");
  }
  if (!isReportFormat(format)) {
    throw new UsageError(
      `--report must be html, pdf or both (got "${format.slice(0, 20)}").`,
      "scan",
    );
  }
  return { format, outputDir };
}

function parseFormat(split: SplitArgs): OutputFormat {
  const value = split.options.get("--format");
  if (value === undefined) return "text";
  if (!(OUTPUT_FORMATS as readonly string[]).includes(value)) {
    throw new UsageError(`--format must be text or json (got "${value.slice(0, 20)}").`, "scan");
  }
  return value as OutputFormat;
}

const SCAN_VARIANTS: Record<string, ScanVariant> = {
  code: "code",
  history: "history",
  web: "web",
  all: "all",
};

/**
 * Parses argv (without node and script path). Validation happens here, before any
 * authorization, scan or network activity.
 */
export function parseCommandLine(argv: readonly string[]): ParsedCommand {
  let topic: HelpTopic = "main";
  const split = splitArgs(argv, () => topic);
  const [command, sub, ...rest] = split.positionals;

  if (command === undefined) {
    if (split.isHelp) return { kind: "help", topic: "main" };
    if (split.isVersion) return { kind: "version" };
    rejectOptions(split, [], "main", "pgard");
    return { kind: "menu" };
  }
  if (split.noStore && command !== "scan") {
    throw new UsageError(`Option ${NO_STORE_FLAG} is only available for pgard scan.`, "main");
  }
  if (split.all && !(command === "history" && sub === "clear")) {
    throw new UsageError(`Option ${ALL_FLAG} is only available for pgard history clear.`, "main");
  }
  if (split.isVersion) {
    throw new UsageError("--version is only available as `pgard --version`.", "main");
  }

  switch (command) {
    case "project": {
      topic = sub === "verify" ? "project verify" : "project";
      if (split.isHelp) return { kind: "help", topic };
      if (sub !== "verify") {
        throw new UsageError(
          sub === undefined
            ? "Missing subcommand: verify"
            : `Unknown subcommand: project ${sub.slice(0, 40)}`,
          "project",
        );
      }
      rejectExtraPositionals(rest, topic);
      rejectOptions(split, [], topic, "project verify", true);
      return { kind: "project-verify", noBrowser: split.noBrowser };
    }
    case "scan": {
      topic = "scan";
      if (split.isHelp) return { kind: "help", topic };
      let variant: ScanVariant = "default";
      if (sub !== undefined) {
        const known = SCAN_VARIANTS[sub];
        if (known === undefined) {
          throw new UsageError(
            `Unknown scan type: ${sub.slice(0, 40)}. Valid scan types: ${Object.keys(SCAN_VARIANTS).join(", ")}.`,
            topic,
          );
        }
        variant = known;
      }
      rejectExtraPositionals(rest, topic);
      const isWeb = variant === "web" || variant === "all";
      rejectOptions(
        split,
        isWeb
          ? ["--port", "--report", "--output-dir", "--format"]
          : ["--report", "--output-dir", "--format"],
        topic,
        variant === "default" ? "pgard scan" : `pgard scan ${variant}`,
        true,
        true,
      );
      const portValue = split.options.get("--port");
      const port = portValue === undefined ? null : parsePortOption("--port", portValue, topic);
      return {
        kind: "scan",
        variant,
        port,
        report: parseReport(split),
        noBrowser: split.noBrowser,
        format: parseFormat(split),
        allFindings: split.allFindings,
        ...(split.noStore ? { noStore: true } : {}),
      };
    }
    case "history": {
      topic = sub === "clear" ? "history clear" : "history";
      if (split.isHelp) return { kind: "help", topic };
      if (sub !== "clear") {
        throw new UsageError(
          sub === undefined
            ? "Missing subcommand: clear"
            : `Unknown subcommand: history ${sub.slice(0, 40)}`,
          "history",
        );
      }
      rejectExtraPositionals(rest, topic);
      rejectOptions(split, ["--repo"], topic, "pgard history clear");
      const repo = split.options.get("--repo") ?? null;
      if (repo !== null && split.all) {
        throw new UsageError("--repo and --all cannot be used together.", topic);
      }
      if (repo === null && !split.all) {
        throw new UsageError(
          "history clear deletes stored results: pass --all or --repo owner/name.",
          topic,
        );
      }
      if (repo !== null && !/^[A-Za-z0-9._-]{1,100}\/[A-Za-z0-9._-]{1,100}$/.test(repo)) {
        throw new UsageError("--repo must look like owner/name.", topic);
      }
      return { kind: "history-clear", repo };
    }
    case "dashboard": {
      topic = "dashboard";
      if (split.isHelp) return { kind: "help", topic };
      rejectExtraPositionals(sub === undefined ? [] : [sub, ...rest], topic);
      rejectOptions(split, ["--target-port"], topic, "pgard dashboard", true);
      const value = split.options.get("--target-port");
      return {
        kind: "dashboard",
        noBrowser: split.noBrowser,
        targetPort: value === undefined ? null : parsePortOption("--target-port", value, topic),
      };
    }
    case "rules": {
      topic = sub === "list" ? "rules list" : "rules";
      if (split.isHelp) return { kind: "help", topic };
      if (sub !== "list") {
        throw new UsageError(
          sub === undefined
            ? "Missing subcommand: list"
            : `Unknown subcommand: rules ${sub.slice(0, 40)}`,
          "rules",
        );
      }
      rejectExtraPositionals(rest, topic);
      rejectOptions(split, ["--language"], topic, "pgard rules list");
      const language = split.options.get("--language");
      if (language !== undefined && !(RULE_LANGUAGES as readonly string[]).includes(language)) {
        throw new UsageError(`--language must be one of ${RULE_LANGUAGES.join(", ")}.`, topic);
      }
      return { kind: "rules-list", language: (language as RuleLanguage | undefined) ?? null };
    }
    case "doctor": {
      topic = "doctor";
      if (split.isHelp) return { kind: "help", topic };
      rejectExtraPositionals(sub === undefined ? [] : [sub, ...rest], topic);
      rejectOptions(split, [], topic, "pgard doctor");
      return { kind: "doctor" };
    }
    case "advisories": {
      topic = sub === "update" ? "advisories update" : "advisories";
      if (split.isHelp) return { kind: "help", topic };
      if (sub !== "update") {
        throw new UsageError(
          sub === undefined
            ? "Missing subcommand: update"
            : `Unknown subcommand: advisories ${sub.slice(0, 40)}`,
          "advisories",
        );
      }
      rejectExtraPositionals(rest, topic);
      rejectOptions(split, [], topic, "pgard advisories update");
      return { kind: "advisories-update" };
    }
    case "login":
    case "logout": {
      topic = command;
      if (split.isHelp) return { kind: "help", topic };
      rejectExtraPositionals(sub === undefined ? [] : [sub, ...rest], topic);
      rejectOptions(split, [], topic, `pgard ${command}`, command === "login");
      return command === "login"
        ? { kind: "login", noBrowser: split.noBrowser }
        : { kind: "logout" };
    }
    default:
      throw new UsageError(`Unknown command: ${command.slice(0, 40)}`, "main");
  }
}
