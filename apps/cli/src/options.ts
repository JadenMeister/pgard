import { isValidPort } from "@pgard/http-local";
import { isReportFormat, type ReportFormat } from "@pgard/report";

export type ScanVariant = "default" | "code" | "history" | "web" | "all";
export type RuleLanguage = "js" | "ts" | "react" | "vue" | "go";
export const RULE_LANGUAGES: readonly RuleLanguage[] = ["js", "ts", "react", "vue", "go"];

export interface ReportRequest {
  format: ReportFormat;
  outputDir: string;
}

export type ParsedCommand =
  | { kind: "menu" }
  | { kind: "help"; topic: HelpTopic }
  | { kind: "version" }
  | { kind: "project-verify" }
  | { kind: "scan"; variant: ScanVariant; port: number | null; report: ReportRequest | null }
  | { kind: "dashboard"; targetPort: number | null }
  | { kind: "rules-list"; language: RuleLanguage | null }
  | { kind: "doctor" };

export type HelpTopic =
  "main" | "project" | "project verify" | "scan" | "dashboard" | "rules" | "rules list" | "doctor";

export class UsageError extends Error {
  readonly helpTopic: HelpTopic;
  constructor(message: string, helpTopic: HelpTopic = "main") {
    super(message);
    this.name = "UsageError";
    this.helpTopic = helpTopic;
  }
}

type OptionName = "--port" | "--target-port" | "--report" | "--output-dir" | "--language";
const VALUE_OPTIONS: readonly OptionName[] = [
  "--port",
  "--target-port",
  "--report",
  "--output-dir",
  "--language",
];

interface SplitArgs {
  positionals: string[];
  options: Map<OptionName, string>;
  isHelp: boolean;
  isVersion: boolean;
}

/** Splits argv into positionals and known options; anything unknown is a usage error. */
function splitArgs(argv: readonly string[], topic: () => HelpTopic): SplitArgs {
  const positionals: string[] = [];
  const options = new Map<OptionName, string>();
  let isHelp = false;
  let isVersion = false;
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
  return { positionals, options, isHelp, isVersion };
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
): void {
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
      rejectOptions(split, [], topic, "project verify");
      return { kind: "project-verify" };
    }
    case "scan": {
      topic = "scan";
      if (split.isHelp) return { kind: "help", topic };
      let variant: ScanVariant = "default";
      if (sub !== undefined) {
        const known = SCAN_VARIANTS[sub];
        if (known === undefined)
          throw new UsageError(`Unknown scan type: ${sub.slice(0, 40)}`, topic);
        variant = known;
      }
      rejectExtraPositionals(rest, topic);
      const isWeb = variant === "web" || variant === "all";
      rejectOptions(
        split,
        isWeb ? ["--port", "--report", "--output-dir"] : ["--report", "--output-dir"],
        topic,
        variant === "default" ? "pgard scan" : `pgard scan ${variant}`,
      );
      const portValue = split.options.get("--port");
      const port = portValue === undefined ? null : parsePortOption("--port", portValue, topic);
      return { kind: "scan", variant, port, report: parseReport(split) };
    }
    case "dashboard": {
      topic = "dashboard";
      if (split.isHelp) return { kind: "help", topic };
      rejectExtraPositionals(sub === undefined ? [] : [sub, ...rest], topic);
      rejectOptions(split, ["--target-port"], topic, "pgard dashboard");
      const value = split.options.get("--target-port");
      return {
        kind: "dashboard",
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
    default:
      throw new UsageError(`Unknown command: ${command.slice(0, 40)}`, "main");
  }
}
