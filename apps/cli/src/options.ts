import { RULE_LOCALES, type RuleLocale } from "@pgard/findings";
import { isValidPort } from "@pgard/http-local";
import { isReportFormat, type ReportFormat } from "@pgard/report";

export type ScanVariant = "default" | "code" | "history" | "web" | "all";
export type RuleLanguage =
  "js" | "ts" | "react" | "vue" | "go" | "java" | "kotlin" | "python" | "php";
export const RULE_LANGUAGES: readonly RuleLanguage[] = [
  "js",
  "ts",
  "react",
  "vue",
  "go",
  "java",
  "kotlin",
  "python",
  "php",
];

export type OutputFormat = "text" | "json" | "sarif";
export const OUTPUT_FORMATS: readonly OutputFormat[] = ["text", "json", "sarif"];

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
      /** `--fixes`: also show each finding's suggested-fix diff (implies `allFindings`). */
      fixes?: boolean;
      /** `--no-store`: do not keep this scan's result on this computer. */
      noStore?: boolean;
      /** `--full`: do not build on an earlier stored scan; scan everything again. */
      full?: boolean;
      /** `--panels`: after the text result, open the full-screen panel view (terminals only). */
      panels?: boolean;
      /** `--lang`: language of rule texts in the terminal result. */
      lang?: RuleLocale;
      /** `--report-lang`: language of rule texts in saved reports. */
      reportLang?: RuleLocale;
    }
  | {
      kind: "report";
      /** `null` only from the menu, which asks; the command line defaults to html. */
      format: "html" | "pdf" | null;
      /** `--output-dir`; `null` uses the default directory of the CLI deps. */
      outputDir: string | null;
      /** `--no-open`: write the file and print its path, never open it. */
      noOpen: boolean;
      lang?: RuleLocale;
    }
  | {
      kind: "sbom";
      format: "cyclonedx-json";
      outputDir: string | null;
      lang?: RuleLocale;
    }
  | { kind: "history-clear"; repo: string | null }
  | { kind: "baseline"; action: BaselineAction; fromCurrent: boolean }
  | { kind: "dashboard"; targetPort: number | null; noBrowser: boolean }
  | { kind: "web"; noBrowser: boolean; noStore: boolean }
  | { kind: "web-scope"; action: WebScopeAction; folder: string | null }
  | { kind: "rules-list"; language: RuleLanguage | null; lang?: RuleLocale }
  | { kind: "doctor" }
  | { kind: "advisories-update"; force?: boolean }
  | { kind: "login"; noBrowser: boolean }
  | { kind: "logout" }
  | { kind: "precommit"; action: PrecommitAction; lang?: RuleLocale };

export type PrecommitAction = "run" | "install" | "uninstall" | "snippet";
const PRECOMMIT_ACTIONS: readonly PrecommitAction[] = ["install", "uninstall", "snippet"];

export type WebScopeAction = "list" | "add" | "remove";
const WEB_SCOPE_ACTIONS: readonly WebScopeAction[] = ["list", "add", "remove"];

export type BaselineAction = "set" | "show" | "clear";
const BASELINE_ACTIONS: readonly BaselineAction[] = ["set", "show", "clear"];

export type HelpTopic =
  | "main"
  | "project"
  | "project verify"
  | "scan"
  | "report"
  | "sbom"
  | "dashboard"
  | "web"
  | "web scope"
  | "rules"
  | "rules list"
  | "doctor"
  | "advisories"
  | "advisories update"
  | "login"
  | "logout"
  | "history"
  | "history clear"
  | "baseline"
  | "precommit";

/** Every help topic, as a value so `pgard help <cmd> [<sub>]` can resolve to one. */
export const HELP_TOPICS: readonly HelpTopic[] = [
  "main",
  "project",
  "project verify",
  "scan",
  "report",
  "sbom",
  "dashboard",
  "web",
  "web scope",
  "rules",
  "rules list",
  "doctor",
  "advisories",
  "advisories update",
  "login",
  "logout",
  "history",
  "history clear",
  "baseline",
  "precommit",
];

/** Maps `pgard help [<cmd> [<sub>]]` to a help topic; `undefined` when there is none. */
function resolveHelpTopic(cmd: string | undefined, sub: string | undefined): HelpTopic | undefined {
  if (cmd === undefined || (cmd === "help" && sub === undefined)) return "main";
  const joined = sub === undefined ? cmd : `${cmd} ${sub}`;
  const exact = HELP_TOPICS.find((topic) => topic === joined);
  if (exact !== undefined && exact !== "main") return exact;
  if (sub === undefined) return undefined;
  const parent = HELP_TOPICS.find((topic) => topic === cmd && topic !== "main");
  if (parent === undefined) return undefined;
  // `scan code` and `baseline set` have no topic of their own: they share the command's help.
  if (cmd === "scan" && SCAN_VARIANTS[sub] !== undefined) return parent;
  if (cmd === "baseline" && BASELINE_ACTIONS.some((action) => action === sub)) return parent;
  if (cmd === "precommit" && PRECOMMIT_ACTIONS.some((action) => action === sub)) return parent;
  return undefined;
}

export class UsageError extends Error {
  readonly helpTopic: HelpTopic;
  constructor(message: string, helpTopic: HelpTopic = "main") {
    super(message);
    this.name = "UsageError";
    this.helpTopic = helpTopic;
  }
}

type OptionName =
  | "--port"
  | "--target-port"
  | "--report"
  | "--output-dir"
  | "--language"
  | "--format"
  | "--repo"
  | "--lang"
  | "--report-lang";
const VALUE_OPTIONS: readonly OptionName[] = [
  "--port",
  "--target-port",
  "--report",
  "--output-dir",
  "--language",
  "--format",
  "--repo",
  "--lang",
  "--report-lang",
];

/** Flag (no value): do not open GitHub pages in the browser automatically; links are printed. */
const NO_BROWSER_FLAG = "--no-browser";
/** Flag (no value), `pgard scan` only: do not keep this scan's result locally. */
const NO_STORE_FLAG = "--no-store";
/** Flag (no value), `pgard report` only: write the report and print its path without opening it. */
const NO_OPEN_FLAG = "--no-open";
/** Flag (no value), `pgard history clear` only: explicit "every repository" (the default). */
const ALL_FLAG = "--all";

/** Flag (no value), `pgard baseline set` only: scan now and use that scan as the baseline. */
const FROM_CURRENT_FLAG = "--from-current";

/** Flag (no value), `pgard scan` only: scan everything again instead of building on the last stored scan. */
const FULL_FLAG = "--full";

/** Flag (no value), `pgard scan` only: open the full-screen panel view over the result. */
const PANELS_FLAG = "--panels";

/** Flag (no value), `pgard advisories update` only: accept data older than the installed data. */
const FORCE_FLAG = "--force";

/** Flag (no value): list every finding and location in the terminal result. */
const ALL_FINDINGS_FLAG = "--all-findings";

/** Flag (no value), `pgard scan` only: show the suggested-fix diffs in the text result. */
const FIXES_FLAG = "--fixes";

/** The flags (options without a value): the one table the parser and the help test both use. */
const FLAG_OPTIONS = [
  [NO_BROWSER_FLAG, "noBrowser"],
  [NO_STORE_FLAG, "noStore"],
  [ALL_FLAG, "all"],
  [ALL_FINDINGS_FLAG, "allFindings"],
  [FIXES_FLAG, "fixes"],
  [FULL_FLAG, "full"],
  [FORCE_FLAG, "force"],
  [NO_OPEN_FLAG, "noOpen"],
  [PANELS_FLAG, "panels"],
  [FROM_CURRENT_FLAG, "fromCurrent"],
] as const;
type FlagKey = (typeof FLAG_OPTIONS)[number][1];

interface SplitArgs extends Record<FlagKey, boolean> {
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
  const flags: Record<FlagKey, boolean> = {
    noBrowser: false,
    noStore: false,
    all: false,
    allFindings: false,
    fixes: false,
    full: false,
    force: false,
    noOpen: false,
    panels: false,
    fromCurrent: false,
  };
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
    const flag = FLAG_OPTIONS.find(([name]) => name === arg);
    if (flag !== undefined) {
      const [name, key] = flag;
      if (flags[key]) throw new UsageError(`Option ${name} was given more than once.`, topic());
      flags[key] = true;
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
  return { positionals, options, isHelp, isVersion, ...flags };
}

/** Validates a `--lang` / `--report-lang` / `PGARD_LANG` value. */
export function parseLanguageValue(name: string, value: string, topic?: HelpTopic): RuleLocale {
  const normalized = value.trim().toLowerCase();
  if (!(RULE_LOCALES as readonly string[]).includes(normalized)) {
    throw new UsageError(
      `${name} must be one of ${RULE_LOCALES.join(", ")} (got "${value.slice(0, 20)}").`,
      topic,
    );
  }
  return normalized as RuleLocale;
}

function parseLangOption(
  split: SplitArgs,
  name: "--lang" | "--report-lang",
  topic: HelpTopic,
): RuleLocale | undefined {
  const value = split.options.get(name);
  return value === undefined ? undefined : parseLanguageValue(name, value, topic);
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
  if (split.fixes && !allowAllFindings) {
    throw new UsageError(`Option ${FIXES_FLAG} is not available for ${where}.`, topic);
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
    throw new UsageError(
      `--format must be text, json or sarif (got "${value.slice(0, 20)}").`,
      "scan",
    );
  }
  return value as OutputFormat;
}

/** Every option name the parser accepts for some command (checked by options-help.test.ts). */
export const ALL_OPTION_NAMES: readonly string[] = [
  ...VALUE_OPTIONS,
  ...FLAG_OPTIONS.map(([name]) => name),
];

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
  if (command === "help") {
    if (split.options.size > 0 || FLAG_OPTIONS.some(([, key]) => split[key])) {
      throw new UsageError("pgard help takes no options.", "main");
    }
  }
  if (split.noStore && command !== "scan" && !(command === "web" && sub === undefined)) {
    throw new UsageError(
      `Option ${NO_STORE_FLAG} is only available for pgard scan and pgard web.`,
      "main",
    );
  }
  if (split.full && command !== "scan") {
    throw new UsageError(`Option ${FULL_FLAG} is only available for pgard scan.`, "main");
  }
  if (split.force && !(command === "advisories" && sub === "update")) {
    throw new UsageError(
      `Option ${FORCE_FLAG} is only available for pgard advisories update.`,
      "main",
    );
  }
  if (split.panels && command !== "scan") {
    throw new UsageError(`Option ${PANELS_FLAG} is only available for pgard scan.`, "main");
  }
  if (split.noOpen && command !== "report") {
    throw new UsageError(`Option ${NO_OPEN_FLAG} is only available for pgard report.`, "main");
  }
  if (split.all && !(command === "history" && sub === "clear")) {
    throw new UsageError(`Option ${ALL_FLAG} is only available for pgard history clear.`, "main");
  }
  if (split.fromCurrent && !(command === "baseline" && sub === "set")) {
    throw new UsageError(
      `Option ${FROM_CURRENT_FLAG} is only available for pgard baseline set.`,
      "main",
    );
  }
  if (split.isVersion) {
    throw new UsageError("--version is only available as `pgard --version`.", "main");
  }

  switch (command) {
    case "help": {
      rejectExtraPositionals(rest.slice(1), "main");
      rejectOptions(split, [], "main", "pgard help");
      const helpTopic = resolveHelpTopic(sub, rest[0]);
      if (helpTopic === undefined) {
        throw new UsageError(
          `No help for: ${[sub, rest[0]]
            .filter((part) => part !== undefined)
            .join(" ")
            .slice(0, 40)}`,
          "main",
        );
      }
      return { kind: "help", topic: helpTopic };
    }
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
          ? ["--port", "--report", "--output-dir", "--format", "--lang", "--report-lang"]
          : ["--report", "--output-dir", "--format", "--lang", "--report-lang"],
        topic,
        variant === "default" ? "pgard scan" : `pgard scan ${variant}`,
        true,
        true,
      );
      const lang = parseLangOption(split, "--lang", topic);
      const reportLang = parseLangOption(split, "--report-lang", topic);
      if (reportLang !== undefined && split.options.get("--report") === undefined) {
        throw new UsageError("--report-lang needs --report and --output-dir.", topic);
      }
      if (split.panels && parseFormat(split) !== "text") {
        throw new UsageError(
          `${PANELS_FLAG} cannot be combined with --format ${parseFormat(split)}: stdout carries only the result document.`,
          topic,
        );
      }
      const portValue = split.options.get("--port");
      const port = portValue === undefined ? null : parsePortOption("--port", portValue, topic);
      return {
        kind: "scan",
        variant,
        port,
        report: parseReport(split),
        noBrowser: split.noBrowser,
        format: parseFormat(split),
        allFindings: split.allFindings || split.fixes,
        ...(split.fixes ? { fixes: true } : {}),
        ...(split.noStore ? { noStore: true } : {}),
        ...(split.full ? { full: true } : {}),
        ...(split.panels ? { panels: true } : {}),
        ...(lang === undefined ? {} : { lang }),
        ...(reportLang === undefined ? {} : { reportLang }),
      };
    }
    case "report": {
      topic = "report";
      if (split.isHelp) return { kind: "help", topic };
      rejectExtraPositionals(sub === undefined ? [] : [sub, ...rest], topic);
      rejectOptions(split, ["--format", "--output-dir", "--lang"], topic, "pgard report");
      const format = split.options.get("--format") ?? "html";
      if (format !== "html" && format !== "pdf") {
        throw new UsageError(`--format must be html or pdf (got "${format.slice(0, 20)}").`, topic);
      }
      const lang = parseLangOption(split, "--lang", topic);
      return {
        kind: "report",
        format,
        outputDir: split.options.get("--output-dir") ?? null,
        noOpen: split.noOpen,
        ...(lang === undefined ? {} : { lang }),
      };
    }
    case "sbom": {
      topic = "sbom";
      if (split.isHelp) return { kind: "help", topic };
      rejectExtraPositionals(sub === undefined ? [] : [sub, ...rest], topic);
      rejectOptions(split, ["--format", "--output-dir", "--lang"], topic, "pgard sbom");
      const format = split.options.get("--format") ?? "cyclonedx-json";
      if (format !== "cyclonedx-json") {
        throw new UsageError(
          `--format must be cyclonedx-json (got "${format.slice(0, 20)}").`,
          topic,
        );
      }
      const lang = parseLangOption(split, "--lang", topic);
      return {
        kind: "sbom",
        format,
        outputDir: split.options.get("--output-dir") ?? null,
        ...(lang === undefined ? {} : { lang }),
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
    case "baseline": {
      topic = "baseline";
      if (split.isHelp) return { kind: "help", topic };
      const action = BASELINE_ACTIONS.find((known) => known === sub);
      if (action === undefined) {
        throw new UsageError(
          sub === undefined
            ? "Missing subcommand: set, show or clear"
            : `Unknown subcommand: baseline ${sub.slice(0, 40)}`,
          topic,
        );
      }
      rejectExtraPositionals(rest, topic);
      rejectOptions(split, [], topic, `pgard baseline ${action}`);
      return { kind: "baseline", action, fromCurrent: split.fromCurrent };
    }
    case "precommit": {
      topic = "precommit";
      if (split.isHelp) return { kind: "help", topic };
      const action = sub === undefined ? "run" : PRECOMMIT_ACTIONS.find((known) => known === sub);
      if (action === undefined) {
        throw new UsageError(
          `Unknown subcommand: precommit ${sub?.slice(0, 40) ?? ""}. Valid: install, uninstall, snippet (or none to check the staged changes).`,
          topic,
        );
      }
      rejectExtraPositionals(rest, topic);
      rejectOptions(
        split,
        ["--lang"],
        topic,
        `pgard precommit${sub === undefined ? "" : ` ${sub}`}`,
      );
      const lang = parseLangOption(split, "--lang", topic);
      return { kind: "precommit", action, ...(lang === undefined ? {} : { lang }) };
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
    case "web": {
      if (sub === "scope") {
        topic = "web scope";
        if (split.isHelp) return { kind: "help", topic };
        const action = WEB_SCOPE_ACTIONS.find((known) => known === rest[0]);
        if (action === undefined) {
          throw new UsageError(
            rest[0] === undefined
              ? "Missing subcommand: list, add or remove"
              : `Unknown subcommand: web scope ${rest[0].slice(0, 40)}`,
            topic,
          );
        }
        const folder = rest[1] ?? null;
        if (action === "list") rejectExtraPositionals(rest.slice(1), topic);
        else if (folder === null) {
          throw new UsageError(`pgard web scope ${action} needs a folder.`, topic);
        } else rejectExtraPositionals(rest.slice(2), topic);
        rejectOptions(split, [], topic, `pgard web scope ${action}`);
        return { kind: "web-scope", action, folder };
      }
      topic = "web";
      if (split.isHelp) return { kind: "help", topic };
      rejectExtraPositionals(sub === undefined ? [] : [sub, ...rest], topic);
      rejectOptions(split, [], topic, "pgard web", true);
      return { kind: "web", noBrowser: split.noBrowser, noStore: split.noStore };
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
      rejectOptions(split, ["--language", "--lang"], topic, "pgard rules list");
      const language = split.options.get("--language");
      if (language !== undefined && !(RULE_LANGUAGES as readonly string[]).includes(language)) {
        throw new UsageError(`--language must be one of ${RULE_LANGUAGES.join(", ")}.`, topic);
      }
      const lang = parseLangOption(split, "--lang", topic);
      return {
        kind: "rules-list",
        language: (language as RuleLanguage | undefined) ?? null,
        ...(lang === undefined ? {} : { lang }),
      };
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
      return split.force
        ? { kind: "advisories-update", force: true }
        : { kind: "advisories-update" };
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
