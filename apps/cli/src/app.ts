import type { RuleLocale } from "@pgard/findings";
import { stopBrowserOffers } from "./flows/browser.js";
import { PGARD_VERSION } from "@pgard/scan-core";
import { createCancelController, type InterruptSource } from "./adapters/cancel.js";
import {
  createKeyReader,
  isInteractive,
  isInteractiveOnStderr,
  type CliIo,
} from "./adapters/terminal.js";
import { runAdvisoriesUpdate } from "./commands/advisories.js";
import { runBaseline } from "./commands/baseline.js";
import { runDashboard } from "./commands/dashboard.js";
import { runDoctor } from "./commands/doctor.js";
import { runHistoryClear } from "./commands/history.js";
import { runLogin, runLogout } from "./commands/login.js";
import {
  runPrecommit,
  runPrecommitInstall,
  runPrecommitSnippet,
  runPrecommitUninstall,
} from "./commands/precommit/index.js";
import { runReport } from "./commands/report.js";
import { runSbom } from "./commands/sbom.js";
import { runProjectVerify } from "./commands/project/verify.js";
import { runRulesList } from "./commands/rules/list.js";
import { isMachineFormat, runScanCommand } from "./commands/scan/index.js";
import { runWeb } from "./commands/web.js";
import { runWebScope } from "./commands/web-scope.js";
import { err, out, type CommandContext } from "./context.js";
import { createDefaultDeps, type CliDeps } from "./deps.js";
import { EXIT_CODES, type ExitCode } from "./exit-codes.js";
import { runGuidedFirstRun } from "./flows/first-run.js";
import { PanelsTerminatedError } from "./flows/panels.js";
import { getHelpText } from "./help.js";
import { resolveLanguage } from "./language.js";
import { parseCommandLine, UsageError, type ParsedCommand } from "./options.js";
import { getRuleTextCatalog } from "./rule-texts.js";
import { BACK, promptChoice, UserCancelledError } from "./ui/components/prompts.js";
import { createStyle, safeText, shouldUseColor } from "./ui/formatters/style.js";
import { cliText } from "./ui/i18n/cli-text.js";

export { EXIT_CODES, type ExitCode } from "./exit-codes.js";
export type { CliIo } from "./adapters/terminal.js";
export { createDefaultDeps, type CliDeps } from "./deps.js";

export interface MainOptions {
  deps?: CliDeps;
  interrupts?: InterruptSource;
}

type RunnableCommand = Exclude<
  ParsedCommand,
  { kind: "menu" } | { kind: "help" } | { kind: "version" }
>;

async function runCommand(context: CommandContext, command: RunnableCommand): Promise<ExitCode> {
  switch (command.kind) {
    case "project-verify":
      return runProjectVerify(context);
    case "scan":
      return runScanCommand(context, command);
    case "report":
      return runReport(context, command);
    case "sbom":
      return runSbom(context, command);
    case "dashboard":
      return runDashboard(context, command.targetPort, command.noBrowser);
    case "web":
      return runWeb(context, command.noBrowser, command.noStore);
    case "web-scope":
      return runWebScope(context, command.action, command.folder);
    case "rules-list":
      return runRulesList(context, command.language);
    case "history-clear":
      return runHistoryClear(context, command.repo);
    case "baseline":
      return runBaseline(context, command.action, command.fromCurrent);
    case "doctor":
      return runDoctor(context);
    case "advisories-update":
      return runAdvisoriesUpdate(context, command.force === true);
    case "login":
      return runLogin(context);
    case "logout":
      return runLogout(context);
    case "precommit":
      switch (command.action) {
        case "run":
          return runPrecommit(context);
        case "install":
          return runPrecommitInstall(context);
        case "uninstall":
          return runPrecommitUninstall(context);
        case "snippet":
          return runPrecommitSnippet(context);
      }
  }
}

const MENU_HELP = `Arrow keys move, Enter selects, Esc goes back, ? shows help, Ctrl+C asks to cancel.
Every scan checks repository authorization again; only the GitHub sign-in is reused
(from the OS keychain). Scan results are stored locally unless you pass --no-store
(see pgard history clear); dashboard scans are never stored.`;

const MENU_CHOICES: ReadonlyArray<{
  label: string;
  hint: string;
  value: RunnableCommand | "quit";
}> = [
  {
    label: "Verify project",
    hint: "authorization checks",
    value: { kind: "project-verify", noBrowser: false },
  },
  {
    label: "Scan code + history",
    hint: "pgard scan",
    value: {
      kind: "scan",
      variant: "default",
      port: null,
      report: null,
      noBrowser: false,
      format: "text",
      allFindings: false,
    },
  },
  {
    label: "Scan the current files (code only)",
    hint: "pgard scan code --code-only",
    value: {
      kind: "scan",
      variant: "code",
      // The explicit code-only choice (#414 D1): no authorization, no prompt.
      codeOnly: true,
      port: null,
      report: null,
      noBrowser: false,
      format: "text",
      allFindings: false,
    },
  },
  {
    label: "Scan Git history",
    hint: "pgard scan history",
    value: {
      kind: "scan",
      variant: "history",
      port: null,
      report: null,
      noBrowser: false,
      format: "text",
      allFindings: false,
    },
  },
  {
    label: "Scan local web service",
    hint: "pgard scan web",
    value: {
      kind: "scan",
      variant: "web",
      port: null,
      report: null,
      noBrowser: false,
      format: "text",
      allFindings: false,
    },
  },
  {
    label: "Scan all",
    hint: "code + history + web",
    value: {
      kind: "scan",
      variant: "all",
      port: null,
      report: null,
      noBrowser: false,
      format: "text",
      allFindings: false,
    },
  },
  {
    label: "Build report from last scan",
    hint: "pgard report",
    value: { kind: "report", format: null, outputDir: null, noOpen: false },
  },
  {
    label: "Open dashboard",
    hint: "local web app",
    value: { kind: "dashboard", targetPort: null, noBrowser: false },
  },
  { label: "List rules", hint: "pgard rules list", value: { kind: "rules-list", language: null } },
  { label: "Doctor", hint: "environment diagnosis", value: { kind: "doctor" } },
  { label: "Quit", hint: "", value: "quit" },
];

/** The menu entries; the report and code-only entries have text in both languages. */
function menuChoicesFor(context: CommandContext): typeof MENU_CHOICES {
  const text = cliText(context.ruleLocale);
  const t = text.commands.reportCommand;
  return MENU_CHOICES.map((choice) => {
    if (choice.value === "quit") return choice;
    if (choice.value.kind === "report") return { ...choice, label: t.menuLabel, hint: t.menuHint };
    if (choice.value.kind === "scan" && choice.value.variant === "code") {
      return { ...choice, label: text.codeOnly.menuLabel };
    }
    return choice;
  });
}

async function runMenu(context: CommandContext): Promise<ExitCode> {
  if (context.keys === null) {
    err(context, "The interactive menu needs a terminal. Run `pgard --help` for commands.");
    return EXIT_CODES.usage;
  }
  const prompts = {
    keys: context.keys,
    out: context.io.stdout,
    style: context.style,
    helpText: MENU_HELP,
  };
  // A first run (no stored sign-in) is walked through sign-in, App install and a first scan.
  await runGuidedFirstRun(context);
  let lastExitCode: ExitCode = EXIT_CODES.ok;
  for (;;) {
    out(context, "");
    const picked = await promptChoice(prompts, `pgard ${PGARD_VERSION}`, menuChoicesFor(context));
    // Leaving the menu is a normal end, whatever the last command returned.
    if (picked === BACK || picked === "quit") return EXIT_CODES.ok;
    lastExitCode = await runCommand(context, picked);
    if (picked.kind === "dashboard") return lastExitCode;
    out(
      context,
      context.style.dim(`\n(exit status ${lastExitCode}) Press any key to return to the menu.`),
    );
    await context.keys.readKey();
  }
}

/** CLI entry point. Returns the process exit code; never calls `process.exit` itself. */
export async function main(
  argv: readonly string[],
  io: CliIo,
  options: MainOptions = {},
): Promise<ExitCode> {
  const errStyle = createStyle(shouldUseColor(io.stderr, io.env));
  let command: ParsedCommand;
  let ruleLocale: RuleLocale = "en";
  let reportLocale: RuleLocale = "en";
  try {
    command = parseCommandLine(argv);
    if (
      command.kind === "scan" ||
      command.kind === "rules-list" ||
      command.kind === "menu" ||
      command.kind === "report" ||
      command.kind === "sbom" ||
      command.kind === "precommit"
    ) {
      const flag = "lang" in command && command.lang !== undefined ? command.lang : null;
      ruleLocale = resolveLanguage({ flag, env: io.env });
      reportLocale = command.kind === "scan" ? (command.reportLang ?? ruleLocale) : ruleLocale;
    } else if (command.kind === "doctor" || command.kind === "login" || command.kind === "logout") {
      // These commands only have fixed text, and it is fully translated. A bad PGARD_LANG must
      // not break them, so it falls back to the system language, with a one-line hint. The other
      // commands (project verify, dashboard, advisories update, history clear, baseline) have
      // mostly English screens, so they stay English rather than mixing the two languages.
      try {
        ruleLocale = resolveLanguage({ flag: null, env: io.env });
      } catch (error) {
        if (!(error instanceof UsageError)) throw error;
        ruleLocale = resolveLanguage({ flag: null, env: { ...io.env, PGARD_LANG: undefined } });
        io.stderr.write(
          ruleLocale === "ko"
            ? "PGARD_LANG 값이 en 또는 ko가 아니어서 시스템 언어를 사용합니다.\n"
            : "PGARD_LANG is not en or ko; using the system language instead.\n",
        );
      }
      reportLocale = ruleLocale;
    }
  } catch (error) {
    if (error instanceof UsageError) {
      io.stderr.write(
        `${errStyle.red(`Error: ${safeText(error.message, 300)}`)}\n\n${getHelpText(error.helpTopic)}\n`,
      );
      return EXIT_CODES.usage;
    }
    throw error;
  }
  if (command.kind === "help") {
    io.stdout.write(`${getHelpText(command.topic)}\n`);
    return EXIT_CODES.ok;
  }
  if (command.kind === "version") {
    io.stdout.write(`pgard ${PGARD_VERSION}\n`);
    return EXIT_CODES.ok;
  }

  const deps = options.deps ?? createDefaultDeps();
  // `--format json` leaves stdout for the result, so a person can still answer prompts (shown on
  // stderr) when stdin and stderr are terminals even though stdout is redirected.
  const isJsonScan = command.kind === "scan" && isMachineFormat(command.format);
  const keys = (isJsonScan ? isInteractiveOnStderr(io) : isInteractive(io))
    ? createKeyReader(io.stdin)
    : null;
  const cancel = createCancelController(options.interrupts ?? process, (message) =>
    io.stderr.write(`${errStyle.yellow(message)}\n`),
  );
  const noBrowser = "noBrowser" in command && command.noBrowser;
  const context: CommandContext = {
    io,
    deps,
    // GitHub pages open automatically only for a person at a terminal who did not opt out.
    canOpenBrowser: io.stdout.isTTY === true && !noBrowser,
    style: createStyle(shouldUseColor(io.stdout, io.env)),
    errStyle,
    keys,
    signal: cancel.signal,
    isMenu: command.kind === "menu",
    ruleLocale,
    reportLocale,
    ruleTexts: getRuleTextCatalog(),
    releaseInterrupts: cancel.dispose,
    suspendInterrupts: cancel.suspend,
  };
  try {
    return command.kind === "menu" ? await runMenu(context) : await runCommand(context, command);
  } catch (error) {
    if (error instanceof PanelsTerminatedError) return EXIT_CODES.terminated;
    if (error instanceof UserCancelledError) {
      io.stderr.write(`${errStyle.yellow("Cancelled.")}\n`);
      return EXIT_CODES.cancelled;
    }
    // Never print stack traces or error details that could contain tokens or paths.
    io.stderr.write(`${errStyle.red("Internal error. No results were saved.")}\n`);
    if (io.env.PGARD_DEBUG === "1" && error instanceof Error) {
      io.stderr.write(`${safeText(`${error.name}: ${error.message}`, 500)}\n`);
    }
    return EXIT_CODES.internal;
  } finally {
    stopBrowserOffers(context);
    keys?.close();
    cancel.dispose();
  }
}
