import { stopBrowserOffers } from "./flows/browser.js";
import { PGARD_VERSION } from "@pgard/scan-core";
import { createCancelController, type InterruptSource } from "./adapters/cancel.js";
import {
  createKeyReader,
  isInteractive,
  isInteractiveOnStderr,
  type CliIo,
} from "./adapters/terminal.js";
import { runDashboard } from "./commands/dashboard.js";
import { runDoctor } from "./commands/doctor.js";
import { runHistoryClear } from "./commands/history.js";
import { runLogin, runLogout } from "./commands/login.js";
import { runProjectVerify } from "./commands/project/verify.js";
import { runRulesList } from "./commands/rules/list.js";
import { runScanCommand } from "./commands/scan/index.js";
import { err, out, type CommandContext } from "./context.js";
import { createDefaultDeps, type CliDeps } from "./deps.js";
import { EXIT_CODES, type ExitCode } from "./exit-codes.js";
import { getHelpText } from "./help.js";
import { parseCommandLine, UsageError, type ParsedCommand } from "./options.js";
import { BACK, promptChoice, UserCancelledError } from "./ui/components/prompts.js";
import { createStyle, safeText, shouldUseColor } from "./ui/formatters/style.js";

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
    case "dashboard":
      return runDashboard(context, command.targetPort, command.noBrowser);
    case "rules-list":
      return runRulesList(context, command.language);
    case "history-clear":
      return runHistoryClear(context, command.repo);
    case "doctor":
      return runDoctor(context);
    case "login":
      return runLogin(context);
    case "logout":
      return runLogout(context);
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
    label: "Scan code",
    hint: "pgard scan code",
    value: {
      kind: "scan",
      variant: "code",
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
    label: "Open dashboard",
    hint: "local web app",
    value: { kind: "dashboard", targetPort: null, noBrowser: false },
  },
  { label: "List rules", hint: "pgard rules list", value: { kind: "rules-list", language: null } },
  { label: "Doctor", hint: "environment diagnosis", value: { kind: "doctor" } },
  { label: "Quit", hint: "", value: "quit" },
];

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
  let lastExitCode: ExitCode = EXIT_CODES.ok;
  for (;;) {
    out(context, "");
    const picked = await promptChoice(prompts, `pgard ${PGARD_VERSION}`, MENU_CHOICES);
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
  try {
    command = parseCommandLine(argv);
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
  const isJsonScan = command.kind === "scan" && command.format === "json";
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
    releaseInterrupts: cancel.dispose,
  };
  try {
    return command.kind === "menu" ? await runMenu(context) : await runCommand(context, command);
  } catch (error) {
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
