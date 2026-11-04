import { execFile } from "node:child_process";
import { access, constants } from "node:fs/promises";
import path from "node:path";
import { windowsSystemRoot } from "../open-local-url.js";

/**
 * #414: the operating system's own folder dialog, opened by the local server for the
 * page's "Choose folder" button. Fixed argv only (no shell); the only text in the arguments is
 * the prompt, which comes from PGARD's own strings, never from the request. One dialog at a time
 * is enforced by the caller; the child is killed on cancel, on shutdown and after `timeoutMs`.
 */

export type FolderDialogResult =
  | { status: "chosen"; path: string }
  | { status: "cancelled" }
  | { status: "timeout" }
  | { status: "unavailable" };

export type FolderDialog = (options: {
  prompt: string;
  signal: AbortSignal;
}) => Promise<FolderDialogResult>;

export const FOLDER_DIALOG_TIMEOUT_MS = 5 * 60 * 1000;
const MAX_OUTPUT_BYTES = 64 * 1024;

export interface DialogCommand {
  file: string;
  args: string[];
  /** Exit codes that mean "the user closed the dialog". */
  cancelCodes: number[];
  /** Added to the child's environment (the Windows prompt text; never part of the arguments). */
  env?: Record<string, string>;
  /** `base64`: stdout is the chosen path as base64 of its UTF-8 bytes (Windows). */
  output?: "text" | "base64";
}

/** The environment variable that carries the Windows dialog's prompt into the fixed script. */
export const WINDOWS_PROMPT_VARIABLE = "PGARD_DIALOG_PROMPT";

/** Exit code of the Windows script when the user closed the dialog. */
export const WINDOWS_CANCEL_CODE = 3;

/**
 * The fixed Windows script (#477): no text of ours or the user's is ever put into it. The prompt
 * comes from the `PGARD_DIALOG_PROMPT` environment variable; the chosen path leaves as base64 of
 * its UTF-8 bytes, so no console code page can garble a Korean folder name. A failure (blocked
 * assembly, policy, no desktop) exits 1, which the caller reports as "no folder window".
 */
export const WINDOWS_DIALOG_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "$ProgressPreference = 'SilentlyContinue'",
  "Add-Type -AssemblyName System.Windows.Forms",
  "[System.Windows.Forms.Application]::EnableVisualStyles()",
  "$owner = New-Object System.Windows.Forms.Form",
  "$owner.TopMost = $true",
  "$dialog = New-Object System.Windows.Forms.FolderBrowserDialog",
  "$dialog.Description = $env:" + WINDOWS_PROMPT_VARIABLE,
  "$dialog.ShowNewFolderButton = $true",
  "$result = $dialog.ShowDialog($owner)",
  "if ($result -ne [System.Windows.Forms.DialogResult]::OK) { exit " + WINDOWS_CANCEL_CODE + " }",
  "[Console]::Out.Write([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($dialog.SelectedPath)))",
  "exit 0",
].join("\r\n");

/** `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`, absolute (never searched for). */
export function windowsPowerShellPath(env: Readonly<Record<string, string | undefined>>): string {
  return path.win32.join(
    windowsSystemRoot(env),
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe",
  );
}

/** Decodes the Windows script's output; `null` when it is not what the script writes. */
export function decodeWindowsDialogOutput(stdout: string): string | null {
  const text = stdout.trim();
  if (text.length === 0) return "";
  if (text.length > 16 * 1024 || !/^[A-Za-z0-9+/]+={0,2}$/.test(text)) {
    return null;
  }
  const bytes = Buffer.from(text, "base64");
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/** AppleScript string literal: backslash and quote escaped (the prompt is our own text). */
function appleScriptString(text: string): string {
  return `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/**
 * The fixed dialog command per platform, or `null` when there is none. Windows runs Windows
 * PowerShell from its absolute path under `%SystemRoot%` with a fixed encoded script; the prompt
 * travels in an environment variable only.
 */
export async function dialogCommandFor(
  platform: string,
  prompt: string,
  isExecutable: (file: string) => Promise<boolean> = defaultIsExecutable,
  env: Readonly<Record<string, string | undefined>> = process.env,
): Promise<DialogCommand | null> {
  if (platform === "darwin") {
    return {
      file: "/usr/bin/osascript",
      // `activate` brings osascript's dialog to the front; `-128` (exit 1) is "User canceled".
      args: [
        "-e",
        "activate",
        "-e",
        `POSIX path of (choose folder with prompt ${appleScriptString(prompt)})`,
      ],
      cancelCodes: [1],
    };
  }
  if (platform === "win32") {
    const file = windowsPowerShellPath(env);
    if (!(await isExecutable(file))) return null;
    return {
      file,
      args: [
        "-NoProfile",
        "-NonInteractive",
        "-STA",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        Buffer.from(WINDOWS_DIALOG_SCRIPT, "utf16le").toString("base64"),
      ],
      cancelCodes: [WINDOWS_CANCEL_CODE],
      env: { [WINDOWS_PROMPT_VARIABLE]: prompt },
      output: "base64",
    };
  }
  for (const directory of ["/usr/bin", "/usr/local/bin", "/bin"]) {
    const zenity = `${directory}/zenity`;
    if (await isExecutable(zenity)) {
      return {
        file: zenity,
        args: ["--file-selection", "--directory", `--title=${prompt}`],
        cancelCodes: [1, 5],
      };
    }
    const kdialog = `${directory}/kdialog`;
    if (await isExecutable(kdialog)) {
      return {
        file: kdialog,
        args: ["--getexistingdirectory", "--title", prompt],
        cancelCodes: [1],
      };
    }
  }
  return null;
}

async function defaultIsExecutable(file: string): Promise<boolean> {
  try {
    await access(file, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export interface RunDialog {
  (
    command: DialogCommand,
    options: { signal: AbortSignal; timeoutMs: number },
  ): Promise<{
    code: number | null;
    stdout: string;
    timedOut: boolean;
  }>;
}

const defaultRunDialog: RunDialog = (command, { signal, timeoutMs }) =>
  new Promise((resolve) => {
    execFile(
      command.file,
      command.args,
      {
        shell: false,
        signal,
        timeout: timeoutMs,
        killSignal: "SIGKILL",
        maxBuffer: MAX_OUTPUT_BYTES,
        encoding: "utf8",
        windowsHide: false,
        env: {
          ...process.env,
          LC_ALL: process.env.LC_ALL ?? "en_US.UTF-8",
          ...command.env,
        },
      },
      (error, stdout) => {
        if (error === null) return resolve({ code: 0, stdout, timedOut: false });
        const failure = error as NodeJS.ErrnoException & { code?: unknown; killed?: boolean };
        const timedOut = failure.killed === true && !signal.aborted;
        resolve({
          code: typeof failure.code === "number" ? failure.code : null,
          stdout: typeof stdout === "string" ? stdout : "",
          timedOut,
        });
      },
    );
  });

export function createFolderDialog(
  options: {
    platform?: string;
    run?: RunDialog;
    isExecutable?: (file: string) => Promise<boolean>;
    env?: Readonly<Record<string, string | undefined>>;
    timeoutMs?: number;
  } = {},
): FolderDialog {
  const platform = options.platform ?? process.platform;
  const run = options.run ?? defaultRunDialog;
  const timeoutMs = options.timeoutMs ?? FOLDER_DIALOG_TIMEOUT_MS;
  return async ({ prompt, signal }) => {
    const command = await dialogCommandFor(
      platform,
      prompt,
      options.isExecutable,
      options.env ?? process.env,
    );
    if (command === null) return { status: "unavailable" };
    if (signal.aborted) return { status: "cancelled" };
    let outcome;
    try {
      outcome = await run(command, { signal, timeoutMs });
    } catch {
      return { status: "unavailable" };
    }
    if (signal.aborted) return { status: "cancelled" };
    if (outcome.timedOut) return { status: "timeout" };
    if (outcome.code !== 0) {
      // A missing tool (ENOENT) has no numeric code: treat it as unavailable.
      return outcome.code !== null && command.cancelCodes.includes(outcome.code)
        ? { status: "cancelled" }
        : { status: "unavailable" };
    }
    const chosen =
      command.output === "base64"
        ? decodeWindowsDialogOutput(outcome.stdout)
        : outcome.stdout.replace(/\r?\n$/, "");
    if (chosen === null) return { status: "unavailable" };
    if (chosen.length === 0) return { status: "cancelled" };
    return { status: "chosen", path: chosen };
  };
}
