import { execFile } from "node:child_process";
import { access, constants } from "node:fs/promises";

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
}

/** AppleScript string literal: backslash and quote escaped (the prompt is our own text). */
function appleScriptString(text: string): string {
  return `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/**
 * The fixed dialog command per platform, or `null` when there is none. Windows has none: the
 * folder checks (realpath, `lstat` chain, ownership and write bits) and the pasted-path rules are
 * POSIX-only, so the picker is not supported there: the page shows the "no folder window" state
 * and a pasted `C:\` path is refused as `bad_path` (design doc, section 6.1).
 */
export async function dialogCommandFor(
  platform: string,
  prompt: string,
  isExecutable: (file: string) => Promise<boolean> = defaultIsExecutable,
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
  if (platform === "win32") return null;
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
        env: { ...process.env, LC_ALL: process.env.LC_ALL ?? "en_US.UTF-8" },
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
    timeoutMs?: number;
  } = {},
): FolderDialog {
  const platform = options.platform ?? process.platform;
  const run = options.run ?? defaultRunDialog;
  const timeoutMs = options.timeoutMs ?? FOLDER_DIALOG_TIMEOUT_MS;
  return async ({ prompt, signal }) => {
    const command = await dialogCommandFor(platform, prompt, options.isExecutable);
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
    const chosen = outcome.stdout.replace(/\r?\n$/, "");
    if (chosen.length === 0) return { status: "cancelled" };
    return { status: "chosen", path: chosen };
  };
}
