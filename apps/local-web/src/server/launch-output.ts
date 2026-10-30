import {
  openLocalUrl,
  type OpenerEnvironment,
  type OpenOutcome,
  type OpenSkipReason,
  type SpawnDetached,
} from "./open-local-url.js";

/** What the terminal shows instead of the token (#419). */
export const TOKEN_MASK = "••••";

/** `http://127.0.0.1:4317/#token=••••`: the session URL with its token hidden. */
export function maskSessionUrl(url: string): string {
  return url.replace(/#token=[^&]*/, `#token=${TOKEN_MASK}`);
}

const SKIP_TEXT: Record<OpenSkipReason, string> = {
  disabled: "--no-open or --no-browser was given",
  no_terminal: "the output is not a terminal",
  ci: "CI is set",
  ssh: "this is an SSH session",
  no_display: "there is no display (DISPLAY or WAYLAND_DISPLAY)",
  bad_url: "the link did not pass the local URL check",
  failed: "the browser could not be started",
};

export interface LaunchAnnouncement {
  url: string;
  mode: "picker" | "fixed";
  /** `--print-url`: also print the full link after opening it. */
  printUrl: boolean;
  open: OpenOutcome;
}

/**
 * The launcher's terminal lines. The full link (with its one-time token) appears only when the
 * browser was not opened, or with `--print-url`; otherwise the token is masked, so it does not
 * stay in the scrollback, a recording or a screen share.
 */
export function launchLines(announcement: LaunchAnnouncement): string[] {
  const { url, mode, printUrl, open } = announcement;
  const command = mode === "picker" ? "pgard web" : "pgard dashboard";
  const lines = [
    mode === "picker"
      ? "PGARD web is running on 127.0.0.1 only. Choose a folder in the browser."
      : "PGARD dashboard is running on 127.0.0.1 only.",
  ];
  if (open.isOpened) {
    lines.push(`Opened in your browser: ${maskSessionUrl(url)}`);
    if (printUrl) lines.push(`Full one-time link: ${url}`);
    else lines.push("Run again with --print-url to see the full link.");
    lines.push("To open it elsewhere, stop and rerun the command.");
  } else {
    lines.push(`Not opened automatically (${SKIP_TEXT[open.reason]}).`);
    lines.push(`Open this one-time link in your browser: ${url}`);
  }
  lines.push(
    "The link works once, in one tab, within 10 minutes. Do not share it.",
    `Press Ctrl+C to stop; results and the session are discarded when ${command} stops.`,
    "",
  );
  return lines;
}

/** `Browser connected at 23:41:07.` (local time), printed on every exchange. */
export function connectedLine(at: Date): string {
  const pad = (value: number): string => String(value).padStart(2, "0");
  return `Browser connected at ${pad(at.getHours())}:${pad(at.getMinutes())}:${pad(at.getSeconds())}.\n`;
}

/** Opens the browser (when allowed) and prints the matching lines. */
export async function announceLaunch(options: {
  url: string;
  mode: "picker" | "fixed";
  printUrl: boolean;
  environment: OpenerEnvironment;
  write: (text: string) => void;
  spawn?: SpawnDetached;
}): Promise<OpenOutcome> {
  const open = await openLocalUrl(options.url, options.environment, options.spawn);
  options.write(
    launchLines({ url: options.url, mode: options.mode, printUrl: options.printUrl, open }).join(
      "\n",
    ),
  );
  return open;
}
