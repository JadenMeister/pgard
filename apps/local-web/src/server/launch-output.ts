import {
  openLocalUrl,
  type OpenerEnvironment,
  type OpenLocalDeps,
  type OpenOutcome,
  type OpenSkipReason,
} from "./open-local-url.js";
import type { RedirectFile } from "./redirect-file.js";
import { URL_TOKEN_TTL_MS } from "./session/url-session.js";

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
    // The opener starting is not proof that a browser showed the page.
    else lines.push("If no browser opened, run again with --print-url.");
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

const clock = (at: Date): string => {
  const pad = (value: number): string => String(value).padStart(2, "0");
  return `${pad(at.getHours())}:${pad(at.getMinutes())}:${pad(at.getSeconds())}`;
};

/** `Browser connected at 23:41:07.` (local time), printed on every exchange. */
export function connectedLine(at: Date): string {
  return `Browser connected at ${clock(at)}.\n`;
}

/** Printed when the spent link is presented again, so a lost race is visible. */
export function reusedLine(at: Date): string {
  return `Someone tried to reuse the link at ${clock(at)}. If that was not you, stop the server (Ctrl+C) and run the command again.\n`;
}

/** Opens the browser (when allowed) and prints the matching lines. */
export async function announceLaunch(options: {
  url: string;
  mode: "picker" | "fixed";
  printUrl: boolean;
  environment: OpenerEnvironment;
  write: (text: string) => void;
  deps?: OpenLocalDeps;
}): Promise<{ open: OpenOutcome; redirect: RedirectFile | null }> {
  const { outcome, redirect } = await openLocalUrl(options.url, options.environment, options.deps);
  options.write(
    launchLines({
      url: options.url,
      mode: options.mode,
      printUrl: options.printUrl,
      open: outcome,
    }).join("\n"),
  );
  return { open: outcome, redirect };
}

/**
 * When the redirect file is deleted: right after the exchange (`onConnected`), when the unused
 * link expires (`URL_TOKEN_TTL_MS`), and when the server stops (`onStop`, also on SIGINT and
 * SIGTERM; `onExit` is the synchronous last resort for `process.on("exit")`).
 */
export function bindRedirectCleanup(
  redirect: RedirectFile | null,
  timers: {
    setTimer: (run: () => void, ms: number) => { unref?: () => unknown };
    clearTimer: (timer: unknown) => void;
  } = { setTimer: setTimeout, clearTimer: (timer) => clearTimeout(timer as NodeJS.Timeout) },
): { onConnected: () => void; onStop: () => Promise<void>; onExit: () => void } {
  if (redirect === null) {
    return { onConnected: () => undefined, onStop: async () => undefined, onExit: () => undefined };
  }
  const expiry = timers.setTimer(() => void redirect.remove(), URL_TOKEN_TTL_MS);
  expiry.unref?.();
  return {
    onConnected: () => {
      timers.clearTimer(expiry);
      void redirect.remove();
    },
    onStop: async () => {
      timers.clearTimer(expiry);
      await redirect.remove();
    },
    onExit: () => redirect.removeSync(),
  };
}
