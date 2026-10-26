import readline from "node:readline";
import { UserCancelledError } from "../ui/components/prompts.js";

export interface Key {
  name: string | undefined;
  sequence: string | undefined;
  ctrl: boolean;
}

export interface InputStream extends NodeJS.ReadableStream {
  isTTY?: boolean;
  setRawMode?: (mode: boolean) => unknown;
  readableEnded?: boolean;
}

export interface OutputStream extends NodeJS.WritableStream {
  isTTY?: boolean;
}

/** Process boundary for the CLI. Tests pass fakes; `bin/pgard.ts` passes the real process. */
export interface CliIo {
  stdin: InputStream;
  stdout: OutputStream;
  stderr: OutputStream;
  env: Readonly<Record<string, string | undefined>>;
  cwd: string;
}

/** Reads single key presses from a TTY in raw mode. */
export interface KeyReader {
  readKey: () => Promise<Key>;
  /**
   * Leaves raw mode and detaches from stdin until the next `readKey`, so Ctrl+C during
   * long-running work (scan, device-flow wait) reaches the process as SIGINT again. Keys typed
   * meanwhile are not queued into the next prompt.
   */
  suspend: () => void;
  close: () => void;
}

export function isInteractive(io: CliIo): boolean {
  return io.stdin.isTTY === true && io.stdout.isTTY === true;
}

/**
 * Raw-mode key reader. Ctrl+C arrives as a key (not SIGINT) while it is active, so prompts can
 * ask for cancel confirmation themselves.
 */
/**
 * Keys that arrive this soon after a prompt (re)activates were typed ahead while work was
 * running (buffered by the terminal while stdin was paused); they are discarded so they cannot
 * answer the next prompt. A person cannot react to a new prompt this fast.
 */
export const TYPE_AHEAD_DISCARD_MS = 40;

export function createKeyReader(stdin: InputStream, now: () => number = Date.now): KeyReader {
  readline.emitKeypressEvents(stdin);
  const queue: Key[] = [];
  const waiters: Array<{ resolve: (key: Key) => void; reject: (error: Error) => void }> = [];
  // End of input (Ctrl+D in line mode, a closed terminal) means no key can ever arrive again.
  // It is a cancel: every pending and later readKey rejects, so a prompt never hangs.
  let isEnded = stdin.readableEnded === true;
  stdin.once("end", () => {
    isEnded = true;
    for (const waiter of waiters.splice(0)) waiter.reject(new UserCancelledError());
  });
  let activatedAt = Number.NEGATIVE_INFINITY;
  let wasSuspended = false;
  const onKeypress = (sequence: string | undefined, key: Partial<Key> | undefined): void => {
    if (now() - activatedAt < TYPE_AHEAD_DISCARD_MS) return;
    const entry: Key = {
      name: key?.name,
      sequence: key?.sequence ?? sequence,
      ctrl: key?.ctrl === true,
    };
    const waiter = waiters.shift();
    if (waiter === undefined) queue.push(entry);
    else waiter.resolve(entry);
  };
  let isActive = false;
  const activate = (): void => {
    if (isActive) return;
    isActive = true;
    // Only a re-activation after suspend() can have type-ahead from the work in between.
    if (wasSuspended) activatedAt = now();
    stdin.setRawMode?.(true);
    stdin.on("keypress", onKeypress);
    stdin.resume();
  };
  const deactivate = (): void => {
    // Mark first: suspend() before the first prompt (e.g. the `scan web --port` pre-check)
    // must also discard keys typed during that work.
    wasSuspended = true;
    if (!isActive) return;
    isActive = false;
    stdin.off("keypress", onKeypress);
    stdin.setRawMode?.(false);
    stdin.pause();
    queue.length = 0;
  };
  return {
    readKey: () => {
      if (isEnded) return Promise.reject(new UserCancelledError());
      activate();
      const queued = queue.shift();
      if (queued !== undefined) return Promise.resolve(queued);
      return new Promise((resolve, reject) => waiters.push({ resolve, reject }));
    },
    suspend: deactivate,
    close: deactivate,
  };
}

/**
 * Waits for the Enter key in the terminal's normal line mode, so Ctrl+C still arrives as SIGINT
 * (and the CLI's "press Ctrl+C twice" handling is unchanged). Any other typed text is ignored;
 * only a line break counts. A line break already buffered when the wait starts (type-ahead)
 * arrives within `TYPE_AHEAD_DISCARD_MS` and is discarded. Returns a function that stops
 * waiting: it removes the listener and pauses stdin again so the process can exit.
 */
export function waitForEnter(
  stdin: InputStream,
  onEnter: () => void,
  now: () => number = Date.now,
): () => void {
  const startedAt = now();
  let isWaiting = true;
  const onData = (chunk: Buffer | string): void => {
    if (!isWaiting || now() - startedAt < TYPE_AHEAD_DISCARD_MS) return;
    if (!/[\r\n]/.test(chunk.toString())) return;
    stop();
    onEnter();
  };
  const stop = (): void => {
    if (!isWaiting) return;
    isWaiting = false;
    stdin.off("data", onData);
    stdin.off("end", stop);
    stdin.pause();
  };
  // End of input (Ctrl+D) stops the wait without opening anything. It does not cancel the run
  // here (polling goes on); the next key prompt sees the ended stdin and cancels (exit 130).
  stdin.once("end", stop);
  stdin.on("data", onData);
  stdin.resume();
  return stop;
}
