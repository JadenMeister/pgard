import readline from "node:readline";

export interface Key {
  name: string | undefined;
  sequence: string | undefined;
  ctrl: boolean;
}

export interface InputStream extends NodeJS.ReadableStream {
  isTTY?: boolean;
  setRawMode?: (mode: boolean) => unknown;
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
  const waiters: Array<(key: Key) => void> = [];
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
    else waiter(entry);
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
      activate();
      const queued = queue.shift();
      if (queued !== undefined) return Promise.resolve(queued);
      return new Promise((resolve) => waiters.push(resolve));
    },
    suspend: deactivate,
    close: deactivate,
  };
}
