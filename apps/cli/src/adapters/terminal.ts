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
  close: () => void;
}

export function isInteractive(io: CliIo): boolean {
  return io.stdin.isTTY === true && io.stdout.isTTY === true;
}

/**
 * Raw-mode key reader. Ctrl+C arrives as a key (not SIGINT) while it is active, so prompts can
 * ask for cancel confirmation themselves.
 */
export function createKeyReader(stdin: InputStream): KeyReader {
  readline.emitKeypressEvents(stdin);
  const queue: Key[] = [];
  const waiters: Array<(key: Key) => void> = [];
  const onKeypress = (sequence: string | undefined, key: Partial<Key> | undefined): void => {
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
    stdin.setRawMode?.(true);
    stdin.on("keypress", onKeypress);
    stdin.resume();
  };
  return {
    readKey: () => {
      activate();
      const queued = queue.shift();
      if (queued !== undefined) return Promise.resolve(queued);
      return new Promise((resolve) => waiters.push(resolve));
    },
    close: () => {
      if (!isActive) return;
      isActive = false;
      stdin.off("keypress", onKeypress);
      stdin.setRawMode?.(false);
      stdin.pause();
    },
  };
}
