import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { MAX_PORT_CANDIDATES, PORT_DISCOVERY_TIMEOUT_MS } from "./constants.js";
import { sanitizeDisplayText } from "./display-text.js";
import { isValidPort } from "./target.js";

export interface ListeningPort {
  port: number;
  /** Process name when the OS reports it (macOS `lsof`). A hint only. */
  processName: string | null;
}

export type PortDiscoveryMethod = "lsof" | "proc" | "unsupported";

export interface PortDiscoveryResult {
  ports: ListeningPort[];
  method: PortDiscoveryMethod;
  /**
   * Always `false`: OS permissions and process visibility can hide listeners, so callers
   * must always offer "Other port".
   */
  isComplete: false;
  /** `false` when the mechanism is unsupported here or failed to run. */
  isAvailable: boolean;
  note: string | null;
}

export interface PortDiscoveryDeps {
  platform?: NodeJS.Platform;
  runLsof?: () => Promise<string>;
  readProcFile?: (path: "/proc/net/tcp" | "/proc/net/tcp6") => Promise<string>;
}

export class CommandTimeoutError extends Error {
  readonly code = "timeout";
  constructor(file: string, timeoutMs: number) {
    super(`${file} did not finish within ${timeoutMs} ms.`);
    this.name = "CommandTimeoutError";
  }
}

/**
 * Runs a fixed command (no shell) and settles by the deadline even if the child never exits.
 * On macOS `lsof` can hang in an uninterruptible kernel wait where neither SIGTERM nor SIGKILL
 * takes effect, and `execFile`'s own timeout only reports after the child has exited. So we
 * reject on our own timer, send SIGKILL, and unref the child so PGARD can still exit.
 */
export function runCommandWithDeadline(
  file: string,
  args: readonly string[],
  timeoutMs: number,
): Promise<string> {
  return new Promise((resolve, reject) => {
    let isSettled = false;
    const child = execFile(
      file,
      [...args],
      { maxBuffer: 4 * 1024 * 1024, windowsHide: true, shell: false },
      (error, stdout) => {
        if (isSettled) return;
        isSettled = true;
        clearTimeout(timer);
        // lsof exits 1 when nothing matches; treat output as authoritative when present.
        if (error !== null && stdout.length === 0) {
          reject(error);
          return;
        }
        resolve(stdout);
      },
    );
    const timer = setTimeout(() => {
      if (isSettled) return;
      isSettled = true;
      child.kill("SIGKILL");
      child.unref();
      child.stdout?.destroy();
      child.stderr?.destroy();
      reject(new CommandTimeoutError(file, timeoutMs));
    }, timeoutMs);
  });
}

function runLsofDefault(): Promise<string> {
  // -b avoids kernel calls that can block (e.g. on network mounts); -w silences warnings.
  return runCommandWithDeadline(
    "lsof",
    ["-b", "-w", "-nP", "-iTCP", "-sTCP:LISTEN"],
    PORT_DISCOVERY_TIMEOUT_MS,
  );
}

/** Listener addresses reachable through 127.0.0.1. `[::1]`-only listeners are not. */
function isReachableViaIpv4Loopback(address: string): boolean {
  return (
    address === "*" ||
    address === "0.0.0.0" ||
    address === "[::]" ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(address)
  );
}

/** Parses `lsof -nP -iTCP -sTCP:LISTEN` output. */
export function parseLsofOutput(output: string): ListeningPort[] {
  const byPort = new Map<number, ListeningPort>();
  for (const line of output.split("\n").slice(1)) {
    const columns = line.trim().split(/\s+/);
    if (columns.length < 9) continue;
    const command = columns[0] ?? "";
    // NAME column looks like `127.0.0.1:3000 (LISTEN)` or `*:5173 (LISTEN)` or `[::1]:8080 (LISTEN)`.
    const name = columns.find((column, index) => index >= 8 && /:\d+$/.test(column));
    if (name === undefined) continue;
    const separator = name.lastIndexOf(":");
    const address = name.slice(0, separator);
    const port = Number(name.slice(separator + 1));
    if (!isValidPort(port) || !isReachableViaIpv4Loopback(address)) continue;
    if (!byPort.has(port)) {
      byPort.set(port, {
        port,
        processName: sanitizeDisplayText(command.replace(/\\x20/g, " "), 40),
      });
    }
  }
  return [...byPort.values()].sort((a, b) => a.port - b.port);
}

const LISTEN_STATE = "0A";

/** Parses `/proc/net/tcp` or `/proc/net/tcp6`. */
export function parseProcNetTcp(content: string, family: 4 | 6): ListeningPort[] {
  const ports: ListeningPort[] = [];
  for (const line of content.split("\n").slice(1)) {
    const columns = line.trim().split(/\s+/);
    const local = columns[1];
    const state = columns[3];
    if (local === undefined || state !== LISTEN_STATE) continue;
    const [addressHex, portHex] = local.split(":");
    if (addressHex === undefined || portHex === undefined) continue;
    const port = Number.parseInt(portHex, 16);
    if (!isValidPort(port)) continue;
    const isReachable =
      family === 4
        ? addressHex === "00000000" || addressHex.endsWith("7F") // little-endian 127.x.x.x
        : /^0{32}$/.test(addressHex) || /^0{16}FFFF0000[0-9A-F]{6}7F$/i.test(addressHex);
    if (isReachable) ports.push({ port, processName: null });
  }
  return ports;
}

/**
 * Lists TCP listeners that can be reached on 127.0.0.1. The list is a convenience: it may be
 * incomplete, and a listening port says nothing about which project it belongs to.
 */
export async function discoverListeningPorts(
  deps: PortDiscoveryDeps = {},
): Promise<PortDiscoveryResult> {
  const platform = deps.platform ?? process.platform;
  let ports: ListeningPort[] = [];
  let method: PortDiscoveryMethod;
  let note: string | null = null;
  let isAvailable = true;
  try {
    if (platform === "darwin") {
      method = "lsof";
      ports = parseLsofOutput(await (deps.runLsof ?? runLsofDefault)());
    } else if (platform === "linux") {
      method = "proc";
      const read = deps.readProcFile ?? ((path) => readFile(path, "utf8"));
      const v4 = await read("/proc/net/tcp").catch(() => "");
      const v6 = await read("/proc/net/tcp6").catch(() => "");
      ports = [...parseProcNetTcp(v4, 4), ...parseProcNetTcp(v6, 6)];
    } else {
      method = "unsupported";
      isAvailable = false;
      note = "Automatic port discovery is not available on this platform.";
    }
  } catch {
    method = platform === "darwin" ? "lsof" : "proc";
    isAvailable = false;
    note = "Port discovery failed; enter the port manually.";
  }
  const unique = new Map<number, ListeningPort>();
  for (const entry of ports) if (!unique.has(entry.port)) unique.set(entry.port, entry);
  const sorted = [...unique.values()].sort((a, b) => a.port - b.port);
  if (sorted.length > MAX_PORT_CANDIDATES) {
    note = `Showing the first ${MAX_PORT_CANDIDATES} listening ports.`;
  }
  return {
    ports: sorted.slice(0, MAX_PORT_CANDIDATES),
    method,
    isComplete: false,
    isAvailable,
    note,
  };
}
