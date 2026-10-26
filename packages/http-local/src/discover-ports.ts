import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { MAX_PORT_CANDIDATES, PORT_DISCOVERY_TIMEOUT_MS } from "./constants.js";
import { sanitizeDisplayText } from "./display-text.js";
import { isValidPort } from "./target.js";

export interface ListeningPort {
  port: number;
  /** Process name when the OS reports it (macOS `lsof`). A hint only. */
  processName: string | null;
}

export type PortDiscoveryMethod = "lsof" | "netstat" | "proc" | "unsupported";

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

export type WindowsNetstatProtocol = "TCP" | "TCPv6";

export interface PortDiscoveryDeps {
  platform?: NodeJS.Platform;
  runLsof?: () => Promise<string>;
  runNetstat?: () => Promise<string>;
  /** Windows `netstat -ano`; called once per address family (`TCP`, `TCPv6`). */
  runWindowsNetstat?: (protocol: WindowsNetstatProtocol) => Promise<string>;
  readProcFile?: (path: "/proc/net/tcp" | "/proc/net/tcp6") => Promise<string>;
}

export class CommandTimeoutError extends Error {
  readonly code = "timeout";
  constructor(file: string, timeoutMs: number) {
    super(`${file} did not finish within ${timeoutMs} ms.`);
    this.name = "CommandTimeoutError";
  }
}

export interface RunCommandOptions {
  /** Defaults to 4 MiB. Exceeding it rejects instead of returning truncated output. */
  maxBufferBytes?: number;
  /** Test hook; defaults to `child_process.execFile`. */
  execFileImpl?: typeof execFile;
  /** Defaults to `true` (lsof exits 1 for "nothing matched"). Set `false` to require exit 0. */
  isExitCodeOneAcceptable?: boolean;
}

/**
 * Only a clean exit, or exit code 1 without a signal (lsof's "nothing matched"), yields output.
 * Anything else (other exit codes, signals, maxBuffer overflow) would mean partial output, which
 * must not be presented as a complete port list.
 */
function isAcceptableExit(error: ExecFileError | null, isExitCodeOneAcceptable: boolean): boolean {
  if (error === null) return true;
  return (
    isExitCodeOneAcceptable &&
    error.code === 1 &&
    (error.signal === null || error.signal === undefined) &&
    error.killed !== true
  );
}

interface ExecFileError extends Error {
  code?: number | string | null;
  signal?: NodeJS.Signals | null;
  killed?: boolean;
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
  options: RunCommandOptions = {},
): Promise<string> {
  const run = options.execFileImpl ?? execFile;
  return new Promise((resolve, reject) => {
    let isSettled = false;
    const child = run(
      file,
      [...args],
      { maxBuffer: options.maxBufferBytes ?? 4 * 1024 * 1024, windowsHide: true, shell: false },
      (error: ExecFileError | null, stdout: string | Buffer) => {
        if (isSettled) return;
        isSettled = true;
        clearTimeout(timer);
        if (!isAcceptableExit(error, options.isExitCodeOneAcceptable ?? true)) {
          reject(error ?? new Error(`${file} failed.`));
          return;
        }
        resolve(String(stdout));
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

/** Absolute paths: macOS ships both here, and PATH is not consulted. */
export const LSOF_PATH = "/usr/sbin/lsof";
export const NETSTAT_PATH = "/usr/sbin/netstat";
export const NETSTAT_ARGS = ["-an", "-p", "tcp"] as const;

/**
 * `%SystemRoot%\\System32\\netstat.exe`, never looked up through PATH. SystemRoot comes from the
 * environment, so it is only trusted when it is an absolute drive path without odd characters;
 * otherwise the default `C:\\Windows` is used.
 */
export function windowsNetstatPath(env: NodeJS.ProcessEnv = process.env): string {
  const root = env.SystemRoot ?? env.SYSTEMROOT ?? "";
  const isTrusted = /^[A-Za-z]:\\[A-Za-z0-9 _.\\()-]*$/.test(root) && !root.includes("..");
  return path.win32.join(isTrusted ? root : "C:\\Windows", "System32", "netstat.exe");
}

function runWindowsNetstatDefault(protocol: WindowsNetstatProtocol): Promise<string> {
  return runCommandWithDeadline(
    windowsNetstatPath(),
    ["-ano", "-p", protocol],
    PORT_DISCOVERY_TIMEOUT_MS,
    { isExitCodeOneAcceptable: false },
  );
}

function runLsofDefault(): Promise<string> {
  // -b avoids kernel calls that can block (e.g. on network mounts); -w silences warnings.
  return runCommandWithDeadline(
    LSOF_PATH,
    ["-b", "-w", "-nP", "-iTCP", "-sTCP:LISTEN"],
    PORT_DISCOVERY_TIMEOUT_MS,
  );
}

function runNetstatDefault(): Promise<string> {
  // netstat has no "nothing matched" exit code, so anything but 0 is a failure.
  return runCommandWithDeadline(NETSTAT_PATH, NETSTAT_ARGS, PORT_DISCOVERY_TIMEOUT_MS, {
    isExitCodeOneAcceptable: false,
  });
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

/**
 * Parses macOS `netstat -an -p tcp` output. Local addresses look like `127.0.0.1.3000`, `*.8080`
 * or `::1.5173`: the port follows the last dot. netstat reports no process name.
 */
export function parseNetstatOutput(output: string): ListeningPort[] {
  const byPort = new Map<number, ListeningPort>();
  for (const line of output.split("\n")) {
    const columns = line.trim().split(/\s+/);
    const protocol = columns[0] ?? "";
    if (columns.length < 6 || !protocol.startsWith("tcp")) continue;
    if (columns[columns.length - 1] !== "LISTEN") continue;
    const local = columns[3] ?? "";
    const separator = local.lastIndexOf(".");
    if (separator < 0 || !/^\d+$/.test(local.slice(separator + 1))) continue;
    const address = local.slice(0, separator);
    const port = Number(local.slice(separator + 1));
    if (!isValidPort(port) || !isReachableViaIpv4Loopback(address)) continue;
    // `*` on a plain tcp6 line is an IPv6-only socket, which 127.0.0.1 cannot reach.
    if (address === "*" && protocol === "tcp6") continue;
    if (!byPort.has(port)) byPort.set(port, { port, processName: null });
  }
  return [...byPort.values()].sort((a, b) => a.port - b.port);
}

/**
 * Parses Windows `netstat -ano -p TCP|TCPv6` output (`TCP  0.0.0.0:135  0.0.0.0:0  LISTENING  4`).
 * The State column is localized on non-English Windows, so a listener is recognised by its
 * foreign address ending in port 0, which no established or closing connection has. Local
 * addresses reachable through 127.0.0.1 are `0.0.0.0`, `[::]` (dual-stack) and `127.x.x.x`;
 * `[::1]` and other IPv6 addresses are not. netstat reports no process name here (only a PID).
 */
export function parseWindowsNetstatOutput(output: string): ListeningPort[] {
  const byPort = new Map<number, ListeningPort>();
  for (const line of output.split(/\r?\n/)) {
    const columns = line.trim().split(/\s+/);
    if (columns.length !== 5 || columns[0]?.toUpperCase() !== "TCP") continue;
    const local = columns[1] ?? "";
    const foreign = columns[2] ?? "";
    if (!/:0$/.test(foreign)) continue;
    const separator = local.lastIndexOf(":");
    if (separator < 0 || !/^\d+$/.test(local.slice(separator + 1))) continue;
    const address = local.slice(0, separator);
    const port = Number(local.slice(separator + 1));
    if (!isValidPort(port) || !isReachableViaIpv4Loopback(address)) continue;
    if (!byPort.has(port)) byPort.set(port, { port, processName: null });
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
      try {
        ports = parseLsofOutput(await (deps.runLsof ?? runLsofDefault)());
      } catch {
        // lsof can hang on a stuck volume; its deadline has already settled, so netstat runs
        // independently of any lingering lsof child.
        method = "netstat";
        ports = parseNetstatOutput(await (deps.runNetstat ?? runNetstatDefault)());
      }
    } else if (platform === "linux") {
      method = "proc";
      const read = deps.readProcFile ?? ((path) => readFile(path, "utf8"));
      const v4 = await read("/proc/net/tcp").catch(() => "");
      const v6 = await read("/proc/net/tcp6").catch(() => "");
      ports = [...parseProcNetTcp(v4, 4), ...parseProcNetTcp(v6, 6)];
    } else if (platform === "win32") {
      // Same value as the macOS fallback: it is netstat output, which `doctor` shows as-is.
      method = "netstat";
      const run = deps.runWindowsNetstat ?? runWindowsNetstatDefault;
      // IPv4 must work. The IPv6 table (where dual-stack `[::]` listeners appear) is best effort.
      const [v4, v6] = await Promise.all([run("TCP"), run("TCPv6").catch(() => "")]);
      ports = [...parseWindowsNetstatOutput(v4), ...parseWindowsNetstatOutput(v6)];
    } else {
      method = "unsupported";
      isAvailable = false;
      note = "Automatic port discovery is not available on this platform.";
    }
  } catch {
    method = platform === "darwin" || platform === "win32" ? "netstat" : "proc";
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
