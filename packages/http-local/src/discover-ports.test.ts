import { EventEmitter } from "node:events";
import { describe, expect, it } from "vitest";
import {
  CommandTimeoutError,
  discoverListeningPorts,
  LSOF_PATH,
  NETSTAT_ARGS,
  NETSTAT_PATH,
  parseLsofOutput,
  parseNetstatOutput,
  parseProcNetTcp,
  parseWindowsNetstatOutput,
  windowsNetstatPath,
  runCommandWithDeadline,
} from "./discover-ports.js";

const LSOF_SAMPLE = `COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
node      12345 me     23u  IPv4 0x1234567890abcdef      0t0  TCP 127.0.0.1:3000 (LISTEN)
node      12345 me     24u  IPv6 0x1234567890abcdee      0t0  TCP [::1]:3000 (LISTEN)
vite      22222 me     30u  IPv4 0x1234567890abcded      0t0  TCP *:5173 (LISTEN)
onlyv6    33333 me     30u  IPv6 0x1234567890abcdec      0t0  TCP [::1]:9000 (LISTEN)
remote    44444 me     30u  IPv4 0x1234567890abcdeb      0t0  TCP 192.168.1.5:7000 (LISTEN)
`;

describe("parseLsofOutput", () => {
  it("keeps listeners reachable on 127.0.0.1 and drops others", () => {
    expect(parseLsofOutput(LSOF_SAMPLE)).toEqual([
      { port: 3000, processName: "node" },
      { port: 5173, processName: "vite" },
    ]);
  });
});

// Captured from `netstat -an -p tcp` on macOS; ports and foreign peers are generic examples.
const NETSTAT_SAMPLE = `Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  127.0.0.1.3000         *.*                    LISTEN
tcp4       0      0  127.0.0.1.3000         127.0.0.1.60413        ESTABLISHED
tcp46      0      0  *.8080                 *.*                    LISTEN
tcp6       0      0  ::1.5173               *.*                    LISTEN
tcp6       0      0  *.5173                 *.*                    LISTEN
tcp6       0      0  *.6006                 *.*                    LISTEN
tcp4       0      0  127.0.0.1.4001         127.0.0.1.60414        ESTABLISHED
tcp4       0      0  127.0.0.1.4002         127.0.0.1.60415        TIME_WAIT
tcp4       0      0  *.5000                 *.*                    LISTEN
tcp4       0      0  192.168.1.5.7000       *.*                    LISTEN
tcp4       0      0  127.0.0.1.99999        *.*                    LISTEN
tcp4       0      0  127.0.0.1.abc          *.*                    LISTEN
tcp4       0      0  127.0.0.1.3000         *.*                    LISTEN
tcp4       0      0  garbage LISTEN
udp4       0      0  *.5353                 *.*
`;

describe("parseNetstatOutput", () => {
  it("keeps LISTEN lines reachable on 127.0.0.1, deduped, without process names", () => {
    expect(parseNetstatOutput(NETSTAT_SAMPLE)).toEqual([
      { port: 3000, processName: null },
      { port: 5000, processName: null },
      { port: 8080, processName: null },
    ]);
  });

  it("drops a tcp6 wildcard listener with no tcp4 twin and non-LISTEN lines", () => {
    const ports = parseNetstatOutput(NETSTAT_SAMPLE).map((entry) => entry.port);
    expect(ports).not.toContain(6006);
    expect(ports).not.toContain(4001);
    expect(ports).not.toContain(4002);
    expect(parseNetstatOutput("tcp6 0 0 *.6006 *.* LISTEN\n")).toEqual([]);
    expect(parseNetstatOutput("tcp46 0 0 *.6006 *.* LISTEN\n")).toHaveLength(1);
  });

  it("drops ::1-only listeners and returns nothing for empty input", () => {
    expect(parseNetstatOutput("tcp6 0 0 ::1.9000 *.* LISTEN\n")).toEqual([]);
    expect(parseNetstatOutput("")).toEqual([]);
  });
});

const PROC_TCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 1
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 2 1
   2: 0100007F:1F91 0100007F:9C40 01 00000000:00000000 00:00000000 00000000  1000        0 3 1
   3: 0501A8C0:1B58 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4 1
`;
const PROC_TCP6 = `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:2328 00000000000000000000000000000000:0000 0A
   1: 00000000000000000000000001000000:2329 00000000000000000000000000000000:0000 0A
`;

describe("parseProcNetTcp", () => {
  it("parses IPv4 loopback and wildcard listeners only", () => {
    expect(parseProcNetTcp(PROC_TCP, 4).map((entry) => entry.port)).toEqual([3000, 8080]);
  });

  it("parses IPv6 wildcard but not ::1-only listeners", () => {
    expect(parseProcNetTcp(PROC_TCP6, 6).map((entry) => entry.port)).toEqual([9000]);
  });
});

describe("discoverListeningPorts", () => {
  it("uses lsof on macOS and never claims completeness", async () => {
    const result = await discoverListeningPorts({
      platform: "darwin",
      runLsof: async () => LSOF_SAMPLE,
    });
    expect(result.method).toBe("lsof");
    expect(result.isComplete).toBe(false);
    expect(result.isAvailable).toBe(true);
    expect(result.ports.map((entry) => entry.port)).toEqual([3000, 5173]);
  });

  it("reads /proc on Linux", async () => {
    const result = await discoverListeningPorts({
      platform: "linux",
      readProcFile: async (path) => (path === "/proc/net/tcp" ? PROC_TCP : PROC_TCP6),
    });
    expect(result.ports.map((entry) => entry.port)).toEqual([3000, 8080, 9000]);
  });

  it("reports failure without throwing", async () => {
    const result = await discoverListeningPorts({
      platform: "darwin",
      runLsof: async () => {
        throw new Error("lsof missing");
      },
      runNetstat: async () => {
        throw new Error("netstat missing");
      },
    });
    expect(result.isAvailable).toBe(false);
    expect(result.method).toBe("netstat");
    expect(result.ports).toEqual([]);
  });

  it("falls back to netstat on macOS when lsof times out", async () => {
    const result = await discoverListeningPorts({
      platform: "darwin",
      runLsof: async () => {
        throw new CommandTimeoutError("lsof", 5000);
      },
      runNetstat: async () => NETSTAT_SAMPLE,
    });
    expect(result.method).toBe("netstat");
    expect(result.isAvailable).toBe(true);
    expect(result.isComplete).toBe(false);
    expect(result.ports.map((entry) => entry.port)).toEqual([3000, 5000, 8080]);
  });

  it("does not run netstat when lsof works, and never on Linux", async () => {
    let netstatCalls = 0;
    const runNetstat = async () => {
      netstatCalls += 1;
      return NETSTAT_SAMPLE;
    };
    await discoverListeningPorts({
      platform: "darwin",
      runLsof: async () => LSOF_SAMPLE,
      runNetstat,
    });
    const linux = await discoverListeningPorts({
      platform: "linux",
      readProcFile: async (path) => (path === "/proc/net/tcp" ? PROC_TCP : PROC_TCP6),
      runNetstat,
    });
    expect(netstatCalls).toBe(0);
    expect(linux.method).toBe("proc");
  });

  it("marks other platforms unsupported", async () => {
    const result = await discoverListeningPorts({ platform: "freebsd" });
    expect(result.method).toBe("unsupported");
    expect(result.isAvailable).toBe(false);
  });
});

describe("runCommandWithDeadline", () => {
  it("settles at the deadline even if the child ignores termination", async () => {
    const startedAt = Date.now();
    await expect(
      runCommandWithDeadline(
        process.execPath,
        ["-e", "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000);"],
        300,
      ),
    ).rejects.toBeInstanceOf(CommandTimeoutError);
    expect(Date.now() - startedAt).toBeLessThan(2000);
  });

  it("returns stdout of a command that finishes", async () => {
    await expect(
      runCommandWithDeadline(process.execPath, ["-e", "process.stdout.write('ok')"], 5000),
    ).resolves.toBe("ok");
  });
});

describe("netstat command", () => {
  it("spawns the absolute paths with fixed argv", () => {
    expect(LSOF_PATH).toBe("/usr/sbin/lsof");
    expect(NETSTAT_PATH).toBe("/usr/sbin/netstat");
    expect([...NETSTAT_ARGS]).toEqual(["-an", "-p", "tcp"]);
  });

  it("requires exit 0 when exit code 1 is not acceptable", async () => {
    await expect(
      runCommandWithDeadline(
        process.execPath,
        ["-e", "process.stdout.write('x'); process.exit(1)"],
        5000,
        { isExitCodeOneAcceptable: false },
      ),
    ).rejects.toBeDefined();
  });
});

describe("runCommandWithDeadline exit handling", () => {
  const node = process.execPath;

  it("settles when the child never exits and never calls back", async () => {
    const neverExits = (() => {
      const child = Object.assign(new EventEmitter(), {
        kill: () => true,
        unref: () => undefined,
        stdout: null,
        stderr: null,
      });
      return child;
    }) as never;
    const startedAt = Date.now();
    await expect(
      runCommandWithDeadline("lsof", [], 200, { execFileImpl: neverExits }),
    ).rejects.toBeInstanceOf(CommandTimeoutError);
    expect(Date.now() - startedAt).toBeLessThan(1000);
  });

  it("accepts exit code 1 (nothing matched) with its output", async () => {
    await expect(
      runCommandWithDeadline(node, ["-e", "process.stdout.write('x'); process.exit(1)"], 5000),
    ).resolves.toBe("x");
  });

  it("rejects partial output from other exit codes", async () => {
    await expect(
      runCommandWithDeadline(
        node,
        ["-e", "process.stdout.write('partial'); process.exit(2)"],
        5000,
      ),
    ).rejects.toThrow();
  });

  // Windows has no signals: a self-kill exits with code 1, which this API accepts.
  it.skipIf(process.platform === "win32")(
    "rejects output from a child killed by a signal",
    async () => {
      await expect(
        runCommandWithDeadline(
          node,
          ["-e", "process.stdout.write('partial'); process.kill(process.pid, 'SIGTERM')"],
          5000,
        ),
      ).rejects.toThrow();
    },
  );

  it("rejects instead of truncating when output exceeds maxBuffer", async () => {
    await expect(
      runCommandWithDeadline(node, ["-e", "process.stdout.write('y'.repeat(5000))"], 5000, {
        maxBufferBytes: 100,
      }),
    ).rejects.toThrow();
  });
});

const WINDOWS_NETSTAT = [
  "",
  "Active Connections",
  "",
  "  Proto  Local Address          Foreign Address        State           PID",
  "  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1100",
  "  TCP    127.0.0.1:3000         0.0.0.0:0              LISTENING       4242",
  "  TCP    192.168.1.5:8080       0.0.0.0:0              LISTENING       4242",
  "  TCP    127.0.0.1:3000         127.0.0.1:50000        ESTABLISHED     4242",
  "  TCP    0.0.0.0:445            0.0.0.0:0              ÜBERWACHEND     4",
  "  TCP    [::]:5173              [::]:0                 LISTENING       99",
  "  TCP    [::1]:9229             [::]:0                 LISTENING       99",
  "  TCP    0.0.0.0:70000          0.0.0.0:0              LISTENING       1",
  "",
].join("\r\n");

describe("parseWindowsNetstatOutput", () => {
  it("keeps IPv4 loopback and wildcard listeners, localized state included", () => {
    expect(parseWindowsNetstatOutput(WINDOWS_NETSTAT).map((entry) => entry.port)).toEqual([
      135, 445, 3000, 5173,
    ]);
  });

  it("returns no process names", () => {
    expect(parseWindowsNetstatOutput(WINDOWS_NETSTAT).every((e) => e.processName === null)).toBe(
      true,
    );
  });
});

describe("Windows discovery", () => {
  it("uses netstat and tolerates a failing IPv6 table", async () => {
    const calls: string[] = [];
    const result = await discoverListeningPorts({
      platform: "win32",
      runWindowsNetstat: async (protocol) => {
        calls.push(protocol);
        if (protocol === "TCPv6") throw new Error("boom");
        return WINDOWS_NETSTAT;
      },
    });
    expect(calls.sort()).toEqual(["TCP", "TCPv6"]);
    expect(result.method).toBe("netstat");
    expect(result.isAvailable).toBe(true);
    expect(result.ports.map((p) => p.port)).toContain(3000);
  });

  it("reports unavailable when the IPv4 table fails", async () => {
    const result = await discoverListeningPorts({
      platform: "win32",
      runWindowsNetstat: async () => {
        throw new Error("boom");
      },
    });
    expect(result.isAvailable).toBe(false);
    expect(result.method).toBe("netstat");
  });

  it("resolves netstat.exe under SystemRoot only when SystemRoot is trusted", () => {
    expect(windowsNetstatPath({ SystemRoot: "D:\\Windows" })).toBe(
      "D:\\Windows\\System32\\netstat.exe",
    );
    expect(windowsNetstatPath({ SystemRoot: "..\\evil" })).toBe(
      "C:\\Windows\\System32\\netstat.exe",
    );
    expect(windowsNetstatPath({ SystemRoot: "\\\\host\\share" })).toBe(
      "C:\\Windows\\System32\\netstat.exe",
    );
    expect(windowsNetstatPath({})).toBe("C:\\Windows\\System32\\netstat.exe");
  });
});
