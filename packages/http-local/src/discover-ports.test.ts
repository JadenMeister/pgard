import { describe, expect, it } from "vitest";
import { discoverListeningPorts, parseLsofOutput, parseProcNetTcp } from "./discover-ports.js";

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
    });
    expect(result.isAvailable).toBe(false);
    expect(result.ports).toEqual([]);
  });

  it("marks other platforms unsupported", async () => {
    const result = await discoverListeningPorts({ platform: "win32" });
    expect(result.method).toBe("unsupported");
    expect(result.isAvailable).toBe(false);
  });
});
