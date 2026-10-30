import { describe, expect, it } from "vitest";
import {
  AUTHORIZATION_CHECK_IDS,
  AUTHORIZATION_CHECK_STATUSES,
  CONFIDENCES,
  COVERAGE_STATUSES,
  FINDING_CATEGORIES,
  FINDING_CONTEXTS,
  FINDING_STATUSES,
  LOCATION_KINDS,
  OVERALL_STATUSES,
  SCAN_SCOPES,
  SCHEMA_VERSION,
  SEVERITIES,
  type ScanResult,
} from "./contract.js";
import { READ_LIMITS, readScanResult } from "./read-result.js";

function sample(): ScanResult {
  return {
    schemaVersion: SCHEMA_VERSION,
    scanBasis: { mode: "authorized", authorization: "verified", reason: null },
    scanId: "scan-1",
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:01.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code", "history"],
    overallStatus: "completed",
    target: { repo: "octo/app", revision: "a".repeat(40), webOrigin: null },
    authorization: {
      decision: "allowed",
      checks: [
        "repository",
        "github_identity",
        "owner_approval",
        "current_access",
        "contribution",
      ].map((id) => ({
        id,
        status: "passed",
        reason: "ok",
      })) as ScanResult["authorization"]["checks"],
    },
    coverage: [
      {
        area: "source:typescript",
        scope: "code",
        status: "completed",
        ruleIds: ["PG-SQL-001"],
        note: null,
      },
    ],
    findings: [
      {
        id: "f1",
        ruleId: "PG-SQL-001",
        title: "t",
        category: "injection",
        severity: "high",
        status: "suspected",
        confidence: "medium",
        location: { kind: "file", path: "src/db.ts", line: 3, url: null, commit: null },
        evidence: "e",
        impact: "i",
        recommendation: "r",
        references: { cwe: ["CWE-89"], owasp: [], cve: [] },
        sources: ["code"],
        context: "test",
      },
    ],
    advisoryDb: { version: null, updatedAt: null },
  };
}

/** Deep-clones through JSON so tests mutate a plain object. */
function raw(): Record<string, any> {
  return JSON.parse(JSON.stringify(sample()));
}

function errorCode(input: unknown): string | undefined {
  const outcome = readScanResult(input);
  return outcome.ok ? undefined : outcome.error.code;
}

describe("readScanResult version compatibility", () => {
  it("returns a valid current-version result unchanged", () => {
    const outcome = readScanResult(raw());
    expect(outcome).toEqual({ ok: true, result: sample(), sourceVersion: SCHEMA_VERSION });
  });

  it("reads a result written by 1.0 (no ruleStats, no standardsCoverage), normalizing the version", () => {
    const old = raw();
    old.schemaVersion = "1.0";
    const outcome = readScanResult(old);
    expect(outcome).toEqual({ ok: true, result: sample(), sourceVersion: "1.0" });
    expect(outcome.ok && "ruleStats" in outcome.result).toBe(false);
    expect(outcome.ok && "standardsCoverage" in outcome.result).toBe(false);
  });

  it.each(["1.0", "1.7", "1.123456"])("accepts same major, version %s", (version) => {
    const input = raw();
    input.schemaVersion = version;
    const outcome = readScanResult(input);
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.sourceVersion).toBe(version);
  });

  it.each(["2.0", "0.9", "10.0"])("refuses another major version %s", (version) => {
    const input = raw();
    input.schemaVersion = version;
    const outcome = readScanResult(input);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.code).toBe("version_unsupported_major");
      expect(outcome.error.message).toContain(version);
    }
  });

  it.each(["1", "x", "", "1.0.0", "1.", ".1", "01.0", "1.-1", " 1.0", "1.0\n", "1e0.0"])(
    "refuses malformed version %j",
    (version) => {
      const input = raw();
      input.schemaVersion = version;
      expect(errorCode(input)).toBe("version_malformed");
    },
  );

  it.each([1, 1.0, true, ["1.0"], { major: 1 }])("refuses non-string version %j", (version) => {
    const input = raw();
    input.schemaVersion = version;
    expect(errorCode(input)).toBe("version_malformed");
  });

  it("refuses a missing or null version", () => {
    const missing = raw();
    delete missing.schemaVersion;
    expect(errorCode(missing)).toBe("version_missing");
    const nulled = raw();
    nulled.schemaVersion = null;
    expect(errorCode(nulled)).toBe("version_missing");
  });

  it("checks the version before the shape", () => {
    expect(errorCode({ schemaVersion: "2.0" })).toBe("version_unsupported_major");
  });

  it("does not take the version from the prototype chain", () => {
    const input = Object.create({ schemaVersion: "1.0" });
    Object.assign(input, { ...raw(), schemaVersion: undefined });
    expect(errorCode(input)).toBe("version_missing");
  });
});

describe("readScanResult unknown fields", () => {
  it("ignores and drops unknown fields at every level", () => {
    const input = raw();
    input.future = { a: 1 };
    input.findings[0].standards = ["x"];
    input.findings[0].location.extra = 1;
    input.coverage[0].extra = 1;
    input.authorization.checks[0].extra = 1;
    input.tool.extra = 1;
    const outcome = readScanResult(input);
    expect(outcome).toEqual({ ok: true, result: sample(), sourceVersion: SCHEMA_VERSION });
  });

  it("keeps `context` optional", () => {
    const input = raw();
    delete input.findings[0].context;
    const outcome = readScanResult(input);
    expect(outcome.ok && "context" in outcome.result.findings[0]!).toBe(false);
  });
});

describe("readScanResult malformed input", () => {
  it.each([null, undefined, 42, "text", true, [], [raw()]])("refuses non-object %j", (input) => {
    expect(errorCode(input)).toBe("not_an_object");
  });

  const mutations: Array<[string, (r: Record<string, any>) => void]> = [
    ["missing scanId", (r) => delete r.scanId],
    ["numeric scanId", (r) => (r.scanId = 7)],
    ["missing findings", (r) => delete r.findings],
    ["findings not an array", (r) => (r.findings = {})],
    ["null finding", (r) => (r.findings[0] = null)],
    ["finding as array", (r) => (r.findings[0] = [])],
    ["missing coverage", (r) => delete r.coverage],
    ["wrong overallStatus", (r) => (r.overallStatus = "ok")],
    ["wrong severity", (r) => (r.findings[0].severity = "urgent")],
    ["wrong category", (r) => (r.findings[0].category = "other")],
    ["wrong status", (r) => (r.findings[0].status = "maybe")],
    ["wrong confidence", (r) => (r.findings[0].confidence = "certain")],
    ["wrong context", (r) => (r.findings[0].context = "prod")],
    ["wrong location kind", (r) => (r.findings[0].location.kind = "disk")],
    ["string line", (r) => (r.findings[0].location.line = "3")],
    ["negative line", (r) => (r.findings[0].location.line = -1)],
    ["fractional line", (r) => (r.findings[0].location.line = 1.5)],
    ["missing location", (r) => delete r.findings[0].location],
    ["missing references", (r) => delete r.findings[0].references],
    ["references.cwe not strings", (r) => (r.findings[0].references.cwe = [1])],
    ["wrong source scope", (r) => (r.findings[0].sources = ["cloud"])],
    ["wrong coverage scope", (r) => (r.coverage[0].scope = "cloud")],
    ["wrong coverage status", (r) => (r.coverage[0].status = "done")],
    ["undefined note", (r) => delete r.coverage[0].note],
    ["wrong requested scope", (r) => (r.requestedScopes = ["all"])],
    ["wrong tool name", (r) => (r.tool.name = "other")],
    ["missing target", (r) => delete r.target],
    ["wrong decision", (r) => (r.authorization.decision = "maybe")],
    ["wrong check id", (r) => (r.authorization.checks[0].id = "other")],
    ["wrong check status", (r) => (r.authorization.checks[0].status = "ok")],
    ["checks not array", (r) => (r.authorization.checks = "x")],
    ["missing advisoryDb", (r) => delete r.advisoryDb],
  ];

  it.each(mutations)("refuses: %s", (_name, mutate) => {
    const input = raw();
    mutate(input);
    expect(errorCode(input)).toBe("invalid_shape");
  });

  it("gives a path in the message", () => {
    const input = raw();
    input.findings[0].severity = "urgent";
    const outcome = readScanResult(input);
    expect(!outcome.ok && outcome.error.message).toContain("findings[0].severity");
  });
});

describe("readScanResult hostile input", () => {
  it("does not let __proto__, constructor or prototype keys through", () => {
    const text = JSON.stringify(raw()).replace(
      '"scanId"',
      '"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}},"scanId"',
    );
    const input = JSON.parse(text);
    expect(Object.hasOwn(input, "__proto__")).toBe(true);
    const outcome = readScanResult(input);
    expect(outcome.ok).toBe(true);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    if (outcome.ok) {
      expect(Object.hasOwn(outcome.result, "__proto__")).toBe(false);
      expect(Object.hasOwn(outcome.result, "constructor")).toBe(false);
      expect(Object.getPrototypeOf(outcome.result)).toBe(Object.prototype);
    }
  });

  it("does not read required fields from a polluted prototype", () => {
    const input = raw();
    delete input.scanId;
    Object.setPrototypeOf(input, { scanId: "inherited" });
    expect(errorCode(input)).toBe("invalid_shape");
  });

  it("refuses too many findings and too many coverage entries", () => {
    const many = raw();
    many.findings = new Array(READ_LIMITS.findings + 1).fill(many.findings[0]);
    expect(errorCode(many)).toBe("too_large");
    const cov = raw();
    cov.coverage = new Array(READ_LIMITS.coverage + 1).fill(cov.coverage[0]);
    expect(errorCode(cov)).toBe("too_large");
  });

  it("accepts a result exactly at the findings limit", () => {
    const input = raw();
    const first = input.findings[0];
    input.findings = Array.from({ length: READ_LIMITS.findings }, (_, i) => ({
      ...first,
      id: `f${i}`,
    }));
    expect(readScanResult(input).ok).toBe(true);
  });

  it("refuses oversized inner lists and strings", () => {
    const list = raw();
    list.findings[0].references.cwe = new Array(READ_LIMITS.list + 1).fill("CWE-1");
    expect(errorCode(list)).toBe("too_large");
    const text = raw();
    text.findings[0].evidence = "x".repeat(READ_LIMITS.string + 1);
    expect(errorCode(text)).toBe("too_large");
  });

  it("returns an error for a huge sparse array without walking it", () => {
    const input = raw();
    input.findings = new Array(2 ** 32 - 1);
    expect(errorCode(input)).toBe("too_large");
  });

  it("never throws on throwing getters or revoked proxies", () => {
    const getter = raw();
    Object.defineProperty(getter, "scanId", {
      enumerable: true,
      get() {
        throw new Error("boom");
      },
    });
    expect(errorCode(getter)).toBe("invalid_shape");
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    expect(() => readScanResult(proxy)).not.toThrow();
    expect(errorCode(proxy)).toBe("invalid_shape");
  });

  it("handles a self-referencing object", () => {
    const input = raw();
    input.findings = [input];
    expect(errorCode(input)).toBe("invalid_shape");
  });
});

describe("readScanResult array and proxy hardening", () => {
  it("normalizes schemaVersion to SCHEMA_VERSION for a newer minor", () => {
    const input = raw();
    input.schemaVersion = "1.7";
    const outcome = readScanResult(input);
    expect(outcome.ok && outcome.result.schemaVersion).toBe(SCHEMA_VERSION);
    expect(outcome.ok && outcome.sourceVersion).toBe("1.7");
  });

  it("refuses holes and sparse arrays instead of keeping undefined entries", () => {
    const sparse = raw();
    sparse.findings = new Array(3);
    expect(errorCode(sparse)).toBe("invalid_shape");
    const hole = raw();
    hole.findings = [, , hole.findings[0]];
    expect(errorCode(hole)).toBe("invalid_shape");
    const inner = raw();
    inner.findings[0].references.cwe = new Array(2);
    expect(errorCode(inner)).toBe("invalid_shape");
    const scopes = raw();
    scopes.requestedScopes = new Array(1);
    expect(errorCode(scopes)).toBe("invalid_shape");
  });

  it("does not run an own `constructor` species hook", () => {
    let ran = false;
    const input = raw();
    input.findings.constructor = {
      [Symbol.species]: function () {
        ran = true;
        return {};
      },
    };
    const outcome = readScanResult(input);
    expect(ran).toBe(false);
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(Array.isArray(outcome.result.findings)).toBe(true);
  });

  it("does not run getters on objects or array elements", () => {
    let ran = false;
    const input = raw();
    Object.defineProperty(input.findings[0], "title", {
      enumerable: true,
      get() {
        ran = true;
        return "t";
      },
    });
    expect(errorCode(input)).toBe("invalid_shape");
    const arr = raw();
    Object.defineProperty(arr.findings, "0", {
      enumerable: true,
      get() {
        ran = true;
        return {};
      },
    });
    expect(errorCode(arr)).toBe("invalid_shape");
    expect(ran).toBe(false);
  });

  it("reads a proxy's length once, so a lying length cannot bypass the cap", () => {
    const real = raw().findings;
    let lengthReads = 0;
    const lying = new Proxy(real, {
      getOwnPropertyDescriptor(target, key) {
        if (key === "length") {
          lengthReads += 1;
          return { value: lengthReads === 1 ? 1 : 10 ** 9, writable: true, configurable: false };
        }
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
      get(target, key, receiver) {
        return key === "length" ? 10 ** 9 : Reflect.get(target, key, receiver);
      },
    });
    const input = raw();
    input.findings = lying;
    expect(readScanResult(input).ok).toBe(true);
    expect(lengthReads).toBe(1);
    const huge = raw();
    huge.findings = new Proxy(real, {
      getOwnPropertyDescriptor: () => ({ value: 10 ** 9, writable: true, configurable: false }),
    });
    expect(errorCode(huge)).toBe("too_large");
  });

  it("never throws when getPrototypeOf or other traps throw", () => {
    const trap = () => {
      throw new Error("trap");
    };
    const hostile = new Proxy({}, { getPrototypeOf: trap, getOwnPropertyDescriptor: trap });
    expect(() => readScanResult(hostile)).not.toThrow();
    const input = raw();
    input.findings[0] = hostile;
    expect(() => readScanResult(input)).not.toThrow();
    expect(errorCode(input)).toBe("invalid_shape");
    // A trap that throws a hostile proxy: the catch block must not probe its prototype.
    const evil = new Proxy(new Error("evil"), { getPrototypeOf: trap });
    const thrower = raw();
    thrower.target = new Proxy(
      {},
      {
        getOwnPropertyDescriptor() {
          throw evil;
        },
      },
    );
    expect(() => readScanResult(thrower)).not.toThrow();
    expect(errorCode(thrower)).toBe("invalid_shape");
    // The reader's own failure must come back as itself, not trip over the proxy trap.
    const protoOnly = raw();
    protoOnly.target = new Proxy({ repo: 1 }, { getPrototypeOf: trap });
    expect(() => readScanResult(protoOnly)).not.toThrow();
    expect(errorCode(protoOnly)).toBe("invalid_shape");
  });

  it("refuses duplicate finding ids", () => {
    const input = raw();
    input.findings.push({ ...input.findings[0] });
    const outcome = readScanResult(input);
    expect(!outcome.ok && outcome.error.code).toBe("invalid_shape");
    expect(!outcome.ok && outcome.error.message).toContain("findings[1].id");
  });

  it("requires line numbers of at least 1", () => {
    const input = raw();
    input.findings[0].location.line = 0;
    expect(errorCode(input)).toBe("invalid_shape");
  });

  it("caps the total number of array entries", () => {
    const input = raw();
    const finding = input.findings[0];
    const count = Math.floor(READ_LIMITS.entries / READ_LIMITS.list) + 5;
    input.findings = Array.from({ length: count }, (_, i) => ({
      ...finding,
      id: `f${i}`,
      references: { cwe: new Array(READ_LIMITS.list).fill("CWE-1"), owasp: [], cve: [] },
    }));
    expect(errorCode(input)).toBe("too_large");
  });
});

describe("enum constants", () => {
  it("accept every listed value and have no duplicates", () => {
    for (const values of [
      AUTHORIZATION_CHECK_IDS,
      AUTHORIZATION_CHECK_STATUSES,
      CONFIDENCES,
      COVERAGE_STATUSES,
      FINDING_CATEGORIES,
      FINDING_CONTEXTS,
      FINDING_STATUSES,
      LOCATION_KINDS,
      OVERALL_STATUSES,
      SCAN_SCOPES,
      SEVERITIES,
    ]) {
      expect(new Set(values).size).toBe(values.length);
    }
    for (const category of FINDING_CATEGORIES) {
      const input = raw();
      input.findings[0].category = category;
      expect(readScanResult(input).ok).toBe(true);
    }
    for (const status of OVERALL_STATUSES) {
      const input = raw();
      input.overallStatus = status;
      expect(readScanResult(input).ok).toBe(true);
    }
  });
});
