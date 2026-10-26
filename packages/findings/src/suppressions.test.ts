import { describe, expect, it } from "vitest";
import type { Finding, ScanResult } from "./contract.js";
import type { ProjectSuppression } from "./project-config.js";
import {
  BROAD_SUPPRESSION_THRESHOLD,
  applySuppressions,
  formatSuppressedCount,
  isSuppressionExpired,
  suppressionNotices,
} from "./suppressions.js";

const NOW = new Date("2026-10-27T12:00:00Z");

function finding(overrides: Partial<Finding> & { path?: string | null } = {}): Finding {
  const { path = "src/db.ts", ...rest } = overrides;
  return {
    id: `${rest.ruleId ?? "PG-SQL-001"}:${path ?? "none"}:${Math.random()}`,
    ruleId: "PG-SQL-001",
    title: "t",
    category: "injection",
    severity: "high",
    status: "suspected",
    confidence: "medium",
    location: { kind: "file", path, line: 3, url: null, commit: null },
    evidence: "e",
    impact: "i",
    recommendation: "r",
    references: { cwe: [], owasp: [], cve: [] },
    sources: ["code"],
    ...rest,
  };
}

const web = (ruleId = "PG-WEB-005"): Finding =>
  finding({
    ruleId,
    sources: ["web"],
    location: { kind: "url", path: null, line: null, url: "http://127.0.0.1:3000/", commit: null },
  });

const entry = (overrides: Partial<ProjectSuppression> = {}): ProjectSuppression => ({
  ruleId: "PG-SQL-001",
  path: "scripts/**",
  reason: "Admin-only script",
  ...overrides,
});

const suppressedOf = (findings: Finding[]) => findings.filter((f) => f.suppression !== undefined);

describe("applySuppressions matching", () => {
  it("does nothing, and reports nothing, without suppressions", () => {
    const input = [finding()];
    const applied = applySuppressions(input, [], NOW);
    expect(applied.summary).toBeNull();
    expect(applied.findings).toEqual(input);
  });

  it("marks a finding by rule id and path glob and keeps it", () => {
    const hit = finding({ path: "scripts/a/b.ts" });
    const otherRule = finding({ path: "scripts/a.ts", ruleId: "PG-XSS-001" });
    const otherPath = finding({ path: "src/a.ts" });
    const applied = applySuppressions([hit, otherRule, otherPath], [entry()], NOW);
    expect(applied.findings).toHaveLength(3);
    expect(applied.findings[0]?.suppression).toEqual({
      reason: "Admin-only script",
      source: "pgard.config.json",
    });
    expect(applied.findings[1]?.suppression).toBeUndefined();
    expect(applied.findings[2]?.suppression).toBeUndefined();
    expect(applied.summary).toMatchObject({ suppressed: 1, critical: 0, incomplete: false });
    expect(applied.summary?.entries[0]).toMatchObject({ matched: 1, state: "active" });
  });

  it("does not change the input findings", () => {
    const input = finding({ path: "scripts/a.ts" });
    applySuppressions([input], [entry()], NOW);
    expect(input.suppression).toBeUndefined();
  });

  it("keeps the expiry on the finding", () => {
    const applied = applySuppressions(
      [finding({ path: "scripts/a.ts" })],
      [entry({ expires: "2027-01-31" })],
      NOW,
    );
    expect(applied.findings[0]?.suppression?.expires).toBe("2027-01-31");
  });

  it("uses the first matching entry but counts every entry's matches", () => {
    const applied = applySuppressions(
      [finding({ path: "scripts/a.ts" })],
      [entry({ reason: "first" }), entry({ reason: "second", path: "**/a.ts" })],
      NOW,
    );
    expect(applied.findings[0]?.suppression?.reason).toBe("first");
    expect(applied.summary?.entries.map((e) => e.matched)).toEqual([1, 1]);
    expect(applied.summary?.suppressed).toBe(1);
  });

  it("matches a finding without a file path only through a path that matches every file", () => {
    const narrow = applySuppressions(
      [web()],
      [entry({ ruleId: "PG-WEB-005", path: "src/**" })],
      NOW,
    );
    expect(suppressedOf(narrow.findings)).toHaveLength(0);
    const everything = applySuppressions(
      [web()],
      [entry({ ruleId: "PG-WEB-005", path: "**" })],
      NOW,
    );
    expect(suppressedOf(everything.findings)).toHaveLength(1);
    expect(everything.summary?.entries[0]?.wildcard).toBe(true);
  });

  it("never matches a web finding by a path glob even if the finding carries a path", () => {
    const odd = finding({
      ruleId: "PG-WEB-005",
      path: "scripts/a.ts",
      location: {
        kind: "url",
        path: "scripts/a.ts",
        line: null,
        url: "http://127.0.0.1:3000/",
        commit: null,
      },
    });
    const applied = applySuppressions([odd], [entry({ ruleId: "PG-WEB-005" })], NOW);
    expect(suppressedOf(applied.findings)).toHaveLength(0);
  });

  it("matches a history finding by its file path", () => {
    const history = finding({
      ruleId: "PG-SECRET-003",
      sources: ["history"],
      location: { kind: "commit", path: "scripts/k.js", line: 1, url: null, commit: "abc" },
    });
    const applied = applySuppressions(
      [history],
      [entry({ ruleId: "PG-SECRET-003", path: "scripts/**" })],
      NOW,
    );
    expect(suppressedOf(applied.findings)).toHaveLength(1);
  });
});

describe("expiry", () => {
  it("is valid through the end of the expires day (UTC)", () => {
    expect(isSuppressionExpired("2026-10-27", NOW)).toBe(false);
    expect(isSuppressionExpired("2026-10-26", NOW)).toBe(true);
    expect(isSuppressionExpired(undefined, NOW)).toBe(false);
    expect(isSuppressionExpired("garbage", NOW)).toBe(true);
  });

  it("does not apply an expired entry, and reports it", () => {
    const applied = applySuppressions(
      [finding({ path: "scripts/a.ts" })],
      [entry({ expires: "2026-10-26" })],
      NOW,
    );
    expect(suppressedOf(applied.findings)).toHaveLength(0);
    expect(applied.summary).toMatchObject({ suppressed: 0 });
    expect(applied.summary?.entries[0]).toMatchObject({ state: "expired", matched: 0 });
    const notices = suppressionNotices({
      suppressions: applied.summary ?? undefined,
      findings: applied.findings,
    });
    expect(notices.map((n) => n.kind)).toEqual(["expired"]);
    expect(notices[0]?.text).toContain("expired on 2026-10-26");
  });
});

describe("critical policy", () => {
  it("lets a critical finding be suppressed but counts and flags it", () => {
    const critical = finding({ path: "scripts/a.ts", severity: "critical" });
    const high = finding({ path: "scripts/b.ts" });
    const applied = applySuppressions([critical, high], [entry()], NOW);
    expect(applied.summary).toMatchObject({ suppressed: 2, critical: 1 });
    expect(formatSuppressedCount(applied.summary as never)).toBe(
      "2 suppressed (including 1 critical)",
    );
    const notices = suppressionNotices({
      suppressions: applied.summary ?? undefined,
      findings: [...applied.findings, finding()],
    });
    expect(notices.map((n) => n.kind)).toEqual(["critical"]);
    expect(notices[0]?.count).toBe(1);
  });

  it("omits 'including' when no critical finding is suppressed", () => {
    expect(formatSuppressedCount({ suppressed: 3, critical: 0 })).toBe("3 suppressed");
  });
});

describe("broad patterns", () => {
  const many = (count: number) =>
    Array.from({ length: count }, (_, index) => finding({ path: `scripts/f${index}.ts` }));

  it("flags an entry that matches more findings than the threshold", () => {
    const applied = applySuppressions(many(BROAD_SUPPRESSION_THRESHOLD + 1), [entry()], NOW);
    const notices = suppressionNotices({
      suppressions: applied.summary ?? undefined,
      findings: [...applied.findings, finding()],
    });
    expect(notices.map((n) => n.kind)).toEqual(["broad"]);
    expect(notices[0]?.text).toContain(`${BROAD_SUPPRESSION_THRESHOLD + 1} findings`);
  });

  it("does not flag an entry at the threshold", () => {
    const applied = applySuppressions(many(BROAD_SUPPRESSION_THRESHOLD), [entry()], NOW);
    expect(
      suppressionNotices({
        suppressions: applied.summary ?? undefined,
        findings: [...applied.findings, finding()],
      }),
    ).toEqual([]);
  });

  it.each(["**", "*", "**/*"])("flags the wildcard path %s", (path) => {
    const applied = applySuppressions([finding({ path: "a/b.ts" })], [entry({ path })], NOW);
    expect(applied.summary?.entries[0]?.wildcard).toBe(true);
    const kinds = suppressionNotices({
      suppressions: applied.summary ?? undefined,
      findings: [...applied.findings, finding({ ruleId: "PG-XSS-001" })],
    }).map((n) => n.kind);
    expect(kinds).toContain("wildcard");
  });

  it("does not call a narrow pattern a wildcard", () => {
    const applied = applySuppressions([finding()], [entry({ path: "**/*.ts" })], NOW);
    expect(applied.summary?.entries[0]?.wildcard).toBe(false);
  });
});

describe("a malicious config", () => {
  it("that suppresses everything keeps every finding in the result and says so", () => {
    const rules = ["PG-SQL-001", "PG-XSS-001", "PG-SECRET-003", "PG-WEB-005"];
    const findings = [
      ...rules.flatMap((ruleId) => [
        finding({ ruleId, path: "src/a.ts", severity: "critical" }),
        finding({ ruleId, path: "lib/b.ts" }),
      ]),
      web(),
    ];
    const suppressions = [...rules, "PG-WEB-005"].map((ruleId) =>
      entry({ ruleId, path: "**", reason: "all good, nothing to see here" }),
    );
    const applied = applySuppressions(findings, suppressions, NOW);
    expect(applied.findings).toHaveLength(findings.length);
    expect(applied.findings.every((f) => f.suppression !== undefined)).toBe(true);
    expect(applied.summary?.suppressed).toBe(findings.length);
    expect(applied.summary?.critical).toBe(4);
    const kinds = suppressionNotices({
      suppressions: applied.summary ?? undefined,
      findings: applied.findings,
    }).map((n) => n.kind);
    expect(kinds).toContain("everything");
    expect(kinds).toContain("critical");
    expect(kinds.filter((kind) => kind === "wildcard")).toHaveLength(5);
  });

  it("cannot suppress through a different rule id or a pattern that misses the path", () => {
    const applied = applySuppressions(
      [finding({ path: "src/a.ts" })],
      [entry({ ruleId: "PG-XSS-001", path: "**" }), entry({ path: "other/**" })],
      NOW,
    );
    expect(suppressedOf(applied.findings)).toHaveLength(0);
  });
});

describe("pattern work budget", () => {
  it("stops suppressing when the budget runs out and says so", () => {
    const pattern = "*a*a*a*a*a*a*a*a*a*b/**";
    const nasty = Array.from({ length: 50 }, (_, index) =>
      finding({ path: `${"a".repeat(60)}x${index}/f.ts` }),
    );
    const applied = applySuppressions(nasty, [entry({ path: pattern })], NOW, 1);
    expect(applied.summary?.incomplete).toBe(true);
    expect(suppressedOf(applied.findings)).toHaveLength(0);
    expect(applied.findings).toHaveLength(50);
    const kinds = suppressionNotices({
      suppressions: applied.summary ?? undefined,
      findings: applied.findings,
    }).map((n) => n.kind);
    expect(kinds).toContain("incomplete");
  });
});

describe("notices", () => {
  it("are empty without a summary", () => {
    expect(suppressionNotices({ findings: [finding()] } as Pick<ScanResult, "findings">)).toEqual(
      [],
    );
  });
});
