import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanSourceCode } from "../scan-source.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

const SINK =
  'class T { fun t(request: HttpServletRequest) { Runtime.getRuntime().exec(request.getParameter("a")) } }\n';

/** Hostile-repo audit (#368): deep Kotlin nesting keeps its findings or says it is partial. */
describe("deeply nested Kotlin", () => {
  it.each([
    ["a + chain", (k: number) => `val x = a${" + a".repeat(k)}\n`],
    ["nested calls", (k: number) => `val x = ${"f(".repeat(k)}${")".repeat(k)}\n`],
    ["nested blocks", (k: number) => `fun m() { ${"if(a){".repeat(k)}${"}".repeat(k)} }\n`],
  ])(
    "%s 1,000 and 30,000 deep",
    async (_name, body) => {
      for (const depth of [1_000, 30_000]) {
        const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-deep-kt-")));
        roots.push(root);
        writeFileSync(path.join(root, "T.kt"), SINK + body(depth));
        const output = await scanSourceCode(root, { analysisWorker: null });
        expect(output.findings.map((finding) => finding.ruleId)).toEqual(["PG-CMD-003"]);
        const kotlin = output.coverage.find((entry) => entry.area === "source:kotlin");
        if (kotlin?.status !== "completed") {
          expect(kotlin?.status).toBe("partial");
          expect(kotlin?.note).toContain("nested too deeply");
        }
      }
    },
    20_000,
  );

  it("finds a source at the start of a 30,000-term + chain", async () => {
    const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-deep-kt-")));
    roots.push(root);
    const chain = `request.getParameter("a")${' + "x"'.repeat(30_000)}`;
    writeFileSync(
      path.join(root, "T.kt"),
      `class T { fun t(request: HttpServletRequest) { Runtime.getRuntime().exec(${chain}) } }\n`,
    );
    const output = await scanSourceCode(root, { analysisWorker: null });
    expect(output.findings.map((finding) => finding.ruleId)).toEqual(["PG-CMD-003"]);
  }, 20_000);
});
