/**
 * Corpus check for suggested fixes: for every positive corpus sample of a fixable rule, scan it,
 * and where the finding gets a diff, apply the diff in memory (never to the corpus file), scan the
 * result and require that the finding is gone, that nothing else appeared, and that a second round
 * offers no diff for the same place (idempotence). Samples without a diff must get guidance.
 */
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { applyLineReplacementDiff, type Finding } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import { attachFixSuggestions } from "./attach-fixes.js";
import { FIXABLE_RULE_IDS } from "./suggest-fix.js";
import { scanSourceCode } from "../scan-source.js";

const corpusRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../../tests/corpus",
);

async function scanSample(directory: string, name: string, content: string | null) {
  if (content === null)
    copyFileSync(path.join(corpusRoot, directory, name), path.join(directory, name));
  else writeFileSync(path.join(directory, name), content);
  const output = await scanSourceCode(directory);
  return attachFixSuggestions(output.findings, directory);
}

const key = (finding: Finding) => `${finding.ruleId}:${finding.location.path}:${finding.id}`;

describe("suggested fixes against the corpus", () => {
  for (const ruleId of FIXABLE_RULE_IDS) {
    const positives = readdirSync(path.join(corpusRoot, ruleId, "positive")).sort();
    it(`${ruleId}: a suggested diff removes its finding and is idempotent`, async () => {
      let diffs = 0;
      for (const name of positives) {
        const directory = mkdtempSync(path.join(tmpdir(), "pgard-fix-corpus-"));
        try {
          if (/\.(properties|ya?ml)$/.test(name))
            writeFileSync(path.join(directory, "pom.xml"), "<project/>\n");
          const sourcePath = path.join(corpusRoot, ruleId, "positive", name);
          const original = readFileSync(sourcePath, "utf8");
          // A sample the rules are known to miss has no finding to fix.
          if (original.split("\n", 1)[0]?.includes("known=miss")) continue;
          mkdirSync(path.join(directory, "x"), { recursive: true });
          const findings = await scanSample(directory, name, original);
          const own = findings.filter((finding) => finding.ruleId === ruleId);
          expect(own.length, name).toBeGreaterThan(0);
          for (const finding of own) {
            expect(finding.fix, `${name}: a fixable rule always gets a fix entry`).toBeDefined();
            if (finding.fix?.kind !== "diff") {
              expect(finding.fix?.diff, name).toBeUndefined();
              continue;
            }
            diffs += 1;
            const changed = applyLineReplacementDiff(original, finding.fix.diff ?? "");
            expect(changed, `${name}: the diff applies to the sample`).not.toBeNull();
            expect(changed, `${name}: the diff changes the file`).not.toBe(original);
            const after = await scanSample(directory, name, changed);
            // The finding of this place is gone (same line, same rule).
            expect(
              after.filter(
                (candidate) =>
                  candidate.ruleId === ruleId && candidate.location.line === finding.location.line,
              ),
              `${name}: finding still reported after applying the diff`,
            ).toEqual([]);
            // Nothing new appeared.
            const before = new Set(findings.map(key));
            const introduced = after.filter(
              (candidate) =>
                !before.has(key(candidate)) && candidate.location.line !== finding.location.line,
            );
            expect(
              introduced.map((f) => f.ruleId),
              `${name}: new findings after the fix`,
            ).toEqual([]);
            // Idempotent: no diff is offered again for that line.
            expect(
              after.filter(
                (candidate) =>
                  candidate.fix?.kind === "diff" &&
                  candidate.location.line === finding.location.line,
              ),
            ).toEqual([]);
          }
        } finally {
          rmSync(directory, { recursive: true, force: true });
        }
      }
      expect(diffs, `${ruleId} has no positive sample with a diff`).toBeGreaterThan(0);
    });
  }
});
