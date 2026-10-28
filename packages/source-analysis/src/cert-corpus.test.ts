import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scanSourceCode } from "./scan-source.js";

const CORPUS = fileURLToPath(new URL("../../../tests/corpus/", import.meta.url));

/** Scans one real corpus sample, alone in a fresh project, and returns its references.cert. */
async function certOf(rule: string, sample: string): Promise<Array<string[] | undefined>> {
  const root = mkdtempSync(path.join(tmpdir(), "pgard-cert-"));
  try {
    copyFileSync(path.join(CORPUS, rule, "positive", sample), path.join(root, sample));
    const output = await scanSourceCode(root);
    return output.findings.filter((f) => f.ruleId === rule).map((f) => f.references.cert);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

describe("direct CERT references on real analyzer findings", () => {
  it("gives MSC02-J to weak random source findings in Java and Kotlin", async () => {
    for (const sample of ["java-random-iv.java", "kotlin-random-iv.kt"]) {
      const certs = await certOf("PG-CRYPTO-003", sample);
      expect(certs.length, sample).toBeGreaterThan(0);
      for (const cert of certs) expect(cert, sample).toEqual(["MSC02-J"]);
    }
  });

  it("gives no CERT reference to a DES cipher finding", async () => {
    const certs = await certOf("PG-CRYPTO-003", "java-cipher-des.java");
    expect(certs.length).toBeGreaterThan(0);
    for (const cert of certs) expect(cert).toBeUndefined();
  });

  it("gives IDS04-J to a zip slip finding and FIO16-J to a plain path finding", async () => {
    const zip = await certOf("PG-PATH-002", "zip-slip-nio-copy.java");
    expect(zip.length).toBeGreaterThan(0);
    for (const cert of zip) expect(cert).toEqual(["IDS04-J"]);
    const plain = await certOf("PG-PATH-002", "zipfile-open.java");
    expect(plain.length).toBeGreaterThan(0);
    for (const cert of plain) expect(cert).toEqual(["FIO16-J"]);
  });
});
