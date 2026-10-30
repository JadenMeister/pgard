#!/usr/bin/env node
// CONSISTENCY CHECK ONLY: compares the claims in the registry's attestation JSON with a tarball.
// The JSON is unsigned for this script: anyone who can alter registry responses can forge a
// statement that passes. Trust comes only from `gh attestation verify` (signature and identity)
// or from a sha256 taken from the GitHub run summary; update-formula.sh requires one of them.
// Checks that a downloaded pgard tarball is the one the release's provenance statement names.
// Usage: node verify-provenance.mjs <attestations.json> <tarball> <version> [expected-sha256]
// <attestations.json> is the registry's attestation document for the version (what
// `npm view pgard@<v> dist.attestations.url` points to). The SLSA provenance statement in it is
// written by the release workflow run and names the tarball by digest (sha512), the repository,
// the workflow file and the tag. This script compares those with the file in hand; it does not
// check the Sigstore signature (`gh attestation verify` and `npm audit signatures` do, see README).
// An optional sha256 recorded by the release run (the run summary prints it) is compared too.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const EXPECTED_REPOSITORY = "https://github.com/JadenMeister/pgard";
export const EXPECTED_WORKFLOW = ".github/workflows/release.yml";
const SLSA_PROVENANCE = "https://slsa.dev/provenance/v1";

/** The in-toto statements of an attestation document, decoded; `[]` when it has none. */
export function statementsOf(document) {
  const list = Array.isArray(document?.attestations) ? document.attestations : [];
  return list.flatMap((entry) => {
    const payload = entry?.bundle?.dsseEnvelope?.payload;
    if (typeof payload !== "string") return [];
    try {
      const statement = JSON.parse(Buffer.from(payload, "base64").toString("utf8"));
      return [{ predicateType: entry.predicateType, statement }];
    } catch {
      return [];
    }
  });
}

/**
 * Returns one message per problem; empty means the tarball matches the provenance statement.
 * `tarball` is a Buffer; `expectedSha256` is an optional hex digest recorded by the release run.
 */
export function provenanceProblems({ document, tarball, version, expectedSha256 }) {
  const problems = [];
  const sha512 = createHash("sha512").update(tarball).digest("hex");
  const sha256 = createHash("sha256").update(tarball).digest("hex");
  if (
    expectedSha256 !== undefined &&
    expectedSha256 !== "" &&
    expectedSha256.toLowerCase() !== sha256
  ) {
    problems.push(
      `sha256 ${sha256} differs from the release run's recorded sha256 ${expectedSha256}`,
    );
  }
  const provenance = statementsOf(document).filter(
    (item) =>
      item.predicateType === SLSA_PROVENANCE || item.statement?.predicateType === SLSA_PROVENANCE,
  );
  if (provenance.length === 0) {
    problems.push(`no SLSA provenance statement (${SLSA_PROVENANCE}) for pgard@${version}`);
    return problems;
  }
  for (const { statement } of provenance) {
    const subjects = Array.isArray(statement.subject) ? statement.subject : [];
    const named = subjects.find((subject) => subject?.name === `pkg:npm/pgard@${version}`);
    if (named === undefined) {
      problems.push(`the provenance subject is not pkg:npm/pgard@${version}`);
    } else if (String(named.digest?.sha512 ?? "").toLowerCase() !== sha512) {
      problems.push(
        `sha512 ${sha512} differs from the provenance subject digest ${named.digest?.sha512 ?? "(none)"}`,
      );
    }
    const workflow = statement.predicate?.buildDefinition?.externalParameters?.workflow;
    if (workflow?.repository !== EXPECTED_REPOSITORY) {
      problems.push(
        `provenance repository is ${workflow?.repository}, expected ${EXPECTED_REPOSITORY}`,
      );
    }
    if (workflow?.path !== EXPECTED_WORKFLOW) {
      problems.push(`provenance workflow is ${workflow?.path}, expected ${EXPECTED_WORKFLOW}`);
    }
    if (workflow?.ref !== `refs/tags/v${version}`) {
      problems.push(`provenance ref is ${workflow?.ref}, expected refs/tags/v${version}`);
    }
  }
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [attestations, tarball, version, expectedSha256] = process.argv.slice(2);
  if (version === undefined) {
    console.error("usage: verify-provenance.mjs <attestations.json> <tarball> <version> [sha256]");
    process.exit(2);
  }
  const problems = provenanceProblems({
    document: JSON.parse(readFileSync(attestations, "utf8")),
    tarball: readFileSync(tarball),
    version,
    expectedSha256,
  });
  if (problems.length > 0) {
    for (const problem of problems) console.error(`provenance: ${problem}`);
    process.exit(1);
  }
  console.log(
    `provenance claims: pgard@${version} is consistent with the registry's attestation document (consistency check only; the signature is not examined here)`,
  );
}
