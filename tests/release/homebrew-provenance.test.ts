import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  EXPECTED_REPOSITORY,
  EXPECTED_WORKFLOW,
  provenanceProblems,
  statementsOf,
} from "../../packaging/homebrew/verify-provenance.mjs";

const tarball = Buffer.from("pretend this is pgard-0.2.0.tgz");
const version = "0.2.0";
const sha512 = createHash("sha512").update(tarball).digest("hex");
const sha256 = createHash("sha256").update(tarball).digest("hex");

/** A registry attestation document with one SLSA provenance statement. */
function document(overrides: { digest?: string; name?: string; workflow?: object } = {}) {
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [
      {
        name: overrides.name ?? `pkg:npm/pgard@${version}`,
        digest: { sha512: overrides.digest ?? sha512 },
      },
    ],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        externalParameters: {
          workflow: {
            repository: EXPECTED_REPOSITORY,
            path: EXPECTED_WORKFLOW,
            ref: `refs/tags/v${version}`,
            ...overrides.workflow,
          },
        },
      },
    },
  };
  return {
    attestations: [
      {
        predicateType: "https://slsa.dev/provenance/v1",
        bundle: {
          dsseEnvelope: { payload: Buffer.from(JSON.stringify(statement)).toString("base64") },
        },
      },
    ],
  };
}

describe("homebrew provenance check (L3 of #358)", () => {
  it("accepts a tarball that matches the provenance subject, workflow and tag", () => {
    expect(provenanceProblems({ document: document(), tarball, version })).toEqual([]);
    expect(
      provenanceProblems({ document: document(), tarball, version, expectedSha256: sha256 }),
    ).toEqual([]);
  });

  it("mutation: a tarball that differs from the provenance subject digest is refused", () => {
    const other = Buffer.from("a different tarball");
    expect(provenanceProblems({ document: document(), tarball: other, version })).toEqual([
      expect.stringContaining("differs from the provenance subject digest"),
    ]);
  });

  it("mutation: a sha256 that differs from the release run's record is refused", () => {
    expect(
      provenanceProblems({
        document: document(),
        tarball,
        version,
        expectedSha256: "00".repeat(32),
      }),
    ).toEqual([expect.stringContaining("release run's recorded sha256")]);
  });

  it("mutation: a statement for another version, repository, workflow or tag is refused", () => {
    expect(
      provenanceProblems({ document: document({ name: "pkg:npm/pgard@0.1.0" }), tarball, version }),
    ).toEqual([expect.stringContaining("subject is not pkg:npm/pgard@0.2.0")]);
    expect(
      provenanceProblems({
        document: document({ workflow: { repository: "https://github.com/evil/pgard" } }),
        tarball,
        version,
      }),
    ).toEqual([expect.stringContaining("provenance repository")]);
    expect(
      provenanceProblems({
        document: document({ workflow: { path: ".github/workflows/other.yml" } }),
        tarball,
        version,
      }),
    ).toEqual([expect.stringContaining("provenance workflow")]);
    expect(
      provenanceProblems({
        document: document({ workflow: { ref: "refs/heads/main" } }),
        tarball,
        version,
      }),
    ).toEqual([expect.stringContaining("provenance ref")]);
  });

  it("mutation: a missing or malformed attestation document is refused", () => {
    for (const bad of [{}, { attestations: [] }, { attestations: [{ bundle: {} }] }, null]) {
      expect(provenanceProblems({ document: bad, tarball, version })).toEqual([
        expect.stringContaining("no SLSA provenance statement"),
      ]);
    }
    expect(
      statementsOf({ attestations: [{ bundle: { dsseEnvelope: { payload: "!!" } } }] }),
    ).toEqual([]);
  });
});
