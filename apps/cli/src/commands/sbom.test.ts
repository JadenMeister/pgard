import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { collectDependencies, type DependencyCollection } from "@pgard/dependencies";
import { isPathInsideDirectory } from "@pgard/report";
import type { AuthorizationOutcome } from "@pgard/scan-core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { main } from "../app.js";
import { makeSbomDirDefault, type CliDeps } from "../deps.js";
import {
  ALLOWED,
  BLOCKED,
  createTestContext,
  createTestDeps,
  createTestIo,
  noInterrupts,
} from "../test-support.js";
import { parseCommandLine, UsageError } from "../options.js";
import { UserCancelledError } from "../ui/components/prompts.js";
import { runSbom, sbomFileName, type SbomCommand } from "./sbom.js";

const REVISION = "0123456789abcdef0123456789abcdef01234567";
const OUTCOME: AuthorizationOutcome = {
  summary: ALLOWED,
  repo: "owner/name",
  revision: REVISION,
  repositoryId: 4242,
};
const NOW = Date.UTC(2026, 9, 28, 9, 0, 0);
const COLLECTION: DependencyCollection = {
  dependencies: [
    {
      ecosystem: "npm",
      name: "@scope/pkg",
      version: "1.2.3",
      direct: true,
      lockfile: "npm",
      path: "package-lock.json",
    },
    {
      ecosystem: "Go",
      name: "github.com/Azure/x",
      version: "v1.0.0",
      direct: false,
      lockfile: "go.mod",
      path: "go.mod",
    },
  ],
  coverage: [
    { path: "package-lock.json", kind: "npm", status: "parsed", dependencyCount: 1, note: null },
    {
      path: "composer.lock",
      kind: "unsupported",
      status: "unsupported",
      dependencyCount: 0,
      note: "PHP (Composer) lockfiles are not supported yet; these dependencies were not checked.",
    },
  ],
  isTruncated: false,
  limitNotes: [],
  bytesRead: 0,
};

let base: string;
let outDir: string;
let seen: { collected: number; verified: number };

beforeEach(async () => {
  base = await mkdtemp(path.join(os.tmpdir(), "pgard-cli-sbom-"));
  outDir = path.join(base, "out");
  await mkdir(outDir);
  seen = { collected: 0, verified: 0 };
});
afterEach(async () => {
  await rm(base, { recursive: true, force: true });
});

function deps(
  options: {
    outcome?: AuthorizationOutcome;
    collection?: DependencyCollection;
    insideRepository?: boolean;
  } = {},
): CliDeps {
  return createTestDeps({
    findGitRoot: async () => path.join(base, "repo"),
    now: () => NOW,
    verifyProject: async () => {
      seen.verified += 1;
      return options.outcome ?? OUTCOME;
    },
    collectDependencies: async () => {
      seen.collected += 1;
      return options.collection ?? COLLECTION;
    },
    isPathInsideDirectory: async () => options.insideRepository === true,
    makeSbomDir: async () => {
      outDir = await mkdtemp(path.join(base, "auto-"));
      return outDir;
    },
  });
}

async function sbom(
  command: Partial<SbomCommand> = {},
  options: { deps?: CliDeps; isTTY?: boolean; locale?: "en" | "ko" } = {},
) {
  const captured = createTestIo({ isTTY: options.isTTY ?? false });
  const context = {
    ...createTestContext(captured, options.deps ?? deps()),
    ruleLocale: options.locale ?? ("en" as const),
  };
  const code = await runSbom(context, {
    format: "cyclonedx-json",
    outputDir: outDir,
    ...command,
  });
  return { captured, code };
}

describe("pgard sbom", () => {
  it("writes the SBOM with a fixed name and mode 0600, and prints the path", async () => {
    const { captured, code } = await sbom();
    expect(code).toBe(0);
    const files = await readdir(outDir);
    expect(files).toEqual([`pgard-sbom-20261028090000-01234567.cdx.json`]);
    const file = path.join(outDir, files[0] ?? "");
    if (process.platform !== "win32") expect((await stat(file)).mode & 0o777).toBe(0o600);
    const bom = JSON.parse(await readFile(file, "utf8")) as {
      bomFormat: string;
      specVersion: string;
      serialNumber: string;
      metadata: { component: { name: string }; properties: { name: string; value: string }[] };
      components: { purl: string }[];
    };
    expect(bom.bomFormat).toBe("CycloneDX");
    expect(bom.specVersion).toBe("1.6");
    expect(bom.serialNumber).toBe("urn:uuid:00000000-0000-4000-8000-000000000000");
    expect(bom.metadata.component.name).toBe("owner/name");
    expect(bom.components.map((component) => component.purl)).toEqual([
      "pkg:golang/github.com/Azure/x@v1.0.0",
      "pkg:npm/%40scope/pkg@1.2.3",
    ]);
    expect(bom.metadata.properties).toContainEqual({
      name: "pgard:unparsed-lockfile",
      value: "composer.lock (unsupported)",
    });
    expect(captured.stdout()).toContain("Saved CycloneDX SBOM (2 components)");
    expect(captured.stdout()).toContain(await realpath(file));
    expect(captured.stderr()).toContain("pgard:unparsed-lockfile");
  });

  it("is deterministic: the same input gives the same file apart from the serial number", async () => {
    await sbom();
    const first = await readdir(outDir);
    const firstText = await readFile(path.join(outDir, first[0] ?? ""), "utf8");
    await rm(path.join(outDir, first[0] ?? ""));
    await sbom();
    const second = await readdir(outDir);
    expect(second).toEqual(first);
    expect(await readFile(path.join(outDir, second[0] ?? ""), "utf8")).toBe(firstText);
  });

  it("never overwrites an existing file (exit 4)", async () => {
    const target = path.join(outDir, sbomFileName(new Date(NOW).toISOString(), REVISION));
    await writeFile(target, "mine");
    const { captured, code } = await sbom();
    expect(code).toBe(4);
    expect(await readFile(target, "utf8")).toBe("mine");
    expect(captured.stderr()).toContain("never overwritten");
  });

  it("says the refusal to overwrite in Korean", async () => {
    await writeFile(path.join(outDir, sbomFileName(new Date(NOW).toISOString(), REVISION)), "mine");
    const { captured, code } = await sbom({}, { locale: "ko" });
    expect(code).toBe(4);
    expect(captured.stderr()).toContain("덮어쓰지 않습니다");
    expect(captured.stderr()).not.toContain("refusing");
  });

  it("a failure while collecting exits 4 and removes the empty private directory", async () => {
    const failing = createTestDeps({
      ...deps(),
      collectDependencies: async () => {
        throw new Error("boom");
      },
    });
    const { captured, code } = await sbom({ outputDir: null }, { deps: failing });
    expect(code).toBe(4);
    expect(captured.stderr()).toContain("could not be built");
    await expect(stat(outDir)).rejects.toThrow();
  });

  it("does not follow a symbolic link planted at the file name", async () => {
    if (process.platform === "win32") return;
    const victim = path.join(base, "victim.txt");
    await writeFile(victim, "keep");
    await symlink(victim, path.join(outDir, sbomFileName(new Date(NOW).toISOString(), REVISION)));
    const { code } = await sbom();
    expect(code).toBe(4);
    expect(await readFile(victim, "utf8")).toBe("keep");
  });

  it("without --output-dir writes into a fresh private directory", async () => {
    const { captured, code } = await sbom({ outputDir: null });
    expect(code).toBe(0);
    expect(await readdir(outDir)).toHaveLength(1);
    expect(captured.stdout()).toContain(path.basename(outDir));
  });

  it("the default private directory has mode 0700", async () => {
    const dir = await makeSbomDirDefault();
    try {
      expect(path.basename(dir)).toMatch(/^pgard-sbom-/);
      if (process.platform !== "win32") expect((await stat(dir)).mode & 0o777).toBe(0o700);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("reads nothing when the repository cannot be verified (exit 3)", async () => {
    const { captured, code } = await sbom(
      {},
      { deps: deps({ outcome: { summary: BLOCKED, repo: "owner/name", revision: "abc" } }) },
    );
    expect(code).toBe(3);
    expect(seen).toEqual({ collected: 0, verified: 1 });
    expect(captured.stderr()).toContain("could not be verified");
    expect(await readdir(outDir)).toEqual([]);
  });

  it("reads nothing when the gate allowed but gave no repository id (same as pgard report)", async () => {
    const { code } = await sbom(
      {},
      { deps: deps({ outcome: { summary: ALLOWED, repo: "owner/name", revision: "abc" } }) },
    );
    expect(code).toBe(3);
    expect(seen.collected).toBe(0);
  });

  it("rejects a missing output directory before any check (exit 2)", async () => {
    const { captured, code } = await sbom({ outputDir: path.join(base, "nope") });
    expect(code).toBe(2);
    expect(seen).toEqual({ collected: 0, verified: 0 });
    expect(captured.stderr()).toContain("--output-dir");
  });

  it("refuses a directory inside the repository without a terminal to confirm (exit 2)", async () => {
    const { captured, code } = await sbom({}, { deps: deps({ insideRepository: true }) });
    expect(code).toBe(2);
    expect(seen).toEqual({ collected: 0, verified: 0 });
    expect(captured.stderr()).toContain("inside the Git repository");
    expect(captured.stderr()).toContain("Cannot confirm");
    expect(await readdir(outDir)).toEqual([]);
  });

  for (const [answer, writes] of [
    ["y", true],
    ["n", false],
  ] as const) {
    it(`asks before writing inside the repository: "${answer}" ${writes ? "writes" : "does not write"}`, async () => {
      const captured = createTestIo({ isTTY: true });
      const keys = {
        readKey: async () => ({ name: answer }),
        close: () => undefined,
        suspend: () => undefined,
      };
      const context = createTestContext(captured, deps({ insideRepository: true }), keys as never);
      const code = await runSbom(context, { format: "cyclonedx-json", outputDir: outDir });
      expect(captured.stderr()).toContain("inside the Git repository");
      expect(captured.stdout()).toContain("Save the SBOM inside the repository anyway?");
      expect(code).toBe(writes ? 0 : 2);
      expect(await readdir(outDir)).toHaveLength(writes ? 1 : 0);
    });
  }

  it("says the same things in Korean", async () => {
    const { captured, code } = await sbom({}, { locale: "ko" });
    expect(code).toBe(0);
    expect(captured.stdout()).toMatch(/SBOM을 저장했습니다/);
    expect(captured.stderr()).toMatch(/[가-힣]/);
    expect(captured.stderr()).toContain("pgard:unparsed-lockfile");
  });

  it("warns when the search was truncated", async () => {
    const { captured } = await sbom(
      {},
      { deps: deps({ collection: { ...COLLECTION, isTruncated: true } }) },
    );
    expect(captured.stderr()).toContain("limit");
  });

  it("shows the limits that were reached", async () => {
    const { captured } = await sbom(
      {},
      {
        deps: deps({
          collection: {
            ...COLLECTION,
            isTruncated: true,
            limitNotes: [
              "The 256 MiB limit on all lockfile data was reached; later files were not read.",
            ],
          },
        }),
      },
    );
    expect(captured.stderr()).toContain("256 MiB limit on all lockfile data");
  });

  it("treats Ctrl+C while lockfiles are read as a cancel, not an unexpected error", async () => {
    const controller = new AbortController();
    const captured = createTestIo({ isTTY: false });
    const cancelling = createTestDeps({
      findGitRoot: async () => path.join(base, "repo"),
      now: () => NOW,
      verifyProject: async () => OUTCOME,
      collectDependencies: async (_root, options) => {
        expect(options?.signal).toBe(controller.signal);
        controller.abort();
        throw new DOMException("The dependency collection was cancelled.", "AbortError");
      },
      isPathInsideDirectory: async () => false,
      makeSbomDir: async () => outDir,
    });
    const context = { ...createTestContext(captured, cancelling), signal: controller.signal };
    await expect(
      runSbom(context, { format: "cyclonedx-json", outputDir: outDir }),
    ).rejects.toBeInstanceOf(UserCancelledError);
    expect(captured.stderr()).not.toContain("unexpected");
    expect(await readdir(outDir)).toEqual([]);
  });

  it("an empty repository gives a valid, empty SBOM and a warning", async () => {
    const { captured, code } = await sbom(
      {},
      {
        deps: deps({
          collection: {
            dependencies: [],
            coverage: [],
            isTruncated: false,
            limitNotes: [],
            bytesRead: 0,
          },
        }),
      },
    );
    expect(code).toBe(0);
    expect(captured.stderr()).toContain("lists none");
  });

  it("fails outside a Git repository (exit 3)", async () => {
    const { code } = await sbom({}, { deps: createTestDeps({ findGitRoot: async () => null }) });
    expect(code).toBe(3);
  });
});

describe("pgard sbom end to end", () => {
  it("reads real lockfiles from disk, lists the unsupported one and sends nothing to the network", async () => {
    const repo = path.join(base, "repo");
    await mkdir(repo);
    await writeFile(
      path.join(repo, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { "@scope/a": "^1.0.0" } },
          "node_modules/@scope/a": { version: "1.0.0" },
          "node_modules/b": { version: "2.0.0" },
        },
      }),
    );
    await writeFile(
      path.join(repo, "go.mod"),
      "module example.com/m\n\ngo 1.22\n\nrequire github.com/BurntSushi/toml v1.3.2\n",
    );
    await writeFile(path.join(repo, "composer.lock"), "{}");
    const captured = createTestIo({ isTTY: false });
    const context = createTestContext(
      captured,
      createTestDeps({
        findGitRoot: async () => repo,
        now: () => NOW,
        verifyProject: async () => OUTCOME,
        collectDependencies,
        isPathInsideDirectory,
      }),
    );
    const code = await runSbom(context, { format: "cyclonedx-json", outputDir: outDir });
    expect(code).toBe(0);
    const files = await readdir(outDir);
    const bom = JSON.parse(await readFile(path.join(outDir, files[0] ?? ""), "utf8")) as {
      components: { purl: string }[];
      dependencies: { dependsOn: string[] }[];
      metadata: { properties: { name: string; value: string }[] };
    };
    expect(bom.components.map((component) => component.purl)).toEqual([
      "pkg:golang/github.com/BurntSushi/toml@v1.3.2",
      "pkg:npm/%40scope/a@1.0.0",
      "pkg:npm/b@2.0.0",
    ]);
    expect(bom.dependencies[0]?.dependsOn).toContain("pkg:npm/%40scope/a@1.0.0");
    expect(bom.metadata.properties).toContainEqual({
      name: "pgard:unparsed-lockfile",
      value: "composer.lock (unsupported)",
    });
    // The SBOM must not contain the absolute repository path.
    expect(await readFile(path.join(outDir, files[0] ?? ""), "utf8")).not.toContain(base);
  });
});

describe("pgard sbom command line", () => {
  it("parses the options and defaults", () => {
    expect(parseCommandLine(["sbom"])).toEqual({
      kind: "sbom",
      format: "cyclonedx-json",
      outputDir: null,
    });
    expect(
      parseCommandLine(["sbom", "--format", "cyclonedx-json", "--output-dir", "x", "--lang", "ko"]),
    ).toEqual({ kind: "sbom", format: "cyclonedx-json", outputDir: "x", lang: "ko" });
    expect(parseCommandLine(["sbom", "--help"])).toEqual({ kind: "help", topic: "sbom" });
    expect(parseCommandLine(["help", "sbom"])).toEqual({ kind: "help", topic: "sbom" });
  });

  it("rejects other formats, extra words and other commands' options", () => {
    expect(() => parseCommandLine(["sbom", "--format", "html"])).toThrow(UsageError);
    expect(() => parseCommandLine(["sbom", "extra"])).toThrow(UsageError);
    expect(() => parseCommandLine(["sbom", "--no-open"])).toThrow(UsageError);
    expect(() => parseCommandLine(["sbom", "--report", "html"])).toThrow(UsageError);
  });

  it("rejects --output-dir ~user with the hint in Korean (exit 2)", async () => {
    const captured = createTestIo({ isTTY: false });
    const code = await main(["sbom", "--output-dir", "~bob", "--lang", "ko"], captured.io, {
      deps: deps(),
      interrupts: noInterrupts,
    });
    expect(code).toBe(2);
    expect(captured.stderr()).toContain("~ 바로 뒤에 /를 붙이세요(예: ~/Downloads).");
  });

  it("runs through main() with --lang ko and prints Korean errors", async () => {
    const captured = createTestIo({ isTTY: false });
    const code = await main(
      ["sbom", "--output-dir", path.join(base, "nope"), "--lang", "ko"],
      captured.io,
      {
        deps: deps(),
        interrupts: noInterrupts,
      },
    );
    expect(code).toBe(2);
    expect(captured.stderr()).toMatch(/[가-힣]/);
  });
});
