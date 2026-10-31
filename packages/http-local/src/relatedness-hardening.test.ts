import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { sanitizeDisplayText } from "./display-text.js";
import { readProjectSignals } from "./project-signals.js";
import { EMPTY_PROJECT_SIGNALS, relatedness, type ProjectSignals } from "./relatedness.js";
import { TIME_FACTOR } from "../../../tests/support/timing.js";

function project(overrides: Partial<ProjectSignals> = {}): ProjectSignals {
  return { ...EMPTY_PROJECT_SIGNALS, folderName: "shop", ...overrides };
}

describe("a known tool is judged before the project name", () => {
  it("does not take 'Shop metrics - Grafana' for the shop", () => {
    const result = relatedness({ title: "Shop metrics - Grafana", technologies: [] }, project());
    expect(result.verdict).toBe("unlikely");
    expect(result.reasons).toEqual([{ kind: "known-tool", tool: "Grafana" }]);
  });

  it("lets the tool go when the project is named after it", () => {
    expect(
      relatedness(
        { title: "Shop metrics - Grafana", technologies: [] },
        project({ folderName: "grafana-shop" }),
      ).verdict,
    ).toBe("likely");
  });

  it("lets the tool go for an exact or scoped dependency, not for a substring", () => {
    const service = { title: "Grafana", technologies: [] };
    expect(relatedness(service, project({ dependencies: ["grafana"] })).verdict).toBe("unclear");
    expect(relatedness(service, project({ dependencies: ["@grafana/data"] })).verdict).toBe(
      "unclear",
    );
    expect(relatedness(service, project({ dependencies: ["grafanalib-ish"] })).verdict).toBe(
      "unlikely",
    );
  });
});

describe("framework names are not project names", () => {
  it("does not match a project 'next-shop' on the word Next", () => {
    expect(
      relatedness({ title: "Next.js app", technologies: [] }, project({ folderName: "next-shop" }))
        .verdict,
    ).toBe("unclear");
  });
});

describe("text handling", () => {
  it("does not cut a surrogate pair in half", () => {
    const text = `${"a".repeat(9)}\u{1F600}\u{1F600}`;
    const cut = sanitizeDisplayText(text, 11);
    expect(cut).not.toMatch(/[\ud800-\udbff](?![\udc00-\udfff])/);
    expect(cut.endsWith("…")).toBe(true);
  });

  it("tokenizes the title and each technology on their own", () => {
    const result = relatedness({ title: "x".repeat(400), technologies: ["Shop/1.0"] }, project());
    expect(result.verdict).toBe("likely");
  });
});

describe("readProjectSignals is bounded on hostile files", () => {
  const roots: string[] = [];
  afterEach(async () => {
    await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
  });
  async function makeRoot(files: Record<string, string>): Promise<string> {
    const root = await mkdtemp(path.join(tmpdir(), "pgard-redos-"));
    roots.push(root);
    for (const [name, content] of Object.entries(files)) {
      await writeFile(path.join(root, name), content);
    }
    return root;
  }
  const BIG = 512 * 1024;
  const adversarial: Record<string, string> = {
    newlines: "\n".repeat(BIG),
    spacedNewlines: " \n".repeat(BIG / 2),
    quoteSpaces: `"a${" ".repeat(BIG)}`,
    quoteSpacesLines: `"a${" ".repeat(4000)}\n`.repeat(BIG / 4010),
    longLine: `dependencies = [${'"a",'.repeat(BIG / 4)}`,
    tabsAndEquals: `${"\t".repeat(BIG / 2)}name${" ".repeat(BIG / 2)}`,
    manyTables: "[project]\n".repeat(BIG / 10),
  };

  it.each(Object.entries(adversarial))(
    "each manifest reader stays fast on %s",
    async (_n, text) => {
      const root = await makeRoot({
        "pyproject.toml": text,
        "requirements.txt": text,
        "go.mod": text,
        Gemfile: text,
        "pom.xml": text,
        "build.gradle": text,
        "build.gradle.kts": text,
        "package.json": text,
        "composer.json": text,
      });
      const started = performance.now();
      await readProjectSignals(root, null);
      expect(performance.now() - started).toBeLessThan(200 * TIME_FACTOR);
    },
  );

  it("is fast on adversarial input that fits under the size cap", async () => {
    const text = `[project]\nname = "x"\ndependencies = [\n${'  "a'.padEnd(900, " ")}\n`.repeat(70);
    const root = await makeRoot({
      "pyproject.toml": text,
      "go.mod": `${"module  ".repeat(120)}\n`.repeat(70),
      Gemfile: `${" ".repeat(900)}gem\n`.repeat(70),
    });
    const started = performance.now();
    await readProjectSignals(root, null);
    expect(performance.now() - started).toBeLessThan(200 * TIME_FACTOR);
  });

  it("reads only dependency tables of pyproject.toml, not descriptions or other keys", async () => {
    const root = await makeRoot({
      "pyproject.toml": [
        "[project]",
        'name = "pricing"',
        'description = "uses django and flask"',
        "dependencies = [",
        '  "fastapi[all]>=0.100",',
        '  "uvicorn",',
        "]",
        "[project.optional-dependencies]",
        'dev = ["pytest", "Flask-Cors"]',
        "[tool.poetry.dependencies]",
        'python = "^3.12"',
        'requests = "^2"',
        "[tool.poetry.group.dev.dependencies]",
        "black = '*'",
        "[tool.other]",
        'django = "not a dependency"',
        "",
      ].join("\n"),
    });
    const signals = await readProjectSignals(root, null);
    expect(signals.manifestNames).toEqual(["pricing"]);
    expect(signals.dependencies).toEqual(
      expect.arrayContaining(["fastapi", "uvicorn", "pytest", "flask-cors", "requests", "black"]),
    );
    expect(signals.dependencies).not.toContain("django");
    expect(signals.dependencies).not.toContain("flask");
  });

  it("reads a manifest that starts with a UTF-8 BOM", async () => {
    const root = await makeRoot({
      "package.json": `﻿${JSON.stringify({ name: "bom-shop", dependencies: { next: "1" } })}`,
    });
    const signals = await readProjectSignals(root, null);
    expect(signals.manifestNames).toEqual(["bom-shop"]);
    expect(signals.dependencies).toEqual(["next"]);
  });
});

describe("Go module paths and over-long pyproject lines", () => {
  it("matches a tool by a path segment equal to, or starting with, its name", () => {
    const service = { title: "MinIO Console", technologies: [] };
    const base = { ...EMPTY_PROJECT_SIGNALS, folderName: "shop" };
    expect(
      relatedness(service, { ...base, dependencies: ["github.com/minio/minio-go/v7"] }).verdict,
    ).toBe("unclear");
    expect(
      relatedness(service, { ...base, dependencies: ["github.com/acme/minioish"] }).verdict,
    ).toBe("unlikely");
  });

  it("closes a dependency array when a line inside it was too long to read", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "pgard-long-"));
    try {
      await writeFile(
        path.join(root, "pyproject.toml"),
        [
          "[project]",
          'name = "x"',
          "dependencies = [",
          '  "requests",',
          `  "${"a".repeat(2000)}"]`,
          '"flask>=2",',
          "",
        ].join("\n"),
      );
      const signals = await readProjectSignals(root, null);
      expect(signals.dependencies).toEqual(["requests"]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
