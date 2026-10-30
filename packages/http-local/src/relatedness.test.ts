import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readProjectSignals } from "./project-signals.js";
import {
  EMPTY_PROJECT_SIGNALS,
  KNOWN_TOOL_NAMES,
  nameTokens,
  relatedness,
  type ProjectSignals,
} from "./relatedness.js";

function project(overrides: Partial<ProjectSignals> = {}): ProjectSignals {
  return { ...EMPTY_PROJECT_SIGNALS, folderName: "shop", ...overrides };
}

describe("nameTokens", () => {
  it("case-folds, splits on - _ space . and camelCase, keeps 3+ characters, drops filler", () => {
    expect(nameTokens("My_Shop-app.v2 Admin")).toEqual(["shop"]);
    expect(nameTokens("BlueOcean")).toEqual(["blue", "ocean"]);
    expect(nameTokens("ab-12-345")).toEqual([]);
  });
});

describe("relatedness by name", () => {
  it("is likely when the title has a project name token", () => {
    const result = relatedness({ title: "Shop - Home", technologies: [] }, project());
    expect(result.verdict).toBe("likely");
    expect(result.reasons).toEqual([{ kind: "name", token: "shop" }]);
  });

  it("matches the verified repository name and the manifest name", () => {
    expect(
      relatedness(
        { title: "Acme Storefront", technologies: [] },
        project({ folderName: "x", repo: "owner/storefront" }),
      ).verdict,
    ).toBe("likely");
    expect(
      relatedness(
        { title: "Mailer", technologies: [] },
        project({ folderName: "x", manifestNames: ["mailer"] }),
      ).verdict,
    ).toBe("likely");
  });

  it("matches a name in a header value", () => {
    expect(relatedness({ title: null, technologies: ["Shop/1.0"] }, project()).verdict).toBe(
      "likely",
    );
  });

  it("ignores generic words so a folder named 'web-app' does not match everything", () => {
    expect(
      relatedness(
        { title: "Web App Dashboard", technologies: [] },
        project({ folderName: "web-app" }),
      ).verdict,
    ).toBe("unclear");
  });
});

describe("relatedness by framework", () => {
  it("is likely when the service technology is a declared framework", () => {
    const result = relatedness(
      { title: "Welcome", technologies: ["Next.js"] },
      project({ dependencies: ["next", "react"] }),
    );
    expect(result.verdict).toBe("likely");
    expect(result.reasons).toEqual([{ kind: "framework", framework: "next" }]);
  });

  it("counts implied frameworks (Next.js includes React) and language families", () => {
    expect(
      relatedness({ title: "t", technologies: ["React"] }, project({ dependencies: ["next"] }))
        .verdict,
    ).toBe("likely");
    expect(
      relatedness(
        { title: "t", technologies: ["PHP/8.3"] },
        project({ dependencies: ["laravel/framework"] }),
      ).verdict,
    ).toBe("likely");
    expect(
      relatedness(
        { title: "t", technologies: ["Werkzeug/3.0 Python/3.12"] },
        project({ dependencies: ["flask"] }),
      ).verdict,
    ).toBe("likely");
  });

  it("is unlikely for a clear framework mismatch (Next.js service, Django project)", () => {
    const result = relatedness(
      { title: "Welcome", technologies: ["Next.js"] },
      project({ dependencies: ["django"] }),
    );
    expect(result.verdict).toBe("unlikely");
    expect(result.reasons).toEqual([{ kind: "mismatch", service: "Next.js", project: "Django" }]);
  });

  it("is unlikely for a PHP service and a Django project", () => {
    expect(
      relatedness({ title: "t", technologies: ["PHP/8"] }, project({ dependencies: ["django"] }))
        .verdict,
    ).toBe("unlikely");
  });

  it("is not a mismatch when the project only declares UI libraries or nothing", () => {
    expect(
      relatedness({ title: "t", technologies: ["Next.js"] }, project({ dependencies: ["react"] }))
        .verdict,
    ).toBe("unclear");
    expect(relatedness({ title: "t", technologies: ["Next.js"] }, project()).verdict).toBe(
      "unclear",
    );
    expect(
      relatedness(
        { title: "t", technologies: ["Vite dev server"] },
        project({ dependencies: ["django"] }),
      ).verdict,
    ).toBe("unclear");
  });
});

describe("relatedness with known tools", () => {
  it("lists the known tool names", () => {
    expect(KNOWN_TOOL_NAMES).toEqual(
      expect.arrayContaining([
        "Grafana",
        "Jupyter",
        "pgAdmin",
        "Docker Desktop",
        "Ollama",
        "LM Studio",
        "Kubernetes Dashboard",
        "phpMyAdmin",
      ]),
    );
  });

  it.each([
    ["Grafana", "Grafana"],
    ["JupyterLab", "Jupyter"],
    ["pgAdmin 4", "pgAdmin"],
    ["Docker Desktop", "Docker Desktop"],
    ["LM Studio", "LM Studio"],
    ["Kubernetes Dashboard", "Kubernetes Dashboard"],
    ["phpMyAdmin", "phpMyAdmin"],
    ["Adminer 4.8", "Adminer"],
  ])("is unlikely for %s", (title, tool) => {
    const result = relatedness({ title, technologies: [] }, project());
    expect(result.verdict).toBe("unlikely");
    expect(result.reasons).toEqual([{ kind: "known-tool", tool }]);
    expect(result.serviceLabel).toBe(tool);
    expect(result.projectLabel).toBe("shop");
  });

  it("does not warn when the project depends on the tool", () => {
    expect(
      relatedness(
        { title: "Grafana", technologies: [] },
        project({ dependencies: ["@grafana/ui"] }),
      ).verdict,
    ).toBe("unclear");
    expect(
      relatedness(
        { title: "Home - Jupyter", technologies: [] },
        project({ dependencies: ["jupyterlab"] }),
      ).verdict,
    ).toBe("unclear");
  });

  it("does not warn when the project is named after the tool", () => {
    expect(
      relatedness(
        { title: "Grafana", technologies: [] },
        project({ folderName: "grafana-dashboards" }),
      ).verdict,
    ).toBe("likely");
  });

  it("a Mongo Express page is the tool, not the Express framework", () => {
    expect(
      relatedness(
        { title: "Mongo Express", technologies: [] },
        project({ dependencies: ["express"] }),
      ).verdict,
    ).toBe("unlikely");
  });
});

describe("relatedness with missing signals", () => {
  it("is unclear without any project signal", () => {
    expect(
      relatedness({ title: "Grafana", technologies: ["Next.js"] }, EMPTY_PROJECT_SIGNALS).verdict,
    ).toBe("unclear");
  });

  it("is unclear without any service signal", () => {
    expect(relatedness({ title: null, technologies: [] }, project()).verdict).toBe("unclear");
  });

  it("is unclear when nothing matches and nothing is clearly different", () => {
    const result = relatedness({ title: "Landing", technologies: ["nginx/1.25"] }, project());
    expect(result.verdict).toBe("unclear");
    expect(result.reasons).toEqual([]);
  });
});

describe("relatedness text safety", () => {
  it("strips escapes, control and bidi characters and caps labels", () => {
    const hostile = `\u001b[31mGrafana‮\u0007${"x".repeat(500)}`;
    const result = relatedness(
      { title: hostile, technologies: [] },
      project({ folderName: `sh\u001b]0;x\u0007op‮${"y".repeat(500)}` }),
    );
    for (const label of [result.serviceLabel, result.projectLabel]) {
      expect(label).not.toBeNull();
      expect(label as string).not.toMatch(/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/);
      expect([...(label as string)].length).toBeLessThanOrEqual(40);
    }
  });

  it("matches names written with Unicode letters", () => {
    expect(
      relatedness({ title: "카페 주문", technologies: [] }, project({ folderName: "카페-주문-앱" }))
        .verdict,
    ).toBe("unclear");
    expect(
      relatedness(
        { title: "Café Münster", technologies: [] },
        project({ folderName: "münster_shop" }),
      ).verdict,
    ).toBe("likely");
  });
});

describe("readProjectSignals", () => {
  const roots: string[] = [];
  afterEach(async () => {
    await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
  });
  async function makeRoot(files: Record<string, string>): Promise<string> {
    const root = await mkdtemp(path.join(tmpdir(), "pgard-signals-"));
    roots.push(root);
    for (const [name, content] of Object.entries(files)) {
      await writeFile(path.join(root, name), content);
    }
    return root;
  }

  it("reads names and declared dependencies from the common manifests", async () => {
    const root = await makeRoot({
      "package.json": JSON.stringify({
        name: "@acme/storefront",
        dependencies: { Next: "1", react: "18" },
        devDependencies: { vite: "5" },
      }),
      "pyproject.toml": `[project]\nname = "pricing-api"\ndependencies = ["Django>=4", "fastapi[all]"]\n\n[tool.poetry.dependencies]\nflask = "^3"\n`,
      "requirements.txt": "gunicorn==21\n# comment\n",
      "composer.json": JSON.stringify({
        name: "acme/cart",
        require: { "laravel/framework": "^11" },
      }),
      "go.mod": `module github.com/acme/ledger\n\nrequire (\n  github.com/gin-gonic/gin v1.9.0\n)\n`,
      "pom.xml": "<artifactId>spring-boot-starter-web</artifactId>",
      Gemfile: `gem "rails", "~> 7"`,
    });
    const signals = await readProjectSignals(root, "acme/storefront");
    expect(signals.folderName).toBe(path.basename(root));
    expect(signals.repo).toBe("acme/storefront");
    expect(signals.manifestNames).toEqual(["storefront", "pricing-api", "cart", "ledger"]);
    expect(signals.dependencies).toEqual(
      expect.arrayContaining([
        "next",
        "react",
        "vite",
        "django",
        "fastapi",
        "flask",
        "gunicorn",
        "laravel/framework",
        "github.com/gin-gonic/gin",
        "org.springframework.boot",
        "rails",
      ]),
    );
  });

  it("ignores a symlinked manifest, an oversized one and broken JSON", async () => {
    const root = await makeRoot({
      "package.json": "{ not json",
      "composer.json": `{"name":"a/b","pad":"${"x".repeat(600 * 1024)}"}`,
    });
    const outside = await makeRoot({ "package.json": JSON.stringify({ name: "secret-name" }) });
    await mkdir(path.join(root, "sub"));
    await symlink(path.join(outside, "package.json"), path.join(root, "pyproject.toml"));
    const signals = await readProjectSignals(root, null);
    expect(signals.manifestNames).toEqual([]);
    expect(signals.dependencies).toEqual([]);
    expect(signals.repo).toBeNull();
  });

  it("does not throw for a missing folder", async () => {
    const signals = await readProjectSignals(path.join(tmpdir(), "pgard-no-such-folder"), null);
    expect(signals.manifestNames).toEqual([]);
  });
});
