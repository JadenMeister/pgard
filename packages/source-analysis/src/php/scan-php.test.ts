import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanSourceCode } from "../scan-source.js";
import { detectPhpNamespaceFrameworks } from "../tree-sitter/detect-frameworks.js";

const roots: string[] = [];
function project(files: Record<string, string>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-php-")));
  roots.push(root);
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
    writeFileSync(path.join(root, name), content);
  }
  return root;
}
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

const SQL = `<?php
namespace App\\Http\\Controllers;

use Illuminate\\Support\\Facades\\DB;

class UserController extends Controller {
    public function show(Request $request) {
        return DB::select("SELECT * FROM users WHERE id = " . $request->input('id'));
    }
}
`;
const CMD = `<?php
function ping() { system("ping -c 1 " . $_GET['host']); }
`;

describe("scanSourceCode with PHP", () => {
  it("reports findings and per-area coverage for the PHP rules", async () => {
    const root = project({
      "app/Http/Controllers/UserController.php": SQL,
      "public/ping.php": CMD,
      "views/legacy.phtml": `<?php mysqli_query($c, "SELECT * FROM t WHERE a = " . $_GET['a']); ?>\n`,
      "composer.json": JSON.stringify({ require: { "laravel/framework": "^11" } }),
    });
    const output = await scanSourceCode(root);
    expect(
      output.findings
        .filter((finding) => finding.ruleId === "PG-SQL-007")
        .map((finding) => finding.location.path)
        .sort(),
    ).toEqual(["app/Http/Controllers/UserController.php", "views/legacy.phtml"]);
    expect(
      output.findings
        .filter((finding) => finding.ruleId === "PG-CMD-005")
        .map((finding) => finding.location.path),
    ).toEqual(["public/ping.php"]);
    const php = output.coverage.find((item) => item.area === "source:php");
    expect(php).toMatchObject({
      status: "completed",
      ruleIds: ["PG-SQL-007", "PG-CMD-005"],
    });
    expect(php?.note).toContain("3 PHP file(s)");
    expect(php?.note).toContain("frameworks: Laravel");
    // What is not checked yet is said, not left out.
    expect(php?.note).toContain("Not checked yet for PHP: XSS");
    for (const ruleId of ["PG-SQL-007", "PG-CMD-005"]) {
      expect(
        output.ruleStats?.find((row) => row.ruleId === ruleId && row.area === "source:php"),
      ).toMatchObject({
        status: "completed",
        targets: [{ unit: "files", examined: 3 }],
      });
    }
    expect(output.coverage.some((item) => item.area === "source:php:blade")).toBe(false);
  });

  it("detects Laravel from namespaces when there is no composer.json", async () => {
    const root = project({ "app/UserController.php": SQL });
    const output = await scanSourceCode(root);
    expect(output.coverage.find((item) => item.area === "source:php")?.note).toContain(
      "frameworks: Laravel",
    );
  });

  it("detects Blade templates and says their XSS checks are not done", async () => {
    const root = project({
      "resources/views/home.blade.php": "<h1>{!! $title !!}</h1>\n",
      "app/ping.php": CMD,
    });
    const output = await scanSourceCode(root);
    const blade = output.coverage.find((item) => item.area === "source:php:blade");
    expect(blade).toMatchObject({ status: "not_tested", ruleIds: [] });
    expect(blade?.note).toContain("1 Blade template(s)");
    expect(blade?.note).toContain("not a safe result");
  });

  it("makes the area partial for an unsupported library and for dynamic calls", async () => {
    const root = project({
      "a.php": `<?php\nfunction f($wpdb) { return $wpdb->get_results("SELECT * FROM t"); }\n`,
      "b.php": `<?php\nfunction g($run) { $run("SELECT * FROM t WHERE a = " . $_GET['a']); }\n`,
    });
    const output = await scanSourceCode(root);
    expect(output.coverage.find((item) => item.area === "source:php")).toMatchObject({
      status: "partial",
    });
    expect(output.coverage.find((item) => item.area === "source:php")?.note).toContain(
      "dynamic call forms",
    );
    expect(output.coverage.find((item) => item.area === "source:orm:wordpress-wpdb")).toMatchObject(
      {
        status: "partial",
      },
    );
  });

  it("makes the area partial for a file over the size limit", async () => {
    const root = project({
      "big.php": `<?php\n// ${"x".repeat(1024 * 1024 + 10)}\n`,
      "ok.php": CMD,
    });
    const output = await scanSourceCode(root);
    const php = output.coverage.find((item) => item.area === "source:php");
    expect(php?.status).toBe("partial");
    expect(output.findings.some((finding) => finding.ruleId === "PG-CMD-005")).toBe(true);
  });

  it("does not mention PHP when there are no PHP files", async () => {
    const root = project({ "a.js": "const x = 1;\n" });
    const output = await scanSourceCode(root);
    expect(output.coverage.some((item) => item.area === "source:php")).toBe(false);
  });
});

describe("detectPhpNamespaceFrameworks", () => {
  it("reads Laravel and Symfony framework namespaces, not standalone components", () => {
    expect(detectPhpNamespaceFrameworks("<?php\nuse Illuminate\\Http\\Request;\n")).toEqual([
      "Laravel",
    ]);
    expect(
      detectPhpNamespaceFrameworks(
        "<?php\nuse Symfony\\Bundle\\FrameworkBundle\\Controller\\AbstractController;\n",
      ),
    ).toEqual(["Symfony"]);
    expect(
      detectPhpNamespaceFrameworks("<?php\nuse Symfony\\Component\\Process\\Process;\n"),
    ).toEqual([]);
    expect(detectPhpNamespaceFrameworks("<?php\n// use Illuminate\\Foo;\n")).toEqual([]);
  });
});
