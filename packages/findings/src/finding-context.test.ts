import { describe, expect, it } from "vitest";
import type { Finding } from "./contract.js";
import {
  applyFindingContext,
  isTestOrFixturePath,
  isVendoredPath,
  splitFindingsByContext,
} from "./finding-context.js";

function finding(path: string | null, overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    ruleId: "PG-SECRET-002",
    title: "Secret in a tracked file",
    category: "secret_exposure",
    severity: "high",
    status: "suspected",
    confidence: "medium",
    location: { kind: "file", path, line: 3, url: null, commit: null },
    evidence: "credential assignment in a tracked file (value redacted)",
    impact: "i",
    recommendation: "r",
    references: { cwe: [], owasp: [], cve: [] },
    sources: ["history"],
    ...overrides,
  };
}

describe("isTestOrFixturePath", () => {
  it.each([
    "packages/findings/src/redact.test.ts",
    "src/app.spec.js",
    "src/App.test.tsx",
    "cmd/server/main_test.go",
    "src/__tests__/util.ts",
    "src/__mocks__/fs.ts",
    "src/__fixtures__/data.json",
    "test/helpers.js",
    "tests/e2e/login.py",
    "spec/fixtures/key.pem",
    "internal/parser/testdata/input.txt",
    "Tests/Unit/AppTests.swift",
    "test/config.test.json",
    "fixtures/app.yaml",
    "spec/fixtures/.env",
    "internal/testdata/config.toml",
    "src/__tests__/settings.json",
    "tests/test_settings_loader.py",
    "tests/test_settings.py",
    "fixtures/Dockerfile",
  ])("classifies %s as test or fixture code", (path) => {
    expect(isTestOrFixturePath(path)).toBe(true);
  });

  it.each([
    "src/db.ts",
    "packages/scanner/src/secret-patterns.ts",
    "src/testing.ts",
    "src/contest/entry.ts",
    "src/latest.ts",
    "src/test.ts",
    "src/fixtures.ts",
    "src/attestation/tests.go",
    "package-lock.json",
    ".env",
    "",
    // Config for a deployed "test" environment is real configuration.
    "deploy/test/values.yaml",
    "environments/test/.env",
    "environments/tests/.env.local",
    "infra/test/main.tf",
    "infra/test/prod.tfvars",
    "config/test/app.properties",
    "config/test/app.ini",
    "config/tests/app.toml",
    "config/test/secrets.json",
    "deploy/test/Dockerfile",
    "deploy/test/Dockerfile.api",
    "deploy/test/.npmrc",
    "deploy/test/nginx.conf",
    "deploy/test/app.cfg",
    "deploy/test/web.xml",
    "deploy/test/settings.py",
    "deploy/test/local_settings.py",
    "deploy/test/config.py",
  ])("keeps %s as regular code", (path) => {
    expect(isTestOrFixturePath(path)).toBe(false);
  });

  it("does not classify a missing path", () => {
    expect(isTestOrFixturePath(null)).toBe(false);
  });
});

describe("applyFindingContext", () => {
  it("marks test findings and caps confidence at low, keeping rule, severity and evidence", () => {
    const original = finding("src/__tests__/a.ts", { severity: "critical", confidence: "high" });
    expect(applyFindingContext(original)).toEqual({
      ...original,
      context: "test",
      confidence: "low",
    });
  });

  it("leaves regular findings unchanged", () => {
    const original = finding("src/a.ts");
    expect(applyFindingContext(original)).toBe(original);
  });

  it("leaves URL findings unchanged", () => {
    const original = finding(null, {
      location: {
        kind: "url",
        path: null,
        line: null,
        url: "http://127.0.0.1:3000/test/",
        commit: null,
      },
    });
    expect(applyFindingContext(original)).toBe(original);
  });
});

describe("splitFindingsByContext", () => {
  it("separates test findings without dropping any", () => {
    const regular = finding("src/a.ts");
    const test = applyFindingContext(finding("src/a.test.ts"));
    expect(splitFindingsByContext([test, regular])).toEqual({
      primary: [regular],
      test: [test],
      vendored: [],
    });
  });

  it("separates vendored suggestions from test and regular findings", () => {
    const regular = finding("src/a.ts");
    const test = applyFindingContext(finding("src/a.test.ts"));
    const vendored = applyFindingContext(finding("node_modules/pkg/index.js"));
    expect(splitFindingsByContext([vendored, test, regular])).toEqual({
      primary: [regular],
      test: [test],
      vendored: [vendored],
    });
  });
});

describe("isVendoredPath", () => {
  it.each([
    "node_modules/@babel/parser/lib/index.js",
    "packages/web/node_modules/pkg/index.js",
    "bower_components/jquery/dist/jquery.js",
    "jspm_packages/npm/lodash@4.17.21/lodash.js",
    "vendor/github.com/pkg/errors/errors.go",
    "vendor/guzzlehttp/guzzle/src/Client.php",
    "third_party/zlib/zlib.h",
    "ios/Pods/Alamofire/Source/Session.swift",
    "node_modules/",
    "src/node_modules/pkg/index.js",
    "app/assets/bower_components/x.js",
    "packages/web/vendor/acme/lib.php",
    "vendor/github.com/acme/lib/src/a.go",
  ])("treats %s as vendored", (filePath) => {
    expect(isVendoredPath(filePath)).toBe(true);
  });

  it.each([
    "src/vendored.ts",
    "my_node_modules_x/index.js",
    "src/vendor.ts",
    "node_modules",
    "lib/vendors/a.js",
    "k8s/pods/secret.yaml",
    "dist/bundle.js",
    "build/app.js",
    "Vendor/a.js",
    "src/vendor/vendor.service.ts",
    "src/vendor/x.ts",
    "src/integrations/third_party/x.ts",
    "packages/web/src/third_party/a.ts",
    "app/vendor/client.rb",
    "lib/vendor/a.js",
  ])("does not treat %s as vendored", (filePath) => {
    expect(isVendoredPath(filePath)).toBe(false);
  });

  it("returns false without a path", () => {
    expect(isVendoredPath(null)).toBe(false);
    expect(isVendoredPath("")).toBe(false);
  });
});

describe("applyFindingContext for vendored code", () => {
  it("marks vendored findings as suggestions with low confidence, keeping rule, severity and evidence", () => {
    const original = finding("node_modules/@babel/parser/lib/index.js", {
      severity: "high",
      confidence: "high",
    });
    expect(applyFindingContext(original)).toEqual({
      ...original,
      context: "vendored",
      confidence: "low",
    });
  });

  it("prefers vendored over test when a path is both", () => {
    expect(applyFindingContext(finding("node_modules/pkg/test/a.test.js")).context).toBe(
      "vendored",
    );
    expect(applyFindingContext(finding("test/fixtures/vendor/lib.js")).context).toBe("vendored");
  });

  it("keeps a vendored context an analyzer already set", () => {
    const original = finding("node_modules/", { context: "vendored", severity: "info" });
    expect(applyFindingContext(original)).toEqual({ ...original, confidence: "low" });
  });
});
