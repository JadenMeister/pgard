#!/usr/bin/env node
// Entry point of the `pgard` command. It only checks the Node.js version and then loads the real
// CLI (dist/bin/main.js; in the packed package ./main.js). It must stay parseable and runnable on
// old Node.js versions, so: no static imports, no top-level await, no syntax newer than ES2017
// (no `??`, `?.`, optional catch binding, object spread). scripts/pack-lib.mjs checks this, and
// apps/cli/src/bin/node-guard.test.ts runs this file against simulated versions.
// The supported list below must match MIN_NODE_VERSIONS in apps/cli/src/commands/doctor.ts and
// "engines" in the package.json files (a test keeps them in agreement).
"use strict";

const MIN_NODE_VERSIONS = [
  [22, 23, 4],
  [24, 22, 1],
  [26, 12, 1],
];
const NEWEST_NODE_LINE = 26;

function isSupported(version) {
  const parts = String(version)
    .split(".")
    .map((part) => parseInt(part, 10) || 0);
  const major = parts[0];
  if (major > NEWEST_NODE_LINE) return true;
  const floor = MIN_NODE_VERSIONS.find((entry) => entry[0] === major);
  if (floor === undefined) return false;
  if (parts[1] !== floor[1]) return parts[1] > floor[1];
  return parts[2] >= floor[2];
}

// Same order as the CLI: --lang, PGARD_LANG, LC_ALL / LC_MESSAGES / LANG, the OS locale on
// Windows, then English. A bad value cannot be reported here, so it falls through to the next rule.
function pickLanguage(argv, env, platform) {
  let flag;
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--lang") flag = argv[i + 1];
    else if (String(argv[i]).indexOf("--lang=") === 0) flag = String(argv[i]).slice(7);
  }
  if (flag !== undefined) {
    const value = String(flag).toLowerCase();
    if (value === "ko" || value === "en") return value;
  }
  const fromEnv = String(env.PGARD_LANG || "").toLowerCase();
  if (fromEnv === "ko" || fromEnv === "en") return fromEnv;
  let locale;
  const names = ["LC_ALL", "LC_MESSAGES", "LANG"];
  for (let i = 0; i < names.length && locale === undefined; i += 1) {
    const value = env[names[i]];
    if (value !== undefined && String(value).trim() !== "") locale = String(value);
  }
  if (locale === undefined && platform === "win32") {
    try {
      locale = Intl.DateTimeFormat().resolvedOptions().locale;
    } catch (error) {
      locale = undefined;
    }
  }
  return locale !== undefined && /^ko(?:[._@-]|$)/i.test(locale.trim()) ? "ko" : "en";
}

function message(language, current) {
  if (language === "ko") {
    return [
      `pgard는 이 Node.js 버전(${current})에서 실행할 수 없습니다.`,
      "지원 버전: 22.23.4 이상(22.x), 24.22.1 이상(24.x), 26.12.1 이상(26.x 및 그 이후). 홀수 버전(23, 25 등)은 지원하지 않습니다.",
      "업데이트: https://nodejs.org 에서 LTS 버전을 설치하세요. Windows에서는 `winget install OpenJS.NodeJS.LTS`를 실행하거나 설치 프로그램을 사용하세요.",
      "nvm, nvm-windows, fnm을 쓴다면 지원 버전으로 전환하세요(예: `nvm install --lts` 후 `nvm use --lts`, 또는 `fnm use`).",
      "",
    ].join("\n");
  }
  return [
    `pgard cannot run on this Node.js version (${current}).`,
    "Supported: 22.23.4 or newer on 22.x, 24.22.1 or newer on 24.x, and 26.12.1 or newer (26.x and later). Odd-numbered lines (23, 25, ...) are not supported.",
    "Update: install the LTS release from https://nodejs.org. On Windows run `winget install OpenJS.NodeJS.LTS` or use the installer.",
    "If you use nvm, nvm-windows or fnm, switch to a supported version (for example `nvm install --lts` then `nvm use --lts`, or `fnm use`).",
    "",
  ].join("\n");
}

if (isSupported(process.versions.node)) {
  import("../dist/bin/main.js");
} else {
  process.stderr.write(
    message(
      pickLanguage(process.argv.slice(2), process.env, process.platform),
      process.versions.node,
    ),
  );
  // 2 is the documented exit code for usage and environment problems (README, "Exit codes").
  process.exitCode = 2;
}
