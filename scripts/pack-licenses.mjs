// Third-party license handling for the bundled package (#358): which npm packages ended up inside
// dist/, whether each has a permissive license and a license text, and the NOTICE.md section that
// reproduces those texts. Used by pack-pgard.mjs and unit-tested in
// tests/integration/pack-scripts.test.ts. Plain Node, no dependencies.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

/**
 * SPDX identifiers accepted for bundled code. Everything else fails the pack until the owner has
 * looked at it and extended this list on purpose (copyleft, source-available and unknown licenses
 * must never be bundled silently).
 */
export const ALLOWED_LICENSES = [
  "MIT",
  "ISC",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "Apache-2.0",
  "0BSD",
  "BlueOak-1.0.0",
  "CC0-1.0",
  "Python-2.0",
];

const MIT_BODY = `Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`;

/**
 * Reviewed exceptions for packages whose npm tarball lacks a license field or a license file
 * (checked by hand on 2026-10-30). Keyed by exact `name@version`: a new version is not covered and
 * fails the pack until someone looks at it again. `text` replaces a missing license file.
 */
export const LICENSE_OVERRIDES = {
  // Declares no `license` field, but ships LICENSE (MIT, Copyright (c) 2017 Devon Govett).
  "png-js@2.0.0": { license: "MIT" },
  // package.json and README say MIT; the upstream repository has no LICENSE file, and the
  // package names Devon Govett as author. The copyright line is taken from that author field.
  "dfa@1.2.0": {
    license: "MIT",
    text: `MIT License (as declared in package.json and README.md of dfa 1.2.0; the package ships no license file)\n\nCopyright (c) Devon Govett\n\n${MIT_BODY}`,
  },
  "fontkit@2.0.4": {
    license: "MIT",
    text: `MIT License (as declared in package.json and README.md of fontkit 2.0.4; the package ships no license file)\n\nCopyright (c) Devon Govett\n\n${MIT_BODY}`,
  },
  // package.json says MIT, but the decoder sources carry Google's Apache-2.0 header (reproduced
  // here; the full Apache-2.0 text is printed in this file for the other Apache-2.0 packages).
  "brotli@1.3.3": {
    license: "(MIT AND Apache-2.0)",
    text: `MIT as declared in package.json and README.md of brotli 1.3.3 (the package ships no license file; author Devon Govett). Its decoder and encoder sources, a port of Google's Brotli, carry this header:\n\nCopyright 2013 Google Inc. All Rights Reserved.\n\nLicensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0\n\nUnless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.`,
  },
};

/** `a/node_modules/@s/p/lib/x.js` -> `{ name: "@s/p", dir: "a/node_modules/@s/p" }`, else null. */
export function packageOfInput(inputPath) {
  const normalized = inputPath.split("\\").join("/");
  const marker = "node_modules/";
  const at = normalized.lastIndexOf(marker);
  if (at === -1 || (at > 0 && normalized[at - 1] !== "/")) return null;
  const rest = normalized.slice(at + marker.length).split("/");
  const segments = rest[0]?.startsWith("@") ? 2 : 1;
  if (rest.length <= segments) return null;
  const name = rest.slice(0, segments).join("/");
  return { name, dir: normalized.slice(0, at + marker.length) + name };
}

/** License identifier(s) declared in a package.json: `license` string/object or legacy `licenses`. */
export function declaredLicense(manifest) {
  const one = (value) => (typeof value === "string" ? value : value?.type);
  const single = one(manifest.license);
  if (typeof single === "string" && single.trim() !== "") return single.trim();
  if (Array.isArray(manifest.licenses)) {
    const all = manifest.licenses.map(one).filter((entry) => typeof entry === "string");
    if (all.length > 0) return `(${all.join(" OR ")})`;
  }
  return null;
}

/**
 * Whether an SPDX expression is covered by `allowed`: `A OR B` needs one allowed side, `A AND B`
 * needs both, parentheses group. Returns false for anything it cannot parse (WITH exceptions,
 * `-or-later` suffixes, free text), so unusual expressions fail closed.
 */
export function isAllowedExpression(expression, allowed = ALLOWED_LICENSES) {
  const tokens = expression.match(/\(|\)|[^\s()]+/g) ?? [];
  let position = 0;
  const parseOr = () => {
    let ok = parseAnd();
    while (tokens[position] === "OR") {
      position += 1;
      const right = parseAnd();
      ok = ok || right;
    }
    return ok;
  };
  const parseAnd = () => {
    let ok = parseAtom();
    while (tokens[position] === "AND") {
      position += 1;
      const right = parseAtom();
      ok = ok && right;
    }
    return ok;
  };
  const parseAtom = () => {
    const token = tokens[position];
    position += 1;
    if (token === "(") {
      const ok = parseOr();
      if (tokens[position] !== ")") throw new Error("unbalanced parenthesis");
      position += 1;
      return ok;
    }
    if (token === undefined || token === ")" || token === "OR" || token === "AND") {
      throw new Error("unexpected token");
    }
    return allowed.includes(token);
  };
  try {
    const ok = parseOr();
    return ok && position === tokens.length;
  } catch {
    return false;
  }
}

/** Text files at the top of a package directory that carry its license or notice. */
export function licenseFilesOf(packageDir) {
  return readdirSync(packageDir, { withFileTypes: true })
    .filter(
      (entry) => entry.isFile() && /^(licen[sc]e|copying|notice|unlicen[sc]e)/i.test(entry.name),
    )
    .map((entry) => entry.name)
    .sort();
}

/**
 * The npm packages whose code is in the bundle, from an esbuild metafile (inputs that contributed
 * bytes to an output). Returns `{ name, version, license, dir, files: [{ name, text }] }` sorted
 * by name; `license` is null when the package declares none. Workspace packages (@pgard/*) and
 * files outside any node_modules are not third-party and are skipped.
 */
export function bundledPackages(metafile, root, overrides = LICENSE_OVERRIDES) {
  const dirs = new Map();
  for (const output of Object.values(metafile.outputs)) {
    for (const [input, info] of Object.entries(output.inputs)) {
      if (info.bytesInOutput === 0) continue;
      const pkg = packageOfInput(input);
      if (pkg !== null && !pkg.name.startsWith("@pgard/")) dirs.set(pkg.dir, pkg.name);
    }
  }
  const packages = [];
  for (const dir of dirs.keys()) {
    const absolute = join(root, dir);
    const manifestPath = join(absolute, "package.json");
    const manifest = existsSync(manifestPath) ? JSON.parse(readFileSync(manifestPath, "utf8")) : {};
    // The directory name can be an npm alias (typescript-api is typescript); report the real name.
    const name = typeof manifest.name === "string" ? manifest.name : dirs.get(dir);
    const version = typeof manifest.version === "string" ? manifest.version : "unknown";
    const override = overrides[`${name}@${version}`];
    const files = existsSync(absolute)
      ? licenseFilesOf(absolute).map((file) => ({
          name: file,
          text: readFileSync(join(absolute, file), "utf8").replace(/\r\n/g, "\n").trim(),
        }))
      : [];
    if (override?.text !== undefined && !files.some((file) => file.text.length > 0)) {
      files.push({ name: "license text (reviewed by the PGARD maintainers)", text: override.text });
    }
    // The same release installed in two places (nested node_modules) is one package.
    if (packages.some((pkg) => pkg.name === name && pkg.version === version)) continue;
    packages.push({
      name,
      version,
      license: override?.license ?? declaredLicense(manifest),
      dir,
      files,
    });
  }
  return packages.sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`));
}

/** One message per bundled package without a license text, without a license, or with a license outside `allowed`. */
export function licenseProblems(packages, allowed = ALLOWED_LICENSES) {
  const problems = [];
  for (const pkg of packages) {
    const label = `${pkg.name}@${pkg.version}`;
    if (pkg.license === null) {
      problems.push(`${label} declares no license`);
    } else if (!isAllowedExpression(pkg.license, allowed)) {
      problems.push(
        `${label} has license "${pkg.license}", which is not on the permissive allowlist`,
      );
    }
    if (!pkg.files.some((file) => file.text.length > 0)) {
      problems.push(`${label} has no license file (LICENSE, COPYING or NOTICE) to reproduce`);
    }
  }
  return problems;
}

/**
 * The NOTICE.md section for the bundled packages. Identical license texts are written once with
 * the list of packages that carry them, so the file stays readable; no text is dropped.
 */
export function renderBundledNotice(packages) {
  const groups = new Map();
  for (const pkg of packages) {
    const text = pkg.files
      .map((file) => (pkg.files.length > 1 ? `[${file.name}]\n${file.text}` : file.text))
      .join("\n\n");
    const key = createHash("sha256").update(text).digest("hex");
    const group = groups.get(key) ?? { text, members: [] };
    group.members.push(pkg);
    groups.set(key, group);
  }
  const lines = [
    "## Bundled npm packages",
    "",
    `The following ${packages.length} third-party npm packages are bundled into \`dist/\` at pack time, so their versions are fixed in this release. This section is generated from the files that went into the bundle; the license texts below are copied from the packages unchanged. \`@napi-rs/keyring\` and \`web-tree-sitter\` are not bundled: npm installs them as dependencies, each with its own license file.`,
    "",
  ];
  for (const { text, members } of groups.values()) {
    lines.push(
      members
        .map((pkg) => `- ${pkg.name} ${pkg.version} (${pkg.license ?? "no license field"})`)
        .join("\n"),
      "",
      "```text",
      text.split("```").join("` ` `"),
      "```",
      "",
    );
  }
  return lines.join("\n");
}
