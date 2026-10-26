/// <reference types="node" />
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const css = readFileSync(new URL("./app.css", import.meta.url), "utf8");

describe("badge styles", () => {
  const classes = [
    // authorization check and coverage statuses
    "badge-passed",
    "badge-failed",
    "badge-blocked",
    "badge-unverifiable",
    "badge-completed",
    "badge-partial",
    "badge-not_tested",
    "badge-not_selected",
    // finding statuses
    "badge-confirmed",
    "badge-suspected",
    "badge-informational",
    // severities
    ".badge.sev-critical",
    ".badge.sev-high",
    ".badge.sev-medium",
    ".badge.sev-low",
    ".badge.sev-info",
  ];

  it.each(classes)("defines a rule for %s", (name) => {
    const selector = name.startsWith(".") ? name : `.${name}`;
    expect(css).toContain(selector);
  });

  it("never lets a badge wrap its text", () => {
    expect(css).toMatch(/\.badge \{[^}]*white-space: nowrap/);
  });
});
