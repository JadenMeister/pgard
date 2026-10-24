import { describe, expect, it } from "vitest";
import { extractSameOriginLinks, extractTitle, inferTechnologies } from "./html.js";

describe("extractTitle", () => {
  it("decodes entities and strips terminal control characters", () => {
    expect(extractTitle("<html><title>My &amp; App\u001b[31m</title></html>")).toBe(
      "My & App [31m",
    );
    expect(extractTitle("<p>no title</p>")).toBeNull();
    expect(extractTitle("<title>   </title>")).toBeNull();
  });
});

describe("extractSameOriginLinks", () => {
  const page = "http://127.0.0.1:3000/docs/";

  it("keeps same-origin paths only, without query or fragment", () => {
    const html = `
      <a href="/a?token=secret#x">a</a>
      <a href='b'>b</a>
      <a href=http://127.0.0.1:3000/c>c</a>
      <a href="http://127.0.0.1:3001/other-port">x</a>
      <a href="http://localhost:3000/host">x</a>
      <a href="https://example.com/">x</a>
      <a href="mailto:a@example.com">x</a>
      <a href="#top">x</a>`;
    expect(extractSameOriginLinks(html, page, 3000)).toEqual(["/a", "/docs/b", "/c"]);
  });

  it("skips links that look like state-changing actions", () => {
    const html = `<a href="/logout">x</a><a href="/users/1/delete">x</a><a href="/sign-out">x</a><a href="/blog">ok</a>`;
    expect(extractSameOriginLinks(html, page, 3000)).toEqual(["/blog"]);
  });
});

describe("inferTechnologies", () => {
  it("collects hints from headers and markup", () => {
    const hints = inferTechnologies(
      { server: "nginx/1.25", "x-powered-by": "Express" },
      '<script src="/_next/static/x.js"></script><meta name="generator" content="Hugo 0.1">',
    );
    expect(hints).toEqual(["nginx/1.25", "Express", "Hugo 0.1", "Next.js"]);
  });
});
