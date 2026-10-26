import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { apiDownload, filenameFromDisposition, takeTokenFromLocation } from "../../api/client";
import { ko } from "../../i18n/ko";
import { triggerDownload, type DownloadEnvironment } from "./download";
import { ReportPanel } from "./ReportPanel";

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("triggerDownload", () => {
  it("clicks a temporary anchor pointing at an object URL, then removes it and revokes the URL", () => {
    vi.useFakeTimers();
    const events: string[] = [];
    const anchor = {
      href: "",
      download: "",
      rel: "",
      click: () => events.push(`click ${anchor.href} ${anchor.download}`),
      remove: () => events.push("remove"),
    };
    const environment: DownloadEnvironment = {
      createObjectUrl: () => "blob:http://127.0.0.1/abc",
      revokeObjectUrl: (url) => events.push(`revoke ${url}`),
      createAnchor: () => anchor,
      appendAnchor: () => events.push("append"),
    };
    triggerDownload(new Blob(["x"]), "pgard-report-a-1.html", environment);
    expect(events).toEqual([
      "append",
      "click blob:http://127.0.0.1/abc pgard-report-a-1.html",
      "remove",
    ]);
    vi.runAllTimers();
    expect(events.at(-1)).toBe("revoke blob:http://127.0.0.1/abc");
  });

  it("still removes the anchor and revokes the URL when the click throws", () => {
    vi.useFakeTimers();
    const events: string[] = [];
    const anchor = {
      href: "",
      download: "",
      rel: "",
      click: () => {
        throw new Error("blocked");
      },
      remove: () => events.push("remove"),
    };
    const environment: DownloadEnvironment = {
      createObjectUrl: () => "blob:x",
      revokeObjectUrl: () => events.push("revoke"),
      createAnchor: () => anchor,
      appendAnchor: () => undefined,
    };
    expect(() => triggerDownload(new Blob(["x"]), "f.html", environment)).toThrow("blocked");
    vi.runAllTimers();
    expect(events).toEqual(["remove", "revoke"]);
  });
});

describe("apiDownload", () => {
  const TOKEN = "abcdefghijklmnopqrstuvwxyz012345";
  function signIn(): void {
    takeTokenFromLocation(
      { hash: `#token=${TOKEN}`, pathname: "/", search: "" } as Location,
      { replaceState: () => undefined } as unknown as History,
    );
  }

  it("sends the session token and returns the blob with the server's file name", async () => {
    signIn();
    const fetchMock = vi.fn(
      async () =>
        new Response("<html></html>", {
          status: 200,
          headers: {
            "content-disposition": 'attachment; filename="pgard-report-o-n-20261024000000.html"',
          },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const file = await apiDownload("/api/reports/html", "fallback.html");
    expect(file.filename).toBe("pgard-report-o-n-20261024000000.html");
    expect(await file.blob.text()).toBe("<html></html>");
    const [path, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(path).toBe("/api/reports/html");
    expect((init.headers as Record<string, string>)["x-pgard-token"]).toBe(TOKEN);
    expect(init.credentials).toBe("omit");
  });

  it("throws on an error response", async () => {
    signIn();
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify({ error: { code: "no_result", message: "none" } }), {
            status: 409,
          }),
      ),
    );
    await expect(apiDownload("/api/reports/pdf", "f.pdf")).rejects.toMatchObject({
      status: 409,
      code: "no_result",
    });
  });

  it("only accepts a plain file name from the header", () => {
    expect(filenameFromDisposition('attachment; filename="a-b_c.1.pdf"')).toBe("a-b_c.1.pdf");
    expect(filenameFromDisposition('attachment; filename="../x"')).toBeNull();
    expect(filenameFromDisposition(null)).toBeNull();
  });
});

describe("report panel", () => {
  it("has download buttons and no path field", () => {
    const html = renderToStaticMarkup(<ReportPanel />);
    expect(html).toContain("Download HTML");
    expect(html).toContain("Download PDF");
    expect(html).not.toContain("<input");
    expect(html).not.toContain("<form");
    expect(html).not.toMatch(/directory/i);
  });

  it("has Korean wording for the download states", () => {
    expect(ko.report.downloadHtml).toBe("HTML 다운로드");
    expect(ko.report.preparing("PDF")).toContain("PDF");
    expect(ko.report.failed).not.toBe("");
  });
});
