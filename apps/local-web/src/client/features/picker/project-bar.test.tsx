import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { I18nProvider } from "../../i18n/I18nProvider";
import { ProjectBar } from "./ProjectBar";

afterEach(() => vi.unstubAllGlobals());

function render(node: React.ReactNode, language = "en"): string {
  vi.stubGlobal("navigator", { languages: [language] });
  return renderToStaticMarkup(<I18nProvider>{node}</I18nProvider>);
}

const project = { name: "my-project", repo: null };
const noop = (): void => undefined;

describe("Cancel check in pgard dashboard (fixed mode, #377)", () => {
  it("shows only Cancel check, while a check runs, and no Change project", () => {
    const html = render(
      <ProjectBar
        project={project}
        canChange={false}
        isScanRunning={false}
        isAuthRunning
        onChanged={noop}
      />,
    );
    expect(html).toContain("Cancel check");
    expect(html).not.toContain("Change project");
    expect(
      render(
        <ProjectBar
          project={project}
          canChange={false}
          isScanRunning={false}
          isAuthRunning
          onChanged={noop}
        />,
        "ko",
      ),
    ).toContain("확인 취소");
  });

  it("renders nothing in fixed mode when there is nothing to cancel", () => {
    const html = render(
      <ProjectBar
        project={project}
        canChange={false}
        isScanRunning={false}
        isAuthRunning={false}
        onChanged={noop}
      />,
    );
    expect(html).toBe("");
  });

  it("shows Cancel check only while a check really runs, never while only waiting for an install", () => {
    const html = render(
      <ProjectBar project={project} isScanRunning={false} isAuthRunning={false} onChanged={noop} />,
    );
    expect(html).not.toContain("Cancel check");
    expect(html).not.toMatch(/<button[^>]*disabled[^>]*>Change project/);
  });

  it("an owner-approval re-check counts as a running check (Change project waits)", () => {
    const html = render(
      <ProjectBar project={project} isScanRunning={false} isAuthRunning onChanged={noop} />,
    );
    expect(html).toContain("Cancel check");
    expect(html).toMatch(/<button[^>]*disabled[^>]*>Change project/);
  });
});
