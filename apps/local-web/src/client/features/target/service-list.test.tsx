import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { PortListResponse, RelatednessDto } from "../../../shared/api-types";
import { I18nProvider } from "../../i18n/I18nProvider";
import { RelatednessNotice, ServiceList, orderServices } from "./ServiceList";

afterEach(() => vi.unstubAllGlobals());

function render(language: "en" | "ko", node: React.ReactNode): string {
  vi.stubGlobal("navigator", { languages: [language] });
  return renderToStaticMarkup(<I18nProvider>{node}</I18nProvider>);
}

function related(verdict: RelatednessDto["verdict"], serviceLabel = "Grafana"): RelatednessDto {
  return { verdict, serviceLabel, projectLabel: "shop" };
}

function service(
  port: number,
  verdict: RelatednessDto["verdict"],
  title: string,
): PortListResponse["services"][number] {
  return {
    port,
    url: `http://127.0.0.1:${port}/`,
    status: 200,
    title,
    inferredTechnologies: [],
    isHttp: true,
    hasUnfollowedRedirect: false,
    error: null,
    relatedness: related(verdict, title),
    processName: "node",
  };
}

describe("RelatednessNotice", () => {
  it("shows one warning line for an unlikely service, in English and Korean", () => {
    const node = <RelatednessNotice relatedness={related("unlikely")} />;
    const en = render("en", node);
    const ko = render("ko", node);
    expect(en).toContain(
      "This service doesn&#x27;t look related to this project (service: &#x27;Grafana&#x27;, project: &#x27;shop&#x27;).",
    );
    expect(en).toContain("notice-warning");
    expect(ko).toContain(
      "이 서비스는 현재 프로젝트와 관련 없어 보입니다 (서비스: &#x27;Grafana&#x27;, 프로젝트: &#x27;shop&#x27;).",
    );
  });

  it.each(["likely", "unclear"] as const)("shows nothing for a %s service", (verdict) => {
    expect(render("en", <RelatednessNotice relatedness={related(verdict)} />)).toBe("");
    expect(render("ko", <RelatednessNotice relatedness={related(verdict)} />)).toBe("");
  });

  it("renders service text as text, never as markup", () => {
    const html = render(
      "en",
      <RelatednessNotice relatedness={related("unlikely", "<img src=x onerror=alert(1)>")} />,
    );
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
  });
});

describe("ServiceList", () => {
  const services = [
    service(3000, "unlikely", "Grafana"),
    service(4000, "unclear", "Landing"),
    service(5173, "likely", "Shop dev"),
  ];

  it("orders the ones that look like this project first", () => {
    expect(orderServices(services).map((entry) => entry.port)).toEqual([5173, 3000, 4000]);
  });

  it("marks only the likely one, in English and Korean", () => {
    const node = <ServiceList services={services} isBusy={false} onPick={() => undefined} />;
    const en = render("en", node);
    const ko = render("ko", node);
    expect(en.indexOf("127.0.0.1:5173")).toBeLessThan(en.indexOf("127.0.0.1:3000"));
    expect(en.match(/\(name matches this project\)/g)).toHaveLength(1);
    expect(ko.indexOf("127.0.0.1:5173")).toBeLessThan(ko.indexOf("127.0.0.1:3000"));
    expect(ko.match(/\(이름이 프로젝트와 비슷함\)/g)).toHaveLength(1);
  });
});
