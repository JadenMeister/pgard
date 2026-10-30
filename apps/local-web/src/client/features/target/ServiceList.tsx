import type { PortListResponse, RelatednessDto } from "../../../shared/api-types";
import { Notice } from "../../components/ui/Notice";
import { useI18n } from "../../i18n/I18nProvider";

type ListedService = PortListResponse["services"][number];

/** The services that look like this project first; ties keep the order the server gave. */
export function orderServices<T extends { relatedness: RelatednessDto }>(services: T[]): T[] {
  const isLikely = (service: T): boolean => service.relatedness.verdict === "likely";
  return [...services.filter(isLikely), ...services.filter((service) => !isLikely(service))];
}

/** Detected local services, the ones that look like this project first and marked. */
export function ServiceList({
  services,
  isBusy,
  onPick,
}: {
  services: ListedService[];
  isBusy: boolean;
  onPick: (port: number) => void;
}) {
  const { m } = useI18n();
  return (
    <>
      {orderServices(services).map((service) => (
        <button
          type="button"
          key={service.port}
          className="service"
          disabled={isBusy}
          onClick={() => onPick(service.port)}
        >
          <code>http://127.0.0.1:{service.port}</code>
          <span className="muted">
            {service.status ?? ""} {service.title ?? ""}{" "}
            {service.processName ? `(${service.processName})` : ""}
            {service.relatedness.verdict === "likely" ? ` ${m.target.looksRelated}` : ""}
          </span>
        </button>
      ))}
    </>
  );
}

/**
 * One warning line before the question when the service does not look like this project. A hint
 * only: the buttons next to it are unchanged and the answer is still the user's.
 */
export function RelatednessNotice({ relatedness }: { relatedness: RelatednessDto }) {
  const { m } = useI18n();
  if (relatedness.verdict !== "unlikely" || relatedness.serviceLabel === null) return null;
  return (
    <Notice tone="warning">
      {m.target.unrelated(relatedness.serviceLabel, relatedness.projectLabel ?? "")}
    </Notice>
  );
}
