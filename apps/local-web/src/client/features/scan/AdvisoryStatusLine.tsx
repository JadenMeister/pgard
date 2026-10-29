import { useEffect, useState } from "react";
import type { AdvisoryStatusDto } from "../../../shared/api-types";
import { apiGet, hasSessionToken } from "../../api/client";
import { Notice } from "../../components/ui/Notice";
import { useI18n } from "../../i18n/I18nProvider";

/** The advisory-data status line, from an already loaded status (also used by tests). */
export function AdvisoryStatusView({ status }: { status: AdvisoryStatusDto }) {
  const { m } = useI18n();
  const text = m.scan.advisory;
  const hasData = status.ecosystems.some((entry) => entry.fetchedAt !== null);
  const parts: string[] = [];
  if (status.overall === "unreadable") {
    parts.push(text.unreadable);
  } else if (status.overall === "none" && !hasData) {
    parts.push(text.missing);
  } else {
    // `none` with some data: another ecosystem has no data, so the data is only partial.
    const state = status.overall === "none" ? "partial" : status.overall;
    parts.push(`${text.state[state]}.`);
    for (const entry of status.ecosystems) {
      parts.push(
        `${text.ecosystem(
          entry.ecosystem,
          entry.fetchedAt === null ? null : entry.fetchedAt.slice(0, 10),
          entry.ageDays,
          entry.modifiedMax === null ? null : entry.modifiedMax.slice(0, 10),
          entry.dataVersion,
        )};`,
      );
    }
    if (state === "stale") parts.push(text.staleHint(status.staleAfterDays));
    if (state === "damaged") parts.push(text.damagedHint);
  }
  if (status.storePath !== null) parts.push(text.store(status.storePath));
  return (
    <Notice tone={status.overall === "fresh" ? "info" : "warning"}>
      <strong>{text.label}:</strong> {parts.join(" ")}
    </Notice>
  );
}

/** Fetches the status once (local files on the server; no download) and shows it. */
export function AdvisoryStatusLine() {
  const [status, setStatus] = useState<AdvisoryStatusDto | null>(null);
  useEffect(() => {
    if (!hasSessionToken()) return undefined;
    let isCurrent = true;
    apiGet<AdvisoryStatusDto>("/api/advisory-status").then(
      (value) => {
        if (isCurrent) setStatus(value);
      },
      () => undefined,
    );
    return () => {
      isCurrent = false;
    };
  }, []);
  return status === null ? null : <AdvisoryStatusView status={status} />;
}
