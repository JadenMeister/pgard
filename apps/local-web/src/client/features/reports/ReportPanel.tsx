import { useState } from "react";
import type { ReportFormatDto } from "../../../shared/api-types";
import { apiDownload, ApiRequestError } from "../../api/client";
import { Card, Notice } from "../../components/ui/Card";
import { useI18n } from "../../i18n/I18nProvider";
import type { Messages } from "../../i18n/types";
import { triggerDownload } from "./download";

/** A distinct, translated message per failure kind. */
export function reportErrorMessage(caught: unknown, m: Messages): string {
  if (caught instanceof ApiRequestError) {
    if (caught.status === 401 || caught.status === 403) return m.report.sessionExpired;
    if (caught.status === 409) return m.report.noResult;
  }
  return m.report.failed;
}

/** API path of a report download, in the dashboard language. */
export function reportPath(format: ReportFormatDto, language: string): string {
  return `/api/reports/${format}?lang=${language}`;
}

/**
 * Downloads the current result as HTML or PDF through the browser's normal download. The server
 * renders it from the redacted result; the dashboard never writes files on disk.
 */
export function ReportPanel() {
  const { m, language } = useI18n();
  const [busy, setBusy] = useState<ReportFormatDto | null>(null);
  const [downloaded, setDownloaded] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const download = async (format: ReportFormatDto): Promise<void> => {
    setError(null);
    setDownloaded(null);
    setBusy(format);
    try {
      const file = await apiDownload(reportPath(format, language), `pgard-report.${format}`);
      triggerDownload(file.blob, file.filename);
      setDownloaded(file.filename);
    } catch (caught) {
      setError(reportErrorMessage(caught, m));
    } finally {
      setBusy(null);
    }
  };

  return (
    <Card title={m.cards.report} step={5}>
      <div className="button-row">
        <button
          type="button"
          className="button primary"
          disabled={busy !== null}
          onClick={() => void download("html")}
        >
          {m.report.downloadHtml}
        </button>
        <button
          type="button"
          className="button primary"
          disabled={busy !== null}
          onClick={() => void download("pdf")}
        >
          {m.report.downloadPdf}
        </button>
      </div>
      <p className="muted small">{m.report.note}</p>
      {busy !== null && (
        <p className="muted" role="status">
          {m.report.preparing(busy.toUpperCase())}
        </p>
      )}
      {downloaded !== null && (
        <Notice tone="info">
          <span title={downloaded}>{m.report.downloaded(downloaded)}</span>
        </Notice>
      )}
      {error && <Notice tone="error">{error}</Notice>}
    </Card>
  );
}
