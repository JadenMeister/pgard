import { useState } from "react";
import type { ReportFormatDto, ReportResponse } from "../../../shared/api-types";
import { apiPost } from "../../api/client";
import { Card, Notice } from "../../components/ui/Card";
import { useI18n } from "../../i18n/I18nProvider";

/** Exports the current result as HTML/PDF via the server; never overwrites existing files. */
export function ReportPanel() {
  const { m } = useI18n();
  const [format, setFormat] = useState<ReportFormatDto>("html");
  const [outputDir, setOutputDir] = useState("");
  const [warning, setWarning] = useState<string | null>(null);
  const [saved, setSaved] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  const save = async (isInsideRepositoryConfirmed: boolean): Promise<void> => {
    setError(null);
    setSaved([]);
    try {
      const response = await apiPost<ReportResponse>("/api/reports", {
        format,
        outputDir: outputDir.trim(),
        isInsideRepositoryConfirmed,
      });
      if (response.status === "needs_confirmation") {
        setWarning(response.warning);
        return;
      }
      setWarning(null);
      setSaved(response.files);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : m.common.requestFailed);
    }
  };

  return (
    <Card title={m.cards.report} step={5}>
      <form
        className="inline-form"
        onSubmit={(event) => {
          event.preventDefault();
          void save(false);
        }}
      >
        <label>
          {m.report.format}
          <select
            value={format}
            onChange={(event) => setFormat(event.target.value as ReportFormatDto)}
          >
            <option value="html">{m.report.html}</option>
            <option value="pdf">{m.report.pdf}</option>
            <option value="both">{m.report.both}</option>
          </select>
        </label>
        <label className="grow">
          {m.report.outputDir}
          <input
            value={outputDir}
            onChange={(event) => setOutputDir(event.target.value)}
            spellCheck={false}
          />
        </label>
        <button type="submit" className="button primary" disabled={outputDir.trim() === ""}>
          {m.report.save}
        </button>
      </form>
      <p className="muted small">{m.report.note}</p>
      {warning && (
        <div className="confirm-row">
          <Notice tone="warning">{warning}</Notice>
          <button type="button" className="button" onClick={() => void save(true)}>
            {m.report.saveInside}
          </button>
          <button type="button" className="button" onClick={() => setWarning(null)}>
            {m.report.chooseOther}
          </button>
        </div>
      )}
      {saved.length > 0 && (
        <Notice tone="info">
          {m.report.saved}{" "}
          {saved.map((file) => (
            <code key={file}>{file} </code>
          ))}
        </Notice>
      )}
      {error && <Notice tone="error">{error}</Notice>}
    </Card>
  );
}
