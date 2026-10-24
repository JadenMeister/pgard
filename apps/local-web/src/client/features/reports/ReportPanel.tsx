import { useState } from "react";
import type { ReportFormatDto, ReportResponse } from "../../../shared/api-types";
import { apiPost } from "../../api/client";
import { Card, Notice } from "../../components/ui/Card";

/** Exports the current result as HTML/PDF via the server; never overwrites existing files. */
export function ReportPanel() {
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
      setError(caught instanceof Error ? caught.message : "Request failed.");
    }
  };

  return (
    <Card title="Export report" step={5}>
      <form
        className="inline-form"
        onSubmit={(event) => {
          event.preventDefault();
          void save(false);
        }}
      >
        <label>
          Format
          <select
            value={format}
            onChange={(event) => setFormat(event.target.value as ReportFormatDto)}
          >
            <option value="html">HTML</option>
            <option value="pdf">PDF</option>
            <option value="both">HTML and PDF</option>
          </select>
        </label>
        <label className="grow">
          Output directory (absolute path, must exist)
          <input
            value={outputDir}
            onChange={(event) => setOutputDir(event.target.value)}
            spellCheck={false}
          />
        </label>
        <button type="submit" className="button primary" disabled={outputDir.trim() === ""}>
          Save
        </button>
      </form>
      <p className="muted small">
        Existing files are never overwritten. Reports may describe sensitive weaknesses.
      </p>
      {warning && (
        <div className="confirm-row">
          <Notice tone="warning">{warning}</Notice>
          <button type="button" className="button" onClick={() => void save(true)}>
            Save inside the repository anyway
          </button>
          <button type="button" className="button" onClick={() => setWarning(null)}>
            Choose another directory
          </button>
        </div>
      )}
      {saved.length > 0 && (
        <Notice tone="info">
          Saved:{" "}
          {saved.map((file) => (
            <code key={file}>{file} </code>
          ))}
        </Notice>
      )}
      {error && <Notice tone="error">{error}</Notice>}
    </Card>
  );
}
