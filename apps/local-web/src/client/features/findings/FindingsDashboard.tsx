import { useMemo, useState } from "react";
import type { FindingStatus, ScanResult, ScanScope, Severity } from "@pgard/findings";
import { SeverityBarChart } from "../../components/charts/SeverityBarChart";
import { SeverityDonutChart } from "../../components/charts/SeverityDonutChart";
import { SEVERITY_LABELS, SEVERITY_ORDER } from "../../components/charts/severity-scale";
import { Card, Notice } from "../../components/ui/Card";
import {
  countBySeverity,
  EMPTY_FILTERS,
  filterFindings,
  formatLocation,
  type FindingFilters,
} from "./filter-findings";

const OVERALL_LABELS: Record<string, string> = {
  completed: "Completed",
  partial: "Partial - some requested areas did not fully run",
  blocked: "Blocked by the authorization gate - no analysis ran",
  failed: "Failed - an internal error stopped the scan",
};

/** Charts, filters and the finding list for the current session's result (already redacted). */
export function FindingsDashboard({ result }: { result: ScanResult }) {
  const [filters, setFilters] = useState<FindingFilters>(EMPTY_FILTERS);
  const counts = useMemo(() => countBySeverity(result.findings), [result.findings]);
  const visible = useMemo(
    () => filterFindings(result.findings, filters),
    [result.findings, filters],
  );
  const statusCounts = useMemo(() => {
    const split = { confirmed: 0, suspected: 0, informational: 0 };
    for (const finding of result.findings) if (finding.status in split) split[finding.status] += 1;
    return split;
  }, [result.findings]);

  if (result.overallStatus === "blocked") {
    return (
      <Card title="Results" step={4}>
        <Notice tone="warning">
          {OVERALL_LABELS.blocked}. See the authorization reasons above.
        </Notice>
      </Card>
    );
  }

  return (
    <Card title="Results" step={4}>
      <p className={`overall overall-${result.overallStatus}`}>
        {OVERALL_LABELS[result.overallStatus] ?? "Unknown"} - {result.findings.length} finding(s):{" "}
        {statusCounts.confirmed} confirmed, {statusCounts.suspected} suspected,{" "}
        {statusCounts.informational} informational
      </p>
      <div className="charts">
        <SeverityBarChart
          counts={counts}
          activeSeverity={filters.severity}
          onSelect={(severity) => setFilters((current) => ({ ...current, severity }))}
        />
        <SeverityDonutChart counts={counts} />
      </div>
      <div className="filters" role="group" aria-label="Filters">
        <label>
          Severity
          <select
            value={filters.severity ?? ""}
            onChange={(event) =>
              setFilters((current) => ({
                ...current,
                severity: (event.target.value || null) as Severity | null,
              }))
            }
          >
            <option value="">All</option>
            {SEVERITY_ORDER.map((severity) => (
              <option key={severity} value={severity}>
                {SEVERITY_LABELS[severity]}
              </option>
            ))}
          </select>
        </label>
        <label>
          Status
          <select
            value={filters.status ?? ""}
            onChange={(event) =>
              setFilters((current) => ({
                ...current,
                status: (event.target.value || null) as FindingStatus | null,
              }))
            }
          >
            <option value="">All</option>
            <option value="confirmed">Confirmed</option>
            <option value="suspected">Suspected</option>
            <option value="informational">Informational</option>
          </select>
        </label>
        <label>
          Source
          <select
            value={filters.source ?? ""}
            onChange={(event) =>
              setFilters((current) => ({
                ...current,
                source: (event.target.value || null) as ScanScope | null,
              }))
            }
          >
            <option value="">All</option>
            <option value="code">Code</option>
            <option value="history">History</option>
            <option value="web">Web</option>
          </select>
        </label>
        <label>
          Search
          <input
            type="search"
            value={filters.text}
            onChange={(event) =>
              setFilters((current) => ({ ...current, text: event.target.value }))
            }
          />
        </label>
      </div>
      {visible.length === 0 ? (
        <p className="muted">
          {result.findings.length === 0
            ? "No findings in the areas that ran. This does not mean the project is secure; check coverage."
            : "No findings match the filters."}
        </p>
      ) : (
        <ul className="findings">
          {visible.map((finding) => (
            <li key={finding.id} className={`finding sev-${finding.severity}`}>
              <div className="finding-head">
                <span className={`badge sev-badge sev-${finding.severity}`}>
                  {SEVERITY_LABELS[finding.severity]}
                </span>
                <span className="badge">{finding.status}</span>
                <span className="muted">confidence {finding.confidence}</span>
              </div>
              <h3>{finding.title}</h3>
              <p className="location">
                <code>{formatLocation(finding.location)}</code>{" "}
                <span className="muted">{finding.ruleId}</span>
              </p>
              <dl>
                <dt>Evidence (redacted)</dt>
                <dd>
                  <pre>{finding.evidence}</pre>
                </dd>
                <dt>Impact</dt>
                <dd>{finding.impact}</dd>
                <dt>Recommendation</dt>
                <dd>{finding.recommendation}</dd>
              </dl>
            </li>
          ))}
        </ul>
      )}
      <p className="muted small">
        Advisory data: {result.advisoryDb.version ?? "none"}
        {result.advisoryDb.updatedAt ? `, updated ${result.advisoryDb.updatedAt}` : ""}
      </p>
    </Card>
  );
}
