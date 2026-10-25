import { useMemo, useState } from "react";
import type { Finding, FindingStatus, ScanResult, ScanScope, Severity } from "@pgard/findings";
import { SeverityBarChart } from "../../components/charts/SeverityBarChart";
import { SeverityDonutChart } from "../../components/charts/SeverityDonutChart";
import { SEVERITY_LABELS, SEVERITY_ORDER } from "../../components/charts/severity-scale";
import { Card, Notice } from "../../components/ui/Card";
import {
  countBySeverity,
  EMPTY_FILTERS,
  filterFindings,
  formatContextCounts,
  formatLocation,
  formatOutsideContexts,
  splitByContext,
  type FindingFilters,
} from "./filter-findings";

const OVERALL_LABELS: Record<string, string> = {
  completed: "Completed",
  partial: "Partial - some requested areas did not fully run",
  blocked: "Blocked by the authorization gate - no analysis ran",
  failed: "Failed - an internal error stopped the scan",
};

function FindingItem({ finding }: { finding: Finding }) {
  return (
    <li className={`finding sev-${finding.severity}`}>
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
  );
}

/** Charts, filters and the finding list for the current session's result (already redacted). */
export function FindingsDashboard({ result }: { result: ScanResult }) {
  const [filters, setFilters] = useState<FindingFilters>(EMPTY_FILTERS);
  // Headline counts and charts cover regular code; test and fixture findings are listed after,
  // and suggestions in vendored code come last.
  const groups = useMemo(() => splitByContext(result.findings), [result.findings]);
  const counts = useMemo(() => countBySeverity(groups.primary), [groups]);
  const visible = useMemo(() => filterFindings(groups.primary, filters), [groups, filters]);
  const visibleTest = useMemo(() => filterFindings(groups.test, filters), [groups, filters]);
  const visibleVendored = useMemo(
    () => filterFindings(groups.vendored, filters),
    [groups, filters],
  );
  const contextCounts = { test: groups.test.length, vendored: groups.vendored.length };
  const contextNote = formatContextCounts({ test: groups.test.length, vendored: groups.vendored });
  const statusCounts = useMemo(() => {
    const split = { confirmed: 0, suspected: 0, informational: 0 };
    for (const finding of groups.primary) if (finding.status in split) split[finding.status] += 1;
    return split;
  }, [groups]);

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
        {OVERALL_LABELS[result.overallStatus] ?? "Unknown"} - {groups.primary.length} finding(s):{" "}
        {statusCounts.confirmed} confirmed, {statusCounts.suspected} suspected,{" "}
        {statusCounts.informational} informational
        {contextNote === "" ? "" : ` - ${contextNote}`}
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
          {groups.primary.length === 0
            ? `No findings${formatOutsideContexts(contextCounts)} in the areas that ran. This does not mean the project is secure; check coverage.`
            : "No findings match the filters."}
        </p>
      ) : (
        <ul className="findings">
          {visible.map((finding) => (
            <FindingItem key={finding.id} finding={finding} />
          ))}
        </ul>
      )}
      {groups.test.length > 0 ? (
        <section className="test-findings" aria-label="Findings in test or fixture code">
          <h3>In test or fixture code ({groups.test.length})</h3>
          <p className="muted small">
            Matches in files classified as test or fixture code by their path only, with confidence
            capped at low. They are not counted above, but review them: a real value committed in a
            test is still exposed.
          </p>
          {visibleTest.length === 0 ? (
            <p className="muted">No findings match the filters.</p>
          ) : (
            <ul className="findings">
              {visibleTest.map((finding) => (
                <FindingItem key={finding.id} finding={finding} />
              ))}
            </ul>
          )}
        </section>
      ) : null}
      {groups.vendored.length > 0 ? (
        <section
          className="test-findings vendored-findings"
          aria-label="Suggestions in third-party or vendored code"
        >
          <h3>Suggestions: in third-party/vendored code ({groups.vendored.length})</h3>
          <p>
            This code is a committed dependency, not your code. Review it if it&apos;s unexpected;
            otherwise consider removing it from Git (
            <code>git rm -r --cached &lt;directory&gt;</code>, then add the directory to{" "}
            <code>.gitignore</code>).
          </p>
          <p className="muted small">
            Classified by path only: files under a node_modules/, bower_components/, jspm_packages/,
            vendor/, third_party/ or Pods/ directory. Confidence is capped at low and they are not
            counted above, but they are not dropped: a real secret committed there is still exposed.
          </p>
          {visibleVendored.length === 0 ? (
            <p className="muted">No findings match the filters.</p>
          ) : (
            <ul className="findings">
              {visibleVendored.map((finding) => (
                <FindingItem key={finding.id} finding={finding} />
              ))}
            </ul>
          )}
        </section>
      ) : null}
      <p className="muted small">
        PGARD does not ship or query a vulnerability database. Findings come from the code itself
        (query statements, server code, configuration), Git history and, if selected, local HTTP
        checks. Dependency versions are not checked against known vulnerabilities.
      </p>
    </Card>
  );
}
