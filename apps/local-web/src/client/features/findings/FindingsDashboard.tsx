import { useMemo, useState } from "react";
import {
  configTestFindingCount,
  type Finding,
  type FindingStatus,
  type ScanResult,
  type ScanScope,
  type Severity,
} from "@pgard/findings";
import { SeverityBarChart } from "../../components/charts/SeverityBarChart";
import { SeverityDonutChart } from "../../components/charts/SeverityDonutChart";
import { SEVERITY_ORDER } from "../../components/charts/severity-scale";
import { Card, Notice } from "../../components/ui/Card";
import type { RuleTextsResponse } from "../../../shared/api-types";
import { localizeFindingText } from "./rule-texts";
import { useI18n } from "../../i18n/I18nProvider";
import {
  buildFindingsView,
  EMPTY_FILTERS,
  formatLocation,
  type FindingFilters,
} from "./filter-findings";

function FindingItem({ finding, isNew = false }: { finding: Finding; isNew?: boolean }) {
  const { m } = useI18n();
  const statusLabels: Record<string, string> = m.status;
  const confidenceLabels: Record<string, string> = m.confidence;
  const location = formatLocation(finding.location, m);
  return (
    <li className={`finding sev-${finding.severity}`}>
      <div className="finding-head">
        {isNew && <span className="badge badge-new">{m.findings.newBadge}</span>}
        <span className={`badge sev-badge sev-${finding.severity}`}>
          {m.severity[finding.severity]}
        </span>
        <span className={`badge badge-${finding.status}`}>
          {statusLabels[finding.status] ?? finding.status}
        </span>
        <span className="muted">
          {m.findings.confidence(confidenceLabels[finding.confidence] ?? finding.confidence)}
        </span>
      </div>
      <h3>{finding.title}</h3>
      {finding.suppression !== undefined && (
        <p className="suppression-reason">
          {m.findings.suppressedReason(
            finding.suppression.reason,
            finding.suppression.expires ?? "",
          )}
        </p>
      )}
      <p className="location">
        <code title={location}>{location}</code> <span className="muted">{finding.ruleId}</span>
      </p>
      <dl>
        <dt>{m.findings.evidence}</dt>
        <dd>
          <pre>{finding.evidence}</pre>
        </dd>
        <dt>{m.findings.impact}</dt>
        <dd>{finding.impact}</dd>
        <dt>{m.findings.recommendation}</dt>
        <dd>{finding.recommendation}</dd>
      </dl>
    </li>
  );
}

/** Charts, filters and the finding list for the current session's result (already redacted). */
export function FindingsDashboard({
  result,
  ruleTexts = null,
}: {
  result: ScanResult;
  /** Rule texts from `GET /api/rule-texts`; without them findings show their stored English text. */
  ruleTexts?: RuleTextsResponse | null;
}) {
  const { m, language } = useI18n();
  const [filters, setFilters] = useState<FindingFilters>(EMPTY_FILTERS);
  // Headline counts and charts cover regular code; test and fixture findings are listed after,
  // and suggestions in vendored code come last (see buildFindingsView).
  const findings = useMemo(
    () => result.findings.map((finding) => localizeFindingText(finding, ruleTexts, language)),
    [result.findings, ruleTexts, language],
  );
  const view = useMemo(() => buildFindingsView(findings, filters, m), [findings, filters, m]);
  const { counts, statusCounts, contextNote, visible } = view;
  const configTestCount = configTestFindingCount(result.coverage);
  const overallLabels: Record<string, string> = m.findings.overall;

  if (result.overallStatus === "blocked") {
    return (
      <Card title={m.cards.results} step={4}>
        <Notice tone="warning">
          {m.findings.overall.blocked}. {m.findings.blockedNote}
        </Notice>
      </Card>
    );
  }

  return (
    <Card title={m.cards.results} step={4}>
      <p className={`overall overall-${result.overallStatus}`}>
        {m.findings.headline(
          overallLabels[result.overallStatus] ?? m.findings.overall.unknown,
          view.total,
          statusCounts.confirmed,
          statusCounts.suspected,
          statusCounts.informational,
          contextNote,
        )}
      </p>
      {result.baseline !== undefined && (
        <p className="muted">
          {m.findings.baselineCount(result.baseline.matched, result.baseline.new)}
        </p>
      )}
      <div className="charts">
        <SeverityBarChart
          counts={counts}
          activeSeverity={filters.severity}
          onSelect={(severity) => setFilters((current) => ({ ...current, severity }))}
        />
        <SeverityDonutChart counts={counts} />
      </div>
      <div className="filters" role="group" aria-label={m.findings.filters}>
        <label>
          {m.findings.severity}
          <select
            value={filters.severity ?? ""}
            onChange={(event) =>
              setFilters((current) => ({
                ...current,
                severity: (event.target.value || null) as Severity | null,
              }))
            }
          >
            <option value="">{m.common.all}</option>
            {SEVERITY_ORDER.map((severity) => (
              <option key={severity} value={severity}>
                {m.severity[severity]}
              </option>
            ))}
          </select>
        </label>
        <label>
          {m.findings.status}
          <select
            value={filters.status ?? ""}
            onChange={(event) =>
              setFilters((current) => ({
                ...current,
                status: (event.target.value || null) as FindingStatus | null,
              }))
            }
          >
            <option value="">{m.common.all}</option>
            <option value="confirmed">{m.findings.statusOptions.confirmed}</option>
            <option value="suspected">{m.findings.statusOptions.suspected}</option>
            <option value="informational">{m.findings.statusOptions.informational}</option>
          </select>
        </label>
        <label>
          {m.findings.source}
          <select
            value={filters.source ?? ""}
            onChange={(event) =>
              setFilters((current) => ({
                ...current,
                source: (event.target.value || null) as ScanScope | null,
              }))
            }
          >
            <option value="">{m.common.all}</option>
            <option value="code">{m.findings.sources.code}</option>
            <option value="history">{m.findings.sources.history}</option>
            <option value="web">{m.findings.sources.web}</option>
          </select>
        </label>
        <label>
          {m.findings.search}
          <input
            type="search"
            value={filters.text}
            onChange={(event) =>
              setFilters((current) => ({ ...current, text: event.target.value }))
            }
          />
        </label>
      </div>
      {view.emptyMessage !== null ? (
        <p className="muted">{view.emptyMessage}</p>
      ) : (
        <ul className="findings">
          {visible.map((finding) => (
            <FindingItem key={finding.id} finding={finding} isNew={result.baseline !== undefined} />
          ))}
        </ul>
      )}
      {view.sections.map((section) =>
        section.kind === "suppressed" || section.kind === "baseline" ? (
          // Collapsed, never omitted: the count is in the title and the headline, and a section
          // holding a critical finding is open.
          <details
            key={section.kind}
            className="test-findings collapsible-findings"
            open={section.visible.some((finding) => finding.severity === "critical")}
            aria-label={
              section.kind === "suppressed" ? m.findings.suppressedAria : m.findings.baselineAria
            }
          >
            <summary>{section.title}</summary>
            <p className="muted small">
              {section.kind === "suppressed" ? m.findings.suppressedNote : m.findings.baselineNote}
            </p>
            {section.visible.length === 0 ? (
              <p className="muted">{m.findings.noMatch}</p>
            ) : (
              <ul className="findings">
                {section.visible.map((finding) => (
                  <FindingItem key={finding.id} finding={finding} />
                ))}
              </ul>
            )}
          </details>
        ) : (
          <section
            key={section.kind}
            className={
              section.kind === "test" ? "test-findings" : "test-findings vendored-findings"
            }
            aria-label={section.kind === "test" ? m.findings.testAria : m.findings.vendoredAria}
          >
            <h3>{section.title}</h3>
            {section.kind === "test" ? (
              <p className="muted small">
                {m.findings.testNote}
                {configTestCount > 0 ? m.findings.testNoteConfig(configTestCount) : ""}
              </p>
            ) : (
              <>
                <p>
                  {m.findings.vendoredIntro}
                  <code>git rm -r --cached &lt;directory&gt;</code>
                  {m.findings.vendoredThen}
                  <code>.gitignore</code>
                  {m.findings.vendoredEnd}
                </p>
                <p className="muted small">{m.findings.vendoredNote}</p>
              </>
            )}
            {section.visible.length === 0 ? (
              <p className="muted">{m.findings.noMatch}</p>
            ) : (
              <ul className="findings">
                {section.visible.map((finding) => (
                  <FindingItem key={finding.id} finding={finding} />
                ))}
              </ul>
            )}
          </section>
        ),
      )}
      <p className="muted small">{m.findings.noDatabase}</p>
    </Card>
  );
}
