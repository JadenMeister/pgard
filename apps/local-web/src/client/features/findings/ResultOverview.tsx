import { useMemo } from "react";
import type { ScanResult } from "@pgard/findings";
import type { RuleTextsResponse } from "../../../shared/api-types";
import { SEVERITY_ORDER } from "../../components/charts/severity-scale";
import { Section } from "../../components/ui/Section";
import { useI18n } from "../../i18n/I18nProvider";
import {
  buildFindingsView,
  EMPTY_FILTERS,
  formatSeverityBreakdown,
  partitionFindings,
} from "./filter-findings";
import { FindingTable } from "./FindingTable";
import { coverageCounts, statusLine } from "./result-summary";
import { localizeFindingText } from "./rule-texts";

const TOP_COUNT = 5;

/**
 * The result at a glance on the Overview: one status line, the counts, findings per severity, a
 * coverage summary and the five most severe findings. Links lead to the full views.
 */
export function ResultOverview({
  result,
  ruleTexts = null,
}: {
  result: ScanResult;
  ruleTexts?: RuleTextsResponse | null;
}) {
  const { m, language } = useI18n();
  const findings = useMemo(
    () => result.findings.map((finding) => localizeFindingText(finding, ruleTexts, language)),
    [result.findings, ruleTexts, language],
  );
  const view = useMemo(() => buildFindingsView(findings, EMPTY_FILTERS, m), [findings, m]);
  const isBlocked = result.overallStatus === "blocked";
  const coverage = coverageCounts(result.coverage);
  const context = [
    ...(view.contextNote === "" ? [] : [view.contextNote]),
    ...(result.baseline === undefined
      ? []
      : [
          m.findings.baselineCount(
            result.baseline.matched,
            result.baseline.new,
            formatSeverityBreakdown(partitionFindings(result.findings).baseline, m),
          ),
        ]),
  ];
  const stats: Array<[string, number]> = [
    [m.overview.stats.findings, view.total],
    [m.overview.stats.confirmed, view.statusCounts.confirmed],
    [m.overview.stats.suspected, view.statusCounts.suspected],
    [m.overview.stats.informational, view.statusCounts.informational],
  ];

  return (
    <>
      <p className={`status-line overall-${result.overallStatus}`}>
        <span className="status-dot" aria-hidden="true" />
        {statusLine(result, m)}
      </p>
      {!isBlocked && (
        <>
          <dl className="stats">
            {stats.map(([label, value]) => (
              <div key={label} className="stat">
                <dt>{label}</dt>
                <dd className="num">{value}</dd>
              </div>
            ))}
          </dl>
          {context.length > 0 && (
            <ul className="context-list">
              {context.map((entry) => (
                <li key={entry}>{entry}</li>
              ))}
            </ul>
          )}
          <p className="sev-strip" aria-label={m.overview.severityLabel}>
            {SEVERITY_ORDER.map((severity) => (
              <span key={severity} className={`sev-count sev-${severity}`}>
                <span className="num">{view.counts[severity]}</span> {m.severityInline[severity]}
              </span>
            ))}
          </p>
        </>
      )}
      <p className="coverage-summary">
        <span className="coverage-summary-label">{m.overview.coverageTitle}</span>{" "}
        {m.overview.coverageCounts(coverage.completed, coverage.partial, coverage.notTested)}{" "}
        <a href="#coverage">{m.overview.coverageLink}</a>
      </p>
      {!isBlocked && view.visible.length > 0 && (
        <Section
          title={m.overview.topTitle}
          level={3}
          actions={<a href="#findings">{m.overview.allFindings(view.total)}</a>}
        >
          <FindingTable
            label={m.overview.topTitle}
            findings={view.visible.slice(0, TOP_COUNT)}
            ruleTexts={ruleTexts}
            isNew={result.baseline !== undefined}
          />
        </Section>
      )}
    </>
  );
}
