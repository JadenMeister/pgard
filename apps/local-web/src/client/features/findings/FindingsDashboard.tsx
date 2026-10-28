import { useMemo, useReducer } from "react";
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
import { Card } from "../../components/ui/Card";
import { EmptyState } from "../../components/ui/EmptyState";
import { Notice } from "../../components/ui/Notice";
import type { RuleTextsResponse } from "../../../shared/api-types";
import { localizeFindingText } from "./rule-texts";
import { useI18n } from "../../i18n/I18nProvider";
import {
  buildFindingsView,
  formatSeverityBreakdown,
  partitionFindings,
  type FindingFilters,
} from "./filter-findings";
import { FindingList } from "./FindingList";
import {
  findingsListReducer,
  INITIAL_LIST_STATE,
  type FindingListId,
  type FindingsListState,
} from "./pagination";

/** Charts, filters and the paged finding lists for the current session's result (already redacted). */
export function FindingsDashboard({
  result,
  ruleTexts = null,
  initialState = INITIAL_LIST_STATE,
}: {
  result: ScanResult;
  /** Rule texts from `GET /api/rule-texts`; without them findings show their stored English text. */
  ruleTexts?: RuleTextsResponse | null;
  /** Starting filters and pages (tests); the panel always starts at page 1 with no filter. */
  initialState?: FindingsListState;
}) {
  const { m, language } = useI18n();
  const [state, dispatch] = useReducer(findingsListReducer, initialState);
  const { filters, pageSize } = state;
  const setFilter = (patch: Partial<FindingFilters>): void => dispatch({ type: "filter", patch });
  const listProps = (list: FindingListId) => ({
    page: state.pages[list] ?? 1,
    pageSize,
    onPage: (page: number) => dispatch({ type: "page", list, page }),
    onPageSize: (size: number) => dispatch({ type: "pageSize", pageSize: size }),
  });
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

  const groupList = (section: (typeof view.sections)[number], label: string) =>
    section.visible.length === 0 ? (
      <EmptyState title={m.findings.noMatch} />
    ) : (
      <FindingList
        label={label}
        findings={section.visible}
        ruleTexts={ruleTexts}
        {...listProps(section.kind)}
      />
    );

  return (
    <Card title={m.cards.results} step={4}>
      <p className={`headline overall-${result.overallStatus}`}>
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
          {m.findings.baselineCount(
            result.baseline.matched,
            result.baseline.new,
            formatSeverityBreakdown(partitionFindings(result.findings).baseline, m),
          )}
        </p>
      )}
      <div className="charts">
        <SeverityBarChart
          counts={counts}
          activeSeverity={filters.severity}
          onSelect={(severity) => setFilter({ severity })}
        />
        <SeverityDonutChart counts={counts} />
      </div>
      <div className="filters" role="group" aria-label={m.findings.filters}>
        <label>
          {m.findings.severity}
          <select
            value={filters.severity ?? ""}
            onChange={(event) =>
              setFilter({ severity: (event.target.value || null) as Severity | null })
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
              setFilter({ status: (event.target.value || null) as FindingStatus | null })
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
              setFilter({ source: (event.target.value || null) as ScanScope | null })
            }
          >
            <option value="">{m.common.all}</option>
            <option value="code">{m.findings.sources.code}</option>
            <option value="history">{m.findings.sources.history}</option>
            <option value="web">{m.findings.sources.web}</option>
          </select>
        </label>
        <label className="filter-search">
          {m.findings.search}
          <input
            type="search"
            value={filters.text}
            onChange={(event) => setFilter({ text: event.target.value })}
          />
        </label>
      </div>
      {view.emptyMessage !== null ? (
        <EmptyState title={view.emptyMessage} />
      ) : (
        <FindingList
          label={m.findings.pager.regular}
          findings={visible}
          ruleTexts={ruleTexts}
          isNew={result.baseline !== undefined}
          {...listProps("primary")}
        />
      )}
      {view.sections.map((section) =>
        section.kind === "suppressed" || section.kind === "baseline" ? (
          // Collapsed, never omitted: the count is in the title and the headline, and a section
          // holding a critical finding is open.
          <details
            key={section.kind}
            className="finding-group collapsible-findings"
            open={section.visible.some((finding: Finding) => finding.severity === "critical")}
            aria-label={
              section.kind === "suppressed" ? m.findings.suppressedAria : m.findings.baselineAria
            }
          >
            <summary>{section.title}</summary>
            <p className="muted small">
              {section.kind === "suppressed" ? m.findings.suppressedNote : m.findings.baselineNote}
            </p>
            {groupList(
              section,
              section.kind === "suppressed" ? m.findings.suppressedAria : m.findings.baselineAria,
            )}
          </details>
        ) : (
          <section
            key={section.kind}
            className={
              section.kind === "test"
                ? "finding-group test-findings"
                : "finding-group vendored-findings"
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
            {groupList(
              section,
              section.kind === "test" ? m.findings.testAria : m.findings.vendoredAria,
            )}
          </section>
        ),
      )}
      <p className="muted small">{m.findings.noDatabase}</p>
    </Card>
  );
}
