import { useMemo, useReducer } from "react";
import {
  configTestFindingCount,
  type FindingStatus,
  type ScanResult,
  type ScanScope,
} from "@pgard/findings";
import { SEVERITY_ORDER } from "../../components/charts/severity-scale";
import { EmptyState } from "../../components/ui/EmptyState";
import { HelpTip } from "../../components/ui/HelpTip";
import { Notice } from "../../components/ui/Notice";
import { Section } from "../../components/ui/Section";
import type { RuleTextsResponse } from "../../../shared/api-types";
import { localizeFindingText } from "./rule-texts";
import { useI18n } from "../../i18n/I18nProvider";
import { buildFindingsView, type ContextSection, type FindingFilters } from "./filter-findings";
import { FindingTable } from "./FindingTable";
import {
  findingsListReducer,
  INITIAL_LIST_STATE,
  type FindingListId,
  type FindingsListState,
} from "./pagination";

/**
 * The Findings view: a severity filter strip, the other filters, the paged findings table, then
 * the separate groups (test code, vendored code, suppressed, in baseline), each paged on its own.
 */
export function FindingsDashboard({
  result,
  ruleTexts = null,
  initialState = INITIAL_LIST_STATE,
}: {
  result: ScanResult;
  /** Rule texts from `GET /api/rule-texts`; without them findings show their stored English text. */
  ruleTexts?: RuleTextsResponse | null;
  /** Starting filters and pages (tests); the view always starts at page 1 with no filter. */
  initialState?: FindingsListState;
}) {
  const { m, language } = useI18n();
  const [state, dispatch] = useReducer(findingsListReducer, initialState);
  const { filters, pageSize } = state;
  const setFilter = (patch: Partial<FindingFilters>): void => dispatch({ type: "filter", patch });
  const paging = (list: FindingListId) => ({
    page: state.pages[list] ?? 1,
    pageSize,
    onPage: (page: number) => dispatch({ type: "page", list, page }),
    onPageSize: (size: number) => dispatch({ type: "pageSize", pageSize: size }),
  });
  const findings = useMemo(
    () => result.findings.map((finding) => localizeFindingText(finding, ruleTexts, language)),
    [result.findings, ruleTexts, language],
  );
  const view = useMemo(() => buildFindingsView(findings, filters, m), [findings, filters, m]);
  const configTestCount = configTestFindingCount(result.coverage);

  if (result.overallStatus === "blocked") {
    return (
      <Section title={m.nav.findings}>
        <Notice tone="warning">
          {m.findings.overall.blocked}. {m.findings.blockedNote}
        </Notice>
      </Section>
    );
  }

  const groupTable = (section: ContextSection, label: string) =>
    section.visible.length === 0 ? (
      <EmptyState title={m.findings.noMatch} />
    ) : (
      <FindingTable
        label={label}
        findings={section.visible}
        ruleTexts={ruleTexts}
        paging={paging(section.kind)}
      />
    );

  return (
    <Section
      title={m.nav.findings}
      meta={<span className="num">{view.total}</span>}
      help={<p>{m.findings.noDatabase}</p>}
    >
      <div className="toolbar">
        <div className="sev-filter" role="group" aria-label={m.table.severityFilter}>
          {SEVERITY_ORDER.map((severity) => (
            <button
              key={severity}
              type="button"
              className={`sev-chip sev-${severity}`}
              aria-pressed={filters.severity === severity}
              onClick={() =>
                setFilter({ severity: filters.severity === severity ? null : severity })
              }
            >
              <span className="num">{view.counts[severity]}</span> {m.severityInline[severity]}
            </button>
          ))}
        </div>
        <div className="filters" role="group" aria-label={m.findings.filters}>
          <label>
            <span className="sr-only">{m.findings.status}</span>
            <select
              value={filters.status ?? ""}
              onChange={(event) =>
                setFilter({ status: (event.target.value || null) as FindingStatus | null })
              }
            >
              <option value="">
                {m.findings.status}: {m.common.all}
              </option>
              <option value="confirmed">{m.findings.statusOptions.confirmed}</option>
              <option value="suspected">{m.findings.statusOptions.suspected}</option>
              <option value="informational">{m.findings.statusOptions.informational}</option>
            </select>
          </label>
          <label>
            <span className="sr-only">{m.findings.source}</span>
            <select
              value={filters.source ?? ""}
              onChange={(event) =>
                setFilter({ source: (event.target.value || null) as ScanScope | null })
              }
            >
              <option value="">
                {m.findings.source}: {m.common.all}
              </option>
              <option value="code">{m.findings.sources.code}</option>
              <option value="history">{m.findings.sources.history}</option>
              <option value="web">{m.findings.sources.web}</option>
            </select>
          </label>
          <label className="filter-search">
            <span className="sr-only">{m.findings.search}</span>
            <input
              type="search"
              placeholder={m.findings.search}
              value={filters.text}
              onChange={(event) => setFilter({ text: event.target.value })}
            />
          </label>
        </div>
      </div>
      {view.emptyMessage !== null ? (
        <EmptyState title={view.emptyMessage} />
      ) : (
        <FindingTable
          label={m.findings.pager.regular}
          findings={view.visible}
          ruleTexts={ruleTexts}
          isNew={result.baseline !== undefined}
          paging={paging("primary")}
        />
      )}
      {view.sections.map((section) => {
        const label =
          section.kind === "test"
            ? m.findings.testAria
            : section.kind === "vendored"
              ? m.findings.vendoredAria
              : section.kind === "suppressed"
                ? m.findings.suppressedAria
                : m.findings.baselineAria;
        const help =
          section.kind === "test" ? (
            <p>
              {m.findings.testNote}
              {configTestCount > 0 ? m.findings.testNoteConfig(configTestCount) : ""}
            </p>
          ) : section.kind === "vendored" ? (
            <>
              <p>
                {m.findings.vendoredIntro}
                <code>git rm -r --cached &lt;directory&gt;</code>
                {m.findings.vendoredThen}
                <code>.gitignore</code>
                {m.findings.vendoredEnd}
              </p>
              <p>{m.findings.vendoredNote}</p>
            </>
          ) : (
            <p>
              {section.kind === "suppressed" ? m.findings.suppressedNote : m.findings.baselineNote}
            </p>
          );
        return section.kind === "suppressed" || section.kind === "baseline" ? (
          // Collapsed, never omitted: the count is in the title and on the overview, and a group
          // holding a critical finding is open.
          <details
            key={section.kind}
            className="finding-group collapsible-findings"
            open={section.visible.some((finding) => finding.severity === "critical")}
            aria-label={label}
          >
            <summary>{section.title}</summary>
            <div className="group-help">
              <HelpTip>{help}</HelpTip>
            </div>
            {groupTable(section, label)}
          </details>
        ) : (
          <section
            key={section.kind}
            className={`finding-group ${section.kind}-findings`}
            aria-label={label}
          >
            <div className="section-header level-3">
              <h3 className="section-title">{section.title}</h3>
              <HelpTip>{help}</HelpTip>
            </div>
            {groupTable(section, label)}
          </section>
        );
      })}
    </Section>
  );
}
