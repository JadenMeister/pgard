import { useMemo, useReducer } from "react";
import {
  configTestFindingCount,
  type FindingCategory,
  type FindingStatus,
  type ScanResult,
  type ScanScope,
} from "@pgard/findings";
import { SeverityBar } from "../../components/charts/SeverityBar";
import { EmptyState } from "../../components/ui/EmptyState";
import { HelpTip } from "../../components/ui/HelpTip";
import { Notice } from "../../components/ui/Notice";
import { Section } from "../../components/ui/Section";
import type { RuleTextsResponse } from "../../../shared/api-types";
import { localizeFindingText } from "./rule-texts";
import { useI18n } from "../../i18n/I18nProvider";
import type { SetFilters } from "../../app/use-filter-state";
import {
  buildAreaRules,
  buildFindingsView,
  EMPTY_FILTERS,
  toggleFilter,
  type ContextSection,
  type FindingFilters,
} from "./filter-findings";
import { FilterBar } from "./FilterBar";
import { buildLinkedCounts } from "./linked-panels";
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
  linkedFilters,
}: {
  /**
   * Filters kept outside the view (in the address, shared with the overview). Without them the
   * view keeps its own, starting from `initialState`.
   */
  linkedFilters?: {
    filters: FindingFilters;
    onChange: SetFilters;
    onClear: () => void;
  };
  result: ScanResult;
  /** Rule texts from `GET /api/rule-texts`; without them findings show their stored English text. */
  ruleTexts?: RuleTextsResponse | null;
  /** Starting filters and pages (tests); the view always starts at page 1 with no filter. */
  initialState?: FindingsListState;
}) {
  const { m, language } = useI18n();
  const [state, dispatch] = useReducer(findingsListReducer, initialState);
  const { pageSize } = state;
  const filters = linkedFilters?.filters ?? state.filters;
  const setFilter = (patch: Partial<FindingFilters>): void => {
    // A filter change always sends every list back to page 1 (an empty patch just does that).
    if (linkedFilters === undefined) return dispatch({ type: "filter", patch });
    dispatch({ type: "filter", patch: {} });
    // Typing replaces the history entry; a click on a value adds one.
    linkedFilters.onChange(patch, { replace: "text" in patch });
  };
  const clearFilters = (): void => {
    if (linkedFilters === undefined) return dispatch({ type: "filter", patch: EMPTY_FILTERS });
    dispatch({ type: "filter", patch: {} });
    linkedFilters.onClear();
  };
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
  const areaRules = useMemo(
    () => buildAreaRules(result.coverage, result.ruleStats),
    [result.coverage, result.ruleStats],
  );
  const view = useMemo(
    () => buildFindingsView(findings, filters, m, areaRules),
    [findings, filters, m, areaRules],
  );
  const counts = useMemo(
    () => buildLinkedCounts(findings, filters, areaRules).severity,
    [findings, filters, areaRules],
  );
  const toggle = (patch: Partial<FindingFilters>): void => setFilter(toggleFilter(filters, patch));
  const linked = { filters, toggle };
  const configTestCount = configTestFindingCount(result.coverage);
  // Categories present in this result, plus the selected one so the select always shows it.
  const categoryOptions = useMemo(() => {
    const present = new Set(findings.map((finding) => finding.category));
    if (filters.category !== null) present.add(filters.category);
    return [...present].sort((a, b) => m.categories[a].localeCompare(m.categories[b]));
  }, [findings, filters.category, m]);

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
        linked={linked}
        paging={paging(section.kind)}
      />
    );

  return (
    <Section
      title={m.nav.findings}
      meta={<span className="num">{view.total}</span>}
      help={<p>{m.findings.noDatabase}</p>}
    >
      <SeverityBar
        counts={counts}
        selected={filters.severity}
        onSelect={(severity) => setFilter({ severity })}
      />
      <FilterBar
        filters={filters}
        shown={view.visible.length}
        total={view.total}
        onRemove={setFilter}
        onClear={clearFilters}
      />
      <div className="toolbar">
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
          <label>
            <span className="sr-only">{m.table.category}</span>
            <select
              value={filters.category ?? ""}
              onChange={(event) =>
                setFilter({ category: (event.target.value || null) as FindingCategory | null })
              }
            >
              <option value="">
                {m.table.category}: {m.common.all}
              </option>
              {categoryOptions.map((category) => (
                <option key={category} value={category}>
                  {m.categories[category]}
                </option>
              ))}
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
          linked={linked}
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
