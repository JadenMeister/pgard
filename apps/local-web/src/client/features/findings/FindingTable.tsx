import { useEffect, useId, useRef, useState, type MouseEvent } from "react";
import type { Finding } from "@pgard/findings";
import type { RuleTextsResponse } from "../../../shared/api-types";
import { SeverityLabel } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { useI18n } from "../../i18n/I18nProvider";
import { formatLocation } from "./filter-findings";
import { pageRequest, pageWindow, paginate, PAGE_SIZES } from "./pagination";
import { RuleDetailsBlock } from "./RuleDetailsBlock";

const COLUMNS = 6;

/** The expanded part of a row: evidence, impact, fix, suppression reason and rule details. */
function FindingDetail({
  finding,
  ruleTexts,
}: {
  finding: Finding;
  ruleTexts: RuleTextsResponse | null;
}) {
  const { m } = useI18n();
  const confidenceLabels: Record<string, string> = m.confidence;
  return (
    <div className="finding-body">
      {finding.suppression !== undefined && (
        <p className="suppression-reason">
          {m.findings.suppressedReason(
            finding.suppression.reason,
            finding.suppression.expires ?? "",
          )}
        </p>
      )}
      <dl>
        <dt>{m.findings.evidence}</dt>
        <dd>
          <pre>{finding.evidence}</pre>
        </dd>
        <dt>{m.findings.impact}</dt>
        <dd>{finding.impact}</dd>
        <dt>{m.findings.recommendation}</dt>
        <dd>{finding.recommendation}</dd>
        <dt>{m.findings.confidenceLabel}</dt>
        <dd>{confidenceLabels[finding.confidence] ?? finding.confidence}</dd>
      </dl>
      <RuleDetailsBlock finding={finding} ruleTexts={ruleTexts} />
    </div>
  );
}

/**
 * One finding as a table row (severity, title, status, location, rule) and a detail row under
 * it. The title is a button with `aria-expanded`; a click anywhere on the row toggles too. The
 * detail stays in the markup (hidden) so its text is part of the page once opened.
 */
function FindingRow({
  finding,
  ruleTexts,
  isNew,
  isOpen,
  onToggle,
  idPrefix,
}: {
  finding: Finding;
  ruleTexts: RuleTextsResponse | null;
  isNew: boolean;
  isOpen: boolean;
  onToggle: () => void;
  idPrefix: string;
}) {
  const { m } = useI18n();
  const statusLabels: Record<string, string> = m.findings.statusOptions;
  const location = formatLocation(finding.location, m);
  const detailId = `${idPrefix}-${finding.id}`;
  const onRowClick = (event: MouseEvent<HTMLTableRowElement>): void => {
    // Links inside the row keep their own behaviour.
    if ((event.target as Element).closest("a") !== null) return;
    onToggle();
  };
  return (
    <>
      <tr
        className={`finding-row sev-${finding.severity}${isOpen ? " is-open" : ""}`}
        onClick={onRowClick}
      >
        <td className="col-sev">
          <SeverityLabel severity={finding.severity} />
        </td>
        <td className="col-title">
          <button
            type="button"
            className="row-toggle"
            aria-expanded={isOpen}
            aria-controls={detailId}
          >
            {finding.title}
          </button>
          {isNew && <span className="badge-new">{m.findings.newBadge}</span>}
          {finding.suppression !== undefined && (
            <span className="row-note">
              {m.findings.suppressedMarker(finding.suppression.expires ?? "")}
            </span>
          )}
        </td>
        <td className="col-status">{statusLabels[finding.status] ?? finding.status}</td>
        <td className="col-loc">
          <code title={location}>{location}</code>
        </td>
        <td className="col-rule">
          <code>{finding.ruleId}</code>
        </td>
        <td className="col-chevron" aria-hidden="true">
          <span className="chevron" />
        </td>
      </tr>
      <tr className="finding-detail" id={detailId} hidden={!isOpen}>
        <td colSpan={COLUMNS}>
          <FindingDetail finding={finding} ruleTexts={ruleTexts} />
        </td>
      </tr>
    </>
  );
}

interface FindingTableProps {
  /** Accessible name of the table ("Findings", "Suppressed findings"). */
  label: string;
  findings: readonly Finding[];
  ruleTexts: RuleTextsResponse | null;
  isNew?: boolean;
  /** Paging; without it every finding given is shown (the overview's top five). */
  paging?: {
    page: number;
    pageSize: number;
    onPage: (page: number) => void;
    onPageSize: (pageSize: number) => void;
  };
}

/**
 * A dense findings table with sticky column headers and, when paged, the range shown ("Showing
 * 26–50 of 213") and page controls. Only the current page is rendered; filters, counts and
 * report exports always cover every finding.
 *
 * The range line is not a live region (several tables and every filter keystroke would make it
 * chatty). A page change made with the page buttons moves focus to it instead, so keyboard and
 * screen-reader users hear the new range once and land at the top of the new page. Filter and
 * page-size changes never move focus.
 */
export function FindingTable({
  label,
  findings,
  ruleTexts,
  isNew = false,
  paging,
}: FindingTableProps) {
  const { m } = useI18n();
  const text = m.findings.pager;
  const idPrefix = useId();
  const view = paging
    ? paginate(findings, paging.page, paging.pageSize)
    : paginate(findings, 1, Math.max(1, findings.length));
  const [open, setOpen] = useState<ReadonlySet<string>>(() => new Set());
  const statusRef = useRef<HTMLParagraphElement>(null);
  // Bumped only by the page buttons; the effect focuses once per bump.
  const [focusRequest, setFocusRequest] = useState(0);

  useEffect(() => {
    if (focusRequest > 0) statusRef.current?.focus();
  }, [focusRequest]);

  const toggle = (id: string): void =>
    setOpen((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const goTo = (next: number): void => {
    const target = pageRequest(view.page, next, view.pageCount);
    if (target === null || paging === undefined) return;
    setFocusRequest((count) => count + 1);
    paging.onPage(target);
  };

  const showControls = paging !== undefined && view.total > PAGE_SIZES[0];
  return (
    <>
      {paging && (
        <p className="list-status" ref={statusRef} tabIndex={-1}>
          {text.showing(view.start, view.end, view.total)}
        </p>
      )}
      <table className="findings-table" aria-label={label}>
        <thead>
          <tr>
            <th scope="col" className="col-sev">
              {m.table.severity}
            </th>
            <th scope="col" className="col-title">
              {m.table.finding}
            </th>
            <th scope="col" className="col-status">
              {m.table.status}
            </th>
            <th scope="col" className="col-loc">
              {m.table.location}
            </th>
            <th scope="col" className="col-rule">
              {m.table.rule}
            </th>
            <th scope="col" className="col-chevron">
              <span className="sr-only">{m.table.details}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {view.items.map((finding) => (
            <FindingRow
              key={finding.id}
              finding={finding}
              ruleTexts={ruleTexts}
              isNew={isNew}
              isOpen={open.has(finding.id)}
              onToggle={() => toggle(finding.id)}
              idPrefix={idPrefix}
            />
          ))}
        </tbody>
      </table>
      {showControls && paging && (
        <div className="pager">
          <nav aria-label={text.label(label)}>
            <ul className="pager-pages">
              <li>
                <Button size="sm" disabled={view.page <= 1} onClick={() => goTo(view.page - 1)}>
                  {text.previous}
                </Button>
              </li>
              {pageWindow(view.page, view.pageCount).map((entry, index) =>
                entry === null ? (
                  <li key={`gap-${index}`} className="pager-gap" aria-hidden="true">
                    …
                  </li>
                ) : (
                  <li key={entry}>
                    <Button
                      size="sm"
                      variant="ghost"
                      aria-label={text.page(entry)}
                      aria-current={entry === view.page ? "page" : undefined}
                      onClick={() => goTo(entry)}
                    >
                      {entry}
                    </Button>
                  </li>
                ),
              )}
              <li>
                <Button
                  size="sm"
                  disabled={view.page >= view.pageCount}
                  onClick={() => goTo(view.page + 1)}
                >
                  {text.next}
                </Button>
              </li>
            </ul>
          </nav>
          <label className="pager-size">
            {text.pageSize}
            {/* Focus stays on the select: changing a value must not move the user elsewhere. */}
            <select
              value={paging.pageSize}
              onChange={(event) => paging.onPageSize(Number(event.target.value))}
            >
              {PAGE_SIZES.map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </label>
        </div>
      )}
    </>
  );
}
