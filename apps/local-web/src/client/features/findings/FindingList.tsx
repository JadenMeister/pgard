import { useEffect, useRef } from "react";
import type { Finding } from "@pgard/findings";
import type { RuleTextsResponse } from "../../../shared/api-types";
import { Badge, SeverityPill } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { useI18n } from "../../i18n/I18nProvider";
import { formatLocation } from "./filter-findings";
import { pageWindow, paginate, PAGE_SIZES } from "./pagination";
import { RuleDetailsBlock } from "./RuleDetailsBlock";

/**
 * One finding as a disclosure row: severity, title, location and rule id are always visible;
 * evidence, impact, recommendation and the rule details open on demand (Enter or Space on the
 * summary). Everything stays in the markup, so find-in-page reaches the text of the page shown.
 */
export function FindingItem({
  finding,
  ruleTexts,
  isNew = false,
}: {
  finding: Finding;
  ruleTexts: RuleTextsResponse | null;
  isNew?: boolean;
}) {
  const { m } = useI18n();
  const statusLabels: Record<string, string> = m.status;
  const confidenceLabels: Record<string, string> = m.confidence;
  const location = formatLocation(finding.location, m);
  return (
    <li>
      <details className={`finding sev-${finding.severity}`}>
        <summary>
          <span className="finding-sev">
            <SeverityPill severity={finding.severity} />
          </span>
          <h3 className="finding-title">{finding.title}</h3>
          <span className="finding-meta">
            {isNew && <Badge kind="new">{m.findings.newBadge}</Badge>}
            <code className="finding-location" title={location}>
              {location}
            </code>
            <code>{finding.ruleId}</code>
          </span>
        </summary>
        <div className="finding-body">
          <p className="finding-tags">
            <Badge kind={finding.status}>{statusLabels[finding.status] ?? finding.status}</Badge>
            <span className="muted">
              {m.findings.confidence(confidenceLabels[finding.confidence] ?? finding.confidence)}
            </span>
          </p>
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
          </dl>
          <RuleDetailsBlock finding={finding} ruleTexts={ruleTexts} />
        </div>
      </details>
    </li>
  );
}

interface FindingListProps {
  /** Accessible name of the list ("Findings", "Suppressed findings"). */
  label: string;
  findings: readonly Finding[];
  ruleTexts: RuleTextsResponse | null;
  isNew?: boolean;
  page: number;
  pageSize: number;
  onPage: (page: number) => void;
  onPageSize: (pageSize: number) => void;
}

/**
 * A page of findings with the range shown ("Showing 26–50 of 213") and page controls. Only the
 * current page is rendered; filters, counts and report exports always cover every finding. After
 * a page change, focus moves to the range line so keyboard and screen-reader users land at the
 * top of the new page.
 */
export function FindingList({
  label,
  findings,
  ruleTexts,
  isNew = false,
  page,
  pageSize,
  onPage,
  onPageSize,
}: FindingListProps) {
  const { m } = useI18n();
  const text = m.findings.pager;
  const view = paginate(findings, page, pageSize);
  const statusRef = useRef<HTMLParagraphElement>(null);
  const shouldFocus = useRef(false);

  useEffect(() => {
    if (!shouldFocus.current) return;
    shouldFocus.current = false;
    statusRef.current?.focus();
  }, [view.page]);

  const goTo = (next: number): void => {
    shouldFocus.current = true;
    onPage(next);
  };

  const showControls = view.total > PAGE_SIZES[0];
  return (
    <>
      <p className="list-status" ref={statusRef} tabIndex={-1} aria-live="polite">
        <span>{text.showing(view.start, view.end, view.total)}</span>
      </p>
      <ul className="findings" aria-label={label}>
        {view.items.map((finding) => (
          <FindingItem key={finding.id} finding={finding} ruleTexts={ruleTexts} isNew={isNew} />
        ))}
      </ul>
      {showControls && (
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
            <select value={pageSize} onChange={(event) => onPageSize(Number(event.target.value))}>
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
