import { useEffect, useRef, useState } from "react";
import type { Finding } from "@pgard/findings";
import type { RuleTextsResponse } from "../../../shared/api-types";
import { Badge, SeverityPill } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { useI18n } from "../../i18n/I18nProvider";
import { formatLocation } from "./filter-findings";
import { pageRequest, pageWindow, paginate, PAGE_SIZES } from "./pagination";
import { RuleDetailsBlock } from "./RuleDetailsBlock";

/**
 * One finding as a disclosure row: severity, title, status, location, rule id and a suppression
 * are always visible; evidence, impact, recommendation and the rule details open on demand
 * (Enter or Space on the summary). Everything stays in the markup, so find-in-page reaches the
 * text of the page shown.
 */
export function FindingItem({
  finding,
  ruleTexts,
  isNew = false,
  headingLevel = 3,
}: {
  finding: Finding;
  ruleTexts: RuleTextsResponse | null;
  isNew?: boolean;
  /** 3 for the regular list (under the card's h2), 4 inside a group with its own h3. */
  headingLevel?: 3 | 4;
}) {
  const { m } = useI18n();
  const statusLabels: Record<string, string> = m.status;
  const confidenceLabels: Record<string, string> = m.confidence;
  const location = formatLocation(finding.location, m);
  const Title = headingLevel === 3 ? "h3" : "h4";
  return (
    <li>
      <details className={`finding sev-${finding.severity}`}>
        <summary>
          <span className="finding-sev">
            <SeverityPill severity={finding.severity} />
          </span>
          <Title className="finding-title">{finding.title}</Title>
          <span className="finding-meta">
            {isNew && <Badge kind="new">{m.findings.newBadge}</Badge>}
            <Badge kind={finding.status}>{statusLabels[finding.status] ?? finding.status}</Badge>
            {finding.suppression !== undefined && (
              <Badge kind="suppressed">
                {m.findings.suppressedMarker(finding.suppression.expires ?? "")}
              </Badge>
            )}
            <code className="finding-location" title={location}>
              {location}
            </code>
            <code>{finding.ruleId}</code>
          </span>
        </summary>
        <div className="finding-body">
          <p className="finding-tags muted">
            {m.findings.confidence(confidenceLabels[finding.confidence] ?? finding.confidence)}
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
  headingLevel?: 3 | 4;
  page: number;
  pageSize: number;
  onPage: (page: number) => void;
  onPageSize: (pageSize: number) => void;
}

/**
 * A page of findings with the range shown ("Showing 26–50 of 213") and page controls. Only the
 * current page is rendered; filters, counts and report exports always cover every finding.
 *
 * The range line is not a live region (several lists and every filter keystroke would make it
 * chatty). Instead, a page change made with the page buttons moves focus to it, so
 * keyboard and screen-reader users hear the new range once and land at the top of the new page.
 * Filter and page-size changes never move focus.
 */
export function FindingList({
  label,
  findings,
  ruleTexts,
  isNew = false,
  headingLevel = 3,
  page,
  pageSize,
  onPage,
  onPageSize,
}: FindingListProps) {
  const { m } = useI18n();
  const text = m.findings.pager;
  const view = paginate(findings, page, pageSize);
  const statusRef = useRef<HTMLParagraphElement>(null);
  // Bumped only by the page controls; the effect focuses once per bump.
  const [focusRequest, setFocusRequest] = useState(0);

  useEffect(() => {
    if (focusRequest > 0) statusRef.current?.focus();
  }, [focusRequest]);

  const goTo = (next: number): void => {
    const target = pageRequest(view.page, next, view.pageCount);
    if (target === null) return;
    setFocusRequest((count) => count + 1);
    onPage(target);
  };

  const showControls = view.total > PAGE_SIZES[0];
  return (
    <>
      <p className="list-status" ref={statusRef} tabIndex={-1}>
        {text.showing(view.start, view.end, view.total)}
      </p>
      <ul className="findings" aria-label={label}>
        {view.items.map((finding) => (
          <FindingItem
            key={finding.id}
            finding={finding}
            ruleTexts={ruleTexts}
            isNew={isNew}
            headingLevel={headingLevel}
          />
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
            {/* Focus stays on the select: changing a value must not move the user elsewhere. */}
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
