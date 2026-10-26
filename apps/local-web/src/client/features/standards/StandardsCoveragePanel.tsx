import {
  countStandardStates,
  cweUrl,
  getOwaspCategory,
  type ScanResult,
  type StandardCoverageEntry,
} from "@pgard/findings";
import { Card, Notice } from "../../components/ui/Card";
import { useI18n } from "../../i18n/I18nProvider";
import { ExternalLink } from "./ExternalLink";

const MAX_LISTED_RULES = 4;

function listedRules(entry: StandardCoverageEntry): string {
  const rest = entry.ruleIds.length - MAX_LISTED_RULES;
  return `${entry.ruleIds.slice(0, MAX_LISTED_RULES).join(", ")}${rest > 0 ? ` +${rest}` : ""}`;
}

function StateBadge({ state }: { state: StandardCoverageEntry["state"] }) {
  const { m } = useI18n();
  // Neutral styling for every state: a rule that ran is not a pass, so nothing is shown in green.
  return (
    <span className={`badge standard-state state-${state}`}>{m.standardsPanel.states[state]}</span>
  );
}

/**
 * The standards coverage map: for each OWASP Top 10 2025 category whether PGARD rules that map to
 * it ran, how many of its mapped CWEs have a rule at all (breadth) and why, then counts for the
 * CWE Top 25 and a full list in a collapsed section. Ids, titles and official links only.
 */
export function StandardsCoveragePanel({ result }: { result: ScanResult }) {
  const { m } = useI18n();
  const text = m.standardsPanel;
  const standards = result.standardsCoverage;
  if (standards === undefined) {
    return (
      <Card title={m.cards.standards}>
        <Notice tone="info">{text.notRecorded}</Notice>
      </Card>
    );
  }
  const counts = countStandardStates(standards.cweTop25);
  return (
    <Card title={m.cards.standards}>
      <p className="muted small standards-note">{text.note}</p>
      <table className="table standards-map">
        <thead>
          <tr>
            <th>{text.columns.id}</th>
            <th>{text.columns.category}</th>
            <th>{text.columns.state}</th>
            <th>{text.columns.breadth}</th>
            <th>{text.columns.rules}</th>
            <th>{text.columns.reason}</th>
          </tr>
        </thead>
        <tbody>
          {standards.owasp.map((entry) => (
            <tr key={entry.id}>
              <td data-label={text.columns.id}>
                <ExternalLink
                  url={getOwaspCategory(entry.id)?.url ?? ""}
                  hint={m.details.opensExternally}
                >
                  {entry.id.replace(":2025", "")}
                </ExternalLink>
              </td>
              <td data-label={text.columns.category}>{entry.title}</td>
              <td data-label={text.columns.state}>
                <StateBadge state={entry.state} />
              </td>
              <td data-label={text.columns.breadth}>
                {entry.breadth === null
                  ? ""
                  : text.breadth(entry.breadth.cwesWithRules, entry.breadth.cwesInCategory)}
              </td>
              <td data-label={text.columns.rules}>{listedRules(entry)}</td>
              <td data-label={text.columns.reason}>{entry.reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <details className="standards-cwe">
        <summary>
          {text.cweTop25Title}:{" "}
          {text.cweTop25Counts(
            counts.rules_ran,
            counts.rules_partial,
            counts.not_run,
            counts.no_rules,
          )}
        </summary>
        <table className="table standards-map">
          <thead>
            <tr>
              <th>{text.cweColumns.rank}</th>
              <th>{text.cweColumns.id}</th>
              <th>{text.cweColumns.name}</th>
              <th>{text.columns.state}</th>
              <th>{text.columns.rules}</th>
              <th>{text.columns.reason}</th>
            </tr>
          </thead>
          <tbody>
            {standards.cweTop25.map((entry) => (
              <tr key={entry.id}>
                <td data-label={text.cweColumns.rank}>{entry.rank ?? ""}</td>
                <td data-label={text.cweColumns.id}>
                  <ExternalLink url={cweUrl(entry.id)} hint={m.details.opensExternally}>
                    {entry.id}
                  </ExternalLink>
                </td>
                <td data-label={text.cweColumns.name}>{entry.title}</td>
                <td data-label={text.columns.state}>
                  <StateBadge state={entry.state} />
                </td>
                <td data-label={text.columns.rules}>{listedRules(entry)}</td>
                <td data-label={text.columns.reason}>{entry.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
      <div className="muted small standards-attribution">
        <strong>{text.attributionTitle}</strong>
        <p>{text.attributionIntro}</p>
        <ul>
          <li>{text.attributionOwasp}</li>
          <li>{text.attributionCwe}</li>
          <li>{text.attributionCert}</li>
        </ul>
      </div>
    </Card>
  );
}
