import { isJvmSourcePath, standardsForPath, type Finding } from "@pgard/findings";
import type { RuleTextsResponse } from "../../../shared/api-types";
import { useI18n } from "../../i18n/I18nProvider";
import { ExternalLink } from "../standards/ExternalLink";

/**
 * What a finding's rule adds beyond the finding text: the standards it maps to (official links),
 * the rule-level rationale and fix when the finding carries its own different text, and the
 * vulnerable and safe examples in a collapsed section. Everything is rendered as React text, so
 * example code can never become markup.
 */
export function RuleDetailsBlock({
  finding,
  ruleTexts,
}: {
  finding: Finding;
  ruleTexts: RuleTextsResponse | null;
}) {
  const { m, language } = useI18n();
  const entry =
    ruleTexts !== null && Object.hasOwn(ruleTexts, finding.ruleId)
      ? ruleTexts[finding.ruleId]
      : undefined;
  const details = entry?.details;
  if (details === undefined) return null;
  // The finding's Impact and Recommendation already are the rule's texts unless the finding
  // carries its own; show the general text only when it adds something.
  const rationale = details.rationale[language];
  const remediation = details.remediation[language];
  const showRationale = rationale !== finding.impact;
  const showRemediation = remediation !== finding.recommendation;
  // A direct CERT Java link is only valid for a finding in a Java or Kotlin file.
  const standards = standardsForPath(
    details.standards,
    finding.location.path,
    finding.references.cert,
  );
  const noDirectCert =
    details.noDirectCert !== undefined && isJvmSourcePath(finding.location.path)
      ? details.noDirectCert[language]
      : undefined;
  return (
    <div className="rule-details">
      {(showRationale || showRemediation) && (
        <dl className="rule-guidance">
          {showRationale && (
            <>
              <dt>{m.details.ruleRationale}</dt>
              <dd>{rationale}</dd>
            </>
          )}
          {showRemediation && (
            <>
              <dt>{m.details.ruleRemediation}</dt>
              <dd>{remediation}</dd>
            </>
          )}
        </dl>
      )}
      {(standards.length > 0 || noDirectCert !== undefined) && (
        <div className="finding-standards">
          <strong>{m.details.standards}</strong>
          <ul>
            {standards.map((link) => (
              <li key={`${link.kind}:${link.id}`}>
                <ExternalLink url={link.url} hint={m.details.opensExternally}>
                  {link.id}
                </ExternalLink>
                {link.title === null ? "" : ` ${link.title}`}
                {link.viaCwe !== undefined
                  ? ` (${m.details.viaCwe(link.viaCwe)})`
                  : link.direct === true
                    ? ` (${m.details.certDirect})`
                    : ""}
              </li>
            ))}
            {noDirectCert !== undefined && (
              <li>
                {m.details.certNone}: {noDirectCert}
              </li>
            )}
          </ul>
        </div>
      )}
      {details.examples.length > 0 && (
        <details className="rule-examples">
          <summary>{m.details.examples(details.examples.length)}</summary>
          {details.examples.map((example, index) => (
            <div key={index}>
              <p>
                <strong>{m.details.vulnerable}</strong>{" "}
                <span className="muted small">{example.language}</span>
              </p>
              <pre className="code">
                <code>{example.vulnerable}</code>
              </pre>
              <p>
                <strong>{m.details.safe}</strong>
              </p>
              <pre className="code">
                <code>{example.safe}</code>
              </pre>
              {example.note !== undefined && (
                <p className="muted small">{example.note[language]}</p>
              )}
            </div>
          ))}
        </details>
      )}
    </div>
  );
}
