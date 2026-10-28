import type { RuleStat, ScanResult } from "@pgard/findings";
import type { RuleTextsResponse } from "../../../shared/api-types";
import { Badge } from "../../components/ui/Badge";
import { Section } from "../../components/ui/Section";
import { useI18n } from "../../i18n/I18nProvider";

/** Rules sorted by id and area, so the table reads the same on every scan. */
export function sortRuleStats(stats: readonly RuleStat[]): RuleStat[] {
  return [...stats].sort(
    (a, b) => a.ruleId.localeCompare(b.ruleId) || a.area.localeCompare(b.area),
  );
}

/**
 * What each rule examined, per area: targets examined, findings and the area's status. Not
 * shown for results written before schema 1.1 (the standards panel explains that).
 */
export function RuleStatsPanel({
  result,
  ruleTexts,
}: {
  result: ScanResult;
  ruleTexts: RuleTextsResponse | null;
}) {
  const { m, language } = useI18n();
  const text = m.ruleStats;
  const statusLabels: Record<string, string> = m.status;
  if (result.ruleStats === undefined) return null;
  return (
    <Section title={text.summary(result.ruleStats.length)} help={<p>{text.note}</p>}>
      <table className="table rule-stats-table">
        <thead>
          <tr>
            <th>{text.columns.rule}</th>
            <th>{text.columns.area}</th>
            <th>{text.columns.targets}</th>
            <th>{text.columns.findings}</th>
            <th>{text.columns.status}</th>
          </tr>
        </thead>
        <tbody>
          {sortRuleStats(result.ruleStats).map((stat) => {
            const entry =
              ruleTexts !== null && Object.hasOwn(ruleTexts, stat.ruleId)
                ? ruleTexts[stat.ruleId]
                : undefined;
            return (
              <tr key={`${stat.ruleId}:${stat.area}`}>
                <td data-label={text.columns.rule}>
                  <code>{stat.ruleId}</code>
                  {entry === undefined ? null : (
                    <span className="muted small"> {entry.title[language]}</span>
                  )}
                </td>
                <td data-label={text.columns.area}>
                  <code>{stat.area}</code>
                </td>
                <td data-label={text.columns.targets}>
                  {stat.targets
                    .map((target) =>
                      target.examined === null
                        ? text.targetUnknown(target.reason ?? m.common.unknown)
                        : text.targetCount(target.examined, target.unit),
                    )
                    .join(", ")}
                </td>
                <td data-label={text.columns.findings} className="num">
                  {stat.findings}
                </td>
                <td data-label={text.columns.status}>
                  <Badge kind={stat.status}>
                    {statusLabels[stat.status] ?? m.status.unknownStatus}
                  </Badge>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </Section>
  );
}
