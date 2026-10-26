import type { Coverage } from "@pgard/findings";
import { useI18n } from "../../i18n/I18nProvider";

/** What ran and what did not. "No findings" is never shown as "safe". */
export function CoverageTable({ coverage }: { coverage: readonly Coverage[] }) {
  const { m } = useI18n();
  const labels: Record<string, string> = m.status;
  return (
    <table className="table coverage">
      <caption>{m.coverage.caption}</caption>
      <thead>
        <tr>
          <th>{m.coverage.area}</th>
          <th>{m.coverage.status}</th>
          <th>{m.coverage.note}</th>
        </tr>
      </thead>
      <tbody>
        {coverage.map((entry) => (
          <tr key={entry.area}>
            <td data-label={m.coverage.area}>
              <code>{entry.area}</code>
            </td>
            <td data-label={m.coverage.status}>
              <span className={`badge badge-${entry.status}`}>
                {labels[entry.status] ?? m.status.unknownStatus}
              </span>
            </td>
            <td data-label={m.coverage.note}>{entry.note ?? ""}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
