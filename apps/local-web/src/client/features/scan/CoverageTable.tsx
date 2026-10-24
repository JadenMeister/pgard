import type { Coverage } from "@pgard/findings";

const COVERAGE_LABELS: Record<string, string> = {
  completed: "Completed",
  partial: "Partial",
  not_tested: "Not tested",
  not_selected: "Not selected",
};

/** What ran and what did not. "No findings" is never shown as "safe". */
export function CoverageTable({ coverage }: { coverage: readonly Coverage[] }) {
  return (
    <table className="table coverage">
      <caption>Coverage</caption>
      <thead>
        <tr>
          <th>Area</th>
          <th>Status</th>
          <th>Note</th>
        </tr>
      </thead>
      <tbody>
        {coverage.map((entry) => (
          <tr key={entry.area}>
            <td>
              <code>{entry.area}</code>
            </td>
            <td>
              <span className={`badge badge-${entry.status}`}>
                {COVERAGE_LABELS[entry.status] ?? "Unknown"}
              </span>
            </td>
            <td>{entry.note ?? ""}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
