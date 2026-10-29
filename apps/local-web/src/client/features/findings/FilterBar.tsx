import { Button } from "../../components/ui/Button";
import { useI18n } from "../../i18n/I18nProvider";
import type { Messages } from "../../i18n/types";
import type { FindingFilters } from "./filter-findings";

export interface FilterChip {
  key: keyof FindingFilters;
  /** "Severity: high": what the chip shows and the remove button is named after. */
  label: string;
}

/** The active filters in a fixed order, each with its readable "Field: value" label. */
export function activeFilterChips(filters: FindingFilters, m: Messages): FilterChip[] {
  const fields: Record<string, string> = m.linked.fields;
  const statuses: Record<string, string> = m.findings.statusOptions;
  const sources: Record<string, string> = m.findings.sources;
  const categories: Record<string, string> = m.categories;
  const severities: Record<string, string> = m.severityInline;
  const chip = (key: keyof FindingFilters, value: string): FilterChip => ({
    key,
    label: m.linked.chip(fields[key] ?? key, value),
  });
  const chips: FilterChip[] = [];
  if (filters.severity !== null)
    chips.push(chip("severity", severities[filters.severity] ?? filters.severity));
  if (filters.category !== null)
    chips.push(chip("category", categories[filters.category] ?? filters.category));
  if (filters.area !== null) chips.push(chip("area", filters.area));
  if (filters.rule !== null) chips.push(chip("rule", filters.rule));
  if (filters.path !== null) chips.push(chip("path", filters.path));
  if (filters.status !== null)
    chips.push(chip("status", statuses[filters.status] ?? filters.status));
  if (filters.source !== null)
    chips.push(chip("source", sources[filters.source] ?? filters.source));
  if (filters.text.trim() !== "") chips.push(chip("text", filters.text.trim()));
  return chips;
}

const CLEARED: Record<keyof FindingFilters, FindingFilters[keyof FindingFilters]> = {
  severity: null,
  status: null,
  source: null,
  category: null,
  rule: null,
  area: null,
  path: null,
  text: "",
};

/**
 * The one filter bar: every active filter as a removable chip and a "Clear all" button. It sits
 * above the overview panels and above the findings table, and shows nothing without a filter
 * (the hint takes its place on the overview). The count of matching findings is a polite status
 * message, so a screen-reader user hears what a click did without focus moving.
 */
export function FilterBar({
  filters,
  shown,
  total,
  onRemove,
  onClear,
  showHint = false,
}: {
  filters: FindingFilters;
  /** Regular findings that match the filters, and all of them. */
  shown: number;
  total: number;
  onRemove: (patch: Partial<FindingFilters>) => void;
  onClear: () => void;
  /** Show the "select a value to filter" hint while no filter is active. */
  showHint?: boolean;
}) {
  const { m } = useI18n();
  const chips = activeFilterChips(filters, m);
  return (
    <div className="filter-bar" role="group" aria-label={m.linked.barLabel}>
      {chips.length === 0 ? (
        showHint && <p className="filter-hint">{m.linked.hint}</p>
      ) : (
        <div className="filter-bar-row">
          <ul className="filter-chips">
            {chips.map((chip) => (
              <li key={chip.key}>
                <button
                  type="button"
                  className="filter-chip"
                  aria-label={m.linked.remove(chip.label)}
                  onClick={() => onRemove({ [chip.key]: CLEARED[chip.key] })}
                >
                  <span className="filter-chip-text">{chip.label}</span>
                  <span className="filter-chip-x" aria-hidden="true">
                    ×
                  </span>
                </button>
              </li>
            ))}
          </ul>
          <Button size="sm" variant="ghost" aria-label={m.linked.clearAllLabel} onClick={onClear}>
            {m.linked.clearAll}
          </Button>
          <p className="filter-count">{m.linked.matching(shown, total)}</p>
        </div>
      )}
      <p className="sr-only" role="status">
        {chips.length === 0 ? "" : m.linked.matching(shown, total)}
      </p>
    </div>
  );
}
