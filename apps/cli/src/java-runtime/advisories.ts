/**
 * Known-vulnerable Java runtime versions that `pgard doctor` compares the local JDK against. The
 * table ships with the package, so it is only as fresh as the installed PGARD version: the list
 * date is shown with every answer. A version that is not in it is NOT thereby judged unaffected.
 */

/** The highest affected version of one feature release; older versions of it are affected too. */
export interface JavaAffectedRelease {
  /** Feature release: 8, 11, 17, 21, 25, 27. */
  feature: number;
  /** `8u511`, `11.0.33`, `17.0.21`: the same spelling the vendor notice uses. */
  highest: string;
}

export interface JavaAdvisory {
  cve: string;
  severity: "critical" | "high" | "medium" | "low";
  summary: string;
  affected: readonly JavaAffectedRelease[];
  /** Products the vendor notice names (the check compares versions only, not vendors). */
  products: string;
  /** Primary sources, https only. The advisory does not name fixed versions, so none are listed. */
  sources: readonly string[];
  /** ISO date (YYYY-MM-DD) of the vendor's alert. */
  alertDate: string;
  /** ISO date (YYYY-MM-DD) PGARD added or last reviewed the entry. */
  listDate: string;
}

export const JAVA_ADVISORIES: readonly JavaAdvisory[] = [
  {
    cve: "CVE-2026-91403",
    severity: "critical",
    summary: "JSSE, CVSS 9.1",
    affected: [
      { feature: 8, highest: "8u511" },
      { feature: 11, highest: "11.0.33" },
      { feature: 17, highest: "17.0.21" },
      { feature: 21, highest: "21.0.13" },
      { feature: 25, highest: "25.0.5" },
      { feature: 27, highest: "27.0.1" },
    ],
    products:
      "Oracle Java SE 8u511, 8u511-perf, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1; Oracle GraalVM for JDK 17.0.21, 21.0.13; Oracle GraalVM Enterprise Edition 21.3.20 (its own version scheme: this check reads the JDK version and does not match it)",
    sources: [
      "https://www.oracle.com/security-alerts/alert-cve-2026-91403.html",
      "https://github.com/advisories/GHSA-9h75-rf66-wh3r",
    ],
    alertDate: "2026-10-21",
    listDate: "2026-11-18",
  },
];

/** The newest list date in the table: how fresh the shipped list is. */
export function latestListDate(table: readonly JavaAdvisory[] = JAVA_ADVISORIES): string {
  return table.reduce((latest, entry) => (entry.listDate > latest ? entry.listDate : latest), "");
}
