/** Where a bundled dataset came from. Retrieved once by hand; never fetched at runtime. */
export interface StandardProvenance {
  name: string;
  /** Edition or version of the source list. */
  edition: string;
  sourceUrl: string;
  /** ISO date (YYYY-MM-DD) the data was retrieved from the source. */
  retrievedAt: string;
  /** Short license or terms statement; the full text is in NOTICE.md. */
  license: string;
  attribution: string;
}

/** The ten OWASP Top 10 2025 ids. A typo in a rule's standards fails at compile time. */
export const OWASP_IDS = [
  "A01:2025",
  "A02:2025",
  "A03:2025",
  "A04:2025",
  "A05:2025",
  "A06:2025",
  "A07:2025",
  "A08:2025",
  "A09:2025",
  "A10:2025",
] as const;
export type OwaspId = (typeof OWASP_IDS)[number];

export interface OwaspCategory {
  id: OwaspId;
  title: string;
  url: string;
}

export interface CweTop25Entry {
  rank: number;
  /** For example `CWE-79`. */
  id: string;
  name: string;
  url: string;
}

export interface CertJavaRule {
  /** For example `IDS00-J`. */
  id: string;
  title: string;
  /** Path below the CERT Java rules index, used to build the link. */
  path: string;
  /** CWE ids that the CERT "MITRE CWE" related-guidelines table lists for this rule. */
  cwe: readonly string[];
}
