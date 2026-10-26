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

export interface OwaspCategory {
  /** For example `A05:2025`. */
  id: string;
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
