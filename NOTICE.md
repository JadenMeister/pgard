# Third-party reference data

PGARD bundles small reference datasets so rules can link to the security standards they map to. Only
identifiers, titles and links are stored. No descriptions, rule bodies, code examples or other
prose from these sources are copied. The data is static and is never fetched at runtime.

The data lives in `packages/findings/src/standards/`. Each dataset exports a provenance record
(source URL, edition, retrieval date, license) next to the data.

## OWASP Top 10:2025

- Content: the 10 category ids (`A01:2025` to `A10:2025`), titles and page links.
- Source: https://top10.owasp.org/2025 (category pages under the same site), cross-checked against
  https://owasp.org/Top10/2025/0x00_2025-Introduction/
- Edition: 2025. Retrieved 2026-10-26.
- License: Creative Commons Attribution 3.0 Unported (CC BY 3.0),
  https://creativecommons.org/licenses/by/3.0/
- Attribution: OWASP Top 10:2025, (c) OWASP Foundation, https://owasp.org/Top10/

## CWE Top 25 Most Dangerous Software Weaknesses

- Content: rank, CWE id, weakness name and link to the CWE definition.
- Source: https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html (latest edition at retrieval;
  the page was last updated 2025-12-15).
- Edition: 2025. Retrieved 2026-10-26.
- Terms: CWE is used under the MITRE CWE Terms of Use, https://cwe.mitre.org/about/termsofuse.html
- Attribution: (c) 2006-2026 The MITRE Corporation. CWE is a trademark of The MITRE Corporation.
  CWE is sponsored by DHS CISA.

## SEI CERT Oracle Coding Standard for Java

- Content: rule id, title, link path and the CWE ids that the "MITRE CWE" related-guidelines table
  lists for each rule (177 rules in the sections IDS to MSC; the Android DRD section is not
  included).
- Sources: https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/
  for rule ids and titles, and the "MITRE CWE" page under "Related Guidelines" of the same standard
  for the CWE ids. Both were read from the source repository
  https://github.com/cmu-sei/secure-coding-standards (commit 72e8a32, 2026-10-23).
- Retrieved 2026-10-26.
- Caveat from the source: the CWE mapping table "was provided by outside contributors and has not
  been verified by SEI CERT". Treat it as a pointer, not as an assertion by SEI CERT.
- License: the SEI CERT Coding Standards are licensed under Creative Commons Attribution 4.0
  (CC BY 4.0), https://creativecommons.org/licenses/by/4.0/ . Their code examples are MIT-licensed;
  no code examples are included here.
- Attribution: (c) 2026 Carnegie Mellon University. SEI CERT is a registered trademark of Carnegie
  Mellon University. This data is not endorsed by Carnegie Mellon University or the SEI. Titles are
  unmodified apart from removing a trailing period and Markdown escapes.
