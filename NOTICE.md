# Third-party notices

PGARD is MIT (see LICENSE); the following third-party material is bundled.

## Reference data

PGARD bundles small reference datasets so rules can link to the security standards they map to. The
datasets are third-party material and are **not** covered by PGARD's MIT license; each is offered
under the terms below. Only identifiers, titles and links are stored. No descriptions, rule bodies,
code examples or other prose from these sources are copied. The data is static and is never fetched
at runtime.

The data lives in `packages/findings/src/standards/`. Each dataset exports a provenance record
(source URL, edition, retrieval date, license) next to the data.

### OWASP Top 10 2025

- Content: the 10 category ids (`A01:2025` to `A10:2025`), titles and page links.
- Source: https://top10.owasp.org/2025 (category pages under the same site), cross-checked against
  https://owasp.org/Top10/2025/0x00_2025-Introduction/ and the `OWASP/Top10` repository.
- Edition: 2025. Retrieved 2026-10-26.
- License: Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0),
  https://creativecommons.org/licenses/by-sa/4.0/ . This is what the document's own "Copyright and
  License" section (https://top10.owasp.org/2025/0x01_2025-About_OWASP/) and the repository LICENSE
  state. The site footer of the published pages shows CC BY 3.0 instead; PGARD follows the document
  and repository, which are the stricter terms. The bundled OWASP data is offered under CC BY-SA 4.0
  and is not covered by PGARD's MIT license. Anyone reusing it must keep the attribution and share
  it under the same license.
- Attribution: OWASP Top 10:2025, Copyright (c) 2003-2025 The OWASP Foundation, Inc. OWASP is a
  registered trademark of the OWASP Foundation, Inc. The titles are used verbatim (for example
  "Security Logging & Alerting Failures").

### CWE Top 25 2025

- Content: rank, CWE id, weakness name and link to the CWE definition.
- Source: https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html (latest edition at retrieval;
  the page was last updated 2025-12-15).
- Edition: 2025 CWE Top 25 Most Dangerous Software Weaknesses. Retrieved 2026-10-26.
- Terms: MITRE CWE Terms of Use, https://cwe.mitre.org/about/termsofuse.html . The license
  paragraph reads: "CWE is free to use by any organization or individual for any research,
  development, and/or commercial purposes, per these CWE Terms of Use. Accordingly, The MITRE
  Corporation hereby grants you a non-exclusive, royalty-free license to use CWE for research,
  development, and commercial purposes. Any copy you make for such purposes is authorized on the
  condition that you reproduce MITRE's copyright designation and this license in any such copy. CWE
  is a trademark of The MITRE Corporation." This data is not covered by PGARD's MIT license.
- Attribution: Copyright (c) 2006-2026, The MITRE Corporation. CWE is sponsored by DHS CISA.

### SEI CERT Oracle Java

SEI CERT Oracle Coding Standard for Java.

- Content: rule id, title, link path and the CWE ids that the "MITRE CWE" related-guidelines table
  lists for each rule (177 rules in the sections IDS to MSC; the Android DRD section is not
  included).
- Sources: https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/
  for rule ids and titles, and the "MITRE CWE" page under "Related Guidelines" of the same standard
  for the CWE ids. Both were read from the source repository
  https://github.com/cmu-sei/secure-coding-standards (commit 72e8a32, 2026-10-23).
- Retrieved 2026-10-26. `packages/findings/scripts/generate-cert-java.mjs` regenerates the data from
  that pinned commit, and a test pins the result with a hash.
- Caveat from the source: the CWE mapping table "was provided by outside contributors and has not
  been verified by SEI CERT". Treat it as a pointer, not as an assertion by SEI CERT.
- License: the SEI CERT Coding Standards are licensed under Creative Commons Attribution 4.0
  (CC BY 4.0), https://creativecommons.org/licenses/by/4.0/ . Their code examples are MIT-licensed;
  no code examples are included here. This data is not covered by PGARD's MIT license.
- Attribution: (c) 2026 Carnegie Mellon University. SEI CERT is a registered trademark of Carnegie
  Mellon University. This data is not endorsed by Carnegie Mellon University or the SEI. Titles are
  unmodified apart from removing a trailing period and Markdown escapes.
