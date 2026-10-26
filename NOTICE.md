# Third-party notices

PGARD is MIT (see [LICENSE](LICENSE)); the following third-party material is bundled.

## Fonts

### Noto Sans KR

The PDF reports embed this font. It is distributed in `packages/report/fonts/` and is never downloaded at runtime.

- Files: `packages/report/fonts/PgardNotoSansKR-Regular.ttf`, `packages/report/fonts/PgardNotoSansKR-Bold.ttf`
- Copyright: 2014-2021 Adobe (http://www.adobe.com/), with Reserved Font Name 'Source'
- License: SIL Open Font License, Version 1.1 (full text in `packages/report/fonts/OFL.txt`)
- Source: https://github.com/google/fonts, `ofl/notosanskr/NotoSansKR[wght].ttf` at commit `b38c5c93af322c45f633e17ac440ec1e6c94d489` (SHA-256 `194018e6b2b293a7964f037b25c0249ce1418bc9ab3c971060a03aa57861e252`)
- Changes: the variable font was instantiated at weights 400 (Regular) and 700 (Bold) and subset to Basic Latin, Latin-1, common punctuation, CJK symbols and punctuation, Hangul compatibility Jamo and Hangul syllables, and fullwidth ASCII. Hinting was removed and layout features removed (the GSUB, GPOS and BASE tables remain with 0 features). The reproducible recipe is `packages/report/fonts/subset.py` (fontTools 4.67.0). The files are renamed (`PgardNotoSansKR-*`), and the font itself does not use the Reserved Font Name.
- SHA-256 (Regular): `e1a4564bbbb0676ea20c72ba7cc130917096c5f43655ca99f06c99efcec2fdfb`
- SHA-256 (Bold): `ff1968fc53fb9abf71041d8c9a9783518de3f85ef2e49ca713ca9a03770aa894`

## Parser runtime and grammars

The Java, Kotlin, Python and PHP analyzers parse with tree-sitter compiled to WebAssembly. The grammars
are vendored unchanged in `packages/source-analysis/grammars/` (sources, versions and SHA-256 in its
`README.md`, checked by a test); no native code is installed. All of the following are MIT-licensed, and
the license texts are kept next to the grammars as `LICENSE.*`.

- web-tree-sitter 0.27.1 (npm dependency): Copyright (c) 2018 Max Brunsfeld. https://github.com/tree-sitter/tree-sitter
- tree-sitter-java grammar 0.23.5 (`tree-sitter-java.wasm`): Copyright (c) 2017 Ayman Nadeem. https://github.com/tree-sitter/tree-sitter-java
- tree-sitter-python grammar 0.25.0 (`tree-sitter-python.wasm`): Copyright (c) 2016 Max Brunsfeld. https://github.com/tree-sitter/tree-sitter-python
- tree-sitter-php grammar 0.24.2 (`tree-sitter-php.wasm`): Copyright (c) 2017 Josh Vera, GitHub. https://github.com/tree-sitter/tree-sitter-php
- The Java, Python and PHP `.wasm` files were built by Microsoft's `@vscode/tree-sitter-wasm` 0.3.1 (MIT, Copyright (c) Microsoft Corporation; `LICENSE.vscode-tree-sitter-wasm`), https://github.com/microsoft/vscode-tree-sitter-wasm . The package itself is not a dependency.
- tree-sitter-kotlin grammar 1.1.0 (`tree-sitter-kotlin.wasm`, from `@tree-sitter-grammars/tree-sitter-kotlin`): Copyright (c) 2024 Amaan Qureshi. https://github.com/tree-sitter-grammars/tree-sitter-kotlin

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

### OWASP Top 10 2025 mapped CWEs and CWE mapping notes

Used by the rule mapping policy ([docs/RULE_MAPPING.md](docs/RULE_MAPPING.md)).

- Content: for each OWASP Top 10:2025 category, the CWE ids in the "List of Mapped CWEs" section of
  its page (ids only, no names or descriptions); and, for the CWEs that PGARD rules reference, the
  abstraction level and Vulnerability Mapping usage label shown on the CWE page (CWE 4.20).
- Sources: the category pages under https://top10.owasp.org/2025/ and the CWE definitions under
  https://cwe.mitre.org/data/definitions/ . `packages/findings/scripts/generate-owasp-mapped-cwes.mjs`
  regenerates the lists.
- Retrieved 2026-10-26.
- Terms: the OWASP lists are offered under CC BY-SA 4.0 (see "OWASP Top 10 2025" above); the CWE
  labels fall under the MITRE CWE Terms of Use (see "CWE Top 25 2025" above). This data is not
  covered by PGARD's MIT license.
- Attribution: OWASP Top 10:2025, Copyright (c) 2003-2025 The OWASP Foundation, Inc.; Copyright (c)
  2006-2026, The MITRE Corporation. CWE is sponsored by DHS CISA.
