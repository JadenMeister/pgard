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
