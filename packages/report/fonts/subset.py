# Regenerates PgardNotoSansKR-{Regular,Bold}.ttf from the upstream variable font.
#
# Source: https://github.com/google/fonts, ofl/notosanskr/NotoSansKR[wght].ttf at commit
#   b38c5c93af322c45f633e17ac440ec1e6c94d489
#   SHA-256 194018e6b2b293a7964f037b25c0249ce1418bc9ab3c971060a03aa57861e252 (10414588 bytes)
# License: SIL Open Font License 1.1 (see OFL.txt next to this file).
#
# Usage (needs `pip install fonttools`):
#   python3 -I subset.py <dir containing the upstream file saved as full.ttf>
# Output files are written to that same directory. The glyph ranges below must match
# SUPPORTED_RANGES in src/pdf-font.ts, and the SHA-256 values there must be updated.
import sys
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer
from fontTools import subset

d = sys.argv[1]
U = [
    *range(0x20, 0x7F),
    *range(0xA0, 0x100),
    *range(0x2010, 0x2028),
    *range(0x2030, 0x203B),
    0x20AC,
    *range(0x2190, 0x2194),
    0x2022,
    *range(0x3000, 0x3040),
    *range(0x3131, 0x318F),
    *range(0xAC00, 0xD7A4),
    *range(0xFF01, 0xFF5F),
]
for w, nm in ((400, "Regular"), (700, "Bold")):
    f = TTFont(d + "/full.ttf")
    f = instancer.instantiateVariableFont(f, {"wght": w})
    opts = subset.Options()
    opts.layout_features = []
    opts.hinting = False
    opts.notdef_outline = True
    opts.name_IDs = ["*"]
    s = subset.Subsetter(opts)
    s.populate(unicodes=U)
    s.subset(f)
    # The instancer keeps the variable font's default (Thin) names; name the instance properly.
    names = f["name"]
    for rec in list(names.names):
        if rec.nameID in (16, 17, 21, 22, 25):
            names.names.remove(rec)
    for name_id, value in (
        (1, "Noto Sans KR"),
        (2, nm),
        (4, "Noto Sans KR " + nm),
        (6, "NotoSansKR-" + nm),
    ):
        names.setName(value, name_id, 3, 1, 0x409)
        names.setName(value, name_id, 1, 0, 0)
    f.save(d + "/PgardNotoSansKR-" + nm + ".ttf")
