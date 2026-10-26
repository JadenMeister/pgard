/** Reads the hex digits of `<...>` groups as a code point string (UTF-16BE). */
function utf16Hex(hex: string): string {
  let out = "";
  for (let i = 0; i + 4 <= hex.length; i += 4)
    out += String.fromCharCode(parseInt(hex.slice(i, i + 4), 16));
  return out;
}

/** Parses a ToUnicode CMap into glyph id -> text. */
function parseToUnicode(cmap: string): Map<number, string> {
  const map = new Map<number, string>();
  for (const block of cmap.matchAll(/beginbfchar([\s\S]*?)endbfchar/g)) {
    for (const m of (block[1] ?? "").matchAll(/<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>/g)) {
      map.set(parseInt(m[1] ?? "", 16), utf16Hex(m[2] ?? ""));
    }
  }
  for (const block of cmap.matchAll(/beginbfrange([\s\S]*?)endbfrange/g)) {
    for (const m of (block[1] ?? "").matchAll(
      /<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*(?:<([0-9a-fA-F]+)>|\[([^\]]*)\])/g,
    )) {
      const from = parseInt(m[1] ?? "", 16);
      const to = parseInt(m[2] ?? "", 16);
      if (m[3] !== undefined) {
        const base = parseInt(m[3], 16);
        for (let g = from; g <= to; g++) map.set(g, String.fromCharCode(base + (g - from)));
      } else {
        const items = [...(m[4] ?? "").matchAll(/<([0-9a-fA-F]+)>/g)];
        items.forEach((item, index) => map.set(from + index, utf16Hex(item[1] ?? "")));
      }
    }
  }
  return map;
}

/**
 * Text of an uncompressed PDF that embeds fonts: glyph ids in `TJ`/`Tj` operations are mapped back
 * to characters through each font's ToUnicode CMap, so this proves what a viewer would extract.
 */
export function extractEmbeddedFontText(pdf: Buffer): string[] {
  const source = pdf.toString("latin1");
  const objects = new Map<number, string>();
  for (const m of source.matchAll(/(\d+) 0 obj([\s\S]*?)endobj/g)) {
    objects.set(Number(m[1]), m[2] ?? "");
  }
  const cmapOf = new Map<string, Map<number, string>>();
  for (const m of source.matchAll(/\/(F\d+) (\d+) 0 R/g)) {
    const font = objects.get(Number(m[2]));
    const toUnicode = font?.match(/\/ToUnicode (\d+) 0 R/);
    const stream = toUnicode ? objects.get(Number(toUnicode[1])) : undefined;
    if (stream !== undefined) cmapOf.set(m[1] ?? "", parseToUnicode(stream));
  }
  const lines: string[] = [];
  let current = "";
  for (const m of source.matchAll(
    /\/(F\d+) [\d.]+ Tf|\[((?:<[0-9a-fA-F]*>|[-\d.\s])*)\]\s*TJ|<([0-9a-fA-F]*)>\s*Tj/g,
  )) {
    if (m[1] !== undefined) {
      current = m[1];
      continue;
    }
    const map = cmapOf.get(current);
    const hexes = [...(m[2] ?? m[3] ?? "").matchAll(/<([0-9a-fA-F]*)>/g)];
    let text = m[3] !== undefined ? [m[3]] : hexes.map((h) => h[1] ?? "");
    text = text.length === 0 && m[3] !== undefined ? [m[3]] : text;
    if (map === undefined) throw new Error(`font ${current} has no ToUnicode CMap`);
    let line = "";
    for (const hex of text) {
      for (let i = 0; i + 4 <= hex.length; i += 4) {
        const glyph = parseInt(hex.slice(i, i + 4), 16);
        const char = map.get(glyph);
        if (char === undefined) throw new Error(`glyph ${glyph} of font ${current} is unmapped`);
        line += char;
      }
    }
    lines.push(line.trimEnd());
  }
  return lines;
}
