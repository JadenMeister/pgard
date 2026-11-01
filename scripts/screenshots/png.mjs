// Tiny PNG optimizer, no dependencies: decodes the RGBA PNG that Chrome writes, reduces it to at
// most 256 colours (median cut) and writes an indexed PNG. Screens of a dark terminal or a flat
// web page have few colours, so the result is much smaller and looks the same.
import { deflateSync, inflateSync } from "node:zlib";

const SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function crcTable() {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
}
const CRC = crcTable();
function crc32(buffer) {
  let c = 0xffffffff;
  for (const byte of buffer) c = CRC[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const body = Buffer.concat([Buffer.from(type, "latin1"), data]);
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  body.copy(out, 4);
  out.writeUInt32BE(crc32(body), 4 + body.length);
  return out;
}

/** Decodes an 8-bit, non-interlaced RGB or RGBA PNG to { width, height, rgba }. */
export function decodePng(buffer) {
  if (!buffer.subarray(0, 8).equals(SIGNATURE)) throw new Error("not a PNG");
  let offset = 8;
  let header;
  const parts = [];
  while (offset < buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.toString("latin1", offset + 4, offset + 8);
    const data = buffer.subarray(offset + 8, offset + 8 + length);
    if (type === "IHDR") header = data;
    else if (type === "IDAT") parts.push(data);
    offset += 12 + length;
  }
  const width = header.readUInt32BE(0);
  const height = header.readUInt32BE(4);
  const depth = header[8];
  const colorType = header[9];
  if (depth !== 8 || header[12] !== 0 || (colorType !== 6 && colorType !== 2)) {
    throw new Error(`unsupported PNG (depth ${depth}, type ${colorType})`);
  }
  const bpp = colorType === 6 ? 4 : 3;
  const stride = width * bpp;
  const raw = inflateSync(Buffer.concat(parts));
  const pixels = Buffer.alloc(height * stride);
  for (let y = 0; y < height; y += 1) {
    const filter = raw[y * (stride + 1)];
    const src = y * (stride + 1) + 1;
    const dst = y * stride;
    for (let x = 0; x < stride; x += 1) {
      const a = x >= bpp ? pixels[dst + x - bpp] : 0;
      const b = y > 0 ? pixels[dst - stride + x] : 0;
      const c = x >= bpp && y > 0 ? pixels[dst - stride + x - bpp] : 0;
      let value = raw[src + x];
      if (filter === 1) value += a;
      else if (filter === 2) value += b;
      else if (filter === 3) value += (a + b) >> 1;
      else if (filter === 4) {
        const p = a + b - c;
        const pa = Math.abs(p - a);
        const pb = Math.abs(p - b);
        const pc = Math.abs(p - c);
        value += pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
      }
      pixels[dst + x] = value & 0xff;
    }
  }
  const rgba = Buffer.alloc(width * height * 4);
  for (let i = 0; i < width * height; i += 1) {
    rgba[i * 4] = pixels[i * bpp];
    rgba[i * 4 + 1] = pixels[i * bpp + 1];
    rgba[i * 4 + 2] = pixels[i * bpp + 2];
    rgba[i * 4 + 3] = bpp === 4 ? pixels[i * bpp + 3] : 255;
  }
  return { width, height, rgba };
}

/** Median cut over the distinct colours (weighted by use). Returns the palette as [r, g, b][]. */
function buildPalette(rgba, maxColors) {
  const counts = new Map();
  for (let i = 0; i < rgba.length; i += 4) {
    const key = (rgba[i] << 16) | (rgba[i + 1] << 8) | rgba[i + 2];
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const colors = [...counts].map(([key, n]) => ({
    r: key >> 16,
    g: (key >> 8) & 255,
    b: key & 255,
    n,
  }));
  if (colors.length <= maxColors) return colors.map((c) => [c.r, c.g, c.b]);
  const boxes = [colors];
  while (boxes.length < maxColors) {
    let best = -1;
    let bestRange = 0;
    let bestChannel = "r";
    boxes.forEach((box, index) => {
      if (box.length < 2) return;
      for (const channel of ["r", "g", "b"]) {
        let lo = 255;
        let hi = 0;
        for (const c of box) {
          lo = Math.min(lo, c[channel]);
          hi = Math.max(hi, c[channel]);
        }
        if (hi - lo > bestRange) {
          bestRange = hi - lo;
          best = index;
          bestChannel = channel;
        }
      }
    });
    if (best < 0) break;
    const box = boxes[best].sort((x, y) => x[bestChannel] - y[bestChannel]);
    const total = box.reduce((sum, c) => sum + c.n, 0);
    let seen = 0;
    let split = 1;
    for (let i = 0; i < box.length - 1; i += 1) {
      seen += box[i].n;
      split = i + 1;
      if (seen >= total / 2) break;
    }
    boxes.splice(best, 1, box.slice(0, split), box.slice(split));
  }
  return boxes.map((box) => {
    const total = box.reduce((sum, c) => sum + c.n, 0);
    return [
      Math.round(box.reduce((s, c) => s + c.r * c.n, 0) / total),
      Math.round(box.reduce((s, c) => s + c.g * c.n, 0) / total),
      Math.round(box.reduce((s, c) => s + c.b * c.n, 0) / total),
    ];
  });
}

/** Re-encodes a PNG as an indexed PNG with at most `maxColors` colours. */
export function optimizePng(buffer, maxColors = 256) {
  const { width, height, rgba } = decodePng(buffer);
  const palette = buildPalette(rgba, maxColors);
  const cache = new Map();
  const indexOf = (r, g, b) => {
    const key = (r << 16) | (g << 8) | b;
    let found = cache.get(key);
    if (found === undefined) {
      let bestDistance = Infinity;
      found = 0;
      palette.forEach(([pr, pg, pb], index) => {
        const d = (pr - r) ** 2 + (pg - g) ** 2 + (pb - b) ** 2;
        if (d < bestDistance) {
          bestDistance = d;
          found = index;
        }
      });
      cache.set(key, found);
    }
    return found;
  };
  const rows = Buffer.alloc((width + 1) * height);
  for (let y = 0; y < height; y += 1) {
    const row = y * (width + 1);
    rows[row] = 0;
    for (let x = 0; x < width; x += 1) {
      const p = (y * width + x) * 4;
      rows[row + 1 + x] = indexOf(rgba[p], rgba[p + 1], rgba[p + 2]);
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 3;
  return Buffer.concat([
    SIGNATURE,
    chunk("IHDR", ihdr),
    chunk("PLTE", Buffer.from(palette.flat())),
    chunk("IDAT", deflateSync(rows, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}
