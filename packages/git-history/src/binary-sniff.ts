/**
 * Telling binary data from text for staged files. A wrong "binary" hides a secret (the file is
 * skipped), a wrong "text" only costs a little scanning, so a file counts as binary only when
 * it is clearly so: a known file-format signature, or content that is mostly control bytes or
 * looks like compressed or random data at both ends. A few NUL bytes, or a lot of them in
 * UTF-16 text, are not enough. All functions take a body read as latin1 (one char per byte).
 */

/** Bytes at each end of a file that are looked at. */
export const BINARY_SNIFF_BYTES = 8000;

/** File-format signatures (start of the file). */
const SIGNATURES: readonly string[] = [
  "\x89PNG\r\n\x1a\n",
  "\xff\xd8\xff",
  "GIF87a",
  "GIF89a",
  "%PDF-",
  "PK\x03\x04",
  "PK\x05\x06",
  "\x1f\x8b",
  "\x7fELF",
  "\xfe\xed\xfa\xce",
  "\xfe\xed\xfa\xcf",
  "\xce\xfa\xed\xfe",
  "\xcf\xfa\xed\xfe",
  "\xca\xfe\xba\xbe",
  "\xfd7zXZ\x00",
  "7z\xbc\xaf\x27\x1c",
  "\x28\xb5\x2f\xfd",
  "wOFF\x00\x01\x00\x00",
  "wOFFOTTO",
  "wOF2\x00\x01\x00\x00",
  "wOF2OTTO",
  "OggS\x00",
  "OTTO\x00",
  "\x00\x01\x00\x00\x00",
  "\x00\x00\x01\x00",
  "SQLite format 3\x00",
  "\x00asm",
  // Apple: Finder metadata, binary property lists, asset catalogues, nibs.
  "\x00\x00\x00\x01Bud1",
  "bplist0",
  "BOMStore",
  "NIBArchive",
  // Images (TIFF).
  "II*\x00",
  "MM\x00*",
  // Audio: MP3 with an ID3 tag.
  "ID3\x02",
  "ID3\x03",
  "ID3\x04",
  // Data: NumPy, HDF5, RAR, Java keystore.
  "\x93NUMPY",
  "\x89HDF\r\n\x1a\n",
  "Rar!\x1a\x07",
  "\xfe\xed\xfe\xed",
];

const uint32be = (body: string, at: number): number =>
  ((body.charCodeAt(at) << 24) >>> 0) +
  (body.charCodeAt(at + 1) << 16) +
  (body.charCodeAt(at + 2) << 8) +
  body.charCodeAt(at + 3);
const uint32le = (body: string, at: number): number =>
  ((body.charCodeAt(at + 3) << 24) >>> 0) +
  (body.charCodeAt(at + 2) << 16) +
  (body.charCodeAt(at + 1) << 8) +
  body.charCodeAt(at);

/* MPEG audio bit rates (kbit/s) by bit rate index 1..14, and sample rates by index 0..2. */
const MPEG1_BITRATES: Record<number, readonly number[]> = {
  3: [32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448],
  2: [32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384],
  1: [32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320],
};
const MPEG2_BITRATES: Record<number, readonly number[]> = {
  3: [32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256],
  2: [8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
  1: [8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
};
const MPEG_SAMPLE_RATES: Record<number, readonly number[]> = {
  3: [44100, 48000, 32000],
  2: [22050, 24000, 16000],
  0: [11025, 12000, 8000],
};

/** The length of the MPEG audio frame whose header is at `at`, or `null` when it is not one. */
function mpegFrameLength(body: string, at: number): number | null {
  if (body.length < at + 4 || body.charCodeAt(at) !== 0xff) return null;
  const second = body.charCodeAt(at + 1);
  const third = body.charCodeAt(at + 2);
  // 0xfe is also the UTF-16 little-endian byte order mark: never read it as audio.
  if ((second & 0xe0) !== 0xe0 || second === 0xfe || second === 0xff) return null;
  const version = (second >> 3) & 3;
  const layer = (second >> 1) & 3;
  const bitrateIndex = third >> 4;
  const rateIndex = (third >> 2) & 3;
  if (version === 1 || layer === 0 || bitrateIndex === 0 || bitrateIndex === 15) return null;
  if (rateIndex === 3) return null;
  const bitrates = version === 3 ? MPEG1_BITRATES[layer] : MPEG2_BITRATES[layer];
  const kbps = bitrates?.[bitrateIndex - 1];
  const rate = MPEG_SAMPLE_RATES[version]?.[rateIndex];
  if (kbps === undefined || rate === undefined) return null;
  const padding = (third >> 1) & 1;
  if (layer === 3) return (Math.floor((12 * kbps * 1000) / rate) + padding) * 4;
  const factor = layer === 1 && version !== 3 ? 72 : 144;
  return Math.floor((factor * kbps * 1000) / rate) + padding;
}

/**
 * An MP3 without an ID3 tag: a valid frame header, and a second one with the same version and
 * layer exactly where the first frame ends (two bytes of text cannot fake that).
 */
function isMpegAudio(body: string): boolean {
  const length = mpegFrameLength(body, 0);
  if (length === null || mpegFrameLength(body, length) === null) return false;
  return (body.charCodeAt(1) & 0xfe) === (body.charCodeAt(length + 1) & 0xfe);
}

/**
 * Formats whose signature is short or could start a text file, so the signature alone is not
 * enough: each also needs its header to be consistent (a length field equal to the file size, a
 * known version, the expected next block). `size` is the whole file's size; `body` may be only
 * its start (a blob over the size limit), which holds every field checked here.
 */
function hasWeakSignature(body: string, size: number): boolean {
  // Apple icon: "icns" and the big-endian file length.
  if (body.startsWith("icns")) return body.length >= 8 && uint32be(body, 4) === size;
  // glTF binary: version 2 and the little-endian file length.
  if (body.startsWith("glTF")) {
    return body.length >= 12 && uint32le(body, 4) === 2 && uint32le(body, 8) === size;
  }
  // TrueType collection: version 1.0 or 2.0.
  if (body.startsWith("ttcf")) return /^\x00[\x01\x02]\x00\x00$/.test(body.slice(4, 8));
  // Photoshop: version 1 (PSD) or 2 (PSB), then six reserved zero bytes.
  if (body.startsWith("8BPS")) return /^\x00[\x01\x02]\x00{6}$/.test(body.slice(4, 12));
  // FLAC: the first metadata block is STREAMINFO (type 0), 34 bytes long.
  if (body.startsWith("fLaC")) {
    return (body.charCodeAt(4) & 0x7f) === 0 && body.slice(5, 8) === "\x00\x00\x22";
  }
  // ICC colour profile: the big-endian size field equals the file size, "acsp" at byte 36.
  if (body.length >= 128 && body.slice(36, 40) === "acsp") {
    return uint32be(body, 0) === size && size >= 128;
  }
  // Compiled Python 3.7 or later: magic (second byte 0x0d), "\r\n", a flags word of 0 to 3,
  // and the rest of the 16-byte header.
  if (body.charCodeAt(1) === 0x0d && body.slice(2, 4) === "\r\n") {
    return size >= 16 && body.length >= 16 && uint32le(body, 4) <= 3;
  }
  return isMpegAudio(body);
}

/**
 * True when the body starts with a known binary file format's signature. `size` is the whole
 * file's size when `body` is only its start (a blob over the size limit).
 */
export function hasBinarySignature(body: string, size: number = body.length): boolean {
  if (SIGNATURES.some((signature) => body.startsWith(signature))) return true;
  // RIFF....WEBP / WAVE / AVI, and ISO media (mp4, mov, heic): "ftyp" at byte 4.
  if (body.startsWith("RIFF") && /^(?:WEBP|WAVE|AVI )/.test(body.slice(8, 12))) return true;
  if (body.charCodeAt(0) === 0 && body.charCodeAt(1) === 0 && body.slice(4, 8) === "ftyp")
    return true;
  if (/^BZh[1-9]1AY&SY/.test(body.slice(0, 10))) return true;
  // AIFF audio (FORM....AIFF / AIFC).
  if (body.startsWith("FORM") && /^AIF[FC]$/.test(body.slice(8, 12))) return true;
  if (hasWeakSignature(body, size)) return true;
  // A DOS/Windows executable: "MZ" followed by the usual header, not just two letters.
  return body.startsWith("MZ") && body.length > 0x40 && body.includes("This program", 0x40);
}

/**
 * `le` or `be` when the sample is UTF-16 text without a byte order mark: ASCII-range text in
 * UTF-16 has a NUL in every second byte, and none in the others.
 */
export function utf16WithoutMark(sample: string): "le" | "be" | null {
  const length = sample.length - (sample.length % 2);
  if (length < 8) return null;
  let evenNul = 0;
  let oddNul = 0;
  for (let index = 0; index < length; index += 1) {
    if (sample.charCodeAt(index) !== 0) continue;
    if (index % 2 === 0) evenNul += 1;
    else oddNul += 1;
  }
  const pairs = length / 2;
  if (oddNul >= pairs * 0.3 && evenNul <= pairs * 0.05) return "le";
  if (evenNul >= pairs * 0.3 && oddNul <= pairs * 0.05) return "be";
  return null;
}

/** True when a sample of 512 bytes or more is as even as compressed or random data. */
export function isHighEntropy(sample: string): boolean {
  return sample.length >= 512 && entropy(sample) > 7.2;
}

function entropy(sample: string): number {
  const counts = new Array<number>(256).fill(0);
  for (let index = 0; index < sample.length; index += 1) {
    counts[sample.charCodeAt(index) & 0xff] = (counts[sample.charCodeAt(index) & 0xff] ?? 0) + 1;
  }
  let bits = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const share = count / sample.length;
    bits -= share * Math.log2(share);
  }
  return bits;
}

/**
 * True when a sample shows binary content: at least one byte in ten is a control byte (NUL
 * included) or, for 512 bytes or more, the bytes are as even as compressed or random data
 * (over 7.2 bits each). UTF-16 text is never binary here.
 */
export function looksBinaryContent(sample: string): boolean {
  if (sample.length === 0 || utf16WithoutMark(sample) !== null) return false;
  let control = 0;
  for (let index = 0; index < sample.length; index += 1) {
    const code = sample.charCodeAt(index);
    if ((code < 0x20 && code !== 9 && code !== 10 && code !== 13 && code !== 12) || code === 0x7f) {
      control += 1;
    }
  }
  if (control * 10 >= sample.length) return true;
  return isHighEntropy(sample);
}

/**
 * Git's own test for "binary" (a NUL in the first 8000 bytes), or compressed-looking content.
 * A format signature alone proves nothing: a text file can start with `%PDF-1.4`.
 */
export function isBinaryByGitsRule(head: string): boolean {
  return head.includes("\0") || isHighEntropy(head);
}

/**
 * True when a whole body is clearly binary: a known signature, or content that looks binary at
 * the start and at the end (so a binary header on a text file, or text after a few NULs, is
 * not enough).
 */
export function isClearlyBinary(body: string): boolean {
  return binaryKind(body) !== null;
}

/**
 * Why a body is clearly binary: `signature` (a known file format, skipped by design), `content`
 * (no signature, only the content heuristic: it may be text such as a coloured log, so a caller
 * reports it as not scanned), or `null` (text).
 */
export function binaryKind(body: string): "signature" | "content" | null {
  if (hasBinarySignature(body) && isBinaryByGitsRule(body.slice(0, BINARY_SNIFF_BYTES)))
    return "signature";
  return looksBinaryContent(body.slice(0, BINARY_SNIFF_BYTES)) &&
    looksBinaryContent(body.slice(-BINARY_SNIFF_BYTES))
    ? "content"
    : null;
}
