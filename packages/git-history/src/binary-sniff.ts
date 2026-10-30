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
  // Apple: icons, Finder metadata, binary property lists, asset catalogues, nibs.
  "icns",
  "\x00\x00\x00\x01Bud1",
  "bplist0",
  "BOMStore",
  "NIBArchive",
  // Fonts (TrueType collection), images (TIFF, Photoshop), 3D (glTF binary).
  "ttcf",
  "II*\x00",
  "MM\x00*",
  "8BPS",
  "glTF",
  // Audio: MP3 with an ID3 tag, FLAC.
  "ID3\x02",
  "ID3\x03",
  "ID3\x04",
  "fLaC",
  // Data: NumPy, HDF5, RAR, Java keystore.
  "\x93NUMPY",
  "\x89HDF\r\n\x1a\n",
  "Rar!\x1a\x07",
  "\xfe\xed\xfe\xed",
];

/** An MPEG audio frame header (an MP3 without an ID3 tag): 11 sync bits and valid fields. */
function isMpegFrame(body: string): boolean {
  if (body.charCodeAt(0) !== 0xff || body.length < 3) return false;
  const second = body.charCodeAt(1);
  const third = body.charCodeAt(2);
  // 0xfe is also the UTF-16 little-endian byte order mark: never read it as audio.
  if ((second & 0xe0) !== 0xe0 || second === 0xfe || second === 0xff) return false;
  const version = (second >> 3) & 3;
  const layer = (second >> 1) & 3;
  return version !== 1 && layer !== 0 && third >> 4 !== 0xf && ((third >> 2) & 3) !== 3;
}

/**
 * Compiled Python (`.pyc`): a two-byte magic number followed by `\r\n`. Python 3 numbers are
 * 0x0d00 to 0x0dff (little-endian, so the second byte is 0x0d); Python 2.7 is 0xf303.
 */
function isPythonBytecode(body: string): boolean {
  if (body.slice(2, 4) !== "\r\n") return false;
  const first = body.charCodeAt(0);
  const second = body.charCodeAt(1);
  return second === 0x0d || (first === 0x03 && second === 0xf3);
}

/** True when the body starts with a known binary file format's signature. */
export function hasBinarySignature(body: string): boolean {
  if (SIGNATURES.some((signature) => body.startsWith(signature))) return true;
  // RIFF....WEBP / WAVE / AVI, and ISO media (mp4, mov, heic): "ftyp" at byte 4.
  if (body.startsWith("RIFF") && /^(?:WEBP|WAVE|AVI )/.test(body.slice(8, 12))) return true;
  if (body.charCodeAt(0) === 0 && body.charCodeAt(1) === 0 && body.slice(4, 8) === "ftyp")
    return true;
  if (/^BZh[1-9]1AY&SY/.test(body.slice(0, 10))) return true;
  // AIFF audio (FORM....AIFF / AIFC), ICC colour profiles ("acsp" at byte 36).
  if (body.startsWith("FORM") && /^AIF[FC]$/.test(body.slice(8, 12))) return true;
  if (body.length >= 128 && body.slice(36, 40) === "acsp") return true;
  if (isMpegFrame(body) || isPythonBytecode(body)) return true;
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
