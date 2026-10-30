import { describe, expect, it } from "vitest";
import { binaryKind, hasBinarySignature } from "./binary-sniff.js";

/** A header followed by binary-looking filler (NULs and uneven bytes), read as latin1. */
function file(header: string | number[], size = 2048): string {
  const head = typeof header === "string" ? header : String.fromCharCode(...header);
  const filler = Array.from({ length: size }, (_, index) =>
    String.fromCharCode(index % 5 === 0 ? 0 : (index * 37 + 11) % 256),
  ).join("");
  return head + filler;
}

/** An ICC profile: a 128-byte header with "acsp" at byte 36. */
function iccHeader(): string {
  const bytes = new Array<number>(128).fill(0);
  bytes[3] = 0x80;
  "appl".split("").forEach((char, index) => (bytes[4 + index] = char.charCodeAt(0)));
  "mntrRGB XYZ ".split("").forEach((char, index) => (bytes[12 + index] = char.charCodeAt(0)));
  "acsp".split("").forEach((char, index) => (bytes[36 + index] = char.charCodeAt(0)));
  return String.fromCharCode(...bytes);
}

const FORMATS: ReadonlyArray<readonly [string, string]> = [
  ["icns (Apple icon)", "icns\x00\x01\x2f\x10ic12\x00\x00\x0b\x6c"],
  [".DS_Store", "\x00\x00\x00\x01Bud1\x00\x00\x10\x00\x00\x00\x08\x00"],
  ["binary plist / .loctable", "bplist00\xd4\x01\x02\x03\x04\x05\x06\x07\x0a"],
  [".car asset catalogue", "BOMStore\x00\x00\x00\x01\x00\x00\x00\x2a"],
  [".nib archive", "NIBArchive\x01\x00\x00\x00\x09\x00\x00\x00"],
  ["TrueType collection (.ttc)", "ttcf\x00\x02\x00\x00\x00\x00\x00\x0c"],
  ["TIFF little-endian", "II*\x00\x08\x00\x00\x00\x0e\x00"],
  ["TIFF big-endian", "MM\x00*\x00\x00\x00\x08\x00\x0e"],
  ["Photoshop (.psd)", "8BPS\x00\x01\x00\x00\x00\x00\x00\x00\x00\x03"],
  ["glTF binary (.glb)", "glTF\x02\x00\x00\x00\x9c\x05\x00\x00"],
  ["MP3 with ID3v2.3", "ID3\x03\x00\x00\x00\x00\x1f\x76"],
  ["MP3 with ID3v2.4", "ID3\x04\x00\x00\x00\x00\x00\x23"],
  ["MP3 frame (MPEG-1 layer III)", "\xff\xfb\x90\x64\x00\x00\x00\x00"],
  ["MP3 frame (MPEG-2 layer III)", "\xff\xf3\x48\xc4\x00\x00\x00\x00"],
  ["FLAC", "fLaC\x00\x00\x00\x22\x10\x00\x10\x00"],
  ["AIFF", "FORM\x00\x01\x2a\x3cAIFFCOMM\x00\x00\x00\x12"],
  ["AIFF-C", "FORM\x00\x01\x2a\x3cAIFCFVER\x00\x00\x00\x04"],
  ["NumPy (.npy)", "\x93NUMPY\x01\x00v\x00{'descr': '<f8', 'fortran_order': False, }"],
  ["HDF5", "\x89HDF\r\n\x1a\n\x00\x00\x00\x00\x00\x08\x08\x00"],
  ["RAR 4", "Rar!\x1a\x07\x00\xcf\x90\x73\x00\x00"],
  ["RAR 5", "Rar!\x1a\x07\x01\x00\x33\x92\xb5\xe5"],
  ["Java keystore (JKS)", "\xfe\xed\xfe\xed\x00\x00\x00\x02\x00\x00\x00\x01"],
  ["Python 3.12 bytecode (.pyc)", "\xcb\x0d\r\n\x00\x00\x00\x00\x8a\x3c\x1e\x67"],
  ["Python 2.7 bytecode (.pyc)", "\x03\xf3\r\n\x8a\x3c\x1e\x67c\x00\x00\x00"],
  ["ICC colour profile", iccHeader()],
];

describe("binaryKind: known file formats are skipped by design", () => {
  it.each(FORMATS)("%s has a known signature", (_name, header) => {
    const body = file(header);
    expect(hasBinarySignature(body)).toBe(true);
    expect(binaryKind(body)).toBe("signature");
  });

  it("keeps a known signature with no NUL or compressed content as text (a text file can start with it)", () => {
    expect(binaryKind(`ID3\x03 tag notes\n${"plain text line\n".repeat(50)}`)).toBeNull();
    expect(binaryKind(`FORMAIFF and more\n${"plain text line\n".repeat(50)}`)).toBeNull();
  });

  it("never reads UTF-16 text with a byte order mark as MP3 audio", () => {
    const text = `\xff\xfe${"token = value\n"
      .split("")
      .map((char) => `${char}\x00`)
      .join("")
      .repeat(40)}`;
    expect(hasBinarySignature(text)).toBe(false);
    expect(binaryKind(text)).toBeNull();
  });

  it("does not take two letters and a line break for Python bytecode", () => {
    expect(hasBinarySignature("ab\r\nplain text\r\n")).toBe(false);
  });

  it("still calls signature-less binary-looking content `content`", () => {
    expect(binaryKind(file("\x01\x02\x03\x04"))).toBe("content");
  });
});
