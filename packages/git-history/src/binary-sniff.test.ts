import { describe, expect, it } from "vitest";
import { binaryKind, hasBinarySignature } from "./binary-sniff.js";

const FILLER_BYTES = 2048;

/** Binary-looking filler (NULs and uneven bytes), read as latin1. */
function filler(length = FILLER_BYTES): string {
  return Array.from({ length }, (_, index) =>
    String.fromCharCode(index % 5 === 0 ? 0 : (index * 37 + 11) % 256),
  ).join("");
}

/** A header followed by filler. */
function file(header: string): string {
  return header + filler();
}

const be32 = (value: number): string =>
  String.fromCharCode(
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  );
const le32 = (value: number): string =>
  String.fromCharCode(
    value & 0xff,
    (value >>> 8) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 24) & 0xff,
  );

/** The size of `file(header)` for a header of `headerLength` bytes. */
const sizeWith = (headerLength: number): number => headerLength + FILLER_BYTES;

/** An Apple icon whose length field is `length` (the real file size unless given). */
function icns(length?: number): string {
  return `icns${be32(length ?? sizeWith(8))}`;
}

/** A glTF binary header: version, then the length field. */
function gltf(version = 2, length?: number): string {
  return `glTF${le32(version)}${le32(length ?? sizeWith(12))}`;
}

/** An ICC profile: a 128-byte header with the size field and "acsp" at byte 36. */
function icc(size?: number): string {
  const bytes = new Array<number>(128).fill(0);
  const write = (at: number, text: string): void =>
    text.split("").forEach((char, index) => (bytes[at + index] = char.charCodeAt(0)));
  write(0, be32(size ?? sizeWith(128)));
  write(4, "appl");
  write(12, "mntrRGB XYZ ");
  write(36, "acsp");
  return String.fromCharCode(...bytes);
}

/** Two MPEG-1 layer III frames (128 kbit/s, 44.1 kHz: 417 bytes each), or one and noise. */
function mp3(secondFrame = true): string {
  const header = "\xff\xfb\x90\x64";
  const frame = header + filler(417 - 4);
  return frame + (secondFrame ? header : "\x01\x02\x03\x04") + filler(400);
}

/** Two MPEG-2 layer III frames (32 kbit/s, 16 kHz: 144 bytes each). */
function mp3v2(): string {
  const header = "\xff\xf3\x48\xc4";
  return header + filler(144 - 4) + header + filler(400);
}

const FORMATS: ReadonlyArray<readonly [string, string]> = [
  ["icns (Apple icon)", file(icns())],
  [".DS_Store", file("\x00\x00\x00\x01Bud1\x00\x00\x10\x00\x00\x00\x08\x00")],
  ["binary plist / .loctable", file("bplist00\xd4\x01\x02\x03\x04\x05\x06\x07\x0a")],
  [".car asset catalogue", file("BOMStore\x00\x00\x00\x01\x00\x00\x00\x2a")],
  [".nib archive", file("NIBArchive\x01\x00\x00\x00\x09\x00\x00\x00")],
  ["TrueType collection 1.0", file("ttcf\x00\x01\x00\x00\x00\x00\x00\x0c")],
  ["TrueType collection 2.0", file("ttcf\x00\x02\x00\x00\x00\x00\x00\x0c")],
  ["TIFF little-endian", file("II*\x00\x08\x00\x00\x00\x0e\x00")],
  ["TIFF big-endian", file("MM\x00*\x00\x00\x00\x08\x00\x0e")],
  ["Photoshop (.psd)", file("8BPS\x00\x01\x00\x00\x00\x00\x00\x00\x00\x03")],
  ["Photoshop large (.psb)", file("8BPS\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03")],
  ["glTF binary (.glb)", file(gltf())],
  ["MP3 with ID3v2.3", file("ID3\x03\x00\x00\x00\x00\x1f\x76")],
  ["MP3 with ID3v2.4", file("ID3\x04\x00\x00\x00\x00\x00\x23")],
  ["MP3 frames (MPEG-1 layer III)", mp3()],
  ["MP3 frames (MPEG-2 layer III)", mp3v2()],
  ["FLAC", file("fLaC\x00\x00\x00\x22\x10\x00\x10\x00")],
  ["FLAC (last metadata block)", file("fLaC\x80\x00\x00\x22\x10\x00\x10\x00")],
  ["AIFF", file("FORM\x00\x01\x2a\x3cAIFFCOMM\x00\x00\x00\x12")],
  ["AIFF-C", file("FORM\x00\x01\x2a\x3cAIFCFVER\x00\x00\x00\x04")],
  ["NumPy (.npy)", file("\x93NUMPY\x01\x00v\x00{'descr': '<f8', 'fortran_order': False, }")],
  ["HDF5", file("\x89HDF\r\n\x1a\n\x00\x00\x00\x00\x00\x08\x08\x00")],
  ["RAR 4", file("Rar!\x1a\x07\x00\xcf\x90\x73\x00\x00")],
  ["RAR 5", file("Rar!\x1a\x07\x01\x00\x33\x92\xb5\xe5")],
  ["Java keystore (JKS)", file("\xfe\xed\xfe\xed\x00\x00\x00\x02\x00\x00\x00\x01")],
  [
    "Python 3.12 bytecode (.pyc)",
    file("\xcb\x0d\r\n\x00\x00\x00\x00\x8a\x3c\x1e\x67\x10\x00\x00\x00"),
  ],
  [
    "Python bytecode with hash flags",
    file("\xcb\x0d\r\n\x03\x00\x00\x00\x8a\x3c\x1e\x67\x10\x00\x00\x00"),
  ],
  ["ICC colour profile", file(icc())],
];

describe("binaryKind: known file formats are skipped by design", () => {
  it.each(FORMATS)("%s has a known signature", (_name, body) => {
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

  it("still calls signature-less binary-looking content `content`", () => {
    expect(binaryKind(file("\x01\x02\x03\x04"))).toBe("content");
  });

  it("checks a too-large blob's length fields against its real size, not the sampled start", () => {
    const body = file(icns(1_000_000));
    expect(hasBinarySignature(body.slice(0, 800))).toBe(false);
    expect(hasBinarySignature(body.slice(0, 800), 1_000_000)).toBe(true);
  });
});

describe("weak signatures need a consistent header, so text with a NUL is still read", () => {
  const TOKEN = `${"ghp_"}${"a".repeat(36)}`;
  const TEXT = "line of a log\n".repeat(30);

  it("does not take `a\\r\\r\\n` + text + NUL + token for compiled Python (the review repro)", () => {
    const body = `a\r\r\n${TEXT}\0 token=${TOKEN}\n`;
    expect(hasBinarySignature(body)).toBe(false);
    expect(binaryKind(body)).toBeNull();
  });

  const NEGATIVES: ReadonlyArray<readonly [string, string]> = [
    [".pyc: no flags word of 0 to 3", file("\xcb\x0d\r\nflag\x8a\x3c\x1e\x67\x10\x00\x00\x00")],
    [".pyc: shorter than the 16-byte header", "\xcb\x0d\r\n\x00\x00\x00\x00\x8a"],
    ["MPEG: no second frame header where the first frame ends", mp3(false)],
    ["MPEG: a free-format bit rate", file("\xff\xfb\x00\x64")],
    ["icns: a length that is not the file size", file(icns(12))],
    ["glTF: version 1", file(gltf(1))],
    ["glTF: a length that is not the file size", file(gltf(2, 99))],
    ["ttcf: version 3.0", file("ttcf\x00\x03\x00\x00\x00\x00\x00\x0c")],
    ["ttcf: followed by text", file("ttcf is a font collection\n")],
    ["8BPS: version 3", file("8BPS\x00\x03\x00\x00\x00\x00\x00\x00\x00\x03")],
    ["8BPS: no reserved zero bytes", file("8BPS\x00\x01 notes about PSD")],
    ["fLaC: the first block is not STREAMINFO", file("fLaC\x04\x00\x00\x22\x10\x00\x10\x00")],
    ["fLaC: a STREAMINFO length other than 34", file("fLaC\x00\x00\x01\x00\x10\x00\x10\x00")],
    ["ICC: a size field that is not the file size", file(icc(512))],
  ];

  it.each(NEGATIVES)("%s", (_name, body) => {
    expect(hasBinarySignature(body)).toBe(false);
    expect(binaryKind(body)).not.toBe("signature");
  });
});
