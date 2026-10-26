import { open, type FileHandle } from "node:fs/promises";
import { crc32, inflateRawSync } from "node:zlib";

/** A zip read never extracts to disk, so entry names are only labels; still, keep them plain. */
const ENTRY_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*\.json$/;

export interface ZipLimits {
  maxEntries: number;
  /** Largest single entry once inflated. */
  maxEntryBytes: number;
  /** Sum of all inflated entries (zip-bomb guard). */
  maxTotalBytes: number;
  maxCentralDirectoryBytes: number;
}

export const DEFAULT_ZIP_LIMITS: ZipLimits = {
  maxEntries: 2_000_000,
  maxEntryBytes: 32 * 1024 * 1024,
  maxTotalBytes: 4 * 1024 * 1024 * 1024,
  maxCentralDirectoryBytes: 512 * 1024 * 1024,
};

export class ZipError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ZipError";
  }
}

interface CentralEntry {
  name: string;
  method: number;
  crc: number;
  compressedSize: number;
  size: number;
  localOffset: number;
}

async function readAt(handle: FileHandle, position: number, length: number): Promise<Buffer> {
  const buffer = Buffer.alloc(length);
  let done = 0;
  while (done < length) {
    const { bytesRead } = await handle.read(buffer, done, length - done, position + done);
    if (bytesRead === 0) throw new ZipError("The archive ends early.");
    done += bytesRead;
  }
  return buffer;
}

/**
 * Reads the central directory (zip and zip64) of a downloaded file. Verification is complete only
 * after `forEachZipEntry` has inflated every entry and matched its CRC-32 and size.
 */
export async function readCentralDirectory(
  handle: FileHandle,
  fileSize: number,
  limits: ZipLimits = DEFAULT_ZIP_LIMITS,
): Promise<CentralEntry[]> {
  if (fileSize < 22) throw new ZipError("Not a zip archive (too small).");
  const tailLength = Math.min(fileSize, 22 + 65535);
  const tail = await readAt(handle, fileSize - tailLength, tailLength);
  let eocd = -1;
  for (let index = tail.length - 22; index >= 0; index -= 1) {
    if (tail.readUInt32LE(index) === 0x06054b50) {
      eocd = index;
      break;
    }
  }
  if (eocd === -1) throw new ZipError("Not a zip archive (no end-of-directory record).");
  let entryCount = tail.readUInt16LE(eocd + 10);
  let directorySize = tail.readUInt32LE(eocd + 12);
  let directoryOffset = tail.readUInt32LE(eocd + 16);
  if (entryCount === 0xffff || directorySize === 0xffffffff || directoryOffset === 0xffffffff) {
    if (eocd < 20 || tail.readUInt32LE(eocd - 20) !== 0x07064b50) {
      throw new ZipError("The zip64 locator is missing.");
    }
    const recordOffset = Number(tail.readBigUInt64LE(eocd - 20 + 8));
    if (!Number.isSafeInteger(recordOffset) || recordOffset + 56 > fileSize) {
      throw new ZipError("The zip64 record is out of range.");
    }
    const record = await readAt(handle, recordOffset, 56);
    if (record.readUInt32LE(0) !== 0x06064b50) throw new ZipError("The zip64 record is invalid.");
    entryCount = Number(record.readBigUInt64LE(32));
    directorySize = Number(record.readBigUInt64LE(40));
    directoryOffset = Number(record.readBigUInt64LE(48));
  }
  if (entryCount > limits.maxEntries) throw new ZipError("The archive has too many entries.");
  if (
    directorySize > limits.maxCentralDirectoryBytes ||
    !Number.isSafeInteger(directoryOffset) ||
    directoryOffset + directorySize > fileSize
  ) {
    throw new ZipError("The central directory is out of range.");
  }
  const directory = await readAt(handle, directoryOffset, directorySize);
  const entries: CentralEntry[] = [];
  let position = 0;
  for (let index = 0; index < entryCount; index += 1) {
    if (position + 46 > directory.length || directory.readUInt32LE(position) !== 0x02014b50) {
      throw new ZipError("The central directory is damaged.");
    }
    const flags = directory.readUInt16LE(position + 8);
    const method = directory.readUInt16LE(position + 10);
    const crc = directory.readUInt32LE(position + 16);
    let compressedSize = directory.readUInt32LE(position + 20);
    let size = directory.readUInt32LE(position + 24);
    const nameLength = directory.readUInt16LE(position + 28);
    const extraLength = directory.readUInt16LE(position + 30);
    const commentLength = directory.readUInt16LE(position + 32);
    let localOffset = directory.readUInt32LE(position + 42);
    const next = position + 46 + nameLength + extraLength + commentLength;
    if (next > directory.length) throw new ZipError("The central directory is damaged.");
    if ((flags & 1) !== 0) throw new ZipError("Encrypted entries are not supported.");
    const name = directory.toString("utf8", position + 46, position + 46 + nameLength);
    // zip64 extended information (id 0x0001) supplies whichever fields are 0xFFFFFFFF, in order.
    let extra = position + 46 + nameLength;
    const extraEnd = extra + extraLength;
    while (extra + 4 <= extraEnd) {
      const id = directory.readUInt16LE(extra);
      const length = directory.readUInt16LE(extra + 2);
      if (id === 0x0001) {
        let cursor = extra + 4;
        if (size === 0xffffffff) {
          size = Number(directory.readBigUInt64LE(cursor));
          cursor += 8;
        }
        if (compressedSize === 0xffffffff) {
          compressedSize = Number(directory.readBigUInt64LE(cursor));
          cursor += 8;
        }
        if (localOffset === 0xffffffff) {
          localOffset = Number(directory.readBigUInt64LE(cursor));
        }
      }
      extra += 4 + length;
    }
    entries.push({ name, method, crc, compressedSize, size, localOffset });
    position = next;
  }
  return entries;
}

export interface ZipEntryContent {
  name: string;
  data: Buffer;
}

/**
 * Inflates every entry in turn and checks CRC-32 and size against the central directory. Throws
 * `ZipError` on the first mismatch; `visit` sees only verified content. Names that are not plain
 * `*.json` file names fail the archive.
 */
export async function forEachZipEntry(
  filePath: string,
  visit: (entry: ZipEntryContent) => void | Promise<void>,
  limits: ZipLimits = DEFAULT_ZIP_LIMITS,
): Promise<{ entryCount: number; totalBytes: number }> {
  const handle = await open(filePath, "r");
  try {
    const { size: fileSize } = await handle.stat();
    const entries = await readCentralDirectory(handle, fileSize, limits);
    let totalBytes = 0;
    for (const entry of entries) {
      if (entry.name.endsWith("/")) continue; // directory marker
      if (!ENTRY_NAME.test(entry.name))
        throw new ZipError("The archive has an unexpected entry name.");
      if (entry.size > limits.maxEntryBytes) throw new ZipError("An entry is larger than allowed.");
      totalBytes += entry.size;
      if (totalBytes > limits.maxTotalBytes)
        throw new ZipError("The archive expands to too much data.");
      if (entry.localOffset + 30 > fileSize) throw new ZipError("An entry is out of range.");
      const local = await readAt(handle, entry.localOffset, 30);
      if (local.readUInt32LE(0) !== 0x04034b50) throw new ZipError("A local header is damaged.");
      const dataStart = entry.localOffset + 30 + local.readUInt16LE(26) + local.readUInt16LE(28);
      if (dataStart + entry.compressedSize > fileSize)
        throw new ZipError("An entry is out of range.");
      const stored = await readAt(handle, dataStart, entry.compressedSize);
      let data: Buffer;
      if (entry.method === 0) {
        data = stored;
      } else if (entry.method === 8) {
        try {
          data = inflateRawSync(stored, { maxOutputLength: Math.max(entry.size, 1) });
        } catch {
          throw new ZipError("An entry could not be decompressed.");
        }
      } else {
        throw new ZipError("An entry uses an unsupported compression method.");
      }
      if (data.length !== entry.size) throw new ZipError("An entry has the wrong size.");
      if (crc32(data) !== entry.crc) throw new ZipError("An entry failed its checksum.");
      await visit({ name: entry.name, data });
    }
    return { entryCount: entries.length, totalBytes };
  } finally {
    await handle.close();
  }
}
