import { crc32, deflateRawSync } from "node:zlib";

export interface TestZipEntry {
  name: string;
  content: string;
  /** Store without compression. */
  stored?: boolean;
  /** Write a wrong CRC-32 in the headers. */
  badCrc?: boolean;
  /** Announce a larger inflated size in the central directory than the real one. */
  lieSize?: boolean;
}

/** Builds a small zip in memory. `zip64` writes the zip64 end-of-directory records. */
export function makeZip(
  entries: readonly TestZipEntry[],
  options: { zip64?: boolean } = {},
): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const entry of entries) {
    const raw = Buffer.from(entry.content, "utf8");
    const data = entry.stored === true ? raw : deflateRawSync(raw);
    const crc = entry.badCrc === true ? (crc32(raw) ^ 0xdeadbeef) >>> 0 : crc32(raw);
    const name = Buffer.from(entry.name, "utf8");
    const method = entry.stored === true ? 0 : 8;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    locals.push(local, name, data);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(entry.lieSize === true ? raw.length + 5 : raw.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, name);
    offset += 30 + name.length + data.length;
  }
  const directory = Buffer.concat(centrals);
  const parts = [...locals, directory];
  if (options.zip64 === true) {
    const record = Buffer.alloc(56);
    record.writeUInt32LE(0x06064b50, 0);
    record.writeBigUInt64LE(44n, 4);
    record.writeBigUInt64LE(BigInt(entries.length), 24);
    record.writeBigUInt64LE(BigInt(entries.length), 32);
    record.writeBigUInt64LE(BigInt(directory.length), 40);
    record.writeBigUInt64LE(BigInt(offset), 48);
    const locator = Buffer.alloc(20);
    locator.writeUInt32LE(0x07064b50, 0);
    locator.writeBigUInt64LE(BigInt(offset + directory.length), 8);
    locator.writeUInt32LE(1, 16);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0);
    end.writeUInt16LE(0xffff, 10);
    end.writeUInt32LE(0xffffffff, 12);
    end.writeUInt32LE(0xffffffff, 16);
    parts.push(record, locator, end);
  } else {
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0);
    end.writeUInt16LE(entries.length, 8);
    end.writeUInt16LE(entries.length, 10);
    end.writeUInt32LE(directory.length, 12);
    end.writeUInt32LE(offset, 16);
    parts.push(end);
  }
  return Buffer.concat(parts);
}

export function osvRecord(id: string, name: string, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    id,
    modified: "2026-10-20T10:00:00Z",
    summary: `summary of ${id}`,
    details: "long text that must not be stored",
    aliases: [`CVE-${id}`],
    affected: [
      {
        package: { ecosystem: "npm", name },
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.2.3" }] }],
      },
    ],
    ...extra,
  });
}
