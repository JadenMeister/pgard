// corpus: expect=PG-CRYPTO-003
import { createCipheriv } from "crypto";

const CIPHER = "aes-128-ecb";

export function seal(key: Buffer, data: Buffer): Buffer {
  const cipher = createCipheriv(CIPHER, key, null);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}
