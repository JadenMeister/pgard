// corpus: expect=none
import { createCipheriv, randomBytes } from "crypto";

const ALGORITHM = "aes-256-gcm";

export function seal(key: Buffer, data: Buffer) {
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  return { iv, body: Buffer.concat([cipher.update(data), cipher.final()]), tag: cipher.getAuthTag() };
}
