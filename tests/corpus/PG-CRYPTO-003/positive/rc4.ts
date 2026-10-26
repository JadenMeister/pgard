// corpus: expect=PG-CRYPTO-003
import { createCipheriv } from "node:crypto";

export const encrypt = (key: Buffer, data: Buffer) => {
  const c = createCipheriv("rc4", key, null);
  return Buffer.concat([c.update(data), c.final()]);
};
