// corpus: expect=PG-CRYPTO-003
import { createCipheriv } from "node:crypto";

const alg = "rc4";

export const stream = (key, data) => {
  const c = createCipheriv(alg, key, "");
  return Buffer.concat([c.update(data), c.final()]);
};
