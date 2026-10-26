// corpus: expect=none
import { createCipheriv, randomBytes } from "node:crypto";

export const encrypt = (key: Buffer, data: Buffer) => {
  const nonce = randomBytes(12);
  const c = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  return Buffer.concat([nonce, c.update(data), c.final(), c.getAuthTag()]);
};
