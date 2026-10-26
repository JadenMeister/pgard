// corpus: expect=none
import { createHash } from "crypto";

const HASH_ALGO = "sha256";

export const fingerprintPassword = (password: string) =>
  createHash(HASH_ALGO).update(password).digest("hex");
