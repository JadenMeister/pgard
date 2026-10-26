// corpus: expect=PG-CRYPTO-001
import { createHash } from "crypto";

const HASH_ALGO = "sha1";

export function hashPassword(password: string): string {
  return createHash(HASH_ALGO).update(password).digest("hex");
}
