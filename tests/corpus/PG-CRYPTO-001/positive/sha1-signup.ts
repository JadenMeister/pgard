// corpus: expect=PG-CRYPTO-001
import { createHash } from "node:crypto";

export async function register(req: { body: { email: string; password: string } }) {
  const passwordHash = createHash("sha1").update(req.body.password).digest("hex");
  return { email: req.body.email, passwordHash };
}
