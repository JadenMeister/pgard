// corpus: expect=none
import { createHmac, randomBytes } from "node:crypto";

const key = randomBytes(32);
export const sign = (body: string) => createHmac("sha256", key).update(body).digest("hex");
