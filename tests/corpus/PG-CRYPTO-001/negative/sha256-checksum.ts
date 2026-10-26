// corpus: expect=none
import { createHash } from "node:crypto";

export const checksum = (data: Buffer) => createHash("sha256").update(data).digest("hex");
