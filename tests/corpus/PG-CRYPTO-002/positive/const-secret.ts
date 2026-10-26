// corpus: expect=PG-CRYPTO-002
import jwt from "jsonwebtoken";

const JWT_SECRET = "d3adb33f-super-secret-signing-key";

export const sign = (sub: string) => jwt.sign({ sub }, JWT_SECRET, { expiresIn: "1h" });
