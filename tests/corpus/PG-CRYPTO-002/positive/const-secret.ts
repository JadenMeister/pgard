// corpus: expect=PG-CRYPTO-002; known=miss:PG-CRYPTO-002:a hardcoded secret held in a constant and passed by name to jwt.sign is not followed
import jwt from "jsonwebtoken";

const JWT_SECRET = "d3adb33f-super-secret-signing-key";

export const sign = (sub: string) => jwt.sign({ sub }, JWT_SECRET, { expiresIn: "1h" });
