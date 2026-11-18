// corpus: expect=PG-CRYPTO-002
import { jwtVerify } from "jose";

const SECRET = "jose-encoded-secret-value";

export const verify = (token: string) => jwtVerify(token, new TextEncoder().encode(SECRET));
