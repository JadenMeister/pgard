// corpus: expect=PG-CRYPTO-002
import jwt from "jsonwebtoken";

const PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----";

export const verify = (token: string) => jwt.verify(token, PUBLIC_KEY);
