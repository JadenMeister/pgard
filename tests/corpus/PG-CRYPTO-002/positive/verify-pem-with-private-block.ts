// corpus: expect=PG-CRYPTO-002
import jwt from "jsonwebtoken";

const KEYS = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----\n-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49\n-----END PRIVATE KEY-----";

export const verify = (token: string) => jwt.verify(token, KEYS, { algorithms: ["RS256"] });
