// corpus: expect=PG-CRYPTO-002
import jwt from "jsonwebtoken";

const KEY = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49\n-----END PRIVATE KEY-----";

export const verify = (token: string) => jwt.verify(token, KEY, { algorithms: ["RS256"] });
