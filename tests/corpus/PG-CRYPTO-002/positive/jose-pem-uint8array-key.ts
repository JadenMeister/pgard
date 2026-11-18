// corpus: expect=PG-CRYPTO-002
import { jwtVerify } from "jose";

const PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----";

// A Uint8Array key is an HMAC secret to jose, so a public key held this way is forgeable.
export const verify = (token: string) => jwtVerify(token, new TextEncoder().encode(PUBLIC_KEY));
