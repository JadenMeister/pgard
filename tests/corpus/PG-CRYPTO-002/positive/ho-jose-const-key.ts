// corpus: expect=PG-CRYPTO-002
import { SignJWT } from "jose";

const secret = new TextEncoder().encode("a-very-long-hardcoded-signing-secret");

export const issue = (sub: string) =>
  new SignJWT({ sub }).setProtectedHeader({ alg: "HS256" }).setExpirationTime("2h").sign(secret);
