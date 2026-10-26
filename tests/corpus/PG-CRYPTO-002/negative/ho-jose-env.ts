// corpus: expect=none
import { SignJWT } from "jose";

const secret = new TextEncoder().encode(process.env.JWT_SECRET);

export const issue = (sub: string) =>
  new SignJWT({ sub }).setProtectedHeader({ alg: "HS256" }).sign(secret);
