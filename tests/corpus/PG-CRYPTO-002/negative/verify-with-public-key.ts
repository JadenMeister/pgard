// corpus: expect=none
import { readFileSync } from "node:fs";
import jwt from "jsonwebtoken";

const publicKey = readFileSync("keys/public.pem");
export const verify = (token: string) => jwt.verify(token, publicKey, { algorithms: ["RS256"] });
