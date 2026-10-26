// corpus: expect=none
import jwt from "jsonwebtoken";

const secret = "only-used-in-the-test-banner";
console.log(secret.length);

export function issue(payload: object, secret: string) {
  return jwt.sign(payload, secret, { expiresIn: "1h" });
}
