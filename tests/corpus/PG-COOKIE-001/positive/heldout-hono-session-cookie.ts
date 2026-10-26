// corpus: expect=PG-COOKIE-001
import { setCookie } from "hono/cookie";

export const login = (c: any) => {
  setCookie(c, "session", "abc", { path: "/" });
  return c.body(null, 204);
};
