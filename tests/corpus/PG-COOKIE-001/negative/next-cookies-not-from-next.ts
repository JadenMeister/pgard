// corpus: expect=none
import { cookies } from "./my-cookie-jar";

export function remember() {
  cookies().set("session", "abc");
}
