// corpus: expect=none
import { cookies } from "next/headers";

export async function POST() {
  (await cookies()).set("auth_token", "abc", { httpOnly: true, secure: true, sameSite: "strict", path: "/" });
  return new Response(null, { status: 204 });
}
