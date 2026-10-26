// corpus: expect=PG-COOKIE-001
import { cookies } from "next/headers";

export async function POST() {
  (await cookies()).set("auth_token", "abc", { path: "/" });
  return new Response(null, { status: 204 });
}
