// corpus: expect=PG-COOKIE-001; known=miss:PG-COOKIE-001:the Next.js cookies().set() API is not recognised
import { cookies } from "next/headers";

export async function POST() {
  (await cookies()).set("auth_token", "abc", { path: "/" });
  return new Response(null, { status: 204 });
}
